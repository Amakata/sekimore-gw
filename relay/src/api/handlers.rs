//! The individual endpoints. Each checks the request's required fields, obtains proof via
//! `Project::authorize`, and hands the operation to the forge relay for that repository's upstream
//! (#328). Everything up to the proof is here, in the gateway; the upstream calls and the shaping of
//! their answer are the relay's (`crate::forge::github`).

use std::time::SystemTime;

use hyper::body::Incoming;
use hyper::{Request, StatusCode};
use serde_json::Value;

use super::types::{ApiRequest, ApiResponse, BootstrapRequest, BootstrapResponse, SigningBlock};
use super::{read_body, ApiContext, ApiError};
use crate::audit::Actor;
use crate::config::BootstrapMode;
use crate::forge::{unexpected, Answer, Handle, Query, Resolved};
use crate::paths;
use crate::policy::SigningMode;
use crate::policy::{Action, Authorized, Mode, Resource};
use crate::ssh::authorized_keys::Added;
use crate::tokens::TokenRecord;

/// The forge relay for the upstream of the repo the proof refers to (each upstream has its own
/// token and API base. 0.2.0).
fn relay<'a>(ctx: &'a ApiContext, auth: &Authorized<'_>) -> Result<Handle<'a>, ApiError> {
    let host = ctx.project.host_of(auth.policy());
    let key = if host.is_empty() {
        ctx.git_domain.as_str()
    } else {
        host
    };
    ctx.relays.get(key).ok_or_else(|| ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        message: format!("upstream API for {key} is not configured on the gateway"),
    })
}

/// Hand an authorized operation to the relay, with nothing resolved beforehand.
async fn forward(
    relay: Handle<'_>,
    op: &str,
    auth: &Authorized<'_>,
    req: &ApiRequest,
) -> Result<ApiResponse, ApiError> {
    relay.call(op, &[auth], req, &Resolved::default()).await
}

fn need(cond: bool, msg: &str) -> Result<(), ApiError> {
    if cond {
        Ok(())
    } else {
        Err(ApiError::bad_request(msg))
    }
}

/// The guard 33 handlers opened with. Named so a handler that cannot use `repo_scope` still
/// states the requirement the same way.
fn need_repo(req: &ApiRequest) -> Result<(), ApiError> {
    need(!req.repo.is_empty(), "repo is required")
}

/// The preamble every repo-scoped handler shares: check the repo, ask the policy, pick the relay
/// for that repo's upstream.
///
/// Resource and action stay arguments rather than being inferred from anything, because this is
/// the security boundary: the permission a handler demands has to be readable at the handler, not
/// looked up somewhere else. What is hidden here is only the mechanical part — the empty-string
/// check and which relay the proof belongs to.
fn repo_scope<'a>(
    ctx: &'a ApiContext,
    req: &'a ApiRequest,
    resource: Resource,
    action: Action,
) -> Result<(Authorized<'a>, Handle<'a>), ApiError> {
    need_repo(req)?;
    let auth = ctx.project.authorize(&req.repo, resource, action)?;
    let r = relay(ctx, &auth)?;
    Ok((auth, r))
}

/// As `repo_scope`, plus the `number is required` guard.
fn numbered_scope<'a>(
    ctx: &'a ApiContext,
    req: &'a ApiRequest,
    resource: Resource,
    action: Action,
) -> Result<(Authorized<'a>, Handle<'a>), ApiError> {
    // Repo first, then the number: a request missing both is answered the way it always was.
    need_repo(req)?;
    need(req.number != 0, "number is required")?;
    repo_scope(ctx, req, resource, action)
}

/// What a number turned out to name.
///
/// GitHub serves pull requests from the issues endpoints, so `issue close --number <a PR>` reached
/// a pull request under `issue:close`. A project that withheld `pr:close` deliberately — leaving
/// review and closing to people — found `issue:close` doing the same job.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Numbered {
    Issue,
    PullRequest,
}

impl Numbered {
    fn resource(self) -> Resource {
        match self {
            Numbered::Issue => Resource::Issue,
            Numbered::PullRequest => Resource::Pr,
        }
    }
}

/// Whether a number names a pull request: the relay looks, the gateway decides what follows.
async fn names_a_pull_request(
    r: Handle<'_>,
    auth: &Authorized<'_>,
    number: u64,
) -> Result<bool, ApiError> {
    let q = Query::NamesAPullRequest { number };
    match r.ask(&q, auth).await? {
        Answer::Bool(b) => Ok(b),
        other => Err(unexpected(&q, &other)),
    }
}

/// As `numbered_scope`, for a write where the number may name either kind.
///
/// Looks the number up and authorizes against what it is, so the same command reaches an issue
/// under `issue:<action>` and a pull request under `pr:<action>`.
///
/// The order matters. A caller holding neither permission is refused before anything is asked
/// upstream, so this cannot be used to probe whether a number is a pull request. Only once one of
/// the two is held does the lookup happen, and the proof that comes back is for whichever the
/// number turned out to be — so a project with `issue:close` alone is refused on a pull request,
/// naming `pr:close`.
async fn numbered_write_scope<'a>(
    ctx: &'a ApiContext,
    req: &'a ApiRequest,
    action: Action,
) -> Result<(Authorized<'a>, Handle<'a>, Numbered), ApiError> {
    need_repo(req)?;
    need(req.number != 0, "number is required")?;

    let holds_issue = ctx
        .project
        .authorize(&req.repo, Resource::Issue, action)
        .is_ok();
    let holds_pr = ctx
        .project
        .authorize(&req.repo, Resource::Pr, action)
        .is_ok();
    if !holds_issue && !holds_pr {
        // Neither: answer in the terms the caller asked in, and reach nothing upstream
        ctx.project.authorize(&req.repo, Resource::Issue, action)?;
    }
    let probe_resource = if holds_issue {
        Resource::Issue
    } else {
        Resource::Pr
    };
    let probe = ctx.project.authorize(&req.repo, probe_resource, action)?;
    let r = relay(ctx, &probe)?;
    let target = if names_a_pull_request(r, &probe, req.number).await? {
        Numbered::PullRequest
    } else {
        Numbered::Issue
    };
    let auth = ctx
        .project
        .authorize(&req.repo, target.resource(), action)?;
    Ok((auth, r, target))
}

/// As `repo_scope`, but anchored on the project rather than a named repo (Projects v2 and search
/// carry no repository of their own).
fn project_scope<'a>(
    ctx: &'a ApiContext,
    req: &'a ApiRequest,
    resource: Resource,
    action: Action,
) -> Result<(Authorized<'a>, Handle<'a>), ApiError> {
    let anchor = project_anchor(ctx, req)?;
    let auth = ctx.project.authorize(anchor, resource, action)?;
    let r = relay(ctx, &auth)?;
    Ok((auth, r))
}

/// Projects v2 is org-scoped, so the repo may be omitted. The policy anchor is then the project's first repository.
fn project_anchor<'a>(ctx: &'a ApiContext, req: &'a ApiRequest) -> Result<&'a str, ApiError> {
    if !req.repo.is_empty() {
        return Ok(&req.repo);
    }
    ctx.project
        .repos
        .first()
        .map(|r| r.full_name.as_str())
        .ok_or_else(|| ApiError::forbidden("project has no repositories"))
}

/// The boards this project declared, as `--board 2 (orgs/Acme/projects/2)`, for a message that
/// tells the caller what it may name instead of only what it may not.
fn board_choices(boards: &[crate::api::ResolvedBoard]) -> String {
    boards
        .iter()
        .map(|b| format!("--board {} ({})", b.number, b.label))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Which board this request means, checked against the ones the project declared.
///
/// 0.2.7: the board has to be one the project declared. A Projects v2 node id is opaque and
/// carries no owner, so nothing about the id itself says which board it is — without this check
/// any board the upstream token can see would be reachable from `project:add_item`.
///
/// 0.2.15: `--board <number>` names it the way `relay.project.boards` and the URL do, and a single
/// configured board is the default. Requiring `--project-id PVT_…` made the agent carry an id it
/// has no way to obtain — the command that prints it is the operator's — while the relay had the
/// mapping from start-up all along.
/// #277: the board actually named decides last. `authorize` counted a key any board adds; here
/// the board is known, and its own allow / deny settle it. Every Projects handler goes
/// through this, so a board is never reached on the anchor repository's permissions alone.
/// #291: the relay it hands back is the board's upstream's, not the anchor repository's: a
/// board on the GHE is asked on the GHE whatever `--repo` / `SEKIMORE_REPO` name.
async fn board_scope<'a>(
    ctx: &'a ApiContext,
    req: &ApiRequest,
    auth: &crate::policy::Authorized<'_>,
) -> Result<(Resolved, Handle<'a>), ApiError> {
    let board = resolve_board(ctx, req).await?;
    ctx.project.authorize_board(auth, &board.label)?;
    let r = ctx.relays.get(&board.upstream).ok_or_else(|| ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        message: format!(
            "upstream API for {} (the upstream of project board {}) is not configured on the gateway",
            board.upstream, board.label
        ),
    })?;
    Ok((
        Resolved {
            board_id: board.id,
            ..Resolved::default()
        },
        r,
    ))
}

async fn resolve_board(
    ctx: &ApiContext,
    req: &ApiRequest,
) -> Result<crate::api::ResolvedBoard, ApiError> {
    if ctx.project_boards.is_declared_empty() {
        return Err(ApiError::forbidden(
            "no project board is allowed; add relay.project.boards (the org / user and the number from the board's URL)",
        ));
    }
    let boards = ctx.project_boards.get(&ctx.relays, &ctx.git_domain).await;
    if boards.is_empty() {
        // Declared but not resolvable. Saying "add relay.project.boards" here would send the
        // operator to a file that already has it; the usual reason is a locked secret store,
        // since resolving needs the upstream token (#99).
        return Err(ApiError::forbidden(
            "the project's boards are declared but could not be resolved; the relay needs the              upstream API token for that, so a locked secret store is the usual reason.              Ask a human to run: sgw unlock",
        ));
    }
    let id = req.project_id.trim();
    match (id.is_empty(), req.board) {
        (false, Some(_)) => Err(ApiError::bad_request(
            "pass --board or --project-id, not both",
        )),
        (true, Some(n)) => boards
            .iter()
            .find(|b| b.number == n)
            .cloned()
            .ok_or_else(|| {
                ApiError::forbidden(format!(
                    "project board {n} is not in this project; this project has {}",
                    board_choices(&boards)
                ))
            }),
        (false, None) => boards.iter().find(|b| b.id == id).cloned().ok_or_else(|| {
            ApiError::forbidden(format!("project board {id} is not in this project"))
        }),
        (true, None) => match boards.as_slice() {
            [only] => Ok(only.clone()),
            _ => Err(ApiError::bad_request(format!(
                "--board is required when the project has more than one board: {}",
                board_choices(&boards)
            ))),
        },
    }
}

pub async fn dispatch(
    ctx: &ApiContext,
    path: &str,
    req: &ApiRequest,
    rec: &TokenRecord,
) -> Result<ApiResponse, ApiError> {
    match path {
        "/whoami" => whoami(ctx, rec).await,
        "/signing/owner" => signing_owner(ctx, req).await,
        "/pr/create" => pr_create(ctx, req).await,
        "/pr/comment" => pr_comment(ctx, req).await,
        "/pr/reply" => pr_reply(ctx, req).await,
        "/pr/comment-edit" => comment_edit(ctx, path, req).await,
        "/pr/comment-delete" => comment_delete(ctx, path, req).await,
        "/issue/comment-edit" => comment_edit(ctx, path, req).await,
        "/issue/comment-delete" => comment_delete(ctx, path, req).await,
        "/pr/draft" => pr_draft(ctx, req).await,
        "/ci/dispatch" => ci_dispatch(ctx, req).await,
        "/pr/review" => pr_review(ctx, req).await,
        "/pr/resolve" => pr_resolve(ctx, req).await,
        "/pr/merge" => pr_merge(ctx, req).await,
        "/pr/close" => pr_close(ctx, req).await,
        "/pr/reopen" => pr_reopen(ctx, req).await,
        "/pr/update" => pr_update(ctx, req).await,
        "/pr/status" => pr_status(ctx, req).await,
        "/pr/view" => pr_view(ctx, req).await,
        "/pr/comments" => pr_comments(ctx, req).await,
        "/pr/files" => pr_files(ctx, req).await,
        "/pr/diff" => pr_diff(ctx, req).await,
        "/pr/list" => pr_list(ctx, req).await,
        "/issue/view" => issue_view(ctx, req).await,
        "/issue/comments" => issue_comments(ctx, req).await,
        "/issue/list" => issue_list(ctx, req).await,
        "/ci/runs" => ci_runs(ctx, req).await,
        "/ci/jobs" => ci_jobs(ctx, req).await,
        "/ci/log" => ci_log(ctx, req).await,
        "/issue/create" => issue_create(ctx, req).await,
        "/issue/comment" => issue_comment(ctx, req).await,
        "/issue/update" => issue_update(ctx, req).await,
        "/issue/close" => issue_close(ctx, req).await,
        "/issue/reopen" => issue_reopen(ctx, req).await,
        "/issue/label" => issue_label(ctx, req).await,
        "/issue/unlabel" => issue_unlabel(ctx, req).await,
        "/issue/assign" => issue_assign(ctx, req).await,
        "/issue/unassign" => issue_unassign(ctx, req).await,
        "/project/add-item" => project_add_item(ctx, req).await,
        "/project/update-item" => project_update_item(ctx, req).await,
        "/project/list" => project_list(ctx, req).await,
        "/project/fields" => project_fields(ctx, req).await,
        "/pr/request-review" => pr_request_review(ctx, req).await,
        "/search/issues" => search_issues(ctx, req).await,
        "/repo/vocabulary" => repo_vocabulary(ctx, req).await,
        "/release/create" => release_create(ctx, req).await,
        "/release/view" => release_view(ctx, req).await,
        "/release/list" => release_list(ctx, req).await,
        "/release/edit" => release_edit(ctx, req).await,
        "/ci/rerun" => ci_rerun(ctx, req).await,
        "/ci/cancel" => ci_cancel(ctx, req).await,
        "/security/alerts" => security_alerts(ctx, req).await,
        "/security/alert" => security_alert(ctx, req).await,
        "/security/dismiss" => security_dismiss(ctx, req).await,
        "/security/reopen" => security_reopen(ctx, req).await,
        "/issue/tasks" => task_list(ctx, req, Resource::Issue).await,
        "/pr/tasks" => task_list(ctx, req, Resource::Pr).await,
        "/issue/check" | "/pr/check" => task_check(ctx, req).await,
        _ => Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: format!("unknown endpoint {path}"),
        }),
    }
}

// ---- Permission checks ----

async fn whoami(ctx: &ApiContext, rec: &TokenRecord) -> Result<ApiResponse, ApiError> {
    let perms = ctx.project.granted();
    // #143: a repository's own allow / deny change what the relay decides for it, so its line
    // says how its permissions differ from the project-wide ones: `+` what it adds, `-` what it
    // takes away. Printing only the project line had an agent conclude it could not merge where
    // the repository granted pr:merge.
    let repos: Vec<String> = ctx
        .project
        .repos
        .iter()
        .map(|r| {
            let effective = ctx.project.effective_keys(r);
            let mut delta: Vec<String> = effective
                .iter()
                .filter(|k| !perms.contains(k))
                .map(|k| format!("+{k}"))
                .collect();
            delta.extend(
                perms
                    .iter()
                    .filter(|k| !effective.contains(k))
                    .map(|k| format!("-{k}")),
            );
            let mut line = format!("{} ({})", r.full_name, r.mode.as_str());
            if !delta.is_empty() {
                line = format!("{line} {}", delta.join(" "));
            }
            // #158: which branch names this repository accepts, and how each ref spelling names
            // the branch it creates. Without them an agent has to guess, and the guess that fails
            // is a push that has already been made. Read-only repositories say nothing: a rule
            // that cannot apply is a line that gets ignored when it can (the reasoning of #59).
            if r.mode == Mode::ReadWrite {
                let bases = if r.bases.is_empty() {
                    "any".to_string()
                } else {
                    r.bases.join(" ")
                };
                // `refs/pr/` opens against the default branch, so it is refused where `bases`
                // restricts which base a pull request may have (#158).
                let pr_line = if r.bases.is_empty() {
                    "refs/pr/<branch>   the branch as named, PR against the default branch"
                } else {
                    "refs/pr/<branch>   not available here: this repository restricts its bases"
                };
                line.push_str(&format!(
                    "\n  push   {}\n  bases  {bases}\n  refs   {pr_line}\n         refs/for/<base>    {}, PR against <base>",
                    r.push.join(" "),
                    ctx.project
                        .branch
                        .template
                        .replace("{branch}", "<base>")
                        .replace("{base}", "<base>")
                        .replace("{sha}", "<sha7>"),
                ));
            }
            line
        })
        .collect();
    // #59: said only when it is required. `optional` asks nothing of the agent, and a line about
    // a rule that does not apply is a line that gets ignored when it does.
    let signing = match strictest_signing(&ctx.project) {
        SigningMode::Required => {
            // "ok" has to mean the key is actually in the host agent. #59 was a signing key
            // that had silently gone, and a line that says ok without looking would be the same
            // mistake in a new place.
            let key = match &ctx.signing {
                Some(a) => match a.identity().await {
                    Some(_) => format!("{} ok", a.fingerprint()),
                    None => format!(
                        "{} is NOT in the gateway's agent — ask the operator to ssh-add it on the host; commits will not sign",
                        a.fingerprint()
                    ),
                },
                None => "no signing key is offered by the gateway — ask the operator; commits will not sign".to_string(),
            };
            format!("\nsigning: required — {key}")
        }
        _ => String::new(),
    };
    // #277: a board with a delta of its own says how its project:* keys differ from the
    // project-wide ones, the way a repo line does. Without it an agent reads the permissions
    // line, tries the board that is allowed less, and learns the answer from a refusal.
    let boards = match (
        ctx.project_boards.declared_labels(),
        ctx.project.repos.first(),
    ) {
        (labels, Some(anchor)) if !labels.is_empty() => {
            let upstreams = ctx.project_boards.declared_upstreams();
            let lines: Vec<String> = labels
                .iter()
                .zip(upstreams.iter())
                .map(|(label, upstream)| {
                    let effective = ctx.project.effective_board_keys(anchor, label);
                    let mut delta: Vec<String> = effective
                        .iter()
                        .filter(|k| !perms.contains(k))
                        .map(|k| format!("+{k}"))
                        .collect();
                    delta.extend(
                        perms
                            .iter()
                            .filter(|k| k.starts_with("project:") && !effective.contains(k))
                            .map(|k| format!("-{k}")),
                    );
                    // #291: a board on another upstream says so; the call goes there by itself
                    let at = match upstream {
                        Some(u) => format!(" (on {u})"),
                        None => String::new(),
                    };
                    if delta.is_empty() {
                        format!("{label}{at}")
                    } else {
                        format!("{label}{at} {}", delta.join(" "))
                    }
                })
                .collect();
            format!(
                "\nboards (--board <number>; a line's +/- adds or removes):\n  {}",
                lines.join("\n  ")
            )
        }
        _ => String::new(),
    };
    let msg = format!(
        "project={} token={} expires={}\npermissions (every repo; a repo line's +/- adds or removes): {}{signing}\nrepos:\n  {}{boards}",
        rec.project,
        rec.label,
        humantime::format_rfc3339_seconds(rec.expires_at),
        if perms.is_empty() {
            "(none)".to_string()
        } else {
            perms.join(" ")
        },
        repos.join("\n  ")
    );
    Ok(ApiResponse {
        message: Some(msg),
        ..Default::default()
    })
}

/// #339: the dev container's user, so the signing socket can belong to it.
///
/// Any project token will do and no permission is asked: the only thing this changes is which uid
/// on the shared volume may open the socket, and root in the dev container can open it whatever the
/// owner is. What it fixes is a dev user Dev Containers gave the host's uid on Linux (501, say),
/// shut out of a socket made for 1000. Root is refused: that would shut the dev user out instead.
async fn signing_owner(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let uid = req
        .uid
        .ok_or_else(|| ApiError::bad_request("uid is required"))?;
    need(
        uid != 0,
        "uid 0 is root; the socket is for the dev container's user",
    )?;
    let Some(sig) = &ctx.signing else {
        return Ok(ApiResponse {
            message: Some("no signing key is offered by the gateway".into()),
            ..ApiResponse::ok()
        });
    };
    let changed = sig.follow_dev_uid(uid).map_err(|e| ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: format!("cannot hand the signing socket to uid {uid}: {e}"),
    })?;
    let now = sig.socket_uid();
    Ok(ApiResponse {
        message: Some(if changed {
            format!("the signing socket now belongs to uid {now}")
        } else {
            format!("the signing socket belongs to uid {now}")
        }),
        ..ApiResponse::ok()
    })
}

// ---- PR ----

async fn pr_create(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        !req.head.is_empty() && !req.base.is_empty() && !req.title.is_empty(),
        "head, base and title are required",
    )?;
    let auth = ctx
        .project
        .authorize_pr_from(&req.repo, &req.head, &req.base)?;
    forward(relay(ctx, &auth)?, "/pr/create", &auth, req).await
}

async fn pr_comment(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 && !req.body.is_empty(),
        "number and body are required",
    )?;
    let (auth, r) = repo_scope(ctx, req, Resource::Pr, Action::Comment)?;
    forward(r, "/pr/comment", &auth, req).await
}

/// #165: answer a line comment where it was left. `pr:comment` rather than a permission of its
/// own — it is the same act as commenting, in a different place, so a project that allowed one
/// does not have to declare the other.
async fn pr_reply(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 && req.comment_id != 0 && !req.body.is_empty(),
        "number, comment-id and body are required",
    )?;
    let (auth, r) = repo_scope(ctx, req, Resource::Pr, Action::Comment)?;
    forward(r, "/pr/reply", &auth, req).await
}

/// #169: offer a draft for review, or put one back. `pr:create` rather than a key of its own —
/// an agent that may open a ready pull request can already reach this state directly.
async fn pr_draft(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(req.number != 0, "number is required")?;
    let (auth, r) = repo_scope(ctx, req, Resource::Pr, Action::Create)?;
    forward(r, "/pr/draft", &auth, req).await
}

/// #168: start a workflow that has not run. `ci:dispatch`, not `ci:rerun`: a re-run repeats what
/// already happened here, while this can start a deploy on a ref of the agent's choosing.
async fn ci_dispatch(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        !req.workflow.is_empty() && !req.git_ref.is_empty(),
        "workflow and ref are required",
    )?;
    let (auth, r) = repo_scope(ctx, req, Resource::Ci, Action::Dispatch)?;
    forward(r, "/ci/dispatch", &auth, req).await
}

/// #172: the permission follows what the number names, not which command was typed. GitHub keeps
/// the conversation on a pull request and on an issue in one namespace, so `pr comment-edit`
/// taken at its word would let `pr:comment_update` rewrite an issue comment a project meant to
/// keep behind `issue:comment_update`. The comment is then checked to sit on that number.
async fn comment_scope<'a>(
    ctx: &'a ApiContext,
    req: &'a ApiRequest,
    action: Action,
) -> Result<(Authorized<'a>, Handle<'a>), ApiError> {
    need(req.comment_id != 0, "comment-id is required")?;
    let (auth, r, target) = numbered_write_scope(ctx, req, action).await?;
    // A line comment exists only on a pull request; the pulls endpoint is outside issue:*
    need(
        !req.inline || target == Numbered::PullRequest,
        "--inline names a line comment, and only a pull request has those",
    )?;
    Ok((auth, r))
}

async fn comment_edit(
    ctx: &ApiContext,
    path: &str,
    req: &ApiRequest,
) -> Result<ApiResponse, ApiError> {
    need(!req.body.is_empty(), "body is required")?;
    let (auth, r) = comment_scope(ctx, req, Action::CommentUpdate).await?;
    forward(r, path, &auth, req).await
}

async fn comment_delete(
    ctx: &ApiContext,
    path: &str,
    req: &ApiRequest,
) -> Result<ApiResponse, ApiError> {
    let (auth, r) = comment_scope(ctx, req, Action::CommentDelete).await?;
    forward(r, path, &auth, req).await
}

async fn pr_review(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 && !req.event.is_empty(),
        "number and event are required",
    )?;
    need(
        matches!(
            req.event.as_str(),
            "APPROVE" | "REQUEST_CHANGES" | "COMMENT"
        ),
        "event must be APPROVE, REQUEST_CHANGES or COMMENT",
    )?;
    // #167: GitHub refuses a review with neither a body nor comments, and its message does not
    // say which is missing.
    need(
        !req.body.is_empty() || !req.comments.is_empty(),
        "a review needs a body, line comments, or both",
    )?;
    for c in &req.comments {
        need(
            !c.path.is_empty() && c.line != 0 && !c.body.trim().is_empty(),
            "each comment needs a path, a line and a body",
        )?;
    }
    let (auth, r) = repo_scope(ctx, req, Resource::Pr, Action::Review)?;
    forward(r, "/pr/review", &auth, req).await
}

/// 0.2.59: settle a review conversation, or open it again.
///
/// `pr:resolve` rather than `pr:comment`: resolving closes out someone else's review note, which
/// is a different authority from answering one. The thread id comes from `pr comments`, which is
/// the only place that has it, and the client checks it really is on `number` before it writes.
async fn pr_resolve(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(req.number != 0, "number is required")?;
    need(
        !req.thread_id.trim().is_empty(),
        "thread-id is required; `pr comments` prints it beside each line comment",
    )?;
    let (auth, r) = repo_scope(ctx, req, Resource::Pr, Action::Resolve)?;
    forward(r, "/pr/resolve", &auth, req).await
}

async fn pr_merge(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(req.number != 0, "number is required")?;
    // A typo here would otherwise become an upstream 422; catch it before spending a call.
    need(
        req.method.is_empty() || matches!(req.method.as_str(), "merge" | "squash" | "rebase"),
        "method must be merge, squash or rebase",
    )?;
    let (auth, r) = repo_scope(ctx, req, Resource::Pr, Action::Merge)?;
    // `delete_merged_branch` was declared as a repo policy and never enforced. It is the operator's
    // switch for exactly this, so the agent asking is necessary but not sufficient.
    if req.delete_branch && !auth.policy().delete_merged_branch {
        return Err(ApiError::forbidden(format!(
            "deleting the merged branch is not allowed for {} (set delete_merged_branch)",
            auth.repo()
        )));
    }
    forward(r, "/pr/merge", &auth, req).await
}

async fn pr_close(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r) = numbered_scope(ctx, req, Resource::Pr, Action::Close)?;
    forward(r, "/pr/close", &auth, req).await
}

/// The inverse of closing, under the same permission: `pr:close` already lets the agent change the
/// state, and reopening is the less destructive direction.
async fn pr_reopen(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r) = numbered_scope(ctx, req, Resource::Pr, Action::Close)?;
    forward(r, "/pr/reopen", &auth, req).await
}

/// Edit a pull request's own metadata.
///
/// Title and body are `pr:create`: changing what you wrote is the authority you used to write it.
/// A new base is not — retargeting a PR from an allowed base to a forbidden one would walk straight
/// around `bases`, so that case goes through `authorize_pr`, the same check `pr create` runs.
async fn pr_update(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(req.number != 0, "number is required")?;
    need(
        !req.title.is_empty() || !req.body.is_empty() || !req.base.is_empty(),
        "one of title, body or base is required",
    )?;
    let auth = if req.base.is_empty() {
        ctx.project
            .authorize(&req.repo, Resource::Pr, Action::Create)?
    } else {
        ctx.project.authorize_pr(&req.repo, &req.base)?
    };
    forward(relay(ctx, &auth)?, "/pr/update", &auth, req).await
}

async fn pr_status(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r) = numbered_scope(ctx, req, Resource::Pr, Action::Read)?;
    forward(r, "/pr/status", &auth, req).await
}

// ---- reading pull requests and issues (0.2.8) ----

/// The three values GitHub accepts. Anything else is the agent's mistake, not an upstream error.
fn list_state(state: &str) -> Result<&str, ApiError> {
    match state {
        "" => Ok("open"),
        "open" | "closed" | "all" => Ok(state),
        _ => Err(ApiError::bad_request("state must be open, closed or all")),
    }
}

async fn pr_view(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r) = numbered_scope(ctx, req, Resource::Pr, Action::Read)?;
    forward(r, "/pr/view", &auth, req).await
}

/// The conversation, the reviews and the comments on the diff, as one ordered list. Each of the
/// three is a separate GitHub endpoint, and reading one of them misses most of a review.
async fn pr_comments(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r) = numbered_scope(ctx, req, Resource::Pr, Action::Read)?;
    forward(r, "/pr/comments", &auth, req).await
}

/// #173: which files a pull request touches, and how much moved in each.
async fn pr_files(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r) = numbered_scope(ctx, req, Resource::Pr, Action::Read)?;
    forward(r, "/pr/files", &auth, req).await
}

/// #173: one file's patch, numbered the way `pr review --comment` wants.
async fn pr_diff(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r) = numbered_scope(ctx, req, Resource::Pr, Action::Read)?;
    forward(r, "/pr/diff", &auth, req).await
}

async fn pr_list(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    list_state(&req.state)?;
    let (auth, r) = repo_scope(ctx, req, Resource::Pr, Action::Read)?;
    forward(r, "/pr/list", &auth, req).await
}

/// One issue. GitHub serves pull requests from this endpoint too, so the answer says which it got
/// rather than presenting a PR as an issue; the payload is still returned.
async fn issue_view(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r) = numbered_scope(ctx, req, Resource::Issue, Action::Read)?;
    forward(r, "/issue/view", &auth, req).await
}

async fn issue_comments(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r) = numbered_scope(ctx, req, Resource::Issue, Action::Read)?;
    forward(r, "/issue/comments", &auth, req).await
}

async fn issue_list(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    list_state(&req.state)?;
    let (auth, r) = repo_scope(ctx, req, Resource::Issue, Action::Read)?;
    forward(r, "/issue/list", &auth, req).await
}

// ---- releases (0.2.6) ----

/// Create a release for a tag that the relay already let through. The tag has to exist upstream,
/// so this runs after `git push origin <tag>`; GitHub answers 422 when it does not.
async fn release_create(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(!req.tag.is_empty(), "tag is required")?;
    let (auth, r) = repo_scope(ctx, req, Resource::Release, Action::Create)?;
    forward(r, "/release/create", &auth, req).await
}

async fn release_view(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(!req.tag.is_empty(), "tag is required")?;
    let (auth, r) = repo_scope(ctx, req, Resource::Release, Action::Read)?;
    forward(r, "/release/view", &auth, req).await
}

async fn release_list(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r) = repo_scope(ctx, req, Resource::Release, Action::Read)?;
    forward(r, "/release/list", &auth, req).await
}

/// Publish a draft, or edit a release in place.
///
/// `release create --draft` used to be a door the agent could walk through and not come back from:
/// nothing could publish the draft afterwards. Editing while it stays a draft is `release:create`.
/// Taking it out of draft is `release:publish` — that is the boundary `--draft` exists to draw, and
/// folding it into `create` would erase it. Which of the two is demanded depends on the release's
/// current state, so the relay looks it up first and only asks for `release:publish` when the call
/// really does flip draft to false.
async fn release_edit(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(!req.tag.is_empty(), "tag is required")?;
    need(
        !req.title.is_empty()
            || !req.body.is_empty()
            || req.set_draft.is_some()
            || req.set_prerelease.is_some(),
        "one of title, notes, draft or prerelease is required",
    )?;
    // The floor for any edit. The lookup rides on it so that editing never needs release:read too.
    let base = ctx
        .project
        .authorize(&req.repo, Resource::Release, Action::Create)?;
    let r = relay(ctx, &base)?;
    let q = Query::ReleaseForEdit {
        tag: req.tag.clone(),
    };
    let current = match r.ask(&q, &base).await? {
        Answer::Release(found) => found,
        other => return Err(unexpected(&q, &other)),
    }
    .ok_or_else(|| ApiError::bad_request(format!("no release for tag {}", req.tag)))?;
    // Publishing is draft true → false. Anything else (staying a draft, or turning one back into a
    // draft) stays inside release:create.
    let publishing = current.draft && req.set_draft == Some(false);
    let auth = if publishing {
        ctx.project
            .authorize(&req.repo, Resource::Release, Action::Publish)?
    } else {
        base
    };
    let resolved = Resolved {
        release_id: current.id,
        publishing,
        ..Resolved::default()
    };
    relay(ctx, &auth)?
        .call("/release/edit", &[&auth], req, &resolved)
        .await
}

/// Re-run a workflow run, or only the jobs that failed.
///
/// `ci:rerun`, not a wider `ci:read`: a re-run spends the account's Actions minutes and executes
/// workflow code with the repository's secrets. Reading a log does neither.
async fn ci_rerun(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(req.run_id != 0, "run_id is required")?;
    let (auth, r) = repo_scope(ctx, req, Resource::Ci, Action::Rerun)?;
    forward(r, "/ci/rerun", &auth, req).await
}

async fn ci_cancel(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(req.run_id != 0, "run_id is required")?;
    let (auth, r) = repo_scope(ctx, req, Resource::Ci, Action::Rerun)?;
    forward(r, "/ci/cancel", &auth, req).await
}

// ---- Dependabot alerts (0.2.28, #132) ----

const ALERT_STATES: &[&str] = &["open", "dismissed", "fixed", "auto_dismissed", "all"];

async fn security_alerts(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    let state = if req.state.is_empty() {
        "open"
    } else {
        req.state.as_str()
    };
    need(
        ALERT_STATES.contains(&state),
        "state is one of open / dismissed / fixed / auto_dismissed / all",
    )?;
    let (auth, r) = repo_scope(ctx, req, Resource::Security, Action::Read)?;
    forward(r, "/security/alerts", &auth, req).await
}

async fn security_alert(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r) = numbered_scope(ctx, req, Resource::Security, Action::Read)?;
    forward(r, "/security/alert", &auth, req).await
}

async fn security_dismiss(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r) = numbered_scope(ctx, req, Resource::Security, Action::Dismiss)?;
    let resp = forward(r, "/security/dismiss", &auth, req).await?;
    // The generic api_ok line has the path; the reason is what a reader of the audit wants
    ctx.audit.log_edge(
        paths::DEV_RELAY_API,
        "security_alert_dismissed",
        Actor::Agent,
        &[
            ("repo", auth.repo()),
            ("number", &req.number.to_string()),
            ("reason", &req.reason),
            ("comment", &req.body),
        ],
    );
    Ok(resp)
}

/// The inverse of dismissing, under the same permission: `security:dismiss` already lets the
/// agent change an alert's state, and reopening is the less destructive direction.
async fn security_reopen(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r) = numbered_scope(ctx, req, Resource::Security, Action::Dismiss)?;
    let resp = forward(r, "/security/reopen", &auth, req).await?;
    ctx.audit.log_edge(
        paths::DEV_RELAY_API,
        "security_alert_reopened",
        Actor::Agent,
        &[("repo", auth.repo()), ("number", &req.number.to_string())],
    );
    Ok(resp)
}

async fn ci_runs(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        !req.git_ref.is_empty(),
        "ref (tag / branch / sha) is required",
    )?;
    let (auth, r) = repo_scope(ctx, req, Resource::Ci, Action::Read)?;
    forward(r, "/ci/runs", &auth, req).await
}

async fn ci_jobs(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 || req.run_id != 0,
        "number or run_id is required",
    )?;
    let (auth, r) = repo_scope(ctx, req, Resource::Ci, Action::Read)?;
    forward(r, "/ci/jobs", &auth, req).await
}

async fn ci_log(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r) = repo_scope(ctx, req, Resource::Ci, Action::Read)?;
    forward(r, "/ci/log", &auth, req).await
}

// ---- Issue ----

async fn issue_create(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(!req.title.is_empty(), "title is required")?;
    let (auth, r) = repo_scope(ctx, req, Resource::Issue, Action::Create)?;
    // Applying labels is a separate permission: issue:label is required to set them
    if req.labels.is_empty() {
        return forward(r, "/issue/create", &auth, req).await;
    }
    let label_auth = ctx
        .project
        .authorize(&req.repo, Resource::Issue, Action::Label)?;
    r.call(
        "/issue/create",
        &[&auth, &label_auth],
        req,
        &Resolved::default(),
    )
    .await
}

async fn issue_comment(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 && !req.body.is_empty(),
        "number and body are required",
    )?;
    let (auth, r, _) = numbered_write_scope(ctx, req, Action::Comment).await?;
    forward(r, "/issue/comment", &auth, req).await
}

/// 0.2.15: correct an issue's title or body.
///
/// A pull request is refused rather than reaching `pr:*`: `pr update` already edits one, and a
/// second way in under a different permission is the shape #52 was about.
async fn issue_update(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(
        !req.title.is_empty() || !req.body.is_empty(),
        "title or body is required",
    )?;
    let (auth, r) = numbered_scope(ctx, req, Resource::Issue, Action::Update)?;
    if names_a_pull_request(r, &auth, req.number).await? {
        return Err(ApiError::bad_request(format!(
            "#{} is a pull request; use sekimore pr update",
            req.number
        )));
    }
    forward(r, "/issue/update", &auth, req).await
}

async fn issue_close(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r, _) = numbered_write_scope(ctx, req, Action::Close).await?;
    forward(r, "/issue/close", &auth, req).await
}

async fn issue_reopen(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r, _) = numbered_write_scope(ctx, req, Action::Close).await?;
    forward(r, "/issue/reopen", &auth, req).await
}

async fn issue_label(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 && !req.labels.is_empty(),
        "number and labels are required",
    )?;
    let (auth, r, _) = numbered_write_scope(ctx, req, Action::Label).await?;
    forward(r, "/issue/label", &auth, req).await
}

/// Take labels off again. Adding and removing are one authority, `issue:label`.
async fn issue_unlabel(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 && !req.labels.is_empty(),
        "number and labels are required",
    )?;
    let (auth, r, _) = numbered_write_scope(ctx, req, Action::Label).await?;
    forward(r, "/issue/unlabel", &auth, req).await
}

async fn issue_assign(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 && !req.assignees.is_empty(),
        "number and assignees are required",
    )?;
    let (auth, r, _) = numbered_write_scope(ctx, req, Action::Assign).await?;
    forward(r, "/issue/assign", &auth, req).await
}

async fn issue_unassign(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 && !req.assignees.is_empty(),
        "number and assignees are required",
    )?;
    let (auth, r, _) = numbered_write_scope(ctx, req, Action::Assign).await?;
    forward(r, "/issue/unassign", &auth, req).await
}

// ---- task-list boxes (#345) ----

/// `issue tasks` / `pr tasks`: every box in the body or a comment, with the id `check --id` takes.
async fn task_list(
    ctx: &ApiContext,
    req: &ApiRequest,
    resource: Resource,
) -> Result<ApiResponse, ApiError> {
    let (auth, r) = numbered_scope(ctx, req, resource, Action::Read)?;
    need(
        !req.inline || resource == Resource::Pr,
        "--inline names a line comment, and only a pull request has those",
    )?;
    let op = if resource == Resource::Pr {
        "/pr/tasks"
    } else {
        "/issue/tasks"
    };
    forward(r, op, &auth, req).await
}

/// `issue check` / `pr check`: tick or untick one box, and nothing else.
///
/// The number decides the key, as for closing: a box on a pull request is `pr:check` whichever
/// command was typed. The relay picks the item by its text (narrowed by heading and parent, never
/// by position), flips the one mark, and writes it back only when that is the whole difference and
/// nobody changed the text meanwhile. The audit is written here, from what the relay reports.
async fn task_check(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(req.number != 0, "number is required")?;
    need(
        !req.task_match.trim().is_empty() || !req.task_id.trim().is_empty(),
        "--match <text> is required (or --id from `tasks`): the item, as `issue tasks` / `pr tasks` list it",
    )?;
    let (auth, r, target) = numbered_write_scope(ctx, req, Action::Check).await?;
    need(
        !req.inline || target == Numbered::PullRequest,
        "--inline names a line comment, and only a pull request has those",
    )?;
    let op = match target {
        Numbered::PullRequest => "/pr/check",
        Numbered::Issue => "/issue/check",
    };
    let resp = forward(r, op, &auth, req).await?;
    let done = resp.raw.as_ref();
    if done.and_then(|v| v.get("changed")).and_then(Value::as_bool) == Some(true) {
        let field = |k: &str| {
            done.and_then(|v| v.get(k))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        // The generic api_ok line has the path; the item and its new state are what a reader wants
        let comment_id = if req.comment_id != 0 {
            req.comment_id.to_string()
        } else {
            String::new()
        };
        ctx.audit.log_edge(
            paths::DEV_RELAY_API,
            "task_checked",
            Actor::Agent,
            &[
                ("repo", auth.repo()),
                ("number", &req.number.to_string()),
                ("comment", &comment_id),
                ("item", &field("item")),
                ("heading", &field("heading")),
                ("checked", if req.uncheck { "false" } else { "true" }),
            ],
        );
    }
    Ok(resp)
}

// ---- Projects ----

/// The four Projects operations share their shape: the project-anchored scope, then the board the
/// request names, checked and resolved, then the relay of the board's upstream.
async fn board_op(
    ctx: &ApiContext,
    op: &str,
    req: &ApiRequest,
    action: Action,
) -> Result<ApiResponse, ApiError> {
    let (auth, _) = project_scope(ctx, req, Resource::Project, action)?;
    let (resolved, r) = board_scope(ctx, req, &auth).await?;
    r.call(op, &[&auth], req, &resolved).await
}

async fn project_add_item(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.content_id.is_empty(), "content_id is required")?;
    board_op(ctx, "/project/add-item", req, Action::AddItem).await
}

async fn project_update_item(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(
        !req.item_id.is_empty() && !req.field_id.is_empty(),
        "item_id and field_id are required",
    )?;
    board_op(ctx, "/project/update-item", req, Action::UpdateItem).await
}

async fn project_list(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, _) = project_scope(ctx, req, Resource::Project, Action::Read)?;
    let (resolved, r) = board_scope(ctx, req, &auth).await?;
    // #344: above GitHub's page size used to fall back to 20 without a word, which read as "the
    // board has 20 items". Said instead, with the ways to get more.
    need(
        req.first <= PROJECT_PAGE,
        "--first is at most 100 (one page); --all reads every page, --after <cursor> the next one",
    )?;
    if !req.all {
        return r.call("/project/list", &[&auth], req, &resolved).await;
    }
    // `--all`: every page, oldest first, folded into one answer of the same shape. Bounded, like
    // the review threads (#315): a board past this is answered as far as it goes, with the cursor
    // to carry on from. The relay answers one page at a time; the folding is here
    let mut page_req = req.clone();
    page_req.all = false;
    page_req.first = PROJECT_PAGE;
    let mut raw = r
        .call("/project/list", &[&auth], &page_req, &resolved)
        .await?
        .raw
        .unwrap_or(Value::Null);
    let mut nodes: Vec<Value> = raw
        .pointer("/data/node/items/nodes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut page = raw.pointer("/data/node/items/pageInfo").cloned();
    while nodes.len() < PROJECT_ALL_MAX {
        let next = page
            .as_ref()
            .filter(|p| p.get("hasNextPage").and_then(Value::as_bool) == Some(true))
            .and_then(|p| p.get("endCursor").and_then(Value::as_str))
            .map(str::to_string);
        let Some(cursor) = next else { break };
        page_req.after = cursor;
        let more = r
            .call("/project/list", &[&auth], &page_req, &resolved)
            .await?
            .raw
            .unwrap_or(Value::Null);
        nodes.extend(
            more.pointer("/data/node/items/nodes")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        );
        page = more.pointer("/data/node/items/pageInfo").cloned();
    }
    if let Some(items) = raw.pointer_mut("/data/node/items") {
        items["nodes"] = Value::Array(nodes);
        if let Some(p) = page {
            items["pageInfo"] = p;
        }
    }
    Ok(ApiResponse {
        raw: Some(raw),
        ..Default::default()
    })
}

/// GitHub's page size for a board's items.
const PROJECT_PAGE: u32 = 100;
/// How many items `project list --all` reads before it stops and hands back the cursor.
const PROJECT_ALL_MAX: usize = 1000;

/// 0.2.7: the board's fields and their option ids, which `project update-item` needs.
async fn project_fields(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    board_op(ctx, "/project/fields", req, Action::Read).await
}

/// 0.2.7: ask people to review a pull request.
async fn pr_request_review(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(req.number != 0, "number is required")?;
    need(
        !req.reviewers.is_empty() || !req.team_reviewers.is_empty(),
        "at least one reviewer or team is required",
    )?;
    let (auth, r) = repo_scope(ctx, req, Resource::Pr, Action::RequestReview)?;
    forward(r, "/pr/request-review", &auth, req).await
}

/// 0.2.7: search issues and pull requests across the project.
///
/// A search names no repository, so the policy anchor is the project's first one, the same way
/// Projects does it. What keeps the answer inside the project is the `repo:` scoping and the filter
/// applied to the results, both over the repositories handed to the relay here.
async fn search_issues(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.query.is_empty(), "query is required")?;
    let (auth, r) = project_scope(ctx, req, Resource::Search, Action::Read)?;
    let resolved = Resolved {
        repos: ctx
            .project
            .repos
            .iter()
            .map(|r| r.full_name.clone())
            .collect(),
        ..Resolved::default()
    };
    r.call("/search/issues", &[&auth], req, &resolved).await
}

/// 0.2.9: the labels, assignees and milestones a repository defines, so `issue label` and
/// `issue assign` can use a value that exists instead of guessing at one.
async fn repo_vocabulary(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, r) = repo_scope(ctx, req, Resource::Repo, Action::Read)?;
    forward(r, "/repo/vocabulary", &auth, req).await
}

// ---- Bootstrap (unauthenticated) ----

pub async fn bootstrap(
    ctx: &ApiContext,
    req: Request<Incoming>,
    peer_ip: &str,
) -> Result<BootstrapResponse, ApiError> {
    if ctx.bootstrap == BootstrapMode::Manual {
        ctx.audit.deny_edge(
            paths::DEV_RELAY_API,
            "bootstrap_denied",
            Actor::Agent,
            "bootstrap is manual",
            &[("peer", peer_ip)],
        );
        return Err(ApiError { status: StatusCode::NOT_FOUND, message: "bootstrap is disabled (relay.bootstrap: manual); ask the operator to run `docker compose exec sekimore-gw sekimore-relay add-key` and `... token` on the host running docker".into() });
    }
    if ctx.bootstrap_disabled_path.exists() {
        ctx.audit.deny_edge(
            paths::DEV_RELAY_API,
            "bootstrap_denied",
            Actor::Agent,
            "kill-switch",
            &[("peer", peer_ip)],
        );
        return Err(ApiError::forbidden(
            "bootstrap is disabled by the operator (sekimore-relay bootstrap enable to re-allow)",
        ));
    }
    if !ctx.bootstrap_rate_ok() {
        ctx.audit.deny_edge(
            paths::DEV_RELAY_API,
            "bootstrap_denied",
            Actor::Agent,
            "rate limited",
            &[("peer", peer_ip)],
        );
        return Err(ApiError {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "too many bootstrap requests; retry later".into(),
        });
    }
    let body = read_body(req, ctx.body_cap).await?;
    let breq: BootstrapRequest = serde_json::from_slice(&body).map_err(|e| {
        ctx.audit.deny_edge(
            paths::DEV_RELAY_API,
            "bootstrap_denied",
            Actor::Agent,
            &format!("invalid JSON: {e}"),
            &[("peer", peer_ip)],
        );
        ApiError::bad_request(format!("invalid JSON: {e}"))
    })?;
    let added = ctx.keys.add(&breq.public_key).map_err(|e| {
        ctx.audit.deny_edge(
            paths::DEV_RELAY_API,
            "bootstrap_denied",
            Actor::Agent,
            &e.to_string(),
            &[("peer", peer_ip)],
        );
        ApiError::bad_request(e.to_string())
    })?;
    let (fingerprint, is_new) = match added {
        Added::New { fingerprint } => (fingerprint, true),
        Added::AlreadyPresent { fingerprint } => (fingerprint, false),
    };
    // A re-bootstrap from the same key (e.g. after the container is recreated) revokes the previous token: one valid token per key
    let revoked_previous = ctx.tokens.revoke_by_fingerprint(&fingerprint).unwrap_or(0);
    let (token, rec) = ctx
        .tokens
        .issue_for(&ctx.project.name, ctx.token_ttl, Some(&fingerprint))
        .map_err(|e| ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("cannot issue token: {e}"),
        })?;
    let label = breq.label.unwrap_or_default();
    ctx.audit.log_edge(
        paths::DEV_RELAY_API,
        "bootstrap_ok",
        Actor::Agent,
        &[
            ("fingerprint", &fingerprint),
            ("key_added", if is_new { "true" } else { "false" }),
            ("token_label", &rec.label),
            ("revoked_previous", &revoked_previous.to_string()),
            ("client_label", &label),
            ("peer", peer_ip),
        ],
    );
    Ok(BootstrapResponse {
        ok: true,
        error: None,
        fingerprint: Some(fingerprint),
        added: is_new,
        token: Some(token),
        token_expires: Some(humantime::format_rfc3339_seconds(rec.expires_at).to_string()),
        project: Some(ctx.project.name.clone()),
        repos: ctx
            .project
            .repos
            .iter()
            .map(|r| r.full_name.clone())
            .collect(),
        git_domain: Some(ctx.git_domain.clone()),
        upstream: Some(ctx.upstream.clone()),
        git_domains: ctx.git_domains.clone(),
        signing: signing_block(ctx).await,
    })
}

/// The signing block for `/bootstrap`, or nothing when the gateway has no key to offer.
///
/// Asked of the agent on every request rather than cached: the operator may load the key into the
/// host agent after the gateway is already up, and `agent-setup.sh` runs on every container start.
async fn signing_block(ctx: &ApiContext) -> Option<SigningBlock> {
    let id = ctx.signing.as_ref()?.identity().await?;
    Some(SigningBlock {
        socket: id.socket.display().to_string(),
        fingerprint: id.fingerprint,
        namespace: id.namespace,
        public_key: id.public_key,
        mode: strictest_signing(&ctx.project).as_str().to_string(),
    })
}

/// The strictest `signing` any repository in the project asks for.
///
/// One answer for the whole container, because `agent-setup.sh` writes one git configuration and
/// one guide. Taking the strictest means an agent is never told less than some repository it can
/// push to demands.
fn strictest_signing(project: &crate::policy::Project) -> SigningMode {
    if project
        .repos
        .iter()
        .any(|r| r.signing == SigningMode::Required)
    {
        SigningMode::Required
    } else if project
        .repos
        .iter()
        .any(|r| r.signing == SigningMode::Optional)
    {
        SigningMode::Optional
    } else {
        SigningMode::Off
    }
}

#[allow(dead_code)]
fn now() -> SystemTime {
    SystemTime::now()
}
