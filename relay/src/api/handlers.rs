//! The individual endpoints. Each checks the request's required fields, obtains proof via `Project::authorize`, and passes it to `GitHub`.

use std::time::SystemTime;

use hyper::body::Incoming;
use hyper::{Request, StatusCode};
use serde_json::Value;

use super::types::{ApiRequest, ApiResponse, BootstrapRequest, BootstrapResponse, SigningBlock};
use super::{read_body, ApiContext, ApiError};
use crate::audit::Actor;
use crate::config::BootstrapMode;
use crate::github::GitHub;
use crate::github::SecurityAlert;
use crate::policy::SigningMode;
use crate::policy::{Action, Authorized, Mode, Resource};
use crate::ssh::authorized_keys::Added;
use crate::tokens::TokenRecord;

/// The GitHub client for the upstream of the repo the proof refers to (each upstream has its own token and API base. 0.2.0).
fn gh<'a>(ctx: &'a ApiContext, auth: &Authorized<'_>) -> Result<&'a GitHub, ApiError> {
    let host = ctx.project.host_of(auth.policy());
    let key = if host.is_empty() {
        ctx.git_domain.as_str()
    } else {
        host
    };
    ctx.githubs
        .get(key)
        .map(|g| g.as_ref())
        .ok_or_else(|| ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: format!("upstream API for {key} is not configured on the gateway"),
        })
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

/// The preamble every repo-scoped handler shares: check the repo, ask the policy, pick the client
/// for that repo's upstream.
///
/// Resource and action stay arguments rather than being inferred from anything, because this is
/// the security boundary: the permission a handler demands has to be readable at the handler, not
/// looked up somewhere else. What is hidden here is only the mechanical part — the empty-string
/// check and which `GitHub` the proof belongs to.
fn repo_scope<'a>(
    ctx: &'a ApiContext,
    req: &'a ApiRequest,
    resource: Resource,
    action: Action,
) -> Result<(Authorized<'a>, &'a GitHub), ApiError> {
    need_repo(req)?;
    let auth = ctx.project.authorize(&req.repo, resource, action)?;
    let client = gh(ctx, &auth)?;
    Ok((auth, client))
}

/// As `repo_scope`, plus the `number is required` guard.
fn numbered_scope<'a>(
    ctx: &'a ApiContext,
    req: &'a ApiRequest,
    resource: Resource,
    action: Action,
) -> Result<(Authorized<'a>, &'a GitHub), ApiError> {
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
) -> Result<(Authorized<'a>, &'a GitHub, Numbered), ApiError> {
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
    let client = gh(ctx, &probe)?;
    let target = if client.names_a_pull_request(&probe, req.number).await? {
        Numbered::PullRequest
    } else {
        Numbered::Issue
    };
    let auth = ctx
        .project
        .authorize(&req.repo, target.resource(), action)?;
    Ok((auth, client, target))
}

/// As `repo_scope`, but anchored on the project rather than a named repo (Projects v2 and search
/// carry no repository of their own).
fn project_scope<'a>(
    ctx: &'a ApiContext,
    req: &'a ApiRequest,
    resource: Resource,
    action: Action,
) -> Result<(Authorized<'a>, &'a GitHub), ApiError> {
    let anchor = project_anchor(ctx, req)?;
    let auth = ctx.project.authorize(anchor, resource, action)?;
    let client = gh(ctx, &auth)?;
    Ok((auth, client))
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
async fn resolve_board(
    ctx: &ApiContext,
    gh: &GitHub,
    req: &ApiRequest,
) -> Result<String, ApiError> {
    if ctx.project_boards.is_declared_empty() {
        return Err(ApiError::forbidden(
            "no project board is allowed; add relay.project.boards (the org / user and the number from the board's URL)",
        ));
    }
    let boards = ctx.project_boards.get(gh).await;
    if boards.is_empty() {
        // Declared but not resolvable. Saying "add relay.project.boards" here would send the
        // operator to a file that already has it; the usual reason is a locked secret store,
        // since resolving needs the upstream token (#99).
        return Err(ApiError::forbidden(
            "the project's boards are declared but could not be resolved; the relay needs the              upstream API token for that, so a locked secret store is the usual reason.              Ask a human to run: mise run gw:unlock",
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
            .map(|b| b.id.clone())
            .ok_or_else(|| {
                ApiError::forbidden(format!(
                    "project board {n} is not in this project; this project has {}",
                    board_choices(&boards)
                ))
            }),
        (false, None) => boards
            .iter()
            .find(|b| b.id == id)
            .map(|b| b.id.clone())
            .ok_or_else(|| {
                ApiError::forbidden(format!("project board {id} is not in this project"))
            }),
        (true, None) => match boards.as_slice() {
            [only] => Ok(only.id.clone()),
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
        "/pr/create" => pr_create(ctx, req).await,
        "/pr/comment" => pr_comment(ctx, req).await,
        "/pr/reply" => pr_reply(ctx, req).await,
        "/pr/comment-edit" => comment_edit(ctx, req).await,
        "/pr/comment-delete" => comment_delete(ctx, req).await,
        "/issue/comment-edit" => comment_edit(ctx, req).await,
        "/issue/comment-delete" => comment_delete(ctx, req).await,
        "/pr/draft" => pr_draft(ctx, req).await,
        "/ci/dispatch" => ci_dispatch(ctx, req).await,
        "/pr/review" => pr_review(ctx, req).await,
        "/pr/merge" => pr_merge(ctx, req).await,
        "/pr/close" => pr_close(ctx, req).await,
        "/pr/reopen" => pr_reopen(ctx, req).await,
        "/pr/update" => pr_update(ctx, req).await,
        "/pr/status" => pr_status(ctx, req).await,
        "/pr/view" => pr_view(ctx, req).await,
        "/pr/comments" => pr_comments(ctx, req).await,
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
    let msg = format!(
        "project={} token={} expires={}\npermissions (every repo; a repo line's +/- adds or removes): {}{signing}\nrepos:\n  {}",
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
    let pr = gh(ctx, &auth)?
        .create_pull_request(
            &auth,
            &req.head,
            &req.base,
            &req.title,
            &req.body,
            req.pr_draft,
        )
        .await?;
    Ok(ApiResponse {
        number: Some(pr.number),
        url: Some(pr.html_url),
        node_id: Some(pr.node_id),
        ..Default::default()
    })
}

async fn pr_comment(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 && !req.body.is_empty(),
        "number and body are required",
    )?;
    let (auth, client) = repo_scope(ctx, req, Resource::Pr, Action::Comment)?;
    client
        .comment_pull_request(&auth, req.number, &req.body)
        .await?;
    Ok(ApiResponse::default())
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
    let (auth, client) = repo_scope(ctx, req, Resource::Pr, Action::Comment)?;
    client
        .reply_to_review_comment(&auth, req.number, req.comment_id, &req.body)
        .await?;
    Ok(ApiResponse::default())
}

/// #169: offer a draft for review, or put one back. `pr:create` rather than a key of its own —
/// an agent that may open a ready pull request can already reach this state directly.
async fn pr_draft(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(req.number != 0, "number is required")?;
    let (auth, client) = repo_scope(ctx, req, Resource::Pr, Action::Create)?;
    client
        .set_pull_request_draft(&auth, req.number, req.pr_draft)
        .await?;
    Ok(ApiResponse {
        message: Some(format!(
            "PR #{} is now {}",
            req.number,
            if req.pr_draft {
                "a draft"
            } else {
                "ready for review"
            }
        )),
        ..Default::default()
    })
}

/// #168: start a workflow that has not run. `ci:dispatch`, not `ci:rerun`: a re-run repeats what
/// already happened here, while this can start a deploy on a ref of the agent's choosing.
async fn ci_dispatch(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        !req.workflow.is_empty() && !req.git_ref.is_empty(),
        "workflow and ref are required",
    )?;
    let (auth, client) = repo_scope(ctx, req, Resource::Ci, Action::Dispatch)?;
    client
        .dispatch_workflow(&auth, &req.workflow, &req.git_ref, &req.inputs)
        .await?;
    Ok(ApiResponse {
        message: Some(format!(
            "dispatched {} on {}; find the run with `ci runs --ref {}`",
            req.workflow, req.git_ref, req.git_ref
        )),
        ..Default::default()
    })
}

/// #172: the permission follows what the number names, not which command was typed. GitHub keeps
/// the conversation on a pull request and on an issue in one namespace, so `pr comment-edit`
/// taken at its word would let `pr:comment_update` rewrite an issue comment a project meant to
/// keep behind `issue:comment_update`. The comment is then checked to sit on that number.
async fn comment_scope<'a>(
    ctx: &'a ApiContext,
    req: &'a ApiRequest,
    action: Action,
) -> Result<(Authorized<'a>, &'a GitHub), ApiError> {
    need(req.comment_id != 0, "comment-id is required")?;
    let (auth, client, target) = numbered_write_scope(ctx, req, action).await?;
    // A line comment exists only on a pull request; the pulls endpoint is outside issue:*
    need(
        !req.inline || target == Numbered::PullRequest,
        "--inline names a line comment, and only a pull request has those",
    )?;
    Ok((auth, client))
}

async fn comment_edit(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.body.is_empty(), "body is required")?;
    let (auth, client) = comment_scope(ctx, req, Action::CommentUpdate).await?;
    client
        .update_comment(&auth, req.number, req.inline, req.comment_id, &req.body)
        .await?;
    Ok(ApiResponse::default())
}

async fn comment_delete(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = comment_scope(ctx, req, Action::CommentDelete).await?;
    client
        .delete_comment(&auth, req.number, req.inline, req.comment_id)
        .await?;
    Ok(ApiResponse::default())
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
    let (auth, client) = repo_scope(ctx, req, Resource::Pr, Action::Review)?;
    client
        .review_pull_request(&auth, req.number, &req.event, &req.body, &req.comments)
        .await?;
    Ok(ApiResponse::default())
}

/// Nothing, or the string — so a handler can tell "leave it alone" from "set it to empty".
fn opt(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

async fn pr_merge(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(req.number != 0, "number is required")?;
    // A typo here would otherwise become an upstream 422; catch it before spending a call.
    need(
        req.method.is_empty() || matches!(req.method.as_str(), "merge" | "squash" | "rebase"),
        "method must be merge, squash or rebase",
    )?;
    let (auth, client) = repo_scope(ctx, req, Resource::Pr, Action::Merge)?;
    // `delete_merged_branch` was declared as a repo policy and never enforced. It is the operator's
    // switch for exactly this, so the agent asking is necessary but not sufficient.
    if req.delete_branch && !auth.policy().delete_merged_branch {
        return Err(ApiError::forbidden(format!(
            "deleting the merged branch is not allowed for {} (set delete_merged_branch)",
            auth.repo()
        )));
    }
    let res = client
        .merge_pull_request(
            &auth,
            req.number,
            opt(&req.method),
            opt(&req.title),
            opt(&req.body),
            req.delete_branch,
        )
        .await?;
    let msg = format!(
        "merged #{}{}{}",
        req.number,
        if req.method.is_empty() {
            String::new()
        } else {
            format!(" ({})", req.method)
        },
        if res.branch_deleted {
            format!(", deleted {}", res.branch)
        } else {
            String::new()
        }
    );
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(msg),
        raw: serde_json::to_value(&res).ok(),
        ..ApiResponse::ok()
    })
}

async fn pr_close(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = numbered_scope(ctx, req, Resource::Pr, Action::Close)?;
    client.close_pull_request(&auth, req.number).await?;
    Ok(ApiResponse::default())
}

/// The inverse of closing, under the same permission: `pr:close` already lets the agent change the
/// state, and reopening is the less destructive direction.
async fn pr_reopen(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = numbered_scope(ctx, req, Resource::Pr, Action::Close)?;
    client.reopen_pull_request(&auth, req.number).await?;
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(format!("reopened #{}", req.number)),
        ..ApiResponse::ok()
    })
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
    gh(ctx, &auth)?
        .update_pull_request(
            &auth,
            req.number,
            opt(&req.title),
            opt(&req.body),
            opt(&req.base),
        )
        .await?;
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(format!("updated #{}", req.number)),
        ..ApiResponse::ok()
    })
}

async fn pr_status(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = numbered_scope(ctx, req, Resource::Pr, Action::Read)?;
    let st = client.pull_request_status(&auth, req.number).await?;
    let raw = serde_json::to_value(&st).unwrap_or(serde_json::Value::Null);
    let n = st.checks.len();
    let msg = format!(
        "PR #{} [{}{}] checks: {} ({} total)",
        st.number,
        st.state,
        if st.merged { ", merged" } else { "" },
        st.rollup,
        n
    );
    Ok(ApiResponse {
        ok: true,
        number: Some(st.number),
        raw: Some(raw),
        message: Some(msg),
        ..Default::default()
    })
}

// ---- reading pull requests and issues (0.2.8) ----

/// How many to fetch: the agent's number, clamped, or the default when it asked for nothing.
fn limit_or(first: u32, default: u32) -> u32 {
    if first == 0 {
        default
    } else {
        first.clamp(1, 100)
    }
}

/// The three values GitHub accepts. Anything else is the agent's mistake, not an upstream error.
fn list_state(state: &str) -> Result<&str, ApiError> {
    match state {
        "" => Ok("open"),
        "open" | "closed" | "all" => Ok(state),
        _ => Err(ApiError::bad_request("state must be open, closed or all")),
    }
}

/// Render one discussion entry. The body is whatever a human wrote: it is printed, never parsed.
/// #165: a review is one submission — a verdict, a body, and the line comments that came with
/// it — so it is shown as one thing, with its comments nested under it. Flat and sorted by time,
/// which is what this did before, left the reader to guess which comment belonged to which
/// review, and two reviewers landing in the same second made that guess unreliable.
fn comment_lines(items: &[crate::github::CommentItem]) -> String {
    // The date alone is enough to follow a discussion; the time is in the JSON.
    let day =
        |c: &crate::github::CommentItem| c.created_at.split('T').next().unwrap_or("").to_string();
    // Where an inline comment sits, and the id `pr reply` needs. The id appears only on the
    // lines that can be answered, so its presence is what says a reply is possible.
    let inline_tail = |c: &crate::github::CommentItem| {
        let where_ = match (&c.path, c.line) {
            (Some(p), Some(l)) => format!("{p}:{l}"),
            (Some(p), None) => p.clone(),
            _ => "[inline]".to_string(),
        };
        match c.id {
            Some(id) => format!("{where_}  #{id}"),
            None => where_,
        }
    };

    let mut out = String::new();
    let mut first = true;
    for c in items {
        match c.kind.as_str() {
            // An inline comment is printed under its review, below; one that belongs to no
            // review (a reply posted on its own) is printed where it falls.
            "inline" if c.review_id.is_some() => continue,
            // A review without an id cannot own anything: matching on None would make every
            // parentless inline comment belong to it, and to every other such review too.
            "review" | "review_envelope"
                if c.review_id.is_none() && c.kind == "review_envelope" =>
            {
                continue
            }
            "review" | "review_envelope" => {
                let children: Vec<_> = match c.review_id {
                    Some(rid) => items
                        .iter()
                        .filter(|x| x.kind == "inline" && x.review_id == Some(rid))
                        .collect(),
                    None => Vec::new(),
                };
                // An envelope exists only to hold line comments; with none it says nothing.
                if c.kind == "review_envelope" && children.is_empty() {
                    continue;
                }
                if !first {
                    out.push('\n');
                }
                out.push_str(&format!(
                    "{} {:<6} review {}\n",
                    day(c),
                    c.author,
                    c.state.clone().unwrap_or_default()
                ));
                for line in c.body.lines() {
                    out.push_str(&format!("  {line}\n"));
                }
                for ch in children {
                    out.push_str(&format!("    {}\n", inline_tail(ch)));
                    for line in ch.body.lines() {
                        out.push_str(&format!("      {line}\n"));
                    }
                }
            }
            _ => {
                let tail = if c.kind == "inline" {
                    inline_tail(c)
                } else {
                    "[comment]".to_string()
                };
                if !first {
                    out.push('\n');
                }
                out.push_str(&format!("{} {:<6} {tail}\n", day(c), c.author));
                for line in c.body.lines() {
                    out.push_str(&format!("  {line}\n"));
                }
            }
        }
        first = false;
    }
    out.trim_end().to_string()
}

async fn pr_view(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = numbered_scope(ctx, req, Resource::Pr, Action::Read)?;
    let pr = client.pull_request_view(&auth, req.number).await?;
    let state = if pr.merged {
        "merged".to_string()
    } else if pr.draft {
        format!("{}, draft", pr.state)
    } else {
        pr.state.clone()
    };
    let msg = format!(
        "#{} {} [{}] {} ← {} by {}\n{} files +{} -{}, {} comments ({} on the diff)\n{}\n\n{}",
        pr.number,
        pr.title,
        state,
        pr.base,
        pr.head,
        pr.author,
        pr.changed_files,
        pr.additions,
        pr.deletions,
        pr.comments,
        pr.review_comments,
        pr.html_url,
        pr.body
    );
    Ok(ApiResponse {
        number: Some(pr.number),
        url: Some(pr.html_url.clone()),
        message: Some(msg.trim_end().to_string()),
        raw: serde_json::to_value(&pr).ok(),
        ..ApiResponse::ok()
    })
}

/// The conversation, the reviews and the comments on the diff, as one ordered list. Each of the
/// three is a separate GitHub endpoint, and reading one of them misses most of a review.
async fn pr_comments(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = numbered_scope(ctx, req, Resource::Pr, Action::Read)?;
    let items = client
        .pull_request_comments(&auth, req.number, limit_or(req.first, 30))
        .await?;
    let msg = if items.is_empty() {
        format!("no comments on PR #{}", req.number)
    } else {
        comment_lines(&items)
    };
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(msg),
        raw: serde_json::to_value(&items).ok(),
        ..ApiResponse::ok()
    })
}

async fn pr_list(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    let state = list_state(&req.state)?;
    let (auth, client) = repo_scope(ctx, req, Resource::Pr, Action::Read)?;
    let prs = client
        .list_pull_requests(
            &auth,
            state,
            if req.base.is_empty() {
                None
            } else {
                Some(&req.base)
            },
            limit_or(req.first, 20),
        )
        .await?;
    let msg = if prs.is_empty() {
        format!("no {state} pull requests")
    } else {
        prs.iter()
            .map(|p| {
                format!(
                    "#{} [{}{}] {} ({}, {} ← {})",
                    p.number,
                    p.state,
                    if p.draft { ", draft" } else { "" },
                    p.title,
                    p.author,
                    p.base,
                    p.head
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok(ApiResponse {
        message: Some(msg),
        raw: serde_json::to_value(&prs).ok(),
        ..ApiResponse::ok()
    })
}

/// One issue. GitHub serves pull requests from this endpoint too, so the answer says which it got
/// rather than presenting a PR as an issue; the payload is still returned.
async fn issue_view(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = numbered_scope(ctx, req, Resource::Issue, Action::Read)?;
    let iss = client.issue_view(&auth, req.number).await?;
    let mut msg = format!(
        "#{} {} [{}] by {}",
        iss.number, iss.title, iss.state, iss.author
    );
    if !iss.labels.is_empty() {
        msg.push_str(&format!("\nlabels: {}", iss.labels.join(", ")));
    }
    if !iss.assignees.is_empty() {
        msg.push_str(&format!("\nassignees: {}", iss.assignees.join(", ")));
    }
    msg.push_str(&format!("\n{} comments\n{}", iss.comments, iss.html_url));
    if iss.is_pull_request {
        msg.push_str("\nthis is a pull request, not an issue: sekimore pr view --number ");
        msg.push_str(&iss.number.to_string());
    }
    if !iss.body.is_empty() {
        msg.push_str(&format!("\n\n{}", iss.body));
    }
    Ok(ApiResponse {
        number: Some(iss.number),
        url: Some(iss.html_url.clone()),
        message: Some(msg),
        raw: serde_json::to_value(&iss).ok(),
        ..ApiResponse::ok()
    })
}

async fn issue_comments(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = numbered_scope(ctx, req, Resource::Issue, Action::Read)?;
    let items = client
        .issue_comments(&auth, req.number, limit_or(req.first, 30))
        .await?;
    let msg = if items.is_empty() {
        format!("no comments on issue #{}", req.number)
    } else {
        comment_lines(&items)
    };
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(msg),
        raw: serde_json::to_value(&items).ok(),
        ..ApiResponse::ok()
    })
}

async fn issue_list(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    let state = list_state(&req.state)?;
    let (auth, client) = repo_scope(ctx, req, Resource::Issue, Action::Read)?;
    let issues = client
        .list_issues(
            &auth,
            state,
            &req.labels,
            if req.assignee.is_empty() {
                None
            } else {
                Some(&req.assignee)
            },
            limit_or(req.first, 20),
        )
        .await?;
    let msg = if issues.is_empty() {
        format!("no {state} issues")
    } else {
        issues
            .iter()
            .map(|i| {
                format!(
                    "#{} [{}] {} ({}, {} comments)",
                    i.number, i.state, i.title, i.author, i.comments
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok(ApiResponse {
        message: Some(msg),
        raw: serde_json::to_value(&issues).ok(),
        ..ApiResponse::ok()
    })
}

// ---- releases (0.2.6) ----

/// Create a release for a tag that the relay already let through. The tag has to exist upstream,
/// so this runs after `git push origin <tag>`; GitHub answers 422 when it does not.
async fn release_create(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(!req.tag.is_empty(), "tag is required")?;
    // Without notes of its own a release would be empty, so ask GitHub to write them.
    let generate = req.generate_notes || req.body.is_empty();
    let (auth, client) = repo_scope(ctx, req, Resource::Release, Action::Create)?;
    let rel = client
        .create_release(
            &auth,
            &req.tag,
            if req.title.is_empty() {
                None
            } else {
                Some(&req.title)
            },
            if req.body.is_empty() {
                None
            } else {
                Some(&req.body)
            },
            generate,
            req.draft,
            req.prerelease,
        )
        .await?;
    let state = if rel.draft { " (draft)" } else { "" };
    Ok(ApiResponse {
        number: Some(rel.id),
        url: Some(rel.html_url.clone()),
        message: Some(format!("created release {}{}", rel.tag_name, state)),
        raw: serde_json::to_value(&rel).ok(),
        ..Default::default()
    })
}

async fn release_view(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(!req.tag.is_empty(), "tag is required")?;
    let (auth, client) = repo_scope(ctx, req, Resource::Release, Action::Read)?;
    match client.get_release_by_tag(&auth, &req.tag).await? {
        Some(rel) => Ok(ApiResponse {
            number: Some(rel.id),
            url: Some(rel.html_url.clone()),
            message: Some(format!(
                "{}{} {}",
                rel.tag_name,
                if rel.draft { " (draft)" } else { "" },
                rel.html_url
            )),
            raw: serde_json::to_value(&rel).ok(),
            ..Default::default()
        }),
        None => Ok(ApiResponse {
            message: Some(format!("no release for tag {}", req.tag)),
            ..ApiResponse::ok()
        }),
    }
}

async fn release_list(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = repo_scope(ctx, req, Resource::Release, Action::Read)?;
    let limit = if req.first == 0 { 20 } else { req.first };
    let rels = client.list_releases(&auth, limit).await?;
    let msg = rels
        .iter()
        .map(|r| {
            format!(
                "{}{}{} {}",
                r.tag_name,
                if r.draft { " [draft]" } else { "" },
                if r.prerelease { " [prerelease]" } else { "" },
                r.html_url
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(ApiResponse {
        message: Some(msg),
        raw: serde_json::to_value(&rels).ok(),
        ..ApiResponse::ok()
    })
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
    let client = gh(ctx, &base)?;
    let current = client
        .get_release_for_edit(&base, &req.tag)
        .await?
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
    let rel = gh(ctx, &auth)?
        .update_release(
            &auth,
            current.id,
            publishing,
            opt(&req.title),
            opt(&req.body),
            req.set_draft,
            req.set_prerelease,
        )
        .await?;
    Ok(ApiResponse {
        number: Some(rel.id),
        url: Some(rel.html_url.clone()),
        message: Some(format!(
            "{} {}{}",
            if publishing { "published" } else { "updated" },
            rel.tag_name,
            if rel.draft { " (draft)" } else { "" }
        )),
        raw: serde_json::to_value(&rel).ok(),
        ..ApiResponse::ok()
    })
}

/// Re-run a workflow run, or only the jobs that failed.
///
/// `ci:rerun`, not a wider `ci:read`: a re-run spends the account's Actions minutes and executes
/// workflow code with the repository's secrets. Reading a log does neither.
async fn ci_rerun(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(req.run_id != 0, "run_id is required")?;
    let (auth, client) = repo_scope(ctx, req, Resource::Ci, Action::Rerun)?;
    client.rerun_ci(&auth, req.run_id, req.all).await?;
    Ok(ApiResponse {
        message: Some(format!(
            "re-running {} of run {}",
            if req.all {
                "every job"
            } else {
                "the failed jobs"
            },
            req.run_id
        )),
        ..ApiResponse::ok()
    })
}

async fn ci_cancel(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(req.run_id != 0, "run_id is required")?;
    let (auth, client) = repo_scope(ctx, req, Resource::Ci, Action::Rerun)?;
    client.cancel_ci(&auth, req.run_id).await?;
    Ok(ApiResponse {
        message: Some(format!("cancelled run {}", req.run_id)),
        ..ApiResponse::ok()
    })
}

// ---- Dependabot alerts (0.2.28, #132) ----

/// GitHub's own list; a dismissal without one of these is refused by the API too, but the
/// message here names them.
const DISMISS_REASONS: &[&str] = &[
    "fix_started",
    "inaccurate",
    "no_bandwidth",
    "not_used",
    "tolerable_risk",
];
const ALERT_STATES: &[&str] = &["open", "dismissed", "fixed", "auto_dismissed", "all"];
/// GitHub's limit on `dismissed_comment`
const DISMISS_COMMENT_MAX: usize = 280;

fn alert_line(a: &SecurityAlert) -> String {
    let mut line = format!(
        "#{} [{}] {}/{} {}",
        a.number, a.severity, a.ecosystem, a.package, a.manifest_path
    );
    if !a.scope.is_empty() {
        line.push_str(&format!(" ({})", a.scope));
    }
    line.push(' ');
    line.push_str(&a.ghsa_id);
    if let Some(cve) = &a.cve_id {
        line.push_str(&format!(" {cve}"));
    }
    match &a.fixed_in {
        Some(v) => line.push_str(&format!(" fixed in {v}")),
        None => line.push_str(" no fix yet"),
    }
    if a.state != "open" {
        line.push_str(&format!(" [{}", a.state));
        if let Some(r) = &a.dismissed_reason {
            line.push_str(&format!(": {r}"));
        }
        line.push(']');
    }
    line.push_str(" — ");
    line.push_str(&a.summary);
    line
}

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
    let (auth, client) = repo_scope(ctx, req, Resource::Security, Action::Read)?;
    let alerts = client.security_alerts(&auth, state).await?;
    let raw = serde_json::to_value(&alerts).unwrap_or(serde_json::Value::Null);
    let msg = alerts.iter().map(alert_line).collect::<Vec<_>>().join("\n");
    Ok(ApiResponse {
        ok: true,
        raw: Some(raw),
        message: Some(if msg.is_empty() {
            format!("no {state} Dependabot alerts in {}", req.repo)
        } else {
            msg
        }),
        ..Default::default()
    })
}

async fn security_alert(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = numbered_scope(ctx, req, Resource::Security, Action::Read)?;
    let a = client.security_alert(&auth, req.number).await?;
    let mut msg = alert_line(&a);
    if let Some(u) = &a.url {
        msg.push('\n');
        msg.push_str(u);
    }
    Ok(ApiResponse {
        ok: true,
        number: Some(a.number),
        url: a.url.clone(),
        raw: Some(serde_json::to_value(&a).unwrap_or(serde_json::Value::Null)),
        message: Some(msg),
        ..Default::default()
    })
}

async fn security_dismiss(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = numbered_scope(ctx, req, Resource::Security, Action::Dismiss)?;
    need(
        DISMISS_REASONS.contains(&req.reason.as_str()),
        "reason is one of fix_started / inaccurate / no_bandwidth / not_used / tolerable_risk",
    )?;
    need(
        req.body.chars().count() <= DISMISS_COMMENT_MAX,
        "comment is at most 280 characters",
    )?;
    client
        .security_alert_dismiss(&auth, req.number, &req.reason, &req.body)
        .await?;
    // The generic api_ok line has the path; the reason is what a reader of the audit wants
    ctx.audit.log(
        "security_alert_dismissed",
        Actor::Agent,
        &[
            ("repo", auth.repo()),
            ("number", &req.number.to_string()),
            ("reason", &req.reason),
            ("comment", &req.body),
        ],
    );
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(format!("dismissed alert #{} ({})", req.number, req.reason)),
        ..ApiResponse::ok()
    })
}

/// The inverse of dismissing, under the same permission: `security:dismiss` already lets the
/// agent change an alert's state, and reopening is the less destructive direction.
async fn security_reopen(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = numbered_scope(ctx, req, Resource::Security, Action::Dismiss)?;
    client.security_alert_reopen(&auth, req.number).await?;
    ctx.audit.log(
        "security_alert_reopened",
        Actor::Agent,
        &[("repo", auth.repo()), ("number", &req.number.to_string())],
    );
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(format!("reopened alert #{}", req.number)),
        ..ApiResponse::ok()
    })
}

async fn ci_runs(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        !req.git_ref.is_empty(),
        "ref (tag / branch / sha) is required",
    )?;
    let (auth, client) = repo_scope(ctx, req, Resource::Ci, Action::Read)?;
    let runs = client.ci_runs(&auth, &req.git_ref).await?;
    let raw = serde_json::to_value(&runs).unwrap_or(serde_json::Value::Null);
    let msg = runs
        .iter()
        .map(|r| {
            let st = if r.conclusion.is_empty() {
                r.status.as_str()
            } else {
                r.conclusion.as_str()
            };
            format!(
                "{} [{}] event={} run_id={} {}",
                r.name, st, r.event, r.id, r.created_at
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(ApiResponse {
        ok: true,
        raw: Some(raw),
        message: Some(if msg.is_empty() {
            format!("no workflow runs for ref {}", req.git_ref)
        } else {
            msg
        }),
        ..Default::default()
    })
}

async fn ci_jobs(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 || req.run_id != 0,
        "number or run_id is required",
    )?;
    let (auth, client) = repo_scope(ctx, req, Resource::Ci, Action::Read)?;
    let jobs = if req.run_id != 0 {
        client.ci_jobs_for_run(&auth, req.run_id).await?
    } else {
        client.ci_jobs(&auth, req.number).await?
    };
    let raw = serde_json::to_value(&jobs).unwrap_or(serde_json::Value::Null);
    let msg = jobs
        .iter()
        .map(|j| {
            let st = if j.conclusion.is_empty() {
                j.status.as_str()
            } else {
                j.conclusion.as_str()
            };
            format!("{} [{}] job_id={}", j.name, st, j.id)
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(ApiResponse {
        ok: true,
        raw: Some(raw),
        message: Some(if msg.is_empty() {
            "no CI jobs for this PR".into()
        } else {
            msg
        }),
        ..Default::default()
    })
}

async fn ci_log(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = repo_scope(ctx, req, Resource::Ci, Action::Read)?;
    let window = if req.window == 0 {
        200
    } else {
        req.window as usize
    };
    let before = req.before.map(|b| b as usize);
    // With no job_id given, pick the PR's failing job automatically (or the last job if none failed)
    let (job_id, name, concl) = if req.job_id != 0 {
        (req.job_id, String::new(), String::new())
    } else {
        need(
            req.number != 0 || req.run_id != 0,
            "number, run_id or job_id is required",
        )?;
        let jobs = if req.run_id != 0 {
            client.ci_jobs_for_run(&auth, req.run_id).await?
        } else {
            client.ci_jobs(&auth, req.number).await?
        };
        let pick = jobs
            .iter()
            .find(|j| j.conclusion == "failure")
            .or_else(|| jobs.last())
            .ok_or_else(|| ApiError::bad_request("no CI jobs for this PR"))?;
        (pick.id, pick.name.clone(), pick.conclusion.clone())
    };
    let page = client
        .ci_job_log(&auth, job_id, &name, &concl, window, before)
        .await?;
    let raw = serde_json::to_value(&page).unwrap_or(serde_json::Value::Null);
    Ok(ApiResponse {
        ok: true,
        raw: Some(raw),
        ..Default::default()
    })
}

// ---- Issue ----

async fn issue_create(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(!req.title.is_empty(), "title is required")?;
    let (auth, client) = repo_scope(ctx, req, Resource::Issue, Action::Create)?;
    // Applying labels is a separate permission: issue:label is required to set them
    let label_auth = if req.labels.is_empty() {
        None
    } else {
        Some(
            ctx.project
                .authorize(&req.repo, Resource::Issue, Action::Label)?,
        )
    };
    let labels = label_auth.as_ref().map(|a| (a, req.labels.as_slice()));
    let iss = client
        .create_issue(&auth, &req.title, &req.body, labels)
        .await?;
    Ok(ApiResponse {
        number: Some(iss.number),
        url: Some(iss.html_url),
        node_id: Some(iss.node_id),
        ..Default::default()
    })
}

async fn issue_comment(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 && !req.body.is_empty(),
        "number and body are required",
    )?;
    let (auth, client, _) = numbered_write_scope(ctx, req, Action::Comment).await?;
    client.comment_issue(&auth, req.number, &req.body).await?;
    Ok(ApiResponse::default())
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
    let (auth, client) = numbered_scope(ctx, req, Resource::Issue, Action::Update)?;
    if client.names_a_pull_request(&auth, req.number).await? {
        return Err(ApiError::bad_request(format!(
            "#{} is a pull request; use sekimore pr update",
            req.number
        )));
    }
    let title = (!req.title.is_empty()).then_some(req.title.as_str());
    let body = (!req.body.is_empty()).then_some(req.body.as_str());
    client.update_issue(&auth, req.number, title, body).await?;
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(format!("updated #{}", req.number)),
        ..ApiResponse::ok()
    })
}

async fn issue_close(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client, _) = numbered_write_scope(ctx, req, Action::Close).await?;
    client.close_issue(&auth, req.number).await?;
    Ok(ApiResponse::default())
}

async fn issue_reopen(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client, _) = numbered_write_scope(ctx, req, Action::Close).await?;
    client.reopen_issue(&auth, req.number).await?;
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(format!("reopened #{}", req.number)),
        ..ApiResponse::ok()
    })
}

async fn issue_label(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 && !req.labels.is_empty(),
        "number and labels are required",
    )?;
    let (auth, client, _) = numbered_write_scope(ctx, req, Action::Label).await?;
    client.label_issue(&auth, req.number, &req.labels).await?;
    Ok(ApiResponse::default())
}

/// Take labels off again. Adding and removing are one authority, `issue:label`.
///
/// GitHub removes one label per request, so several names mean several calls. The names are
/// agent-supplied and land in the path; `unlabel_issue` is what keeps them inside the repository.
async fn issue_unlabel(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 && !req.labels.is_empty(),
        "number and labels are required",
    )?;
    let (auth, client, _) = numbered_write_scope(ctx, req, Action::Label).await?;
    for label in &req.labels {
        client.unlabel_issue(&auth, req.number, label).await?;
    }
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(format!(
            "removed {} from #{}",
            req.labels.join(", "),
            req.number
        )),
        ..ApiResponse::ok()
    })
}

async fn issue_assign(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 && !req.assignees.is_empty(),
        "number and assignees are required",
    )?;
    let (auth, client, _) = numbered_write_scope(ctx, req, Action::Assign).await?;
    client
        .assign_issue(&auth, req.number, &req.assignees)
        .await?;
    Ok(ApiResponse::default())
}

async fn issue_unassign(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(
        req.number != 0 && !req.assignees.is_empty(),
        "number and assignees are required",
    )?;
    let (auth, client, _) = numbered_write_scope(ctx, req, Action::Assign).await?;
    client
        .unassign_issue(&auth, req.number, &req.assignees)
        .await?;
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(format!(
            "unassigned {} from #{}",
            req.assignees.join(", "),
            req.number
        )),
        ..ApiResponse::ok()
    })
}

// ---- Projects ----

async fn project_add_item(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.content_id.is_empty(), "content_id is required")?;
    let (auth, client) = project_scope(ctx, req, Resource::Project, Action::AddItem)?;
    let board = resolve_board(ctx, client, req).await?;
    let item = client
        .add_project_item(&auth, &board, &req.content_id)
        .await?;
    Ok(ApiResponse {
        item_id: Some(item),
        ..Default::default()
    })
}

async fn project_update_item(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(
        !req.item_id.is_empty() && !req.field_id.is_empty(),
        "item_id and field_id are required",
    )?;
    let (auth, client) = project_scope(ctx, req, Resource::Project, Action::UpdateItem)?;
    let board = resolve_board(ctx, client, req).await?;
    let value = req.value.clone().unwrap_or(Value::Null);
    client
        .update_project_item_field(&auth, &board, &req.item_id, &req.field_id, value)
        .await?;
    Ok(ApiResponse::default())
}

async fn project_list(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = project_scope(ctx, req, Resource::Project, Action::Read)?;
    let board = resolve_board(ctx, client, req).await?;
    let first = if req.first == 0 || req.first > 100 {
        20
    } else {
        req.first
    };
    let raw = client.list_project_items(&auth, &board, first).await?;
    Ok(ApiResponse {
        raw: Some(raw),
        ..Default::default()
    })
}

/// 0.2.7: the board's fields and their option ids, which `project update-item` needs.
async fn project_fields(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = project_scope(ctx, req, Resource::Project, Action::Read)?;
    let board = resolve_board(ctx, client, req).await?;
    let first = if req.first == 0 || req.first > 100 {
        50
    } else {
        req.first
    };
    let raw = client.list_project_fields(&auth, &board, first).await?;
    Ok(ApiResponse {
        raw: Some(raw),
        ..Default::default()
    })
}

/// 0.2.7: ask people to review a pull request.
async fn pr_request_review(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need_repo(req)?;
    need(req.number != 0, "number is required")?;
    need(
        !req.reviewers.is_empty() || !req.team_reviewers.is_empty(),
        "at least one reviewer or team is required",
    )?;
    let (auth, client) = repo_scope(ctx, req, Resource::Pr, Action::RequestReview)?;
    client
        .request_reviewers(&auth, req.number, &req.reviewers, &req.team_reviewers)
        .await?;
    let mut who = req.reviewers.clone();
    who.extend(req.team_reviewers.iter().map(|t| format!("@{t}")));
    Ok(ApiResponse {
        message: Some(format!(
            "requested review on #{} from {}",
            req.number,
            who.join(", ")
        )),
        ..ApiResponse::ok()
    })
}

/// 0.2.7: search issues and pull requests across the project.
///
/// A search names no repository, so the policy anchor is the project's first one, the same way
/// Projects does it. What actually keeps the answer inside the project is the `repo:` scoping and
/// the filter applied to the results, both in the client.
async fn search_issues(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.query.is_empty(), "query is required")?;
    let (auth, client) = project_scope(ctx, req, Resource::Search, Action::Read)?;
    let limit = if req.first == 0 { 20 } else { req.first };
    let hits = client
        .search_issues(&auth, &ctx.project, &req.query, limit)
        .await?;
    let msg = if hits.is_empty() {
        "no match in this project".to_string()
    } else {
        hits.iter()
            .map(|h| {
                format!(
                    "{}#{} [{}] {} ({})",
                    h.repository, h.number, h.state, h.title, h.kind
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok(ApiResponse {
        message: Some(msg),
        raw: serde_json::to_value(&hits).ok(),
        ..ApiResponse::ok()
    })
}

/// 0.2.9: the labels, assignees and milestones a repository defines, so `issue label` and
/// `issue assign` can use a value that exists instead of guessing at one.
async fn repo_vocabulary(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (auth, client) = repo_scope(ctx, req, Resource::Repo, Action::Read)?;
    let limit = if req.first == 0 { 100 } else { req.first };
    let raw = client.repo_vocabulary(&auth, limit).await?;
    let line = |key: &str| {
        raw.get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "(none)".to_string())
    };
    Ok(ApiResponse {
        message: Some(format!(
            "labels:     {}\nassignees:  {}\nmilestones: {}",
            line("labels"),
            line("assignees"),
            line("milestones")
        )),
        raw: Some(raw),
        ..ApiResponse::ok()
    })
}

// ---- Bootstrap (unauthenticated) ----

pub async fn bootstrap(
    ctx: &ApiContext,
    req: Request<Incoming>,
    peer_ip: &str,
) -> Result<BootstrapResponse, ApiError> {
    if ctx.bootstrap == BootstrapMode::Manual {
        ctx.audit.deny(
            "bootstrap_denied",
            Actor::Agent,
            "bootstrap is manual",
            &[("peer", peer_ip)],
        );
        return Err(ApiError { status: StatusCode::NOT_FOUND, message: "bootstrap is disabled (relay.bootstrap: manual); ask the operator to run `docker compose exec sekimore-gw sekimore-relay add-key` and `... token` on the host running docker".into() });
    }
    if ctx.bootstrap_disabled_path.exists() {
        ctx.audit.deny(
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
        ctx.audit.deny(
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
        ctx.audit.deny(
            "bootstrap_denied",
            Actor::Agent,
            &format!("invalid JSON: {e}"),
            &[("peer", peer_ip)],
        );
        ApiError::bad_request(format!("invalid JSON: {e}"))
    })?;
    let added = ctx.keys.add(&breq.public_key).map_err(|e| {
        ctx.audit.deny(
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
    ctx.audit.log(
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

#[cfg(test)]
mod comment_rendering {
    use crate::github::CommentItem;

    fn item(kind: &str, author: &str, body: &str) -> CommentItem {
        CommentItem {
            kind: kind.into(),
            author: author.into(),
            created_at: "2026-09-24T10:00:00Z".into(),
            body: body.into(),
            state: None,
            path: None,
            line: None,
            in_reply_to_id: None,
            id: None,
            review_id: None,
        }
    }
    fn review(author: &str, state: &str, body: &str, rid: u64) -> CommentItem {
        CommentItem {
            state: Some(state.into()),
            review_id: Some(rid),
            ..item("review", author, body)
        }
    }
    fn inline(
        author: &str,
        path: &str,
        line: u64,
        body: &str,
        id: u64,
        rid: Option<u64>,
    ) -> CommentItem {
        CommentItem {
            path: Some(path.into()),
            line: Some(line),
            id: Some(id),
            review_id: rid,
            ..item("inline", author, body)
        }
    }

    /// #165: one submission reads as one thing, whoever else reviewed in the same second.
    #[test]
    fn line_comments_sit_under_the_review_they_came_with() {
        let items = vec![
            item("comment", "alice", "looks fine"),
            review("bob", "CHANGES_REQUESTED", "two things", 1),
            inline("bob", "pack.rs", 142, "why is this safe?", 2451, Some(1)),
            review("carol", "APPROVED", "lgtm", 2),
            inline("carol", "policy.rs", 88, "nice", 2452, Some(2)),
        ];
        let out = super::comment_lines(&items);
        let bob = out.find("review CHANGES_REQUESTED").unwrap();
        let carol = out.find("review APPROVED").unwrap();
        let q = out.find("why is this safe?").unwrap();
        let n = out.find("nice").unwrap();
        assert!(
            bob < q && q < carol,
            "bob's comment must sit inside bob's review:\n{out}"
        );
        assert!(
            carol < n,
            "carol's comment must sit inside carol's review:\n{out}"
        );
        assert!(
            out.contains("      why is this safe?"),
            "nested deeper than its review:\n{out}"
        );
    }

    /// The id is what says "you can answer this", so it appears only where a reply is possible.
    #[test]
    fn only_the_lines_that_can_be_replied_to_carry_an_id() {
        let items = vec![
            item("comment", "alice", "looks fine"),
            review("bob", "COMMENTED", "a note", 1),
            inline("bob", "pack.rs", 142, "why?", 2451, Some(1)),
        ];
        let out = super::comment_lines(&items);
        assert!(out.contains("pack.rs:142  #2451"), "{out}");
        let conversation = out.lines().find(|l| l.contains("[comment]")).unwrap();
        assert!(
            !conversation.contains('#'),
            "a conversation comment needs no id: {conversation}"
        );
    }

    /// A COMMENTED review with no body is only an envelope; with nothing in it, it says nothing.
    #[test]
    fn an_empty_envelope_is_dropped_but_a_full_one_is_not() {
        let empty = vec![CommentItem {
            ..review("bob", "COMMENTED", "", 1)
        }];
        let mut e = empty.clone();
        e[0].kind = "review_envelope".into();
        assert_eq!(
            super::comment_lines(&e),
            "",
            "an envelope with no comments must not print"
        );

        let mut full = e.clone();
        full.push(inline("bob", "pack.rs", 1, "here", 99, Some(1)));
        let out = super::comment_lines(&full);
        assert!(
            out.contains("pack.rs:1  #99"),
            "its comments must still show:\n{out}"
        );
    }

    /// A reply posted on its own belongs to no review, and still has to appear.
    #[test]
    fn an_inline_comment_with_no_review_is_not_lost() {
        let items = vec![inline("bob", "pack.rs", 7, "standalone", 42, None)];
        let out = super::comment_lines(&items);
        assert!(out.contains("pack.rs:7  #42"), "{out}");
        assert!(out.contains("standalone"), "{out}");
    }
}
