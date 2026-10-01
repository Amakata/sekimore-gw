//! The github forge relay (#328): each agent-facing operation from the point the gateway holds the
//! policy's proof — the upstream calls and the shaping of their answer. What comes before (the
//! argument checks, the scope, `authorize`) is in `api::handlers`, and stays in the gateway.
//!
//! The same code serves both transports: built in, the gateway calls it here; as a sidecar (#329)
//! it is reached over a socket with the same request.

use std::sync::Arc;

use async_trait::async_trait;
use hyper::StatusCode;
use serde_json::Value;

use super::{Answer, ForgeRelay, Grant, OpenPrError, OpenedPr, Query, ReleaseRef, Resolved};
use crate::api::types::{ApiRequest, ApiResponse};
use crate::api::ApiError;
use crate::github::{CommentItem, GhError, GitHub, SecurityAlert};
use crate::policy::{Action, Resource};

/// GitHub (github.com or a GHES), one upstream per instance.
pub struct GitHubRelay {
    gh: Arc<GitHub>,
}

impl GitHubRelay {
    pub fn new(gh: Arc<GitHub>) -> Self {
        GitHubRelay { gh }
    }
}

#[async_trait]
impl ForgeRelay for GitHubRelay {
    async fn call(
        &self,
        op: &str,
        grants: &[Grant],
        req: &ApiRequest,
        resolved: &Resolved,
    ) -> Result<ApiResponse, ApiError> {
        let Some(g) = grants.first() else {
            return Err(ApiError::forbidden(format!("{op} arrived without a grant")));
        };
        let gh = self.gh.as_ref();
        match op {
            "/pr/create" => pr_create(gh, g, req).await,
            "/pr/comment" => pr_comment(gh, g, req).await,
            "/pr/reply" => pr_reply(gh, g, req).await,
            "/pr/comment-edit" | "/issue/comment-edit" => comment_edit(gh, g, req).await,
            "/pr/comment-delete" | "/issue/comment-delete" => comment_delete(gh, g, req).await,
            "/pr/draft" => pr_draft(gh, g, req).await,
            "/ci/dispatch" => ci_dispatch(gh, g, req).await,
            "/pr/review" => pr_review(gh, g, req).await,
            "/pr/resolve" => pr_resolve(gh, g, req).await,
            "/pr/merge" => pr_merge(gh, g, req).await,
            "/pr/close" => pr_close(gh, g, req).await,
            "/pr/reopen" => pr_reopen(gh, g, req).await,
            "/pr/update" => pr_update(gh, g, req).await,
            "/pr/status" => pr_status(gh, g, req).await,
            "/pr/view" => pr_view(gh, g, req).await,
            "/pr/comments" => pr_comments(gh, g, req).await,
            "/pr/files" => pr_files(gh, g, req).await,
            "/pr/diff" => pr_diff(gh, g, req).await,
            "/pr/list" => pr_list(gh, g, req).await,
            "/pr/request-review" => pr_request_review(gh, g, req).await,
            "/issue/view" => issue_view(gh, g, req).await,
            "/issue/comments" => issue_comments(gh, g, req).await,
            "/issue/list" => issue_list(gh, g, req).await,
            "/issue/create" => issue_create(gh, grants, req).await,
            "/issue/comment" => issue_comment(gh, g, req).await,
            "/issue/update" => issue_update(gh, g, req).await,
            "/issue/close" => issue_close(gh, g, req).await,
            "/issue/reopen" => issue_reopen(gh, g, req).await,
            "/issue/label" => issue_label(gh, g, req).await,
            "/issue/unlabel" => issue_unlabel(gh, g, req).await,
            "/issue/assign" => issue_assign(gh, g, req).await,
            "/issue/unassign" => issue_unassign(gh, g, req).await,
            "/project/add-item" => project_add_item(gh, g, req, resolved).await,
            "/project/update-item" => project_update_item(gh, g, req, resolved).await,
            "/project/list" => project_list(gh, g, req, resolved).await,
            "/project/fields" => project_fields(gh, g, req, resolved).await,
            "/search/issues" => search_issues(gh, g, req, resolved).await,
            "/repo/vocabulary" => repo_vocabulary(gh, g, req).await,
            "/release/create" => release_create(gh, g, req).await,
            "/release/view" => release_view(gh, g, req).await,
            "/release/list" => release_list(gh, g, req).await,
            "/release/edit" => release_edit(gh, g, req, resolved).await,
            "/ci/rerun" => ci_rerun(gh, g, req).await,
            "/ci/cancel" => ci_cancel(gh, g, req).await,
            "/ci/runs" => ci_runs(gh, g, req).await,
            "/ci/jobs" => ci_jobs(gh, g, req).await,
            "/ci/log" => ci_log(gh, g, req).await,
            "/security/alerts" => security_alerts(gh, g, req).await,
            "/security/alert" => security_alert(gh, g, req).await,
            "/security/dismiss" => security_dismiss(gh, g, req).await,
            "/security/reopen" => security_reopen(gh, g, req).await,
            _ => Err(ApiError {
                status: StatusCode::NOT_FOUND,
                message: format!("unknown endpoint {op}"),
            }),
        }
    }

    async fn query(&self, query: &Query, grant: Option<&Grant>) -> Result<Answer, ApiError> {
        let gh = self.gh.as_ref();
        let need = || {
            grant.ok_or_else(|| ApiError::forbidden(format!("{query:?} arrived without a grant")))
        };
        Ok(match query {
            Query::NamesAPullRequest { number } => {
                Answer::Bool(gh.names_a_pull_request(need()?, *number).await?)
            }
            Query::ReleaseForEdit { tag } => Answer::Release(
                gh.get_release_for_edit(need()?, tag)
                    .await?
                    .map(|r| ReleaseRef {
                        id: r.id,
                        draft: r.draft,
                    }),
            ),
            Query::BoardId { org, user, number } => Answer::Id(
                gh.resolve_project_board(org.as_deref(), user.as_deref(), *number)
                    .await?,
            ),
            Query::DefaultBranch => Answer::Branch(gh.default_branch(need()?).await?),
            Query::CommitExists { sha } => Answer::Bool(gh.commit_exists(need()?, sha).await?),
            Query::IsAncestor { base, head } => {
                Answer::Bool(gh.is_ancestor(need()?, base, head).await?)
            }
        })
    }

    /// GitHub answers 422 to a pull request that already exists for this head and base; that is
    /// success for a push, so the open one is looked up and reported instead.
    async fn open_pr(
        &self,
        grant: &Grant,
        head: &str,
        base: &str,
        title: &str,
        body: &str,
    ) -> Result<OpenedPr, OpenPrError> {
        let gh = self.gh.as_ref();
        match gh
            .create_pull_request(grant, head, base, title, body, false)
            .await
        {
            Ok(r) => Ok(OpenedPr {
                number: r.number,
                url: r.html_url,
                existed: false,
            }),
            Err(GhError::Status { status: 422, .. }) => {
                match gh.find_pull_request(grant, head, base).await {
                    Ok(Some(existing)) => Ok(OpenedPr {
                        number: existing.number,
                        url: existing.html_url,
                        existed: true,
                    }),
                    Ok(None) => Err(OpenPrError::NotOpened(
                        "upstream returned 422 and no matching open PR was found".into(),
                    )),
                    Err(e) => Err(OpenPrError::LookupFailed(e.into())),
                }
            }
            Err(e) => Err(OpenPrError::CreateFailed(e.into())),
        }
    }
}

/// Nothing, or the string — so a call can tell "leave it alone" from "set it to empty".
fn opt(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// How many to fetch: the agent's number, clamped, or the default when it asked for nothing.
fn limit_or(first: u32, default: u32) -> u32 {
    if first == 0 {
        default
    } else {
        first.clamp(1, 100)
    }
}

/// The list state the gateway already checked (`api::handlers::list_state`); empty is `open`.
fn state_or_open(state: &str) -> &str {
    if state.is_empty() {
        "open"
    } else {
        state
    }
}

fn bad(msg: &str) -> ApiError {
    ApiError::bad_request(msg)
}

// ---- PR ----

async fn pr_create(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let pr = gh
        .create_pull_request(g, &req.head, &req.base, &req.title, &req.body, req.pr_draft)
        .await?;
    Ok(ApiResponse {
        number: Some(pr.number),
        url: Some(pr.html_url),
        node_id: Some(pr.node_id),
        ..Default::default()
    })
}

async fn pr_comment(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.comment_pull_request(g, req.number, &req.body).await?;
    Ok(ApiResponse::default())
}

async fn pr_reply(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.reply_to_review_comment(g, req.number, req.comment_id, &req.body)
        .await?;
    Ok(ApiResponse::default())
}

async fn pr_draft(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.set_pull_request_draft(g, req.number, req.pr_draft)
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

async fn ci_dispatch(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.dispatch_workflow(g, &req.workflow, &req.git_ref, &req.inputs)
        .await?;
    Ok(ApiResponse {
        message: Some(format!(
            "dispatched {} on {}; find the run with `ci runs --ref {}`",
            req.workflow, req.git_ref, req.git_ref
        )),
        ..Default::default()
    })
}

async fn comment_edit(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.update_comment(g, req.number, req.inline, req.comment_id, &req.body)
        .await?;
    Ok(ApiResponse::default())
}

async fn comment_delete(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.delete_comment(g, req.number, req.inline, req.comment_id)
        .await?;
    Ok(ApiResponse::default())
}

async fn pr_review(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.review_pull_request(g, req.number, &req.event, &req.body, &req.comments)
        .await?;
    Ok(ApiResponse::default())
}

async fn pr_resolve(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let want = !req.unresolve;
    let now = gh
        .resolve_review_thread(g, req.number, req.thread_id.trim(), want)
        .await?;
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(format!(
            "{} {} on #{}",
            if now { "resolved" } else { "unresolved" },
            req.thread_id.trim(),
            req.number
        )),
        ..ApiResponse::ok()
    })
}

async fn pr_merge(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let res = gh
        .merge_pull_request(
            g,
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

async fn pr_close(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.close_pull_request(g, req.number).await?;
    Ok(ApiResponse::default())
}

async fn pr_reopen(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.reopen_pull_request(g, req.number).await?;
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(format!("reopened #{}", req.number)),
        ..ApiResponse::ok()
    })
}

async fn pr_update(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.update_pull_request(
        g,
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

async fn pr_status(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let st = gh.pull_request_status(g, req.number).await?;
    let raw = serde_json::to_value(&st).unwrap_or(Value::Null);
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

/// Render one discussion entry. The body is whatever a human wrote: it is printed, never parsed.
/// #165: a review is one submission — a verdict, a body, and the line comments that came with
/// it — so it is shown as one thing, with its comments nested under it. Flat and sorted by time,
/// which is what this did before, left the reader to guess which comment belonged to which
/// review, and two reviewers landing in the same second made that guess unreliable.
fn comment_lines(items: &[CommentItem]) -> String {
    // The date alone is enough to follow a discussion; the time is in the JSON.
    let day = |c: &CommentItem| c.created_at.split('T').next().unwrap_or("").to_string();
    // Where an inline comment sits, and the id `pr reply` needs. The id appears only on the
    // lines that can be answered, so its presence is what says a reply is possible.
    // 0.2.59: and the conversation it sits in, which `pr resolve` takes. A thread id is long and
    // every comment in a thread repeats it, so it is printed once — on the first comment of that
    // thread this rendering reaches. Not on the thread's root: with a limit in play the root can
    // fall outside the page while a reply is inside it, and then the id would never be shown.
    // Only a settled thread is marked; an unmarked one is open.
    let mut seen_threads: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut inline_tail = |c: &CommentItem| {
        let where_ = match (&c.path, c.line) {
            (Some(p), Some(l)) => format!("{p}:{l}"),
            (Some(p), None) => p.clone(),
            _ => "[inline]".to_string(),
        };
        let mut s = match c.id {
            Some(id) => format!("{where_}  #{id}"),
            None => where_,
        };
        if let Some(t) = c.thread_id.as_deref() {
            if seen_threads.insert(t.to_string()) {
                s.push_str(&format!("  thread {t}"));
                if c.resolved == Some(true) {
                    s.push_str(" (resolved)");
                }
            }
        }
        s
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

async fn pr_view(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let pr = gh.pull_request_view(g, req.number).await?;
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
async fn pr_comments(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let items = gh
        .pull_request_comments(g, req.number, limit_or(req.first, 30))
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

/// #173: which files a pull request touches, and how much moved in each.
async fn pr_files(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let (files, truncated) = gh.pull_request_files(g, req.number).await?;
    let (add, del): (u64, u64) = files
        .iter()
        .fold((0, 0), |(a, d), f| (a + f.additions, d + f.deletions));
    let mut msg = files
        .iter()
        .map(|f| {
            format!(
                "{:<10} +{:<5} -{:<5} {}{}",
                f.status,
                f.additions,
                f.deletions,
                f.path,
                f.no_patch
                    .as_deref()
                    .map(|w| format!("  ({w})"))
                    .unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    if files.is_empty() {
        msg = format!("PR #{} touches no files", req.number);
    } else {
        msg.push_str(&format!(
            "\n{}{} files, +{add} -{del}. sekimore pr diff --number {} --path <path>",
            files.len(),
            // Say so rather than let a file the relay never listed look like one that is not there
            if truncated { "+" } else { "" },
            req.number
        ));
    }
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(msg),
        raw: serde_json::to_value(&files).ok(),
        ..ApiResponse::ok()
    })
}

/// #173: one file's patch, numbered the way `pr review --comment` wants.
async fn pr_diff(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let window = if req.window == 0 {
        400
    } else {
        req.window as usize
    };
    let page = gh
        .pull_request_diff(
            g,
            req.number,
            if req.file_path.is_empty() {
                None
            } else {
                Some(&req.file_path)
            },
            window,
            req.before.unwrap_or(0) as usize,
        )
        .await?;
    Ok(ApiResponse {
        number: Some(req.number),
        raw: serde_json::to_value(&page).ok(),
        ..ApiResponse::ok()
    })
}

async fn pr_list(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let state = state_or_open(&req.state);
    let prs = gh
        .list_pull_requests(
            g,
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

/// 0.2.7: ask people to review a pull request.
async fn pr_request_review(
    gh: &GitHub,
    g: &Grant,
    req: &ApiRequest,
) -> Result<ApiResponse, ApiError> {
    gh.request_reviewers(g, req.number, &req.reviewers, &req.team_reviewers)
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

// ---- issues ----

/// One issue. GitHub serves pull requests from this endpoint too, so the answer says which it got
/// rather than presenting a PR as an issue; the payload is still returned.
async fn issue_view(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let iss = gh.issue_view(g, req.number).await?;
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

async fn issue_comments(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let items = gh
        .issue_comments(g, req.number, limit_or(req.first, 30))
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

async fn issue_list(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let state = state_or_open(&req.state);
    let issues = gh
        .list_issues(
            g,
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

/// Labels on creation are a second grant, `issue:label`, which the gateway adds only when the
/// request carries labels.
async fn issue_create(
    gh: &GitHub,
    grants: &[Grant],
    req: &ApiRequest,
) -> Result<ApiResponse, ApiError> {
    let g = &grants[0];
    let label_grant = grants[1..]
        .iter()
        .find(|x| x.is(Resource::Issue, Action::Label));
    let labels = label_grant.map(|a| (a, req.labels.as_slice()));
    let iss = gh.create_issue(g, &req.title, &req.body, labels).await?;
    Ok(ApiResponse {
        number: Some(iss.number),
        url: Some(iss.html_url),
        node_id: Some(iss.node_id),
        ..Default::default()
    })
}

async fn issue_comment(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.comment_issue(g, req.number, &req.body).await?;
    Ok(ApiResponse::default())
}

async fn issue_update(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let title = (!req.title.is_empty()).then_some(req.title.as_str());
    let body = (!req.body.is_empty()).then_some(req.body.as_str());
    gh.update_issue(g, req.number, title, body).await?;
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(format!("updated #{}", req.number)),
        ..ApiResponse::ok()
    })
}

async fn issue_close(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.close_issue(g, req.number).await?;
    Ok(ApiResponse::default())
}

async fn issue_reopen(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.reopen_issue(g, req.number).await?;
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(format!("reopened #{}", req.number)),
        ..ApiResponse::ok()
    })
}

async fn issue_label(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.label_issue(g, req.number, &req.labels).await?;
    Ok(ApiResponse::default())
}

/// GitHub removes one label per request, so several names mean several calls. The names are
/// agent-supplied and land in the path; `unlabel_issue` is what keeps them inside the repository.
async fn issue_unlabel(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    for label in &req.labels {
        gh.unlabel_issue(g, req.number, label).await?;
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

async fn issue_assign(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.assign_issue(g, req.number, &req.assignees).await?;
    Ok(ApiResponse::default())
}

async fn issue_unassign(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.unassign_issue(g, req.number, &req.assignees).await?;
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

async fn project_add_item(
    gh: &GitHub,
    g: &Grant,
    req: &ApiRequest,
    r: &Resolved,
) -> Result<ApiResponse, ApiError> {
    let item = gh.add_project_item(g, &r.board_id, &req.content_id).await?;
    Ok(ApiResponse {
        item_id: Some(item),
        ..Default::default()
    })
}

async fn project_update_item(
    gh: &GitHub,
    g: &Grant,
    req: &ApiRequest,
    r: &Resolved,
) -> Result<ApiResponse, ApiError> {
    let value = req.value.clone().unwrap_or(Value::Null);
    gh.update_project_item_field(g, &r.board_id, &req.item_id, &req.field_id, value)
        .await?;
    Ok(ApiResponse::default())
}

async fn project_list(
    gh: &GitHub,
    g: &Grant,
    req: &ApiRequest,
    r: &Resolved,
) -> Result<ApiResponse, ApiError> {
    let first = if req.first == 0 || req.first > 100 {
        20
    } else {
        req.first
    };
    let raw = gh.list_project_items(g, &r.board_id, first).await?;
    Ok(ApiResponse {
        raw: Some(raw),
        ..Default::default()
    })
}

/// 0.2.7: the board's fields and their option ids, which `project update-item` needs.
async fn project_fields(
    gh: &GitHub,
    g: &Grant,
    req: &ApiRequest,
    r: &Resolved,
) -> Result<ApiResponse, ApiError> {
    let first = if req.first == 0 || req.first > 100 {
        50
    } else {
        req.first
    };
    let raw = gh.list_project_fields(g, &r.board_id, first).await?;
    Ok(ApiResponse {
        raw: Some(raw),
        ..Default::default()
    })
}

/// 0.2.7: search issues and pull requests across the project. The gateway hands over the
/// project's repositories; the query is scoped to them and the results filtered back to them.
async fn search_issues(
    gh: &GitHub,
    g: &Grant,
    req: &ApiRequest,
    r: &Resolved,
) -> Result<ApiResponse, ApiError> {
    let limit = if req.first == 0 { 20 } else { req.first };
    let hits = gh.search_issues(g, &r.repos, &req.query, limit).await?;
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
async fn repo_vocabulary(
    gh: &GitHub,
    g: &Grant,
    req: &ApiRequest,
) -> Result<ApiResponse, ApiError> {
    let limit = if req.first == 0 { 100 } else { req.first };
    let raw = gh.repo_vocabulary(g, limit).await?;
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

// ---- releases (0.2.6) ----

async fn release_create(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    // Without notes of its own a release would be empty, so ask GitHub to write them.
    let generate = req.generate_notes || req.body.is_empty();
    let rel = gh
        .create_release(
            g,
            &req.tag,
            opt(&req.title),
            opt(&req.body),
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

async fn release_view(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    match gh.get_release_by_tag(g, &req.tag).await? {
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

async fn release_list(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let limit = if req.first == 0 { 20 } else { req.first };
    let rels = gh.list_releases(g, limit).await?;
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

/// The release and whether this edit publishes it were settled by the gateway, which looked the
/// release up to decide between `release:create` and `release:publish`.
async fn release_edit(
    gh: &GitHub,
    g: &Grant,
    req: &ApiRequest,
    r: &Resolved,
) -> Result<ApiResponse, ApiError> {
    let rel = gh
        .update_release(
            g,
            r.release_id,
            r.publishing,
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
            if r.publishing { "published" } else { "updated" },
            rel.tag_name,
            if rel.draft { " (draft)" } else { "" }
        )),
        raw: serde_json::to_value(&rel).ok(),
        ..ApiResponse::ok()
    })
}

// ---- CI ----

async fn ci_rerun(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.rerun_ci(g, req.run_id, req.all).await?;
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

async fn ci_cancel(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    gh.cancel_ci(g, req.run_id).await?;
    Ok(ApiResponse {
        message: Some(format!("cancelled run {}", req.run_id)),
        ..ApiResponse::ok()
    })
}

async fn ci_runs(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let runs = gh.ci_runs(g, &req.git_ref).await?;
    let raw = serde_json::to_value(&runs).unwrap_or(Value::Null);
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

async fn ci_jobs(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let jobs = if req.run_id != 0 {
        gh.ci_jobs_for_run(g, req.run_id).await?
    } else {
        gh.ci_jobs(g, req.number).await?
    };
    let raw = serde_json::to_value(&jobs).unwrap_or(Value::Null);
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

async fn ci_log(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
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
        if req.number == 0 && req.run_id == 0 {
            return Err(bad("number, run_id or job_id is required"));
        }
        let jobs = if req.run_id != 0 {
            gh.ci_jobs_for_run(g, req.run_id).await?
        } else {
            gh.ci_jobs(g, req.number).await?
        };
        let pick = jobs
            .iter()
            .find(|j| j.conclusion == "failure")
            .or_else(|| jobs.last())
            .ok_or_else(|| bad("no CI jobs for this PR"))?;
        (pick.id, pick.name.clone(), pick.conclusion.clone())
    };
    let page = gh
        .ci_job_log(g, job_id, &name, &concl, window, before)
        .await?;
    let raw = serde_json::to_value(&page).unwrap_or(Value::Null);
    Ok(ApiResponse {
        ok: true,
        raw: Some(raw),
        ..Default::default()
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

async fn security_alerts(
    gh: &GitHub,
    g: &Grant,
    req: &ApiRequest,
) -> Result<ApiResponse, ApiError> {
    let state = state_or_open(&req.state);
    let alerts = gh.security_alerts(g, state).await?;
    let raw = serde_json::to_value(&alerts).unwrap_or(Value::Null);
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

async fn security_alert(gh: &GitHub, g: &Grant, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    let a = gh.security_alert(g, req.number).await?;
    let mut msg = alert_line(&a);
    if let Some(u) = &a.url {
        msg.push('\n');
        msg.push_str(u);
    }
    Ok(ApiResponse {
        ok: true,
        number: Some(a.number),
        url: a.url.clone(),
        raw: Some(serde_json::to_value(&a).unwrap_or(Value::Null)),
        message: Some(msg),
        ..Default::default()
    })
}

async fn security_dismiss(
    gh: &GitHub,
    g: &Grant,
    req: &ApiRequest,
) -> Result<ApiResponse, ApiError> {
    if !DISMISS_REASONS.contains(&req.reason.as_str()) {
        return Err(bad(
            "reason is one of fix_started / inaccurate / no_bandwidth / not_used / tolerable_risk",
        ));
    }
    if req.body.chars().count() > DISMISS_COMMENT_MAX {
        return Err(bad("comment is at most 280 characters"));
    }
    gh.security_alert_dismiss(g, req.number, &req.reason, &req.body)
        .await?;
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(format!("dismissed alert #{} ({})", req.number, req.reason)),
        ..ApiResponse::ok()
    })
}

async fn security_reopen(
    gh: &GitHub,
    g: &Grant,
    req: &ApiRequest,
) -> Result<ApiResponse, ApiError> {
    gh.security_alert_reopen(g, req.number).await?;
    Ok(ApiResponse {
        number: Some(req.number),
        message: Some(format!("reopened alert #{}", req.number)),
        ..ApiResponse::ok()
    })
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
            thread_id: None,
            resolved: None,
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

    /// 0.2.59: `pr resolve` takes a thread id, and this is the only place one is shown. It is
    /// printed once per conversation — a node id is long and every reply in a thread repeats it —
    /// and on the first comment of the thread that is rendered rather than on the thread's root,
    /// because a limit can leave the root out while a reply is still on the page.
    #[test]
    fn a_thread_id_is_printed_once_per_conversation_with_its_state() {
        let threaded = |mut c: CommentItem, tid: &str, done: bool| {
            c.thread_id = Some(tid.into());
            c.resolved = Some(done);
            c
        };
        let items = vec![
            threaded(
                inline("bob", "pack.rs", 7, "why?", 42, None),
                "PRRT_a",
                false,
            ),
            threaded(
                inline("bob", "pack.rs", 7, "and also", 43, None),
                "PRRT_a",
                false,
            ),
            threaded(
                inline("carol", "policy.rs", 9, "settled", 44, None),
                "PRRT_b",
                true,
            ),
            // No thread at all: the join found nothing, and the line still prints as before.
            inline("dave", "main.rs", 1, "orphan", 45, None),
        ];
        let out = super::comment_lines(&items);
        assert!(
            out.contains("pack.rs:7  #42  thread PRRT_a"),
            "the first comment of a conversation carries its id:\n{out}"
        );
        assert_eq!(
            out.matches("PRRT_a").count(),
            1,
            "a thread id is not repeated on every reply:\n{out}"
        );
        assert!(
            out.contains("policy.rs:9  #44  thread PRRT_b (resolved)"),
            "a settled conversation says so:\n{out}"
        );
        assert!(
            !out.contains("PRRT_a (resolved)"),
            "an open one is left unmarked:\n{out}"
        );
        assert!(
            out.contains("main.rs:1  #45\n"),
            "a comment with no thread prints as it always did:\n{out}"
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

#[cfg(test)]
mod boundary {
    use std::sync::Arc;

    use url::Url;

    use super::GitHubRelay;
    use crate::audit::Audit;
    use crate::forge::{ForgeRelay, Grant, Query, Resolved};
    use crate::github::upstream_token::UpstreamTokenStore;
    use crate::github::GitHub;
    use crate::policy::{Action, Mode, Project, Resource};

    /// A relay whose upstream does not resolve and whose token store is empty: anything that gets
    /// past the grant checks fails on the token, so a 403 here is the check, not the network.
    fn relay() -> GitHubRelay {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(UpstreamTokenStore::in_memory(
            "upstream.invalid",
            &dir.path().join("t"),
        ));
        std::mem::forget(dir);
        GitHubRelay::new(Arc::new(GitHub::new(
            Url::parse("https://upstream.invalid/api/v3").unwrap(),
            Url::parse("https://upstream.invalid/api/graphql").unwrap(),
            reqwest::Client::new(),
            store,
            Arc::new(Audit::disabled()),
        )))
    }

    #[tokio::test]
    async fn an_operation_without_a_grant_is_refused() {
        let e = relay()
            .call("/pr/close", &[], &Default::default(), &Resolved::default())
            .await
            .unwrap_err();
        assert_eq!(e.status, hyper::StatusCode::FORBIDDEN, "{}", e.message);
    }

    #[tokio::test]
    async fn a_repository_question_without_a_grant_is_refused() {
        let e = relay()
            .query(&Query::DefaultBranch, None)
            .await
            .unwrap_err();
        assert_eq!(e.status, hyper::StatusCode::FORBIDDEN, "{}", e.message);
    }

    /// The git path's reads take the push's own grant; an API grant for the same repository —
    /// even one as broad as `pr:merge` — does not stand in for it.
    #[tokio::test]
    async fn an_api_grant_does_not_answer_for_the_git_path() {
        let p = Project::new("case-a")
            .with_repo("Org/Repo", Mode::ReadWrite, &[])
            .grant("pr:merge");
        let auth = p
            .authorize("Org/Repo", Resource::Pr, Action::Merge)
            .unwrap();
        let g = Grant::for_test(&auth);
        for q in [
            Query::DefaultBranch,
            Query::CommitExists {
                sha: "a".repeat(40),
            },
            Query::IsAncestor {
                base: "a".repeat(40),
                head: "b".repeat(40),
            },
        ] {
            let e = relay().query(&q, Some(&g)).await.unwrap_err();
            assert_eq!(
                e.status,
                hyper::StatusCode::FORBIDDEN,
                "{q:?}: {}",
                e.message
            );
        }
    }

    /// A grant for one action does not drive another: the relay checks the kind it was handed.
    #[tokio::test]
    async fn a_grant_for_one_operation_does_not_drive_another() {
        let p = Project::new("case-a")
            .with_repo("Org/Repo", Mode::ReadWrite, &[])
            .grant("pr:read");
        let auth = p.authorize("Org/Repo", Resource::Pr, Action::Read).unwrap();
        let req = crate::api::types::ApiRequest {
            number: 1,
            ..Default::default()
        };
        let e = relay()
            .call(
                "/pr/merge",
                &[Grant::for_test(&auth)],
                &req,
                &Resolved::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(e.status, hyper::StatusCode::FORBIDDEN, "{}", e.message);
    }
}
