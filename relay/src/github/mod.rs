//! Upstream (github.com / GHES) API client.
//!
//! The key point: **every method requires an `&Authorized<'_>`**, so code that reaches upstream without
//! passing a policy check will not compile. For GraphQL (Projects v2) the relay builds the query itself, so agents never write GraphQL.
//!
//! ```compile_fail
//! # use sekimore_relay::github::GitHub;
//! # async fn f(gh: &GitHub) {
//! // You cannot call this with just a repository name, bypassing the policy check.
//! let _ = gh.create_pull_request("Attacker/evil", "x", "main", "t", "").await;
//! # }
//! ```

pub mod device_flow;
pub mod http;
pub mod upstream_token;

use std::fmt;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use crate::audit::{Actor, Audit};
use crate::policy::{Action, Authorized, Denied, Resource};
use http::{read_limited, truncate};
use upstream_token::{TokenError, UpstreamTokenStore};

pub const API_VERSION: &str = "2022-11-28";
const RESPONSE_CAP: usize = 1 << 20;
/// CI logs are large. The relay truncates them to the tail before returning, but caps the fetch at 16 MiB.
const CI_LOG_CAP: usize = 16 << 20;

#[derive(Debug)]
pub enum GhError {
    Denied(Denied),
    Token(TokenError),
    Http(reqwest::Error),
    Status {
        method: String,
        path: String,
        status: u16,
        body: String,
    },
    Parse(String),
    Graphql(String),
}

impl fmt::Display for GhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GhError::Denied(d) => write!(f, "{d}"),
            GhError::Token(e) => write!(f, "{e}"),
            GhError::Http(e) => write!(f, "upstream request failed: {e}"),
            GhError::Status {
                method,
                path,
                status,
                body,
            } => write!(f, "{method} {path}: HTTP {status} ({body})"),
            GhError::Parse(m) => write!(f, "parse upstream response: {m}"),
            GhError::Graphql(m) => write!(f, "graphql: {m}"),
        }
    }
}

impl std::error::Error for GhError {}

impl From<Denied> for GhError {
    fn from(d: Denied) -> Self {
        GhError::Denied(d)
    }
}
impl From<TokenError> for GhError {
    fn from(e: TokenError) -> Self {
        GhError::Token(e)
    }
}
impl From<reqwest::Error> for GhError {
    fn from(e: reqwest::Error) -> Self {
        GhError::Http(e)
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PrResult {
    pub number: u64,
    #[serde(default)]
    pub html_url: String,
    #[serde(default)]
    pub node_id: String,
}

/// 0.2.9: what a merge did, so the caller can report it and know whether the branch went with it.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct MergeResult {
    pub merged: bool,
    pub sha: String,
    pub branch_deleted: bool,
    /// The head branch, as the upstream named it (never as the caller named it)
    pub branch: String,
}

/// 0.2.6: a GitHub release.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReleaseResult {
    #[serde(default)]
    pub id: u64,
    pub tag_name: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub html_url: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub published_at: Option<String>,
}

/// 0.2.7: one hit from a search. `repository` is `Org/Repo`, which is what scopes it to the project.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SearchHit {
    pub number: u64,
    pub title: String,
    pub state: String,
    /// "issue" or "pr" — the search API mixes both and the caller needs to tell them apart
    pub kind: String,
    pub repository: String,
    pub author: String,
    pub html_url: String,
    pub updated_at: String,
}

/// A single CI check on a PR (a check-run or commit status, normalized to one shape).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CheckItem {
    pub name: String,
    /// success / failure / pending / neutral / skipped / … (GitHub's conclusion / state, verbatim)
    pub state: String,
    pub source: String, // "check-run" | "status"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// A PR and the rollup of its checks.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PrStatus {
    pub number: u64,
    pub head_sha: String,
    pub state: String, // open / closed
    pub merged: bool,
    pub mergeable: Option<bool>,
    pub checks: Vec<CheckItem>,
    /// Rollup over all checks: success / failure / pending / none
    pub rollup: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct IssueResult {
    pub number: u64,
    #[serde(default)]
    pub html_url: String,
    #[serde(default)]
    pub node_id: String,
}

/// 0.2.8: the full view of a pull request (`pr view`).
///
/// `pull_request_status` fetches the same object but keeps only what a CI rollup needs, so this is
/// a separate read rather than a widening of that one.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PrView {
    pub number: u64,
    pub title: String,
    pub body: String,
    pub state: String, // open / closed
    pub draft: bool,
    pub merged: bool,
    pub head: String,
    pub base: String,
    pub author: String,
    pub html_url: String,
    pub comments: u64,
    pub review_comments: u64,
    pub changed_files: u64,
    pub additions: u64,
    pub deletions: u64,
}

/// 0.2.8: the full view of an issue (`issue view`).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IssueView {
    pub number: u64,
    pub title: String,
    pub body: String,
    pub state: String,
    pub author: String,
    pub labels: Vec<String>,
    pub assignees: Vec<String>,
    pub html_url: String,
    pub comments: u64,
    /// GitHub serves pull requests from the issues endpoint too. True when this one is really a PR.
    pub is_pull_request: bool,
}

/// 0.2.8: one entry of a discussion, whichever of the three endpoints it came from.
///
/// The body is written by whoever commented. It is **data**: the relay carries the text through and
/// never reads it for instructions.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CommentItem {
    /// "comment" (conversation) | "review" (a review submission) | "inline" (a comment on the diff)
    pub kind: String,
    pub author: String,
    pub created_at: String,
    pub body: String,
    /// The review state: APPROVED / CHANGES_REQUESTED / COMMENTED (reviews only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// File an inline comment hangs on (inline only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    /// Set when an inline comment answers another one
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to_id: Option<u64>,
}

/// 0.2.8: one line of `issue list`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IssueBrief {
    pub number: u64,
    pub title: String,
    pub state: String,
    pub author: String,
    pub labels: Vec<String>,
    pub comments: u64,
    pub html_url: String,
}

/// 0.2.8: one line of `pr list`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PrBrief {
    pub number: u64,
    pub title: String,
    pub state: String,
    pub draft: bool,
    pub author: String,
    pub head: String,
    pub base: String,
    pub html_url: String,
}

pub struct GitHub {
    api_base: Url,
    graphql_base: Url,
    http: reqwest::Client,
    tokens: Arc<UpstreamTokenStore>,
    audit: Arc<Audit>,
}

impl GitHub {
    pub fn new(
        api_base: Url,
        graphql_base: Url,
        http: reqwest::Client,
        tokens: Arc<UpstreamTokenStore>,
        audit: Arc<Audit>,
    ) -> Self {
        GitHub {
            api_base,
            graphql_base,
            http,
            tokens,
            audit,
        }
    }

    // ---- Pull Request ----

    pub async fn create_pull_request(
        &self,
        auth: &Authorized<'_>,
        head: &str,
        base: &str,
        title: &str,
        body: &str,
    ) -> Result<PrResult, GhError> {
        auth.ensure(Resource::Pr, Action::Create)?;
        let out: Value = self
            .rest(
                "POST",
                &format!("/repos/{}/pulls", auth.repo()),
                Some(json!({"title": title, "head": head, "base": base, "body": body})),
            )
            .await?;
        serde_json::from_value::<PrResult>(out.clone()).map_err(|_| {
            GhError::Parse(format!(
                "PR not created: {}",
                out.get("message").and_then(Value::as_str).unwrap_or("?")
            ))
        })
    }

    /// 0.2.6: create a release for a tag that already exists upstream.
    ///
    /// `generate_notes` asks GitHub to build the body from the merged pull requests since the
    /// previous tag, which is what the CLI does by default. An explicit `body` is used as-is, and
    /// combines with `generate_notes`: GitHub appends the generated notes to it.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_release(
        &self,
        auth: &Authorized<'_>,
        tag: &str,
        name: Option<&str>,
        body: Option<&str>,
        generate_notes: bool,
        draft: bool,
        prerelease: bool,
    ) -> Result<ReleaseResult, GhError> {
        auth.ensure(Resource::Release, Action::Create)?;
        let mut payload = json!({
            "tag_name": tag,
            "generate_release_notes": generate_notes,
            "draft": draft,
            "prerelease": prerelease,
        });
        // The tag is the name unless the caller says otherwise, so a release is never left untitled.
        payload["name"] = json!(name.unwrap_or(tag));
        if let Some(b) = body {
            payload["body"] = json!(b);
        }
        let out: Value = self
            .rest(
                "POST",
                &format!("/repos/{}/releases", auth.repo()),
                Some(payload),
            )
            .await?;
        serde_json::from_value::<ReleaseResult>(out.clone()).map_err(|_| {
            GhError::Parse(format!(
                "release not created: {}",
                out.get("message").and_then(Value::as_str).unwrap_or("?")
            ))
        })
    }

    /// 0.2.6: the release for one tag. `Ok(None)` when the tag has no release yet.
    pub async fn get_release_by_tag(
        &self,
        auth: &Authorized<'_>,
        tag: &str,
    ) -> Result<Option<ReleaseResult>, GhError> {
        auth.ensure(Resource::Release, Action::Read)?;
        self.release_by_tag(auth.repo(), tag).await
    }

    /// The fetch behind `get_release_by_tag` and `get_release_for_edit`. Private, and reachable
    /// only from a method that has already proved something, so it adds no way around the policy.
    /// The tag is agent-supplied text in a path segment, hence `path_segment`.
    async fn release_by_tag(
        &self,
        repo: &str,
        tag: &str,
    ) -> Result<Option<ReleaseResult>, GhError> {
        match self
            .rest::<Value>(
                "GET",
                &format!("/repos/{repo}/releases/tags/{}", path_segment(tag)),
                None,
            )
            .await
        {
            Ok(v) => Ok(serde_json::from_value::<ReleaseResult>(v).ok()),
            Err(GhError::Status { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// 0.2.6: the most recent releases, newest first.
    pub async fn list_releases(
        &self,
        auth: &Authorized<'_>,
        limit: u32,
    ) -> Result<Vec<ReleaseResult>, GhError> {
        auth.ensure(Resource::Release, Action::Read)?;
        let out: Value = self
            .rest(
                "GET",
                &format!(
                    "/repos/{}/releases?per_page={}",
                    auth.repo(),
                    limit.clamp(1, 100)
                ),
                None,
            )
            .await?;
        Ok(serde_json::from_value::<Vec<ReleaseResult>>(out).unwrap_or_default())
    }

    /// 0.2.9: the release for a tag, for a caller that is about to edit it.
    ///
    /// `release edit` has to know the current draft state before it can tell whether the call
    /// publishes, and that lookup is part of the edit rather than a read of its own — demanding
    /// `release:read` to edit would make editing need two permissions. `release:create` is the
    /// floor for any edit, so that is what proves this one.
    pub async fn get_release_for_edit(
        &self,
        auth: &Authorized<'_>,
        tag: &str,
    ) -> Result<Option<ReleaseResult>, GhError> {
        auth.ensure(Resource::Release, Action::Create)?;
        self.release_by_tag(auth.repo(), tag).await
    }

    /// 0.2.9: edit a release, and publish a draft.
    ///
    /// `release create --draft` used to be a one-way door: the agent could make a draft and had no
    /// way to finish it. Editing a release that stays a draft is `release:create`; taking it out of
    /// draft is `release:publish`, which is the boundary `--draft` exists to create. The caller
    /// decides which proof to bring by looking the release up first, so `release:publish` is
    /// demanded only when the call actually publishes.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_release(
        &self,
        auth: &Authorized<'_>,
        release_id: u64,
        publishing: bool,
        name: Option<&str>,
        body: Option<&str>,
        draft: Option<bool>,
        prerelease: Option<bool>,
    ) -> Result<ReleaseResult, GhError> {
        auth.ensure(
            Resource::Release,
            if publishing {
                Action::Publish
            } else {
                Action::Create
            },
        )?;
        let mut payload = json!({});
        if let Some(n) = name {
            payload["name"] = json!(n);
        }
        if let Some(b) = body {
            payload["body"] = json!(b);
        }
        if let Some(d) = draft {
            payload["draft"] = json!(d);
        }
        if let Some(p) = prerelease {
            payload["prerelease"] = json!(p);
        }
        let out: Value = self
            .rest(
                "PATCH",
                &format!("/repos/{}/releases/{release_id}", auth.repo()),
                Some(payload),
            )
            .await?;
        serde_json::from_value::<ReleaseResult>(out.clone()).map_err(|_| {
            GhError::Parse(format!(
                "release not updated: {}",
                out.get("message").and_then(Value::as_str).unwrap_or("?")
            ))
        })
    }

    /// 0.2.9: re-run a workflow run, or only the jobs that failed.
    ///
    /// `ci:rerun` and not `ci:read`: this spends the account's Actions minutes and re-executes
    /// workflow code with the repository's secrets, which is a different authority from reading a
    /// log. The run id is a `u64` and cannot leave its path segment.
    pub async fn rerun_ci(
        &self,
        auth: &Authorized<'_>,
        run_id: u64,
        all: bool,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Ci, Action::Rerun)?;
        let what = if all { "rerun" } else { "rerun-failed-jobs" };
        self.rest::<Value>(
            "POST",
            &format!("/repos/{}/actions/runs/{run_id}/{what}", auth.repo()),
            None,
        )
        .await?;
        Ok(())
    }

    /// 0.2.9: stop a workflow run. Same permission as re-running: both steer what CI is doing.
    pub async fn cancel_ci(&self, auth: &Authorized<'_>, run_id: u64) -> Result<(), GhError> {
        auth.ensure(Resource::Ci, Action::Rerun)?;
        self.rest::<Value>(
            "POST",
            &format!("/repos/{}/actions/runs/{run_id}/cancel", auth.repo()),
            None,
        )
        .await?;
        Ok(())
    }

    /// Find an open PR with the same head/base, so a re-push to `refs/for` can report the existing PR.
    ///
    /// This reads, so `pr:read` is the right proof; the `refs/for` path holds `pr:create` and is
    /// accepted too, since creating a PR implies seeing the one that already exists.
    pub async fn find_pull_request(
        &self,
        auth: &Authorized<'_>,
        head: &str,
        base: &str,
    ) -> Result<Option<PrResult>, GhError> {
        if auth.ensure(Resource::Pr, Action::Read).is_err() {
            auth.ensure(Resource::Pr, Action::Create)?;
        }
        let owner = auth.repo().split('/').next().unwrap_or("");
        let path = format!(
            "/repos/{}/pulls?state=open&head={}&base={}",
            auth.repo(),
            url_escape(&format!("{owner}:{head}")),
            url_escape(base)
        );
        let out: Vec<PrResult> = self.rest("GET", &path, None).await?;
        Ok(out.into_iter().next())
    }
}

/// One page of a CI log: a window counted back from the end.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CiLogPage {
    pub job_id: u64,
    pub job_name: String,
    pub conclusion: String,
    /// Total number of log lines for this job
    pub total_lines: usize,
    /// The range being returned, [start, end) as zero-based line numbers
    pub start: usize,
    pub end: usize,
    pub lines: Vec<String>,
    /// Whether older lines exist before this window; if so, --before start walks further back
    pub has_more_before: bool,
}

/// An Actions run attached to a ref (tag / branch / SHA). Runs triggered by a tag push, such as Docker Publish,
/// have no PR, so they are reached through the ref rather than a PR number.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CiRun {
    pub id: u64,
    pub name: String,       // workflow name
    pub event: String,      // push / pull_request / workflow_dispatch …
    pub status: String,     // queued / in_progress / completed
    pub conclusion: String, // success / failure / "" (not finished)
    pub head_sha: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// The CI jobs of a PR (to see which ones failed).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CiJob {
    pub id: u64,
    pub name: String,
    pub status: String,     // queued / in_progress / completed
    pub conclusion: String, // success / failure / "" (not finished)
}

impl GitHub {
    /// Summarize a PR's state and CI checks, covering both check-runs (GitHub Actions and friends) and commit statuses (external CI).
    pub async fn pull_request_status(
        &self,
        auth: &Authorized<'_>,
        number: u64,
    ) -> Result<PrStatus, GhError> {
        auth.ensure(Resource::Pr, Action::Read)?;
        let repo = auth.repo();
        let pr: Value = self
            .rest("GET", &format!("/repos/{repo}/pulls/{number}"), None)
            .await?;
        let head_sha = pr
            .pointer("/head/sha")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let state = pr
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let merged = pr.get("merged").and_then(Value::as_bool).unwrap_or(false);
        let mergeable = pr.get("mergeable").and_then(Value::as_bool);

        let mut checks: Vec<CheckItem> = Vec::new();
        if !head_sha.is_empty() {
            // check-runs（GitHub Actions / Checks API）
            let runs: Value = self
                .rest(
                    "GET",
                    &format!("/repos/{repo}/commits/{head_sha}/check-runs?per_page=100"),
                    None,
                )
                .await?;
            if let Some(arr) = runs.get("check_runs").and_then(Value::as_array) {
                for r in arr {
                    let name = r
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    // Use the conclusion once finished; while running, treat the status (queued / in_progress) as pending.
                    let state = match r.get("conclusion").and_then(Value::as_str) {
                        Some(c) if !c.is_empty() => c.to_string(),
                        _ => "pending".to_string(),
                    };
                    checks.push(CheckItem {
                        name,
                        state,
                        source: "check-run".into(),
                        url: r
                            .get("html_url")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    });
                }
            }
            // Commit statuses (the older Status API used by Travis and others: only the latest per context)
            let st: Value = self
                .rest(
                    "GET",
                    &format!("/repos/{repo}/commits/{head_sha}/status"),
                    None,
                )
                .await?;
            if let Some(arr) = st.get("statuses").and_then(Value::as_array) {
                for s in arr {
                    checks.push(CheckItem {
                        name: s
                            .get("context")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        state: s
                            .get("state")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        source: "status".into(),
                        url: s
                            .get("target_url")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    });
                }
            }
        }
        let rollup = rollup_state(&checks);
        Ok(PrStatus {
            number,
            head_sha,
            state,
            merged,
            mergeable,
            checks,
            rollup,
        })
    }
    /// Resolve a ref (tag name / branch name / SHA) to a SHA. `GET /repos/{repo}/commits/{ref}` accepts all three forms.
    async fn resolve_sha(&self, repo: &str, git_ref: &str) -> Result<String, GhError> {
        let c: Value = self
            .rest(
                "GET",
                &format!("/repos/{repo}/commits/{}", path_segment(git_ref)),
                None,
            )
            .await?;
        c.get("sha")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| GhError::Parse(format!("no sha for ref {git_ref:?}")))
    }

    /// Actions runs attached to a ref, newest first. Used to see runs with no PR, such as Docker Publish on a tag push.
    pub async fn ci_runs(
        &self,
        auth: &Authorized<'_>,
        git_ref: &str,
    ) -> Result<Vec<CiRun>, GhError> {
        auth.ensure(Resource::Ci, Action::Read)?;
        let repo = auth.repo();
        let sha = self.resolve_sha(repo, git_ref).await?;
        let runs: Value = self
            .rest(
                "GET",
                &format!("/repos/{repo}/actions/runs?head_sha={sha}&per_page=100"),
                None,
            )
            .await?;
        let mut out: Vec<CiRun> = Vec::new();
        if let Some(arr) = runs.get("workflow_runs").and_then(Value::as_array) {
            for r in arr {
                let s = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                out.push(CiRun {
                    id: r.get("id").and_then(Value::as_u64).unwrap_or(0),
                    name: s("name"),
                    event: s("event"),
                    status: s("status"),
                    conclusion: s("conclusion"),
                    head_sha: s("head_sha"),
                    created_at: s("created_at"),
                    url: r
                        .get("html_url")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                });
            }
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(out)
    }

    /// The jobs of a run.
    pub async fn ci_jobs_for_run(
        &self,
        auth: &Authorized<'_>,
        run_id: u64,
    ) -> Result<Vec<CiJob>, GhError> {
        auth.ensure(Resource::Ci, Action::Read)?;
        let repo = auth.repo();
        let jobs: Value = self
            .rest(
                "GET",
                &format!("/repos/{repo}/actions/runs/{run_id}/jobs?per_page=100"),
                None,
            )
            .await?;
        let mut out = Vec::new();
        if let Some(arr) = jobs.get("jobs").and_then(Value::as_array) {
            for j in arr {
                let s = |k: &str| j.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                out.push(CiJob {
                    id: j.get("id").and_then(Value::as_u64).unwrap_or(0),
                    name: s("name"),
                    status: s("status"),
                    conclusion: s("conclusion"),
                });
            }
        }
        Ok(out)
    }

    /// Jobs of the latest Actions runs for a PR's head commit. Used to get the job_id of a failing job.
    pub async fn ci_jobs(&self, auth: &Authorized<'_>, number: u64) -> Result<Vec<CiJob>, GhError> {
        auth.ensure(Resource::Ci, Action::Read)?;
        let repo = auth.repo();
        let pr: Value = self
            .rest("GET", &format!("/repos/{repo}/pulls/{number}"), None)
            .await?;
        let head_sha = pr
            .pointer("/head/sha")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if head_sha.is_empty() {
            return Ok(Vec::new());
        }
        // A single SHA can have several workflow runs (relay.yml / test.yml / lint.yml …), so collect jobs from all of them.
        // If a workflow was re-run, keep only the newest one (first by descending created_at).
        let runs = self.ci_runs(auth, &head_sha).await?;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut out = Vec::new();
        for run in &runs {
            if !seen.insert(run.name.clone()) {
                continue;
            }
            for mut j in self.ci_jobs_for_run(auth, run.id).await? {
                if !run.name.is_empty() {
                    j.name = format!("{} / {}", run.name, j.name);
                }
                out.push(j);
            }
        }
        Ok(out)
    }

    /// One page of a job's log: `window` lines ending just before `before`; `before=None` means from the end.
    /// GitHub returns job logs as one plain-text blob, so the relay splits it into lines and returns the window.
    pub async fn ci_job_log(
        &self,
        auth: &Authorized<'_>,
        job_id: u64,
        job_name: &str,
        conclusion: &str,
        window: usize,
        before: Option<usize>,
    ) -> Result<CiLogPage, GhError> {
        auth.ensure(Resource::Ci, Action::Read)?;
        let repo = auth.repo();
        let text = self
            .rest_text("GET", &format!("/repos/{repo}/actions/jobs/{job_id}/logs"))
            .await?;
        let all: Vec<&str> = text.lines().collect();
        let total = all.len();
        let window = window.clamp(1, 2000);
        let end = before.unwrap_or(total).min(total);
        let start = end.saturating_sub(window);
        let lines = all[start..end].iter().map(|s| s.to_string()).collect();
        Ok(CiLogPage {
            job_id,
            job_name: job_name.to_string(),
            conclusion: conclusion.to_string(),
            total_lines: total,
            start,
            end,
            lines,
            has_more_before: start > 0,
        })
    }

    pub async fn comment_pull_request(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        body: &str,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Pr, Action::Comment)?;
        // PRs and issues share this endpoint, so the path cannot gate access; the caller's intent (the resource kind) decides.
        self.rest::<Value>(
            "POST",
            &format!("/repos/{}/issues/{number}/comments", auth.repo()),
            Some(json!({"body": body})),
        )
        .await?;
        Ok(())
    }

    pub async fn review_pull_request(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        event: &str,
        body: &str,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Pr, Action::Review)?;
        self.rest::<Value>(
            "POST",
            &format!("/repos/{}/pulls/{number}/reviews", auth.repo()),
            Some(json!({"event": event, "body": body})),
        )
        .await?;
        Ok(())
    }

    /// 0.2.7: ask people to review a pull request. Separate permission from submitting a review,
    /// because this notifies humans rather than recording an opinion.
    pub async fn request_reviewers(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        reviewers: &[String],
        team_reviewers: &[String],
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Pr, Action::RequestReview)?;
        let mut body = json!({});
        if !reviewers.is_empty() {
            body["reviewers"] = json!(reviewers);
        }
        if !team_reviewers.is_empty() {
            body["team_reviewers"] = json!(team_reviewers);
        }
        self.rest::<Value>(
            "POST",
            &format!("/repos/{}/pulls/{number}/requested_reviewers", auth.repo()),
            Some(body),
        )
        .await?;
        Ok(())
    }

    /// 0.2.9: merge with the options a repository may require.
    ///
    /// A repository configured squash-only rejects the default merge commit with 405, so the method
    /// has to be selectable. `method` / `title` / `message` are sent only when given, which keeps
    /// the request identical to the old one when the caller asks for nothing.
    ///
    /// `delete_branch` removes the head branch afterwards, and only after the merge actually
    /// succeeded. The branch name is never taken from the caller: it comes from the merge response,
    /// or from the pull request itself, so this cannot be turned into "delete an arbitrary ref".
    /// That is why it stays under `pr:merge` rather than the git-level `delete` flag — it completes
    /// the merge instead of deleting something of its own.
    pub async fn merge_pull_request(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        method: Option<&str>,
        title: Option<&str>,
        message: Option<&str>,
        delete_branch: bool,
    ) -> Result<MergeResult, GhError> {
        auth.ensure(Resource::Pr, Action::Merge)?;
        // Look the PR up first only when the head branch will be needed: the merge response carries
        // the SHA but not the branch name.
        let head = if delete_branch {
            let pr: Value = self
                .rest::<Value>(
                    "GET",
                    &format!("/repos/{}/pulls/{number}", auth.repo()),
                    None,
                )
                .await?;
            pointer_str(&pr, "/head/ref")
        } else {
            String::new()
        };
        let mut payload = json!({});
        if let Some(m) = method {
            payload["merge_method"] = json!(m);
        }
        if let Some(t) = title {
            payload["commit_title"] = json!(t);
        }
        if let Some(m) = message {
            payload["commit_message"] = json!(m);
        }
        let out: Value = self
            .rest(
                "PUT",
                &format!("/repos/{}/pulls/{number}/merge", auth.repo()),
                Some(payload),
            )
            .await?;
        let merged = out.get("merged").and_then(Value::as_bool).unwrap_or(true);
        let mut res = MergeResult {
            merged,
            sha: str_at(&out, "sha"),
            branch_deleted: false,
            branch: head.clone(),
        };
        // Only after a merge that actually happened, and only for a branch the upstream named.
        if delete_branch && merged && !head.is_empty() {
            self.rest::<Value>(
                "DELETE",
                &format!(
                    "/repos/{}/git/refs/heads/{}",
                    auth.repo(),
                    path_segment(&head)
                ),
                None,
            )
            .await?;
            res.branch_deleted = true;
        }
        Ok(res)
    }

    /// 0.2.9: the inverse of `close_pull_request`. Reopening is strictly less destructive than
    /// closing, so `pr:close` covers both.
    pub async fn reopen_pull_request(
        &self,
        auth: &Authorized<'_>,
        number: u64,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Pr, Action::Close)?;
        self.rest::<Value>(
            "PATCH",
            &format!("/repos/{}/pulls/{number}", auth.repo()),
            Some(json!({"state": "open"})),
        )
        .await?;
        Ok(())
    }

    /// 0.2.9: edit a pull request's own metadata.
    ///
    /// `pr:create` is the authority for title and body — editing the PR you opened is the same
    /// thing you already did when you opened it. `base` is different: retargeting a PR at another
    /// branch is exactly what `bases` exists to stop, so the caller has to bring a proof obtained
    /// from `Project::authorize_pr(repo, new_base)`, the same check `pr create` runs.
    pub async fn update_pull_request(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        title: Option<&str>,
        body: Option<&str>,
        base: Option<&str>,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Pr, Action::Create)?;
        let mut payload = json!({});
        if let Some(t) = title {
            payload["title"] = json!(t);
        }
        if let Some(b) = body {
            payload["body"] = json!(b);
        }
        if let Some(b) = base {
            payload["base"] = json!(b);
        }
        self.rest::<Value>(
            "PATCH",
            &format!("/repos/{}/pulls/{number}", auth.repo()),
            Some(payload),
        )
        .await?;
        Ok(())
    }

    pub async fn close_pull_request(
        &self,
        auth: &Authorized<'_>,
        number: u64,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Pr, Action::Close)?;
        self.rest::<Value>(
            "PATCH",
            &format!("/repos/{}/pulls/{number}", auth.repo()),
            Some(json!({"state": "closed"})),
        )
        .await?;
        Ok(())
    }

    // ---- Issue ----

    /// Applying labels is a separate permission: doing so also requires `label_auth` (proof of `issue:label`).
    pub async fn create_issue(
        &self,
        auth: &Authorized<'_>,
        title: &str,
        body: &str,
        labels: Option<(&Authorized<'_>, &[String])>,
    ) -> Result<IssueResult, GhError> {
        auth.ensure(Resource::Issue, Action::Create)?;
        let mut payload = json!({"title": title, "body": body});
        if let Some((label_auth, labels)) = labels {
            label_auth.ensure(Resource::Issue, Action::Label)?;
            if label_auth.repo() != auth.repo() {
                return Err(Denied::NotPermitted {
                    resource: "issue",
                    action: "label",
                }
                .into());
            }
            payload["labels"] = json!(labels);
        }
        let out: Value = self
            .rest(
                "POST",
                &format!("/repos/{}/issues", auth.repo()),
                Some(payload),
            )
            .await?;
        serde_json::from_value::<IssueResult>(out.clone()).map_err(|_| {
            GhError::Parse(format!(
                "issue not created: {}",
                out.get("message").and_then(Value::as_str).unwrap_or("?")
            ))
        })
    }

    pub async fn comment_issue(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        body: &str,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Issue, Action::Comment)?;
        self.rest::<Value>(
            "POST",
            &format!("/repos/{}/issues/{number}/comments", auth.repo()),
            Some(json!({"body": body})),
        )
        .await?;
        Ok(())
    }

    pub async fn close_issue(&self, auth: &Authorized<'_>, number: u64) -> Result<(), GhError> {
        auth.ensure(Resource::Issue, Action::Close)?;
        self.rest::<Value>(
            "PATCH",
            &format!("/repos/{}/issues/{number}", auth.repo()),
            Some(json!({"state": "closed"})),
        )
        .await?;
        Ok(())
    }

    /// 0.2.9: the inverse of `close_issue`, under the same permission — reopening undoes a close
    /// rather than adding a new power.
    pub async fn reopen_issue(&self, auth: &Authorized<'_>, number: u64) -> Result<(), GhError> {
        auth.ensure(Resource::Issue, Action::Close)?;
        self.rest::<Value>(
            "PATCH",
            &format!("/repos/{}/issues/{number}", auth.repo()),
            Some(json!({"state": "open"})),
        )
        .await?;
        Ok(())
    }

    pub async fn label_issue(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        labels: &[String],
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Issue, Action::Label)?;
        self.rest::<Value>(
            "POST",
            &format!("/repos/{}/issues/{number}/labels", auth.repo()),
            Some(json!({"labels": labels})),
        )
        .await?;
        Ok(())
    }

    pub async fn assign_issue(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        assignees: &[String],
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Issue, Action::Assign)?;
        self.rest::<Value>(
            "POST",
            &format!("/repos/{}/issues/{number}/assignees", auth.repo()),
            Some(json!({"assignees": assignees})),
        )
        .await?;
        Ok(())
    }

    /// 0.2.9: take one label off an issue. Adding and removing are the same authority, `issue:label`.
    ///
    /// The label name is agent-supplied text that lands in the request PATH, so it goes through
    /// `path_segment` and not `url_escape`: a name of `../../../Other/Secret/issues/1/labels/x`
    /// would otherwise be resolved by the URL parser and reach a repository outside the project
    /// with the operator's token (the 0.2.7 traversal fix).
    pub async fn unlabel_issue(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        label: &str,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Issue, Action::Label)?;
        self.rest::<Value>(
            "DELETE",
            &format!(
                "/repos/{}/issues/{number}/labels/{}",
                auth.repo(),
                path_segment(label)
            ),
            None,
        )
        .await?;
        Ok(())
    }

    /// 0.2.9: take assignees off an issue. The logins travel in a JSON body, so no path escaping is
    /// involved.
    pub async fn unassign_issue(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        assignees: &[String],
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Issue, Action::Assign)?;
        self.rest::<Value>(
            "DELETE",
            &format!("/repos/{}/issues/{number}/assignees", auth.repo()),
            Some(json!({"assignees": assignees})),
        )
        .await?;
        Ok(())
    }

    // ---- Projects v2 (GraphQL only) ----

    pub async fn add_project_item(
        &self,
        auth: &Authorized<'_>,
        project_id: &str,
        content_node_id: &str,
    ) -> Result<String, GhError> {
        auth.ensure(Resource::Project, Action::AddItem)?;
        const Q: &str = "mutation($project:ID!,$content:ID!){ addProjectV2ItemById(input:{projectId:$project,contentId:$content}){ item{ id } } }";
        let out = self
            .graphql(
                Q,
                json!({"project": project_id, "content": content_node_id}),
            )
            .await?;
        out.pointer("/data/addProjectV2ItemById/item/id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| GhError::Graphql("no item id in response".into()))
    }

    pub async fn update_project_item_field(
        &self,
        auth: &Authorized<'_>,
        project_id: &str,
        item_id: &str,
        field_id: &str,
        value: Value,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Project, Action::UpdateItem)?;
        const Q: &str = "mutation($project:ID!,$item:ID!,$field:ID!,$value:ProjectV2FieldValue!){ updateProjectV2ItemFieldValue(input:{projectId:$project,itemId:$item,fieldId:$field,value:$value}){ projectV2Item{ id } } }";
        self.graphql(
            Q,
            json!({"project": project_id, "item": item_id, "field": field_id, "value": value}),
        )
        .await?;
        Ok(())
    }

    pub async fn list_project_items(
        &self,
        auth: &Authorized<'_>,
        project_id: &str,
        first: u32,
    ) -> Result<Value, GhError> {
        auth.ensure(Resource::Project, Action::Read)?;
        const Q: &str = "query($project:ID!,$first:Int!){ node(id:$project){ ... on ProjectV2 { title items(first:$first){ nodes{ id type content{ ... on Issue { number title } ... on PullRequest { number title } } } } } } }";
        self.graphql(Q, json!({"project": project_id, "first": first}))
            .await
    }

    /// 0.2.7: the fields of a project board, with the option ids of every single-select.
    ///
    /// `project update-item` needs a `field_id`, and for a single-select the option's id rather
    /// than its name. Without this the ids had to come from a human, which made the update
    /// command unusable on its own.
    pub async fn list_project_fields(
        &self,
        auth: &Authorized<'_>,
        project_id: &str,
        first: u32,
    ) -> Result<Value, GhError> {
        auth.ensure(Resource::Project, Action::Read)?;
        const Q: &str = "query($project:ID!,$first:Int!){ node(id:$project){ ... on ProjectV2 { title fields(first:$first){ nodes{ ... on ProjectV2FieldCommon { id name dataType } ... on ProjectV2SingleSelectField { id name dataType options{ id name } } ... on ProjectV2IterationField { id name dataType configuration{ iterations{ id title } } } } } } } }";
        self.graphql(Q, json!({"project": project_id, "first": first}))
            .await
    }

    /// 0.2.7: resolve `orgs/<org>/projects/<n>` (or the user form) to its Projects v2 node id.
    ///
    /// The node id is what every Projects mutation takes, and it appears nowhere a person can copy
    /// it from, so the operator writes the board the way its URL reads and the relay looks it up
    /// once at startup. No agent proof: this runs before any agent is served, from the same place
    /// that reads the configuration.
    pub async fn resolve_project_board(
        &self,
        org: Option<&str>,
        user: Option<&str>,
        number: u32,
    ) -> Result<String, GhError> {
        const Q_ORG: &str = "query($login:String!,$number:Int!){ organization(login:$login){ projectV2(number:$number){ id } } }";
        const Q_USER: &str = "query($login:String!,$number:Int!){ user(login:$login){ projectV2(number:$number){ id } } }";
        let (q, login, owner_key) = match (org, user) {
            (Some(o), None) => (Q_ORG, o, "organization"),
            (None, Some(u)) => (Q_USER, u, "user"),
            _ => {
                return Err(GhError::Parse(
                    "project board needs exactly one of org / user".into(),
                ))
            }
        };
        let out = self
            .graphql(q, json!({"login": login, "number": number}))
            .await?;
        out.get("data")
            .and_then(|d| d.get(owner_key))
            .and_then(|o| o.get("projectV2"))
            .and_then(|p| p.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                GhError::Parse(format!(
                    "no Projects v2 board number {number} for {login}; check the number in its URL and that the upstream token can see it"
                ))
            })
    }

    /// 0.2.7: search issues and pull requests across the project's repositories.
    ///
    /// Unlike every other operation this is not addressed to one repository, so the project's
    /// repositories are appended to the query as `repo:` qualifiers. That is the scoping. The
    /// caller's own text is still their own — someone can write `repo:other/thing` and GitHub will
    /// honour it — so whatever comes back is filtered again against the project before it is
    /// returned. Two layers, because the first one is a request and the second one is a fact.
    pub async fn search_issues(
        &self,
        auth: &Authorized<'_>,
        project: &crate::policy::Project,
        query: &str,
        limit: u32,
    ) -> Result<Vec<SearchHit>, GhError> {
        auth.ensure(Resource::Search, Action::Read)?;
        let scope = project.search_scope();
        if scope.is_empty() {
            return Ok(Vec::new());
        }
        // `a OR b` over repo: qualifiers is how the search API takes several repositories
        let scoped = format!("{query} {}", scope.join(" "));
        let path = format!(
            "/search/issues?q={}&per_page={}",
            url_escape(&scoped),
            limit.clamp(1, 100)
        );
        let out: Value = self.rest("GET", &path, None).await?;
        let items = out
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut hits = Vec::new();
        for it in items {
            // repository_url is `…/repos/<owner>/<name>`; the search API gives no plain full name
            let repo = it
                .get("repository_url")
                .and_then(Value::as_str)
                .and_then(|u| {
                    let mut parts = u.rsplitn(3, '/');
                    let name = parts.next()?;
                    let owner = parts.next()?;
                    Some(format!("{owner}/{name}"))
                })
                .unwrap_or_default();
            if !project.owns_repo(&repo) {
                // A result from outside the project: the query was scoped, so this means the
                // caller wrote their own repo: qualifier. Drop it rather than report it.
                continue;
            }
            hits.push(SearchHit {
                number: it.get("number").and_then(Value::as_u64).unwrap_or(0),
                title: it
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                state: it
                    .get("state")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                kind: if it.get("pull_request").is_some() {
                    "pr".to_string()
                } else {
                    "issue".to_string()
                },
                repository: repo,
                author: it
                    .get("user")
                    .and_then(|u| u.get("login"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                html_url: it
                    .get("html_url")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                updated_at: it
                    .get("updated_at")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            });
        }
        Ok(hits)
    }

    /// 0.2.9: the vocabularies a repository defines — labels, the people who may be assigned, and
    /// the open milestones.
    ///
    /// `issue label` and `issue assign` take free text today, so an agent guesses: GitHub silently
    /// creates a label that does not exist, and 422s on an assignee who cannot be assigned. This is
    /// what `repo:read` is for; until now that key was declared and nothing checked it.
    pub async fn repo_vocabulary(
        &self,
        auth: &Authorized<'_>,
        limit: u32,
    ) -> Result<Value, GhError> {
        auth.ensure(Resource::Repo, Action::Read)?;
        let n = limit.clamp(1, 100);
        let repo = auth.repo();
        // Three independent reads; a failure on one should not lose the others
        let labels: Value = self
            .rest("GET", &format!("/repos/{repo}/labels?per_page={n}"), None)
            .await
            .unwrap_or(Value::Array(vec![]));
        let assignees: Value = self
            .rest(
                "GET",
                &format!("/repos/{repo}/assignees?per_page={n}"),
                None,
            )
            .await
            .unwrap_or(Value::Array(vec![]));
        let milestones: Value = self
            .rest(
                "GET",
                &format!("/repos/{repo}/milestones?state=open&per_page={n}"),
                None,
            )
            .await
            .unwrap_or(Value::Array(vec![]));
        let names = |v: &Value, key: &str| -> Vec<String> {
            v.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.get(key).and_then(Value::as_str))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        };
        Ok(json!({
            "labels": names(&labels, "name"),
            "assignees": names(&assignees, "login"),
            "milestones": names(&milestones, "title"),
        }))
    }

    // ---- For the operator (no proof required; never called from the agent path) ----

    /// Which upstream identity the relay acts as.
    pub async fn whoami(&self) -> Result<String, GhError> {
        let out: Value = self.rest("GET", "/user", None).await?;
        out.get("login")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| GhError::Parse("no login in /user".into()))
    }

    /// Upstream SSH host keys (`ssh_keys` from `GET /meta`). Used to generate known_hosts.
    pub async fn meta_ssh_keys(&self) -> Result<Vec<String>, GhError> {
        let out: Value = self.rest("GET", "/meta", None).await?;
        Ok(out
            .get("ssh_keys")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default())
    }

    // ---- Lower layer ----

    fn api_url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.api_base.as_str().trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    async fn rest<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        payload: Option<Value>,
    ) -> Result<T, GhError> {
        let token = self.tokens.token()?;
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| GhError::Parse(e.to_string()))?;
        let mut req = self
            .http
            .request(m, self.api_url(path))
            .bearer_auth(&token)
            .header(reqwest::header::USER_AGENT, http::USER_AGENT)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION);
        if let Some(p) = payload {
            req = req.json(&p);
        }
        self.send(req, method, path).await
    }

    /// Endpoints that return plain text (Actions job logs and the like). reqwest follows the redirects.
    async fn rest_text(&self, method: &str, path: &str) -> Result<String, GhError> {
        let token = self.tokens.token()?;
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| GhError::Parse(e.to_string()))?;
        let req = self
            .http
            .request(m, self.api_url(path))
            .bearer_auth(&token)
            .header(reqwest::header::USER_AGENT, http::USER_AGENT)
            .header("X-GitHub-Api-Version", API_VERSION);
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let body = read_limited(resp, CI_LOG_CAP).await?;
        let audit_path = path.split('?').next().unwrap_or(path);
        self.audit.log(
            "api_call",
            Actor::System,
            &[
                ("method", method),
                ("path", audit_path),
                ("status", &status.to_string()),
            ],
        );
        if status >= 400 {
            return Err(GhError::Status {
                method: method.to_string(),
                path: audit_path.to_string(),
                status,
                body: truncate(&body),
            });
        }
        Ok(String::from_utf8_lossy(&body).into_owned())
    }

    async fn graphql(&self, query: &str, variables: Value) -> Result<Value, GhError> {
        let token = self.tokens.token()?;
        let req = self
            .http
            .post(self.graphql_base.clone())
            .bearer_auth(&token)
            .header(reqwest::header::USER_AGENT, http::USER_AGENT)
            .header("X-GitHub-Api-Version", API_VERSION)
            .json(&json!({"query": query, "variables": variables}));
        let out: Value = self.send(req, "POST", "/graphql").await?;
        if let Some(errs) = out.get("errors").and_then(Value::as_array) {
            if let Some(first) = errs.first() {
                let msg = first
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error");
                return Err(GhError::Graphql(msg.to_string()));
            }
        }
        Ok(out)
    }

    async fn send<T: DeserializeOwned>(
        &self,
        req: reqwest::RequestBuilder,
        method: &str,
        path: &str,
    ) -> Result<T, GhError> {
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let body = read_limited(resp, RESPONSE_CAP).await?;
        // The query string is not worth auditing (the values are long).
        let audit_path = path.split('?').next().unwrap_or(path);
        self.audit.log(
            "api_call",
            Actor::System,
            &[
                ("method", method),
                ("path", audit_path),
                ("status", &status.to_string()),
            ],
        );
        if status >= 400 {
            return Err(GhError::Status {
                method: method.to_string(),
                path: audit_path.to_string(),
                status,
                body: truncate(&body),
            });
        }
        if body.is_empty() {
            // 204 and similar: yield null if the caller expects a Value.
            return serde_json::from_value(Value::Null).map_err(|e| GhError::Parse(e.to_string()));
        }
        serde_json::from_slice(&body)
            .map_err(|e| GhError::Parse(format!("{e}: {}", truncate(&body))))
    }
}

/// 0.2.8: read and list operations.
///
/// Everything here reads, so each method proves `Read` on its resource and nothing more. The only
/// agent-supplied text reaching upstream is a query VALUE (`state`, `base`, `labels`, `assignee`),
/// which goes through `url_escape`; the numbers are `u64` and cannot leave their path segment.
impl GitHub {
    /// The whole pull request, including the counts GitHub attaches to it.
    pub async fn pull_request_view(
        &self,
        auth: &Authorized<'_>,
        number: u64,
    ) -> Result<PrView, GhError> {
        auth.ensure(Resource::Pr, Action::Read)?;
        let pr: Value = self
            .rest(
                "GET",
                &format!("/repos/{}/pulls/{number}", auth.repo()),
                None,
            )
            .await?;
        Ok(PrView {
            number: pr.get("number").and_then(Value::as_u64).unwrap_or(number),
            title: str_at(&pr, "title"),
            body: pr
                .get("body")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            state: str_at(&pr, "state"),
            draft: pr.get("draft").and_then(Value::as_bool).unwrap_or(false),
            merged: pr.get("merged").and_then(Value::as_bool).unwrap_or(false),
            head: pointer_str(&pr, "/head/ref"),
            base: pointer_str(&pr, "/base/ref"),
            author: pointer_str(&pr, "/user/login"),
            html_url: str_at(&pr, "html_url"),
            comments: u64_at(&pr, "comments"),
            review_comments: u64_at(&pr, "review_comments"),
            changed_files: u64_at(&pr, "changed_files"),
            additions: u64_at(&pr, "additions"),
            deletions: u64_at(&pr, "deletions"),
        })
    }

    /// Everything said on a pull request, from the three places GitHub keeps it, as one list
    /// ordered by creation time: the conversation, the review submissions, and the comments on the
    /// diff. Reading only one of them misses most of a review.
    pub async fn pull_request_comments(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        limit: u32,
    ) -> Result<Vec<CommentItem>, GhError> {
        auth.ensure(Resource::Pr, Action::Read)?;
        let repo = auth.repo();
        let per = limit.clamp(1, 100);
        let mut out: Vec<CommentItem> = Vec::new();

        let conv: Value = self
            .rest(
                "GET",
                &format!("/repos/{repo}/issues/{number}/comments?per_page={per}"),
                None,
            )
            .await?;
        for c in conv.as_array().unwrap_or(&Vec::new()) {
            out.push(CommentItem {
                kind: "comment".into(),
                author: pointer_str(c, "/user/login"),
                created_at: str_at(c, "created_at"),
                body: str_at(c, "body"),
                state: None,
                path: None,
                line: None,
                in_reply_to_id: None,
            });
        }

        let reviews: Value = self
            .rest(
                "GET",
                &format!("/repos/{repo}/pulls/{number}/reviews?per_page={per}"),
                None,
            )
            .await?;
        for r in reviews.as_array().unwrap_or(&Vec::new()) {
            let body = str_at(r, "body");
            let state = str_at(r, "state");
            // A COMMENTED review with no body is just the envelope around the inline comments
            // below; it carries nothing to read, so it would only be noise.
            if body.is_empty() && state == "COMMENTED" {
                continue;
            }
            out.push(CommentItem {
                kind: "review".into(),
                author: pointer_str(r, "/user/login"),
                // A review is stamped when it is submitted; a pending one has no timestamp.
                created_at: str_at(r, "submitted_at"),
                body,
                state: Some(state),
                path: None,
                line: None,
                in_reply_to_id: None,
            });
        }

        let inline: Value = self
            .rest(
                "GET",
                &format!("/repos/{repo}/pulls/{number}/comments?per_page={per}"),
                None,
            )
            .await?;
        for c in inline.as_array().unwrap_or(&Vec::new()) {
            out.push(CommentItem {
                kind: "inline".into(),
                author: pointer_str(c, "/user/login"),
                created_at: str_at(c, "created_at"),
                body: str_at(c, "body"),
                state: None,
                path: c.get("path").and_then(Value::as_str).map(str::to_string),
                // `line` is null on a comment left against an outdated diff; original_line still has it.
                line: c
                    .get("line")
                    .and_then(Value::as_u64)
                    .or_else(|| c.get("original_line").and_then(Value::as_u64)),
                in_reply_to_id: c.get("in_reply_to_id").and_then(Value::as_u64),
            });
        }

        // One timeline across the three sources. The timestamps are RFC 3339 in UTC, so they sort
        // as strings; an entry without one (a pending review) sorts first rather than being dropped.
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(out)
    }

    /// One issue. GitHub also serves pull requests here, so the caller is told which it got.
    pub async fn issue_view(
        &self,
        auth: &Authorized<'_>,
        number: u64,
    ) -> Result<IssueView, GhError> {
        auth.ensure(Resource::Issue, Action::Read)?;
        let iss: Value = self
            .rest(
                "GET",
                &format!("/repos/{}/issues/{number}", auth.repo()),
                None,
            )
            .await?;
        Ok(IssueView {
            number: iss.get("number").and_then(Value::as_u64).unwrap_or(number),
            title: str_at(&iss, "title"),
            body: iss
                .get("body")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            state: str_at(&iss, "state"),
            author: pointer_str(&iss, "/user/login"),
            labels: label_names(&iss),
            assignees: logins(iss.get("assignees")),
            html_url: str_at(&iss, "html_url"),
            comments: u64_at(&iss, "comments"),
            is_pull_request: iss.get("pull_request").is_some(),
        })
    }

    /// The conversation on an issue. Issues have only the one kind of comment.
    pub async fn issue_comments(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        limit: u32,
    ) -> Result<Vec<CommentItem>, GhError> {
        auth.ensure(Resource::Issue, Action::Read)?;
        let out: Value = self
            .rest(
                "GET",
                &format!(
                    "/repos/{}/issues/{number}/comments?per_page={}",
                    auth.repo(),
                    limit.clamp(1, 100)
                ),
                None,
            )
            .await?;
        Ok(out
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|c| CommentItem {
                kind: "comment".into(),
                author: pointer_str(c, "/user/login"),
                created_at: str_at(c, "created_at"),
                body: str_at(c, "body"),
                state: None,
                path: None,
                line: None,
                in_reply_to_id: None,
            })
            .collect())
    }

    /// The repository's issues. The endpoint mixes pull requests in; they are dropped here, since
    /// `pr list` is where a PR belongs and `issue:read` is not `pr:read`.
    pub async fn list_issues(
        &self,
        auth: &Authorized<'_>,
        state: &str,
        labels: &[String],
        assignee: Option<&str>,
        limit: u32,
    ) -> Result<Vec<IssueBrief>, GhError> {
        auth.ensure(Resource::Issue, Action::Read)?;
        let mut path = format!(
            "/repos/{}/issues?state={}&per_page={}",
            auth.repo(),
            url_escape(state),
            limit.clamp(1, 100)
        );
        if !labels.is_empty() {
            path.push_str(&format!("&labels={}", url_escape(&labels.join(","))));
        }
        if let Some(a) = assignee {
            path.push_str(&format!("&assignee={}", url_escape(a)));
        }
        let out: Value = self.rest("GET", &path, None).await?;
        Ok(out
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter(|i| i.get("pull_request").is_none())
            .map(|i| IssueBrief {
                number: i.get("number").and_then(Value::as_u64).unwrap_or(0),
                title: str_at(i, "title"),
                state: str_at(i, "state"),
                author: pointer_str(i, "/user/login"),
                labels: label_names(i),
                comments: u64_at(i, "comments"),
                html_url: str_at(i, "html_url"),
            })
            .collect())
    }

    /// The repository's pull requests.
    pub async fn list_pull_requests(
        &self,
        auth: &Authorized<'_>,
        state: &str,
        base: Option<&str>,
        limit: u32,
    ) -> Result<Vec<PrBrief>, GhError> {
        auth.ensure(Resource::Pr, Action::Read)?;
        let mut path = format!(
            "/repos/{}/pulls?state={}&per_page={}",
            auth.repo(),
            url_escape(state),
            limit.clamp(1, 100)
        );
        if let Some(b) = base {
            path.push_str(&format!("&base={}", url_escape(b)));
        }
        let out: Value = self.rest("GET", &path, None).await?;
        Ok(out
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|p| PrBrief {
                number: p.get("number").and_then(Value::as_u64).unwrap_or(0),
                title: str_at(p, "title"),
                state: str_at(p, "state"),
                draft: p.get("draft").and_then(Value::as_bool).unwrap_or(false),
                author: pointer_str(p, "/user/login"),
                head: pointer_str(p, "/head/ref"),
                base: pointer_str(p, "/base/ref"),
                html_url: str_at(p, "html_url"),
            })
            .collect())
    }
}

/// A string field, or "" when it is absent or null.
fn str_at(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn u64_at(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// A string at a JSON pointer, or "" (`/user/login` is null on a comment left by a deleted account).
fn pointer_str(v: &Value, ptr: &str) -> String {
    v.pointer(ptr)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// The `name` of each label. GitHub gives objects here, and strings on some older payloads.
fn label_names(v: &Value) -> Vec<String> {
    v.get("labels")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|l| {
                    l.as_str()
                        .map(str::to_string)
                        .or_else(|| l.get("name").and_then(Value::as_str).map(str::to_string))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn logins(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|u| u.get("login").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Roll up a set of checks: failure if any check failed, otherwise pending if any is pending,
/// success if all are success/neutral/skipped, and none if there are no checks at all.
fn rollup_state(checks: &[CheckItem]) -> String {
    if checks.is_empty() {
        return "none".to_string();
    }
    let mut pending = false;
    for c in checks {
        match c.state.as_str() {
            "success" | "neutral" | "skipped" => {}
            "pending" | "queued" | "in_progress" | "expected" => pending = true,
            // failure / error / cancelled / timed_out / action_required / stale / startup_failure …
            _ => return "failure".to_string(),
        }
    }
    if pending {
        "pending".to_string()
    } else {
        "success".to_string()
    }
}

/// Escape a value that goes into a query string. `/` and `.` are safe there, and `head=owner:branch`
/// relies on `/` surviving.
fn url_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Escape one **path segment**. Unlike a query value, `/` and `.` must not survive here: the URL
/// parser resolves `..` when it builds the request, so a tag or ref of `../../../Other/Repo/…`
/// would otherwise walk out of `/repos/<owner>/<repo>/` and reach a repository the project never
/// granted, using the operator's token. Percent-encoding both characters keeps the segment inert.
fn path_segment(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Mode, Project};

    fn gh() -> GitHub {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(UpstreamTokenStore::new(
            &dir.path().join("t"),
            std::time::Duration::from_secs(60),
        ));
        std::mem::forget(dir);
        GitHub::new(
            Url::parse("https://upstream.invalid/api/v3").unwrap(),
            Url::parse("https://upstream.invalid/api/graphql").unwrap(),
            reqwest::Client::new(),
            store,
            Arc::new(Audit::disabled()),
        )
    }

    #[tokio::test]
    async fn wrong_proof_is_rejected_before_http() {
        let p = Project::new("case-a")
            .with_repo("Org/Repo", Mode::ReadWrite, &[])
            .grant("pr:create");
        let auth = p
            .authorize("Org/Repo", Resource::Pr, Action::Create)
            .unwrap();
        let g = gh();
        // Proof of pr:create cannot drive a merge (it reaches neither upstream nor the token store).
        assert!(matches!(
            g.merge_pull_request(&auth, 1, None, None, None, false)
                .await,
            Err(GhError::Denied(_))
        ));
        assert!(matches!(
            g.comment_issue(&auth, 1, "x").await,
            Err(GhError::Denied(_))
        ));
        // Even with the right proof, a missing upstream token is a Token error (nothing hits the network).
        assert!(matches!(
            g.create_pull_request(&auth, "h", "main", "t", "").await,
            Err(GhError::Token(_))
        ));
    }

    #[tokio::test]
    async fn pr_status_requires_pr_read() {
        // pr:create alone cannot query pr status (that needs proof of Read), and never reaches upstream.
        let p = Project::new("case-a")
            .with_repo("Org/Repo", Mode::ReadWrite, &[])
            .grant("pr:create");
        let auth = p
            .authorize("Org/Repo", Resource::Pr, Action::Create)
            .unwrap();
        assert!(matches!(
            gh().pull_request_status(&auth, 1).await,
            Err(GhError::Denied(_))
        ));
        // With pr:read the proof passes and we get as far as the missing upstream token.
        let p = Project::new("case-a")
            .with_repo("Org/Repo", Mode::ReadOnly, &[])
            .grant("pr:read");
        let auth = p.authorize("Org/Repo", Resource::Pr, Action::Read).unwrap();
        assert!(matches!(
            gh().pull_request_status(&auth, 1).await,
            Err(GhError::Token(_))
        ));
    }

    #[test]
    fn rollup_prioritises_failure_then_pending() {
        let mk = |state: &str| CheckItem {
            name: "c".into(),
            state: state.into(),
            source: "check-run".into(),
            url: None,
        };
        assert_eq!(rollup_state(&[]), "none");
        assert_eq!(rollup_state(&[mk("success"), mk("skipped")]), "success");
        assert_eq!(rollup_state(&[mk("success"), mk("in_progress")]), "pending");
        // failure wins over pending: one broken check makes the rollup failure.
        assert_eq!(rollup_state(&[mk("in_progress"), mk("failure")]), "failure");
        assert_eq!(rollup_state(&[mk("success"), mk("timed_out")]), "failure");
        assert_eq!(rollup_state(&[mk("neutral"), mk("cancelled")]), "failure");
    }

    #[tokio::test]
    async fn ci_requires_ci_read() {
        // pr:read alone cannot query ci.
        let p = Project::new("case-a")
            .with_repo("Org/Repo", Mode::ReadOnly, &[])
            .grant("pr:read");
        let auth = p.authorize("Org/Repo", Resource::Pr, Action::Read).unwrap();
        assert!(matches!(
            gh().ci_jobs(&auth, 1).await,
            Err(GhError::Denied(_))
        ));
        // With ci:read the proof passes and we get as far as the upstream token.
        let p = Project::new("case-a")
            .with_repo("Org/Repo", Mode::ReadOnly, &[])
            .grant("ci:read");
        let auth = p.authorize("Org/Repo", Resource::Ci, Action::Read).unwrap();
        assert!(matches!(
            gh().ci_jobs(&auth, 1).await,
            Err(GhError::Token(_))
        ));
        assert!(matches!(
            gh().ci_job_log(&auth, 99, "test", "failure", 100, None)
                .await,
            Err(GhError::Token(_))
        ));
        // The ref / run_id paths take the same proof and likewise reach the upstream token stage.
        assert!(matches!(
            gh().ci_runs(&auth, "v0.1.6").await,
            Err(GhError::Token(_))
        ));
        assert!(matches!(
            gh().ci_jobs_for_run(&auth, 1).await,
            Err(GhError::Token(_))
        ));
        // Proof of pr:read alone is denied.
        let p = Project::new("case-a")
            .with_repo("Org/Repo", Mode::ReadOnly, &[])
            .grant("pr:read");
        let auth = p.authorize("Org/Repo", Resource::Pr, Action::Read).unwrap();
        assert!(matches!(
            gh().ci_runs(&auth, "main").await,
            Err(GhError::Denied(_))
        ));
    }

    #[test]
    fn ci_read_is_a_valid_permission() {
        use crate::policy::parse_permission;
        assert!(parse_permission("ci:read").is_ok());
        assert!(crate::policy::all_permission_keys().contains(&"ci:read".to_string()));
    }

    #[test]
    fn pr_read_is_a_valid_permission() {
        use crate::policy::parse_permission;
        assert!(parse_permission("pr:read").is_ok());
        assert!(crate::policy::all_permission_keys().contains(&"pr:read".to_string()));
    }

    #[test]
    fn api_url_joins_without_double_slash() {
        let g = gh();
        assert_eq!(
            g.api_url("/repos/a/b/pulls"),
            "https://upstream.invalid/api/v3/repos/a/b/pulls"
        );
        assert_eq!(
            url_escape("Org:sekimore/main-abc"),
            "Org%3Asekimore/main-abc"
        );
    }
}
