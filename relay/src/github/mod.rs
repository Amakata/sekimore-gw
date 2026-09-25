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
use crate::paths;
use crate::policy::{Action, Authorized, Denied, Resource};
use http::{read_limited, truncate};
use upstream_token::{TokenError, UpstreamTokenStore};

pub const API_VERSION: &str = "2022-11-28";
const RESPONSE_CAP: usize = 1 << 20;
/// CI logs are large. The relay truncates them to the tail before returning, but caps the fetch at 16 MiB.
const CI_LOG_CAP: usize = 16 << 20;
/// #173: how many files of a pull request are asked for at once. Every file's patch comes with it
/// whether or not it is wanted, and `rest` truncates at `RESPONSE_CAP` (1 MiB) — a response cut
/// mid-JSON does not parse — so the page is kept well inside that rather than GitHub's 100.
const PR_FILES_PER_PAGE: u32 = 30;
/// #173: how many such pages are walked. 30 × 10 = 300 files, past which listing a pull request
/// file by file has stopped being a way to read it.
const PR_FILES_PAGES: u32 = 10;
/// #173: the most diff lines one `pr diff` page returns, matching the cap on a CI log page.
const PR_DIFF_MAX_LINES: usize = 2000;

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
    /// 0.2.34 (#172): the upstream would have allowed it and the relay would not. Its own variant
    /// so the audit can tell "we refused" apart from "GitHub refused"
    Refused(String),
}

impl fmt::Display for GhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GhError::Denied(d) => write!(f, "{d}"),
            GhError::Token(e) => write!(f, "{e}"),
            // #206: reqwest prints only its own layer, so a `HandshakeFailure` from the upstream
            // proxy arrived as "error sending request for url (…)" and said nothing. Walk the
            // chain, and when the alert is in there say what the proxy must offer.
            GhError::Http(e) => write!(f, "upstream request failed: {e}{}", handshake_hint(e)),
            GhError::Status {
                method,
                path,
                status,
                body,
            } => write!(f, "{method} {path}: HTTP {status} ({body})"),
            GhError::Parse(m) => write!(f, "parse upstream response: {m}"),
            GhError::Graphql(m) => write!(f, "graphql: {m}"),
            GhError::Refused(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for GhError {}

/// The `HandshakeFailure` hint for a reqwest error, or the empty string (#205, #206).
///
/// `Display` on a reqwest error shows one layer; the alert rustls raised is further down the
/// `source()` chain, so the whole chain is flattened before it is matched on.
fn handshake_hint(e: &reqwest::Error) -> &'static str {
    hint_for_chain(&error_chain(e))
}

/// Every layer of an error's `source()` chain, joined — what `Display` alone does not show.
fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        out.push_str(": ");
        out.push_str(&s.to_string());
        src = s.source();
    }
    out
}

fn hint_for_chain(chain: &str) -> &'static str {
    if crate::netutil::is_handshake_failure(chain) {
        crate::netutil::HANDSHAKE_HINT
    } else {
        ""
    }
}

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
    /// The GraphQL node id. `project add-item` takes one, and nothing else hands it out:
    /// without this, an item can only join a board in the same breath as being created.
    pub node_id: String,
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
    /// The GraphQL node id — see `PrView::node_id`.
    pub node_id: String,
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
    /// 0.2.33 (#165): the comment's own id, which `pr reply` needs to answer it. Inline comments
    /// only: a conversation comment is answered with `pr comment`, which names no id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    /// 0.2.33 (#165): the review this belongs to. A review carries its own id here and its line
    /// comments repeat it, which is what lets one submission be shown as one thing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_id: Option<u64>,
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
    /// 0.2.34 (#172): who the token belongs to, read once. It cannot change without the token
    /// changing, and checking a comment's author on every edit would otherwise pay for it twice
    viewer: std::sync::OnceLock<String>,
    /// #228: the ledger edge every `api_call` is written on — direct, via the upstream proxy,
    /// or via the local Squid — decided once from the proxy config (`paths::github_route`).
    route: &'static str,
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
            viewer: std::sync::OnceLock::new(),
            route: paths::RELAY_GITHUB_API,
        }
    }

    /// Names the hop this client's calls take (see `paths::github_route`).
    pub fn with_route(mut self, route: &'static str) -> Self {
        self.route = route;
        self
    }

    // ---- Pull Request ----

    pub async fn create_pull_request(
        &self,
        auth: &Authorized<'_>,
        head: &str,
        base: &str,
        title: &str,
        body: &str,
        draft: bool,
    ) -> Result<PrResult, GhError> {
        auth.ensure(Resource::Pr, Action::Create)?;
        let out: Value = self
            .rest(
                "POST",
                &format!("/repos/{}/pulls", auth.repo()),
                Some(json!({
                    "title": title, "head": head, "base": base, "body": body,
                    // #169: a draft runs CI without asking anyone to look yet
                    "draft": draft,
                })),
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

/// One file in a pull request, without its patch. What `pr files` answers with.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PrFile {
    pub path: String,
    /// added / modified / removed / renamed / copied / changed / unchanged
    pub status: String,
    pub additions: u64,
    pub deletions: u64,
    /// Set when GitHub sends no patch for this file: binary, or too large to diff
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_patch: Option<String>,
    /// The hunks, as GitHub sends them. Not serialized: `pr files` answers without patches, and
    /// `pr diff` renders them into `DiffLine`s
    #[serde(skip)]
    pub patch: Option<String>,
}

/// One line of a diff, carrying the number to quote it by.
///
/// #173: `pr review --comment path:line:body` takes GitHub's line number in the new file, and
/// nothing else in the relay could tell an agent what that number is. A deleted line has no
/// number in the new file, so `line` is None there — it cannot be commented on by line.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DiffLine {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    /// add / del / ctx / hunk
    pub kind: String,
    pub text: String,
}

/// One page of one file's patch. Paged like `ci log`, but forwards from the top: a diff is read
/// from its first hunk, where a log is read from its last line.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PrDiffPage {
    pub path: String,
    pub status: String,
    pub additions: u64,
    pub deletions: u64,
    pub lines: Vec<DiffLine>,
    pub total_lines: usize,
    /// The range being returned, [start, end) as zero-based line numbers within this file's patch
    pub start: usize,
    pub end: usize,
    pub has_more_after: bool,
    /// The file after this one, when the pull request touches more than the one being shown
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_path: Option<String>,
    /// Set instead of `lines` when GitHub sends no patch for this file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_patch: Option<String>,
    /// How many files the pull request touches, and which one this is (1-based)
    pub file_index: usize,
    pub file_count: usize,
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

/// One Dependabot alert (0.2.28, #132): what is vulnerable, how badly, and what fixes it. The
/// fields are the ones a triage reads; the whole object is in `raw` for anything else.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecurityAlert {
    pub number: u64,
    pub state: String,    // open / dismissed / fixed / auto_dismissed
    pub severity: String, // low / medium / high / critical
    pub ecosystem: String,
    pub package: String,
    pub manifest_path: String,
    pub scope: String, // runtime / development / ""
    pub ghsa_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve_id: Option<String>,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_in: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dismissed_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl SecurityAlert {
    fn from_json(a: &Value) -> Self {
        let s = |v: Option<&Value>| v.and_then(Value::as_str).unwrap_or("").to_string();
        let opt = |v: Option<&Value>| v.and_then(Value::as_str).map(str::to_string);
        let adv = a.get("security_advisory");
        let dep = a.get("dependency");
        let pkg = dep.and_then(|d| d.get("package"));
        SecurityAlert {
            number: a.get("number").and_then(Value::as_u64).unwrap_or(0),
            state: s(a.get("state")),
            severity: s(adv.and_then(|v| v.get("severity"))),
            ecosystem: s(pkg.and_then(|v| v.get("ecosystem"))),
            package: s(pkg.and_then(|v| v.get("name"))),
            manifest_path: s(dep.and_then(|v| v.get("manifest_path"))),
            scope: s(dep.and_then(|v| v.get("scope"))),
            ghsa_id: s(adv.and_then(|v| v.get("ghsa_id"))),
            cve_id: opt(adv.and_then(|v| v.get("cve_id"))),
            summary: s(adv.and_then(|v| v.get("summary"))),
            fixed_in: opt(a
                .get("security_vulnerability")
                .and_then(|v| v.get("first_patched_version"))
                .and_then(|v| v.get("identifier"))),
            dismissed_reason: opt(a.get("dismissed_reason")),
            url: opt(a.get("html_url")),
        }
    }
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
    /// 0.2.29 (#59): whether the upstream already holds this commit object.
    ///
    /// Asked while judging a push under `signing: required`. A pack carries only what the upstream
    /// lacks, so a sha the scan did not see is *supposed* to be history the upstream already has —
    /// but a commit hidden behind a delta whose base lives upstream looks exactly the same from
    /// inside the pack, and that is a way to push an unsigned commit past the check. The upstream
    /// is the only thing that can tell the two apart.
    ///
    /// Scoped by the push's own authorization rather than by an API permission: the question is
    /// about a commit in the repository this push was already allowed to write to, so
    /// `GitAuthorized` is exactly the proof it needs. Demanding `repo:read` instead would make
    /// `signing: required` refuse every push in a project that does not grant it.
    pub async fn commit_exists(
        &self,
        auth: &crate::policy::GitAuthorized<'_>,
        sha: &str,
    ) -> Result<bool, GhError> {
        // The sha comes off the wire. A path segment is escaped everywhere else in this file for
        // the same reason, and this one is also checked to be a sha at all, because anything that
        // is not cannot name a commit and asking would only spend a call.
        if sha.len() != 40 || !sha.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Ok(false);
        }
        match self
            .rest::<Value>(
                "GET",
                &format!("/repos/{}/git/commits/{}", auth.repo(), path_segment(sha)),
                None,
            )
            .await
        {
            Ok(_) => Ok(true),
            // 404 is "no such object"; 422 is what GitHub answers for a sha that is well-formed
            // but names something that is not a commit
            Err(GhError::Status {
                status: 404 | 422, ..
            }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// 0.3.0 (#158): the repository's default branch, for `refs/pr/<branch>`, which names no base.
    ///
    /// Read at pull-request time rather than when the push is planned: planning is offline and
    /// synchronous, and creating the pull request already calls the API.
    pub async fn default_branch(
        &self,
        auth: &crate::policy::GitAuthorized<'_>,
    ) -> Result<String, GhError> {
        let r: Value = self
            .rest("GET", &format!("/repos/{}", auth.repo()), None)
            .await?;
        r.get("default_branch")
            .and_then(Value::as_str)
            .filter(|b| !b.is_empty())
            .map(str::to_string)
            .ok_or_else(|| GhError::Parse(format!("no default_branch for {}", auth.repo())))
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

    /// The repository's Dependabot alerts (0.2.28, #132). `state` is GitHub's filter — open /
    /// dismissed / fixed / auto_dismissed — or `all` for no filter. Needs the `security_events`
    /// OAuth scope on the upstream token; without it GitHub answers 403 and this says so.
    pub async fn security_alerts(
        &self,
        auth: &Authorized<'_>,
        state: &str,
    ) -> Result<Vec<SecurityAlert>, GhError> {
        auth.ensure(Resource::Security, Action::Read)?;
        let repo = auth.repo();
        let filter = if state == "all" {
            String::new()
        } else {
            format!("&state={state}")
        };
        let v: Value = self
            .rest(
                "GET",
                &format!(
                    "/repos/{repo}/dependabot/alerts?per_page=100&sort=created&direction=desc{filter}"
                ),
                None,
            )
            .await?;
        Ok(v.as_array()
            .map(|arr| arr.iter().map(SecurityAlert::from_json).collect())
            .unwrap_or_default())
    }

    pub async fn security_alert(
        &self,
        auth: &Authorized<'_>,
        number: u64,
    ) -> Result<SecurityAlert, GhError> {
        auth.ensure(Resource::Security, Action::Read)?;
        let v: Value = self
            .rest(
                "GET",
                &format!("/repos/{}/dependabot/alerts/{number}", auth.repo()),
                None,
            )
            .await?;
        Ok(SecurityAlert::from_json(&v))
    }

    /// Set an alert aside. `reason` is one of GitHub's five; `comment` is optional and at most
    /// 280 characters — both are checked by the handler, and GitHub checks them again.
    pub async fn security_alert_dismiss(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        reason: &str,
        comment: &str,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Security, Action::Dismiss)?;
        let mut body = json!({"state": "dismissed", "dismissed_reason": reason});
        if !comment.is_empty() {
            body["dismissed_comment"] = Value::String(comment.to_string());
        }
        self.rest::<Value>(
            "PATCH",
            &format!("/repos/{}/dependabot/alerts/{number}", auth.repo()),
            Some(body),
        )
        .await?;
        Ok(())
    }

    /// The inverse of dismissing, under the same authority.
    pub async fn security_alert_reopen(
        &self,
        auth: &Authorized<'_>,
        number: u64,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Security, Action::Dismiss)?;
        self.rest::<Value>(
            "PATCH",
            &format!("/repos/{}/dependabot/alerts/{number}", auth.repo()),
            Some(json!({"state": "open"})),
        )
        .await?;
        Ok(())
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

    /// #173: the files a pull request touches, without their patches.
    ///
    /// The cheap half of reading a diff: which files, and how much moved in each. `pr diff` then
    /// asks for one of them.
    ///
    /// `pages` bounds how much is fetched. Every patch of every file arrives on this endpoint, and
    /// `rest` reads at most `RESPONSE_CAP` and *truncates* — a page cut mid-JSON fails to parse,
    /// which is exactly what a wide pull request would do. So the list is walked a page at a time
    /// and stops rather than asking for one oversized response.
    async fn pull_request_files_paged(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        pages: u32,
        per_page: u32,
    ) -> Result<(Vec<PrFile>, bool), GhError> {
        auth.ensure(Resource::Pr, Action::Read)?;
        let mut all = Vec::new();
        for page in 1..=pages {
            let out: Value = self
                .rest(
                    "GET",
                    &format!(
                        "/repos/{}/pulls/{number}/files?per_page={per_page}&page={page}",
                        auth.repo()
                    ),
                    None,
                )
                .await?;
            let batch = out.as_array().map(Vec::as_slice).unwrap_or_default();
            let short = batch.len() < per_page as usize;
            all.extend(batch.iter().map(pr_file));
            if short {
                return Ok((all, false));
            }
        }
        // A full last page means GitHub may hold more than was asked for
        Ok((all, true))
    }

    /// #173: the file list alone.
    ///
    /// The patches ride along whether or not they are wanted — GitHub has no way to ask for the
    /// list without them — so the page is kept small enough that a page of large ones still fits
    /// under `RESPONSE_CAP`, and each patch is dropped once its counts have been read.
    pub async fn pull_request_files(
        &self,
        auth: &Authorized<'_>,
        number: u64,
    ) -> Result<(Vec<PrFile>, bool), GhError> {
        let (mut files, more) = self
            .pull_request_files_paged(auth, number, PR_FILES_PAGES, PR_FILES_PER_PAGE)
            .await?;
        for f in &mut files {
            f.patch = None;
        }
        Ok((files, more))
    }

    /// #173: one file's patch, with GitHub's line numbers, a window at a time.
    ///
    /// `path` names the file; without one the first file of the pull request is taken, so that an
    /// agent that knows only the number still gets something to read. Paged forward from `before`
    /// — here a start offset, not an end — because a diff is read from the top.
    pub async fn pull_request_diff(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        path: Option<&str>,
        window: usize,
        from: usize,
    ) -> Result<PrDiffPage, GhError> {
        // Keeps the patches: this is the one caller that renders them
        let (files, truncated) = self
            .pull_request_files_paged(auth, number, PR_FILES_PAGES, PR_FILES_PER_PAGE)
            .await?;
        if files.is_empty() {
            return Err(GhError::Refused(format!(
                "pull request #{number} touches no files"
            )));
        }
        let idx = match path {
            None => 0,
            Some(p) => files.iter().position(|f| f.path == p).ok_or_else(|| {
                // Saying which it is matters: "not in this pull request" and "past the point
                // where the relay stopped listing" call for different next steps
                let tail = if truncated {
                    format!(
                        "; #{number} touches more files than the relay lists ({} so far)",
                        files.len()
                    )
                } else {
                    String::new()
                };
                GhError::Refused(format!(
                    "#{number} does not touch {p}{tail}; sekimore pr files --number {number} lists what it does"
                ))
            })?,
        };
        let f = &files[idx];
        let all = f.patch.as_deref().map(parse_patch).unwrap_or_default();
        let total = all.len();
        let window = window.clamp(1, PR_DIFF_MAX_LINES);
        let start = from.min(total);
        let end = (start + window).min(total);
        Ok(PrDiffPage {
            path: f.path.clone(),
            status: f.status.clone(),
            additions: f.additions,
            deletions: f.deletions,
            lines: all[start..end].to_vec(),
            total_lines: total,
            start,
            end,
            has_more_after: end < total,
            next_path: files.get(idx + 1).map(|n| n.path.clone()),
            no_patch: f.no_patch.clone(),
            file_index: idx + 1,
            file_count: files.len(),
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

    /// #172: who the upstream token belongs to. Cached for the life of the client: it cannot
    /// change without the token changing, and every edit or delete would otherwise pay for it.
    async fn viewer_login(&self) -> Result<String, GhError> {
        if let Some(l) = self.viewer.get() {
            return Ok(l.clone());
        }
        let me: Value = self.rest("GET", "/user", None).await?;
        let login = me
            .get("login")
            .and_then(Value::as_str)
            .ok_or_else(|| GhError::Parse("no login for the upstream token".into()))?
            .to_string();
        let _ = self.viewer.set(login.clone());
        Ok(login)
    }

    /// #172: refuse to touch a comment the agent did not write, or one on another number.
    ///
    /// GitHub lets a token with write access edit or delete anyone's comment. An agent deleting a
    /// reviewer's note would be worse than anything this feature is for, so the author is read
    /// before the write and anything else is refused. The number is checked too: the caller was
    /// authorized for what `number` names, and a comment id is repo-wide, so without it an id from
    /// an issue would ride on a pull request's permission. Returns the path to write to.
    async fn own_comment(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        inline: bool,
        comment_id: u64,
    ) -> Result<String, GhError> {
        // A conversation comment and a line comment live in different namespaces
        let (kind, parent_field, parent_kind) = if inline {
            ("pulls", "/pull_request_url", "pulls")
        } else {
            ("issues", "/issue_url", "issues")
        };
        let path = format!("/repos/{}/{kind}/comments/{comment_id}", auth.repo());
        let c: Value = self.rest("GET", &path, None).await?;
        let parent = pointer_str(&c, parent_field);
        if !parent.ends_with(&format!("/{parent_kind}/{number}")) {
            return Err(GhError::Refused(format!(
                "comment {comment_id} is not on #{number}"
            )));
        }
        let author = pointer_str(&c, "/user/login");
        let me = self.viewer_login().await?;
        if author.is_empty() || !author.eq_ignore_ascii_case(&me) {
            return Err(GhError::Refused(format!(
                "comment {comment_id} was written by {}, not by this agent ({me}); \
                 only its own comments can be changed or removed",
                if author.is_empty() {
                    "someone else"
                } else {
                    &author
                }
            )));
        }
        Ok(path)
    }

    /// #172: correct a comment the agent posted on `number`. `inline` names a line comment.
    pub async fn update_comment(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        inline: bool,
        comment_id: u64,
        body: &str,
    ) -> Result<(), GhError> {
        let path = self.own_comment(auth, number, inline, comment_id).await?;
        self.rest::<Value>("PATCH", &path, Some(json!({"body": body})))
            .await?;
        Ok(())
    }

    /// #172: withdraw a comment the agent posted on `number`.
    pub async fn delete_comment(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        inline: bool,
        comment_id: u64,
    ) -> Result<(), GhError> {
        let path = self.own_comment(auth, number, inline, comment_id).await?;
        self.rest::<Value>("DELETE", &path, None).await?;
        Ok(())
    }

    /// #165: reply to a line comment, in the thread it belongs to. GitHub takes this on the
    /// pulls endpoint with `in_reply_to`; the conversation endpoint cannot address a thread.
    /// #168: start a `workflow_dispatch` run. `workflow_id` takes the file name, which is what a
    /// person writes. The response is 204 with no body, so the run is found afterwards with
    /// `ci runs --ref`.
    pub async fn dispatch_workflow(
        &self,
        auth: &Authorized<'_>,
        workflow: &str,
        git_ref: &str,
        inputs: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Ci, Action::Dispatch)?;
        let mut payload = json!({"ref": git_ref});
        if !inputs.is_empty() {
            payload["inputs"] = json!(inputs);
        }
        self.rest::<Value>(
            "POST",
            &format!(
                "/repos/{}/actions/workflows/{}/dispatches",
                auth.repo(),
                path_segment(workflow)
            ),
            Some(payload),
        )
        .await?;
        Ok(())
    }

    /// #169: offer a draft for review, or put one back. REST does not serve either; GraphQL is
    /// the only way, and it wants the pull request's node id rather than its number.
    pub async fn set_pull_request_draft(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        draft: bool,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Pr, Action::Create)?;
        let pr: Value = self
            .rest(
                "GET",
                &format!("/repos/{}/pulls/{number}", auth.repo()),
                None,
            )
            .await?;
        let node_id = pr
            .get("node_id")
            .and_then(Value::as_str)
            .ok_or_else(|| GhError::Parse(format!("no node_id for pull request {number}")))?;
        let (mutation, field) = if draft {
            ("convertPullRequestToDraft", "convertPullRequestToDraft")
        } else {
            (
                "markPullRequestReadyForReview",
                "markPullRequestReadyForReview",
            )
        };
        let query = format!(
            "mutation($id: ID!) {{ {mutation}(input: {{pullRequestId: $id}})              {{ pullRequest {{ isDraft }} }} }}"
        );
        let out = self.graphql(&query, json!({"id": node_id})).await?;
        out.pointer(&format!("/data/{field}/pullRequest/isDraft"))
            .and_then(Value::as_bool)
            .map(|_| ())
            .ok_or_else(|| GhError::Parse(format!("pull request {number} was not changed")))
    }

    pub async fn reply_to_review_comment(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        comment_id: u64,
        body: &str,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Pr, Action::Comment)?;
        self.rest::<Value>(
            "POST",
            &format!("/repos/{}/pulls/{number}/comments", auth.repo()),
            Some(json!({"body": body, "in_reply_to": comment_id})),
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
        comments: &[crate::api::types::ReviewComment],
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Pr, Action::Review)?;
        let mut payload = json!({"event": event, "body": body});
        // #167: the same endpoint takes the notes that hang on lines of the diff. Sent only when
        // there are some: an empty array is not the same as the key being absent to GitHub.
        if !comments.is_empty() {
            payload["comments"] = json!(comments
                .iter()
                .map(|c| json!({"path": c.path, "line": c.line, "body": c.body}))
                .collect::<Vec<_>>());
        }
        self.rest::<Value>(
            "POST",
            &format!("/repos/{}/pulls/{number}/reviews", auth.repo()),
            Some(payload),
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
        // false when the field is missing or not a bool: it gates the branch deletion below,
        // and a branch left standing after a merge is recoverable where a branch deleted
        // without one is not.
        let merged = out.get("merged").and_then(Value::as_bool).unwrap_or(false);
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
        // A number reaches either kind (see numbered_write_scope); the proof already
        // matches whichever it turned out to be
        auth.ensure_any(&[
            (Resource::Issue, Action::Comment),
            (Resource::Pr, Action::Comment),
        ])?;
        self.rest::<Value>(
            "POST",
            &format!("/repos/{}/issues/{number}/comments", auth.repo()),
            Some(json!({"body": body})),
        )
        .await?;
        Ok(())
    }

    pub async fn close_issue(&self, auth: &Authorized<'_>, number: u64) -> Result<(), GhError> {
        // A number reaches either kind (see numbered_write_scope); the proof already
        // matches whichever it turned out to be
        auth.ensure_any(&[
            (Resource::Issue, Action::Close),
            (Resource::Pr, Action::Close),
        ])?;
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
        // A number reaches either kind (see numbered_write_scope); the proof already
        // matches whichever it turned out to be
        auth.ensure_any(&[
            (Resource::Issue, Action::Close),
            (Resource::Pr, Action::Close),
        ])?;
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
        // A number reaches either kind (see numbered_write_scope); the proof already
        // matches whichever it turned out to be
        auth.ensure_any(&[
            (Resource::Issue, Action::Label),
            (Resource::Pr, Action::Label),
        ])?;
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
        // A number reaches either kind (see numbered_write_scope); the proof already
        // matches whichever it turned out to be
        auth.ensure_any(&[
            (Resource::Issue, Action::Assign),
            (Resource::Pr, Action::Assign),
        ])?;
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
        // A number reaches either kind (see numbered_write_scope); the proof already
        // matches whichever it turned out to be
        auth.ensure_any(&[
            (Resource::Issue, Action::Label),
            (Resource::Pr, Action::Label),
        ])?;
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
        // A number reaches either kind (see numbered_write_scope); the proof already
        // matches whichever it turned out to be
        auth.ensure_any(&[
            (Resource::Issue, Action::Assign),
            (Resource::Pr, Action::Assign),
        ])?;
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

    /// 0.2.15: every item's field values come with it.
    ///
    /// Without them a write could not be read back: `update-item` answered `ok` and nothing said
    /// what the field now held, or whether it still held it. An agent asked to put a board in
    /// order could not see the board.
    pub async fn list_project_items(
        &self,
        auth: &Authorized<'_>,
        project_id: &str,
        first: u32,
    ) -> Result<Value, GhError> {
        auth.ensure(Resource::Project, Action::Read)?;
        /// Field values fetched per item. A board with more than this many fields has the rest
        /// left out of the listing; `project fields` still shows them all.
        const FIELDS_PER_ITEM: u32 = 20;
        const Q: &str = r#"
query($project:ID!,$first:Int!,$fields:Int!){
  node(id:$project){ ... on ProjectV2 { title
    items(first:$first){ nodes{
      id type
      content{ ... on Issue { number title } ... on PullRequest { number title } }
      fieldValues(first:$fields){ nodes{
        __typename
        ... on ProjectV2ItemFieldSingleSelectValue { name   field{ ... on ProjectV2FieldCommon { name } } }
        ... on ProjectV2ItemFieldTextValue         { text   field{ ... on ProjectV2FieldCommon { name } } }
        ... on ProjectV2ItemFieldNumberValue       { number field{ ... on ProjectV2FieldCommon { name } } }
        ... on ProjectV2ItemFieldDateValue         { date   field{ ... on ProjectV2FieldCommon { name } } }
      } }
    } }
  } }
}"#;
        self.graphql(
            Q,
            json!({"project": project_id, "first": first, "fields": FIELDS_PER_ITEM}),
        )
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
        let labels = self
            .rest::<Value>("GET", &format!("/repos/{repo}/labels?per_page={n}"), None)
            .await;
        let assignees = self
            .rest::<Value>(
                "GET",
                &format!("/repos/{repo}/assignees?per_page={n}"),
                None,
            )
            .await;
        let milestones = self
            .rest::<Value>(
                "GET",
                &format!("/repos/{repo}/milestones?state=open&per_page={n}"),
                None,
            )
            .await;
        // A failed read reports the failure rather than an empty list. This command exists so
        // an agent can reuse the labels a repository already has; told there are none, it
        // creates new ones, and GitHub accepts an unknown label name silently — the very
        // mistake the command is here to prevent.
        let field = |r: Result<Value, GhError>, key: &str| -> Value {
            match r {
                Ok(v) => json!(v
                    .as_array()
                    .map(|a| a
                        .iter()
                        .filter_map(|x| x.get(key).and_then(Value::as_str))
                        .map(str::to_string)
                        .collect::<Vec<_>>())
                    .unwrap_or_default()),
                Err(e) => json!({ "error": e.to_string() }),
            }
        };
        Ok(json!({
            "labels": field(labels, "name"),
            "assignees": field(assignees, "login"),
            "milestones": field(milestones, "title"),
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
        let token = self.tokens.token().await?;
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
        let token = self.tokens.token().await?;
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
        self.audit.log_edge(
            self.route,
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
        let token = self.tokens.token().await?;
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
        self.audit.log_edge(
            self.route,
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
            node_id: str_at(&pr, "node_id"),
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
                id: None,
                review_id: None,
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
            // below. It carries nothing to read on its own, but it is what they hang from, so it
            // is kept and the renderer drops it when it turns out to have none (#165).
            let empty_envelope = body.is_empty() && state == "COMMENTED";
            out.push(CommentItem {
                kind: if empty_envelope {
                    "review_envelope".into()
                } else {
                    "review".into()
                },
                author: pointer_str(r, "/user/login"),
                // A review is stamped when it is submitted; a pending one has no timestamp.
                created_at: str_at(r, "submitted_at"),
                body,
                state: Some(state),
                path: None,
                line: None,
                in_reply_to_id: None,
                id: None,
                review_id: r.get("id").and_then(Value::as_u64),
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
                id: c.get("id").and_then(Value::as_u64),
                review_id: c.get("pull_request_review_id").and_then(Value::as_u64),
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
            node_id: str_at(&iss, "node_id"),
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

    /// Correct an issue's title or body.
    ///
    /// 0.2.15: an issue body is the change instruction the agent works from, so rewriting one is
    /// changing what it was asked to do. `issue:update` is separate from `issue:create` for that
    /// reason — a project can want issues opened without wanting what a person wrote rewritable.
    pub async fn update_issue(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        title: Option<&str>,
        body: Option<&str>,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Issue, Action::Update)?;
        let mut payload = serde_json::Map::new();
        if let Some(t) = title {
            payload.insert("title".into(), json!(t));
        }
        if let Some(b) = body {
            payload.insert("body".into(), json!(b));
        }
        self.rest::<Value>(
            "PATCH",
            &format!("/repos/{}/issues/{number}", auth.repo()),
            Some(Value::Object(payload)),
        )
        .await?;
        Ok(())
    }

    /// Whether `number` names a pull request rather than an issue.
    ///
    /// GitHub serves pull requests from the issues endpoints, so the number alone does not say
    /// which it is, and the permission that should apply depends on the answer.
    ///
    /// Deliberately not `ensure(Issue, Read)`. This is not a read of the issue's content — only of
    /// which of the two kinds the number is — and requiring the read permission would mean a
    /// project granting a write and not the read could not be told apart correctly. That is where
    /// the 0.2.13 attempt stalled. A proof is still required, so nothing reaches upstream without
    /// passing the policy; what it does not require is a *particular* proof, because deciding which
    /// one applies is the question being asked.
    pub async fn names_a_pull_request(
        &self,
        auth: &Authorized<'_>,
        number: u64,
    ) -> Result<bool, GhError> {
        let iss: Value = self
            .rest(
                "GET",
                &format!("/repos/{}/issues/{number}", auth.repo()),
                None,
            )
            .await?;
        Ok(iss.get("pull_request").is_some())
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
                id: None,
                review_id: None,
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
/// #173: one file of `/pulls/{n}/files`. GitHub omits `patch` for a binary file and for one whose
/// diff it considers too large; either way there is nothing to render, and saying which is the
/// only useful answer.
fn pr_file(v: &Value) -> PrFile {
    let patch = v.get("patch").and_then(Value::as_str).map(str::to_string);
    let status = pointer_str(v, "/status");
    let no_patch = if patch.is_some() {
        None
    } else if status == "renamed" {
        Some("renamed with no change to its contents".to_string())
    } else {
        Some("no patch: binary, or too large for GitHub to diff".to_string())
    };
    PrFile {
        path: pointer_str(v, "/filename"),
        status,
        additions: v.get("additions").and_then(Value::as_u64).unwrap_or(0),
        deletions: v.get("deletions").and_then(Value::as_u64).unwrap_or(0),
        no_patch,
        patch,
    }
}

/// #173: a unified diff hunk, numbered as GitHub numbers it.
///
/// `@@ -a,b +c,d @@` says the hunk's first line is line `c` of the new file; every added or
/// context line after it advances that counter, and a deleted line does not — it does not exist in
/// the new file, so it has no number to be commented on. This is exactly the number that
/// `pr review --comment path:line:body` wants, which is the reason for rendering rather than
/// handing over the raw diff.
fn parse_patch(patch: &str) -> Vec<DiffLine> {
    let mut out = Vec::new();
    let mut new_line = 0u64;
    for raw in patch.lines() {
        if let Some(rest) = raw.strip_prefix("@@") {
            // The `+c` of `@@ -a,b +c,d @@`; anything unparseable leaves the counter where it was
            if let Some(plus) = rest.split('+').nth(1) {
                let num: String = plus.chars().take_while(char::is_ascii_digit).collect();
                if let Ok(n) = num.parse::<u64>() {
                    new_line = n;
                }
            }
            out.push(DiffLine {
                line: None,
                kind: "hunk".into(),
                text: raw.to_string(),
            });
            continue;
        }
        // "\ No newline at end of file" is a note about the line above it, not a line of the
        // file, so it takes no number: counting it would shift every number after it by one
        let (kind, text, counts) = match raw.as_bytes().first() {
            Some(b'+') => ("add", &raw[1..], true),
            Some(b'-') => ("del", &raw[1..], false),
            Some(b'\\') => ("ctx", raw, false),
            _ => ("ctx", raw.get(1..).unwrap_or(""), true),
        };
        let line = if !counts {
            None
        } else {
            let n = new_line;
            new_line += 1;
            Some(n)
        };
        out.push(DiffLine {
            line,
            kind: kind.into(),
            text: text.to_string(),
        });
    }
    out
}

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
        let store = Arc::new(UpstreamTokenStore::in_memory(
            "upstream.invalid",
            &dir.path().join("t"),
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

    /// #173: the line numbers are the whole point of rendering a patch rather than passing it
    /// through, so they are pinned here against a hunk that has every kind of line in it.
    #[test]
    fn a_patch_is_numbered_the_way_github_numbers_it() {
        let lines = parse_patch(
            "@@ -38,4 +38,5 @@ fn check()\n ctx one\n-gone\n+added\n ctx two\n\\ No newline at end of file",
        );
        let got: Vec<_> = lines
            .iter()
            .map(|l| (l.line, l.kind.as_str(), l.text.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                (None, "hunk", "@@ -38,4 +38,5 @@ fn check()"),
                (Some(38), "ctx", "ctx one"),
                // A deleted line is not in the new file, so it has no number to be quoted by
                (None, "del", "gone"),
                (Some(39), "add", "added"),
                (Some(40), "ctx", "ctx two"),
                (None, "ctx", "\\ No newline at end of file"),
            ]
        );
    }

    /// A second hunk restarts the counter at its own header rather than carrying on.
    #[test]
    fn each_hunk_restarts_the_count_at_its_header() {
        let lines = parse_patch("@@ -1,1 +1,1 @@\n a\n@@ -80,2 +90,2 @@\n b\n+c");
        let nums: Vec<_> = lines.iter().map(|l| l.line).collect();
        assert_eq!(nums, vec![None, Some(1), None, Some(90), Some(91)]);
    }

    /// A hunk header the parser cannot read must not silently renumber what follows: better to
    /// carry the previous count than to claim a line is line 0.
    #[test]
    fn an_unreadable_hunk_header_does_not_reset_to_zero() {
        let lines = parse_patch("@@ -1,1 +5,1 @@\n a\n@@ garbage @@\n b");
        assert_eq!(lines[1].line, Some(5));
        assert_eq!(lines[3].line, Some(6));
    }

    /// A file GitHub sends no patch for (binary, or too large) says so instead of rendering empty.
    #[test]
    fn a_file_with_no_patch_says_why() {
        let f = pr_file(&json!({
            "filename": "logo.png", "status": "modified", "additions": 0, "deletions": 0
        }));
        assert_eq!(
            f.no_patch.as_deref().unwrap_or(""),
            "no patch: binary, or too large for GitHub to diff"
        );
        assert!(f.patch.is_none());
        // And a file that does have one carries no warning
        let g = pr_file(&json!({
            "filename": "a.rs", "status": "modified", "additions": 1, "deletions": 0,
            "patch": "@@ -1,1 +1,2 @@\n a\n+b"
        }));
        assert!(g.no_patch.is_none());
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
            g.create_pull_request(&auth, "h", "main", "t", "", false)
                .await,
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

    /// #206: "error sending request for url (…)" alone told the reporter nothing. reqwest keeps
    /// the alert in its source chain, so the chain is what decides.
    #[test]
    fn a_handshake_failure_in_the_chain_earns_the_hint() {
        let chain = "error sending request for url (https://api.github.com/user): \
                     client error: received fatal alert: HandshakeFailure";
        assert!(hint_for_chain(chain).contains("cipher suites"));
        assert!(hint_for_chain(chain).contains("tls-dh="));
        assert_eq!(
            hint_for_chain("error sending request for url (…): operation timed out"),
            ""
        );
    }

    #[test]
    fn the_chain_is_flattened_layer_by_layer() {
        #[derive(Debug)]
        struct Inner;
        impl std::fmt::Display for Inner {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("received fatal alert: HandshakeFailure")
            }
        }
        impl std::error::Error for Inner {}
        #[derive(Debug)]
        struct Outer(Inner);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("error sending request")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let chain = error_chain(&Outer(Inner));
        assert_eq!(
            chain,
            "error sending request: received fatal alert: HandshakeFailure"
        );
        assert!(!hint_for_chain(&chain).is_empty());
    }
}
