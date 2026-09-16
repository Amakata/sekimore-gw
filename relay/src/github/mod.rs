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

impl GhError {
    /// Whether this was a denial before reaching upstream (used to decide the audit entry and HTTP status).
    pub fn is_denied(&self) -> bool {
        matches!(self, GhError::Denied(_))
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

    pub fn api_base(&self) -> &Url {
        &self.api_base
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

    /// Find an open PR with the same head/base, so a re-push to `refs/for` can report the existing PR.
    pub async fn find_pull_request(
        &self,
        auth: &Authorized<'_>,
        head: &str,
        base: &str,
    ) -> Result<Option<PrResult>, GhError> {
        auth.ensure(Resource::Pr, Action::Create)?;
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
                &format!("/repos/{repo}/commits/{}", url_escape(git_ref)),
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

    pub async fn merge_pull_request(
        &self,
        auth: &Authorized<'_>,
        number: u64,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Pr, Action::Merge)?;
        self.rest::<Value>(
            "PUT",
            &format!("/repos/{}/pulls/{number}/merge", auth.repo()),
            Some(json!({})),
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
            g.merge_pull_request(&auth, 1).await,
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
