//! 上流（github.com / GHES）API クライアント。
//!
//! **全メソッドが `&Authorized<'_>` を要求する**のが要点。ポリシー検査を通さずに上流を叩くコードは
//! コンパイルできない。GraphQL（Projects v2）は関所がクエリを組み立てるので、エージェントは GraphQL を書かない。
//!
//! ```compile_fail
//! # use sekimore_relay::github::GitHub;
//! # async fn f(gh: &GitHub) {
//! // 検査を通さずリポジトリ名だけで呼ぶことはできない
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
    /// 上流に到達する前の拒否か（監査・HTTP ステータスの判定に使う）。
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

/// PR の CI チェック 1 件（check-run または commit status を正規化した形）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CheckItem {
    pub name: String,
    /// success / failure / pending / neutral / skipped / … （GitHub の conclusion / state をそのまま）
    pub state: String,
    pub source: String, // "check-run" | "status"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// PR とそのチェックの集計。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PrStatus {
    pub number: u64,
    pub head_sha: String,
    pub state: String, // open / closed
    pub merged: bool,
    pub mergeable: Option<bool>,
    pub checks: Vec<CheckItem>,
    /// 全チェックの総合。success / failure / pending / none
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

    /// 同じ head/base の open PR を探す（`refs/for` の再 push で既存 PR を報告するため）。
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

    /// PR の状態と CI チェックを集計する。check-runs（GitHub Actions 等）と commit statuses（外部 CI）の両方を見る。
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
                    // 完了していれば conclusion、実行中なら status（queued / in_progress）を pending 扱いに
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
            // commit statuses（Travis 等の古い Status API。context 単位で最新だけ）
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

    pub async fn comment_pull_request(
        &self,
        auth: &Authorized<'_>,
        number: u64,
        body: &str,
    ) -> Result<(), GhError> {
        auth.ensure(Resource::Pr, Action::Comment)?;
        // PR も Issue も同じエンドポイント。だからパスでは制御できず、呼び出し側の意図（リソース種別）で判定する
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

    /// ラベル付与は別権限。付けるなら `label_auth`（`issue:label` の証明）も要る。
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

    // ---- Projects v2 (GraphQL のみ) ----

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

    // ---- 操作者向け（証明不要。エージェント経路からは呼ばない） ----

    /// 関所がどの上流 identity として動くか。
    pub async fn whoami(&self) -> Result<String, GhError> {
        let out: Value = self.rest("GET", "/user", None).await?;
        out.get("login")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| GhError::Parse("no login in /user".into()))
    }

    /// 上流 SSH ホスト鍵（`GET /meta` の `ssh_keys`）。known_hosts の生成に使う。
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

    // ---- 下位層 ----

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
        // クエリ文字列は監査に不要（値が長い）
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
            // 204 等。呼び出し側が Value を期待していれば null
            return serde_json::from_value(Value::Null).map_err(|e| GhError::Parse(e.to_string()));
        }
        serde_json::from_slice(&body)
            .map_err(|e| GhError::Parse(format!("{e}: {}", truncate(&body))))
    }
}

/// チェック集合の総合判定。1 つでも失敗系なら failure、pending があれば pending、
/// 全部 success/neutral/skipped なら success、チェックが無ければ none。
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
        // pr:create の証明で merge は叩けない（上流にも、トークンストアにも到達しない）
        assert!(matches!(
            g.merge_pull_request(&auth, 1).await,
            Err(GhError::Denied(_))
        ));
        assert!(matches!(
            g.comment_issue(&auth, 1, "x").await,
            Err(GhError::Denied(_))
        ));
        // 正しい証明でも上流トークンが無ければ Token エラー（ネットワークには出ない）
        assert!(matches!(
            g.create_pull_request(&auth, "h", "main", "t", "").await,
            Err(GhError::Token(_))
        ));
    }

    #[tokio::test]
    async fn pr_status_requires_pr_read() {
        // pr:create だけでは pr status は叩けない（Read の証明が要る）。上流にも出ない
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
        // pr:read を付ければ証明は通り、上流トークンが無い段階まで進む
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
        // failure は pending より優先（1 つでも壊れていれば failure）
        assert_eq!(rollup_state(&[mk("in_progress"), mk("failure")]), "failure");
        assert_eq!(rollup_state(&[mk("success"), mk("timed_out")]), "failure");
        assert_eq!(rollup_state(&[mk("neutral"), mk("cancelled")]), "failure");
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
