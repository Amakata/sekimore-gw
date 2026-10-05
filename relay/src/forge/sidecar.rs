//! #329: the socket transport. A forge relay that runs as a sidecar is reached over a Unix socket
//! with HTTP/1.1 and JSON; the gateway's side is [`SocketRelay`], a [`ForgeRelay`] like the built-in
//! one, and the sidecar's side is [`serve`].
//!
//! What crosses the socket is what the built-in call takes, plus the two things the gateway keeps:
//!
//! - **the credential.** Each request carries the token for its upstream and nothing else. The
//!   sidecar stores nothing, so there is nothing to hoard and nothing to revoke there.
//! - **the record.** The sidecar hands back every upstream call it made, and the gateway writes
//!   them to the audit. A sidecar that left a call out would only hide it from its own reply; the
//!   connection still crossed the gateway's 443 passthrough, which logs it.
//!
//! Before the first call the gateway reads `GET /describe` and connects only if the sidecar names
//! itself as configured and claims no resource `relay.sidecars.<name>.resources` does not list.
//!
//! The sidecar reaches the upstream API through the gateway's 443 passthrough: it dials the
//! gateway (`--via`) for the API's host name and keeps that name for SNI and the certificate, so its
//! egress passes the same SNI check, upload cap and audit as dev's.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use url::Url;

use super::github::GitHubRelay;
use super::{Answer, ForgeRelay, Grant, GrantKind, OpenPrError, OpenedPr, Query, Resolved};
use crate::api::types::{ApiRequest, ApiResponse};
use crate::api::ApiError;
use crate::audit::{Actor, Audit};
use crate::github::upstream_token::TokenError;
use crate::github::{CallLog, GhError, GitHub, TokenSource};
use crate::paths;

/// The largest reply the gateway reads from a sidecar. A CI log page or a diff is the biggest
/// thing a call returns; this is well above those and still bounds what a sidecar can push back.
pub const REPLY_CAP: usize = 32 * 1024 * 1024;
/// The largest request a sidecar reads. The gateway's own API body cap is far below this.
pub const REQUEST_CAP: usize = 8 * 1024 * 1024;
/// How long the gateway waits for a sidecar. The upstream calls inside have their own timeout
/// (30 s each); a call can make several, so this is a ceiling, not a per-hop budget.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(120);

/// The upstream a call is about.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpstreamApi {
    pub api_base: Url,
    pub graphql_base: Url,
}

/// A grant on the wire: the repository and either the permission (`pr:create`) or `git`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireGrant {
    pub repo: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub git: bool,
}

impl WireGrant {
    fn of(g: &Grant) -> Self {
        match g.kind {
            GrantKind::Api(r, a) => WireGrant {
                repo: g.repo.clone(),
                permission: Some(format!("{}:{}", r.as_str(), a.as_str())),
                git: false,
            },
            GrantKind::Git => WireGrant {
                repo: g.repo.clone(),
                permission: None,
                git: true,
            },
        }
    }

    /// The sidecar's side: the gateway made this grant, and the sidecar takes it as given.
    fn into_grant(self) -> Result<Grant, String> {
        let kind = match (self.permission, self.git) {
            (Some(p), false) => {
                let (r, a) = crate::policy::parse_permission(&p)?;
                GrantKind::Api(r, a)
            }
            (None, true) => GrantKind::Git,
            _ => return Err("a grant is a permission or git, exactly one".into()),
        };
        Ok(Grant {
            repo: self.repo,
            kind,
        })
    }
}

/// An upstream call the sidecar made, for the gateway's audit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallRecord {
    pub method: String,
    pub path: String,
    pub status: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireError {
    pub status: u16,
    pub message: String,
}

impl WireError {
    fn of(e: &ApiError) -> Self {
        WireError {
            status: e.status.as_u16(),
            message: e.message.clone(),
        }
    }

    fn into_api(self) -> ApiError {
        ApiError {
            status: StatusCode::from_u16(self.status).unwrap_or(StatusCode::BAD_GATEWAY),
            message: self.message,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireOpenPrError {
    NotOpened { reason: String },
    CreateFailed { error: WireError },
    LookupFailed { error: WireError },
}

/// `POST /call`
#[derive(Debug, Serialize, Deserialize)]
pub struct CallRequest {
    pub op: String,
    pub upstream: UpstreamApi,
    pub token: String,
    pub grants: Vec<WireGrant>,
    pub req: ApiRequest,
    #[serde(default)]
    pub resolved: Resolved,
}

/// `POST /query`
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryRequest {
    pub query: Query,
    pub upstream: UpstreamApi,
    pub token: String,
    #[serde(default)]
    pub grant: Option<WireGrant>,
}

/// `POST /open-pr`
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenPrRequest {
    pub upstream: UpstreamApi,
    pub token: String,
    pub grant: WireGrant,
    pub head: String,
    pub base: String,
    pub title: String,
    pub body: String,
}

/// What every `POST` answers: one of the results or an error, and the upstream calls made.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Reply {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<ApiResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<Answer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened: Option<OpenedPr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<WireError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_pr_error: Option<WireOpenPrError>,
    #[serde(default)]
    pub calls: Vec<CallRecord>,
}

/// `GET /describe`: who the sidecar says it is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Describe {
    pub name: String,
    pub version: String,
    pub resources: Vec<String>,
    /// How to use it, for the agent's guide (#330). Required: a relay that cannot say how it is
    /// used is not connected
    pub guide: String,
    /// #366: a command sidecar's commands. A forge relay has none: its operations are the gateway's
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<super::command::CommandSpec>,
}

/// One request to a sidecar over its socket: HTTP/1.1, JSON, the reply capped at [`REPLY_CAP`] and
/// the whole exchange at [`CALL_TIMEOUT`]. A non-2xx answer is an error, with the start of its body.
pub(crate) async fn exchange(
    socket: &Path,
    method: Method,
    path: &str,
    body: Bytes,
) -> Result<Bytes, String> {
    let fut = async {
        let stream = tokio::net::UnixStream::connect(socket)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| format!("handshake: {e}"))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header(hyper::header::HOST, "sidecar")
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(body))
            .map_err(|e| format!("request: {e}"))?;
        let resp = send
            .send_request(req)
            .await
            .map_err(|e| format!("send: {e}"))?;
        let status = resp.status();
        let bytes = Limited::new(resp.into_body(), REPLY_CAP)
            .collect()
            .await
            .map_err(|e| format!("reply: {e}"))?
            .to_bytes();
        if !status.is_success() {
            return Err(format!(
                "HTTP {status}: {}",
                String::from_utf8_lossy(&bytes[..bytes.len().min(200)])
            ));
        }
        Ok(bytes)
    };
    tokio::time::timeout(CALL_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| Err(format!("no reply in {}s", CALL_TIMEOUT.as_secs())))
}

// ---- the gateway's side --------------------------------------------------------------------

/// A forge relay reached over its socket.
pub struct SocketRelay {
    name: String,
    socket: PathBuf,
    upstream: UpstreamApi,
    tokens: Arc<dyn TokenSource>,
    audit: Arc<Audit>,
    /// `relay.sidecars.<name>.resources`: what the sidecar may claim
    declared: Vec<String>,
    /// Whether `/describe` has been read and matched. Not cached when it fails: the sidecar may
    /// simply not be up yet, and the next call should look again
    checked: tokio::sync::Mutex<bool>,
}

impl SocketRelay {
    pub fn new(
        name: &str,
        socket: &Path,
        upstream: UpstreamApi,
        tokens: Arc<dyn TokenSource>,
        audit: Arc<Audit>,
        declared: Vec<String>,
    ) -> Self {
        SocketRelay {
            name: name.to_string(),
            socket: socket.to_path_buf(),
            upstream,
            tokens,
            audit,
            declared,
            checked: tokio::sync::Mutex::new(false),
        }
    }

    fn unavailable(&self, why: &str) -> ApiError {
        self.audit.deny_edge(
            paths::RELAY_SIDECAR,
            "sidecar_unavailable",
            Actor::System,
            why,
            &[
                ("sidecar", &self.name),
                ("socket", &self.socket.display().to_string()),
            ],
        );
        ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: format!(
                "the {} relay sidecar does not answer at {} ({why}); ask a human to check the sekimore-{} service on the host running docker",
                self.name,
                self.socket.display(),
                self.name
            ),
        }
    }

    fn refused(&self, why: String) -> ApiError {
        self.audit.deny_edge(
            paths::RELAY_SIDECAR,
            "sidecar_refused",
            Actor::System,
            &why,
            &[("sidecar", &self.name)],
        );
        ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: format!("the {} relay sidecar is not connected: {why}", self.name),
        }
    }

    async fn token(&self) -> Result<String, ApiError> {
        self.tokens
            .token()
            .await
            .map_err(|e| ApiError::from(GhError::Token(e)))
    }

    async fn exchange(&self, method: Method, path: &str, body: Bytes) -> Result<Bytes, String> {
        exchange(&self.socket, method, path, body).await
    }

    /// Read `/describe` once and hold the sidecar to the configuration.
    async fn check(&self) -> Result<(), ApiError> {
        let mut ok = self.checked.lock().await;
        if *ok {
            return Ok(());
        }
        let raw = self
            .exchange(Method::GET, "/describe", Bytes::new())
            .await
            .map_err(|e| self.unavailable(&e))?;
        let d: Describe = serde_json::from_slice(&raw)
            .map_err(|e| self.refused(format!("its /describe is not readable: {e}")))?;
        if d.name != self.name {
            return Err(self.refused(format!(
                "it names itself {:?}, and relay.sidecars names it {:?}",
                d.name, self.name
            )));
        }
        let extra: Vec<&String> = d
            .resources
            .iter()
            .filter(|r| !self.declared.iter().any(|x| x == *r))
            .collect();
        if !extra.is_empty() {
            return Err(self.refused(format!(
                "it claims {extra:?}, which relay.sidecars.{}.resources does not list",
                self.name
            )));
        }
        if d.guide.trim().is_empty() {
            return Err(self.refused(
                "it gives no guide, and a relay that cannot say how it is used is not connected"
                    .to_string(),
            ));
        }
        log::info!(
            "{} relay sidecar {} at {} serves {}",
            self.name,
            d.version,
            self.socket.display(),
            d.resources.join(" ")
        );
        *ok = true;
        Ok(())
    }

    async fn post<T: Serialize>(&self, path: &str, body: &T) -> Result<Reply, ApiError> {
        self.check().await?;
        let bytes = serde_json::to_vec(body).map_err(|e| ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("encode a request for the {} sidecar: {e}", self.name),
        })?;
        let raw = self
            .exchange(Method::POST, path, Bytes::from(bytes))
            .await
            .map_err(|e| self.unavailable(&e))?;
        let reply: Reply = serde_json::from_slice(&raw).map_err(|e| ApiError {
            status: StatusCode::BAD_GATEWAY,
            message: format!("the {} sidecar's reply is not readable: {e}", self.name),
        })?;
        for c in &reply.calls {
            self.audit.log_edge(
                paths::SIDECAR_API,
                "api_call",
                Actor::System,
                &[
                    ("sidecar", &self.name),
                    ("method", &c.method),
                    ("path", &c.path),
                    ("status", &c.status.to_string()),
                ],
            );
        }
        Ok(reply)
    }

    fn missing(&self, what: &str) -> ApiError {
        ApiError {
            status: StatusCode::BAD_GATEWAY,
            message: format!("the {} sidecar's reply has no {what}", self.name),
        }
    }
}

#[async_trait::async_trait]
impl ForgeRelay for SocketRelay {
    async fn call(
        &self,
        op: &str,
        grants: &[Grant],
        req: &ApiRequest,
        resolved: &Resolved,
    ) -> Result<ApiResponse, ApiError> {
        let body = CallRequest {
            op: op.to_string(),
            upstream: self.upstream.clone(),
            token: self.token().await?,
            grants: grants.iter().map(WireGrant::of).collect(),
            req: req.clone(),
            resolved: resolved.clone(),
        };
        let reply = self.post("/call", &body).await?;
        if let Some(e) = reply.error {
            return Err(e.into_api());
        }
        reply.response.ok_or_else(|| self.missing("response"))
    }

    async fn query(&self, query: &Query, grant: Option<&Grant>) -> Result<Answer, ApiError> {
        let body = QueryRequest {
            query: query.clone(),
            upstream: self.upstream.clone(),
            token: self.token().await?,
            grant: grant.map(WireGrant::of),
        };
        let reply = self.post("/query", &body).await?;
        if let Some(e) = reply.error {
            return Err(e.into_api());
        }
        reply.answer.ok_or_else(|| self.missing("answer"))
    }

    async fn open_pr(
        &self,
        grant: &Grant,
        head: &str,
        base: &str,
        title: &str,
        body: &str,
    ) -> Result<OpenedPr, OpenPrError> {
        let token = self.token().await.map_err(OpenPrError::CreateFailed)?;
        let req = OpenPrRequest {
            upstream: self.upstream.clone(),
            token,
            grant: WireGrant::of(grant),
            head: head.to_string(),
            base: base.to_string(),
            title: title.to_string(),
            body: body.to_string(),
        };
        let reply = self
            .post("/open-pr", &req)
            .await
            .map_err(OpenPrError::CreateFailed)?;
        if let Some(e) = reply.open_pr_error {
            return Err(match e {
                WireOpenPrError::NotOpened { reason } => OpenPrError::NotOpened(reason),
                WireOpenPrError::CreateFailed { error } => {
                    OpenPrError::CreateFailed(error.into_api())
                }
                WireOpenPrError::LookupFailed { error } => {
                    OpenPrError::LookupFailed(error.into_api())
                }
            });
        }
        if let Some(e) = reply.error {
            return Err(OpenPrError::CreateFailed(e.into_api()));
        }
        reply
            .opened
            .ok_or_else(|| OpenPrError::CreateFailed(self.missing("pull request")))
    }
}

// ---- the sidecar's side --------------------------------------------------------------------

/// The token of one call. The sidecar keeps it for that call and no longer.
struct CallToken(String);

#[async_trait::async_trait]
impl TokenSource for CallToken {
    async fn token(&self) -> Result<String, TokenError> {
        Ok(self.0.clone())
    }
}

/// The upstream calls of one request, for the reply.
#[derive(Default)]
struct Collected(Mutex<Vec<CallRecord>>);

impl CallLog for Collected {
    fn api_call(&self, _route: &'static str, method: &str, path: &str, status: u16) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(CallRecord {
                method: method.to_string(),
                path: path.to_string(),
                status,
            });
    }
}

/// The github sidecar.
pub struct Sidecar {
    /// Where the upstream API is dialed: the gateway's 443 passthrough (`host[:port]`). `None` dials
    /// the API's own address — for tests against a local mock, never for a deployment
    via: Option<String>,
    /// Who each token belongs to, by the token's digest, once a call has asked — so a sidecar that
    /// builds a client per call asks GitHub once per token, as the built-in client does
    viewers: Mutex<HashMap<String, String>>,
}

impl Sidecar {
    pub fn new(via: Option<String>) -> Self {
        Sidecar {
            via,
            viewers: Mutex::new(HashMap::new()),
        }
    }

    fn describe() -> Describe {
        Describe {
            name: "github".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            resources: [
                "pr", "issue", "project", "repo", "ci", "release", "search", "security",
            ]
            .map(String::from)
            .to_vec(),
            guide: "GitHub: pull requests, issues, CI, releases, Projects v2, search and Dependabot alerts; see `sgw-agent guide`.".into(),
            commands: Vec::new(),
        }
    }

    async fn client(
        &self,
        up: &UpstreamApi,
        token: String,
    ) -> anyhow::Result<(GitHub, Arc<Collected>, String)> {
        let mut connect_to: Vec<(String, SocketAddr)> = Vec::new();
        if let Some(via) = &self.via {
            let target = if via.contains(':') {
                via.clone()
            } else {
                format!("{via}:443")
            };
            let addr = tokio::net::lookup_host(&target)
                .await
                .with_context(|| format!("resolve the gateway {target}"))?
                .next()
                .with_context(|| format!("the gateway {target} has no address"))?;
            for u in [&up.api_base, &up.graphql_base] {
                if let Some(h) = u.host_str() {
                    connect_to.push((h.to_string(), addr));
                }
            }
        }
        let http = crate::github::http::build_client(&crate::github::http::HttpOptions {
            connect_to: &connect_to,
            no_env_proxy: true,
            ..Default::default()
        })?;
        let calls = Arc::new(Collected::default());
        let key = token_key(&token);
        let gh = GitHub::with_sources(
            up.api_base.clone(),
            up.graphql_base.clone(),
            http,
            Arc::new(CallToken(token)),
            calls.clone(),
        );
        if let Some(v) = self
            .viewers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            gh.seed_viewer(v.clone());
        }
        Ok((gh, calls, key))
    }

    fn remember_viewer(&self, key: String, gh: &GitHub) {
        if let Some(v) = gh.viewer() {
            self.viewers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key, v);
        }
    }

    fn calls_of(calls: &Collected) -> Vec<CallRecord> {
        calls.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    async fn handle_call(&self, r: CallRequest) -> Reply {
        let grants: Result<Vec<Grant>, String> =
            r.grants.into_iter().map(WireGrant::into_grant).collect();
        let grants = match grants {
            Ok(g) => g,
            Err(e) => return error_reply(StatusCode::BAD_REQUEST, &e),
        };
        let (gh, calls, key) = match self.client(&r.upstream, r.token).await {
            Ok(x) => x,
            Err(e) => return error_reply(StatusCode::BAD_GATEWAY, &format!("{e:#}")),
        };
        let gh = Arc::new(gh);
        let relay = GitHubRelay::new(gh.clone());
        let out = relay.call(&r.op, &grants, &r.req, &r.resolved).await;
        self.remember_viewer(key, &gh);
        let mut reply = match out {
            Ok(resp) => Reply {
                response: Some(resp),
                ..Reply::default()
            },
            Err(e) => Reply {
                error: Some(WireError::of(&e)),
                ..Reply::default()
            },
        };
        reply.calls = Self::calls_of(&calls);
        reply
    }

    async fn handle_query(&self, r: QueryRequest) -> Reply {
        let grant = match r.grant.map(WireGrant::into_grant).transpose() {
            Ok(g) => g,
            Err(e) => return error_reply(StatusCode::BAD_REQUEST, &e),
        };
        let (gh, calls, key) = match self.client(&r.upstream, r.token).await {
            Ok(x) => x,
            Err(e) => return error_reply(StatusCode::BAD_GATEWAY, &format!("{e:#}")),
        };
        let gh = Arc::new(gh);
        let out = GitHubRelay::new(gh.clone())
            .query(&r.query, grant.as_ref())
            .await;
        self.remember_viewer(key, &gh);
        let mut reply = match out {
            Ok(a) => Reply {
                answer: Some(a),
                ..Reply::default()
            },
            Err(e) => Reply {
                error: Some(WireError::of(&e)),
                ..Reply::default()
            },
        };
        reply.calls = Self::calls_of(&calls);
        reply
    }

    async fn handle_open_pr(&self, r: OpenPrRequest) -> Reply {
        let grant = match r.grant.into_grant() {
            Ok(g) => g,
            Err(e) => return error_reply(StatusCode::BAD_REQUEST, &e),
        };
        let (gh, calls, _) = match self.client(&r.upstream, r.token).await {
            Ok(x) => x,
            Err(e) => return error_reply(StatusCode::BAD_GATEWAY, &format!("{e:#}")),
        };
        let out = GitHubRelay::new(Arc::new(gh))
            .open_pr(&grant, &r.head, &r.base, &r.title, &r.body)
            .await;
        let mut reply = match out {
            Ok(p) => Reply {
                opened: Some(p),
                ..Reply::default()
            },
            Err(OpenPrError::NotOpened(reason)) => Reply {
                open_pr_error: Some(WireOpenPrError::NotOpened { reason }),
                ..Reply::default()
            },
            Err(OpenPrError::CreateFailed(e)) => Reply {
                open_pr_error: Some(WireOpenPrError::CreateFailed {
                    error: WireError::of(&e),
                }),
                ..Reply::default()
            },
            Err(OpenPrError::LookupFailed(e)) => Reply {
                open_pr_error: Some(WireOpenPrError::LookupFailed {
                    error: WireError::of(&e),
                }),
                ..Reply::default()
            },
        };
        reply.calls = Self::calls_of(&calls);
        reply
    }

    async fn handle(&self, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
        let path = req.uri().path().to_string();
        let method = req.method().clone();
        match (method, path.as_str()) {
            (Method::GET, "/healthz") => plain(StatusCode::OK, "ok\n"),
            (Method::GET, "/describe") => json(StatusCode::OK, &Self::describe()),
            (Method::POST, "/call" | "/query" | "/open-pr") => {
                let body = match Limited::new(req.into_body(), REQUEST_CAP).collect().await {
                    Ok(b) => b.to_bytes(),
                    Err(e) => {
                        return json(
                            StatusCode::OK,
                            &error_reply(StatusCode::PAYLOAD_TOO_LARGE, &e.to_string()),
                        )
                    }
                };
                let reply = match path.as_str() {
                    "/call" => match serde_json::from_slice(&body) {
                        Ok(r) => self.handle_call(r).await,
                        Err(e) => error_reply(StatusCode::BAD_REQUEST, &e.to_string()),
                    },
                    "/query" => match serde_json::from_slice(&body) {
                        Ok(r) => self.handle_query(r).await,
                        Err(e) => error_reply(StatusCode::BAD_REQUEST, &e.to_string()),
                    },
                    _ => match serde_json::from_slice(&body) {
                        Ok(r) => self.handle_open_pr(r).await,
                        Err(e) => error_reply(StatusCode::BAD_REQUEST, &e.to_string()),
                    },
                };
                json(StatusCode::OK, &reply)
            }
            _ => plain(StatusCode::NOT_FOUND, "not found\n"),
        }
    }
}

/// The digest a token is remembered by. The token itself is not kept as a key.
fn token_key(token: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(token.as_bytes()))
}

fn error_reply(status: StatusCode, message: &str) -> Reply {
    Reply {
        error: Some(WireError {
            status: status.as_u16(),
            message: message.to_string(),
        }),
        ..Reply::default()
    }
}

fn json<T: Serialize>(status: StatusCode, body: &T) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .expect("static response")
}

fn plain(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("static response")
}

/// Run the sidecar on `socket` until the process is stopped.
pub async fn serve(socket: &Path, sidecar: Arc<Sidecar>) -> anyhow::Result<()> {
    let listener = bind(socket)?;
    run(listener, sidecar).await
}

/// Bind the socket, replacing one a previous run left behind.
pub fn bind(socket: &Path) -> anyhow::Result<tokio::net::UnixListener> {
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    match std::fs::remove_file(socket) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("remove stale {}", socket.display())),
    }
    let listener = tokio::net::UnixListener::bind(socket)
        .with_context(|| format!("bind {}", socket.display()))?;
    // Only the gateway connects. The volume is shared with nothing else, and the mode says so too
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660))
            .with_context(|| format!("chmod {}", socket.display()))?;
    }
    Ok(listener)
}

pub async fn run(listener: tokio::net::UnixListener, sidecar: Arc<Sidecar>) -> anyhow::Result<()> {
    loop {
        let (stream, _) = listener.accept().await.context("sidecar accept")?;
        let sidecar = sidecar.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                let sidecar = sidecar.clone();
                async move { Ok::<_, std::convert::Infallible>(sidecar.handle(req).await) }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await
            {
                log::debug!("sidecar connection: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Action, Resource};

    #[test]
    fn a_grant_survives_the_wire_and_nothing_else_does() {
        let g = Grant {
            repo: "Org/Repo".into(),
            kind: GrantKind::Api(Resource::Pr, Action::Merge),
        };
        assert_eq!(WireGrant::of(&g).into_grant().unwrap(), g);
        let git = Grant {
            repo: "Org/Repo".into(),
            kind: GrantKind::Git,
        };
        assert_eq!(WireGrant::of(&git).into_grant().unwrap(), git);
        // Both, neither, or a permission that does not exist: not a grant
        for bad in [
            WireGrant {
                repo: "Org/Repo".into(),
                permission: Some("pr:merge".into()),
                git: true,
            },
            WireGrant {
                repo: "Org/Repo".into(),
                permission: None,
                git: false,
            },
            WireGrant {
                repo: "Org/Repo".into(),
                permission: Some("pr:delete".into()),
                git: false,
            },
        ] {
            assert!(bad.clone().into_grant().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_token_is_remembered_by_its_digest_only() {
        let k = token_key("gho_secret");
        assert_eq!(k.len(), 64);
        assert!(!k.contains("gho_secret"));
    }
}
