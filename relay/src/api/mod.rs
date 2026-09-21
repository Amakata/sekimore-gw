//! The relay's HTTP surface, which the agent-side CLI talks to (plaintext, reachable only from internal-net).
//!
//! Shared pipeline: verify the token → match the project → parse JSON → dispatch to a handler (which gets an `Authorized` to pass to `GitHub`).
//! `/bootstrap` is the only unauthenticated endpoint (it registers a disposable key and issues a project token).

pub mod handlers;
pub mod types;

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;

use crate::audit::{Actor, Audit};
use crate::config::BootstrapMode;
use crate::github::{GhError, GitHub};
use crate::policy::Project;
use crate::ssh::authorized_keys::AuthorizedKeys;
use crate::tokens::{TokenRecord, TokenStore, VerifyError};
use types::{ApiRequest, ApiResponse};

pub struct ApiContext {
    pub project: Project,
    pub tokens: TokenStore,
    /// GitHub client per upstream (keyed by git-relay domain). Became a map in 0.2.0
    pub githubs: HashMap<String, Arc<GitHub>>,
    pub audit: Arc<Audit>,
    pub keys: Arc<AuthorizedKeys>,
    pub bootstrap: BootstrapMode,
    pub bootstrap_disabled_path: PathBuf,
    pub token_ttl: Duration,
    pub body_cap: usize,
    pub rate: Mutex<VecDeque<Instant>>,
    /// The git-relay domain and its upstream (reported to the agent in the `/bootstrap` response). The default upstream
    pub git_domain: String,
    pub upstream: String,
    /// 0.2.0: every git domain (the first is the default)
    pub git_domains: Vec<types::GitDomain>,
    /// 0.2.7: the Projects v2 boards this project may touch, from `relay.project.boards`. A
    /// board the agent names has to be one of these. Declaring none refuses every board: a node
    /// id is opaque and unbounded, so without a list any board the upstream token can see would
    /// be reachable.
    pub project_boards: ProjectBoards,
}

/// The declared boards, and their node ids once something has needed them.
///
/// **Resolved on first use, not at start-up.** Turning `{ user: …, number: 2 }` into a node id is
/// a GraphQL call, so it needs the upstream API token — and since 0.2.19 that token lives in the
/// secret store, which starts locked. Resolving at start-up meant the call failed, the board was
/// dropped, and unlocking afterwards never revisited it: every Projects operation stayed refused
/// for the life of the process, reported as though no board had been configured (#99).
///
/// Doing it on demand also covers the case the old code accepted and shrugged at — the upstream
/// being unreachable at start-up permanently refusing a board that is perfectly valid.
pub struct ProjectBoards {
    declared: Vec<crate::config::BoardRef>,
    /// `None` until the first attempt. A failed attempt is not cached: the reason is usually
    /// temporary (locked store, upstream down) and the next request should try again.
    resolved: tokio::sync::Mutex<Option<Vec<ResolvedBoard>>>,
}

impl ProjectBoards {
    pub fn new(declared: Vec<crate::config::BoardRef>) -> Self {
        ProjectBoards {
            declared,
            resolved: tokio::sync::Mutex::new(None),
        }
    }

    /// Boards that are already resolved. For the tests that inject a mapping rather than have
    /// one looked up, and for nothing else — a deployment always starts from the declaration.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn already_resolved(boards: Vec<ResolvedBoard>) -> Self {
        ProjectBoards {
            declared: boards
                .iter()
                .map(|b| crate::config::BoardRef {
                    org: None,
                    user: Some("test".into()),
                    number: b.number,
                })
                .collect(),
            resolved: tokio::sync::Mutex::new(Some(boards)),
        }
    }

    /// Whether the operator declared any at all. Readable without the upstream, so a message can
    /// tell "none configured" apart from "configured but not resolvable yet".
    pub fn is_declared_empty(&self) -> bool {
        self.declared.is_empty()
    }

    /// The resolved boards, resolving them if this is the first call that needed them.
    ///
    /// Every board resolving is the success case. A partial result is returned rather than an
    /// error so that one bad entry does not take the others down, but it is not cached — see
    /// `resolved`.
    pub async fn get(&self, gh: &crate::github::GitHub) -> Vec<ResolvedBoard> {
        let mut slot = self.resolved.lock().await;
        if let Some(found) = slot.as_ref() {
            return found.clone();
        }
        let mut out = Vec::new();
        for b in &self.declared {
            match gh
                .resolve_project_board(b.org.as_deref(), b.user.as_deref(), b.number)
                .await
            {
                Ok(id) => {
                    log::info!("project board {} → {id}", b.label());
                    out.push(ResolvedBoard {
                        id,
                        number: b.number,
                        label: b.label(),
                    });
                }
                Err(e) => log::warn!(
                    "project board {} could not be resolved ({e}); it stays refused until the \
                     next attempt",
                    b.label()
                ),
            }
        }
        if out.len() == self.declared.len() {
            *slot = Some(out.clone());
        }
        out
    }
}

/// A configured board and the node id it resolved to.
///
/// 0.2.15: the number is kept alongside the id. It was discarded before, which left `--project-id
/// PVT_…` as the only way to name a board — an id the agent cannot look up, since the command that
/// would print it is the operator's. The relay held the mapping the whole time.
#[derive(Clone, Debug)]
pub struct ResolvedBoard {
    pub id: String,
    /// The number in the board's URL, as `relay.project.boards` writes it
    pub number: u32,
    /// `orgs/<org>/projects/<n>` or `users/<user>/projects/<n>`, for messages
    pub label: String,
}

pub const BOOTSTRAP_RATE_PER_MINUTE: usize = 10;

impl ApiContext {
    /// Simple rate limit for `/bootstrap` (N requests per minute, across all callers).
    pub fn bootstrap_rate_ok(&self) -> bool {
        let mut q = self.rate.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
        {
            q.pop_front();
        }
        if q.len() >= BOOTSTRAP_RATE_PER_MINUTE {
            return false;
        }
        q.push_back(now);
        true
    }
}

/// A handler error, carrying an HTTP status and the JSON error message.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn bad_request(m: impl Into<String>) -> Self {
        ApiError {
            status: StatusCode::BAD_REQUEST,
            message: m.into(),
        }
    }
    pub fn forbidden(m: impl Into<String>) -> Self {
        ApiError {
            status: StatusCode::FORBIDDEN,
            message: m.into(),
        }
    }
}

impl From<GhError> for ApiError {
    fn from(e: GhError) -> Self {
        let status = match &e {
            GhError::Denied(_) => StatusCode::FORBIDDEN,
            GhError::Token(_) => StatusCode::SERVICE_UNAVAILABLE,
            GhError::Status { .. } | GhError::Http(_) | GhError::Parse(_) | GhError::Graphql(_) => {
                StatusCode::BAD_GATEWAY
            }
        };
        ApiError {
            status,
            message: e.to_string(),
        }
    }
}

impl From<crate::policy::Denied> for ApiError {
    fn from(d: crate::policy::Denied) -> Self {
        ApiError::forbidden(d.to_string())
    }
}

pub async fn serve(ctx: Arc<ApiContext>, listener: TcpListener) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await.context("api accept")?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let ctx = ctx.clone();
                async move { Ok::<_, Infallible>(handle(ctx, req, peer).await) }
            });
            let conn = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .keep_alive(true)
                .serve_connection(io, svc);
            if let Err(e) = conn.await {
                log::debug!("api connection {peer}: {e}");
            }
        });
    }
}

fn json_response<T: serde::Serialize>(status: StatusCode, body: &T) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(body)
        .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"encode\"}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .expect("static response")
}

fn error_response(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    json_response(status, &ApiResponse::error(msg))
}

fn bearer_token(req: &Request<Incoming>) -> Option<String> {
    let h = req
        .headers()
        .get(hyper::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let t = h.strip_prefix("Bearer ")?.trim();
    (!t.is_empty()).then(|| t.to_string())
}

async fn read_body(req: Request<Incoming>, cap: usize) -> Result<Bytes, ApiError> {
    let limited = Limited::new(req.into_body(), cap);
    match limited.collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(e) => {
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                Err(ApiError {
                    status: StatusCode::PAYLOAD_TOO_LARGE,
                    message: format!("body exceeds {cap} bytes"),
                })
            } else {
                Err(ApiError::bad_request(format!("cannot read body: {e}")))
            }
        }
    }
}

/// Handles one request.
pub async fn handle(
    ctx: Arc<ApiContext>,
    req: Request<Incoming>,
    peer: SocketAddr,
) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let peer_ip = peer.ip().to_string();

    if method == Method::GET && path == "/healthz" {
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from_static(b"ok\n")))
            .expect("static response");
    }
    if method != Method::POST {
        return error_response(StatusCode::METHOD_NOT_ALLOWED, "POST only");
    }
    if path == "/bootstrap" {
        return match handlers::bootstrap(&ctx, req, &peer_ip).await {
            Ok(resp) => json_response(StatusCode::OK, &resp),
            Err(e) => json_response(
                e.status,
                &types::BootstrapResponse {
                    ok: false,
                    error: Some(e.message),
                    ..Default::default()
                },
            ),
        };
    }

    // ---- Authentication ----
    let Some(token) = bearer_token(&req) else {
        ctx.audit.deny(
            "token_denied",
            Actor::Agent,
            "missing token",
            &[("path", &path), ("peer", &peer_ip)],
        );
        return error_response(
            StatusCode::UNAUTHORIZED,
            "missing token (Authorization: Bearer skm_...)",
        );
    };
    let rec: TokenRecord = match ctx.tokens.verify(&token) {
        Ok(r) => r,
        Err(e) => {
            let reason = e.to_string();
            ctx.audit.deny(
                "token_denied",
                Actor::Agent,
                &reason,
                &[("path", &path), ("peer", &peer_ip)],
            );
            let status = match e {
                VerifyError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::UNAUTHORIZED,
            };
            return error_response(status, &reason);
        }
    };
    // A project token can only touch its own project
    if rec.project != ctx.project.name {
        ctx.audit.deny(
            "token_wrong_project",
            Actor::Agent,
            "token belongs to another project",
            &[
                ("token_project", &rec.project),
                ("server_project", &ctx.project.name),
                ("label", &rec.label),
                ("peer", &peer_ip),
            ],
        );
        return error_response(StatusCode::FORBIDDEN, "token belongs to another project");
    }

    let body = match read_body(req, ctx.body_cap).await {
        Ok(b) => b,
        Err(e) => return error_response(e.status, &e.message),
    };
    let apireq: ApiRequest = if body.is_empty() {
        ApiRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                return error_response(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}"))
            }
        }
    };

    // Check the repository belongs to the project (Projects may omit the repo)
    if !apireq.repo.is_empty() {
        if let Err(d) = ctx.project.find_repo(&apireq.repo) {
            ctx.audit.deny(
                "repo_denied",
                Actor::Agent,
                &d.to_string(),
                &[
                    ("repo", &apireq.repo),
                    ("path", &path),
                    ("label", &rec.label),
                ],
            );
            return error_response(StatusCode::FORBIDDEN, &d.to_string());
        }
    }

    match handlers::dispatch(&ctx, &path, &apireq, &rec).await {
        Ok(mut resp) => {
            resp.ok = true;
            ctx.audit.log(
                "api_ok",
                Actor::Agent,
                &[
                    ("path", &path),
                    ("label", &rec.label),
                    ("repo", &apireq.repo),
                    ("peer", &peer_ip),
                ],
            );
            json_response(StatusCode::OK, &resp)
        }
        Err(e) => {
            ctx.audit.deny(
                "api_error",
                Actor::Agent,
                &e.message,
                &[
                    ("path", &path),
                    ("label", &rec.label),
                    ("repo", &apireq.repo),
                    ("status", &e.status.as_u16().to_string()),
                ],
            );
            error_response(e.status, &e.message)
        }
    }
}
