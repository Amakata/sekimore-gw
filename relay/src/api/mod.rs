//! エージェント側 CLI が話しかける関所の HTTP 面（平文、internal-net 内のみ）。
//!
//! 共通処理: トークン検証 → 案件一致 → JSON → ハンドラ（`Authorized` を得て `GitHub` に渡す）。
//! `/bootstrap` だけは認証なし（使い捨て鍵の登録 + 案件トークンの発行）。

pub mod handlers;
pub mod types;

use std::collections::VecDeque;
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
    pub github: Option<Arc<GitHub>>,
    pub audit: Arc<Audit>,
    pub keys: Arc<AuthorizedKeys>,
    pub bootstrap: BootstrapMode,
    pub bootstrap_disabled_path: PathBuf,
    pub token_ttl: Duration,
    pub body_cap: usize,
    pub rate: Mutex<VecDeque<Instant>>,
    /// git-relay のドメインと上流（/bootstrap の応答でエージェントに伝える）
    pub git_domain: String,
    pub upstream: String,
}

pub const BOOTSTRAP_RATE_PER_MINUTE: usize = 10;

impl ApiContext {
    /// `/bootstrap` の簡易レート制限（1 分あたり N 回、全体）。
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

/// ハンドラのエラー。HTTP ステータスと JSON の error を持つ。
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

/// 1 リクエストの処理。
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

    // ---- 認証 ----
    let Some(token) = bearer_token(&req) else {
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
    // 案件トークンは自分の案件しか触れない
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

    // リポジトリが案件に含まれるか（Projects は repo 省略可）
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
