//! The gateway's Web UI (the dashboard on :8080), inside `sekimore-relay serve` (0.3.0-alpha.4,
//! Issue #493). Ported from the Python gateway's `src/web_ui/` with nothing added: the same URLs,
//! the same JSON, the same `dashboard.html`, `/ws` and `/api/i18n`.
//!
//! # The boundary (0.3.0 plan, "`serve` の中での分離")
//!
//! dev reaches this listener without authentication, and the process it runs in holds the secret
//! store's key, the upstream tokens and the project tokens. Five things keep the two apart:
//!
//! 1. **Its own listener and router.** Nothing is shared with the API on :8420
//!    (`tests::every_api_path_is_a_404_here` and its mirror in `api::tests`)
//! 2. **One narrow, read-only input**, [`UiView`]: paths, a boolean and a receiver of a value with
//!    nothing secret in it. No `Resolved`, `RelayConfig`, `ProxySpec`, store, token source,
//!    control socket or closure. `tests::ui_view_is_exactly_these_fields` names every field
//! 3. **Imports held to a list** (`tests::webui_imports_only_what_it_may`), and the relay's
//!    configuration types not serializable (`tests::the_config_types_are_not_serializable`)
//! 4. **Every answer built field by field** in this module's own [`json::Json`]; nothing here
//!    derives `Serialize`, and `config.yml` is projected to the keys the endpoints read the moment
//!    it is parsed ([`cfg`])
//! 5. **A sentinel secret** put everywhere a secret can be, with every route and `/ws` searched
//!    for it (`relay/tests/webui.rs`)
//!
//! # Panics
//!
//! The release build aborts on a panic (`panic = "abort"`), so a panic here would take the relay
//! down with the UI and leave the store locked until someone runs `sgw unlock`. The lints below
//! keep `unwrap`, `expect`, indexing and `panic!` out of this module; a handler that fails answers
//! 500, as FastAPI did.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented
)]

pub mod cfg;
pub mod config_api;
pub mod db;
pub mod http;
pub mod i18n;
pub mod json;
pub mod logs;
pub mod relay_view;
pub mod stream;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use sha1::{Digest, Sha1};
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};

use http::{Req, Resp};

/// The dashboard page, moved here unchanged from `src/web_ui/templates/dashboard.html`.
const DASHBOARD: &str = include_str!("dashboard.html");

/// The upstream proxy credential as the store holds it now, with nothing of the credential in it.
/// The `serve` side writes it (`cli::serve`); the UI turns it into `/api/config`'s
/// `upstream_auth` the way the Python UI turned the control socket's answer into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialState {
    /// No store to ask: no relay configured, the relay not up (yet), or the store unopenable
    Unreachable,
    Locked,
    /// The store is open and holds none
    NotSet,
    /// The store holds one Squid cannot use (a username with a space in it)
    Unusable,
    Set,
}

/// Everything the Web UI is given. Read only, owned, and nothing in it can reach a secret.
///
/// Adding a field breaks `tests::ui_view_is_exactly_these_fields` on purpose: whoever adds one
/// writes down there why it cannot reach the store, a token or a credential.
pub struct UiView {
    /// `config.yml`, read on every request as the Python UI read it
    pub config_path: PathBuf,
    /// The log database (`SEKIMORE_DB_PATH`), opened read only
    pub db_path: PathBuf,
    /// The generated `squid.conf` (`SEKIMORE_SQUID_CONFIG`), returned with its password blanked
    pub squid_config_path: PathBuf,
    /// The command that lists the firewall rules (`iptables-legacy`)
    pub iptables: PathBuf,
    /// Whether `SEKIMORE_UPSTREAM_PROXY_USERNAME` is set and not empty — only that
    pub env_proxy_username_set: bool,
    /// The credential's state, kept current by `serve`
    pub credential: watch::Receiver<CredentialState>,
}

impl UiView {
    /// The gateway's paths, from the same environment variables the Python UI read.
    pub fn from_env(config_path: PathBuf, credential: watch::Receiver<CredentialState>) -> UiView {
        let env = |k: &str, d: &str| PathBuf::from(std::env::var(k).unwrap_or_else(|_| d.into()));
        UiView {
            config_path,
            db_path: env("SEKIMORE_DB_PATH", "/data/security_gateway.db"),
            squid_config_path: env("SEKIMORE_SQUID_CONFIG", "/etc/squid/squid.conf"),
            iptables: PathBuf::from("iptables-legacy"),
            env_proxy_username_set: std::env::var("SEKIMORE_UPSTREAM_PROXY_USERNAME")
                .is_ok_and(|v| !v.is_empty()),
            credential,
        }
    }

    pub fn credential_state(&self) -> CredentialState {
        *self.credential.borrow()
    }
}

/// Where the UI listens: `SEKIMORE_WEB_HOST` (0.0.0.0) and `SEKIMORE_WEB_PORT` (8080).
pub fn listen_addr() -> Result<(String, u16), String> {
    let host = std::env::var("SEKIMORE_WEB_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port = match std::env::var("SEKIMORE_WEB_PORT") {
        Err(_) => 8080,
        Ok(p) => crate::settings::py::int(&p)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| format!("SEKIMORE_WEB_PORT={p} is not a port"))?,
    };
    Ok((host, port))
}

/// Open the listener. Done first in `serve`, before anything of the relay.
pub async fn bind() -> anyhow::Result<TcpListener> {
    let (host, port) = listen_addr().map_err(anyhow::Error::msg)?;
    let l = TcpListener::bind((host.as_str(), port)).await?;
    Ok(l)
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// The routes, all `GET`. Their own table: none is the API's.
pub const ROUTES: [&str; 22] = [
    "/",
    "/api/gateway-info",
    "/api/proxy-env",
    "/api/config",
    "/api/i18n",
    "/api/stats",
    "/api/cache-stats",
    "/api/logs",
    "/api/firewall-blocks",
    "/api/proxy-logs",
    "/api/proxy-blocks",
    "/api/blocked-ips",
    "/api/domains/allowed",
    "/api/domains/blocked",
    "/api/domains/blocked-actual",
    "/api/domains/unique",
    "/api/domains/ignored-config",
    "/api/domains/ignored",
    "/api/relay/config",
    "/api/relay/stats",
    "/api/relay/tokens",
    "/api/relay/audit",
];

/// The WebSocket route.
pub const WS_ROUTE: &str = "/ws";

/// One `GET` request to a known route.
pub fn route(view: &UiView, req: &Req, now: f64) -> Resp {
    let answer = |r: cfg::Py<json::Json>| match r {
        Ok(j) => Resp::json(&j),
        Err(e) => {
            log::debug!("webui: {} answered 500 ({})", req.path, e.0);
            Resp::internal_error()
        }
    };
    let limit = || http::int_param(req, "limit", 100);
    match req.path.as_str() {
        "/" => Resp::html(DASHBOARD),
        "/api/gateway-info" => answer(config_api::gateway_info(view)),
        "/api/proxy-env" => answer(config_api::proxy_env(view)),
        "/api/config" => answer(config_api::config(view)),
        "/api/i18n" => answer(config_api::i18n(view, req)),
        "/api/stats" => answer(logs::stats(view, now)),
        "/api/cache-stats" => answer(logs::cache_stats(view)),
        "/api/logs" => match limit() {
            Ok(l) => answer(logs::logs(view, l)),
            Err(r) => r,
        },
        "/api/firewall-blocks" => match limit() {
            Ok(l) => answer(logs::firewall_blocks(view, l)),
            Err(r) => r,
        },
        "/api/proxy-logs" => match limit() {
            Ok(l) => answer(logs::proxy_logs(view, l, false)),
            Err(r) => r,
        },
        "/api/proxy-blocks" => match limit() {
            Ok(l) => answer(logs::proxy_logs(view, l, true)),
            Err(r) => r,
        },
        "/api/blocked-ips" => match limit() {
            Ok(l) => answer(logs::blocked_ips(view, l)),
            Err(r) => r,
        },
        "/api/domains/allowed" => answer(logs::config_list(view, "allow_domains")),
        "/api/domains/blocked" => answer(logs::config_list(view, "block_domains")),
        "/api/domains/ignored-config" => answer(logs::config_list(view, "ignore_domains")),
        "/api/domains/blocked-actual" => answer(logs::blocked_actual(view)),
        "/api/domains/unique" => answer(logs::unique_domains(view)),
        "/api/domains/ignored" => answer(logs::ignored_domains(view)),
        "/api/relay/config" => answer(relay_view::config(view)),
        "/api/relay/stats" => answer(relay_view::stats(view, now)),
        "/api/relay/tokens" => answer(relay_view::tokens(view, now)),
        "/api/relay/audit" => match limit() {
            Ok(l) => answer(relay_view::audit(view, l, req.param("kind"))),
            Err(r) => r,
        },
        _ => Resp::not_found(),
    }
}

/// What Starlette's router answered for a plain HTTP request: the route, 405 for another method
/// on a known route, a 307 to the path with its trailing slash toggled when that one is known,
/// else 404.
pub fn dispatch(view: &UiView, method: &str, req: &Req, now: f64, local: &str) -> Resp {
    if ROUTES.contains(&req.path.as_str()) {
        return if method == "GET" {
            route(view, req, now)
        } else {
            Resp::method_not_allowed()
        };
    }
    if req.path != "/" {
        let toggled = match req.path.strip_suffix('/') {
            Some(p) => p.to_string(),
            None => format!("{}/", req.path),
        };
        if ROUTES.contains(&toggled.as_str()) {
            return Resp::redirect(req, &toggled, local);
        }
    }
    Resp::not_found()
}

fn header<'a>(req: &'a Request<Incoming>, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

fn is_upgrade(req: &Request<Incoming>) -> bool {
    let has = |name: &str, token: &str| {
        header(req, name)
            .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    };
    has("connection", "upgrade") && has("upgrade", "websocket")
}

fn to_hyper(r: Resp) -> Response<Full<Bytes>> {
    let mut b = Response::builder().status(r.status);
    if let Some(ct) = r.content_type {
        b = b.header("content-type", ct);
    }
    for (k, v) in &r.headers {
        b = b.header(*k, v.as_str());
    }
    b.body(Full::new(Bytes::from(r.body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"Internal Server Error"))))
}

/// `Sec-WebSocket-Accept` for a key (RFC 6455 §4.2.2).
fn accept_key(key: &str) -> String {
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

/// The handshake for `/ws`, and the connection handed to [`stream::serve_ws`] once it upgrades.
fn websocket(
    mut req: Request<Incoming>,
    streamer: Arc<stream::Streamer>,
    sockets: Arc<Semaphore>,
) -> Response<Full<Bytes>> {
    let bad = |msg: &str| {
        to_hyper(Resp {
            status: 400,
            content_type: Some("text/plain"),
            headers: vec![],
            body: format!("Failed to open a WebSocket connection: {msg}.\n").into_bytes(),
        })
    };
    if req.method() != hyper::Method::GET {
        return bad("invalid method");
    }
    if header(&req, "sec-websocket-version") != Some("13") {
        return bad("unsupported Sec-WebSocket-Version");
    }
    let Some(key) = header(&req, "sec-websocket-key")
        .map(str::trim)
        .map(String::from)
    else {
        return bad("missing Sec-WebSocket-Key");
    };
    let decoded = base64::engine::general_purpose::STANDARD.decode(&key);
    if !decoded.is_ok_and(|k| k.len() == 16) {
        return bad("invalid Sec-WebSocket-Key");
    }
    let Ok(permit) = sockets.try_acquire_owned() else {
        return to_hyper(Resp {
            status: 503,
            content_type: Some("text/plain"),
            headers: vec![],
            body: b"too many WebSocket connections\n".to_vec(),
        });
    };
    let on_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        let _permit = permit;
        match on_upgrade.await {
            Ok(upgraded) => stream::serve_ws(upgraded, streamer).await,
            Err(e) => log::debug!("webui: websocket upgrade failed: {e}"),
        }
    });
    let mut r = Response::new(Full::new(Bytes::new()));
    *r.status_mut() = hyper::StatusCode::SWITCHING_PROTOCOLS;
    let h = r.headers_mut();
    h.insert(
        hyper::header::UPGRADE,
        hyper::header::HeaderValue::from_static("websocket"),
    );
    h.insert(
        hyper::header::CONNECTION,
        hyper::header::HeaderValue::from_static("Upgrade"),
    );
    if let Ok(v) = hyper::header::HeaderValue::from_str(&accept_key(&key)) {
        h.insert("sec-websocket-accept", v);
    }
    r
}

/// How many HTTP connections the UI serves at once, and how many WebSockets. Its own limits, so a
/// flood of the dashboard does not take the API's or the passthrough's.
pub const MAX_CONNECTIONS: usize = 128;
pub const MAX_WEBSOCKETS: usize = 64;
/// An HTTP connection (not a WebSocket) is closed after this, idle or not.
const CONNECTION_LIFETIME: Duration = Duration::from_secs(300);

async fn handle(
    view: Arc<UiView>,
    streamer: Arc<stream::Streamer>,
    sockets: Arc<Semaphore>,
    req: Request<Incoming>,
    local: SocketAddr,
) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_string();
    if is_upgrade(&req) {
        return if http::percent_decode(&path, false) == WS_ROUTE {
            websocket(req, streamer, sockets)
        } else {
            to_hyper(Resp::forbidden())
        };
    }
    let r = Req::new(
        &path,
        req.uri().query(),
        header(&req, "host"),
        header(&req, "accept-language"),
        header(&req, "cookie"),
    );
    let method = req.method().as_str().to_string();
    let local = local.to_string();
    let resp = tokio::task::spawn_blocking(move || dispatch(&view, &method, &r, now(), &local))
        .await
        .unwrap_or_else(|_| Resp::internal_error());
    to_hyper(resp)
}

/// Serve the UI on `listener` until the process ends.
pub async fn serve(view: UiView, listener: TcpListener) {
    let view = Arc::new(view);
    let streamer = stream::Streamer::new(view.db_path.clone());
    let conns = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let sockets = Arc::new(Semaphore::new(MAX_WEBSOCKETS));
    loop {
        let Ok(permit) = conns.clone().acquire_owned().await else {
            return;
        };
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // EMFILE and the like: wait a little rather than spin
                log::warn!("webui accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let local = stream
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 8080)));
        let (view, streamer, sockets) = (view.clone(), streamer.clone(), sockets.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let svc = service_fn(move |req| {
                let (view, streamer, sockets) = (view.clone(), streamer.clone(), sockets.clone());
                async move { Ok::<_, Infallible>(handle(view, streamer, sockets, req, local).await) }
            });
            let conn = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .serve_connection(TokioIo::new(stream), svc)
                .with_upgrades();
            if let Ok(Err(e)) = tokio::time::timeout(CONNECTION_LIFETIME, conn).await {
                log::debug!("webui connection {peer}: {e}");
            }
        });
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests;
