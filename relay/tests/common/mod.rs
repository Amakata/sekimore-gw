//! Shared fixtures for the integration tests: a temp state dir, a mock GitHub, API server startup, and HTTP helpers.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sekimore_relay::api::types::{ApiRequest, ApiResponse, BootstrapRequest, BootstrapResponse};
use sekimore_relay::api::{self, ApiContext};
use sekimore_relay::audit::Audit;
use sekimore_relay::config::BootstrapMode;
use sekimore_relay::github::upstream_token::UpstreamTokenStore;
use sekimore_relay::github::GitHub;
use sekimore_relay::policy::{Mode, Project};
use sekimore_relay::ssh::authorized_keys::AuthorizedKeys;
use sekimore_relay::tokens::TokenStore;
use tokio::net::TcpListener;
use url::Url;

#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: serde_json::Value,
}

pub type Recorder = Arc<Mutex<Vec<Recorded>>>;

/// Mock GitHub API: records requests and returns canned JSON.
pub async fn mock_github() -> (Url, Recorder) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let rec: Recorder = Arc::new(Mutex::new(Vec::new()));
    let rec2 = rec.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let rec = rec2.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let rec = rec.clone();
                    async move {
                        let method = req.method().to_string();
                        let path = req
                            .uri()
                            .path_and_query()
                            .map(|p| p.to_string())
                            .unwrap_or_default();
                        let headers: Vec<(String, String)> = req
                            .headers()
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                            .collect();
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map(|c| c.to_bytes())
                            .unwrap_or_default();
                        let body: serde_json::Value =
                            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                        rec.lock().unwrap().push(Recorded {
                            method: method.clone(),
                            path: path.clone(),
                            headers,
                            body: body.clone(),
                        });
                        let (status, json) = canned(&method, &path, &body);
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(json.to_string())))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (Url::parse(&format!("http://{addr}/api/v3")).unwrap(), rec)
}

fn canned(method: &str, path: &str, body: &serde_json::Value) -> (StatusCode, serde_json::Value) {
    let p = path.split('?').next().unwrap_or(path);
    if method == "POST" && p.ends_with("/pulls") {
        if body.get("head").and_then(|h| h.as_str()) == Some("sekimore/main-dup0000") {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({"message": "Validation Failed", "errors": [{"message": "A pull request already exists"}]}),
            );
        }
        return (
            StatusCode::CREATED,
            serde_json::json!({"number": 42, "html_url": "https://github.example/pr/42", "node_id": "PR_42"}),
        );
    }
    if method == "GET" && p.ends_with("/pulls") {
        return (
            StatusCode::OK,
            serde_json::json!([{"number": 41, "html_url": "https://github.example/pr/41", "node_id": "PR_41"}]),
        );
    }
    // 0.2.6: releases
    if method == "POST" && p.ends_with("/releases") {
        if body.get("tag_name").and_then(|t| t.as_str()) == Some("v9.9.9-missing") {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({"message": "Validation Failed", "errors": [{"code": "invalid", "field": "tag_name"}]}),
            );
        }
        let tag = body
            .get("tag_name")
            .and_then(|t| t.as_str())
            .unwrap_or("v0.0.0");
        return (
            StatusCode::CREATED,
            serde_json::json!({
                "id": 900,
                "tag_name": tag,
                "name": body.get("name").and_then(|n| n.as_str()).unwrap_or(tag),
                "html_url": format!("https://github.example/releases/{tag}"),
                "draft": body.get("draft").and_then(|d| d.as_bool()).unwrap_or(false),
                "prerelease": body.get("prerelease").and_then(|d| d.as_bool()).unwrap_or(false),
            }),
        );
    }
    if method == "GET" && p.contains("/releases/tags/") {
        if p.ends_with("/v0.0.0-none") {
            return (
                StatusCode::NOT_FOUND,
                serde_json::json!({"message": "Not Found"}),
            );
        }
        let tag = p.rsplit('/').next().unwrap_or("v1.0.0");
        return (
            StatusCode::OK,
            serde_json::json!({"id": 901, "tag_name": tag, "name": tag, "html_url": format!("https://github.example/releases/{tag}"), "draft": false, "prerelease": false}),
        );
    }
    if method == "GET" && p.ends_with("/releases") {
        return (
            StatusCode::OK,
            serde_json::json!([
                {"id": 902, "tag_name": "v1.1.0", "name": "v1.1.0", "html_url": "https://github.example/releases/v1.1.0", "draft": false, "prerelease": false},
                {"id": 901, "tag_name": "v1.0.0", "name": "v1.0.0", "html_url": "https://github.example/releases/v1.0.0", "draft": true, "prerelease": false}
            ]),
        );
    }
    if method == "POST" && p.ends_with("/issues") {
        return (
            StatusCode::CREATED,
            serde_json::json!({"number": 7, "html_url": "https://github.example/issues/7", "node_id": "I_7"}),
        );
    }
    if p == "/api/v3/user" {
        return (StatusCode::OK, serde_json::json!({"login": "operator"}));
    }
    if p == "/api/v3/meta" {
        return (
            StatusCode::OK,
            serde_json::json!({"ssh_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"]}),
        );
    }
    if p == "/api/graphql" {
        return (
            StatusCode::OK,
            serde_json::json!({"data": {"addProjectV2ItemById": {"item": {"id": "PVTI_1"}}, "node": {"title": "Board", "items": {"nodes": []}}}}),
        );
    }
    (StatusCode::OK, serde_json::json!({}))
}

pub fn project_case_a(grants: &[&str]) -> Project {
    let mut p = Project::new("case-a")
        .with_repo("LibOrg/awesome-lib", Mode::ReadWrite, &["main"])
        .with_repo("VendorOrg/reference-impl", Mode::ReadOnly, &[]);
    for g in grants {
        p = p.grant(g);
    }
    p
}

pub struct ApiFixture {
    pub dir: tempfile::TempDir,
    pub addr: SocketAddr,
    pub ctx: Arc<ApiContext>,
    pub recorder: Recorder,
    pub token: String,
    pub audit_path: std::path::PathBuf,
}

pub async fn start_api(
    project: Project,
    bootstrap: BootstrapMode,
    upstream_token: bool,
) -> ApiFixture {
    let dir = tempfile::tempdir().unwrap();
    let (api_base, recorder) = mock_github().await;
    let graphql = Url::parse(&format!(
        "{}/graphql",
        api_base.as_str().trim_end_matches("/api/v3").to_string() + "/api"
    ))
    .unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(Audit::new(Some(&audit_path), false).unwrap());
    let store = Arc::new(UpstreamTokenStore::new(
        &dir.path().join("upstream_token"),
        Duration::from_secs(60),
    ));
    if upstream_token {
        store.save("upstream.test", "gho_test", "repo").unwrap();
    }
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let gh = Arc::new(GitHub::new(api_base, graphql, http, store, audit.clone()));
    let tokens = TokenStore::new(&dir.path().join("tokens.json"));
    let (token, _) = tokens
        .issue(&project.name, Duration::from_secs(3600))
        .unwrap();
    let ctx = Arc::new(ApiContext {
        project,
        tokens,
        githubs: HashMap::from([("github.com".to_string(), gh)]),
        audit,
        keys: Arc::new(AuthorizedKeys::new(&dir.path().join("authorized_keys"), 8)),
        bootstrap,
        bootstrap_disabled_path: dir.path().join("bootstrap.disabled"),
        token_ttl: Duration::from_secs(3600),
        body_cap: 64 * 1024,
        rate: Mutex::new(VecDeque::new()),
        git_domain: "github.com".into(),
        upstream: "github.com".into(),
        git_domains: vec![],
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(api::serve(ctx.clone(), listener));
    ApiFixture {
        dir,
        addr,
        ctx,
        recorder,
        token,
        audit_path,
    }
}

pub fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

pub async fn post(
    addr: SocketAddr,
    path: &str,
    token: Option<&str>,
    body: &ApiRequest,
) -> (u16, ApiResponse) {
    let mut req = http().post(format!("http://{addr}{path}")).json(body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let body: ApiResponse = resp.json().await.unwrap();
    (status, body)
}

pub async fn post_bootstrap(addr: SocketAddr, key: &str) -> (u16, BootstrapResponse) {
    let resp = http()
        .post(format!("http://{addr}/bootstrap"))
        .json(&BootstrapRequest {
            public_key: key.to_string(),
            label: Some("test".into()),
        })
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap())
}

pub fn gen_pubkey() -> String {
    use russh::keys::ssh_key::private::Ed25519Keypair;
    use russh::keys::PrivateKey;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    PrivateKey::from(Ed25519Keypair::from_seed(&seed))
        .public_key()
        .to_openssh()
        .unwrap()
}

pub fn recorded(rec: &Recorder) -> Vec<Recorded> {
    rec.lock().unwrap().clone()
}
