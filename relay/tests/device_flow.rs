//! device flow の自前実装を偽 OAuth サーバで検証する。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use sekimore_relay::github::device_flow::{DeviceFlow, Poll};
use tokio::net::TcpListener;
use url::Url;

/// `/login/oauth/access_token` の応答列を順に返す偽サーバ。
async fn fake_oauth(responses: Vec<serde_json::Value>) -> (Url, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let queue = Arc::new(Mutex::new(responses));
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let queue = queue.clone();
            let seen = seen2.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let queue = queue.clone();
                    let seen = seen.clone();
                    async move {
                        let path = req.uri().path().to_string();
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        seen.lock()
                            .unwrap()
                            .push(format!("{path} {}", String::from_utf8_lossy(&body)));
                        let json = if path == "/login/device/code" {
                            serde_json::json!({"device_code": "dc-1", "user_code": "ABCD-EFGH", "verification_uri": "https://github.example/login/device", "expires_in": 900, "interval": 0})
                        } else {
                            let mut q = queue.lock().unwrap();
                            if q.is_empty() {
                                serde_json::json!({"error": "expired_token"})
                            } else {
                                q.remove(0)
                            }
                        };
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
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
    (Url::parse(&format!("http://{addr}")).unwrap(), seen)
}

fn flow(base: Url) -> DeviceFlow {
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    DeviceFlow::new("github.com", "client-id-x", &["repo", "project"], http)
        .unwrap()
        .with_base(base)
        .with_min_interval(Duration::from_millis(10))
}

#[tokio::test]
async fn pending_then_slow_down_then_token() {
    let (base, seen) = fake_oauth(vec![
        serde_json::json!({"error": "authorization_pending"}),
        serde_json::json!({"error": "slow_down"}),
        serde_json::json!({"access_token": "gho_abc", "token_type": "bearer", "scope": "repo project"}),
    ])
    .await;
    let prompted = Arc::new(Mutex::new(None));
    let p2 = prompted.clone();
    let (token, scope) = flow(base)
        .authenticate(move |code, url| {
            *p2.lock().unwrap() = Some((code.to_string(), url.to_string()));
        })
        .await
        .unwrap();
    assert_eq!(token, "gho_abc");
    assert_eq!(scope, "repo project");
    assert_eq!(prompted.lock().unwrap().clone().unwrap().0, "ABCD-EFGH");
    let seen = seen.lock().unwrap();
    assert!(seen[0].starts_with("/login/device/code "));
    assert!(
        seen[0].contains("client_id=client-id-x") && seen[0].contains("scope=repo+project"),
        "{}",
        seen[0]
    );
    assert!(
        seen[1].contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"),
        "{}",
        seen[1]
    );
    assert_eq!(seen.len(), 4);
}

#[tokio::test]
async fn access_denied_and_expired() {
    let (base, _) = fake_oauth(vec![serde_json::json!({"error": "access_denied"})]).await;
    let err = flow(base).authenticate(|_, _| {}).await.unwrap_err();
    assert!(err.to_string().contains("denied"), "{err}");

    let (base, _) = fake_oauth(vec![]).await; // 空 → expired_token
    let err = flow(base).authenticate(|_, _| {}).await.unwrap_err();
    assert!(err.to_string().contains("expired"), "{err}");
}

#[tokio::test]
async fn poll_once_maps_errors() {
    let (base, _) = fake_oauth(vec![
        serde_json::json!({"error": "authorization_pending"}),
        serde_json::json!({"error": "slow_down"}),
        serde_json::json!({"error": "incorrect_device_code", "error_description": "nope"}),
    ])
    .await;
    let f = flow(base);
    assert_eq!(f.poll_once("dc-1").await.unwrap(), Poll::Pending);
    assert_eq!(f.poll_once("dc-1").await.unwrap(), Poll::SlowDown);
    assert!(f
        .poll_once("dc-1")
        .await
        .unwrap_err()
        .to_string()
        .contains("incorrect_device_code"));
}
