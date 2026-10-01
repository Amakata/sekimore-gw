//! #329: the github forge relay as a sidecar — what the socket transport adds over the built-in one.
//! The whole API suite also runs over the socket (`SEKIMORE_TEST_FORGE=socket`); these are the
//! cases only a sidecar has.

mod common;

use std::sync::Arc;

use bytes::Bytes;
use common::*;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use sekimore_relay::api::types::ApiRequest;
use sekimore_relay::config::BootstrapMode;
use sekimore_relay::forge::sidecar;

fn status_req() -> ApiRequest {
    ApiRequest {
        repo: "LibOrg/awesome-lib".into(),
        number: 1,
        ..Default::default()
    }
}

async fn start(forge: Forge) -> ApiFixture {
    start_api_on(
        project_case_a(&["pr:read"]),
        BootstrapMode::Auto,
        true,
        vec![board(TEST_BOARD_NUMBER, TEST_BOARD)],
        None,
        forge,
    )
    .await
}

fn audit_events(f: &ApiFixture) -> Vec<serde_json::Value> {
    std::fs::read_to_string(&f.audit_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn has(events: &[serde_json::Value], edge: &str, event: &str) -> bool {
    events.iter().any(|e| {
        e.get("edge").and_then(|v| v.as_str()) == Some(edge)
            && e.get("event").and_then(|v| v.as_str()) == Some(event)
    })
}

/// The sidecar makes the upstream call and the gateway writes it down, on the sidecar's edge —
/// not on the built-in client's, which made no call.
#[tokio::test]
async fn the_gateway_audits_the_calls_the_sidecar_made() {
    let f = start(Forge::Sidecar).await;
    let (code, resp) = post(f.addr, "/pr/status", Some(&f.token), &status_req()).await;
    assert_eq!(code, 200, "{resp:?}");
    assert!(
        !recorded(&f.recorder).is_empty(),
        "the call reached the upstream"
    );
    let events = audit_events(&f);
    assert!(
        has(&events, "sidecar.api", "api_call"),
        "the sidecar's upstream calls are in the gateway's audit: {events:?}"
    );
    assert!(
        !has(&events, "relay.github.api", "api_call"),
        "the built-in client made no call here: {events:?}"
    );
}

/// The permission is still decided by the gateway: a request the policy refuses never reaches the
/// sidecar, let alone the upstream.
#[tokio::test]
async fn a_refused_request_never_reaches_the_sidecar() {
    let f = start(Forge::Sidecar).await;
    let mut r = status_req();
    r.method = String::new();
    let (code, _) = post(f.addr, "/pr/merge", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    assert!(recorded(&f.recorder).is_empty(), "nothing reached upstream");
    assert!(
        !has(&audit_events(&f), "sidecar.api", "api_call"),
        "and nothing went to the sidecar"
    );
}

/// A sidecar that is not up makes the API unavailable — and says where to look — without
/// remembering the failure: once it is up, the next call goes through.
#[tokio::test]
async fn a_sidecar_that_is_not_up_yet_is_retried() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("github.sock");
    let f = start(Forge::SocketAt(sock.clone())).await;

    let (code, resp) = post(f.addr, "/pr/status", Some(&f.token), &status_req()).await;
    assert_eq!(code, 503, "{resp:?}");
    let msg = resp.error.unwrap_or_default();
    assert!(msg.contains("does not answer"), "{msg}");
    assert!(
        msg.contains("sekimore-github"),
        "it names the service: {msg}"
    );
    assert!(has(
        &audit_events(&f),
        "relay.sidecar",
        "sidecar_unavailable"
    ));

    let listener = sidecar::bind(&sock).unwrap();
    tokio::spawn(sidecar::run(
        listener,
        Arc::new(sidecar::Sidecar::new(None)),
    ));
    let (code, resp) = post(f.addr, "/pr/status", Some(&f.token), &status_req()).await;
    assert_eq!(code, 200, "{resp:?}");
}

/// A stand-in sidecar that answers `/describe` with what it is given and nothing else.
async fn fake_sidecar(sock: std::path::PathBuf, describe: serde_json::Value) {
    let listener = sidecar::bind(&sock).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let body = describe.to_string();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |_req| {
                    let body = body.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
}

/// What a sidecar claims is checked against config.yml, not trusted: one that claims a resource
/// the operator did not list is not connected.
#[tokio::test]
async fn a_sidecar_claiming_more_than_configured_is_not_connected() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("github.sock");
    fake_sidecar(
        sock.clone(),
        serde_json::json!({
            "name": "github", "version": "0", "guide": "g",
            "resources": ["pr", "s3"]
        }),
    )
    .await;
    let f = start(Forge::SocketAt(sock)).await;
    let (code, resp) = post(f.addr, "/pr/status", Some(&f.token), &status_req()).await;
    assert_eq!(code, 503, "{resp:?}");
    let msg = resp.error.unwrap_or_default();
    assert!(msg.contains("not connected") && msg.contains("s3"), "{msg}");
    assert!(has(&audit_events(&f), "relay.sidecar", "sidecar_refused"));
}

/// The same for a sidecar that names itself as another relay, or gives no guide.
#[tokio::test]
async fn a_sidecar_that_is_not_what_was_configured_is_not_connected() {
    for (describe, says) in [
        (
            serde_json::json!({"name": "gitlab", "version": "0", "guide": "g", "resources": ["pr"]}),
            "gitlab",
        ),
        (
            serde_json::json!({"name": "github", "version": "0", "guide": " ", "resources": ["pr"]}),
            "guide",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("github.sock");
        fake_sidecar(sock.clone(), describe).await;
        let f = start(Forge::SocketAt(sock)).await;
        let (code, resp) = post(f.addr, "/pr/status", Some(&f.token), &status_req()).await;
        assert_eq!(code, 503, "{resp:?}");
        let msg = resp.error.unwrap_or_default();
        assert!(msg.contains(says), "{msg}");
    }
}

/// A locked store is the gateway's to report, as it is built in: the sidecar is never asked to
/// make a call it has no credential for.
#[tokio::test]
async fn without_an_upstream_token_the_sidecar_is_not_called() {
    let f = start_api_on(
        project_case_a(&["pr:read"]),
        BootstrapMode::Auto,
        false,
        vec![board(TEST_BOARD_NUMBER, TEST_BOARD)],
        None,
        Forge::Sidecar,
    )
    .await;
    let (code, resp) = post(f.addr, "/pr/status", Some(&f.token), &status_req()).await;
    assert_eq!(code, 503, "{resp:?}");
    assert!(recorded(&f.recorder).is_empty());
    assert!(!has(&audit_events(&f), "sidecar.api", "api_call"));
}
