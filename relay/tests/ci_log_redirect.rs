//! #485: `ci log` when the upstream answers the job's log with a redirect to another host, as
//! GitHub does (a storage host). Built in and through a sidecar alike: the gateway fetches it,
//! without the token, and only where it may.
//!
//! The storage host goes by a name only the gateway's fetcher is told about (`STORAGE_HOST`), the
//! way only the gateway can reach a real one: a sidecar that tried to follow the redirect itself
//! fails here as it does in its container with no route out.

mod common;

use std::sync::Arc;

use bytes::Bytes;
use common::*;
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use sekimore_relay::api::types::ApiRequest;
use sekimore_relay::config::BootstrapMode;
use sekimore_relay::forge::sidecar;

async fn start(forge: Forge) -> ApiFixture {
    start_api_on(
        project_case_a(&["ci:read"]),
        BootstrapMode::Auto,
        true,
        vec![],
        None,
        forge,
    )
    .await
}

fn log_req(job_id: u64) -> ApiRequest {
    ApiRequest {
        repo: "LibOrg/awesome-lib".into(),
        job_id,
        window: 2,
        ..Default::default()
    }
}

fn storage_url(f: &ApiFixture, path: &str) -> String {
    format!("http://{STORAGE_HOST}:{}{path}", f.storage.port())
}

fn audit_events(f: &ApiFixture) -> Vec<serde_json::Value> {
    std::fs::read_to_string(&f.audit_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn events_named<'a>(events: &'a [serde_json::Value], event: &str) -> Vec<&'a serde_json::Value> {
    events
        .iter()
        .filter(|e| e.get("event").and_then(|v| v.as_str()) == Some(event))
        .collect()
}

fn header<'a>(r: &'a Recorded, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Each case runs built in and through a sidecar; the job ids keep them apart.
fn both() -> [(Forge, u64); 2] {
    [(Forge::BuiltIn, 0), (Forge::Sidecar, 1)]
}

/// The issue: the log is fetched, its tail comes back, the token stays with the API host, and
/// the fetch is in the gateway's audit — with the host and path, never the signature in the query.
#[tokio::test]
async fn the_log_behind_a_redirect_comes_back_through_either_transport() {
    for (forge, n) in both() {
        let sidecar = matches!(forge, Forge::Sidecar);
        let f = start(forge).await;
        let job = 485_100 + n;
        let path = format!("/logs/{job}.txt");
        storage_holds(&path, Stored::Body(b"one\ntwo\nthree\n".to_vec()));
        upstream_redirects_log(job, &format!("{}?sig=SECRET", storage_url(&f, &path)));

        let (code, resp) = post(f.addr, "/ci/log", Some(&f.token), &log_req(job)).await;
        assert_eq!(code, 200, "sidecar={sidecar}: {resp:?}");
        let raw = resp.raw.unwrap();
        assert_eq!(raw["lines"], serde_json::json!(["two", "three"]), "{raw}");
        assert_eq!(raw["total_lines"], 3);
        assert_eq!(raw["job_id"], job);

        // The API call carried the token; the storage host got the one request, without it
        let api = recorded(&f.recorder);
        let call = api
            .iter()
            .find(|r| r.path.ends_with(&format!("/jobs/{job}/logs")))
            .expect("the API was asked");
        assert_eq!(header(call, "authorization"), Some("Bearer gho_test"));
        let stored = recorded(&f.storage_recorder);
        assert_eq!(stored.len(), 1, "sidecar={sidecar}: {stored:?}");
        assert_eq!(stored[0].path, format!("{path}?sig=SECRET"));
        assert_eq!(
            header(&stored[0], "authorization"),
            None,
            "sidecar={sidecar}: the token went to the storage host"
        );
        assert_eq!(header(&stored[0], "cookie"), None);

        let events = audit_events(&f);
        let fetches = events_named(&events, "redirect_fetch");
        assert_eq!(fetches.len(), 1, "sidecar={sidecar}: {events:?}");
        let e = fetches[0];
        assert_eq!(e["edge"], "relay.github.api", "the gateway's hop: {e}");
        assert_eq!(e["path"], path.as_str());
        assert_eq!(e["status"], "200");
        assert!(e["host"].as_str().unwrap().starts_with(STORAGE_HOST), "{e}");
        if sidecar {
            assert_eq!(e["sidecar"], "github", "{e}");
        }
        let all = std::fs::read_to_string(&f.audit_path).unwrap();
        assert!(!all.contains("SECRET"), "the query is in the audit: {all}");
        assert!(!all.contains("gho_test"), "the token is in the audit");
    }
}

/// Where the gateway must not go, it does not: plain http, an address on the internal net, the
/// metadata service, loopback (the gateway's own API among it). Refused before anything is
/// dialled, and audited.
#[tokio::test]
async fn a_redirect_to_where_the_gateway_must_not_go_is_refused() {
    for (forge, n) in both() {
        let sidecar = matches!(forge, Forge::Sidecar);
        let f = start(forge).await;
        for (i, (location, why)) in [
            ("http://logs.example.com/x", "not https"),
            ("https://10.1.2.3/x", "not a public address"),
            (
                "https://169.254.169.254/latest/meta-data/",
                "not a public address",
            ),
            ("https://127.0.0.1:8420/ci/log", "not a public address"),
            ("https://localhost/x", "this host"),
        ]
        .into_iter()
        .enumerate()
        {
            let job = 485_200 + n * 10 + i as u64;
            upstream_redirects_log(job, location);
            let (code, resp) = post(f.addr, "/ci/log", Some(&f.token), &log_req(job)).await;
            let msg = resp.error.unwrap_or_default();
            assert_ne!(code, 200, "sidecar={sidecar} {location}");
            assert!(msg.contains(why), "sidecar={sidecar} {location}: {msg}");
        }
        let events = audit_events(&f);
        assert_eq!(
            events_named(&events, "redirect_refused").len(),
            5,
            "sidecar={sidecar}: {events:?}"
        );
        assert!(events_named(&events, "redirect_fetch").is_empty());
    }
}

/// Up to three redirects after the upstream's are followed, each checked; a fourth is refused.
#[tokio::test]
async fn at_most_three_more_redirects_are_followed() {
    for (forge, n) in both() {
        let sidecar = matches!(forge, Forge::Sidecar);
        let f = start(forge).await;
        // a chain of `hops` redirects on the storage host, ending at the log
        let chain = |name: &str, hops: usize| {
            let end = format!("/hops/{name}/end");
            storage_holds(&end, Stored::Body(b"done\n".to_vec()));
            let mut next = storage_url(&f, &end);
            for h in (0..hops).rev() {
                let p = format!("/hops/{name}/{h}");
                storage_holds(&p, Stored::Redirect(next));
                next = storage_url(&f, &p);
            }
            next
        };
        let ok = 485_300 + n * 10;
        upstream_redirects_log(ok, &chain(&format!("ok-{n}"), 3));
        let (code, resp) = post(f.addr, "/ci/log", Some(&f.token), &log_req(ok)).await;
        assert_eq!(code, 200, "sidecar={sidecar}: {resp:?}");
        assert_eq!(resp.raw.unwrap()["lines"], serde_json::json!(["done"]));

        let too_many = ok + 1;
        upstream_redirects_log(too_many, &chain(&format!("long-{n}"), 4));
        let (code, resp) = post(f.addr, "/ci/log", Some(&f.token), &log_req(too_many)).await;
        assert_ne!(code, 200);
        let msg = resp.error.unwrap_or_default();
        assert!(
            msg.contains("more than 3 redirects"),
            "sidecar={sidecar}: {msg}"
        );
        // and a hop that goes somewhere refused is refused like the first one
        let bad = ok + 2;
        let p = format!("/hops/bad-{n}/0");
        storage_holds(&p, Stored::Redirect("https://169.254.169.254/".into()));
        upstream_redirects_log(bad, &storage_url(&f, &p));
        let (_, resp) = post(f.addr, "/ci/log", Some(&f.token), &log_req(bad)).await;
        let msg = resp.error.unwrap_or_default();
        assert!(
            msg.contains("not a public address"),
            "sidecar={sidecar}: {msg}"
        );
    }
}

/// The 16 MiB cap holds on the fetched log, whichever transport asked for it.
#[tokio::test]
async fn the_fetched_log_is_capped_at_16_mib() {
    const CAP: usize = 16 << 20;
    // 17 MiB of 16-byte lines
    let line = b"0123456789abcde\n";
    let body: Vec<u8> = line.repeat((17 << 20) / line.len());
    for (forge, n) in both() {
        let sidecar = matches!(forge, Forge::Sidecar);
        let f = start(forge).await;
        let job = 485_400 + n;
        let path = format!("/logs/big-{n}.txt");
        storage_holds(&path, Stored::Body(body.clone()));
        upstream_redirects_log(job, &storage_url(&f, &path));
        let (code, resp) = post(f.addr, "/ci/log", Some(&f.token), &log_req(job)).await;
        assert_eq!(code, 200, "sidecar={sidecar}: {resp:?}");
        let raw = resp.raw.unwrap();
        assert_eq!(
            raw["total_lines"].as_u64().unwrap() as usize,
            CAP / line.len(),
            "sidecar={sidecar}: read past the cap"
        );
    }
}

/// A sidecar's `fetch` is taken only for the operation that was asked for: one that answers
/// `pr status` with a log fetch is refused, and nothing is fetched.
#[tokio::test]
async fn a_fetch_for_another_operation_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("github.sock");
    let f = start_api_on(
        project_case_a(&["pr:read"]),
        BootstrapMode::Auto,
        true,
        vec![],
        None,
        Forge::SocketAt(sock.clone()),
    )
    .await;
    let location = storage_url(&f, "/logs/not-asked-for.txt");
    storage_holds("/logs/not-asked-for.txt", Stored::Body(b"x\n".to_vec()));
    let reply = serde_json::json!({
        "fetch": {
            "url": location,
            "then": {"kind": "ci_log", "job_id": 1, "job_name": "", "conclusion": "",
                     "window": 10, "before": null}
        },
        "calls": []
    });
    lying_sidecar(sock, reply).await;
    let req = ApiRequest {
        repo: "LibOrg/awesome-lib".into(),
        number: 1,
        ..Default::default()
    };
    let (code, resp) = post(f.addr, "/pr/status", Some(&f.token), &req).await;
    assert_eq!(code, 502, "{resp:?}");
    let msg = resp.error.unwrap_or_default();
    assert!(
        msg.contains("answered /pr/status with a fetch for /ci/log"),
        "{msg}"
    );
    assert!(
        recorded(&f.storage_recorder).is_empty(),
        "nothing was fetched"
    );
}

/// A sidecar that describes itself properly and answers every `POST` with `reply`.
async fn lying_sidecar(sock: std::path::PathBuf, reply: serde_json::Value) {
    let listener = sidecar::bind(&sock).unwrap();
    let describe = serde_json::json!({
        "name": "github",
        "version": "0",
        "resources": ["pr", "ci"],
        "guide": "## github\n",
    });
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let describe = describe.to_string();
            let reply = reply.to_string();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: hyper::Request<_>| {
                    let body = if req.method() == hyper::Method::GET {
                        describe.clone()
                    } else {
                        reply.clone()
                    };
                    async move {
                        let _ = BodyExt::collect(req.into_body()).await;
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

/// The sidecar's side on its own: it does not follow the redirect (it has nowhere to go), it
/// says where the log is and what is left to do, and its record of the call is the API's 302.
#[tokio::test]
async fn the_sidecar_hands_the_redirect_back_instead_of_following_it() {
    let (api, rec) = mock_github().await;
    let job = 485_500;
    upstream_redirects_log(job, "https://storage.example.net/logs/1?sig=SECRET");
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("github.sock");
    let listener = sidecar::bind(&sock).unwrap();
    tokio::spawn(sidecar::run(
        listener,
        Arc::new(sidecar::Sidecar::new(None)),
    ));
    let graphql = url::Url::parse(&format!("{}/graphql", api.as_str())).unwrap();
    let body = serde_json::json!({
        "op": "/ci/log",
        "upstream": {"api_base": api, "graphql_base": graphql},
        "token": "gho_test",
        "grants": [{"repo": "LibOrg/awesome-lib", "permission": "ci:read"}],
        "req": {"repo": "LibOrg/awesome-lib", "job_id": job, "window": 5},
    });
    let stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let resp = send
        .send_request(
            hyper::Request::post("/call")
                .header("host", "sidecar")
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let raw = resp.into_body().collect().await.unwrap().to_bytes();
    let reply: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert!(reply.get("response").is_none(), "{reply}");
    assert!(reply.get("error").is_none(), "{reply}");
    assert_eq!(
        reply["fetch"]["url"],
        "https://storage.example.net/logs/1?sig=SECRET"
    );
    assert_eq!(reply["fetch"]["then"]["kind"], "ci_log");
    assert_eq!(reply["fetch"]["then"]["job_id"], job);
    assert_eq!(reply["fetch"]["then"]["window"], 5);
    assert_eq!(reply["calls"][0]["status"], 302);
    assert_eq!(recorded(&rec).len(), 1, "one call, to the API");
}
