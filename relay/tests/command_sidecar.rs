//! #366: a command sidecar end to end — the gateway's API, a fake sidecar on a Unix socket, and
//! what crosses between them.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use common::*;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Response};
use hyper_util::rt::TokioIo;
use sekimore_relay::api::types::ApiRequest;
use sekimore_relay::config::BootstrapMode;
use sekimore_relay::forge::command::CommandSidecar;
use sekimore_relay::vars::{State, Vars};
use serde_json::{json, Value};

const KEY: &str = "notes/api_key";
const SECRET: &str = "k-not-for-the-audit";

/// What the fake sidecar was sent: the path and the JSON body of each request.
type Seen = Arc<Mutex<Vec<(String, Value)>>>;

fn describe() -> Value {
    json!({
        "name": "notes",
        "version": "1.0.0",
        "resources": ["notes"],
        "about": "Short notes for this project",
        "guide": "## Notes\n\nsgw-agent notes note add --text …   [notes:write]\n",
        "commands": [
            {
                "name": "note add",
                "about": "Add a note",
                "permission": "notes:write",
                "args": [
                    {"name": "text", "kind": "string", "required": true},
                    {"name": "tag", "kind": "list"}
                ]
            },
            {"name": "note list", "about": "List the notes", "permission": "notes:read"}
        ]
    })
}

/// A sidecar that answers `describe` with what it is given and every command with what it got.
fn fake_sidecar(sock: &Path, describe: Value) -> Seen {
    let seen: Seen = Arc::default();
    let listener = tokio::net::UnixListener::bind(sock).unwrap();
    let s = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (s, d) = (s.clone(), describe.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let (s, d) = (s.clone(), d.clone());
                    async move {
                        let path = req.uri().path().to_string();
                        let get = req.method() == Method::GET;
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                        s.lock().unwrap().push((path.clone(), v.clone()));
                        let out = if get && path == "/describe" {
                            d
                        } else {
                            json!({
                                "message": format!("added {}", v["args"]["text"].as_str().unwrap_or("")),
                                "calls": [{"method": "POST", "path": "/v1/notes", "status": 201}]
                            })
                        };
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                            out.to_string(),
                        ))))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    seen
}

struct Run {
    f: ApiFixture,
    seen: Seen,
}

async fn run(grants: &[&str], describe: Value, credential: State) -> Run {
    let tmp = tempfile::tempdir().unwrap();
    let sock: PathBuf = tmp.path().join("notes.sock");
    let seen = fake_sidecar(&sock, describe);
    let f = start(sock, grants, credential).await;
    // the socket's directory lives as long as the fixture
    std::mem::forget(tmp);
    Run { f, seen }
}

/// The gateway's API with the `notes` sidecar at `sock`.
async fn start(sock: PathBuf, grants: &[&str], credential: State) -> ApiFixture {
    let vars = Vars::new();
    vars.replace_all(HashMap::from([(KEY.to_string(), credential)]));
    let mut project = project_case_a(&["pr:create"]);
    let grants: Vec<String> = grants.iter().map(|g| g.to_string()).collect();
    project.set_extensions(&grants, &[]);
    start_api_with_commands(
        project,
        BootstrapMode::Auto,
        true,
        vec![],
        None,
        Forge::BuiltIn,
        move |audit| {
            BTreeMap::from([(
                "notes".to_string(),
                Arc::new(CommandSidecar::new(
                    "notes",
                    &sock,
                    vec!["notes".into()],
                    BTreeMap::from([("api_key".to_string(), KEY.to_string())]),
                    vars,
                    audit,
                )),
            )])
        },
    )
    .await
}

fn add(text: Value) -> ApiRequest {
    ApiRequest {
        args: json!({"text": text, "tag": ["a", "b"]})
            .as_object()
            .unwrap()
            .clone(),
        ..ApiRequest::default()
    }
}

fn commands_sent(seen: &Seen) -> Vec<Value> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|(p, _)| p == "/command")
        .map(|(_, v)| v.clone())
        .collect()
}

#[tokio::test]
async fn an_allowed_command_reaches_the_sidecar_checked_and_with_its_credential() {
    let r = run(&["notes:write"], describe(), State::Set(SECRET.into())).await;
    let (code, resp) = post(
        r.f.addr,
        "/x/notes/note/add",
        Some(&r.f.token),
        &add(json!("hi")),
    )
    .await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert_eq!(resp.message.as_deref(), Some("added hi"));
    let sent = commands_sent(&r.seen);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["command"], "note add");
    assert_eq!(sent[0]["permission"], "notes:write");
    assert_eq!(sent[0]["args"], json!({"text": "hi", "tag": ["a", "b"]}));
    assert_eq!(sent[0]["credentials"], json!({"api_key": SECRET}));
    // the sidecar's upstream call and the agent's call are both on the record; the credential is not
    let audit = std::fs::read_to_string(&r.f.audit_path).unwrap();
    assert!(audit.contains("\"/v1/notes\""), "{audit}");
    assert!(audit.contains("/x/notes/note/add"), "{audit}");
    assert!(!audit.contains(SECRET), "{audit}");
}

#[tokio::test]
async fn a_command_the_project_does_not_grant_is_refused_before_the_sidecar_hears_of_it() {
    let r = run(&["notes:read"], describe(), State::Set(SECRET.into())).await;
    let (code, resp) = post(
        r.f.addr,
        "/x/notes/note/add",
        Some(&r.f.token),
        &add(json!("hi")),
    )
    .await;
    assert_eq!(code, 403);
    assert!(resp.error.unwrap().contains("notes:write"));
    assert!(commands_sent(&r.seen).is_empty());
}

#[tokio::test]
async fn arguments_are_checked_by_the_gateway() {
    let r = run(&["notes:write"], describe(), State::Set(SECRET.into())).await;
    let (code, resp) = post(
        r.f.addr,
        "/x/notes/note/add",
        Some(&r.f.token),
        &add(json!(3)),
    )
    .await;
    assert_eq!(code, 400);
    assert!(resp.error.unwrap().contains("--text must be a string"));
    let (code, _) = post(
        r.f.addr,
        "/x/notes/note/add",
        Some(&r.f.token),
        &ApiRequest::default(),
    )
    .await;
    assert_eq!(code, 400);
    assert!(commands_sent(&r.seen).is_empty());
}

#[tokio::test]
async fn a_locked_store_stops_a_command_that_needs_a_credential() {
    let r = run(&["notes:write"], describe(), State::Locked).await;
    let (code, resp) = post(
        r.f.addr,
        "/x/notes/note/add",
        Some(&r.f.token),
        &add(json!("hi")),
    )
    .await;
    assert_eq!(code, 503);
    assert!(resp.error.unwrap().contains("sgw unlock"));
    assert!(commands_sent(&r.seen).is_empty());
}

#[tokio::test]
async fn a_sidecar_that_claims_more_than_it_was_given_is_not_connected() {
    let mut d = describe();
    d["resources"] = json!(["notes", "pr"]);
    let r = run(&["notes:write"], d, State::Set(SECRET.into())).await;
    let (code, resp) = post(
        r.f.addr,
        "/x/notes/note/add",
        Some(&r.f.token),
        &add(json!("hi")),
    )
    .await;
    assert_eq!(code, 503);
    assert!(resp.error.unwrap().contains("does not list"));
    assert!(commands_sent(&r.seen).is_empty());
}

#[tokio::test]
async fn an_unknown_sidecar_or_command_is_named_with_what_there_is() {
    let r = run(&["notes:write"], describe(), State::Set(SECRET.into())).await;
    let (code, resp) = post(
        r.f.addr,
        "/x/s3/ls",
        Some(&r.f.token),
        &ApiRequest::default(),
    )
    .await;
    assert_eq!(code, 404);
    assert!(resp.error.unwrap().contains("notes"));
    let (code, resp) = post(
        r.f.addr,
        "/x/notes/note/drop",
        Some(&r.f.token),
        &ApiRequest::default(),
    )
    .await;
    assert_eq!(code, 404);
    assert!(resp.error.unwrap().contains("note add"));
}

#[tokio::test]
async fn whoami_lists_a_sidecar_s_permissions_apart_from_the_repositories() {
    let r = run(
        &["notes:read", "notes:write"],
        describe(),
        State::Set(SECRET.into()),
    )
    .await;
    let (code, resp) = post(
        r.f.addr,
        "/whoami",
        Some(&r.f.token),
        &ApiRequest::default(),
    )
    .await;
    assert_eq!(code, 200);
    let msg = resp.message.unwrap();
    assert!(
        msg.contains("sidecar permissions (sgw-agent <sidecar> …): notes:read notes:write"),
        "{msg}"
    );
    // a repository line says only how it differs from the project; it has no say over these
    assert!(!msg.contains("-notes:"), "{msg}");
}

#[tokio::test]
async fn relays_lists_each_sidecar_with_what_the_project_may_run() {
    use sekimore_relay::forge::command::RelayList;
    let r = run(&["notes:read"], describe(), State::Set(SECRET.into())).await;
    let (code, resp) = post(
        r.f.addr,
        "/relays",
        Some(&r.f.token),
        &ApiRequest::default(),
    )
    .await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let list: RelayList = serde_json::from_value(resp.raw.unwrap()).unwrap();
    let names: Vec<&str> = list.relays.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["github", "notes"]);
    let notes = &list.relays[1];
    assert!(notes.available && notes.guide.contains("## Notes"));
    // #480: the sidecar's line in `sgw-agent --help`
    assert_eq!(notes.about, "Short notes for this project");
    let granted: Vec<(&str, bool)> = notes
        .commands
        .iter()
        .map(|c| (c.spec.name.as_str(), c.granted))
        .collect();
    assert_eq!(granted, [("note add", false), ("note list", true)]);
    // nothing is sent to run a command just to list them
    assert!(commands_sent(&r.seen).is_empty());
}

#[tokio::test]
async fn relays_says_why_a_sidecar_is_not_there() {
    use sekimore_relay::forge::command::RelayList;
    let mut d = describe();
    d["name"] = json!("other");
    let r = run(&["notes:read"], d, State::Set(SECRET.into())).await;
    let (_, resp) = post(
        r.f.addr,
        "/relays",
        Some(&r.f.token),
        &ApiRequest::default(),
    )
    .await;
    let list: RelayList = serde_json::from_value(resp.raw.unwrap()).unwrap();
    let notes = &list.relays[1];
    assert!(!notes.available);
    assert!(notes.reason.as_deref().unwrap().contains("names itself"));
    assert!(notes.commands.is_empty());
}

/// The template sidecar (examples/sidecar-template), a stopped child when dropped.
struct Template(std::process::Child);

impl Drop for Template {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The template's directory.
fn template_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/sidecar-template")
}

/// Builds the Go template into `dir` with `go build` (`GO` names a toolchain other than `go` on
/// PATH). `None` where there is no Go: skipped, or a failure when `SEKIMORE_E2E_REQUIRED` is set,
/// as CI and `mise run ci` set it.
fn build_template(dir: &Path) -> Option<PathBuf> {
    let go = std::env::var("GO").unwrap_or_else(|_| "go".into());
    let has_go = std::process::Command::new(&go)
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !has_go {
        if std::env::var("SEKIMORE_E2E_REQUIRED").is_ok() {
            panic!("no {go} to build the template with: install Go, or name it with GO");
        }
        eprintln!("skipped: no {go} to build the template with");
        return None;
    }
    let bin = dir.join("notes");
    let out = std::process::Command::new(&go)
        .args(["build", "-o"])
        .arg(&bin)
        .arg(".")
        .current_dir(template_dir())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "go build: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(bin)
}

/// #331, #499: the template a third party copies is built and run as it is, through the gateway,
/// which reads its describe with the real checks.
#[tokio::test]
async fn the_template_sidecar_works_through_the_gateway() {
    let tmp = tempfile::tempdir().unwrap();
    let Some(bin) = build_template(tmp.path()) else {
        return;
    };
    let sock = tmp.path().join("notes.sock");
    let mut child = Template(
        std::process::Command::new(&bin)
            .arg("--socket")
            .arg(&sock)
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    for _ in 0..200 {
        if sock.exists() {
            break;
        }
        assert!(child.0.try_wait().unwrap().is_none(), "the template exited");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let f = start(
        sock,
        &["notes:read", "notes:write"],
        State::Set(SECRET.into()),
    )
    .await;
    // the gateway connects it: its describe passes check_describe, the optional about included
    let (_, resp) = post(f.addr, "/relays", Some(&f.token), &ApiRequest::default()).await;
    let list: sekimore_relay::forge::command::RelayList =
        serde_json::from_value(resp.raw.unwrap()).unwrap();
    let notes = list.relays.iter().find(|r| r.name == "notes").unwrap();
    assert!(notes.available, "{:?}", notes.reason);
    assert_eq!(notes.about, "Short notes kept for this project");

    let (code, resp) = post(
        f.addr,
        "/x/notes/note/add",
        Some(&f.token),
        &ApiRequest {
            args: json!({"text": "hi", "tag": ["a"], "pin": true})
                .as_object()
                .unwrap()
                .clone(),
            ..ApiRequest::default()
        },
    )
    .await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert_eq!(resp.message.as_deref(), Some("added note 1"));
    let (code, resp) = post(
        f.addr,
        "/x/notes/note/list",
        Some(&f.token),
        &ApiRequest::default(),
    )
    .await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert_eq!(resp.message.as_deref(), Some("1: hi"));
    assert_eq!(resp.raw.unwrap()[0]["tags"], json!(["a"]));
    // the gateway's argument check comes before the template's own
    let (code, resp) = post(
        f.addr,
        "/x/notes/note/list",
        Some(&f.token),
        &ApiRequest {
            args: json!({"limit": "1"}).as_object().unwrap().clone(),
            ..ApiRequest::default()
        },
    )
    .await;
    assert_eq!(code, 400);
    assert!(resp.error.unwrap().contains("an integer"));
    // and a failure the template reports keeps its status
    let (code, _) = post(
        f.addr,
        "/x/notes/note/list",
        Some(&f.token),
        &ApiRequest {
            args: json!({"limit": 0}).as_object().unwrap().clone(),
            ..ApiRequest::default()
        },
    )
    .await;
    assert_eq!(code, 400);
    let audit = std::fs::read_to_string(&f.audit_path).unwrap();
    assert!(!audit.contains(SECRET), "{audit}");
    drop(child);
}

/// #499: the Go version is written in four places, and they move together: the template's
/// go.mod (the language version, `major.minor`, so a copy builds with any patch release), the
/// golang image its Dockerfile builds in, mise.toml, and the setup-go step of relay.yml. Dependabot
/// bumps the Dockerfile alone; this fails until the other three follow.
#[test]
fn the_go_version_agrees_across_the_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let read = |p: &str| std::fs::read_to_string(root.join(p)).unwrap();
    // the value after `prefix` on the first line that starts with it, up to `end`
    let find = |text: &str, prefix: &str, end: &[char]| -> String {
        text.lines()
            .map(str::trim)
            .find_map(|l| l.strip_prefix(prefix))
            .map(|v| v.split(end).next().unwrap().to_string())
            .unwrap_or_else(|| panic!("no line starting {prefix:?}"))
    };
    let mise = find(&read("mise.toml"), "go = \"", &['"']);
    let docker = find(
        &read("examples/sidecar-template/Dockerfile"),
        "FROM golang:",
        &['@', ' '],
    );
    let ci = find(
        &read(".github/workflows/relay.yml"),
        "go-version: \"",
        &['"'],
    );
    let go_mod = find(&read("examples/sidecar-template/go.mod"), "go ", &[' ']);
    assert_eq!(docker, mise, "the Dockerfile's golang image and mise.toml");
    assert_eq!(ci, mise, "relay.yml's setup-go and mise.toml");
    let minor: Vec<&str> = mise.split('.').take(2).collect();
    assert_eq!(go_mod, minor.join("."), "go.mod's go line and mise.toml");
}
