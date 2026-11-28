//! The `webui` comparison: the same HTTP requests (and `/ws` sessions) to the Python Web UI and to
//! the Rust one, over the same `config.yml`, log database, relay state and `squid.conf`.
//!
//! The cases are `relay/tests/fixtures/webui/cases.json`. Each names a config, the rows of the
//! log database, the files of the relay's state, the generated `squid.conf`, how `iptables-legacy`
//! behaves, the proxy credential's state, the requests and the WebSocket steps. Every case is
//! materialized twice — once for each side — from the same text, so neither sees what the other
//! did (a `/ws` case writes rows while it watches).
//!
//! Placeholders, filled before either side sees a file: `{dir}` (the case's directory), `{now}`
//! and `{now±N}` (epoch seconds), `{ts:now±N}` (RFC 3339 with `Z`), `{tsx:now±N}` (the same
//! without the `Z`, for a case that writes its own fraction). `now` is one whole second per run.
//!
//! **The Python side is gone.** The Python UI was removed in the same change that brought the Rust
//! one (0.3.0-alpha.4; the plan switches the Web UI without a fallback), so the record is the only
//! oracle: `relay/tests/fixtures/oracle/webui.json`, made at commit [`RECORDED_AT`] with the
//! Python UI still in the tree. CONTRIBUTING.md says how to make it again from there.
//!
//! Before comparing (and recording), both answers lose what changes from run to run: the case
//! directory becomes `{dir}`, a number within thirty days of `now` becomes `now±N`, the
//! dashboard's HTML its SHA-256, and `version_package` `{version}` (the record outlives
//! releases; the version is checked by `relay/tests/webui.rs`).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use sekimore_relay::webui::{self, CredentialState, UiView};

use crate::harness::{repo_root, Case, Comparison};

pub struct WebUi {
    now: i64,
    /// The directories materialized for the oracle, alive until the run ends
    dirs: Mutex<Vec<tempfile::TempDir>>,
}

impl WebUi {
    pub fn new() -> WebUi {
        WebUi {
            now: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("after 1970")
                .as_secs() as i64,
            dirs: Mutex::new(Vec::new()),
        }
    }
}

const CASES: &str = "relay/tests/fixtures/webui/cases.json";

fn scenarios() -> &'static BTreeMap<String, Value> {
    static S: OnceLock<BTreeMap<String, Value>> = OnceLock::new();
    S.get_or_init(|| {
        let path = repo_root().join(CASES);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{CASES}: {e}"));
        let v: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{CASES}: {e}"));
        let mut out = BTreeMap::new();
        for c in v["cases"].as_array().expect("cases") {
            let name = c["name"].as_str().expect("name").to_string();
            assert!(
                out.insert(name.clone(), c.clone()).is_none(),
                "{CASES}: {name} twice"
            );
        }
        out
    })
}

/// The cases, as the harness runs them.
pub fn cases() -> Vec<Case> {
    scenarios()
        .iter()
        .map(|(name, c)| Case {
            id: format!("webui/{name}"),
            path: repo_root().join(CASES),
            env: Default::default(),
            ledger: c["ledger"].as_str().map(String::from),
        })
        .collect()
}

fn scenario(case: &Case) -> &'static Value {
    let name = case.id.strip_prefix("webui/").expect("a webui case");
    &scenarios()[name]
}

// ---- placeholders ------------------------------------------------------------------------------

fn rfc3339(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    // civil_from_days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

fn fill(text: &str, dir: &Path, now: i64) -> String {
    let mut out = text.replace("{dir}", &dir.display().to_string());
    // {now}, {now+N}, {now-N}, {ts:now±N}, {tsx:now±N}
    let mut result = String::new();
    while let Some(start) = out.find('{') {
        let Some(len) = out[start..].find('}') else {
            break;
        };
        let inner = &out[start + 1..start + len];
        let (kind, expr) = match inner.split_once(':') {
            Some((k @ ("ts" | "tsx"), e)) => (k, e),
            _ => ("num", inner),
        };
        let offset = expr.strip_prefix("now").and_then(|rest| {
            if rest.is_empty() {
                Some(0)
            } else {
                rest.parse::<i64>().ok()
            }
        });
        result.push_str(&out[..start]);
        match offset {
            Some(o) => match kind {
                "ts" => result.push_str(&format!("{}Z", rfc3339(now + o))),
                "tsx" => result.push_str(&rfc3339(now + o)),
                _ => result.push_str(&(now + o).to_string()),
            },
            None => {
                // not a placeholder (a YAML flow mapping, a JSON object): keep the brace and look
                // inside it
                result.push('{');
                out = out[start + 1..].to_string();
                continue;
            }
        }
        out = out[start + len + 1..].to_string();
    }
    result.push_str(&out);
    result
}

/// The gateway's own tables, as `src/dns_server.py`, `src/firewall_monitor.py` and
/// `src/proxy_monitor.py` create them.
const GATEWAY_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS dns_queries (timestamp REAL, client_ip TEXT, query_domain TEXT, response_ips TEXT, ttl INTEGER, query_type TEXT, status TEXT DEFAULT 'allowed');
CREATE INDEX IF NOT EXISTS idx_response_ips ON dns_queries(response_ips);
CREATE INDEX IF NOT EXISTS idx_query_domain ON dns_queries(query_domain);
CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_queries(timestamp);
CREATE INDEX IF NOT EXISTS idx_dns_status_timestamp ON dns_queries(status, timestamp);
CREATE TABLE IF NOT EXISTS firewall_blocks (timestamp REAL, src_ip TEXT, dst_ip TEXT, dst_port INTEGER, protocol TEXT, action TEXT DEFAULT 'blocked');
CREATE INDEX IF NOT EXISTS idx_firewall_timestamp ON firewall_blocks(timestamp);
CREATE TABLE IF NOT EXISTS proxy_logs (timestamp REAL, client_ip TEXT, method TEXT, url TEXT, status_code INTEGER, squid_result TEXT, action TEXT DEFAULT 'allowed');
CREATE INDEX IF NOT EXISTS idx_proxy_logs_timestamp ON proxy_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_proxy_logs_action ON proxy_logs(action);
CREATE TABLE IF NOT EXISTS cache_stats (id INTEGER PRIMARY KEY, timestamp REAL, size INTEGER, hits INTEGER, misses INTEGER, hit_rate REAL);
";

/// One side's copy of a case.
struct Materialized {
    dir: PathBuf,
    config: PathBuf,
    db: PathBuf,
    squid: PathBuf,
    bin: PathBuf,
}

fn materialize(sc: &Value, dir: &Path, now: i64) -> Materialized {
    let m = Materialized {
        dir: dir.to_path_buf(),
        config: dir.join("config.yml"),
        db: match sc["db"].as_str().unwrap_or("gateway") {
            "nodir" => dir.join("no/such/dir/gateway.db"),
            _ => dir.join("gateway.db"),
        },
        squid: dir.join("squid.conf"),
        bin: dir.join("bin"),
    };
    if let Some(c) = sc["config"].as_str() {
        std::fs::write(&m.config, fill(c, dir, now)).unwrap();
    }
    if let Some(files) = sc["files"].as_object() {
        for (name, text) in files {
            let p = dir.join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, fill(text.as_str().expect("file text"), dir, now)).unwrap();
        }
    }
    match sc["db"].as_str().unwrap_or("gateway") {
        "gateway" | "empty-file" => {
            let c = rusqlite::Connection::open(&m.db).unwrap();
            if sc["db"].as_str() != Some("empty-file") {
                c.execute_batch(GATEWAY_SCHEMA).unwrap();
            }
            for stmt in sc["sql"].as_array().into_iter().flatten() {
                c.execute_batch(&fill(stmt.as_str().expect("sql"), dir, now))
                    .unwrap_or_else(|e| panic!("{stmt}: {e}"));
            }
        }
        _ => {}
    }
    if let Some(s) = sc["squid"].as_str() {
        std::fs::write(&m.squid, fill(s, dir, now)).unwrap();
    }
    std::fs::create_dir_all(&m.bin).unwrap();
    let script = match sc["iptables"].as_str().unwrap_or("missing") {
        "ok" => Some("#!/bin/sh\nif [ \"$1\" = -t ]; then printf 'Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)\\n'; else printf 'Chain INPUT (policy DROP 0 packets, 0 bytes)\\nChain FORWARD (policy DROP)\\n'; fi\n"),
        "nat-fails" => Some("#!/bin/sh\nif [ \"$1\" = -t ]; then echo 'no nat' >&2; exit 3; fi\nprintf 'Chain INPUT (policy DROP)\\n'\n"),
        "fails" => Some("#!/bin/sh\necho '  iptables v1.8.11 (legacy): cannot open table: Permission denied (you must be root)  ' >&2\nexit 4\n"),
        _ => None,
    };
    if let Some(script) = script {
        let p = m.bin.join("iptables-legacy");
        std::fs::write(&p, script).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    m
}

fn steps(sc: &Value, dir: &Path, now: i64) -> Value {
    let steps: Vec<Value> = sc["ws"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| match s.get("sql") {
            Some(sql) => json!({"sql": sql.as_array().unwrap().iter().map(|q| fill(q.as_str().unwrap(), dir, now)).collect::<Vec<_>>()}),
            None => s.clone(),
        })
        .collect();
    Value::Array(steps)
}

fn requests(sc: &Value) -> Vec<Value> {
    sc["requests"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| match r {
            Value::String(p) => {
                let (path, query) = p.split_once('?').unwrap_or((p, ""));
                json!({"method": "GET", "path": path, "query": query, "headers": {}})
            }
            other => json!({
                "method": other["method"].as_str().unwrap_or("GET"),
                "path": other["path"],
                "query": other["query"].as_str().unwrap_or(""),
                "headers": other.get("headers").cloned().unwrap_or(json!({})),
            }),
        })
        .collect()
}

/// The commit the record was made at: the last one with the Python Web UI in the tree.
pub const RECORDED_AT: &str = "37335fc";

impl Comparison for WebUi {
    fn kind(&self) -> &'static str {
        "webui"
    }

    fn live_gone(&self) -> Option<&'static str> {
        Some(
            "the Python Web UI was removed in 0.3.0-alpha.4 (it switched without a fallback); \
             relay/tests/fixtures/oracle/webui.json was recorded at commit 37335fc, where it still \
             was, and is the reference (CONTRIBUTING.md says how to record it again)",
        )
    }

    fn record_test(&self) -> &'static str {
        "the_web_ui_answers_as_python_did"
    }

    fn request(&self, case: &Case) -> Value {
        let sc = scenario(case);
        let dir = tempfile::tempdir().unwrap();
        let m = materialize(sc, dir.path(), self.now);
        let req = json!({
            "id": case.id,
            "dir": m.dir,
            "config_path": m.config,
            "db_path": m.db,
            "squid_path": m.squid,
            "bin": m.bin,
            "env_username": sc["env_username"].as_bool().unwrap_or(false),
            "credential": sc["credential"].as_str().unwrap_or("unreachable"),
            "requests": requests(sc),
            "ws": steps(sc, dir.path(), self.now),
        });
        self.dirs.lock().unwrap().push(dir);
        req
    }

    fn rust(&self, case: &Case, _request: &Value) -> Value {
        let sc = scenario(case);
        let dir = tempfile::tempdir().unwrap();
        let m = materialize(sc, dir.path(), self.now);
        let credential = match sc["credential"].as_str().unwrap_or("unreachable") {
            "set" => CredentialState::Set,
            "locked" => CredentialState::Locked,
            "none" => CredentialState::NotSet,
            "unusable" => CredentialState::Unusable,
            _ => CredentialState::Unreachable,
        };
        let (_tx, rx) = tokio::sync::watch::channel(credential);
        let view = UiView {
            config_path: m.config.clone(),
            db_path: m.db.clone(),
            squid_config_path: m.squid.clone(),
            iptables: m.bin.join("iptables-legacy"),
            env_proxy_username_set: sc["env_username"].as_bool().unwrap_or(false),
            credential: rx,
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let addr = rt.block_on(async {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            tokio::spawn(webui::serve(view, l));
            addr
        });
        let responses: Vec<Value> = requests(sc).iter().map(|r| http(addr, r)).collect();
        let ws = ws_session(addr, &steps(sc, dir.path(), self.now), &m.db);
        drop(rt);
        json!({
            "id": case.id,
            "dir": m.dir,
            "responses": responses,
            "ws": ws,
        })
    }

    fn normalize(&self, mut answer: Value) -> Value {
        let dir = answer["dir"].as_str().map(String::from);
        if let Some(o) = answer.as_object_mut() {
            o.remove("dir");
        }
        walk(&mut answer, dir.as_deref(), self.now as f64, None);
        answer
    }
}

fn walk(v: &mut Value, dir: Option<&str>, now: f64, key: Option<&str>) {
    match v {
        Value::String(s) => {
            if key == Some("version_package") {
                *s = "{version}".into();
            } else if let Some(d) = dir {
                if s.contains(d) {
                    *s = s.replace(d, "{dir}");
                }
            }
        }
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if (f - now).abs() < 30.0 * 86_400.0 {
                    *v = Value::String(format!("now{:+.3}", f - now));
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|i| walk(i, dir, now, None)),
        Value::Object(o) => {
            for (k, x) in o.iter_mut() {
                walk(x, dir, now, Some(k));
            }
        }
        _ => {}
    }
}

/// The body as the record holds it: JSON parsed, the dashboard's HTML as its hash, else text.
pub fn body_of(content_type: Option<&str>, body: &[u8]) -> Value {
    match content_type {
        Some(ct) if ct.starts_with("application/json") => serde_json::from_slice(body)
            .unwrap_or_else(|_| json!({"unparsable": String::from_utf8_lossy(body)})),
        Some(ct) if ct.starts_with("text/html") => {
            json!({"sha256": hex::encode(Sha256::digest(body))})
        }
        _ => Value::String(String::from_utf8_lossy(body).into_owned()),
    }
}

/// One request over a plain socket, so the request line and the headers are exactly these.
fn http(addr: std::net::SocketAddr, r: &Value) -> Value {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut target = r["path"].as_str().unwrap().to_string();
    let q = r["query"].as_str().unwrap_or("");
    if !q.is_empty() {
        target.push('?');
        target.push_str(q);
    }
    let headers = r["headers"].as_object().cloned().unwrap_or_default();
    let mut text = format!("{} {target} HTTP/1.1\r\n", r["method"].as_str().unwrap());
    if !headers.keys().any(|k| k.eq_ignore_ascii_case("host")) {
        text.push_str("host: testserver\r\n");
    }
    for (k, v) in &headers {
        text.push_str(&format!("{k}: {}\r\n", v.as_str().unwrap()));
    }
    text.push_str("connection: close\r\n\r\n");
    s.write_all(text.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a response head");
    let head = String::from_utf8_lossy(&buf[..split]).to_string();
    let body = &buf[split + 4..];
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .expect("a status");
    let mut h = BTreeMap::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            h.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    response(status, &h, body)
}

/// The shape both sides answer a request in.
pub fn response(status: u16, h: &BTreeMap<String, String>, body: &[u8]) -> Value {
    let ct = h.get("content-type").map(String::as_str);
    json!({
        "status": status,
        "content_type": ct,
        "location": h.get("location"),
        "allow": h.get("allow"),
        "body": body_of(ct, body),
    })
}

type Ws = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

/// The next message within `secs`: its JSON, `"nothing"`, or `"closed"`.
async fn next(ws: &mut Ws, secs: f64) -> Value {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::protocol::Message;
    match tokio::time::timeout(Duration::from_secs_f64(secs), ws.next()).await {
        Err(_) => json!("nothing"),
        Ok(Some(Ok(Message::Text(t)))) => {
            serde_json::from_str(t.as_str()).unwrap_or(json!(t.as_str()))
        }
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => json!("closed"),
        Ok(Some(Ok(other))) => json!(format!("unexpected {other:?}")),
    }
}

/// A `/ws` session: the snapshot on connect, then each step's outcome.
fn ws_session(addr: std::net::SocketAddr, steps: &Value, db: &Path) -> Value {
    let steps = steps.as_array().cloned().unwrap_or_default();
    if steps.is_empty() {
        return Value::Null;
    }
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        use futures_util::SinkExt;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_tungstenite::tungstenite::protocol::{Message, Role};

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(
            b"GET /ws HTTP/1.1\r\nhost: testserver\r\nconnection: Upgrade\r\nupgrade: websocket\r\n\
              sec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .await
        .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut b = [0u8; 1];
            s.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
        }
        assert!(
            head.starts_with(b"HTTP/1.1 101"),
            "{}",
            String::from_utf8_lossy(&head)
        );
        let mut ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(s, Role::Client, None).await;
        let mut out = vec![next(&mut ws, 5.0).await];
        for step in steps {
            if let Some(text) = step.get("send").and_then(Value::as_str) {
                ws.send(Message::text(text)).await.unwrap();
                let wait = step["wait"].as_f64().unwrap_or(5.0);
                out.push(next(&mut ws, wait).await);
            } else if step.get("binary").is_some() {
                let _ = ws.send(Message::binary(vec![1u8, 2, 3])).await;
                out.push(next(&mut ws, 5.0).await);
            } else if let Some(sql) = step.get("sql").and_then(Value::as_array) {
                let c = rusqlite::Connection::open(db).unwrap();
                for q in sql {
                    c.execute_batch(q.as_str().unwrap()).unwrap();
                }
            } else if let Some(wait) = step.get("expect").and_then(Value::as_f64) {
                out.push(next(&mut ws, wait).await);
            }
        }
        let _ = ws.close(None).await;
        Value::Array(out)
    })
}
