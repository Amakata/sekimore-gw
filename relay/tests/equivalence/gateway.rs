//! The comparisons of the gateway's periphery (0.3.0 plan, "α5"):
//!
//! | kind | the same input | compared |
//! |---|---|---|
//! | `followers` | bytes written to ulogd's log (through a stand-in `tail`) or to Squid's access.log | the rows of `firewall_blocks` / `proxy_logs`, `tail`'s arguments, whether the follower stopped |
//! | `maint` | a command line, a database, `config.yml`, the reload window's state file | exit code, stdout, stderr, the state file afterwards, the rows left, the files left |
//! | `reload_state` | a state file (some written by `sekimore-relay maint`) under four configurations | what the Python orchestrator's `ReloadWindow` and maint's make of it |
//!
//! The cases are `relay/tests/fixtures/gateway/{followers,maint,reload_state}.json`. Both sides run
//! their real loops: the followers' own read loops on a file (the firewall's through a `tail` on
//! PATH that prints the case and waits), `python -m src.maint` and `sekimore-relay maint` as
//! processes. A follower is stopped once it has recorded a sentinel line written after the case,
//! or when it ends by itself.
//!
//! Before comparing, both answers lose what changes from run to run: a firewall row's time (the
//! time it was recorded) becomes `now`; the directory becomes `{dir}`; `open for Xm Ys` and the
//! state file's `until` are rounded to a minute from the run's time; a log line on stdout keeps
//! only its message's first words (the log's format is not kept, its place is); an exception's
//! traceback and Rust's report of the same are both `<raised>`, a refused command line `<usage>`,
//! and `--help` `<help>`.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::{json, Value};

use sekimore_relay::gateway::{firewall_log, logdb, proxy_log, reload_window};
use sekimore_relay::settings::py::float_repr;

use crate::harness::{repo_root, Case, Comparison};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn now() -> f64 {
    sekimore_relay::gateway::now()
}

/// `{now}`, `{now+N}`, `{now-N}` and `{now-Nd}` (days), as whole seconds.
fn fill(text: &str, now: f64) -> String {
    let now = now.floor() as i64;
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = rest.find("{now") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 4..];
        let end = after.find('}').expect("a closed placeholder");
        let spec = &after[..end];
        let value = if spec.is_empty() {
            now
        } else {
            let (num, days) = match spec.strip_suffix('d') {
                Some(n) => (n, 86_400),
                None => (spec, 1),
            };
            now + num.parse::<i64>().expect("{now±N}") * days
        };
        out.push_str(&value.to_string());
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

fn fixture(name: &str) -> &'static Value {
    static F: OnceLock<std::sync::Mutex<BTreeMap<String, &'static Value>>> = OnceLock::new();
    let map = F.get_or_init(Default::default);
    let mut map = map.lock().unwrap();
    if let Some(v) = map.get(name) {
        return v;
    }
    let path = repo_root().join(format!("relay/tests/fixtures/gateway/{name}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
    let v: &'static Value = Box::leak(Box::new(
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}")),
    ));
    map.insert(name.to_string(), v);
    v
}

fn cases_of(name: &str) -> Vec<Case> {
    let path = repo_root().join(format!("relay/tests/fixtures/gateway/{name}.json"));
    fixture(name)["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|c| Case {
            id: format!("{name}/{}", c["name"].as_str().expect("name")),
            path: path.clone(),
            env: Default::default(),
            ledger: c["ledger"].as_str().map(String::from),
        })
        .collect()
}

fn case_of(name: &str, id: &str) -> &'static Value {
    let short = id
        .strip_prefix(&format!("{name}/"))
        .expect("this kind's case");
    fixture(name)["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["name"] == short)
        .unwrap_or_else(|| panic!("no case {id}"))
}

fn sqlite_rows(db: &Path, sql: &str) -> Vec<Vec<Value>> {
    use rusqlite::types::ValueRef;
    let conn = rusqlite::Connection::open(db).unwrap();
    let mut st = conn.prepare(sql).unwrap();
    let n = st.column_count();
    st.query_map([], |r| {
        Ok((0..n)
            .map(|i| match r.get_ref(i).unwrap() {
                ValueRef::Null => Value::Null,
                ValueRef::Integer(i) => json!(i),
                // JSON has no infinity: repr()'s word for it
                ValueRef::Real(f) if !f.is_finite() => json!(float_repr(f)),
                ValueRef::Real(f) => json!(f),
                ValueRef::Text(t) => json!(String::from_utf8_lossy(t)),
                ValueRef::Blob(_) => json!("<blob>"),
            })
            .collect())
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ---- followers ---------------------------------------------------------------------------------

pub struct Followers;

const FIREWALL_SENTINEL: &[u8] =
    b"[FIREWALL-BLOCK] SRC=255.255.255.255 DST=255.255.255.255 PROTO=SENTINEL";
const PROXY_SENTINEL: &[u8] = b"9999999999.5 0 sentinel TCP_MISS/200 0 GET sentinel";

pub fn followers_cases() -> Vec<Case> {
    cases_of("followers")
}

fn follower_data(c: &Value) -> Vec<u8> {
    let mut data = match (c["text"].as_str(), c["hex"].as_str()) {
        (Some(t), _) => t.as_bytes().to_vec(),
        (None, Some(h)) => hex::decode(h).expect("hex"),
        _ => panic!("a follower case has text or hex"),
    };
    if let Some(n) = c["repeat"].as_u64() {
        data = data.repeat(n as usize);
    }
    if let Some(h) = c["then_hex"].as_str() {
        data.extend(hex::decode(h).expect("hex"));
    }
    data
}

impl Comparison for Followers {
    fn kind(&self) -> &'static str {
        "followers"
    }

    fn record_test(&self) -> &'static str {
        "the_followers_record_what_python_recorded"
    }

    fn request(&self, case: &Case) -> Value {
        let c = case_of("followers", &case.id);
        json!({
            "id": case.id,
            "follower": c["follower"],
            "data_b64": B64.encode(follower_data(c)),
        })
    }

    fn rust(&self, case: &Case, request: &Value) -> Value {
        let data = B64.decode(request["data_b64"].as_str().unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let out = if request["follower"] == "firewall" {
            firewall(dir.path(), &data)
        } else {
            proxy(dir.path(), &data)
        };
        let mut answer = json!({"id": case.id});
        answer
            .as_object_mut()
            .unwrap()
            .extend(out.as_object().unwrap().clone());
        answer
    }
}

fn firewall(d: &Path, data: &[u8]) -> Value {
    let bin = d.join("bin");
    std::fs::create_dir(&bin).unwrap();
    let mut feed = data.to_vec();
    feed.push(b'\n');
    feed.extend_from_slice(FIREWALL_SENTINEL);
    feed.push(b'\n');
    std::fs::write(d.join("feed"), feed).unwrap();
    let tail = bin.join("tail");
    std::fs::write(
        &tail,
        format!(
            "#!/bin/sh\nprintf \"%s\\n\" \"$@\" > \"{d}/argv\"\necho $$ > \"{d}/pid\"\ncat \"{d}/feed\"\nexec sleep 60\n",
            d = d.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tail, std::fs::Permissions::from_mode(0o755)).unwrap();
    let log = d.join("firewall.log");
    let db = d.join("gw.db");
    let conn = logdb::open(&db).unwrap();
    logdb::init_firewall(&conn).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let t = {
        let (stop, log, tail) = (stop.clone(), log.clone(), tail.clone());
        std::thread::spawn(move || {
            let mut conn = conn;
            firewall_log::follow_with(&mut conn, &log, tail.as_os_str(), &|| {
                stop.load(Ordering::SeqCst)
            });
        })
    };
    wait_for("the firewall sentinel", || {
        !sqlite_rows(
            &db,
            "SELECT 1 FROM firewall_blocks WHERE src_ip = '255.255.255.255'",
        )
        .is_empty()
    });
    stop.store(true, Ordering::SeqCst);
    let pid = std::fs::read_to_string(d.join("pid")).unwrap();
    let _ = Command::new("kill").arg(pid.trim()).status();
    t.join().unwrap();
    let rows = sqlite_rows(
        &db,
        "SELECT timestamp, src_ip, dst_ip, dst_port, protocol, action FROM firewall_blocks \
         WHERE src_ip != '255.255.255.255' ORDER BY rowid",
    );
    let argv = std::fs::read_to_string(d.join("argv")).unwrap();
    let t_now = now();
    json!({
        "rows": rows.into_iter().map(|mut r| {
            if r[0].as_f64().is_some_and(|ts| (ts - t_now).abs() < 300.0) {
                r[0] = json!("now");
            }
            r
        }).collect::<Vec<_>>(),
        "argv": argv.lines().map(|a| a.replace(&log.display().to_string(), "{log}")).collect::<Vec<_>>(),
    })
}

fn opened_by_me(path: &Path) -> bool {
    std::fs::read_dir("/proc/self/fd")
        .map(|rd| {
            rd.filter_map(Result::ok)
                .any(|e| std::fs::read_link(e.path()).is_ok_and(|l| l == path))
        })
        .unwrap_or(false)
}

fn proxy(d: &Path, data: &[u8]) -> Value {
    let log = d.join("access.log");
    std::fs::write(&log, b"").unwrap();
    let db = d.join("gw.db");
    let mut conn = logdb::open(&db).unwrap();
    logdb::init_proxy(&mut conn).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let t = {
        let (stop, log) = (stop.clone(), log.clone());
        std::thread::spawn(move || {
            let mut conn = conn;
            proxy_log::follow(&mut conn, &log, &|| stop.load(Ordering::SeqCst));
        })
    };
    wait_for("the proxy follower to open its log", || opened_by_me(&log));
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        let mut all = data.to_vec();
        all.push(b'\n');
        all.extend_from_slice(PROXY_SENTINEL);
        all.push(b'\n');
        f.write_all(&all).unwrap();
    }
    let mut reached = false;
    wait_for("the proxy sentinel or the follower's end", || {
        reached =
            !sqlite_rows(&db, "SELECT 1 FROM proxy_logs WHERE client_ip = 'sentinel'").is_empty();
        reached || t.is_finished()
    });
    stop.store(true, Ordering::SeqCst);
    t.join().unwrap();
    let rows = sqlite_rows(
        &db,
        "SELECT timestamp, client_ip, method, url, status_code, squid_result, action \
         FROM proxy_logs WHERE client_ip != 'sentinel' ORDER BY rowid",
    );
    json!({
        "rows": rows.into_iter().map(|mut r| {
            if let Some(f) = r[0].as_f64() {
                r[0] = json!(float_repr(f));
            }
            r
        }).collect::<Vec<_>>(),
        "stopped": !reached,
    })
}

// ---- maint -------------------------------------------------------------------------------------

pub struct Maint;

pub fn maint_cases() -> Vec<Case> {
    cases_of("maint")
}

/// The case's database, built here once so that both sides start from the same bytes.
fn build_db(spec: &Value, now: f64) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gw.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        if spec["journal"] == "wal" {
            let _: String = conn
                .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
                .unwrap();
        }
        for sql in spec["sql"].as_array().unwrap() {
            conn.execute_batch(&fill(sql.as_str().unwrap(), now))
                .unwrap();
        }
    }
    std::fs::read(&path).unwrap()
}

impl Comparison for Maint {
    fn kind(&self) -> &'static str {
        "maint"
    }

    fn record_test(&self) -> &'static str {
        "maint_answers_as_python_did"
    }

    fn request(&self, case: &Case) -> Value {
        let c = case_of("maint", &case.id);
        let t = now();
        let mut files = serde_json::Map::new();
        if let Some(db) = c["db"].as_str() {
            let spec = &fixture("maint")["dbs"][db];
            files.insert("gw.db".into(), json!(B64.encode(build_db(spec, t))));
        }
        if let Some(cfg) = c["config"].as_str() {
            files.insert("config.yml".into(), json!(B64.encode(fill(cfg, t))));
        }
        if let Some(state) = c["state"].as_str() {
            files.insert(
                "state/reload-window.json".into(),
                json!(B64.encode(fill(state, t))),
            );
        }
        if c["blocked"].as_bool() == Some(true) {
            // a file where the state's directory goes: nothing can be written under it
            files.insert("state".into(), json!(B64.encode("")));
        }
        json!({
            "id": case.id,
            "args": c["args"],
            "lang": c["lang"].as_str().unwrap_or("en"),
            "files": files,
        })
    }

    fn rust(&self, case: &Case, request: &Value) -> Value {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        materialize(d, request);
        let args: Vec<String> = request["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                a.as_str()
                    .unwrap()
                    .replace("{dir}", &d.display().to_string())
            })
            .collect();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sekimore-relay"));
        for (k, _) in std::env::vars() {
            if k.starts_with("LC_") || k.starts_with("SEKIMORE_") || k == "LANG" {
                cmd.env_remove(k);
            }
        }
        let out = cmd
            .arg("maint")
            .args(&args)
            .env("SEKIMORE_LANG", request["lang"].as_str().unwrap())
            .env("SEKIMORE_RELOAD_STATE", d.join("state/reload-window.json"))
            .current_dir(repo_root())
            .output()
            .unwrap();
        let ds = d.display().to_string();
        let mut answer = json!({
            "id": case.id,
            "code": out.status.code().unwrap_or(-1),
            "stdout": String::from_utf8_lossy(&out.stdout).replace(&ds, "{dir}"),
            "stderr": String::from_utf8_lossy(&out.stderr).replace(&ds, "{dir}"),
            "now": now(),
        });
        answer
            .as_object_mut()
            .unwrap()
            .extend(after(d).as_object().unwrap().clone());
        answer
    }

    fn normalize(&self, answer: Value) -> Value {
        let c = case_of("maint", answer["id"].as_str().unwrap());
        let t = answer["now"].as_f64().unwrap_or_else(now);
        let mut a = answer;
        let obj = a.as_object_mut().unwrap();
        obj.remove("now");
        let stdout = obj["stdout"].as_str().unwrap().to_string();
        obj["stdout"] = if c["help"].as_bool() == Some(true) {
            json!("<help>")
        } else {
            json!(stdout
                .lines()
                .map(|l| open_for(&log_line(l)))
                .map(|l| l + "\n")
                .collect::<String>())
        };
        let stderr = obj["stderr"].as_str().unwrap().to_string();
        obj["stderr"] = json!(if stderr.contains("Traceback (most recent call last)")
            || stderr.starts_with("sekimore-relay maint: failed: ")
        {
            "<raised>".to_string()
        } else if stderr.starts_with("usage:") {
            "<usage>".to_string()
        } else {
            stderr
        });
        if let Some(state) = obj.get("state").and_then(Value::as_str).map(String::from) {
            obj["state"] = json!(until(&state, t));
        }
        a
    }
}

fn materialize(d: &Path, request: &Value) {
    for (name, b64) in request["files"].as_object().unwrap() {
        let path = d.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = B64.decode(b64.as_str().unwrap()).unwrap();
        // {dir} in a text file is the case's directory (config.yml's database_path)
        let bytes = match String::from_utf8(bytes) {
            Ok(t) if name != "gw.db" => t.replace("{dir}", &d.display().to_string()).into_bytes(),
            Ok(t) => t.into_bytes(),
            Err(e) => e.into_bytes(),
        };
        std::fs::write(&path, bytes).unwrap();
    }
}

fn after(d: &Path) -> Value {
    let state = d.join("state/reload-window.json");
    let mut files: Vec<String> = Vec::new();
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).unwrap().filter_map(Result::ok) {
            let p = e.path();
            if p.is_dir() {
                walk(root, &p, out);
            } else if p.is_file() {
                out.push(p.strip_prefix(root).unwrap().display().to_string());
            }
        }
    }
    walk(d, d, &mut files);
    files.sort();
    let mut out = json!({
        "state": state.is_file().then(|| std::fs::read_to_string(&state).unwrap()),
        "files": files,
    });
    let db = d.join("gw.db");
    if db.is_file() {
        let mut rows = serde_json::Map::new();
        for t in sqlite_rows(
            &db,
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
        ) {
            let name = t[0].as_str().unwrap().to_string();
            let n = sqlite_rows(&db, &format!("SELECT COUNT(*) FROM {name}"))[0][0].clone();
            rows.insert(name, n);
        }
        out["rows"] = Value::Object(rows);
    }
    out
}

/// A structlog line (`2026-11-28 01:54:36 [error    ] message: detail component=…`) as
/// `<log: message>`.
fn log_line(l: &str) -> String {
    let b = l.as_bytes();
    let stamp = b.len() > 21
        && b[..19].iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b' ',
            13 | 16 => *c == b':',
            _ => c.is_ascii_digit(),
        })
        && b[19] == b' '
        && b[20] == b'[';
    if !stamp {
        return l.to_string();
    }
    let msg = l.split_once("] ").map_or("", |(_, m)| m);
    format!("<log: {}>", msg.split(": ").next().unwrap_or(msg))
}

/// `open for Xm Ys` as the whole seconds rounded to a minute (Python's interpreter takes a second
/// or two to start).
fn open_for(l: &str) -> String {
    let Some(i) = l.find("open for ") else {
        return l.to_string();
    };
    let rest = &l[i + 9..];
    let parsed = rest.split_once("m ").and_then(|(m, r)| {
        let (s, tail) = r.split_once('s')?;
        Some((m.parse::<i128>().ok()?, s.parse::<i128>().ok()?, tail))
    });
    match parsed {
        Some((m, s, tail)) => format!("{}open for ~{}s{tail}", &l[..i], round60(m * 60 + s)),
        None => l.to_string(),
    }
}

fn round60(n: i128) -> i128 {
    n.saturating_add(30).div_euclid(60) * 60
}

/// `{"until": X}` with X as `<now+N>`, N the seconds from the run's time rounded to a minute.
fn until(state: &str, t: f64) -> String {
    let Some(num) = state
        .strip_prefix("{\"until\": ")
        .and_then(|s| s.strip_suffix('}'))
    else {
        return state.to_string();
    };
    // a number, or a string holding one (a state file written by hand)
    let quoted = num.starts_with('"');
    match num.trim_matches('"').trim().parse::<f64>() {
        Ok(x) if (x - t).abs() < 1e15 => {
            let q = if quoted { "\"" } else { "" };
            format!(
                "{{\"until\": {q}<now+{}>{q}}}",
                round60((x - t).round() as i128)
            )
        }
        // too far out for a difference to mean anything: the digits are compared
        Ok(_) => state.to_string(),
        Err(_) => state.to_string(),
    }
}

// ---- reload_state ------------------------------------------------------------------------------

pub struct ReloadState;

pub fn reload_state_cases() -> Vec<Case> {
    cases_of("reload_state")
}

/// The state file `sekimore-relay maint <args>` writes.
fn written_by(args: &[Value]) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("reload-window.json");
    let cfg = dir.path().join("config.yml");
    std::fs::write(&cfg, "reload: auto\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sekimore-relay"))
        .arg("maint")
        .arg("--config")
        .arg(&cfg)
        .args(args.iter().map(|a| a.as_str().unwrap()))
        .env("SEKIMORE_RELOAD_STATE", &state)
        .env("SEKIMORE_LANG", "en")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(&state).unwrap()
}

impl Comparison for ReloadState {
    fn kind(&self) -> &'static str {
        "reload_state"
    }

    fn record_test(&self) -> &'static str {
        "the_orchestrator_reads_the_window_maint_writes"
    }

    fn request(&self, case: &Case) -> Value {
        let c = case_of("reload_state", &case.id);
        let t = now();
        let state: Option<Vec<u8>> = if let Some(args) = c["written_by"].as_array() {
            Some(written_by(args))
        } else if let Some(s) = c["state"].as_str() {
            Some(fill(s, t).into_bytes())
        } else {
            c["state_hex"].as_str().map(|h| hex::decode(h).unwrap())
        };
        json!({
            "id": case.id,
            "mode": c["mode"],
            "window": c["window"],
            "state_b64": state.map(|s| B64.encode(s)),
        })
    }

    fn rust(&self, case: &Case, request: &Value) -> Value {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reload-window.json");
        if let Some(b) = request["state_b64"].as_str() {
            std::fs::write(&path, B64.decode(b).unwrap()).unwrap();
        }
        let window = request["window"].as_i64().map(i128::from);
        let mode = request["mode"].as_str().unwrap();
        let prefixes = |logged: &[String]| -> Vec<String> {
            logged
                .iter()
                .map(|m| m.split(": ").next().unwrap_or(m).to_string())
                .collect()
        };
        let answer = match reload_window::ReloadWindow::new(mode, window, &path) {
            Ok(w) => match (w.describe(), w.seconds_left()) {
                (Ok(describe), Ok(left)) => json!({
                    "is_open": w.is_open(),
                    "describe": describe,
                    "seconds_left": left.map(|l| l.to_string()),
                    "logged": prefixes(&w.logged),
                }),
                _ => json!({"raised": true, "logged": prefixes(&w.logged)}),
            },
            Err(_) => json!({"raised": true, "logged": []}),
        };
        let mut a = json!({"id": case.id, "now": now()});
        a.as_object_mut()
            .unwrap()
            .extend(answer.as_object().unwrap().clone());
        a
    }

    fn normalize(&self, answer: Value) -> Value {
        let mut a = answer;
        let obj = a.as_object_mut().unwrap();
        obj.remove("now");
        if let Some(d) = obj
            .get("describe")
            .and_then(Value::as_str)
            .map(String::from)
        {
            obj["describe"] = json!(open_for(&d));
        }
        // seconds_left: Python's int (a JSON number, or a string from Rust for i128), rounded
        if let Some(v) = obj.get("seconds_left").cloned() {
            let n: Option<i128> = match &v {
                Value::Number(n) => n
                    .as_i64()
                    .map(i128::from)
                    .or_else(|| n.as_f64().map(|f| f as i128)),
                Value::String(s) => s.parse().ok(),
                _ => None,
            };
            obj["seconds_left"] = n.map_or(Value::Null, |n| json!(format!("~{}", round60(n))));
        }
        a
    }
}

#[test]
fn placeholders_are_filled() {
    assert_eq!(
        fill("a {now} b {now+5} {now-2d}", 100.7),
        "a 100 b 105 -172700"
    );
    assert_eq!(
        until("{\"until\": 1010.25}", 400.0),
        "{\"until\": <now+600>}"
    );
    assert_eq!(
        open_for("reload: open for 29m 59s (applies on save)"),
        "reload: open for ~1800s (applies on save)"
    );
    assert_eq!(
        log_line("2026-11-28 01:54:36 [error    ] Cannot read the reload window state: x component=ORCHESTRATOR"),
        "<log: Cannot read the reload window state>"
    );
}

/// Two processes write the log database from this release on: the Python DNS server (until the
/// core moves) and the Rust followers. The real Python writer (`DNSMapping.record_query`, which
/// lets a failed INSERT raise) and the followers' writer, as fast as each can, on one file: every
/// row of both is there and neither failed. Python is required under `SEKIMORE_E2E_REQUIRED`.
#[test]
fn the_python_dns_writer_and_the_rust_followers_share_the_database() {
    let Some(uv) = crate::harness::uv() else {
        assert!(!crate::harness::required(), "uv is required");
        eprintln!("skipping: uv is not on PATH");
        return;
    };
    const N: usize = 4000;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("gw.db");
    {
        let conn = logdb::open(&db).unwrap();
        logdb::init_firewall(&conn).unwrap();
    }
    let script = format!(
        "import asyncio, sys\n\
         from src.dns_server import DNSMapping\n\
         async def main():\n\
         \x20   m = DNSMapping({db:?})\n\
         \x20   await m.init_db()\n\
         \x20   print('ready', file=sys.stderr, flush=True)\n\
         \x20   for i in range({N}):\n\
         \x20       await m.record_query('10.0.0.2', f'n{{i}}.example', ['1.2.3.4'], 300)\n\
         \x20   await m.db.close()\n\
         asyncio.run(main())\n",
        db = db.display().to_string()
    );
    let mut python = Command::new(uv)
        .args([
            "run", "--frozen", "--no-dev", "--quiet", "python", "-c", &script,
        ])
        .current_dir(repo_root())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // start writing once Python has opened the file, so the two overlap
    {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(python.stderr.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "ready", "Python did not start");
    }
    let rust = {
        let db = db.clone();
        std::thread::spawn(move || {
            let mut conn = logdb::open(&db).unwrap();
            for i in 0..N {
                logdb::record_block(&mut conn, i as f64, "10.0.0.2", "9.9.9.9", Some(22), "TCP")
                    .unwrap();
            }
        })
    };
    rust.join().unwrap();
    let out = python.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let count = |t: &str| sqlite_rows(&db, &format!("SELECT COUNT(*) FROM {t}"))[0][0].clone();
    assert_eq!(count("dns_queries"), json!(N));
    assert_eq!(count("firewall_blocks"), json!(N));
    let mode = sqlite_rows(&db, "PRAGMA journal_mode")[0][0].clone();
    assert_eq!(mode, json!("wal"));
}
