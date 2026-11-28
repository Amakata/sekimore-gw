//! The Web UI inside a running `sekimore-relay serve` (0.3.0-alpha.4, Issue #493).
//!
//! - The three shapes `serve` starts in (0.3.0 plan, "`serve` を常に起動する", property S9): no
//!   relay configured, an invalid relay configuration, a relay that fails to start — the UI is up
//!   in each and nothing of the relay is opened, created or written; and a relay that starts
//! - The sentinel secret (the plan's "秘密の見張り", property S5): a marker in every place a secret
//!   can be, and every route and `/ws` message searched for it
//! - The API's router refuses every UI route (the mirror of `webui::tests`)
//! - `scripts/start-relay.sh`: starts `serve` whatever the configuration, restarts it when it exits

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const SENTINEL: &str = "SENTINEL-7f3a9c";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A running `serve`, killed on drop.
struct Gateway {
    child: Child,
    dir: tempfile::TempDir,
    ui: SocketAddr,
    ssh: u16,
    api: u16,
    https: u16,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Gateway {
    fn state(&self) -> PathBuf {
        self.dir.path().join("relay")
    }

    /// What it logged so far (stops it).
    fn stop_and_log(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut s = String::new();
        if let Some(mut e) = self.child.stderr.take() {
            let _ = e.read_to_string(&mut s);
        }
        s
    }

    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

/// Start `serve` with `config` (`{dir}`, `{ssh}`, `{api}`, `{https}` filled in) and wait for the UI.
fn start(config: &str, env: &[(&str, String)]) -> Gateway {
    let dir = tempfile::tempdir().unwrap();
    let (ssh, api, https, web) = (free_port(), free_port(), free_port(), free_port());
    let text = config
        .replace("{dir}", &dir.path().display().to_string())
        .replace("{ssh}", &ssh.to_string())
        .replace("{api}", &api.to_string())
        .replace("{https}", &https.to_string());
    let cfg = dir.path().join("config.yml");
    std::fs::write(&cfg, text).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sekimore-relay"));
    cmd.arg("--config")
        .arg(&cfg)
        .arg("serve")
        .env("SEKIMORE_WEB_HOST", "127.0.0.1")
        .env("SEKIMORE_WEB_PORT", web.to_string())
        .env("SEKIMORE_DB_PATH", dir.path().join("gateway.db"))
        .env("SEKIMORE_SQUID_CONFIG", dir.path().join("squid.conf"))
        .env_remove("SEKIMORE_UPSTREAM_PROXY_USERNAME")
        .env_remove("SEKIMORE_UPSTREAM_PROXY_PASSWORD")
        .env_remove("SSH_AUTH_SOCK")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let child = cmd.spawn().unwrap();
    let mut gw = Gateway {
        child,
        dir,
        ui: SocketAddr::from(([127, 0, 0, 1], web)),
        ssh,
        api,
        https,
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok((200, _)) = try_get(gw.ui, "/api/gateway-info") {
            break;
        }
        assert!(gw.alive(), "serve exited before the UI came up");
        assert!(Instant::now() < deadline, "the UI never answered");
        std::thread::sleep(Duration::from_millis(50));
    }
    gw
}

fn try_get(addr: SocketAddr, path: &str) -> std::io::Result<(u16, String)> {
    request(addr, "GET", path)
}

fn request(addr: SocketAddr, method: &str, path: &str) -> std::io::Result<(u16, String)> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    s.set_read_timeout(Some(Duration::from_secs(20)))?;
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nhost: testserver\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    )?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| std::io::Error::other(format!("no status in {text:?}")))?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

fn get(addr: SocketAddr, path: &str) -> (u16, String) {
    try_get(addr, path).unwrap_or_else(|e| panic!("GET {path}: {e}"))
}

fn closed(port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(300),
    )
    .is_err()
}

/// One line to the control socket, one line back.
fn control(sock: &Path, line: &str) -> serde_json::Value {
    use std::os::unix::net::UnixStream;
    let mut s = UnixStream::connect(sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    s.write_all(format!("{line}\n").as_bytes()).unwrap();
    s.shutdown(std::net::Shutdown::Write).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    serde_json::from_str(out.lines().next().unwrap_or("{}")).unwrap()
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

const RELAY_KEYS: &str = r#"
relay:
  ssh_listen: 127.0.0.1:{ssh}
  api_listen: 127.0.0.1:{api}
  https_listen: 127.0.0.1:{https}
  state_dir: "{dir}/relay"
  project:
    name: example
    repos:
      - {name: ExampleOrg/app, mode: read-write, bases: [main]}
"#;

/// Nothing of the relay: no listener, nothing under its state directory, no control socket.
fn assert_ui_only(gw: &mut Gateway) {
    // give a relay that should not be there the time to show up
    std::thread::sleep(Duration::from_millis(1500));
    assert!(gw.alive(), "serve exited");
    assert!(
        !gw.state().exists(),
        "the relay's state directory was created"
    );
    assert!(
        closed(gw.ssh) && closed(gw.api) && closed(gw.https),
        "a relay port is open"
    );
    let (status, body) = get(gw.ui, "/api/config");
    assert_eq!(status, 200);
    assert!(body.contains("\"upstream_auth\":\"unavailable\""), "{body}");
    let (status, _) = get(gw.ui, "/api/relay/config");
    assert_eq!(status, 200);
}

#[test]
fn without_a_relay_serve_runs_the_ui_alone() {
    let mut gw = start(&format!("allow_domains: [example.com]\n{RELAY_KEYS}"), &[]);
    assert_ui_only(&mut gw);
    let (_, relay) = get(gw.ui, "/api/relay/config");
    assert!(relay.starts_with("{\"enabled\":false"), "{relay}");
    let log = gw.stop_and_log();
    assert!(log.contains("no git-relay handler"), "{log}");
}

#[test]
fn with_an_invalid_relay_configuration_serve_runs_the_ui_alone() {
    let mut gw = start(
        &format!(
            "allow_domains: [github.com]\ndomain_handlers:\n  github.com: {{handler: git-relay}}\n{RELAY_KEYS}  https: sideways\n"
        ),
        &[],
    );
    assert_ui_only(&mut gw);
    let log = gw.stop_and_log();
    assert!(log.contains("serving the Web UI only"), "{log}");
    assert!(
        log.contains("sideways"),
        "the configuration error is logged: {log}"
    );
}

const RELAY_CONFIG: &str =
    "allow_domains: [github.com]\ndomain_handlers:\n  github.com: {handler: git-relay}\n";

#[test]
fn a_relay_that_fails_to_start_leaves_the_ui_running() {
    // the API's port is taken: the relay gets as far as its SSH listener and stops there
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let api_port = api.local_addr().unwrap().port();
    let config = format!("{RELAY_CONFIG}{RELAY_KEYS}").replace("{api}", &api_port.to_string());
    let mut gw = start(&config, &[]);
    wait_for("the relay to give up", || {
        // its SSH listener goes with its runtime
        gw.state().join("audit.jsonl").exists() && closed(gw.ssh)
    });
    std::thread::sleep(Duration::from_millis(500));
    assert!(gw.alive(), "serve exited with the relay");
    assert!(closed(gw.ssh) && closed(gw.https));
    for _ in 0..3 {
        let (status, body) = get(gw.ui, "/api/config");
        assert_eq!(status, 200);
        assert!(body.contains("\"upstream_auth\":\"unavailable\""), "{body}");
    }
    drop(api);
    let log = gw.stop_and_log();
    assert!(
        log.contains("the relay stopped: serving the Web UI only"),
        "{log}"
    );
}

/// Every route, with the query parameters each takes, and a `/ws` session.
fn every_answer(ui: SocketAddr) -> Vec<(String, u16, String)> {
    let mut out = Vec::new();
    let mut paths: Vec<String> = sekimore_relay::webui::ROUTES
        .iter()
        .map(|r| r.to_string())
        .collect();
    paths.extend(
        [
            "/api/relay/audit?kind=allowed&limit=1000",
            "/api/relay/audit?kind=blocked",
            "/api/logs?limit=-1",
            "/api/i18n?lang=ja",
        ]
        .map(String::from),
    );
    for p in paths {
        let (status, body) = get(ui, &p);
        out.push((p, status, body));
    }
    out.push(("/ws".into(), 101, ws_messages(ui).join("\n")));
    out
}

/// The snapshot, and the one a resync gets.
fn ws_messages(ui: SocketAddr) -> Vec<String> {
    use tungstenite_raw::*;
    let mut s = TcpStream::connect(ui).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(
        b"GET /ws HTTP/1.1\r\nhost: x\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
    )
    .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut b).unwrap();
        head.push(b[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 101"));
    let first = read_text(&mut s);
    write_text(&mut s, r#"{"type":"resync"}"#);
    let second = read_text(&mut s);
    vec![first, second]
}

/// Just enough of RFC 6455 for a test client: unfragmented text frames.
mod tungstenite_raw {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    pub fn read_text(s: &mut TcpStream) -> String {
        let mut h = [0u8; 2];
        s.read_exact(&mut h).unwrap();
        assert_eq!(h[0] & 0x0f, 1, "a text frame");
        let len = match h[1] & 0x7f {
            126 => {
                let mut l = [0u8; 2];
                s.read_exact(&mut l).unwrap();
                u16::from_be_bytes(l) as usize
            }
            127 => {
                let mut l = [0u8; 8];
                s.read_exact(&mut l).unwrap();
                u64::from_be_bytes(l) as usize
            }
            n => n as usize,
        };
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).unwrap();
        String::from_utf8(body).unwrap()
    }

    pub fn write_text(s: &mut TcpStream, text: &str) {
        let mask = [1u8, 2, 3, 4];
        let mut frame = vec![0x81u8];
        let len = text.len();
        assert!(len < 126);
        frame.push(0x80 | len as u8);
        frame.extend_from_slice(&mask);
        frame.extend(text.bytes().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        s.write_all(&frame).unwrap();
    }
}

/// Property S5: a marker in every place a secret can be, and not one answer of the UI carries it.
#[test]
fn no_answer_carries_a_secret() {
    let config = format!(
        "{RELAY_CONFIG}proxy:\n  enabled: true\n  upstream_proxy: 127.0.0.1:9\n  upstream_proxy_username: {SENTINEL}-config-user\n  upstream_proxy_password: {SENTINEL}-config-pass\n{RELAY_KEYS}  sidecars:\n    notes:\n      socket: \"{{dir}}/notes.sock\"\n      resources: [notes]\n      credentials: {{api_key: \"{{notes_key}}\"}}\n"
    );
    let gw = start(
        &config,
        &[
            (
                "SEKIMORE_UPSTREAM_PROXY_USERNAME",
                format!("{SENTINEL}-env-user"),
            ),
            (
                "SEKIMORE_UPSTREAM_PROXY_PASSWORD",
                format!("{SENTINEL}-env-pass"),
            ),
        ],
    );
    let dir = gw.dir.path().to_path_buf();
    // the generated squid.conf carries the password the way Squid needs it
    std::fs::write(
        dir.join("squid.conf"),
        format!(
            "http_port 3128\ncache_peer 127.0.0.1 parent 9 0 login=someone:{SENTINEL}-squid-pass\n"
        ),
    )
    .unwrap();
    // the store: initialised, unlocked, and holding every kind of secret
    let sock = gw.state().join("control.sock");
    wait_for("the control socket", || sock.exists());
    let r = control(
        &sock,
        r#"{"op":"init","passphrase":"correct horse battery"}"#,
    );
    assert_eq!(r["ok"], true, "{r}");
    for (ns, name, value) in [
        ("var", "proxy_user", format!("{SENTINEL}-store-user")),
        ("var", "proxy_password", format!("{SENTINEL}-store-pass")),
        ("var", "notes_key", format!("{SENTINEL}-sidecar")),
        (
            "upstream",
            "github.com",
            format!("{SENTINEL}-upstream-token"),
        ),
        ("relay", "anything", format!("{SENTINEL}-store-value")),
    ] {
        let line = serde_json::json!({"op": "set", "namespace": ns, "name": name, "value": value});
        let r = control(&sock, &line.to_string());
        assert_eq!(r["ok"], true, "{r}");
    }
    // a project token, as the operator mints one
    let out = Command::new(env!("CARGO_BIN_EXE_sekimore-relay"))
        .arg("--config")
        .arg(dir.join("config.yml"))
        .arg("token")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed = String::from_utf8_lossy(&out.stdout).to_string();
    let token = printed
        .split_whitespace()
        .find_map(|w| w.strip_prefix("SEKIMORE_TOKEN="))
        .expect("the token is printed")
        .to_string();
    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    // the credential state reaches the UI from the store (the per-person value)
    wait_for("the store's credential to show", || {
        get(gw.ui, "/api/config")
            .1
            .contains("\"upstream_auth\":\"set\"")
    });

    let answers = every_answer(gw.ui);
    assert!(answers.len() > 22);
    for (path, _status, body) in &answers {
        for needle in [SENTINEL, &token, &hash[..32]] {
            assert!(
                !body.contains(needle),
                "{path} carries a secret ({needle}): {body}"
            );
        }
    }
    // the password is blanked where it used to leak (#217), and the token shows by its label only
    let config = &answers.iter().find(|a| a.0 == "/api/config").unwrap().2;
    assert!(config.contains("login=someone:***"), "{config}");
    let tokens = &answers
        .iter()
        .find(|a| a.0 == "/api/relay/tokens")
        .unwrap()
        .2;
    assert!(tokens.contains("\"state\":\"active\""), "{tokens}");
}

#[test]
fn with_a_relay_both_run_and_the_api_serves_no_ui_route() {
    let mut gw = start(&format!("{RELAY_CONFIG}{RELAY_KEYS}"), &[]);
    let api = SocketAddr::from(([127, 0, 0, 1], gw.api));
    wait_for("the API", || {
        matches!(request(api, "GET", "/healthz"), Ok((200, _)))
    });
    assert!(gw.state().join("control.sock").exists());
    assert!(!closed(gw.ssh) && !closed(gw.https));
    for route in sekimore_relay::webui::ROUTES
        .iter()
        .chain(&[sekimore_relay::webui::WS_ROUTE])
    {
        let (get_status, body) = request(api, "GET", route).unwrap();
        assert_eq!(get_status, 405, "GET {route} on the API: {body}");
        let (post_status, body) = request(api, "POST", route).unwrap();
        assert_eq!(post_status, 401, "POST {route} on the API: {body}");
    }
    // and the UI is the UI
    let (status, body) = get(gw.ui, "/api/relay/config");
    assert_eq!(status, 200);
    assert!(body.starts_with("{\"enabled\":true"), "{body}");
    assert!(gw.alive());
}

#[test]
fn the_ui_reports_the_release_and_serves_the_dashboard_unchanged() {
    let gw = start("allow_domains: []\n", &[]);
    let (_, body) = get(gw.ui, "/api/config");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["version_package"], env!("CARGO_PKG_VERSION"));
    assert_eq!(v["version_core"], "0.1.3");
    assert_eq!(v["version_webui"], "0.3.2");
    let (status, html) = get(gw.ui, "/");
    assert_eq!(status, 200);
    let file = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/webui/dashboard.html"),
    )
    .unwrap();
    assert_eq!(html, file);
}

// ---- scripts/start-relay.sh --------------------------------------------------------------------

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("scripts/start-relay.sh")
}

#[test]
fn start_relay_skips_when_the_binary_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new("bash")
        .arg(script())
        .env("SEKIMORE_RELAY_BIN", dir.path().join("nope"))
        .env("SEKIMORE_CONFIG_PATH", dir.path().join("config.yml"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("missing, skipping"));
}

/// `serve` starts whatever the configuration, and is started again when it exits (a panic aborts
/// it). `needs-relay` is no longer asked.
#[test]
fn start_relay_starts_serve_and_restarts_it() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let calls = dir.path().join("calls");
    let bin = dir.path().join("sekimore-relay");
    std::fs::write(
        &bin,
        format!("#!/bin/sh\necho \"$*\" >> {}\nexit 1\n", calls.display()),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut child = Command::new("bash")
        .arg(script())
        .env("SEKIMORE_RELAY_BIN", &bin)
        .env("SEKIMORE_CONFIG_PATH", "/etc/x/config.yml")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let lines = loop {
        let text = std::fs::read_to_string(&calls).unwrap_or_default();
        if text.lines().count() >= 2 || Instant::now() > deadline {
            break text;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let _ = child.kill();
    let _ = child.wait();
    let calls: Vec<&str> = lines.lines().collect();
    assert!(calls.len() >= 2, "{calls:?}");
    for c in calls {
        assert_eq!(c, "--config /etc/x/config.yml serve");
    }
}
