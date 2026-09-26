//! `sgw-agent setup` end to end (#257): as a process, against the real API server, a fake Web UI
//! for `/api/proxy-env`, a fake `ssh-keyscan`, a temporary HOME and env-file directory. Run
//! twice: the second run keeps the token and changes nothing.
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::*;
use sekimore_relay::config::BootstrapMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The Web UI's `/api/proxy-env`, answering with or without a proxy as the flag says.
async fn fake_webui(configured: Arc<AtomicBool>) -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                break;
            };
            let c = configured.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let body = if c.load(Ordering::SeqCst) {
                    r#"{"configured":true,"port":3128,"no_proxy":["api.github.com","localhost"],"direct_egress":"deny"}"#
                } else {
                    r#"{"configured":false,"port":0,"no_proxy":[],"direct_egress":"allow"}"#
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

struct Bench {
    dir: tempfile::TempDir,
    home: PathBuf,
    env_file: PathBuf,
    root: PathBuf,
    keyscan: PathBuf,
}

fn bench() -> Bench {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(root.join("etc/environment"), "PATH=/usr/bin\n").unwrap();
    let keyscan = dir.path().join("ssh-keyscan");
    std::fs::write(
        &keyscan,
        "#!/usr/bin/env bash\nhost=\"${@: -1}\"\necho \"# $host:22 SSH-2.0-sekimore-relay\"\necho \"$host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&keyscan, std::fs::Permissions::from_mode(0o755)).unwrap();
    Bench {
        env_file: dir.path().join("etc/env"),
        dir,
        home,
        root,
        keyscan,
    }
}

async fn setup(b: &Bench, api_port: u16, webui_port: u16) -> (i32, String, String) {
    let me = sekimore_relay::agent_setup::files::current_user().unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_sgw-agent"));
    for k in [
        "SEKIMORE_TOKEN",
        "SEKIMORE_TOKEN_EXPIRES",
        "SEKIMORE_ENDPOINT",
        "SEKIMORE_REPO",
        "SEKIMORE_IP",
        "SEKIMORE_KEY_DIR",
        "SEKIMORE_BOOTSTRAP",
        "SEKIMORE_GIT_DOMAIN",
        "SEKIMORE_AGENT_INSTRUCTIONS",
        "SEKIMORE_SIGNING_KEY_COMMENT",
        "GIT_AUTHOR_EMAIL",
    ] {
        c.env_remove(k);
    }
    c.env("HOME", &b.home)
        .env("SEKIMORE_LANG", "en")
        .env("SEKIMORE_AGENT_USER", &me.name)
        .env("SEKIMORE_AGENT_HOME", &b.home)
        .env("SEKIMORE_AGENT_ENV_FILE", &b.env_file)
        .env("SEKIMORE_PROXY_ENV_ROOT", &b.root)
        .env("SEKIMORE_RELAY_API_PORT", api_port.to_string())
        .env("SEKIMORE_WEBUI_PORT", webui_port.to_string())
        .env("SEKIMORE_SSH_KEYSCAN", &b.keyscan)
        .env("SEKIMORE_PROJECT", "case-a")
        .env("SEKIMORE_ALLOW_CREDENTIAL_HELPER", "1")
        .env("GIT_COMMITTER_EMAIL", "agent@example.invalid")
        .args(["setup", "--gateway", "127.0.0.1"]);
    let out = tokio::task::spawn_blocking(move || c.output().unwrap())
        .await
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn text(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_writes_everything_and_a_second_run_changes_nothing() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let configured = Arc::new(AtomicBool::new(true));
    let webui = fake_webui(configured.clone()).await;
    let b = bench();

    let (code, out, err) = setup(&b, f.addr.port(), webui).await;
    assert_eq!(code, 0, "stdout: {out}\nstderr: {err}");
    assert!(
        out.contains("registered the disposable key and received a project token"),
        "{out}"
    );
    assert!(
        out.contains("[agent] relay: ready — git via github.com:22 → 127.0.0.1"),
        "{out}"
    );
    assert!(out.contains("commits are signed with"), "{out}");

    // the env file, the way agent-setup.sh wrote it
    let env = text(&b.env_file);
    assert_eq!(mode(&b.env_file), 0o600);
    for needle in [
        "SEKIMORE_IP=127.0.0.1\n",
        &format!("SEKIMORE_ENDPOINT=http://127.0.0.1:{}\n", f.addr.port()),
        "SEKIMORE_GIT_DOMAIN=github.com\n",
        "SEKIMORE_GIT_DOMAINS=github.com:22\n",
        "SEKIMORE_REPO=LibOrg/awesome-lib\n",
        "SEKIMORE_TOKEN=skm_",
        "SEKIMORE_TOKEN_EXPIRES=",
        &format!(
            "SEKIMORE_AGENT_KEY={}/.ssh/sekimore/id_ed25519.pub\n",
            b.home.display()
        ),
    ] {
        assert!(env.contains(needle), "{needle:?} missing in {env}");
    }
    assert!(
        !env.contains("SSH_AUTH_SOCK="),
        "no gateway socket, so none exported: {env}"
    );

    // the keys
    let keydir = b.home.join(".ssh/sekimore");
    assert_eq!(mode(&keydir.join("id_ed25519")), 0o600);
    assert_eq!(mode(&keydir.join("id_ed25519.pub")), 0o644);
    let signing_pub = text(&keydir.join("signing_ed25519.pub"));
    assert!(
        signing_pub
            .trim()
            .ends_with("sekimore-agent-signing: case-a"),
        "{signing_pub}"
    );

    // known_hosts and ~/.ssh/config
    let kh = text(&b.home.join(".ssh/known_hosts"));
    assert!(
        kh.contains("github.com,127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE"),
        "{kh}"
    );
    let cfg = text(&b.home.join(".ssh/config"));
    assert_eq!(mode(&b.home.join(".ssh/config")), 0o600);
    assert!(
        cfg.contains("# >>> sekimore-relay >>>\nHost github.com\n  User git\n  Port 22\n"),
        "{cfg}"
    );
    assert!(
        cfg.contains(&format!(
            "IdentityFile {}\n",
            keydir.join("id_ed25519").display()
        )),
        "{cfg}"
    );

    // git signs with the generated key, from a file ~/.gitconfig includes last (#145)
    let gitconfig = text(&b.dir.path().join("etc/gitconfig"));
    assert!(
        gitconfig.contains(&format!(
            "signingkey = {}\n",
            keydir.join("signing_ed25519.pub").display()
        )),
        "{gitconfig}"
    );
    assert!(gitconfig.contains("gpgsign = true"), "{gitconfig}");
    let global = text(&b.home.join(".gitconfig"));
    assert!(
        global.trim_end().ends_with(&format!(
            "[include]\n\tpath = {}",
            b.dir.path().join("etc/gitconfig").display()
        )),
        "{global}"
    );
    assert!(global.contains("gpgsign = true"), "{global}");
    let signers = text(&b.home.join(".config/git/allowed_signers"));
    assert!(
        signers.starts_with("agent@example.invalid namespaces=\"git\" ssh-ed25519 "),
        "{signers}"
    );

    // the guide for Claude Code and Codex
    let skill = text(&b.home.join(".claude/skills/sekimore-relay/SKILL.md"));
    assert!(
        skill.starts_with("---\nname: sekimore-relay\n") && skill.contains("sgw-agent whoami"),
        "{skill}"
    );
    assert!(
        !skill.contains("Signing is required here"),
        "not a signing: required project"
    );
    let agents = text(&b.home.join(".codex/AGENTS.md"));
    assert!(
        agents.contains("<!-- >>> sekimore-relay >>> -->") && agents.contains("`sgw-agent guide`"),
        "{agents}"
    );

    // the proxy environment, from the Web UI's answer
    let profile = text(&b.root.join("etc/profile.d/sekimore-proxy.sh"));
    assert!(
        profile.contains("export HTTP_PROXY=\"http://127.0.0.1:3128\""),
        "{profile}"
    );
    assert!(text(&b.root.join("etc/environment")).contains("NO_PROXY=\"api.github.com,localhost\""));

    // the token in the env file is one the relay accepts: sgw-agent whoami runs with it
    let mut w = Command::new(env!("CARGO_BIN_EXE_sgw-agent"));
    w.env_remove("SEKIMORE_TOKEN")
        .env_remove("SEKIMORE_REPO")
        .env("SEKIMORE_AGENT_ENV_FILE", &b.env_file)
        .env("SEKIMORE_LANG", "en")
        .arg("whoami");
    let who = tokio::task::spawn_blocking(move || w.output().unwrap())
        .await
        .unwrap();
    assert!(
        who.status.success(),
        "{}",
        String::from_utf8_lossy(&who.stderr)
    );

    // ---- the second run: nothing changes, the token is kept, the proxy is gone ----
    configured.store(false, Ordering::SeqCst);
    let before = [
        text(&b.env_file),
        cfg.clone(),
        kh.clone(),
        gitconfig.clone(),
        agents.clone(),
        text(&keydir.join("id_ed25519.pub")),
        signing_pub.clone(),
    ];
    let (code, out, err) = setup(&b, f.addr.port(), webui).await;
    assert_eq!(code, 0, "stdout: {out}\nstderr: {err}");
    assert!(
        out.contains("existing project token is still valid, keeping it"),
        "{out}"
    );
    let after = [
        text(&b.env_file),
        text(&b.home.join(".ssh/config")),
        text(&b.home.join(".ssh/known_hosts")),
        text(&b.dir.path().join("etc/gitconfig")),
        text(&b.home.join(".codex/AGENTS.md")),
        text(&keydir.join("id_ed25519.pub")),
        text(&keydir.join("signing_ed25519.pub")),
    ];
    assert_eq!(before, after, "a second run must change nothing");
    let global = text(&b.home.join(".gitconfig"));
    assert_eq!(
        global.matches("[include]").count(),
        1,
        "the include is there once: {global}"
    );
    assert_eq!(
        text(&b.home.join(".config/git/allowed_signers"))
            .lines()
            .count(),
        1
    );
    assert!(
        !b.root.join("etc/profile.d/sekimore-proxy.sh").exists(),
        "no proxy any more"
    );
    assert_eq!(text(&b.root.join("etc/environment")), "PATH=/usr/bin\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_relay_setup_still_writes_the_proxy_environment_and_exits_zero() {
    let configured = Arc::new(AtomicBool::new(true));
    let webui = fake_webui(configured).await;
    let b = bench();
    // a port nothing listens on: no relay
    let (code, out, _) = setup(&b, 1, webui).await;
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("no relay on 127.0.0.1:1, skipping"), "{out}");
    assert!(b.root.join("etc/profile.d/sekimore-proxy.sh").exists());
    assert!(!b.env_file.exists());
}
