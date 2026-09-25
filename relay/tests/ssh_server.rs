//! SSH server behaviour: unregistered keys are denied, non-git exec is denied, shell/pty/env/subsystem/direct-tcpip
//! are denied, policy denials happen before reaching the upstream, and a key appended by bootstrap works without a restart.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use async_trait::async_trait;
use russh::client;
use russh::client::AuthResult;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::ChannelMsg;
use sekimore_relay::audit::Audit;
use sekimore_relay::config::Limits;
use sekimore_relay::git::{GitContext, UpstreamError, UpstreamGit, UpstreamProcess};
use sekimore_relay::policy::{GitAuthorized, Project};
use sekimore_relay::ssh::authorized_keys::AuthorizedKeys;
use sekimore_relay::ssh::{load_or_create_host_key, server_config, SshServer};
use tokio::net::TcpListener;

struct NoCheck;
impl client::Handler for NoCheck {
    type Error = anyhow::Error;
    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A stub upstream that fails if it is ever reached, proving policy denials stop short of the upstream.
struct FailingUpstream {
    reached: Arc<AtomicBool>,
}

#[async_trait]
impl UpstreamGit for FailingUpstream {
    async fn preflight(&self) -> Result<(), UpstreamError> {
        Ok(())
    }
    async fn spawn(&self, _auth: &GitAuthorized<'_>) -> Result<UpstreamProcess, UpstreamError> {
        self.reached.store(true, Ordering::SeqCst);
        Err(UpstreamError {
            kind: "test",
            message: "upstream must not be reached in this test".into(),
        })
    }
    fn describe(&self) -> String {
        "failing".into()
    }
}

fn gen_key() -> PrivateKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    PrivateKey::from(Ed25519Keypair::from_seed(&seed))
}

struct Server {
    addr: SocketAddr,
    keys: Arc<AuthorizedKeys>,
    reached: Arc<AtomicBool>,
    audit_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn start(project: Project) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let host_key = load_or_create_host_key(&dir.path().join("host_key")).unwrap();
    // Loading a second time returns the same key (generate, persist, reload)
    let again = load_or_create_host_key(&dir.path().join("host_key")).unwrap();
    assert_eq!(host_key.public_key(), again.public_key());
    let keys = Arc::new(AuthorizedKeys::new(&dir.path().join("authorized_keys"), 8));
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(Audit::new(Some(&audit_path), false).unwrap());
    let reached = Arc::new(AtomicBool::new(false));
    let ctx = Arc::new(GitContext {
        project,
        host: String::new(),
        upstream: Arc::new(FailingUpstream {
            reached: reached.clone(),
        }),
        github: None,
        audit: audit.clone(),
        limits: Limits::default(),
    });
    let server = SshServer::new(
        server_config(host_key, Duration::from_secs(30)),
        ctx,
        keys.clone(),
        audit,
        4,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server.run(listener));
    Server {
        addr,
        keys,
        reached,
        audit_path,
        _dir: dir,
    }
}

async fn connect(
    addr: SocketAddr,
    key: &PrivateKey,
    user: &str,
) -> anyhow::Result<client::Handle<NoCheck>> {
    let cfg = Arc::new(client::Config::default());
    let mut h = client::connect(cfg, addr, NoCheck).await?;
    let res = h
        .authenticate_publickey(
            user,
            PrivateKeyWithHashAlg::new(Arc::new(key.clone()), None),
        )
        .await?;
    match res {
        AuthResult::Success => Ok(h),
        AuthResult::Failure { .. } => bail!("authentication rejected"),
    }
}

struct ExecResult {
    status: Option<u32>,
    stdout: Vec<u8>,
    stderr: String,
    failure: bool,
}

async fn exec(h: &client::Handle<NoCheck>, cmd: &str) -> ExecResult {
    let mut ch = h.channel_open_session().await.unwrap();
    ch.exec(true, cmd).await.unwrap();
    let mut r = ExecResult {
        status: None,
        stdout: Vec::new(),
        stderr: String::new(),
        failure: false,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let msg = tokio::time::timeout_at(deadline, ch.wait())
            .await
            .expect("exec timed out");
        match msg {
            Some(ChannelMsg::Data { data }) => r.stdout.extend_from_slice(&data),
            Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                r.stderr.push_str(&String::from_utf8_lossy(&data))
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => r.status = Some(exit_status),
            Some(ChannelMsg::Failure) => {
                r.failure = true;
                break;
            }
            Some(ChannelMsg::Close) | None => break,
            _ => {}
        }
    }
    r
}

#[tokio::test]
async fn authorized_key_connects_unknown_key_rejected() {
    let s = start(common::project_case_a(&["pr:create"])).await;
    let good = gen_key();
    let other = gen_key();
    s.keys
        .add(&good.public_key().to_openssh().unwrap())
        .unwrap();

    assert!(
        connect(s.addr, &good, "git").await.is_ok(),
        "registered key must connect"
    );
    assert!(
        connect(s.addr, &other, "git").await.is_err(),
        "unknown key must be rejected"
    );
    assert!(
        connect(s.addr, &good, "root").await.is_err(),
        "only user git is accepted"
    );

    let audit = std::fs::read_to_string(&s.audit_path).unwrap();
    assert!(audit.contains("ssh_auth_ok"));
    assert!(audit.contains("ssh_auth_denied"));
    assert!(audit.contains("\"fingerprint\":\"SHA256:"));
    // #228: the accepted and the refused key are both the agent's edge to the relay
    for event in ["ssh_auth_ok", "ssh_auth_denied"] {
        let line = audit
            .lines()
            .find(|l| l.contains(&format!("\"event\":\"{event}\"")))
            .unwrap();
        assert!(line.contains("\"edge\":\"dev.relay.ssh\""), "{line}");
    }
}

#[tokio::test]
async fn policy_denials_happen_before_upstream() {
    let s = start(common::project_case_a(&["pr:create"])).await;
    let key = gen_key();
    s.keys.add(&key.public_key().to_openssh().unwrap()).unwrap();
    for (cmd, want) in [
        ("rm -rf /", "unsupported command"),
        (
            "git-upload-archive 'LibOrg/awesome-lib.git'",
            "unsupported command",
        ),
        ("git-upload-pack 'Attacker/evil.git'", "not in project"),
        ("git-upload-pack 'LibOrg/other.git'", "not in project"),
        (
            "git-receive-pack 'VendorOrg/reference-impl.git'",
            "read-only",
        ),
    ] {
        // The relay allows one exec per connection (same as git), so connect once per command
        let h = connect(s.addr, &key, "git").await.unwrap();
        let r = exec(&h, cmd).await;
        assert_eq!(r.status, Some(1), "{cmd}");
        assert!(r.stderr.contains(want), "{cmd}: stderr={:?}", r.stderr);
        assert!(
            r.stderr.starts_with("sekimore: "),
            "{cmd}: stderr={:?}",
            r.stderr
        );
    }
    assert!(
        !s.reached.load(Ordering::SeqCst),
        "upstream must not be spawned for denied requests"
    );

    // An allowed repository does reach the upstream (the stub that always fails, in this test)
    let h = connect(s.addr, &key, "git").await.unwrap();
    let r = exec(&h, "git-upload-pack 'LibOrg/awesome-lib.git'").await;
    assert_eq!(r.status, Some(1));
    assert!(r.stderr.contains("upstream must not be reached"));
    assert!(s.reached.load(Ordering::SeqCst));
}

#[tokio::test]
async fn shell_pty_env_subsystem_refused() {
    let s = start(common::project_case_a(&[])).await;
    let key = gen_key();
    s.keys.add(&key.public_key().to_openssh().unwrap()).unwrap();
    let h = connect(s.addr, &key, "git").await.unwrap();

    async fn expect_failure(ch: &mut russh::Channel<client::Msg>, what: &str) {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), ch.wait())
                .await
                .expect(what)
            {
                Some(ChannelMsg::Failure) => return,
                Some(ChannelMsg::Success) => panic!("{what} must be refused"),
                Some(ChannelMsg::Close) | None => panic!("{what}: channel closed without reply"),
                _ => {}
            }
        }
    }
    let mut ch = h.channel_open_session().await.unwrap();
    ch.request_shell(true).await.unwrap();
    expect_failure(&mut ch, "shell").await;
    ch.set_env(true, "GIT_PROTOCOL", "version=2").await.unwrap();
    expect_failure(&mut ch, "env").await;
    ch.request_subsystem(true, "sftp").await.unwrap();
    expect_failure(&mut ch, "subsystem").await;
    ch.request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    expect_failure(&mut ch, "pty").await;
}

#[tokio::test]
async fn direct_tcpip_and_second_exec_refused() {
    let s = start(common::project_case_a(&[])).await;
    let key = gen_key();
    s.keys.add(&key.public_key().to_openssh().unwrap()).unwrap();
    let h = connect(s.addr, &key, "git").await.unwrap();
    assert!(
        h.channel_open_direct_tcpip("localhost", 80, "127.0.0.1", 12345)
            .await
            .is_err(),
        "direct-tcpip must be refused"
    );

    let first = exec(&h, "rm -rf /").await;
    assert_eq!(first.status, Some(1));
    // A second exec is refused at channel open, before there is a channel to exec on.
    assert!(
        h.channel_open_session().await.is_err(),
        "a connection that has already exec'd must not open another session"
    );
    assert!(!s.reached.load(Ordering::SeqCst));
}

/// One exec per connection, so a few open sessions is already more than git needs. Unbounded,
/// an authenticated client can open and abandon channels until the process runs out of memory.
#[tokio::test]
async fn open_session_channels_are_bounded() {
    let s = start(common::project_case_a(&[])).await;
    let key = gen_key();
    s.keys.add(&key.public_key().to_openssh().unwrap()).unwrap();
    let h = connect(s.addr, &key, "git").await.unwrap();

    let mut held = Vec::new();
    let mut refused = false;
    for _ in 0..12 {
        match h.channel_open_session().await {
            Ok(ch) => held.push(ch),
            Err(_) => {
                refused = true;
                break;
            }
        }
    }
    assert!(refused, "opening sessions without limit was allowed");
    assert!(!s.reached.load(Ordering::SeqCst));
}

/// A channel the client opens and closes without exec'ing has to be released, or the same
/// client reaches the limit above by churning rather than holding.
#[tokio::test]
async fn closing_a_session_frees_its_slot() {
    let s = start(common::project_case_a(&[])).await;
    let key = gen_key();
    s.keys.add(&key.public_key().to_openssh().unwrap()).unwrap();
    let h = connect(s.addr, &key, "git").await.unwrap();

    for i in 0..20 {
        let ch = h
            .channel_open_session()
            .await
            .unwrap_or_else(|e| panic!("open {i} refused after closing the previous ones: {e}"));
        ch.close().await.unwrap();
        // The server removes it on close; give that message a moment to land.
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn bootstrap_appended_key_authenticates_without_restart() {
    let s = start(common::project_case_a(&[])).await;
    let key = gen_key();
    assert!(
        connect(s.addr, &key, "git").await.is_err(),
        "empty authorized_keys rejects everyone"
    );
    // Simulates a key appended by /bootstrap or add-key
    s.keys.add(&key.public_key().to_openssh().unwrap()).unwrap();
    assert!(
        connect(s.addr, &key, "git").await.is_ok(),
        "newly added key must work without restarting the server"
    );
}
