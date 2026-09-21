//! The filtered signing agent (#59) against a real `ssh-agent`.
//!
//! The unit tests in `git::agent_proxy` judge hand-built messages; this one puts a genuine
//! OpenSSH agent behind the proxy, takes the private keys off disk so that nothing but the agent
//! can sign, and drives it with the same `ssh-keygen -Y sign` that `git commit -S` runs.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use sekimore_relay::audit::Audit;
use sekimore_relay::config::{SigningKeyConfig, SigningKeySource};
use sekimore_relay::git::agent_proxy::SigningAgent;

/// Look the name up on PATH rather than run it: `ssh-keygen` has no version flag and exits
/// non-zero for every probe, which would read as "absent" (see `have` in e2e_git.rs).
fn have(bin: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let p = dir.join(bin);
                p.is_file()
                    && std::fs::metadata(&p).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
            })
        })
        .unwrap_or(false)
}

/// The uid this test runs as, read off a directory it just created (chown to any other uid
/// would need root).
fn own_uid(dir: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(dir).unwrap().uid()
}

macro_rules! require_tools {
    () => {
        if !have("ssh-agent") || !have("ssh-keygen") || !have("ssh-add") {
            if std::env::var("SEKIMORE_E2E_REQUIRED").is_ok() {
                panic!("ssh-agent, ssh-add and ssh-keygen are required for the signing-agent test");
            }
            eprintln!("skipping: ssh-agent/ssh-add/ssh-keygen not available");
            return;
        }
    };
}

/// A real ssh-agent, killed when this goes out of scope.
struct HostAgent {
    sock: PathBuf,
    pid: String,
}

impl Drop for HostAgent {
    fn drop(&mut self) {
        let _ = Command::new("ssh-agent")
            .args(["-k"])
            .env("SSH_AGENT_PID", &self.pid)
            .output();
    }
}

fn start_agent(dir: &Path) -> HostAgent {
    let sock = dir.join("host-agent.sock");
    let o = Command::new("ssh-agent")
        .arg("-a")
        .arg(&sock)
        .output()
        .expect("run ssh-agent");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let text = String::from_utf8_lossy(&o.stdout).into_owned();
    let pid = text
        .split("SSH_AGENT_PID=")
        .nth(1)
        .and_then(|s| s.split(';').next())
        .expect("ssh-agent printed no pid")
        .to_string();
    HostAgent { sock, pid }
}

fn keygen(path: &Path, comment: &str) {
    let o = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(path)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

fn fingerprint_of(pubkey: &Path) -> String {
    let o = Command::new("ssh-keygen")
        .arg("-lf")
        .arg(pubkey)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout)
        .split_whitespace()
        .nth(1)
        .expect("ssh-keygen -lf printed no fingerprint")
        .to_string()
}

fn ssh_add(agent: &HostAgent, key: &Path) {
    let o = Command::new("ssh-add")
        .arg(key)
        .env("SSH_AUTH_SOCK", &agent.sock)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

/// Run a tool against the *proxy* socket, with no other agent in the environment.
fn through_proxy(sock: &Path, program: &str, args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("SSH_AUTH_SOCK", sock)
        .output()
        .unwrap_or_else(|e| panic!("run {program}: {e}"))
}

/// One framed agent request, spoken straight at a socket.
///
/// The fingerprint check cannot be reached through `ssh-keygen`: it lists the identities first,
/// does not find the key it was handed and stops before any sign request leaves. A client that
/// does not stop is exactly the case that check exists for, so the test has to be that client.
fn raw_request(sock: &Path, payload: &[u8]) -> Vec<u8> {
    use std::io::{Read, Write};
    let mut s = std::os::unix::net::UnixStream::connect(sock).unwrap();
    let mut out = (payload.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(payload);
    s.write_all(&out).unwrap();
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).unwrap();
    let mut body = vec![0u8; u32::from_be_bytes(hdr) as usize];
    s.read_exact(&mut body).unwrap();
    body
}

/// The key blobs in an `SSH_AGENT_IDENTITIES_ANSWER` (12).
fn identity_blobs(answer: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(answer[0], 12, "not an identities answer: {answer:?}");
    let n = u32::from_be_bytes(answer[1..5].try_into().unwrap()) as usize;
    let take = |at: &mut usize| -> Vec<u8> {
        let len = u32::from_be_bytes(answer[*at..*at + 4].try_into().unwrap()) as usize;
        *at += 4;
        let v = answer[*at..*at + len].to_vec();
        *at += len;
        v
    };
    let mut at = 5;
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(take(&mut at));
        let _comment = take(&mut at);
    }
    out
}

fn sign_request(blob: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = vec![13u8];
    for field in [blob, data] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out.extend_from_slice(&0u32.to_be_bytes()); // flags
    out
}

/// What `ssh-keygen -Y sign` asks an agent to sign: the magic, then the namespace.
fn sshsig_data(namespace: &str) -> Vec<u8> {
    let mut out = b"SSHSIG".to_vec();
    for field in [
        namespace.as_bytes(),
        b"".as_slice(),
        b"sha512".as_slice(),
        &[7u8; 64][..],
    ] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_proxy_signs_for_git_and_for_nothing_else() {
    require_tools!();
    let dir = tempfile::tempdir().unwrap();
    let agent = start_agent(dir.path());

    // Two keys in one agent: the AI signing key the configuration names, and a decoy standing in
    // for the operator's own key. The decoy is the adversarial case — a key that is present and
    // would happily sign, and that this socket must not reach.
    let ai = dir.path().join("ai_ed25519");
    let decoy = dir.path().join("operator_ed25519");
    keygen(&ai, "sekimore AI signing key");
    keygen(&decoy, "the operator's own key");
    ssh_add(&agent, &ai);
    ssh_add(&agent, &decoy);
    let ai_fp = fingerprint_of(&dir.path().join("ai_ed25519.pub"));
    // Off disk: from here on only the agent can sign, so anything that succeeds went through the
    // proxy rather than around it.
    std::fs::remove_file(&ai).unwrap();
    std::fs::remove_file(&decoy).unwrap();

    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(Audit::new(Some(&audit_path), false).unwrap());
    let cfg = SigningKeyConfig {
        source: SigningKeySource::Agent,
        fingerprint: ai_fp.clone(),
        namespace: "git".to_string(),
        timeout: Duration::from_secs(15),
        socket: dir.path().join("signing-agent.sock"),
        // The test runs as whoever it runs as; chown to another uid would need root
        socket_uid: own_uid(dir.path()),
    };
    cfg.validate()
        .expect("the fingerprint ssh-keygen printed must be accepted");
    let proxy = Arc::new(SigningAgent::new(&cfg, agent.sock.clone(), audit));
    let listener = proxy.bind().unwrap();
    let sock = proxy.socket().to_path_buf();
    tokio::spawn(proxy.clone().run(listener));

    // ---- the list shows one key, not two ----
    let o = through_proxy(&sock, "ssh-add", &["-l".as_ref()]);
    let listed = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(listed.lines().count(), 1, "exactly one key: {listed}");
    assert!(listed.contains(&ai_fp), "{listed}");
    assert!(
        !listed.contains(&fingerprint_of(&dir.path().join("operator_ed25519.pub"))),
        "the operator's key must stay invisible: {listed}"
    );

    // ---- a git signature goes through ----
    let msg = dir.path().join("msg");
    std::fs::write(&msg, b"a commit, in spirit\n").unwrap();
    let ai_pub = dir.path().join("ai_ed25519.pub");
    let o = through_proxy(
        &sock,
        "ssh-keygen",
        &[
            "-Y".as_ref(),
            "sign".as_ref(),
            "-n".as_ref(),
            "git".as_ref(),
            "-f".as_ref(),
            ai_pub.as_ref(),
            msg.as_ref(),
        ],
    );
    assert!(
        o.status.success(),
        "signing under namespace git must work:\n{}",
        String::from_utf8_lossy(&o.stderr)
    );
    // and it verifies against the key the agent holds
    let signers = dir.path().join("allowed_signers");
    let publine = std::fs::read_to_string(&ai_pub).unwrap();
    let publine: String = publine
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    std::fs::write(
        &signers,
        format!("e2e@example.invalid namespaces=\"git\" {publine}\n"),
    )
    .unwrap();
    let sig = dir.path().join("msg.sig");
    let o = Command::new("ssh-keygen")
        .args([
            "-Y",
            "verify",
            "-I",
            "e2e@example.invalid",
            "-n",
            "git",
            "-f",
        ])
        .arg(&signers)
        .arg("-s")
        .arg(&sig)
        .stdin(std::fs::File::open(&msg).unwrap())
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));

    // ---- another namespace does not ----
    std::fs::remove_file(&sig).unwrap();
    let o = through_proxy(
        &sock,
        "ssh-keygen",
        &[
            "-Y".as_ref(),
            "sign".as_ref(),
            "-n".as_ref(),
            "file".as_ref(),
            "-f".as_ref(),
            ai_pub.as_ref(),
            msg.as_ref(),
        ],
    );
    assert!(
        !o.status.success(),
        "namespace file must be refused:\n{}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert!(!sig.exists(), "no signature file may be produced");

    // ---- and neither does the operator's key, even under namespace git ----
    let decoy_pub = dir.path().join("operator_ed25519.pub");
    let o = through_proxy(
        &sock,
        "ssh-keygen",
        &[
            "-Y".as_ref(),
            "sign".as_ref(),
            "-n".as_ref(),
            "git".as_ref(),
            "-f".as_ref(),
            decoy_pub.as_ref(),
            msg.as_ref(),
        ],
    );
    assert!(
        !o.status.success(),
        "the operator's key must be refused:\n{}",
        String::from_utf8_lossy(&o.stdout)
    );
    // ssh-keygen gave up on the identity list above without ever sending a sign request, so the
    // fingerprint check itself is still untried. Send one the way a client that did not give up
    // would: the decoy's own blob, under namespace git, with everything else well-formed.
    let ai_blob = identity_blobs(&raw_request(&sock, &[11])).remove(0);
    let decoy_blob = identity_blobs(&raw_request(&agent.sock, &[11]))
        .into_iter()
        .find(|b| *b != ai_blob)
        .expect("the host agent holds the decoy as well");
    assert_eq!(
        raw_request(&sock, &sign_request(&decoy_blob, &sshsig_data("git"))),
        vec![5u8],
        "the operator's key must get SSH_AGENT_FAILURE"
    );
    // The identical request with the configured key is signed, so what the line above refused is
    // the fingerprint and nothing incidental
    assert_eq!(
        raw_request(&sock, &sign_request(&ai_blob, &sshsig_data("git")))[0],
        14,
        "SSH_AGENT_SIGN_RESPONSE"
    );
    // add-identity, remove-all-identities, lock and extension, over the real socket
    for kind in [17u8, 19, 22, 27] {
        assert_eq!(
            raw_request(&sock, &[kind]),
            vec![5u8],
            "request type {kind}"
        );
    }

    // ---- what the audit kept ----
    let audit = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        audit.contains("\"event\":\"signing_agent_signed\""),
        "{audit}"
    );
    assert!(audit.contains("\"namespace\":\"git\""), "{audit}");
    let refusals: Vec<&str> = audit
        .lines()
        .filter(|l| l.contains("signing_agent_refused"))
        .collect();
    assert!(
        refusals
            .iter()
            .any(|l| l.contains("namespace \\\"file\\\"")),
        "the namespace refusal has to say which namespace: {refusals:?}"
    );
    assert!(
        refusals
            .iter()
            .any(|l| l.contains("not the configured signing key")),
        "the wrong-key refusal has to be recorded: {refusals:?}"
    );
}

/// The socket is created where the configuration says, owner-only, and a stale one is replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_socket_is_owner_only_and_replaces_a_stale_one() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("run").join("signing-agent.sock");
    // A file left where the socket goes: a gateway that was killed leaves exactly this behind,
    // and bind() fails on it unless it is removed first.
    std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
    // A directory the operator set up keeps the mode the operator gave it. `socket:` is a path
    // from config.yml, and chmod 0755 on an existing one would take the sticky bit off /tmp.
    std::fs::set_permissions(
        sock.parent().unwrap(),
        std::fs::Permissions::from_mode(0o1777),
    )
    .unwrap();
    std::fs::write(&sock, b"stale").unwrap();
    let cfg = SigningKeyConfig {
        source: SigningKeySource::Agent,
        fingerprint: "SHA256:jKUukqk9WD+ycgT05yemhOEOxL4M5i+0l4Ibm7ZMqnw".to_string(),
        namespace: "git".to_string(),
        timeout: Duration::from_secs(15),
        socket: sock.clone(),
        socket_uid: own_uid(dir.path()),
    };
    let agent = SigningAgent::new(
        &cfg,
        dir.path().join("no-such-agent.sock"),
        Arc::new(Audit::disabled()),
    );
    let _listener = agent.bind().unwrap();
    assert_eq!(
        std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(sock.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o1777,
        "an existing directory keeps the mode it had"
    );
    // With no host agent behind it, a listing is a failure rather than a crash or a hang
    assert!(agent.identity().await.is_none());

    // A directory this creates, on the other hand, is traversable and not writable: dev has to
    // reach the socket and must not be able to unlink it and put its own there.
    let fresh = dir.path().join("fresh").join("signing-agent.sock");
    let cfg = SigningKeyConfig {
        socket: fresh.clone(),
        ..cfg
    };
    let agent = SigningAgent::new(&cfg, dir.path().join("none"), Arc::new(Audit::disabled()));
    let _listener = agent.bind().unwrap();
    assert_eq!(
        std::fs::metadata(fresh.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}
