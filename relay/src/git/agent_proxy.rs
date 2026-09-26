//! A filtered ssh-agent for the dev container (#59): one key, signatures only, one namespace.
//!
//! The signing key is the operator's property. It is registered with the forge once, it outlives
//! every container, and losing it makes every commit it ever signed permanently unverifiable — so
//! it cannot be generated inside dev the way the disposable auth key is. It stays in the host
//! ssh-agent, which is already mounted into the gateway, and dev reaches it through the socket
//! this module serves.
//!
//! What makes that socket safe to hand to an agent is the filter, not the mode bits:
//!
//! | request | answer |
//! |---|---|
//! | `SSH_AGENTC_REQUEST_IDENTITIES` (11) | the one configured fingerprint, nothing else |
//! | `SSH_AGENTC_SIGN_REQUEST` (13) | forwarded **only** when the key blob's fingerprint matches *and* the data is an SSHSIG blob whose namespace is the configured one |
//! | everything else (add / remove / lock / extension …) | `SSH_AGENT_FAILURE` (5) |
//!
//! Row two is the security argument. git's signature covers
//! `"SSHSIG" ++ string namespace ++ string reserved ++ string hashalg ++ string H(message)`
//! (`sshsig.c`, `sshsig_wrap_sign`), while an SSH **authentication** signature covers
//! `string session-id ++ byte 50 ++ string user ++ …` — which starts with a length prefix and can
//! never begin with the ASCII `SSHSIG`. Requiring the magic therefore makes this socket unusable
//! for authentication anywhere, the relay's own sshd included, even when the same key is also
//! registered as an auth key. The operator's other keys sit in the same host agent and stay
//! invisible here, by fingerprint.
//!
//! The protocol is implemented rather than depended on: it is a u32 length, a type byte and a few
//! length-prefixed strings, and `agent_check.rs` already speaks the identities half of it.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::audit::{Actor, Audit};
use crate::config::SigningKeyConfig;
use crate::paths;

// Message numbers from PROTOCOL.agent.
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;

/// The preamble of everything `ssh-keygen -Y sign` asks an agent to sign. Six bytes, not a string:
/// it is `sshbuf_put`, not `sshbuf_put_cstring`, so no length precedes it.
const SSHSIG_MAGIC: &[u8] = b"SSHSIG";

/// A cap on one agent message. A sign request carries a hash, not the file, so real ones are a few
/// hundred bytes; the cap is what stops a client on this socket from making the gateway allocate.
const MAX_MESSAGE: usize = 256 * 1024;

/// What a filter decided about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Answer locally, from the host agent's list narrowed to the configured fingerprint
    Identities,
    /// Forward this sign request upstream unchanged
    Sign { namespace: String },
    /// `SSH_AGENT_FAILURE`, with a reason for the audit
    Refuse(String),
}

/// The whole security boundary: one fingerprint, one namespace.
#[derive(Debug, Clone)]
pub struct Filter {
    pub fingerprint: String,
    pub namespace: String,
}

impl Filter {
    /// Judge one agent message (the payload, i.e. without the u32 length).
    pub fn judge(&self, msg: &[u8]) -> Verdict {
        let Some((&kind, rest)) = msg.split_first() else {
            return Verdict::Refuse("an empty agent message".to_string());
        };
        match kind {
            SSH_AGENTC_REQUEST_IDENTITIES => {
                if rest.is_empty() {
                    Verdict::Identities
                } else {
                    // Nothing follows the type byte in a well-formed request. Bytes that do are
                    // either a different request mislabelled or an attempt to confuse the parse.
                    Verdict::Refuse(format!(
                        "request-identities carried {} unexpected bytes",
                        rest.len()
                    ))
                }
            }
            SSH_AGENTC_SIGN_REQUEST => self.judge_sign(rest),
            other => Verdict::Refuse(format!(
                "request type {other} ({}) is not allowed on this socket; it signs and nothing else",
                request_name(other)
            )),
        }
    }

    fn judge_sign(&self, body: &[u8]) -> Verdict {
        let mut r = Reader::new(body);
        let (Some(blob), Some(data), Some(_flags)) = (r.string(), r.string(), r.u32()) else {
            return Verdict::Refuse("a truncated sign request".to_string());
        };
        if !r.is_empty() {
            // The request is forwarded byte for byte, so anything after the fields this filter
            // read would travel upstream unexamined.
            return Verdict::Refuse(format!(
                "a sign request with {} bytes after its flags",
                r.remaining()
            ));
        }
        let asked = fingerprint(blob);
        if asked != self.fingerprint {
            return Verdict::Refuse(format!(
                "the request names {asked}, not the configured signing key {}",
                self.fingerprint
            ));
        }
        let Some(after_magic) = data.strip_prefix(SSHSIG_MAGIC) else {
            return Verdict::Refuse(
                "the data to sign does not begin with the SSHSIG magic; an SSH authentication signature covers a different structure, and this socket signs neither it nor anything else that is not a git signature"
                    .to_string(),
            );
        };
        let mut d = Reader::new(after_magic);
        let Some(ns) = d.string() else {
            return Verdict::Refuse("an SSHSIG blob without a namespace".to_string());
        };
        if ns != self.namespace.as_bytes() {
            return Verdict::Refuse(format!(
                "namespace {:?} is not {:?}",
                String::from_utf8_lossy(ns),
                self.namespace
            ));
        }
        Verdict::Sign {
            namespace: self.namespace.clone(),
        }
    }
}

/// The names in the refusal, so an audit line says what was attempted rather than a bare number.
fn request_name(kind: u8) -> &'static str {
    match kind {
        17 | 25 => "add-identity",
        18 | 26 => "remove-identity",
        19 => "remove-all-identities",
        20 | 21 => "smartcard",
        22 => "lock",
        23 => "unlock",
        27 => "extension",
        _ => "unknown",
    }
}

/// `SHA256:…`, the way `ssh-keygen -lf` prints it: unpadded base64 of the digest of the key blob.
pub fn fingerprint(blob: &[u8]) -> String {
    use base64::Engine;
    let digest = Sha256::digest(blob);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}

/// `ssh-ed25519 AAAA… comment`, the line git wants in `user.signingkey` and `allowed_signers`.
///
/// The type comes from the blob's own first string rather than from a table, so a key type this
/// relay has never heard of still produces the right line.
pub fn public_key_line(blob: &[u8], comment: &str) -> Option<String> {
    use base64::Engine;
    let keytype = Reader::new(blob).string()?;
    let keytype = std::str::from_utf8(keytype).ok()?;
    if keytype.is_empty() || keytype.bytes().any(|c| !(0x21..=0x7e).contains(&c)) {
        return None;
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(blob);
    let comment = comment.trim();
    Some(if comment.is_empty() {
        format!("{keytype} {b64}")
    } else {
        // A comment is a free-form field an operator typed; a newline in it would turn one line of
        // allowed_signers into two, the second of which is not a signer entry
        let comment = comment.replace(['\n', '\r'], " ");
        format!("{keytype} {b64} {comment}")
    })
}

/// What `/bootstrap` tells the dev container about signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningIdentity {
    pub socket: PathBuf,
    pub fingerprint: String,
    pub namespace: String,
    pub public_key: String,
}

/// The filtered agent: a unix socket, a filter, and the host agent behind it.
pub struct SigningAgent {
    filter: Filter,
    socket: PathBuf,
    socket_uid: u32,
    /// The host agent, i.e. `SSH_AUTH_SOCK` inside the gateway
    upstream: PathBuf,
    timeout: Duration,
    audit: Arc<Audit>,
    /// When the "the host agent does not hold the key" refusal was last audited. `agent-setup.sh`
    /// and `relay:verify` both list identities on every container start, and an agent may list
    /// them whenever it likes, so recording every one of those would bury the audit in a line
    /// that says the same thing each time. The log still gets them all
    last_missing_audit: Mutex<Option<Instant>>,
}

/// How often the missing-key refusal is worth an audit line.
const MISSING_KEY_AUDIT_EVERY: Duration = Duration::from_secs(60);

impl SigningAgent {
    pub fn new(cfg: &SigningKeyConfig, upstream: PathBuf, audit: Arc<Audit>) -> Self {
        SigningAgent {
            filter: Filter {
                fingerprint: cfg.fingerprint.trim().to_string(),
                namespace: cfg.namespace.clone(),
            },
            socket: cfg.socket.clone(),
            socket_uid: cfg.socket_uid,
            upstream,
            timeout: cfg.timeout,
            audit,
            last_missing_audit: Mutex::new(None),
        }
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub fn fingerprint(&self) -> &str {
        &self.filter.fingerprint
    }

    /// Bind the socket, 0600 and owned by `socket_uid`.
    ///
    /// 0600 rather than 0666: the volume this sits on is shared, and only the dev container's user
    /// has any business opening it. It is the second lock — the filter is the first, and the one
    /// that matters, since the dev container has sudo.
    ///
    /// **Nothing here changes a file that a path lookup found.** The directory is on a shared
    /// volume and root in the dev container can write it, so a plain `chmod` by path after `bind`
    /// is a race it can win: unlink the socket, drop a symlink in its place, and the gateway
    /// changes the mode of a file of dev's choosing. So the mode is set through a descriptor
    /// opened `O_NOFOLLOW` and checked to be the socket (`set_socket_mode_0600`), and the owner
    /// through `lchown`, which does not follow a symlink either. `remove_file` unlinks a symlink
    /// rather than its target, and `bind` fails on an existing entry rather than writing through
    /// one.
    pub fn bind(&self) -> io::Result<UnixListener> {
        if let Some(dir) = self.socket.parent() {
            // Only a directory this created gets a mode: `socket:` is an operator-written path,
            // and chmod 0755 on one that already exists would take the sticky bit off /tmp or
            // loosen a mount someone set up deliberately. Traversable and not writable is what a
            // new one wants — dev has to reach the socket and must not be able to unlink it and
            // put its own there.
            if !dir.exists() {
                std::fs::create_dir_all(dir)?;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
            }
        }
        // Anything at the path, a dangling symlink included, has to go: `bind` fails on an
        // existing entry. `symlink_metadata` rather than `exists`, which follows and so reports
        // false for a dangling one; `remove_file` unlinks the symlink itself, never its target.
        if std::fs::symlink_metadata(&self.socket).is_ok() {
            std::fs::remove_file(&self.socket)?;
        }
        let listener = UnixListener::bind(&self.socket)?;
        set_socket_mode_0600(&self.socket)?;
        // Not `chown`: the entry this is about may have been replaced by a symlink, and following
        // it is the whole bug. `lchown` on a symlink changes the symlink, never its target.
        std::os::unix::fs::lchown(&self.socket, Some(self.socket_uid), None)?;
        Ok(listener)
    }

    pub async fn run(self: Arc<Self>, listener: UnixListener) -> io::Result<()> {
        log::info!(
            "signing agent listening on {} (key {}, namespace {}, uid {})",
            self.socket.display(),
            self.filter.fingerprint,
            self.filter.namespace,
            self.socket_uid
        );
        loop {
            let (stream, _) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.handle(stream).await {
                    log::debug!("signing agent connection: {e}");
                }
            });
        }
    }

    /// The configured key as the host agent holds it, or `None` when it does not hold it.
    ///
    /// Asked on every `/bootstrap` rather than cached at start-up: the operator may `ssh-add` the
    /// key after the gateway is already up, and a cache would then keep reporting its absence
    /// until the next restart.
    pub async fn identity(&self) -> Option<SigningIdentity> {
        let (blob, comment) = self.upstream_identity().await.ok()??;
        Some(SigningIdentity {
            socket: self.socket.clone(),
            fingerprint: self.filter.fingerprint.clone(),
            namespace: self.filter.namespace.clone(),
            public_key: public_key_line(&blob, &comment)?,
        })
    }

    async fn handle(&self, mut stream: UnixStream) -> io::Result<()> {
        // One connection carries several requests: ssh-keygen lists the identities and then signs
        // on the same descriptor.
        loop {
            let Some(msg) = read_message(&mut stream).await? else {
                return Ok(());
            };
            let reply = match self.filter.judge(&msg) {
                Verdict::Identities => self.answer_identities().await,
                Verdict::Sign { namespace } => {
                    let reply = self.forward(&msg).await;
                    // Success and refusal are both recorded: the audit is how anyone finds out
                    // afterwards which commits this key was asked to sign.
                    if reply.first() == Some(&SSH_AGENT_FAILURE) {
                        self.audit.deny_edge(
                            paths::DEV_SIGNING,
                            "signing_agent_refused",
                            Actor::Agent,
                            "the host agent refused the signature",
                            &[
                                ("fingerprint", &self.filter.fingerprint),
                                ("namespace", &namespace),
                            ],
                        );
                    } else {
                        self.audit.log_edge(
                            paths::DEV_SIGNING,
                            "signing_agent_signed",
                            Actor::Agent,
                            &[
                                ("fingerprint", &self.filter.fingerprint),
                                ("namespace", &namespace),
                            ],
                        );
                    }
                    reply
                }
                Verdict::Refuse(why) => {
                    self.audit.deny_edge(
                        paths::DEV_SIGNING,
                        "signing_agent_refused",
                        Actor::Agent,
                        &why,
                        &[("fingerprint", &self.filter.fingerprint)],
                    );
                    vec![SSH_AGENT_FAILURE]
                }
            };
            write_message(&mut stream, &reply).await?;
        }
    }

    /// The identities answer dev sees: the configured key if the host agent has it, else none.
    async fn answer_identities(&self) -> Vec<u8> {
        match self.upstream_identity().await {
            Ok(Some((blob, comment))) => {
                let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
                out.extend_from_slice(&1u32.to_be_bytes());
                put_string(&mut out, &blob);
                put_string(&mut out, comment.as_bytes());
                out
            }
            Ok(None) => {
                // An empty list rather than FAILURE: the socket is working, the key simply is not
                // loaded on the host. `ssh-add -l` then says so, and git prints a signing error
                // that names the key instead of "communication with agent failed".
                let why = "the host ssh-agent does not hold the configured signing key (ssh-add it on the host)";
                if self.missing_key_audit_due() {
                    self.audit.deny_edge(
                        paths::DEV_SIGNING,
                        "signing_agent_refused",
                        Actor::Agent,
                        why,
                        &[("fingerprint", &self.filter.fingerprint)],
                    );
                } else {
                    log::debug!("signing agent: {why}");
                }
                let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
                out.extend_from_slice(&0u32.to_be_bytes());
                out
            }
            Err(e) => {
                log::warn!("signing agent: cannot list the host agent's identities: {e}");
                vec![SSH_AGENT_FAILURE]
            }
        }
    }

    /// Whether the missing-key refusal has gone unrecorded for long enough to say again.
    fn missing_key_audit_due(&self) -> bool {
        let mut last = self
            .last_missing_audit
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        match *last {
            Some(t) if now.duration_since(t) < MISSING_KEY_AUDIT_EVERY => false,
            _ => {
                *last = Some(now);
                true
            }
        }
    }

    /// `(key blob, comment)` of the configured fingerprint in the host agent.
    async fn upstream_identity(&self) -> io::Result<Option<(Vec<u8>, String)>> {
        let answer = self.ask_upstream(&[SSH_AGENTC_REQUEST_IDENTITIES]).await?;
        let mut r = Reader::new(&answer);
        if r.u8() != Some(SSH_AGENT_IDENTITIES_ANSWER) {
            return Err(io::Error::other(
                "the host agent did not answer with an identities list",
            ));
        }
        let Some(n) = r.u32() else {
            return Err(io::Error::other("a truncated identities answer"));
        };
        for _ in 0..n {
            let (Some(blob), Some(comment)) = (r.string(), r.string()) else {
                return Err(io::Error::other("a truncated identities answer"));
            };
            if fingerprint(blob) == self.filter.fingerprint {
                return Ok(Some((
                    blob.to_vec(),
                    String::from_utf8_lossy(comment).into_owned(),
                )));
            }
        }
        Ok(None)
    }

    /// Forward a judged request and return whatever the host agent says, or FAILURE.
    async fn forward(&self, msg: &[u8]) -> Vec<u8> {
        match self.ask_upstream(msg).await {
            Ok(reply) => reply,
            Err(e) => {
                log::warn!("signing agent: the host agent did not sign: {e}");
                vec![SSH_AGENT_FAILURE]
            }
        }
    }

    async fn ask_upstream(&self, msg: &[u8]) -> io::Result<Vec<u8>> {
        // A connection per request: the host agent is reached through a bind mount that goes stale
        // whenever the forwarding session is re-established, and a long-lived connection would
        // keep a dead one.
        let fut = async {
            let mut up = UnixStream::connect(&self.upstream).await?;
            write_message(&mut up, msg).await?;
            read_message(&mut up)
                .await?
                .ok_or_else(|| io::Error::other("the host agent closed without answering"))
        };
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(r) => r,
            // Named so that the operator reads "the key is waiting for a touch" rather than
            // "the commit hung".
            Err(_) => Err(io::Error::other(format!(
                "the host agent did not answer within {}; a hardware key may be waiting for a touch",
                humantime::format_duration(self.timeout)
            ))),
        }
    }
}

/// Set the socket to 0600 without letting a path lookup pick the file.
///
/// `umask` would set the mode at creation, but it is process-wide: raising it around `bind` makes
/// every other file and directory the process happens to create in those microseconds come out
/// with no group or other bits, and a directory created without its execute bit is a gateway that
/// does not work. (Which is not hypothetical — it broke a sibling test's temporary directory the
/// first time this was written that way.)
///
/// `fchmod` on the listener would be the obvious answer and silently does nothing on Linux: it
/// returns success and leaves the filesystem entry alone. So: open the entry `O_PATH | O_NOFOLLOW`
/// — which refuses to traverse a symlink and opens nothing — confirm through that descriptor that
/// it really is a socket, and chmod the descriptor by way of `/proc/self/fd`. A symlink dev
/// planted instead gets `EOPNOTSUPP` rather than having its target changed.
#[cfg(target_os = "linux")]
fn set_socket_mode_0600(path: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("the socket path contains a NUL"))?;
    // SAFETY: `c` is a valid NUL-terminated path for the length of the call
    let raw = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh descriptor nothing else owns
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: zeroed `stat` is a valid target, and `fd` is open for the length of the call
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        // Something replaced the socket between `bind` and here. Whatever it is, it is not ours
        // to chmod.
        return Err(io::Error::other(format!(
            "{} is not the socket that was just bound; refusing to change its mode",
            path.display()
        )));
    }
    std::fs::set_permissions(
        format!("/proc/self/fd/{}", fd.as_raw_fd()),
        std::fs::Permissions::from_mode(0o600),
    )
}

/// The same, where `O_PATH` and `/proc/self/fd` do not exist. The relay serves on Linux only;
/// this is compiled into the host tool `sgw` on macOS, which never binds the socket. `lstat`
/// refuses the symlink the Linux version refuses, then `fchmodat` with `AT_SYMLINK_NOFOLLOW`.
#[cfg(not(target_os = "linux"))]
fn set_socket_mode_0600(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path)?;
    if meta.mode() & libc::S_IFMT as u32 != libc::S_IFSOCK as u32 {
        return Err(io::Error::other(format!(
            "{} is not the socket that was just bound; refusing to change its mode",
            path.display()
        )));
    }
    let c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()))
        .map_err(|_| io::Error::other("the socket path contains a NUL"))?;
    // SAFETY: `c` is a valid NUL-terminated path for the length of the call
    let rc =
        unsafe { libc::fchmodat(libc::AT_FDCWD, c.as_ptr(), 0o600, libc::AT_SYMLINK_NOFOLLOW) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---- framing ----

/// One message, or `None` at a clean EOF.
async fn read_message<S: AsyncReadExt + Unpin>(s: &mut S) -> io::Result<Option<Vec<u8>>> {
    let mut hdr = [0u8; 4];
    match s.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(hdr) as usize;
    if len == 0 {
        return Err(io::Error::other("a zero-length agent message"));
    }
    if len > MAX_MESSAGE {
        return Err(io::Error::other(format!(
            "an agent message of {len} bytes, over the {MAX_MESSAGE} byte cap"
        )));
    }
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await?;
    Ok(Some(body))
}

async fn write_message<S: AsyncWriteExt + Unpin>(s: &mut S, msg: &[u8]) -> io::Result<()> {
    let mut out = Vec::with_capacity(msg.len() + 4);
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    s.write_all(&out).await?;
    s.flush().await
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// The wire's `byte` / `uint32` / `string`, none of which may read past the end.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key blob shaped like a real one: `string keytype ++ string body`.
    fn blob(keytype: &str, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(&mut out, keytype.as_bytes());
        put_string(&mut out, body);
        out
    }

    fn sshsig(namespace: &str) -> Vec<u8> {
        let mut out = SSHSIG_MAGIC.to_vec();
        put_string(&mut out, namespace.as_bytes());
        put_string(&mut out, b""); // reserved
        put_string(&mut out, b"sha512");
        put_string(&mut out, &[7u8; 64]); // H(message)
        out
    }

    fn sign_request(key: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        let mut out = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut out, key);
        put_string(&mut out, data);
        out.extend_from_slice(&flags.to_be_bytes());
        out
    }

    fn filter_for(key: &[u8]) -> Filter {
        Filter {
            fingerprint: fingerprint(key),
            namespace: "git".to_string(),
        }
    }

    fn refusal(v: Verdict) -> String {
        match v {
            Verdict::Refuse(why) => why,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_git_signature_with_the_configured_key_is_forwarded() {
        let key = blob("ssh-ed25519", &[1u8; 32]);
        let f = filter_for(&key);
        assert_eq!(
            f.judge(&sign_request(&key, &sshsig("git"), 0)),
            Verdict::Sign {
                namespace: "git".into()
            }
        );
        // The flags travel with the request and change nothing this filter decides
        assert!(matches!(
            f.judge(&sign_request(&key, &sshsig("git"), 4)),
            Verdict::Sign { .. }
        ));
        assert_eq!(
            f.judge(&[SSH_AGENTC_REQUEST_IDENTITIES]),
            Verdict::Identities
        );
    }

    #[test]
    fn the_operators_other_key_in_the_same_agent_is_refused() {
        // The host agent holds the operator's own signing key next to the AI one. Naming it here
        // is the adversarial case the fingerprint check exists for: it is a key that is present,
        // that would sign, and that this socket must not reach.
        let ai = blob("ssh-ed25519", &[1u8; 32]);
        let operators = blob("ssh-ed25519", &[2u8; 32]);
        let why = refusal(filter_for(&ai).judge(&sign_request(&operators, &sshsig("git"), 0)));
        assert!(why.contains(&fingerprint(&operators)), "{why}");
        assert!(why.contains("not the configured signing key"), "{why}");
    }

    #[test]
    fn a_key_whose_blob_differs_only_at_the_end_is_refused() {
        // A fingerprint is a digest of the whole blob; a prefix match would accept this.
        let ai = blob("ssh-ed25519", &[1u8; 32]);
        let mut near = ai.clone();
        *near.last_mut().unwrap() ^= 1;
        assert_ne!(fingerprint(&ai), fingerprint(&near));
        assert!(matches!(
            filter_for(&ai).judge(&sign_request(&near, &sshsig("git"), 0)),
            Verdict::Refuse(_)
        ));
    }

    #[test]
    fn an_authentication_signature_is_refused() {
        // What sshd asks an agent to sign: `string session-id, byte 50 (USERAUTH_REQUEST), …`.
        // It begins with a length, so it can never begin with the ASCII SSHSIG — which is exactly
        // why this socket cannot authenticate anywhere, the relay's own sshd included.
        let key = blob("ssh-ed25519", &[1u8; 32]);
        let mut data = Vec::new();
        put_string(&mut data, &[9u8; 32]); // session id
        data.push(50);
        put_string(&mut data, b"git");
        put_string(&mut data, b"ssh-connection");
        put_string(&mut data, b"publickey");
        let why = refusal(filter_for(&key).judge(&sign_request(&key, &data, 0)));
        assert!(why.contains("SSHSIG magic"), "{why}");
    }

    #[test]
    fn a_namespace_other_than_git_is_refused() {
        let key = blob("ssh-ed25519", &[1u8; 32]);
        let f = filter_for(&key);
        for ns in ["file", "email", "", "git ", "gitx", "GIT"] {
            let why = refusal(f.judge(&sign_request(&key, &sshsig(ns), 0)));
            assert!(why.contains("namespace"), "{ns:?}: {why}");
        }
    }

    #[test]
    fn a_namespace_that_only_starts_with_git_is_refused() {
        // `git` is compared whole, not as a prefix: `ssh-keygen -Y sign -n gitsomething` must not
        // pass for having the right first three bytes.
        let key = blob("ssh-ed25519", &[1u8; 32]);
        let why = refusal(filter_for(&key).judge(&sign_request(&key, &sshsig("github"), 0)));
        assert!(why.contains("\"github\""), "{why}");
    }

    #[test]
    fn the_magic_has_to_be_the_magic_and_nothing_near_it() {
        let key = blob("ssh-ed25519", &[1u8; 32]);
        let f = filter_for(&key);
        // A shorter magic, a longer one, and the magic as a length-prefixed string
        for data in [b"SSHSI".to_vec(), b"sshsig\x00\x00\x00\x03git".to_vec(), {
            let mut v = Vec::new();
            put_string(&mut v, b"SSHSIG");
            v
        }] {
            assert!(
                matches!(f.judge(&sign_request(&key, &data, 0)), Verdict::Refuse(_)),
                "{data:?} must be refused"
            );
        }
        // The magic alone, with no namespace after it
        let why = refusal(f.judge(&sign_request(&key, SSHSIG_MAGIC, 0)));
        assert!(why.contains("without a namespace"), "{why}");
    }

    #[test]
    fn every_other_request_type_is_refused() {
        let f = filter_for(&blob("ssh-ed25519", &[1u8; 32]));
        // add-identity, remove-identity, remove-all, smartcard, lock, unlock,
        // add-identity-constrained, remove-identity (v1), extension
        for kind in [17u8, 18, 19, 20, 21, 22, 23, 25, 26, 27, 0, 1, 255] {
            let why = refusal(f.judge(&[kind]));
            assert!(why.contains(&format!("type {kind}")), "{kind}: {why}");
        }
        assert!(matches!(f.judge(&[]), Verdict::Refuse(_)));
    }

    #[test]
    fn a_request_identities_with_a_body_is_refused() {
        // Otherwise a longer message whose first byte is 11 would be answered as a plain list.
        let f = filter_for(&blob("ssh-ed25519", &[1u8; 32]));
        let mut msg = vec![SSH_AGENTC_REQUEST_IDENTITIES];
        msg.extend_from_slice(b"junk");
        assert!(matches!(f.judge(&msg), Verdict::Refuse(_)));
    }

    #[test]
    fn a_truncated_or_padded_sign_request_is_refused() {
        let key = blob("ssh-ed25519", &[1u8; 32]);
        let f = filter_for(&key);
        let good = sign_request(&key, &sshsig("git"), 0);
        for n in 1..good.len() {
            assert!(
                matches!(f.judge(&good[..n]), Verdict::Refuse(_)),
                "a request cut at {n} must be refused"
            );
        }
        // Bytes after the flags would be forwarded unexamined
        let mut padded = good.clone();
        padded.extend_from_slice(b"smuggled");
        let why = refusal(f.judge(&padded));
        assert!(why.contains("after its flags"), "{why}");
        // A string whose declared length runs past the end
        let mut lying = vec![SSH_AGENTC_SIGN_REQUEST];
        lying.extend_from_slice(&0xffff_ffffu32.to_be_bytes());
        lying.extend_from_slice(&key);
        assert!(matches!(f.judge(&lying), Verdict::Refuse(_)));
    }

    #[test]
    fn the_fingerprint_matches_what_ssh_keygen_prints() {
        // `printf '' | ssh-keygen -lf /dev/stdin` cannot be run here, so pin the definition:
        // unpadded base64 of the sha256 of the blob, which is what OpenSSH's SHA256 form is.
        use base64::Engine;
        let blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20".to_vec();
        let want = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&blob))
        );
        assert_eq!(fingerprint(&blob), want);
        assert!(!want.ends_with('='), "the SHA256 form is unpadded: {want}");
        assert_eq!(want.len(), "SHA256:".len() + 43);
    }

    #[test]
    fn the_mode_is_never_set_through_a_symlink_or_onto_something_that_is_not_the_socket() {
        // The window this closes: between `bind` and the chmod, root in the dev container — which
        // can write the shared volume — unlinks the socket and puts a symlink in its place. A
        // chmod by path would then change the mode of a file of dev's choosing, inside the
        // gateway. Both of these fail against a plain `set_permissions(path, 0600)`.
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("gateway-file");
        std::fs::write(&victim, b"gateway state").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.path().join("swapped.sock");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let e = set_socket_mode_0600(&link).expect_err("a symlink must not be chmodded through");
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o644,
            "the symlink's target was chmodded ({e})"
        );

        // and an ordinary file at the path — the same swap without the indirection — is refused
        // by the check that it is still a socket
        let plain = dir.path().join("plain");
        std::fs::write(&plain, b"x").unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = set_socket_mode_0600(&plain).expect_err("only a socket may be chmodded");
        assert!(e.to_string().contains("not the socket"), "{e}");
        assert_eq!(
            std::fs::metadata(&plain).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn the_missing_key_audit_is_rate_limited() {
        // `agent-setup.sh` and `relay:verify` list identities on every container start, and an
        // agent may list them whenever it likes. One line a minute, not one per listing.
        let cfg = crate::config::SigningKeyConfig {
            source: crate::config::SigningKeySource::Agent,
            fingerprint: "SHA256:jKUukqk9WD+ycgT05yemhOEOxL4M5i+0l4Ibm7ZMqnw".into(),
            namespace: "git".into(),
            timeout: Duration::from_secs(1),
            socket: PathBuf::from("/nonexistent/x.sock"),
            socket_uid: 0,
        };
        let a = SigningAgent::new(
            &cfg,
            PathBuf::from("/nonexistent/up.sock"),
            Arc::new(Audit::disabled()),
        );
        assert!(
            a.missing_key_audit_due(),
            "the first one is always recorded"
        );
        assert!(!a.missing_key_audit_due());
        assert!(!a.missing_key_audit_due());
        // …and it is due again once the interval has passed
        *a.last_missing_audit.lock().unwrap() =
            Some(Instant::now() - MISSING_KEY_AUDIT_EVERY - Duration::from_secs(1));
        assert!(a.missing_key_audit_due());
    }

    #[test]
    fn a_public_key_line_is_rebuilt_from_the_blob() {
        let b = blob("ssh-ed25519", &[3u8; 32]);
        let line = public_key_line(&b, "operator signing key").unwrap();
        let mut parts = line.splitn(3, ' ');
        assert_eq!(parts.next().unwrap(), "ssh-ed25519");
        use base64::Engine;
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(parts.next().unwrap())
                .unwrap(),
            b
        );
        assert_eq!(parts.next().unwrap(), "operator signing key");
        // A comment with a newline would otherwise add a line to allowed_signers
        let line = public_key_line(&b, "one\ntwo").unwrap();
        assert!(!line.contains('\n'), "{line}");
        assert!(public_key_line(b"", "").is_none());
        assert!(public_key_line(&blob("bad type", &[1]), "").is_none());
    }
}
