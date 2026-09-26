//! The channel a person unlocks the store through.
//!
//! A unix socket under the relay's state directory, which the dev container does not mount. That
//! placement is the whole design: the agent-facing API on :8420 must never carry a passphrase, and
//! an agent that could ask the relay to unlock itself would make the passphrase pointless.
//!
//! The operator reaches it from the host:
//!
//! ```text
//! docker compose exec sekimore-gw sekimore-relay unlock
//! ```
//!
//! The passphrase is read from the terminal with echo off and sent over the socket. It is never an
//! argument, so it does not reach `ps`, the shell history or the audit.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use zeroize::Zeroize;

use super::crypto::Secret;
use super::{SecretStore, StoreError};

/// One request, one line of JSON. Small enough that a framed protocol would be ceremony.
#[derive(serde::Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Request {
    Status,
    Unlock {
        passphrase: String,
    },
    /// Set the passphrase on a store that does not have one yet. Separate from `Unlock` because
    /// there is nothing to unwrap: 0.2.15 asked for a passphrase on a new store and then tried to
    /// unlock with it, which fails on the missing parameters rather than creating them.
    Init {
        passphrase: String,
        #[serde(default)]
        kdf: Option<String>,
    },
    /// Rewrap the DEK under a new passphrase, optionally under a different KDF. The old one is
    /// required even when the store is unlocked: see `SecretStore::change_passphrase`.
    Passphrase {
        old: String,
        new: String,
        #[serde(default)]
        kdf: Option<String>,
    },
    Lock,
    /// The store as a portable envelope. No passphrase: everything in it is either ciphertext or
    /// the parameters for deriving the key from one, which is what lets a backup be taken from a
    /// locked store.
    Export,
    /// Replace an empty store with an envelope. Refused when the store holds records — an import
    /// is a replacement, and there is no merge that could be right.
    Import {
        envelope: serde_json::Value,
    },
    /// Read one secret. The relay holds the key only while unlocked, and only the process serving
    /// this socket holds it at all — so `sekimore-relay login` and the Python gateway reach a
    /// secret by asking here rather than by opening the database and needing the passphrase of
    /// their own. That is the whole reason these three exist.
    Get {
        namespace: String,
        name: String,
    },
    Set {
        namespace: String,
        name: String,
        value: String,
    },
    Delete {
        namespace: String,
        name: String,
    },
    /// Namespace, name, epoch and when it was written — no values. Readable while locked, which is
    /// what makes it useful for working out whether a secret is there at all.
    List,
}

/// A failure the caller has to act on differently, said in a way that does not involve reading
/// the message. "There is no token" sends the operator to `login`; "the store is sealed" sends
/// them to sgw unlock. Matching on prose to tell those apart breaks the first time the prose is
/// improved.
pub const CODE_NOT_FOUND: &str = "not_found";
pub const CODE_LOCKED: &str = "locked";

#[derive(serde::Serialize)]
struct Response {
    ok: bool,
    message: String,
    /// Structured payload, for the requests that have one to return. `export` puts the envelope
    /// here rather than in `message`, so the caller writes bytes it parsed rather than a string
    /// it has to parse back out of a human-readable field.
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
}

impl Response {
    fn ok(message: impl Into<String>) -> Self {
        Response {
            ok: true,
            message: message.into(),
            data: None,
            code: None,
        }
    }
    fn err(message: impl Into<String>) -> Self {
        Response {
            ok: false,
            message: message.into(),
            data: None,
            code: None,
        }
    }
    fn coded(message: impl Into<String>, code: &'static str) -> Self {
        Response {
            code: Some(code),
            ..Response::err(message)
        }
    }

    /// A store error on a secret operation, with `Locked` singled out — it is the one a caller
    /// routinely has to tell apart, and the one whose own Display is written for a different
    /// reader (see the `Unlock` arm).
    fn from_store_error(e: StoreError) -> Self {
        match e {
            StoreError::Locked => Response::coded(
                "the secret store is locked; ask a human to run: sgw unlock",
                CODE_LOCKED,
            ),
            other => Response::err(other.to_string()),
        }
    }
}

/// Serve the control socket until the process ends.
///
/// The socket is replaced on start-up: a stale one from a killed process would otherwise make bind
/// fail and leave the store unreachable for good.
/// Run when the key is dropped — `lock`, and `import`, which replaces the store and drops it too.
///
/// Whatever caches a decrypted secret has to be told, or a `lock` leaves that secret usable for
/// however long the cache holds it. The upstream token's cache is two hours by default, which is
/// a long time for a lock that has been reported as done.
pub type OnLock = Arc<dyn Fn() + Send + Sync>;

pub async fn serve(
    path: PathBuf,
    store: Arc<Mutex<SecretStore>>,
    on_lock: OnLock,
) -> io::Result<()> {
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    // Owner only. The gateway's own processes are the only ones meant to reach it, and the volume
    // is not mounted into dev, so this is the second lock rather than the first.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    log::info!("control socket listening on {}", path.display());
    loop {
        let (stream, _) = listener.accept().await?;
        let store = store.clone();
        let on_lock = on_lock.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, store, on_lock).await {
                log::warn!("control connection: {e}");
            }
        });
    }
}

/// A request is one line, and `import` is the only one that is not tiny. An envelope holds one
/// base64 blob per record, so this is room for a store far larger than the relay's own handful
/// while still bounding what one connection can make the gateway allocate.
const MAX_REQUEST: u64 = 8 * 1024 * 1024;

async fn handle(
    stream: UnixStream,
    store: Arc<Mutex<SecretStore>>,
    on_lock: OnLock,
) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let read = (&mut reader).take(MAX_REQUEST).read_line(&mut line).await?;
    let response = if read as u64 == MAX_REQUEST {
        Response::err(format!("request is longer than {MAX_REQUEST} bytes"))
    } else {
        match serde_json::from_str::<Request>(&line) {
            Ok(req) => apply(req, &store, &on_lock).await,
            Err(e) => Response::err(format!("bad request: {e}")),
        }
    };
    // Whatever was read holds the passphrase. `clear` only sets the length to zero and leaves the
    // bytes in the allocation, which is what this line used to do. `BufReader`'s own buffer still
    // holds a copy that nothing wipes — reaching it needs a reader of our own, and both are out of
    // host root's way rather than out of its reach.
    line.zeroize();
    let mut out = serde_json::to_vec(&response)?;
    out.push(b'\n');
    reader.into_inner().write_all(&out).await
}

/// The requested KDF, or Argon2id. The error arrives as the response itself, since an unknown
/// name is something the caller asked for rather than a fault.
fn parse_kdf(name: Option<&str>) -> Result<super::crypto::Kdf, Response> {
    match name.map(super::crypto::Kdf::parse).transpose() {
        Ok(k) => Ok(k.unwrap_or(super::crypto::Kdf::Argon2id)),
        Err(e) => Err(Response::err(e.to_string())),
    }
}

async fn apply(req: Request, store: &Arc<Mutex<SecretStore>>, on_lock: &OnLock) -> Response {
    let mut store = store.lock().await;
    match req {
        Request::Status => {
            let state = if store.is_unlocked() {
                "unlocked"
            } else if store.is_initialised().unwrap_or(false) {
                "locked"
            } else {
                "not initialised"
            };
            Response::ok(state.to_string())
        }
        Request::Unlock { passphrase } => {
            let secret = Secret::new(passphrase.into_bytes());
            match store.unlock(&secret) {
                Ok(()) => {
                    log::info!("secret store unlocked");
                    Response::ok("unlocked")
                }
                // `Locked` here is the AEAD tag failing to open the wrapped DEK, which is what a
                // wrong passphrase looks like. Its own Display is written for a consumer that
                // found the store locked and tells the reader to run `sgw unlock` — the
                // command whose prompt they are standing at. Nothing is disclosed by saying so:
                // they just typed it, and `Tampered` keeps its own message so a spliced store is
                // never reported as a typo.
                Err(StoreError::Locked) => Response::err("that passphrase did not open the store"),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Request::Init { passphrase, kdf } => {
            let kdf = match parse_kdf(kdf.as_deref()) {
                Ok(k) => k,
                Err(e) => return e,
            };
            let secret = Secret::new(passphrase.into_bytes());
            match store.initialise(&secret, kdf, super::crypto::KdfParams::default()) {
                Ok(()) => {
                    log::info!("secret store initialised (kdf {})", kdf.as_str());
                    Response::ok("initialised and unlocked")
                }
                Err(e) => Response::err(e.to_string()),
            }
        }
        Request::Passphrase { old, new, kdf } => {
            let kdf = match parse_kdf(kdf.as_deref()) {
                Ok(k) => k,
                Err(e) => return e,
            };
            let old = Secret::new(old.into_bytes());
            let new = Secret::new(new.into_bytes());
            match store.change_passphrase(&old, &new, kdf, super::crypto::KdfParams::default()) {
                Ok(()) => {
                    log::info!("secret store passphrase changed (kdf {})", kdf.as_str());
                    Response::ok(format!("passphrase changed, kdf {}", kdf.as_str()))
                }
                // As in `Unlock`: the old passphrase is what failed to unwrap, and the store is
                // left as it was. Saying "locked, ask a human to unlock" would be doubly wrong,
                // since this works on a store that is already unlocked.
                Err(StoreError::Locked) => Response::err(
                    "the old passphrase is not the one the store is wrapped under; \
                     nothing was changed",
                ),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Request::Lock => {
            store.lock();
            on_lock();
            log::info!("secret store locked");
            Response::ok("locked")
        }
        Request::Export => match store.export() {
            Ok(envelope) => {
                let n = envelope
                    .get("records")
                    .and_then(serde_json::Value::as_array)
                    .map_or(0, Vec::len);
                // Worth an audit line of its own: an export is the whole store leaving, and it
                // needs no passphrase, so nothing else marks that it happened.
                log::info!("secret store exported ({n} records)");
                Response {
                    data: Some(envelope),
                    ..Response::ok(format!("exported {n} records"))
                }
            }
            Err(e) => Response::err(e.to_string()),
        },
        Request::Import { envelope } => match store.import(&envelope) {
            Ok(()) => {
                // `import` drops the DEK as well, so anything holding a decrypted secret from the
                // store that was just replaced is holding one from a store that no longer exists.
                on_lock();
                log::info!("secret store replaced by an import");
                // `import` drops the DEK, so this is the state whatever the store was before.
                Response::ok("imported; the store is locked, unlock it with the passphrase the export was taken under")
            }
            Err(e) => Response::err(e.to_string()),
        },
        // The three below never log a value, and the audit records that a secret was read, not
        // which bytes came back.
        Request::Get { namespace, name } => match store.get(&namespace, &name) {
            Ok(Some(secret)) => match String::from_utf8(secret.as_bytes().to_vec()) {
                Ok(value) => Response {
                    data: Some(serde_json::Value::String(value)),
                    ..Response::ok(format!("{namespace}/{name}"))
                },
                // Everything written through this socket arrives as a JSON string, so a value that
                // is not UTF-8 got there another way. Saying so beats a lossy conversion that
                // hands back a token with a replacement character in it.
                Err(_) => Response::err(format!("{namespace}/{name} is not UTF-8")),
            },
            Ok(None) => Response::coded(format!("no secret {namespace}/{name}"), CODE_NOT_FOUND),
            Err(e) => Response::from_store_error(e),
        },
        Request::Set {
            namespace,
            name,
            value,
        } => {
            let secret = Secret::new(value.into_bytes());
            match store.set(&namespace, &name, secret.as_bytes()) {
                Ok(()) => {
                    log::info!("secret {namespace}/{name} written");
                    Response::ok(format!("wrote {namespace}/{name}"))
                }
                Err(e) => Response::from_store_error(e),
            }
        }
        Request::Delete { namespace, name } => match store.delete(&namespace, &name) {
            Ok(true) => {
                log::info!("secret {namespace}/{name} deleted");
                Response::ok(format!("deleted {namespace}/{name}"))
            }
            Ok(false) => Response::coded(format!("no secret {namespace}/{name}"), CODE_NOT_FOUND),
            Err(e) => Response::from_store_error(e),
        },
        Request::List => match store.list() {
            Ok(rows) => {
                let items: Vec<_> = rows
                    .into_iter()
                    .map(|(namespace, name, epoch, created_at)| {
                        serde_json::json!({
                            "namespace": namespace,
                            "name": name,
                            "epoch": epoch,
                            "created_at": created_at,
                        })
                    })
                    .collect();
                let n = items.len();
                Response {
                    data: Some(serde_json::Value::Array(items)),
                    ..Response::ok(format!("{n} secrets"))
                }
            }
            Err(e) => Response::err(e.to_string()),
        },
    }
}

/// One request, one reply line.
async fn exchange(path: &Path, body: &str) -> anyhow::Result<String> {
    let mut stream = UnixStream::connect(path).await.map_err(|e| {
        anyhow::anyhow!(
            "cannot reach the relay's control socket at {} ({e}). Is the gateway running?",
            path.display()
        )
    })?;
    stream.write_all(body.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.shutdown().await.ok();
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).await?;
    Ok(reply)
}

/// Send one request and return the reply. Used by the operator subcommands.
pub async fn call(path: &Path, body: &str) -> anyhow::Result<(bool, String)> {
    let (ok, message, _) = call_data(path, body).await?;
    Ok((ok, message))
}

/// As `call`, and also the response's `data`. Only `export` returns one.
pub async fn call_data(
    path: &Path,
    body: &str,
) -> anyhow::Result<(bool, String, Option<serde_json::Value>)> {
    let reply = exchange(path, body).await?;
    let (ok, message, data, _) = parse_reply(&reply)?;
    Ok((ok, message, data))
}

/// As `call_data`, and also the failure `code` — `not_found` / `locked` — for a caller that has to
/// act differently on them. Reading the message to tell those apart would break the first time the
/// message is reworded.
pub async fn call_coded(
    path: &Path,
    body: &str,
) -> anyhow::Result<(bool, String, Option<serde_json::Value>, Option<String>)> {
    let reply = exchange(path, body).await?;
    parse_reply(&reply)
}

#[allow(clippy::type_complexity)]
fn parse_reply(
    reply: &str,
) -> anyhow::Result<(bool, String, Option<serde_json::Value>, Option<String>)> {
    let mut v: serde_json::Value = serde_json::from_str(reply)?;
    Ok((
        v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false),
        v.get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string(),
        v.get_mut("data").map(serde_json::Value::take),
        v.get("code").and_then(|c| c.as_str()).map(str::to_string),
    ))
}

/// Read a passphrase from the terminal without echoing it.
///
/// Not an argument and not an environment variable: either would put it in `ps`, and an argument
/// would put it in shell history as well.
pub fn prompt(label: &str) -> anyhow::Result<Secret> {
    use std::io::{BufRead, Write};

    let tty = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;
    if !tty {
        anyhow::bail!(
            "a passphrase has to be typed, and stdin is not a terminal. \
             Run this without piping it, through `sgw unlock`"
        );
    }
    eprint!("{label}: ");
    io::stderr().flush()?;

    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut term) } != 0 {
        anyhow::bail!("cannot read the terminal settings");
    }
    let restore = term;
    term.c_lflag &= !libc::ECHO;
    // TCSAFLUSH, not TCSANOW: it discards what is already in the input queue. Anything typed
    // before the prompt rendered was echoed with ECHO still on, and with TCSANOW it would also be
    // read as the start of the passphrase — so a correctly typed one fails for a reason that is
    // not on the screen. `getpass(3)` flushes for the same reason. What was already echoed cannot
    // be taken back; keeping it out of the passphrase is the part that is fixable.
    unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &term) };

    // Room for a passphrase up front: `read_line` growing from zero would leave the earlier,
    // shorter copies in freed allocations that nothing wipes.
    let mut line = String::with_capacity(256);
    let read = io::stdin().lock().read_line(&mut line);

    unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &restore) };
    eprintln!();
    read?;

    // Into a Secret before anything else, so there is one wiped copy rather than two plain ones.
    // `String::clear` only sets the length, and `trim_end_matches(..).to_string()` would allocate
    // a second buffer that is freed with the passphrase still in it.
    let mut bytes = std::mem::take(&mut line).into_bytes();
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    let secret = Secret::new(bytes);
    if secret.as_bytes().is_empty() {
        anyhow::bail!("an empty passphrase is not accepted");
    }
    Ok(secret)
}

/// The most a passphrase may be when it arrives on stdin. A pipe cannot be seen, so the wrong
/// file redirected into `unlock --stdin` would otherwise be sent to the control socket whole.
const MAX_STDIN_PASSPHRASE: usize = 1024;

/// Whether a descriptor is a terminal. Split out from the refusal below so the decision can be
/// tested against a real pipe and the message against both answers.
fn is_terminal(fd: libc::c_int) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

/// `--stdin` exists for a pipe, so a terminal is refused rather than read.
///
/// This is about the default being echo-off, not about access: `unlock --stdin < /dev/tty` still
/// reaches the reader, and anyone who can run that could have piped the passphrase in anyway.
/// What it does stop is someone reaching for `--stdin` by hand and typing a passphrase that the
/// terminal then echoes onto the screen and into the scrollback.
fn refuse_a_terminal(terminal: bool) -> anyhow::Result<()> {
    if terminal {
        anyhow::bail!(
            "--stdin reads the passphrase from a pipe, and stdin is a terminal. \
             Pipe it in, or run `sgw unlock` to type it with echo off"
        );
    }
    Ok(())
}

/// One line of passphrase from a reader. Exactly one trailing newline is removed and nothing else
/// is trimmed.
///
/// Trimming would be the wrong kind of helpful: a passphrase may begin or end with a space, and a
/// reader that dropped those would unlock the store from a keychain while the same characters
/// typed at the prompt did not. Only the first line is read, so a file with more in it does not
/// turn into a passphrase nobody chose.
pub fn read_passphrase_line(reader: impl io::BufRead) -> anyhow::Result<Secret> {
    use std::io::BufRead as _;

    // Room up front, as in `prompt`: a String growing from zero leaves the shorter copies behind
    // in freed allocations that nothing wipes.
    let mut line = String::with_capacity(256);
    // One byte past the cap, so a passphrase of exactly the cap is accepted and a longer one is
    // reported rather than silently cut in half and sent as a passphrase that will not match.
    let mut capped = reader.take(MAX_STDIN_PASSPHRASE as u64 + 1);
    capped.read_line(&mut line).map_err(|e| {
        anyhow::anyhow!("cannot read the passphrase from stdin ({e}). It has to be valid UTF-8")
    })?;

    // Into a Secret before it is looked at, so there is one wiped copy rather than two plain ones.
    let mut bytes = std::mem::take(&mut line).into_bytes();
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    let secret = Secret::new(bytes);
    if secret.as_bytes().is_empty() {
        anyhow::bail!("empty passphrase on stdin");
    }
    if secret.as_bytes().len() > MAX_STDIN_PASSPHRASE {
        anyhow::bail!(
            "the passphrase on stdin is longer than {MAX_STDIN_PASSPHRASE} bytes. \
             Is that the right file?"
        );
    }
    Ok(secret)
}

/// The passphrase for `unlock --stdin`: one line, from a pipe.
pub fn passphrase_from_stdin() -> anyhow::Result<Secret> {
    refuse_a_terminal(is_terminal(libc::STDIN_FILENO))?;
    read_passphrase_line(io::stdin().lock())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::crypto::{Kdf, KdfParams};

    fn fast() -> KdfParams {
        KdfParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// A store and a socket, as `serve` sets them up.
    async fn served(initialised: bool) -> (PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let mut store = SecretStore::open(&dir.path().join("secrets.db")).unwrap();
        if initialised {
            store
                .initialise(
                    &Secret::new(b"correct horse".to_vec()),
                    Kdf::Argon2id,
                    fast(),
                )
                .unwrap();
            store.set("relay", "t", b"v").unwrap();
            store.lock();
        }
        let store = Arc::new(Mutex::new(store));
        let s = sock.clone();
        tokio::spawn(async move { serve(s, store, Arc::new(|| {})).await });
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        (sock, dir)
    }

    #[tokio::test]
    async fn status_says_locked_before_anything_is_unlocked() {
        let (sock, _d) = served(true).await;
        let (ok, msg) = call(&sock, r#"{"op":"status"}"#).await.unwrap();
        assert!(ok);
        assert_eq!(msg, "locked");
    }

    #[tokio::test]
    async fn status_says_not_initialised_for_a_new_store() {
        let (sock, _d) = served(false).await;
        let (_, msg) = call(&sock, r#"{"op":"status"}"#).await.unwrap();
        assert_eq!(msg, "not initialised");
    }

    #[tokio::test]
    async fn the_right_passphrase_unlocks_and_the_wrong_one_does_not() {
        let (sock, _d) = served(true).await;
        let (ok, msg) = call(&sock, r#"{"op":"unlock","passphrase":"wrong"}"#)
            .await
            .unwrap();
        assert!(!ok, "{msg}");
        let (_, state) = call(&sock, r#"{"op":"status"}"#).await.unwrap();
        assert_eq!(state, "locked");

        let (ok, _) = call(&sock, r#"{"op":"unlock","passphrase":"correct horse"}"#)
            .await
            .unwrap();
        assert!(ok);
        let (_, state) = call(&sock, r#"{"op":"status"}"#).await.unwrap();
        assert_eq!(state, "unlocked");
    }

    #[tokio::test]
    async fn a_wrong_passphrase_does_not_send_the_operator_back_to_the_prompt_they_are_at() {
        // `StoreError::Locked`'s own text reads "the secret store is locked. Ask a human to run:
        // sgw unlock", which is what this used to answer — to the person standing at that
        // very prompt, having just mistyped. Three of them in a row is what opened the issue.
        let (sock, _d) = served(true).await;
        let (ok, msg) = call(&sock, r#"{"op":"unlock","passphrase":"wrong"}"#)
            .await
            .unwrap();
        assert!(!ok);
        assert!(
            !msg.contains("sgw unlock"),
            "must not name the command being run: {msg}"
        );
        assert!(msg.contains("passphrase"), "must say what failed: {msg}");
    }

    #[tokio::test]
    async fn a_tampered_store_is_not_reported_as_a_mistyped_passphrase() {
        // The case just next to the one above: the passphrase is right, and the answer has to stay
        // the one about the record set. Collapsing both into "wrong passphrase" would have an
        // operator retyping while a spliced store goes unmentioned.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let mut store = SecretStore::open(&dir.path().join("secrets.db")).unwrap();
        store
            .initialise(
                &Secret::new(b"correct horse".to_vec()),
                Kdf::Argon2id,
                fast(),
            )
            .unwrap();
        store.set("relay", "t", b"v").unwrap();
        // Straight at the table, so the manifest is not resealed over the smaller set
        store.db.execute("DELETE FROM records", []).unwrap();
        store.lock();

        let store = Arc::new(Mutex::new(store));
        let s = sock.clone();
        tokio::spawn(async move { serve(s, store, Arc::new(|| {})).await });
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let (ok, msg) = call(&sock, r#"{"op":"unlock","passphrase":"correct horse"}"#)
            .await
            .unwrap();
        assert!(!ok);
        assert!(
            msg.contains("sealed with"),
            "the right passphrase on a tampered store still reports tampering: {msg}"
        );
    }

    #[tokio::test]
    async fn a_wrong_old_passphrase_says_nothing_was_changed() {
        // `change_passphrase` works on an unlocked store too, so "the store is locked, ask a human
        // to unlock it" was wrong twice over here.
        let (sock, _d) = served(true).await;
        call(&sock, r#"{"op":"unlock","passphrase":"correct horse"}"#)
            .await
            .unwrap();
        let (ok, msg) = call(
            &sock,
            r#"{"op":"passphrase","old":"wrong","new":"new one"}"#,
        )
        .await
        .unwrap();
        assert!(!ok);
        assert!(!msg.contains("sgw unlock"), "{msg}");
        assert!(msg.contains("old passphrase"), "{msg}");

        // and the store is untouched: the original still opens it
        call(&sock, r#"{"op":"lock"}"#).await.unwrap();
        let (ok, _) = call(&sock, r#"{"op":"unlock","passphrase":"correct horse"}"#)
            .await
            .unwrap();
        assert!(ok, "a refused change must not have rewrapped anything");
    }

    #[tokio::test]
    async fn a_new_store_is_initialised_through_the_socket() {
        // 0.2.15 shipped without this: `unlock` prompted for a new passphrase on a store that had
        // none and then sent `unlock`, which fails on parameters that do not exist yet. The tests
        // reached an uninitialised store only through `status`, so nothing noticed.
        let (sock, _d) = served(false).await;
        let (ok, msg) = call(&sock, r#"{"op":"init","passphrase":"correct horse"}"#)
            .await
            .unwrap();
        assert!(ok, "{msg}");
        let (_, state) = call(&sock, r#"{"op":"status"}"#).await.unwrap();
        assert_eq!(state, "unlocked");
    }

    #[tokio::test]
    async fn a_secret_goes_in_and_comes_back_out() {
        let (sock, _d) = served(true).await;
        call(&sock, r#"{"op":"unlock","passphrase":"correct horse"}"#)
            .await
            .unwrap();

        let (ok, msg) = call(
            &sock,
            r#"{"op":"set","namespace":"upstream","name":"github.com","value":"gho_x"}"#,
        )
        .await
        .unwrap();
        assert!(ok, "{msg}");

        let (ok, _, data) = call_data(
            &sock,
            r#"{"op":"get","namespace":"upstream","name":"github.com"}"#,
        )
        .await
        .unwrap();
        assert!(ok);
        assert_eq!(data.unwrap().as_str().unwrap(), "gho_x");

        let (ok, _) = call(
            &sock,
            r#"{"op":"delete","namespace":"upstream","name":"github.com"}"#,
        )
        .await
        .unwrap();
        assert!(ok);
        let (ok, msg) = call(
            &sock,
            r#"{"op":"get","namespace":"upstream","name":"github.com"}"#,
        )
        .await
        .unwrap();
        assert!(!ok);
        assert!(msg.contains("no secret"), "{msg}");
    }

    #[tokio::test]
    async fn a_locked_store_answers_a_get_with_the_lock_not_with_nothing() {
        // The caller has to be able to tell "nobody logged in" from "nobody unlocked it": one
        // needs a login, the other a passphrase. Answering both as absence sends the operator to
        // the wrong command.
        let (sock, _d) = served(true).await;
        let (ok, msg) = call_data(&sock, r#"{"op":"get","namespace":"relay","name":"t"}"#)
            .await
            .map(|(ok, msg, _)| (ok, msg))
            .unwrap();
        assert!(!ok);
        assert!(
            !msg.contains("no secret"),
            "a locked store must not read as an empty one: {msg}"
        );
    }

    #[tokio::test]
    async fn a_locked_store_refuses_to_be_written_to() {
        let (sock, _d) = served(true).await;
        let (ok, msg) = call(
            &sock,
            r#"{"op":"set","namespace":"upstream","name":"github.com","value":"gho_x"}"#,
        )
        .await
        .unwrap();
        assert!(!ok, "a locked store took a write: {msg}");
    }

    #[tokio::test]
    async fn list_names_the_secrets_without_opening_them() {
        // Readable while locked on purpose: it is how someone works out whether a secret is there
        // at all, and it must never carry a value.
        let (sock, _d) = served(true).await;
        let (ok, msg, data) = call_data(&sock, r#"{"op":"list"}"#).await.unwrap();
        assert!(ok, "{msg}");
        let items = data.unwrap();
        let rows = items.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["namespace"], "relay");
        assert_eq!(rows[0]["name"], "t");
        assert!(
            !items.to_string().contains("\"value\""),
            "list must not carry values: {items}"
        );
    }

    #[tokio::test]
    async fn a_locked_store_can_still_be_exported() {
        // The point of the envelope: a backup needs no key, so it can be taken from a store nobody
        // has unlocked. `served(true)` locks it before serving.
        let (sock, _d) = served(true).await;
        let (ok, msg, data) = call_data(&sock, r#"{"op":"export"}"#).await.unwrap();
        assert!(ok, "{msg}");
        let env = data.expect("an export answers with the envelope");
        assert_eq!(env["records"].as_array().unwrap().len(), 1);
        assert!(env["wrapped_dek"].is_string() && env["salt"].is_string());
        let (_, state) = call(&sock, r#"{"op":"status"}"#).await.unwrap();
        assert_eq!(state, "locked", "exporting does not unlock");
    }

    #[tokio::test]
    async fn an_export_imported_elsewhere_opens_with_the_same_passphrase() {
        let (from, _d1) = served(true).await;
        let (_, _, env) = call_data(&from, r#"{"op":"export"}"#).await.unwrap();

        // An empty store on the other side, as a fresh gateway would have
        let dir = tempfile::tempdir().unwrap();
        let to = dir.path().join("control.sock");
        let store = SecretStore::open(&dir.path().join("secrets.db")).unwrap();
        let store = Arc::new(Mutex::new(store));
        let s = to.clone();
        tokio::spawn(async move { serve(s, store, Arc::new(|| {})).await });
        for _ in 0..50 {
            if to.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let body = serde_json::json!({"op": "import", "envelope": env.unwrap()}).to_string();
        let (ok, msg) = call(&to, &body).await.unwrap();
        assert!(ok, "{msg}");
        let (_, state) = call(&to, r#"{"op":"status"}"#).await.unwrap();
        assert_eq!(state, "locked", "an import leaves the store locked");

        let (ok, msg) = call(&to, r#"{"op":"unlock","passphrase":"correct horse"}"#)
            .await
            .unwrap();
        assert!(
            ok,
            "the passphrase the export was taken under opens it: {msg}"
        );
    }

    #[tokio::test]
    async fn importing_over_a_store_that_holds_records_is_refused() {
        // An import replaces; two stores that both hold `relay/upstream_token` do not hold the
        // same one, so there is no merge that could be right. The destination here is the one
        // `served` set up, which already has a record.
        let (from, _d1) = served(true).await;
        let (_, _, env) = call_data(&from, r#"{"op":"export"}"#).await.unwrap();
        let (to, _d2) = served(true).await;

        let body = serde_json::json!({"op": "import", "envelope": env.unwrap()}).to_string();
        let (ok, msg) = call(&to, &body).await.unwrap();
        assert!(!ok);
        assert!(msg.contains("already holds records"), "{msg}");
    }

    #[tokio::test]
    async fn an_envelope_that_is_not_one_is_refused() {
        let (sock, _d) = served(false).await;
        for bad in [
            r#"{"op":"import","envelope":{}}"#,
            r#"{"op":"import","envelope":{"format":"something-else"}}"#,
        ] {
            let (ok, msg) = call(&sock, bad).await.unwrap();
            assert!(!ok, "{bad} was accepted: {msg}");
        }
    }

    #[tokio::test]
    async fn a_request_longer_than_the_cap_is_answered_not_dropped() {
        // `import` is the first request that is not tiny, so the read is bounded. An over-long one
        // has to come back as a refusal: a dropped connection reads as the gateway being down.
        let (sock, _d) = served(false).await;
        let huge = format!(
            r#"{{"op":"import","envelope":{{"format":"{}"}}}}"#,
            "x".repeat(MAX_REQUEST as usize)
        );
        let (ok, msg) = call(&sock, &huge).await.unwrap();
        assert!(!ok);
        assert!(msg.contains("longer than"), "{msg}");
    }

    #[tokio::test]
    async fn unlocking_a_store_that_has_no_passphrase_yet_says_so() {
        // The 0.2.15 failure, kept as a test: the message named the missing parameter rather than
        // the situation, which is what sent me looking in the wrong place.
        let (sock, _d) = served(false).await;
        let (ok, _) = call(&sock, r#"{"op":"unlock","passphrase":"x"}"#)
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn initialising_an_initialised_store_is_refused() {
        // Otherwise a second init would replace the DEK and strand everything already stored.
        let (sock, _d) = served(true).await;
        let (ok, _) = call(&sock, r#"{"op":"init","passphrase":"another"}"#)
            .await
            .unwrap();
        assert!(!ok);
        let (ok, _) = call(&sock, r#"{"op":"unlock","passphrase":"correct horse"}"#)
            .await
            .unwrap();
        assert!(ok, "the original passphrase still opens it");
    }

    #[tokio::test]
    async fn init_takes_the_kdf_it_is_given() {
        let (sock, _d) = served(false).await;
        let (ok, msg) = call(
            &sock,
            r#"{"op":"init","passphrase":"pw","kdf":"pbkdf2-sha256"}"#,
        )
        .await
        .unwrap();
        assert!(ok, "{msg}");
        let (ok, msg) = call(&sock, r#"{"op":"init","passphrase":"pw","kdf":"rot13"}"#)
            .await
            .unwrap();
        assert!(!ok);
        assert!(msg.contains("rot13"), "{msg}");
    }

    #[tokio::test]
    async fn lock_forgets_the_key_again() {
        let (sock, _d) = served(true).await;
        call(&sock, r#"{"op":"unlock","passphrase":"correct horse"}"#)
            .await
            .unwrap();
        let (ok, _) = call(&sock, r#"{"op":"lock"}"#).await.unwrap();
        assert!(ok);
        let (_, state) = call(&sock, r#"{"op":"status"}"#).await.unwrap();
        assert_eq!(state, "locked");
    }

    #[tokio::test]
    async fn the_socket_is_owner_only() {
        // The volume is not mounted into dev, so this is the second lock rather than the first —
        // but a socket anyone in the container could write to would be a way to hand it a
        // passphrase, or to lock the store at will.
        let (sock, _d) = served(true).await;
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode was {mode:o}");
    }

    #[tokio::test]
    async fn a_stale_socket_does_not_stop_the_next_start() {
        // A killed process leaves the file behind; binding over it would fail and leave the store
        // unreachable with no way back.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        std::fs::write(&sock, b"stale").unwrap();
        let store = Arc::new(Mutex::new(
            SecretStore::open(&dir.path().join("secrets.db")).unwrap(),
        ));
        let s = sock.clone();
        tokio::spawn(async move { serve(s, store, Arc::new(|| {})).await });
        for _ in 0..50 {
            if call(&sock, r#"{"op":"status"}"#).await.is_ok() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the socket never came up over the stale file");
    }

    #[tokio::test]
    async fn a_malformed_request_is_answered_not_dropped() {
        let (sock, _d) = served(true).await;
        let (ok, msg) = call(&sock, "not json").await.unwrap();
        assert!(!ok);
        assert!(msg.contains("bad request"), "{msg}");
    }

    /// `unlock --stdin` reads the passphrase; the operator never sees what it read. What it takes
    /// off the end therefore has to be exactly one thing.
    #[test]
    fn a_piped_passphrase_loses_one_trailing_newline_and_nothing_else() {
        let read = |input: &[u8]| read_passphrase_line(input).map(|s| s.as_bytes().to_vec());
        assert_eq!(read(b"correct horse\n").unwrap(), b"correct horse");
        // `printf '%s'` rather than `printf '%s\n'`: no newline to remove
        assert_eq!(read(b"correct horse").unwrap(), b"correct horse");
        // One line. A keychain entry with a second line in it must not become a passphrase that
        // has the second line in it too.
        assert_eq!(
            read(b"correct horse\nand more\n").unwrap(),
            b"correct horse"
        );
        // Spaces are characters. `trim()` here would unlock from the keychain a store that the
        // same characters typed at the prompt do not open.
        assert_eq!(read(b"  two  words  \n").unwrap(), b"  two  words  ");
        assert_eq!(read(b"\ttabbed\t\n").unwrap(), b"\ttabbed\t");
    }

    #[test]
    fn an_empty_line_is_not_a_passphrase() {
        // A keychain lookup that found nothing pipes in nothing. Sending that as a passphrase
        // would spend an unlock attempt and report "wrong passphrase" for a missing entry.
        for input in [&b""[..], &b"\n"[..]] {
            let err = read_passphrase_line(input).unwrap_err().to_string();
            assert!(err.contains("empty passphrase"), "{err}");
        }
    }

    #[test]
    fn a_file_redirected_in_by_mistake_is_refused_rather_than_sent() {
        let long = vec![b'a'; MAX_STDIN_PASSPHRASE + 1];
        let err = read_passphrase_line(&long[..]).unwrap_err().to_string();
        assert!(err.contains("longer than"), "{err}");
        // and the boundary itself is a passphrase, not an error
        let edge = vec![b'a'; MAX_STDIN_PASSPHRASE];
        assert_eq!(
            read_passphrase_line(&edge[..]).unwrap().as_bytes().len(),
            MAX_STDIN_PASSPHRASE
        );
    }

    #[test]
    fn a_terminal_on_stdin_is_refused_and_a_pipe_is_not() {
        let err = refuse_a_terminal(true).unwrap_err().to_string();
        assert!(err.contains("sgw unlock"), "say what to run instead: {err}");
        assert!(refuse_a_terminal(false).is_ok());
    }

    #[test]
    fn a_pipe_is_not_seen_as_a_terminal() {
        // The other half of the refusal: `refuse_a_terminal` only decides what to do with the
        // answer, and a wrong `isatty` would refuse every piped unlock.
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let piped = is_terminal(fds[0]);
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        assert!(!piped);
    }

    #[tokio::test]
    async fn a_passphrase_read_from_a_pipe_unlocks_a_store_that_was_set_up_by_typing() {
        // The whole point of `--stdin`: `served(true)` initialises the store with the bytes
        // `prompt` would have produced, and the pipe has to arrive at the same ones.
        let (sock, _d) = served(true).await;
        let pass = read_passphrase_line(&b"correct horse\n"[..]).unwrap();
        let body = serde_json::json!({
            "op": "unlock",
            "passphrase": String::from_utf8_lossy(pass.as_bytes()),
        })
        .to_string();
        let (ok, msg) = call(&sock, &body).await.unwrap();
        assert!(ok, "{msg}");
        let (_, state) = call(&sock, r#"{"op":"status"}"#).await.unwrap();
        assert_eq!(state, "unlocked");
    }
}
