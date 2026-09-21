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

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
}

#[derive(serde::Serialize)]
struct Response {
    ok: bool,
    message: String,
}

/// Serve the control socket until the process ends.
///
/// The socket is replaced on start-up: a stale one from a killed process would otherwise make bind
/// fail and leave the store unreachable for good.
pub async fn serve(path: PathBuf, store: Arc<Mutex<SecretStore>>) -> io::Result<()> {
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
        tokio::spawn(async move {
            if let Err(e) = handle(stream, store).await {
                log::warn!("control connection: {e}");
            }
        });
    }
}

async fn handle(stream: UnixStream, store: Arc<Mutex<SecretStore>>) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let response = match serde_json::from_str::<Request>(&line) {
        Ok(req) => apply(req, &store).await,
        Err(e) => Response {
            ok: false,
            message: format!("bad request: {e}"),
        },
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
        Err(e) => Err(Response {
            ok: false,
            message: e.to_string(),
        }),
    }
}

async fn apply(req: Request, store: &Arc<Mutex<SecretStore>>) -> Response {
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
            Response {
                ok: true,
                message: state.to_string(),
            }
        }
        Request::Unlock { passphrase } => {
            let secret = Secret::new(passphrase.into_bytes());
            match store.unlock(&secret) {
                Ok(()) => {
                    log::info!("secret store unlocked");
                    Response {
                        ok: true,
                        message: "unlocked".into(),
                    }
                }
                // `Locked` here is the AEAD tag failing to open the wrapped DEK, which is what a
                // wrong passphrase looks like. Its own Display is written for a consumer that
                // found the store locked and tells the reader to run `mise run gw:unlock` — the
                // command whose prompt they are standing at. Nothing is disclosed by saying so:
                // they just typed it, and `Tampered` keeps its own message so a spliced store is
                // never reported as a typo.
                Err(StoreError::Locked) => Response {
                    ok: false,
                    message: "that passphrase did not open the store".into(),
                },
                Err(e) => Response {
                    ok: false,
                    message: e.to_string(),
                },
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
                    Response {
                        ok: true,
                        message: "initialised and unlocked".into(),
                    }
                }
                Err(e) => Response {
                    ok: false,
                    message: e.to_string(),
                },
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
                    Response {
                        ok: true,
                        message: format!("passphrase changed, kdf {}", kdf.as_str()),
                    }
                }
                // As in `Unlock`: the old passphrase is what failed to unwrap, and the store is
                // left as it was. Saying "locked, ask a human to unlock" would be doubly wrong,
                // since this works on a store that is already unlocked.
                Err(StoreError::Locked) => Response {
                    ok: false,
                    message: "the old passphrase is not the one the store is wrapped under; \
                              nothing was changed"
                        .into(),
                },
                Err(e) => Response {
                    ok: false,
                    message: e.to_string(),
                },
            }
        }
        Request::Lock => {
            store.lock();
            log::info!("secret store locked");
            Response {
                ok: true,
                message: "locked".into(),
            }
        }
    }
}

/// Send one request and return the reply. Used by the operator subcommands.
pub async fn call(path: &Path, body: &str) -> anyhow::Result<(bool, String)> {
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
    let v: serde_json::Value = serde_json::from_str(&reply)?;
    Ok((
        v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false),
        v.get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string(),
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
             Run this without piping it, through `mise run gw:unlock`"
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
        tokio::spawn(async move { serve(s, store).await });
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
        // mise run gw:unlock", which is what this used to answer — to the person standing at that
        // very prompt, having just mistyped. Three of them in a row is what opened the issue.
        let (sock, _d) = served(true).await;
        let (ok, msg) = call(&sock, r#"{"op":"unlock","passphrase":"wrong"}"#)
            .await
            .unwrap();
        assert!(!ok);
        assert!(
            !msg.contains("gw:unlock"),
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
        tokio::spawn(async move { serve(s, store).await });
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
        assert!(!msg.contains("gw:unlock"), "{msg}");
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
        tokio::spawn(async move { serve(s, store).await });
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
}
