//! Storage for the upstream (device flow) token.
//!
//! Until 0.2.18 this was a 0600 file on a container volume the dev container does not mount. That
//! stops the agent reading it and nothing else: a copy of the volume, a backup or a VM disk image
//! carries the token in the clear. It lives in the secret store now, sealed with the rest.
//!
//! **Two ways in, because only one process holds the key.** `serve` unlocks the store and keeps it
//! in memory, so it reads the token directly. Every other process — `sekimore-relay login`,
//! `whoami`, `logout`, and in time the Python side — is a separate `docker compose exec` with no
//! passphrase of its own, and reaches the secret by asking the running relay over its control
//! socket. `SecretSource` is those two.
//!
//! In front of either sits an in-memory cache that drops the token after a TTL, in the spirit of
//! ssh-agent's `-t`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;

use crate::fsutil::read_optional;
use crate::store::{self, SecretStore};

/// The namespace every upstream token is filed under. The name is the upstream's host, so
/// `upstream/github.com` and `upstream/ghe.example.com` sit side by side.
pub const NAMESPACE: &str = "upstream";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    pub host: String,
    pub token: String,
    #[serde(default)]
    pub scope: String,
    #[serde(with = "humantime_serde")]
    pub obtained_at: SystemTime,
}

#[derive(Debug)]
pub enum TokenError {
    /// No token available; carries instructions for the operator
    Missing(String),
    /// The store is there and sealed. Separate from `Missing` because the answer is different:
    /// one needs a login, the other needs the passphrase.
    Locked(String),
    Io(std::io::Error),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Missing(m) | TokenError::Locked(m) => write!(f, "{m}"),
            TokenError::Io(e) => write!(f, "upstream token store: {e}"),
        }
    }
}

impl std::error::Error for TokenError {}

/// Where the secret store can be reached from.
#[derive(Clone)]
pub enum SecretSource {
    /// The store this process holds — `serve`, the one that unlocks it.
    InProcess(Arc<AsyncMutex<SecretStore>>),
    /// The running relay's control socket, for a process that has no key of its own.
    ControlSocket(PathBuf),
    /// The store could not be opened at all — a missing directory, a corrupt database. Carried
    /// rather than papered over, so a read says why instead of "no token, run login", which would
    /// send the operator to a command that cannot help.
    Unavailable(String),
}

impl SecretSource {
    async fn get(&self, name: &str) -> Result<Option<String>, TokenError> {
        self.get_in(NAMESPACE, name).await
    }

    /// A secret from any namespace. #151: the upstream proxy's credential lives under `proxy`, and the
    /// relay reads it the same way it reads its upstream token.
    pub async fn get_in(&self, namespace: &str, name: &str) -> Result<Option<String>, TokenError> {
        match self {
            SecretSource::InProcess(store) => {
                let store = store.lock().await;
                match store.get(namespace, name) {
                    Ok(Some(s)) => {
                        String::from_utf8(s.as_bytes().to_vec())
                            .map(Some)
                            .map_err(|_| {
                                TokenError::Io(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("{namespace}/{name} is not UTF-8"),
                                ))
                            })
                    }
                    Ok(None) => Ok(None),
                    Err(store::StoreError::Locked) => Err(locked(name)),
                    Err(e) => Err(TokenError::Io(std::io::Error::other(e.to_string()))),
                }
            }
            SecretSource::ControlSocket(sock) => {
                let body = serde_json::json!({"op": "get", "namespace": namespace, "name": name})
                    .to_string();
                let (ok, message, data, code) = call(sock, &body).await?;
                if ok {
                    match data {
                        Some(serde_json::Value::String(v)) => Ok(Some(v)),
                        _ => Err(TokenError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "the relay answered a get with no value",
                        ))),
                    }
                } else {
                    match code.as_deref() {
                        Some(store::control::CODE_NOT_FOUND) => Ok(None),
                        Some(store::control::CODE_LOCKED) => Err(locked(name)),
                        _ => Err(TokenError::Io(std::io::Error::other(message))),
                    }
                }
            }
            SecretSource::Unavailable(why) => Err(unavailable(why)),
        }
    }

    async fn set(&self, name: &str, value: &str) -> Result<(), TokenError> {
        match self {
            SecretSource::InProcess(store) => {
                let store = store.lock().await;
                match store.set(NAMESPACE, name, value.as_bytes()) {
                    Ok(()) => Ok(()),
                    Err(store::StoreError::Locked) => Err(locked(name)),
                    Err(e) => Err(TokenError::Io(std::io::Error::other(e.to_string()))),
                }
            }
            SecretSource::ControlSocket(sock) => {
                let body = serde_json::json!({
                    "op": "set", "namespace": NAMESPACE, "name": name, "value": value
                })
                .to_string();
                let (ok, message, _, code) = call(sock, &body).await?;
                if ok {
                    Ok(())
                } else if code.as_deref() == Some(store::control::CODE_LOCKED) {
                    Err(locked(name))
                } else {
                    Err(TokenError::Io(std::io::Error::other(message)))
                }
            }
            SecretSource::Unavailable(why) => Err(unavailable(why)),
        }
    }

    async fn delete(&self, name: &str) -> Result<bool, TokenError> {
        match self {
            SecretSource::InProcess(store) => {
                let store = store.lock().await;
                match store.delete(NAMESPACE, name) {
                    Ok(existed) => Ok(existed),
                    Err(store::StoreError::Locked) => Err(locked(name)),
                    Err(e) => Err(TokenError::Io(std::io::Error::other(e.to_string()))),
                }
            }
            SecretSource::ControlSocket(sock) => {
                let body =
                    serde_json::json!({"op": "delete", "namespace": NAMESPACE, "name": name})
                        .to_string();
                let (ok, message, _, code) = call(sock, &body).await?;
                if ok {
                    Ok(true)
                } else {
                    match code.as_deref() {
                        Some(store::control::CODE_NOT_FOUND) => Ok(false),
                        Some(store::control::CODE_LOCKED) => Err(locked(name)),
                        _ => Err(TokenError::Io(std::io::Error::other(message))),
                    }
                }
            }
            SecretSource::Unavailable(why) => Err(unavailable(why)),
        }
    }
}

/// One message on the control socket, mapped so a gateway that is not running reads as that
/// rather than as a missing token.
#[allow(clippy::type_complexity)]
async fn call(
    sock: &Path,
    body: &str,
) -> Result<(bool, String, Option<serde_json::Value>, Option<String>), TokenError> {
    store::control::call_coded(sock, body)
        .await
        .map_err(|e| TokenError::Io(std::io::Error::other(format!("{e:#}"))))
}

fn unavailable(why: &str) -> TokenError {
    // Not `Locked`: a caller routing on that would tell the operator to run sgw unlock, which
    // cannot help with a database that did not open. This is the relay's own fault, not a state
    // the operator can change with a passphrase.
    TokenError::Io(std::io::Error::other(format!(
        "the secret store could not be opened, so no secret can be read ({why})"
    )))
}

fn locked(name: &str) -> TokenError {
    TokenError::Locked(format!(
        "the secret store is locked, so {NAMESPACE}/{name} cannot be read. \
         Ask a human to run: sgw unlock"
    ))
}

pub struct UpstreamTokenStore {
    /// The upstream's host, which is the secret's name inside the store.
    host: String,
    /// Where the token used to live. Kept for the one-time migration and for saying where the
    /// file that is being replaced was.
    legacy_path: PathBuf,
    source: SecretSource,
    cache_ttl: Duration,
    cache: std::sync::Mutex<Option<(String, Instant)>>,
}

impl UpstreamTokenStore {
    pub fn new(host: &str, legacy_path: &Path, source: SecretSource, cache_ttl: Duration) -> Self {
        UpstreamTokenStore {
            host: host.to_string(),
            legacy_path: legacy_path.to_path_buf(),
            source,
            cache_ttl,
            cache: std::sync::Mutex::new(None),
        }
    }

    /// A store backed by an unlocked in-memory database — what a test wants when it needs a token
    /// to be readable and does not care where it is kept. Gated like `SecretStore::open_in_memory`,
    /// for the same reason: nothing in a deployment should be able to make an unlocked store.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn in_memory(host: &str, legacy_path: &Path) -> Self {
        use crate::store::crypto::{Kdf, KdfParams, Secret};
        let mut s = SecretStore::open_in_memory().expect("in-memory store");
        s.initialise(
            &Secret::new(b"test".to_vec()),
            Kdf::Argon2id,
            KdfParams {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
        )
        .expect("initialise");
        UpstreamTokenStore::new(
            host,
            legacy_path,
            SecretSource::InProcess(Arc::new(AsyncMutex::new(s))),
            Duration::from_secs(60),
        )
    }

    /// Whether a `save` could land, without one.
    ///
    /// `login` walks a person through a device flow on github.com before it has anything to
    /// store. Finding out afterwards that the store is sealed throws that away and leaves an
    /// authorisation granted for a token nobody kept.
    pub async fn writable(&self) -> Result<(), TokenError> {
        // A read is enough: both fail on the same missing key, and it writes nothing.
        self.source.get(&self.host).await.map(|_| ())
    }

    pub async fn save(&self, host: &str, token: &str, scope: &str) -> Result<(), TokenError> {
        let st = StoredToken {
            host: host.to_string(),
            token: token.to_string(),
            scope: scope.to_string(),
            obtained_at: SystemTime::now(),
        };
        let json = serde_json::to_string(&st)
            .map_err(|e| TokenError::Io(std::io::Error::other(e.to_string())))?;
        self.source.set(&self.host, &json).await?;
        self.forget();
        Ok(())
    }

    /// The stored token, migrating the plaintext file in if that is where it still is.
    ///
    /// The migration is lazy rather than run at unlock: this is the first moment the store is
    /// known to be open, and doing it here means no hook has to fire at exactly the right time.
    /// It is idempotent — the file is removed once its contents are in the store.
    pub async fn load(&self) -> Result<Option<StoredToken>, TokenError> {
        if let Some(json) = self.source.get(&self.host).await? {
            return parse(&json).map(Some);
        }
        match self.migrate_legacy_file().await? {
            Some(st) => Ok(Some(st)),
            None => Ok(None),
        }
    }

    /// Move a pre-0.2.18 token file into the store and delete it.
    ///
    /// The file is removed only after the store write succeeded, so a failure here leaves the
    /// token where it was rather than nowhere.
    async fn migrate_legacy_file(&self) -> Result<Option<StoredToken>, TokenError> {
        let bytes = match read_optional(&self.legacy_path).map_err(TokenError::Io)? {
            None => return Ok(None),
            Some(b) => b,
        };
        let st: StoredToken = serde_json::from_slice(&bytes).map_err(|e| {
            TokenError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("parse upstream token {}: {e}", self.legacy_path.display()),
            ))
        })?;
        let json = serde_json::to_string(&st)
            .map_err(|e| TokenError::Io(std::io::Error::other(e.to_string())))?;
        self.source.set(&self.host, &json).await?;
        if let Err(e) = std::fs::remove_file(&self.legacy_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                // The token is in the store either way; a file that could not be removed is a
                // plaintext copy left behind, which is exactly the thing being fixed.
                log::error!(
                    "upstream token moved into the secret store, but {} could not be removed \
                     ({e}); it still holds the token in the clear",
                    self.legacy_path.display()
                );
            }
        }
        log::info!(
            "upstream token for {} moved from {} into the secret store",
            self.host,
            self.legacy_path.display()
        );
        Ok(Some(st))
    }

    pub async fn delete(&self) -> Result<bool, TokenError> {
        self.forget();
        let in_store = self.source.delete(&self.host).await?;
        // A logout before the first read has to take the legacy file too, or the next load would
        // migrate it back in.
        let on_disk = match std::fs::remove_file(&self.legacy_path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(TokenError::Io(e)),
        };
        Ok(in_store || on_disk)
    }

    /// Look in the cache, then the store. If neither has a token, return an error with
    /// instructions for the operator.
    pub async fn token(&self) -> Result<String, TokenError> {
        {
            let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((tok, at)) = c.as_ref() {
                if at.elapsed() < self.cache_ttl {
                    return Ok(tok.clone());
                }
                *c = None;
            }
        }
        let st = self.load().await?.ok_or_else(|| {
            TokenError::Missing(format!(
                "no upstream token for {}: run `docker compose exec sekimore-gw sekimore-relay login`",
                self.host
            ))
        })?;
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        *c = Some((st.token.clone(), Instant::now()));
        Ok(st.token)
    }

    /// Drop the in-memory token, leaving the stored one in place.
    ///
    /// Not async: the control socket's `lock` handler calls this, and a `lock` that leaves the
    /// token readable for the rest of the cache TTL — two hours by default — is a lock that does
    /// not lock. Nothing awaits inside the critical section, so a plain mutex is enough.
    pub fn forget(&self) {
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// Where the token used to be kept. Still named in the messages about the move.
    pub fn legacy_path(&self) -> &Path {
        &self.legacy_path
    }
}

fn parse(json: &str) -> Result<StoredToken, TokenError> {
    serde_json::from_str(json).map_err(|e| {
        TokenError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("parse upstream token: {e}"),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::crypto::{Kdf, KdfParams, Secret};

    fn fast() -> KdfParams {
        KdfParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn unlocked() -> Arc<AsyncMutex<SecretStore>> {
        let mut s = SecretStore::open_in_memory().unwrap();
        s.initialise(&Secret::new(b"pw".to_vec()), Kdf::Argon2id, fast())
            .unwrap();
        Arc::new(AsyncMutex::new(s))
    }

    fn store_at(dir: &Path, store: Arc<AsyncMutex<SecretStore>>) -> UpstreamTokenStore {
        UpstreamTokenStore::new(
            "github.com",
            &dir.join("upstream_token"),
            SecretSource::InProcess(store),
            Duration::from_secs(60),
        )
    }

    #[tokio::test]
    async fn save_load_token_delete() {
        let dir = tempfile::tempdir().unwrap();
        let s = store_at(dir.path(), unlocked());
        assert!(matches!(s.token().await, Err(TokenError::Missing(_))));
        s.save("github.com", "gho_x", "repo project").await.unwrap();
        assert_eq!(s.token().await.unwrap(), "gho_x");
        assert_eq!(s.load().await.unwrap().unwrap().scope, "repo project");
        assert!(s.delete().await.unwrap());
        assert!(!s.delete().await.unwrap());
        assert!(
            matches!(s.token().await, Err(TokenError::Missing(m)) if m.contains("sekimore-relay login"))
        );
    }

    #[tokio::test]
    async fn the_token_is_not_in_the_clear_in_the_database() {
        // The whole point of the move. The value is sealed, and only the plaintext metadata —
        // namespace, name, epoch, written-at — is readable from the row.
        let dir = tempfile::tempdir().unwrap();
        let inner = unlocked();
        let s = store_at(dir.path(), inner.clone());
        s.save("github.com", "gho_secret_value", "repo")
            .await
            .unwrap();

        let guard = inner.lock().await;
        let rows = guard.list().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].0.as_str(), rows[0].1.as_str()),
            (NAMESPACE, "github.com")
        );
        let blobs: Vec<Vec<u8>> = guard
            .db_for_test()
            .prepare("SELECT ciphertext FROM records")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for b in blobs {
            assert!(
                !String::from_utf8_lossy(&b).contains("gho_secret_value"),
                "the token is readable in the row"
            );
        }
    }

    #[tokio::test]
    async fn a_locked_store_says_so_rather_than_saying_there_is_no_token() {
        // The two need different answers: one wants the passphrase, the other wants a login.
        let dir = tempfile::tempdir().unwrap();
        let inner = unlocked();
        let s = store_at(dir.path(), inner.clone());
        s.save("github.com", "gho_x", "repo").await.unwrap();
        s.forget();
        inner.lock().await.lock();

        match s.token().await {
            Err(TokenError::Locked(m)) => assert!(m.contains("sgw unlock"), "{m}"),
            other => panic!("expected Locked, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_plaintext_token_file_is_moved_in_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upstream_token");
        let legacy = serde_json::json!({
            "host": "github.com",
            "token": "gho_old",
            "scope": "repo project",
            "obtained_at": "2026-09-01T00:00:00Z",
        });
        crate::fsutil::atomic_write(&path, legacy.to_string().as_bytes(), 0o600).unwrap();

        let inner = unlocked();
        let s = store_at(dir.path(), inner.clone());
        assert_eq!(s.token().await.unwrap(), "gho_old");
        assert!(
            !path.exists(),
            "the plaintext file is removed once it is in the store"
        );

        // and it is really in the store, not just in the cache
        s.forget();
        assert_eq!(s.load().await.unwrap().unwrap().token, "gho_old");
        assert_eq!(inner.lock().await.list().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_plaintext_file_stays_put_when_the_store_will_not_take_it() {
        // A migration that deletes the file and fails to write would lose the token outright.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upstream_token");
        let legacy = serde_json::json!({
            "host": "github.com",
            "token": "gho_old",
            "scope": "repo",
            "obtained_at": "2026-09-01T00:00:00Z",
        });
        crate::fsutil::atomic_write(&path, legacy.to_string().as_bytes(), 0o600).unwrap();

        let inner = unlocked();
        inner.lock().await.lock();
        let s = store_at(dir.path(), inner);
        assert!(matches!(s.token().await, Err(TokenError::Locked(_))));
        assert!(path.exists(), "the only copy must not be deleted");
    }

    #[tokio::test]
    async fn logout_before_the_first_read_does_not_leave_the_file_to_migrate_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upstream_token");
        crate::fsutil::atomic_write(
            &path,
            serde_json::json!({
                "host": "github.com", "token": "gho_old", "scope": "repo",
                "obtained_at": "2026-09-01T00:00:00Z",
            })
            .to_string()
            .as_bytes(),
            0o600,
        )
        .unwrap();

        let s = store_at(dir.path(), unlocked());
        assert!(s.delete().await.unwrap());
        assert!(!path.exists());
        assert!(matches!(s.token().await, Err(TokenError::Missing(_))));
    }

    /// The path `sekimore-relay login` and `whoami` actually take: a separate process with no
    /// passphrase, asking the running relay over its control socket. The in-process tests above
    /// would all pass with the socket half broken.
    mod over_the_control_socket {
        use super::*;

        async fn served(
            unlock: bool,
        ) -> (
            UpstreamTokenStore,
            tempfile::TempDir,
            Arc<AsyncMutex<SecretStore>>,
        ) {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("control.sock");
            let mut inner = SecretStore::open(&dir.path().join("secrets.db")).unwrap();
            inner
                .initialise(&Secret::new(b"pw".to_vec()), Kdf::Argon2id, fast())
                .unwrap();
            if !unlock {
                inner.lock();
            }
            let inner = Arc::new(AsyncMutex::new(inner));
            let served = inner.clone();
            let s = sock.clone();
            tokio::spawn(async move { store::control::serve(s, served, Arc::new(|| {})).await });
            for _ in 0..50 {
                if sock.exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            let store = UpstreamTokenStore::new(
                "github.com",
                &dir.path().join("upstream_token"),
                SecretSource::ControlSocket(sock),
                Duration::from_secs(60),
            );
            (store, dir, inner)
        }

        #[tokio::test]
        async fn a_token_saved_through_the_socket_reads_back_through_it() {
            let (s, _d, _inner) = served(true).await;
            assert!(matches!(s.token().await, Err(TokenError::Missing(_))));
            s.save("github.com", "gho_x", "repo").await.unwrap();
            s.forget();
            assert_eq!(s.token().await.unwrap(), "gho_x");
            assert!(s.delete().await.unwrap());
            assert!(!s.delete().await.unwrap());
        }

        #[tokio::test]
        async fn a_locked_store_is_not_reported_as_a_missing_token() {
            // The two answers send the operator to different commands, and over the socket the
            // difference arrives as a code rather than as wording — which is the point of the
            // code. Matching on the message would have passed here and broken on a reword.
            let (s, _d, _inner) = served(false).await;
            match s.token().await {
                Err(TokenError::Locked(m)) => assert!(m.contains("sgw unlock"), "{m}"),
                other => panic!("expected Locked, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn locking_the_store_drops_what_the_cache_is_holding() {
            // `gw:lock` is reported as done the moment it returns. A cache still holding the
            // decrypted token would keep the API working for the rest of its TTL — two hours by
            // default — which is a lock that has not locked.
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("control.sock");
            let mut inner = SecretStore::open(&dir.path().join("secrets.db")).unwrap();
            inner
                .initialise(&Secret::new(b"pw".to_vec()), Kdf::Argon2id, fast())
                .unwrap();
            let inner = Arc::new(AsyncMutex::new(inner));

            let store = Arc::new(UpstreamTokenStore::new(
                "github.com",
                &dir.path().join("upstream_token"),
                SecretSource::ControlSocket(sock.clone()),
                Duration::from_secs(3600),
            ));
            let caches = vec![store.clone()];
            let on_lock: store::control::OnLock = Arc::new(move || {
                for c in &caches {
                    c.forget();
                }
            });
            let served = inner.clone();
            let s = sock.clone();
            tokio::spawn(async move { store::control::serve(s, served, on_lock).await });
            for _ in 0..50 {
                if sock.exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }

            store.save("github.com", "gho_x", "repo").await.unwrap();
            assert_eq!(store.token().await.unwrap(), "gho_x", "cached now");

            store::control::call(&sock, r#"{"op":"lock"}"#)
                .await
                .unwrap();
            match store.token().await {
                Err(TokenError::Locked(_)) => {}
                other => panic!("the cache survived a lock: {other:?}"),
            }
        }

        #[tokio::test]
        async fn a_gateway_that_is_not_running_says_so() {
            // Not "no token, run login": the relay is down, and login could not work either.
            let dir = tempfile::tempdir().unwrap();
            let s = UpstreamTokenStore::new(
                "github.com",
                &dir.path().join("upstream_token"),
                SecretSource::ControlSocket(dir.path().join("absent.sock")),
                Duration::from_secs(60),
            );
            match s.token().await {
                Err(TokenError::Io(e)) => {
                    let m = e.to_string();
                    assert!(m.contains("control socket"), "{m}");
                }
                other => panic!("expected Io, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn the_plaintext_file_migrates_over_the_socket_too() {
            let (s, dir, inner) = served(true).await;
            let path = dir.path().join("upstream_token");
            crate::fsutil::atomic_write(
                &path,
                serde_json::json!({
                    "host": "github.com", "token": "gho_old", "scope": "repo",
                    "obtained_at": "2026-09-01T00:00:00Z",
                })
                .to_string()
                .as_bytes(),
                0o600,
            )
            .unwrap();
            assert_eq!(s.token().await.unwrap(), "gho_old");
            assert!(!path.exists());
            assert_eq!(inner.lock().await.list().unwrap().len(), 1);
        }
    }
}
