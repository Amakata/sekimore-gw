//! The secret store: a small encrypted key-value store, unlocked by a person.
//!
//! The relay kept one secret — the upstream token — as a 0600 file. #53 wants the proxy credential
//! in the same place and #59 wants the signing key, and neither should invent the format again.
//!
//! What it is for, and what it is not: the dev container never sees this volume, so encryption is
//! not what keeps the agent out. It is what keeps a copied volume, a backup, a VM disk image or an
//! injection through the gateway's own query path from yielding anything. A compromise of the
//! gateway *while unlocked* is not covered — it holds the key because it has to do the work.
//!
//! The database is its own file, not the audit log's. `mise run gw:db-reset` exists to reset that
//! one; secrets sharing it would be destroyed by routine log maintenance.

pub mod control;
pub mod crypto;

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use crypto::{Kdf, KdfParams, Secret};

#[derive(Debug)]
pub enum StoreError {
    /// No passphrase has been supplied yet, or the one supplied did not open the store
    Locked,
    Format(String),
    Crypto(String),
    Db(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Locked => write!(
                f,
                "the secret store is locked. Ask a human to run: mise run gw:unlock"
            ),
            StoreError::Format(m) => write!(f, "secret store format: {m}"),
            StoreError::Crypto(m) => write!(f, "secret store: {m}"),
            StoreError::Db(m) => write!(f, "secret store database: {m}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Db(e.to_string())
    }
}

/// How the key-encryption key is obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KekSource {
    /// A person types it. Nothing at rest opens the store, and the store is self-contained: the
    /// salt and parameters travel with the ciphertext, so moving machines is copying a file
    Passphrase,
    /// The host's own secret store. Unattended restart works; the key is bound to that machine
    Keychain,
    /// A key file on a volume other than the data one. Protects against injection, not against
    /// someone taking both volumes
    File,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    namespace  TEXT NOT NULL,
    name       TEXT NOT NULL,
    alg        TEXT NOT NULL,
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    epoch      INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (namespace, name)
);
";

/// The algorithm identifier written with every record, so a validated backend can replace the
/// implementation without a format change.
const ALG_AES_256_GCM: &str = "aes-256-gcm";

/// An open store. Locked until `unlock` succeeds; every read and write before that fails with
/// `StoreError::Locked`.
pub struct SecretStore {
    db: Connection,
    dek: Option<Secret>,
}

impl SecretStore {
    /// Open or create the store at `path`. A new store is initialised with fresh salt and DEK, both
    /// of which need a passphrase, so creation and the first unlock happen together.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let db = Connection::open(path)?;
        db.execute_batch(SCHEMA)?;
        Ok(SecretStore { db, dek: None })
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let db = Connection::open_in_memory()?;
        db.execute_batch(SCHEMA)?;
        Ok(SecretStore { db, dek: None })
    }

    fn meta(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .db
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get::<_, String>(0)
            })
            .optional()?)
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.db.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn is_initialised(&self) -> Result<bool, StoreError> {
        Ok(self.meta("wrapped_dek")?.is_some())
    }

    pub fn is_unlocked(&self) -> bool {
        self.dek.is_some()
    }

    /// Give the store its passphrase for the first time: fresh salt, fresh DEK, DEK wrapped by the
    /// KEK the passphrase derives. The passphrase itself is never stored, so there is no recovery
    /// — which is the point, and why `export` exists to keep a copy of the sealed store elsewhere.
    pub fn initialise(
        &mut self,
        passphrase: &Secret,
        kdf: Kdf,
        params_: KdfParams,
    ) -> Result<(), StoreError> {
        if self.is_initialised()? {
            return Err(StoreError::Format(
                "the store is already initialised".into(),
            ));
        }
        let salt = crypto::new_salt()?;
        let kek = crypto::derive_kek(kdf, params_, passphrase, &salt)?;
        let dek = crypto::new_dek()?;
        let (nonce, wrapped) = crypto::seal(&kek, WRAP_AAD, dek.as_bytes())?;

        self.set_meta("kdf", kdf.as_str())?;
        self.set_meta("kdf_memory_kib", &params_.memory_kib.to_string())?;
        self.set_meta("kdf_iterations", &params_.iterations.to_string())?;
        self.set_meta("kdf_parallelism", &params_.parallelism.to_string())?;
        self.set_meta("salt", &b64(&salt))?;
        self.set_meta("wrap_nonce", &b64(&nonce))?;
        self.set_meta("wrapped_dek", &b64(&wrapped))?;
        self.set_meta("store_id", &b64(&crypto::new_salt()?))?;
        self.dek = Some(dek);
        Ok(())
    }

    /// Unwrap the DEK with the key the passphrase derives. A wrong passphrase fails the AEAD tag,
    /// which is reported as `Locked` rather than as a distinguishable "wrong passphrase" — there is
    /// nothing useful to tell apart, and less to learn from guessing.
    pub fn unlock(&mut self, passphrase: &Secret) -> Result<(), StoreError> {
        self.dek = Some(self.unwrap_dek(passphrase)?);
        Ok(())
    }

    /// The DEK, given the passphrase the store was wrapped under. Shared by `unlock` and
    /// `change_passphrase`, so the two cannot disagree about what a valid passphrase is.
    fn unwrap_dek(&self, passphrase: &Secret) -> Result<Secret, StoreError> {
        let kdf = Kdf::parse(&self.required("kdf")?)?;
        let params_ = KdfParams {
            memory_kib: self.required_u32("kdf_memory_kib")?,
            iterations: self.required_u32("kdf_iterations")?,
            parallelism: self.required_u32("kdf_parallelism")?,
        };
        let salt = unb64(&self.required("salt")?)?;
        let nonce = unb64(&self.required("wrap_nonce")?)?;
        let wrapped = unb64(&self.required("wrapped_dek")?)?;
        let kek = crypto::derive_kek(kdf, params_, passphrase, &salt)?;
        crypto::open(&kek, WRAP_AAD, &nonce, &wrapped)
    }

    /// Change the passphrase: fresh salt, a key derived from the new one, the same DEK rewrapped.
    ///
    /// **One row changes.** The records are not re-encrypted, which is the reason the DEK exists
    /// rather than deriving a record key from the passphrase directly.
    ///
    /// The old passphrase is required even when the store is already unlocked. The DEK is in
    /// memory at that point, so it is not needed to do the work — but without it, anyone reaching
    /// the control socket of an unlocked store could rewrap it under a passphrase of their own and
    /// lock the owner out. Requiring it also means the change works while locked.
    pub fn change_passphrase(
        &mut self,
        old: &Secret,
        new: &Secret,
        kdf: Kdf,
        params_: KdfParams,
    ) -> Result<(), StoreError> {
        let dek = self.unwrap_dek(old)?;
        let salt = crypto::new_salt()?;
        let kek = crypto::derive_kek(kdf, params_, new, &salt)?;
        let (nonce, wrapped) = crypto::seal(&kek, WRAP_AAD, dek.as_bytes())?;
        self.set_meta("kdf", kdf.as_str())?;
        self.set_meta("kdf_memory_kib", &params_.memory_kib.to_string())?;
        self.set_meta("kdf_iterations", &params_.iterations.to_string())?;
        self.set_meta("kdf_parallelism", &params_.parallelism.to_string())?;
        self.set_meta("salt", &b64(&salt))?;
        self.set_meta("wrap_nonce", &b64(&nonce))?;
        self.set_meta("wrapped_dek", &b64(&wrapped))?;
        self.dek = Some(dek);
        Ok(())
    }

    /// Forget the key. The database stays open; every access fails until the next unlock.
    pub fn lock(&mut self) {
        self.dek = None;
    }

    fn required(&self, key: &str) -> Result<String, StoreError> {
        self.meta(key)?.ok_or_else(|| {
            StoreError::Format(format!("{key} is missing; the store is not initialised"))
        })
    }

    fn required_u32(&self, key: &str) -> Result<u32, StoreError> {
        self.required(key)?
            .parse()
            .map_err(|_| StoreError::Format(format!("{key} is not a number")))
    }

    fn dek(&self) -> Result<&Secret, StoreError> {
        self.dek.as_ref().ok_or(StoreError::Locked)
    }

    pub fn get(&self, namespace: &str, name: &str) -> Result<Option<Secret>, StoreError> {
        let dek = self.dek()?;
        let row = self
            .db
            .query_row(
                "SELECT alg, nonce, ciphertext, epoch FROM records WHERE namespace = ?1 AND name = ?2",
                params![namespace, name],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((alg, nonce, ct, epoch)) = row else {
            return Ok(None);
        };
        if alg != ALG_AES_256_GCM {
            return Err(StoreError::Format(format!("unknown alg {alg:?}")));
        }
        Ok(Some(crypto::open(
            dek,
            &record_aad(namespace, name, epoch),
            &nonce,
            &ct,
        )?))
    }

    pub fn set(&self, namespace: &str, name: &str, value: &[u8]) -> Result<(), StoreError> {
        let dek = self.dek()?;
        let epoch = self.next_epoch(namespace, name)?;
        let (nonce, ct) = crypto::seal(dek, &record_aad(namespace, name, epoch), value)?;
        self.db.execute(
            "INSERT INTO records (namespace, name, alg, nonce, ciphertext, epoch, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(namespace, name) DO UPDATE SET
                alg = excluded.alg, nonce = excluded.nonce, ciphertext = excluded.ciphertext,
                epoch = excluded.epoch, created_at = excluded.created_at",
            params![namespace, name, ALG_AES_256_GCM, nonce, ct, epoch, now()],
        )?;
        Ok(())
    }

    pub fn delete(&self, namespace: &str, name: &str) -> Result<bool, StoreError> {
        self.dek()?;
        let n = self.db.execute(
            "DELETE FROM records WHERE namespace = ?1 AND name = ?2",
            params![namespace, name],
        )?;
        Ok(n > 0)
    }

    /// Namespace, name, epoch and when it was written — the plaintext metadata, so the store can be
    /// operated without unlocking it.
    pub fn list(&self) -> Result<Vec<(String, String, i64, String)>, StoreError> {
        let mut stmt = self.db.prepare(
            "SELECT namespace, name, epoch, created_at FROM records ORDER BY namespace, name",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// One past the record's current epoch, so a rewritten value never reuses its predecessor's
    /// associated data.
    fn next_epoch(&self, namespace: &str, name: &str) -> Result<i64, StoreError> {
        Ok(self
            .db
            .query_row(
                "SELECT epoch FROM records WHERE namespace = ?1 AND name = ?2",
                params![namespace, name],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .map_or(1, |e| e + 1))
    }
}

/// Associated data for the wrapped DEK. Fixed, because there is only ever one.
const WRAP_AAD: &[u8] = b"sekimore-store/dek/v1";

/// Associated data for a record: its identity.
///
/// Without this, breaking the cipher is not needed to do damage — a write could move a ciphertext
/// from one row to another. Copying the staging credential into the production row, or putting a
/// retired key back in the current slot, would decrypt cleanly. Binding the identity makes the same
/// move fail to authenticate.
fn record_aad(namespace: &str, name: &str, epoch: i64) -> Vec<u8> {
    format!("sekimore-store/v1\u{1f}{namespace}\u{1f}{name}\u{1f}{epoch}").into_bytes()
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>, StoreError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| StoreError::Format(format!("not base64: {e}")))
}

fn now() -> String {
    humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string()
}

#[cfg(test)]
mod tests {
    use super::crypto::{Kdf, KdfParams, Secret};
    use super::*;

    /// Argon2id at its real settings costs most of a second per call; tests do not need the cost.
    fn fast() -> KdfParams {
        KdfParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn pass(s: &str) -> Secret {
        Secret::new(s.as_bytes().to_vec())
    }

    fn opened() -> SecretStore {
        let mut s = SecretStore::open_in_memory().unwrap();
        s.initialise(&pass("correct horse"), Kdf::Argon2id, fast())
            .unwrap();
        s
    }

    #[test]
    fn a_value_survives_a_lock_and_an_unlock() {
        let mut s = opened();
        s.set("relay", "upstream_token", b"ghp_secret").unwrap();
        s.lock();
        assert!(!s.is_unlocked());
        s.unlock(&pass("correct horse")).unwrap();
        assert_eq!(
            s.get("relay", "upstream_token")
                .unwrap()
                .unwrap()
                .as_bytes(),
            b"ghp_secret"
        );
    }

    #[test]
    fn a_locked_store_answers_nothing() {
        let mut s = opened();
        s.set("relay", "t", b"v").unwrap();
        s.lock();
        assert!(matches!(s.get("relay", "t"), Err(StoreError::Locked)));
        assert!(matches!(
            s.set("relay", "t", b"v2"),
            Err(StoreError::Locked)
        ));
        assert!(matches!(s.delete("relay", "t"), Err(StoreError::Locked)));
        // The metadata is readable without the key, so the store can be operated while locked
        assert_eq!(s.list().unwrap().len(), 1);
    }

    #[test]
    fn the_wrong_passphrase_does_not_unlock() {
        let mut s = opened();
        s.set("relay", "t", b"v").unwrap();
        s.lock();
        assert!(matches!(s.unlock(&pass("wrong")), Err(StoreError::Locked)));
        assert!(!s.is_unlocked());
    }

    #[test]
    fn what_is_stored_is_not_the_plaintext() {
        // The point of value-level encryption: a query that reaches the row gets ciphertext.
        let s = opened();
        s.set("relay", "t", b"ghp_secret").unwrap();
        let ct: Vec<u8> =
            s.db.query_row("SELECT ciphertext FROM records", [], |r| r.get(0))
                .unwrap();
        assert!(
            !ct.windows(10).any(|w| w == b"ghp_secret"),
            "the plaintext is in the row"
        );
        let wrapped = s.meta("wrapped_dek").unwrap().unwrap();
        assert!(!wrapped.contains("horse"), "the passphrase is in the store");
    }

    #[test]
    fn a_ciphertext_moved_to_another_record_does_not_open() {
        // Breaking the cipher is not needed to do damage: a write could copy one record's
        // ciphertext over another's. The AAD binds each to its own identity.
        let s = opened();
        s.set("relay", "staging", b"harmless").unwrap();
        s.set("relay", "production", b"the real one").unwrap();
        s.db
            .execute(
                "UPDATE records SET nonce = (SELECT nonce FROM records WHERE name = 'staging'),
                                    ciphertext = (SELECT ciphertext FROM records WHERE name = 'staging')
                 WHERE name = 'production'",
                [],
            )
            .unwrap();
        assert!(matches!(
            s.get("relay", "production"),
            Err(StoreError::Locked)
        ));
    }

    #[test]
    fn rewriting_a_value_moves_its_epoch() {
        // So a rewritten record never reuses its predecessor's associated data.
        let s = opened();
        s.set("relay", "t", b"one").unwrap();
        s.set("relay", "t", b"two").unwrap();
        assert_eq!(s.get("relay", "t").unwrap().unwrap().as_bytes(), b"two");
        assert_eq!(s.list().unwrap()[0].2, 2);
    }

    #[test]
    fn an_old_ciphertext_cannot_be_put_back() {
        // The epoch is in the AAD, so restoring a retired value fails to authenticate.
        let s = opened();
        s.set("relay", "t", b"one").unwrap();
        let (nonce, ct): (Vec<u8>, Vec<u8>) =
            s.db.query_row("SELECT nonce, ciphertext FROM records", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        s.set("relay", "t", b"two").unwrap();
        s.db.execute(
            "UPDATE records SET nonce = ?1, ciphertext = ?2 WHERE name = 't'",
            params![nonce, ct],
        )
        .unwrap();
        assert!(matches!(s.get("relay", "t"), Err(StoreError::Locked)));
    }

    #[test]
    fn pbkdf2_is_selectable_for_a_deployment_that_needs_it() {
        let mut s = SecretStore::open_in_memory().unwrap();
        s.initialise(&pass("pw"), Kdf::Pbkdf2Sha256, fast())
            .unwrap();
        s.set("relay", "t", b"v").unwrap();
        s.lock();
        s.unlock(&pass("pw")).unwrap();
        assert_eq!(s.get("relay", "t").unwrap().unwrap().as_bytes(), b"v");
    }

    #[test]
    fn pbkdf2_agrees_with_the_published_vectors() {
        // Known answers, because a PBKDF2 that is subtly wrong still round-trips with itself: the
        // store would lock and unlock happily and agree with nothing else in the world.
        // PBKDF2-HMAC-SHA-256, "password"/"salt".
        for (iterations, expected) in [
            (
                1,
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            ),
            (
                2,
                "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            ),
            // Enough rounds that an off-by-one in the XOR accumulation shows
            (
                4096,
                "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            ),
        ] {
            let mut out = [0u8; 32];
            super::crypto::pbkdf2_for_test(b"password", b"salt", iterations, &mut out);
            assert_eq!(hex::encode(out), expected, "{iterations} iterations");
        }
    }

    #[test]
    fn pbkdf2_spans_more_than_one_block() {
        // 40 bytes needs a second block, which is where the counter would be wrong.
        let mut out = [0u8; 40];
        super::crypto::pbkdf2_for_test(b"passwd", b"salt", 1, &mut out);
        assert_eq!(
            hex::encode(out),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645"
        );
    }

    #[test]
    fn the_passphrase_can_be_changed_without_touching_the_records() {
        let mut s = opened();
        s.set("relay", "t", b"v").unwrap();
        let before: Vec<u8> =
            s.db.query_row("SELECT ciphertext FROM records", [], |r| r.get(0))
                .unwrap();

        s.change_passphrase(
            &pass("correct horse"),
            &pass("new one"),
            Kdf::Argon2id,
            fast(),
        )
        .unwrap();

        let after: Vec<u8> =
            s.db.query_row("SELECT ciphertext FROM records", [], |r| r.get(0))
                .unwrap();
        assert_eq!(
            before, after,
            "the records were re-encrypted; only the DEK should be rewrapped"
        );

        s.lock();
        s.unlock(&pass("new one")).unwrap();
        assert_eq!(s.get("relay", "t").unwrap().unwrap().as_bytes(), b"v");
    }

    #[test]
    fn the_old_passphrase_stops_working() {
        let mut s = opened();
        s.change_passphrase(
            &pass("correct horse"),
            &pass("new one"),
            Kdf::Argon2id,
            fast(),
        )
        .unwrap();
        s.lock();
        assert!(matches!(
            s.unlock(&pass("correct horse")),
            Err(StoreError::Locked)
        ));
    }

    #[test]
    fn a_wrong_old_passphrase_changes_nothing() {
        // Otherwise anyone reaching an unlocked store could rewrap it under a passphrase of their
        // own and lock the owner out.
        let mut s = opened();
        s.set("relay", "t", b"v").unwrap();
        assert!(s
            .change_passphrase(&pass("guess"), &pass("theirs"), Kdf::Argon2id, fast())
            .is_err());
        s.lock();
        s.unlock(&pass("correct horse")).unwrap();
        assert_eq!(s.get("relay", "t").unwrap().unwrap().as_bytes(), b"v");
    }

    #[test]
    fn the_change_works_while_locked() {
        // The old passphrase is what proves the right to change it, so the DEK need not already
        // be in memory.
        let mut s = opened();
        s.set("relay", "t", b"v").unwrap();
        s.lock();
        s.change_passphrase(
            &pass("correct horse"),
            &pass("new one"),
            Kdf::Argon2id,
            fast(),
        )
        .unwrap();
        assert!(s.is_unlocked(), "changing it leaves the store open");
        assert_eq!(s.get("relay", "t").unwrap().unwrap().as_bytes(), b"v");
    }

    #[test]
    fn the_kdf_can_be_switched_in_the_same_write() {
        // How a deployment that needs FIPS migrates an existing store: no record is re-encrypted.
        let mut s = opened();
        s.set("relay", "t", b"v").unwrap();
        s.change_passphrase(
            &pass("correct horse"),
            &pass("fips"),
            Kdf::Pbkdf2Sha256,
            fast(),
        )
        .unwrap();
        assert_eq!(s.meta("kdf").unwrap().unwrap(), "pbkdf2-sha256");
        s.lock();
        s.unlock(&pass("fips")).unwrap();
        assert_eq!(s.get("relay", "t").unwrap().unwrap().as_bytes(), b"v");
    }

    #[test]
    fn initialising_twice_is_refused() {
        let mut s = opened();
        assert!(s.initialise(&pass("other"), Kdf::Argon2id, fast()).is_err());
    }

    #[test]
    fn a_secret_never_prints_its_bytes() {
        let s = Secret::new(b"ghp_secret".to_vec());
        assert_eq!(format!("{s:?}"), "Secret(10 bytes)");
    }
}
