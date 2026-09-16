//! Project token store.
//!
//! Tokens are opaque: the agent receives meaningless random bytes, while the project and expiry live in the relay's store.
//!   - Revocation is immediate (essential for a credential handed to an autonomous agent)
//!   - Policy changes apply to already-issued tokens right away
//!   - The token itself carries no information
//!
//! The store holds **SHA-256 hashes only**. The plaintext exists only in the value returned at issue time.
//! The label is the first 8 hex characters of the hash (it reveals no part of the plaintext).
//! Updates follow flock → read → modify → atomic rename, so `serve` and the operator CLI can run concurrently.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fsutil::{atomic_write, read_optional, FlockGuard};

pub const TOKEN_PREFIX: &str = "skm_";
/// How long expired records are kept (so `tokens` still shows recent revocations). Past this, they are dropped on save.
/// audit.jsonl holds the permanent record, so keeping them in the store only helps the listing.
pub const RETENTION_AFTER_EXPIRY: Duration = Duration::from_secs(7 * 24 * 3600);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenRecord {
    /// Short display identifier (first 8 hex of the hash), used in logs and listings
    pub label: String,
    pub project: String,
    #[serde(with = "humantime_serde")]
    pub issued_at: SystemTime,
    #[serde(with = "humantime_serde")]
    pub expires_at: SystemTime,
    #[serde(default, with = "humantime_serde")]
    pub last_used: Option<SystemTime>,
    #[serde(default)]
    pub use_count: u64,
    #[serde(default)]
    pub revoked: bool,
    /// Fingerprint of the agent key this token was issued for (bootstrap only; a manual `token` leaves it None)
    #[serde(default)]
    pub fingerprint: Option<String>,
}

impl TokenRecord {
    pub fn state(&self, now: SystemTime) -> &'static str {
        if self.revoked {
            "revoked"
        } else if now > self.expires_at {
            "expired"
        } else {
            "active"
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    #[serde(default)]
    records: BTreeMap<String, TokenRecord>,
}

#[derive(Debug)]
pub enum VerifyError {
    Unknown,
    Revoked,
    Expired(SystemTime),
    Io(std::io::Error),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Unknown => write!(f, "unknown token"),
            VerifyError::Revoked => write!(f, "token revoked"),
            VerifyError::Expired(t) => write!(
                f,
                "token expired at {}",
                humantime::format_rfc3339_seconds(*t)
            ),
            VerifyError::Io(e) => write!(f, "token store error: {e}"),
        }
    }
}

impl std::error::Error for VerifyError {}

pub struct TokenStore {
    path: PathBuf,
}

/// Drops records whose expiry is more than RETENTION_AFTER_EXPIRY ago (same rule for revoked ones). Called on write.
fn prune(f: &mut StoreFile, now: SystemTime) {
    f.records
        .retain(|_, rec| now <= rec.expires_at + RETENTION_AFTER_EXPIRY);
}

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

impl TokenStore {
    pub fn new(path: &Path) -> Self {
        TokenStore {
            path: path.to_path_buf(),
        }
    }

    fn load(&self) -> std::io::Result<StoreFile> {
        match read_optional(&self.path)? {
            None => Ok(StoreFile::default()),
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("parse token store: {e}"),
                )
            }),
        }
    }

    fn save(&self, f: &StoreFile) -> std::io::Result<()> {
        let data = serde_json::to_vec_pretty(f)?;
        atomic_write(&self.path, &data, 0o600)
    }

    /// Issues a token. The plaintext is only returned, never stored.
    pub fn issue(&self, project: &str, ttl: Duration) -> std::io::Result<(String, TokenRecord)> {
        self.issue_for(project, ttl, None)
    }

    /// Issues a token for bootstrap, recording which agent key received it.
    pub fn issue_for(
        &self,
        project: &str,
        ttl: Duration,
        fingerprint: Option<&str>,
    ) -> std::io::Result<(String, TokenRecord)> {
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf).map_err(|e| std::io::Error::other(format!("getrandom: {e}")))?;
        let token = format!("{TOKEN_PREFIX}{}", hex::encode(buf));
        let hash = hash_token(&token);
        let now = SystemTime::now();
        let rec = TokenRecord {
            label: format!("{TOKEN_PREFIX}{}", &hash[..8]),
            project: project.to_string(),
            issued_at: now,
            expires_at: now + ttl,
            last_used: None,
            use_count: 0,
            revoked: false,
            fingerprint: fingerprint.map(str::to_string),
        };
        let _g = FlockGuard::lock(&self.path)?;
        let mut f = self.load()?;
        prune(&mut f, now);
        f.records.insert(hash, rec.clone());
        self.save(&f)?;
        Ok((token, rec))
    }

    /// Revokes every valid token issued to the same agent key (rotation on re-bootstrap). Returns the count.
    pub fn revoke_by_fingerprint(&self, fingerprint: &str) -> std::io::Result<usize> {
        let _g = FlockGuard::lock(&self.path)?;
        let mut f = self.load()?;
        let now = SystemTime::now();
        let mut n = 0;
        for rec in f.records.values_mut() {
            if rec.fingerprint.as_deref() == Some(fingerprint)
                && !rec.revoked
                && now <= rec.expires_at
            {
                rec.revoked = true;
                n += 1;
            }
        }
        if n > 0 {
            self.save(&f)?;
        }
        Ok(n)
    }

    /// Verifies a token and records its use (for audit purposes; the result is returned even if the save fails).
    pub fn verify(&self, token: &str) -> Result<TokenRecord, VerifyError> {
        let hash = hash_token(token);
        let _g = FlockGuard::lock(&self.path).map_err(VerifyError::Io)?;
        let mut f = self.load().map_err(VerifyError::Io)?;
        let rec = f.records.get_mut(&hash).ok_or(VerifyError::Unknown)?;
        if rec.revoked {
            return Err(VerifyError::Revoked);
        }
        let now = SystemTime::now();
        if now > rec.expires_at {
            return Err(VerifyError::Expired(rec.expires_at));
        }
        rec.last_used = Some(now);
        rec.use_count += 1;
        let out = rec.clone();
        let _ = self.save(&f);
        Ok(out)
    }

    /// Revokes by label. Returns true if a matching token was found.
    pub fn revoke(&self, label: &str) -> std::io::Result<bool> {
        let _g = FlockGuard::lock(&self.path)?;
        let mut f = self.load()?;
        let mut found = false;
        for rec in f.records.values_mut() {
            if rec.label == label {
                rec.revoked = true;
                found = true;
            }
        }
        if found {
            prune(&mut f, SystemTime::now());
            self.save(&f)?;
        }
        Ok(found)
    }

    /// Revokes every token of a project (when the project ends). Returns the number revoked.
    pub fn revoke_project(&self, project: &str) -> std::io::Result<usize> {
        let _g = FlockGuard::lock(&self.path)?;
        let mut f = self.load()?;
        let mut n = 0;
        for rec in f.records.values_mut() {
            if rec.project == project && !rec.revoked {
                rec.revoked = true;
                n += 1;
            }
        }
        if n > 0 {
            prune(&mut f, SystemTime::now());
            self.save(&f)?;
        }
        Ok(n)
    }

    /// Lists issued tokens (never the plaintext), ordered by issue time.
    pub fn list(&self) -> std::io::Result<Vec<TokenRecord>> {
        let _g = FlockGuard::lock(&self.path)?;
        let f = self.load()?;
        let mut v: Vec<TokenRecord> = f.records.into_values().collect();
        v.sort_by_key(|r| r.issued_at);
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, TokenStore) {
        let dir = tempfile::tempdir().unwrap();
        let s = TokenStore::new(&dir.path().join("tokens.json"));
        (dir, s)
    }

    #[test]
    fn issue_and_verify_hash_only() {
        let (dir, s) = store();
        let (plain, rec) = s.issue("case-a", Duration::from_secs(3600)).unwrap();
        assert!(plain.starts_with(TOKEN_PREFIX));
        assert_eq!(plain.len(), TOKEN_PREFIX.len() + 64);
        assert_eq!(rec.project, "case-a");
        assert!(rec.label.starts_with(TOKEN_PREFIX) && rec.label.len() == TOKEN_PREFIX.len() + 8);
        // The label is not a substring of the plaintext
        assert!(!plain.starts_with(&rec.label));

        // The plaintext is never persisted to the store
        let text = std::fs::read_to_string(dir.path().join("tokens.json")).unwrap();
        assert!(!text.contains(&plain));
        assert!(text.contains(&hash_token(&plain)));

        let got = s.verify(&plain).unwrap();
        assert_eq!(got.use_count, 1);
        assert!(got.last_used.is_some());
        assert!(matches!(
            s.verify("skm_deadbeef"),
            Err(VerifyError::Unknown)
        ));

        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(dir.path().join("tokens.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn revoke_is_immediate() {
        let (_d, s) = store();
        let (plain, rec) = s.issue("case-a", Duration::from_secs(3600)).unwrap();
        assert!(s.verify(&plain).is_ok());
        assert!(s.revoke(&rec.label).unwrap());
        assert!(matches!(s.verify(&plain), Err(VerifyError::Revoked)));
        assert!(!s.revoke("skm_nothere").unwrap());
    }

    #[test]
    fn expired_is_rejected() {
        let (_d, s) = store();
        let (plain, _) = s.issue("case-a", Duration::ZERO).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(matches!(s.verify(&plain), Err(VerifyError::Expired(_))));
    }

    #[test]
    fn revoke_project_spares_other_project() {
        let (_d, s) = store();
        let (a1, _) = s.issue("case-a", Duration::from_secs(3600)).unwrap();
        let (a2, _) = s.issue("case-a", Duration::from_secs(3600)).unwrap();
        let (b1, _) = s.issue("case-b", Duration::from_secs(3600)).unwrap();
        assert_eq!(s.revoke_project("case-a").unwrap(), 2);
        assert!(s.verify(&a1).is_err());
        assert!(s.verify(&a2).is_err());
        assert!(s.verify(&b1).is_ok());
        assert_eq!(s.revoke_project("case-a").unwrap(), 0);
        let states: Vec<_> = s
            .list()
            .unwrap()
            .iter()
            .map(|r| r.state(SystemTime::now()))
            .collect();
        assert_eq!(states.iter().filter(|s| **s == "revoked").count(), 2);
    }

    #[test]
    fn survives_reload() {
        let (dir, s1) = store();
        let (plain, _) = s1.issue("case-a", Duration::from_secs(3600)).unwrap();
        let s2 = TokenStore::new(&dir.path().join("tokens.json"));
        assert!(s2.verify(&plain).is_ok());
        assert_eq!(s2.list().unwrap().len(), 1);
    }

    #[test]
    fn concurrent_writers_do_not_lose_updates() {
        let (dir, _) = store();
        let path = dir.path().join("tokens.json");
        let mut handles = Vec::new();
        for i in 0..8 {
            let p = path.clone();
            handles.push(std::thread::spawn(move || {
                let s = TokenStore::new(&p);
                for _ in 0..10 {
                    s.issue(&format!("p{i}"), Duration::from_secs(60)).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(TokenStore::new(&path).list().unwrap().len(), 80);
    }
    #[test]
    fn rebootstrap_rotates_tokens_of_the_same_key() {
        let (_d, s) = store();
        let (old_plain, old) = s
            .issue_for("case-a", Duration::from_secs(3600), Some("SHA256:k1"))
            .unwrap();
        let (other_plain, _) = s
            .issue_for("case-a", Duration::from_secs(3600), Some("SHA256:k2"))
            .unwrap();
        let (manual_plain, _) = s.issue("case-a", Duration::from_secs(3600)).unwrap();
        assert_eq!(s.revoke_by_fingerprint("SHA256:k1").unwrap(), 1);
        assert!(matches!(s.verify(&old_plain), Err(VerifyError::Revoked)));
        // Other keys and manually issued tokens are unaffected
        assert!(s.verify(&other_plain).is_ok());
        assert!(s.verify(&manual_plain).is_ok());
        assert_eq!(s.revoke_by_fingerprint("SHA256:k1").unwrap(), 0);
        assert_eq!(
            s.list()
                .unwrap()
                .iter()
                .filter(|r| r.label == old.label)
                .count(),
            1
        );
    }

    #[test]
    fn long_expired_records_are_pruned_on_write() {
        let (_d, s) = store();
        let (_, recent) = s.issue("case-a", Duration::ZERO).unwrap(); // just expired: kept
        let mut f = s.load().unwrap();
        let mut old = recent.clone();
        old.label = "skm_00000000".into();
        old.expires_at = SystemTime::now() - RETENTION_AFTER_EXPIRY - Duration::from_secs(60);
        f.records.insert("f".repeat(64), old);
        s.save(&f).unwrap();
        assert_eq!(s.list().unwrap().len(), 2);
        // The next write drops only the records older than 7 days
        s.issue("case-a", Duration::from_secs(60)).unwrap();
        let labels: Vec<String> = s.list().unwrap().into_iter().map(|r| r.label).collect();
        assert_eq!(labels.len(), 2);
        assert!(labels.contains(&recent.label) && !labels.contains(&"skm_00000000".to_string()));
    }

    #[test]
    fn old_store_without_fingerprint_field_loads() {
        let (d, s) = store();
        let text = r#"{"records":{"aaaa":{"label":"skm_aaaaaaaa","project":"p","issued_at":"2026-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z"}}}"#;
        std::fs::write(d.path().join("tokens.json"), text).unwrap();
        let list = s.list().unwrap();
        assert_eq!(list.len(), 1);
        assert!(list[0].fingerprint.is_none());
        assert_eq!(s.revoke_by_fingerprint("SHA256:x").unwrap(), 0);
    }
}
