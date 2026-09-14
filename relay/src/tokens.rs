//! 案件トークンのストア。
//!
//! 方式は不透明トークン: エージェントに渡すのは意味のない乱数で、案件・有効期限は関所側のストアが持つ。
//!   - 即時失効ができる（自律エージェントに渡す鍵なので必須）
//!   - ポリシー変更が既発行トークンにも即反映される
//!   - トークン自体に情報が載らない
//!
//! ストアには **SHA-256 ハッシュのみ**。平文は発行時の戻り値にしか存在しない。
//! ラベルはハッシュの先頭 8 hex（平文の一部を出さない）。
//! 更新は flock → 読む → 変える → atomic rename（`serve` と操作者 CLI の並行実行に耐える）。

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fsutil::{atomic_write, read_optional, FlockGuard};

pub const TOKEN_PREFIX: &str = "skm_";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenRecord {
    /// 表示用の短い識別子（ハッシュ先頭 8 hex）。ログや一覧に使う
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

    /// 発行。平文は戻り値でのみ返し、保存しない。
    pub fn issue(&self, project: &str, ttl: Duration) -> std::io::Result<(String, TokenRecord)> {
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
        };
        let _g = FlockGuard::lock(&self.path)?;
        let mut f = self.load()?;
        f.records.insert(hash, rec.clone());
        self.save(&f)?;
        Ok((token, rec))
    }

    /// 検証。使用実績も記録する（監査のため。保存失敗でも検証結果は返す）。
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

    /// ラベル指定で失効。見つかれば true。
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
            self.save(&f)?;
        }
        Ok(found)
    }

    /// 案件のトークンを全て失効させる（案件終了時）。失効させた件数を返す。
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
            self.save(&f)?;
        }
        Ok(n)
    }

    /// 発行済みトークンの一覧（平文は含まない）。発行日時順。
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
        // ラベルは平文の一部ではない
        assert!(!plain.starts_with(&rec.label));

        // 平文はストアに保存されない
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
}
