//! 上流（device flow）トークンの保管。
//!
//! Mac の Keychain は使えない（関所は VM 内のコンテナ）。当面はコンテナ内ボリュームのファイル（0600）。
//! 「使うときだけ取り出し、TTL で破棄する」メモリキャッシュを前に置く（ssh-agent の -t と同じ発想）。

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::fsutil::{atomic_write, read_optional};

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
    /// トークンが無い。操作者への案内文を含む
    Missing(String),
    Io(std::io::Error),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Missing(m) => write!(f, "{m}"),
            TokenError::Io(e) => write!(f, "upstream token store: {e}"),
        }
    }
}

impl std::error::Error for TokenError {}

pub struct UpstreamTokenStore {
    path: PathBuf,
    cache_ttl: Duration,
    cache: Mutex<Option<(String, Instant)>>,
}

impl UpstreamTokenStore {
    pub fn new(path: &Path, cache_ttl: Duration) -> Self {
        UpstreamTokenStore {
            path: path.to_path_buf(),
            cache_ttl,
            cache: Mutex::new(None),
        }
    }

    pub fn save(&self, host: &str, token: &str, scope: &str) -> std::io::Result<()> {
        let st = StoredToken {
            host: host.to_string(),
            token: token.to_string(),
            scope: scope.to_string(),
            obtained_at: SystemTime::now(),
        };
        let data = serde_json::to_vec_pretty(&st)?;
        atomic_write(&self.path, &data, 0o600)?;
        self.forget();
        Ok(())
    }

    pub fn load(&self) -> std::io::Result<Option<StoredToken>> {
        match read_optional(&self.path)? {
            None => Ok(None),
            Some(b) => serde_json::from_slice(&b).map(Some).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("parse upstream token: {e}"),
                )
            }),
        }
    }

    pub fn delete(&self) -> std::io::Result<bool> {
        self.forget();
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// キャッシュ → ファイルの順で取得。無ければ操作者向けの案内付きエラー。
    pub fn token(&self) -> Result<String, TokenError> {
        {
            let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((tok, at)) = c.as_ref() {
                if at.elapsed() < self.cache_ttl {
                    return Ok(tok.clone());
                }
                *c = None;
            }
        }
        let st = self.load().map_err(TokenError::Io)?.ok_or_else(|| {
            TokenError::Missing(format!(
                "no upstream token in {}: run `docker compose exec sekimore-gw sekimore-relay login`",
                self.path.display()
            ))
        })?;
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        *c = Some((st.token.clone(), Instant::now()));
        Ok(st.token)
    }

    /// メモリ上のトークンを破棄する（ファイルには残す）。
    pub fn forget(&self) {
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_token_delete() {
        let dir = tempfile::tempdir().unwrap();
        let s =
            UpstreamTokenStore::new(&dir.path().join("upstream_token"), Duration::from_secs(60));
        assert!(matches!(s.token(), Err(TokenError::Missing(_))));
        s.save("github.com", "gho_x", "repo project").unwrap();
        assert_eq!(s.token().unwrap(), "gho_x");
        assert_eq!(s.load().unwrap().unwrap().scope, "repo project");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(s.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(s.delete().unwrap());
        assert!(!s.delete().unwrap());
        assert!(
            matches!(s.token(), Err(TokenError::Missing(m)) if m.contains("sekimore-relay login"))
        );
    }
}
