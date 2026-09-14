//! 使い捨て SSH 鍵（エージェント側）の公開鍵リスト。
//!
//! `/data/relay/authorized_keys`（OpenSSH 形式）。`POST /bootstrap` や `add-key` が追記するので、
//! mtime / サイズの変化を見て再読込する（再起動なしで有効になる）。

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use russh::keys::ssh_key::public::KeyData;
use russh::keys::{HashAlg, PublicKey};

use crate::fsutil::{atomic_write, read_optional, FlockGuard};

#[derive(Default)]
struct Cache {
    stamp: Option<(SystemTime, u64)>,
    keys: HashSet<KeyData>,
    count: usize,
}

pub struct AuthorizedKeys {
    path: PathBuf,
    max_keys: usize,
    cache: Mutex<Cache>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Added {
    New { fingerprint: String },
    AlreadyPresent { fingerprint: String },
}

#[derive(Debug)]
pub enum AddError {
    Parse(String),
    TooMany(usize),
    Io(std::io::Error),
}

impl std::fmt::Display for AddError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddError::Parse(m) => write!(f, "invalid OpenSSH public key: {m}"),
            AddError::TooMany(n) => write!(
                f,
                "authorized_keys already holds {n} keys (max); revoke some first"
            ),
            AddError::Io(e) => write!(f, "authorized_keys: {e}"),
        }
    }
}

impl std::error::Error for AddError {}

pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// 1 行の公開鍵を解析する。options 付き行（`no-pty ssh-ed25519 …`）や秘密鍵は拒否される。
pub fn parse_public_key(line: &str) -> Result<PublicKey, AddError> {
    let line = line.trim();
    if line.is_empty() || line.contains('\n') {
        return Err(AddError::Parse(
            "expected one line: <type> <base64> [comment]".into(),
        ));
    }
    PublicKey::from_openssh(line).map_err(|e| AddError::Parse(e.to_string()))
}

impl AuthorizedKeys {
    pub fn new(path: &Path, max_keys: usize) -> Self {
        AuthorizedKeys {
            path: path.to_path_buf(),
            max_keys,
            cache: Mutex::new(Cache::default()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn stamp(&self) -> Option<(SystemTime, u64)> {
        let md = std::fs::metadata(&self.path).ok()?;
        Some((md.modified().ok()?, md.len()))
    }

    fn parse_file(&self) -> std::io::Result<(HashSet<KeyData>, usize)> {
        let mut set = HashSet::new();
        let mut count = 0;
        if let Some(bytes) = read_optional(&self.path)? {
            for line in String::from_utf8_lossy(&bytes).lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                match PublicKey::from_openssh(line) {
                    Ok(k) => {
                        set.insert(k.key_data().clone());
                        count += 1;
                    }
                    Err(e) => log::warn!("authorized_keys: skipping unparseable line: {e}"),
                }
            }
        }
        Ok((set, count))
    }

    fn refresh(&self) {
        let stamp = self.stamp();
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if c.stamp == stamp && stamp.is_some() {
            return;
        }
        match self.parse_file() {
            Ok((keys, count)) => {
                c.keys = keys;
                c.count = count;
                c.stamp = stamp;
            }
            Err(e) => log::warn!("authorized_keys: cannot read {}: {e}", self.path.display()),
        }
    }

    /// 登録済みか。ファイルが変わっていれば読み直す。
    pub fn contains(&self, key: &PublicKey) -> bool {
        self.refresh();
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys
            .contains(key.key_data())
    }

    pub fn count(&self) -> usize {
        self.refresh();
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).count
    }

    /// 公開鍵を追記する（冪等）。
    pub fn add(&self, line: &str) -> Result<Added, AddError> {
        let key = parse_public_key(line)?;
        let fp = fingerprint(&key);
        let _g = FlockGuard::lock(&self.path).map_err(AddError::Io)?;
        let (existing, count) = self.parse_file().map_err(AddError::Io)?;
        if existing.contains(key.key_data()) {
            return Ok(Added::AlreadyPresent { fingerprint: fp });
        }
        if count >= self.max_keys {
            return Err(AddError::TooMany(count));
        }
        let mut content = read_optional(&self.path)
            .map_err(AddError::Io)?
            .unwrap_or_default();
        if !content.is_empty() && !content.ends_with(b"\n") {
            content.push(b'\n');
        }
        let canonical = key
            .to_openssh()
            .map_err(|e| AddError::Parse(e.to_string()))?;
        content.extend_from_slice(canonical.as_bytes());
        content.push(b'\n');
        atomic_write(&self.path, &content, 0o600).map_err(AddError::Io)?;
        Ok(Added::New { fingerprint: fp })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::private::Ed25519Keypair;
    use russh::keys::PrivateKey;

    fn gen() -> PublicKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        PrivateKey::from(Ed25519Keypair::from_seed(&seed))
            .public_key()
            .clone()
    }

    #[test]
    fn add_is_idempotent_and_hot_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let ak = AuthorizedKeys::new(&dir.path().join("authorized_keys"), 4);
        let k1 = gen();
        assert!(!ak.contains(&k1));
        let line = format!("{} agent@dev", k1.to_openssh().unwrap());
        assert!(matches!(ak.add(&line).unwrap(), Added::New { .. }));
        assert!(matches!(
            ak.add(&line).unwrap(),
            Added::AlreadyPresent { .. }
        ));
        assert!(ak.contains(&k1));
        assert_eq!(ak.count(), 1);
        // 別プロセスが追記した想定
        let k2 = gen();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(ak.path())
            .unwrap();
        use std::io::Write;
        writeln!(f, "{}", k2.to_openssh().unwrap()).unwrap();
        drop(f);
        // mtime の粒度に負けないよう少し待つ
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(ak.contains(&k2));
        assert_eq!(ak.count(), 2);
    }

    #[test]
    fn rejects_options_private_keys_and_too_many() {
        let dir = tempfile::tempdir().unwrap();
        let ak = AuthorizedKeys::new(&dir.path().join("authorized_keys"), 1);
        assert!(matches!(ak.add("no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVuY29kZWRfa2V5X2J5dGVzX2hlcmVfXw agent"), Err(AddError::Parse(_))));
        assert!(matches!(
            ak.add("-----BEGIN OPENSSH PRIVATE KEY-----"),
            Err(AddError::Parse(_))
        ));
        assert!(matches!(ak.add(""), Err(AddError::Parse(_))));
        ak.add(&gen().to_openssh().unwrap()).unwrap();
        assert!(matches!(
            ak.add(&gen().to_openssh().unwrap()),
            Err(AddError::TooMany(1))
        ));
    }
}
