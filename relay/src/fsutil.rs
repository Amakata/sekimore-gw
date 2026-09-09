//! ファイル操作のユーティリティ: 0600/0700、atomic write、flock。
//!
//! `serve` と操作者 CLI（`docker compose exec … token`）が同じファイルを並行に触るので、
//! 「flock → 読む → 変える → atomic rename」を徹底する（PoC は lost update があった）。

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// ディレクトリを 0700 で作る（存在すれば mode だけ揃える）。
pub fn ensure_dir_0700(path: &Path) -> io::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// 同一ディレクトリの一時ファイルへ書いてから rename する。mode は作成時に付ける。
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let base = path.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    let tmp: PathBuf = dir.join(format!(".{base}.{}.tmp", std::process::id()));
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        use std::io::Write;
        f.write_all(data)?;
        f.sync_all()?;
    }
    // 既存ファイルの mode が緩くても上書きで揃う
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// `<path>.lock` に対する排他ロック。drop で解放。
pub struct FlockGuard {
    _file: File,
}

impl FlockGuard {
    pub fn lock(path: &Path) -> io::Result<Self> {
        let lock_path = lock_path_for(path);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)?;
        use std::os::unix::io::AsRawFd;
        // SAFETY: fd は open 直後の有効な記述子。flock は fd と定数しか受け取らない
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(FlockGuard { _file: file })
    }
}

fn lock_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".lock");
    PathBuf::from(s)
}

/// 読めなければ `None`（存在しない）。
pub fn read_optional(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_sets_mode_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        atomic_write(&p, b"one", 0o600).unwrap();
        atomic_write(&p, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            fs::read_dir(dir.path()).unwrap().count() == 1,
            "no temp files left"
        );
    }

    #[test]
    fn flock_serializes_writers() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("store.json");
        let g = FlockGuard::lock(&p).unwrap();
        // 2 つ目のロックはブロックする（非ブロッキングで試す）
        let f2 = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path_for(&p))
            .unwrap();
        use std::os::unix::io::AsRawFd;
        let rc = unsafe { libc::flock(f2.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_ne!(rc, 0);
        drop(g);
        let rc = unsafe { libc::flock(f2.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0);
    }
}
