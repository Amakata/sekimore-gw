//! Filesystem helpers: 0600/0700 modes, atomic writes, flock.
//!
//! `serve` and the operator CLI (`docker compose exec … token`) touch the same files concurrently,
//! so every update follows "flock → read → modify → atomic rename" (the PoC suffered lost updates).

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Creates a directory with mode 0700 (if it already exists, only the mode is fixed up).
pub fn ensure_dir_0700(path: &Path) -> io::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Writes to a temporary file in the same directory, then renames it. The mode is applied at creation time.
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
    // Fix up the mode even if the existing file was more permissive
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// An exclusive lock on `<path>.lock`, released on drop.
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
        // SAFETY: fd is a valid descriptor straight from open; flock only takes an fd and a constant
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

/// Returns `None` if the file cannot be read (does not exist).
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
        // The second lock blocks (try it non-blocking to prove it)
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
