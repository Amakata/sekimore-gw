//! File helpers for `setup`: ownership, marked blocks, the env file, small subprocesses.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context};

/// The agent user everything is written for: root runs `setup`, the user owns the result.
#[derive(Debug, Clone)]
pub struct Owner {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}

/// `/etc/passwd` by name. NSS is not consulted: in the dev container the file is the truth.
pub fn passwd(name: &str) -> Option<Owner> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() >= 7 && f[0] == name {
            Some(Owner {
                name: name.to_string(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
                home: PathBuf::from(f[5]),
            })
        } else {
            None
        }
    })
}

/// The user running this process, by uid.
pub fn current_user() -> Option<Owner> {
    let uid = unsafe { libc::getuid() };
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() >= 7 && f[2].parse::<u32>().ok() == Some(uid) {
            Some(Owner {
                name: f[0].to_string(),
                uid,
                gid: f[3].parse().ok()?,
                home: PathBuf::from(f[5]),
            })
        } else {
            None
        }
    })
}

pub fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

pub fn chown(path: &Path, o: &Owner) -> anyhow::Result<()> {
    std::os::unix::fs::chown(path, Some(o.uid), Some(o.gid))
        .with_context(|| format!("chown {}", path.display()))
}

/// `chown -R`, symlinks not followed.
pub fn chown_all(path: &Path, o: &Owner) -> anyhow::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    std::os::unix::fs::lchown(path, Some(o.uid), Some(o.gid))
        .with_context(|| format!("chown {}", path.display()))?;
    if meta.is_dir() {
        for e in std::fs::read_dir(path)? {
            chown_all(&e?.path(), o)?;
        }
    }
    Ok(())
}

pub fn chmod(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {:o} {}", mode, path.display()))
}

/// `install -d -m <mode>`: the directory exists afterwards with that mode (an existing one keeps
/// what it had, as `install -d` does).
pub fn ensure_dir(path: &Path, mode: u32) -> anyhow::Result<()> {
    if !path.is_dir() {
        std::fs::create_dir_all(path).with_context(|| format!("mkdir {}", path.display()))?;
        chmod(path, mode)?;
    }
    Ok(())
}

/// Write through a temporary file beside the target and rename: a reader never sees half a file.
pub fn write_atomic(path: &Path, text: &str, mode: u32) -> anyhow::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .map(|s| s.to_string_lossy())
            .unwrap_or_default(),
        std::process::id()
    ));
    std::fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
    chmod(&tmp, mode)?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}

pub fn read_or_empty(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// A block between two marker lines, replaced or removed as a whole. The four markers the shell
/// script kept in awk and sed one-liners, in one place.
pub struct MarkedBlock {
    pub begin: &'static str,
    pub end: &'static str,
}

impl MarkedBlock {
    /// `text` without the block (marker lines included). Everything else stays as it was.
    pub fn remove(&self, text: &str) -> String {
        let mut out = String::new();
        let mut skip = false;
        for line in text.lines() {
            if line == self.begin {
                skip = true;
                continue;
            }
            if skip {
                if line == self.end {
                    skip = false;
                }
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// `text` with the old block taken out and the new one at the end.
    pub fn replace(&self, text: &str, body: &str) -> String {
        let mut out = self.remove(text);
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(self.begin);
        out.push('\n');
        out.push_str(body);
        if !body.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(self.end);
        out.push('\n');
        out
    }
}

/// Whether `name` is on PATH.
pub fn on_path(name: &str) -> bool {
    if name.contains('/') {
        return Path::new(name).is_file();
    }
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()))
        .unwrap_or(false)
}

/// Run a command; stdout on success, the stderr in the error otherwise.
pub fn run(cmd: &mut Command) -> anyhow::Result<String> {
    let o = cmd
        .output()
        .with_context(|| format!("run {:?}", cmd.get_program()))?;
    if !o.status.success() {
        bail!(
            "{:?} failed: {}",
            cmd.get_program(),
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

pub fn hostname() -> String {
    let h = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    let h = h.trim();
    if h.is_empty() {
        "dev".to_string()
    } else {
        h.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: MarkedBlock = MarkedBlock {
        begin: "# >>> x >>>",
        end: "# <<< x <<<",
    };

    #[test]
    fn a_marked_block_is_replaced_in_place_and_added_when_absent() {
        assert_eq!(B.replace("", "a\n"), "# >>> x >>>\na\n# <<< x <<<\n");
        let once = B.replace("keep\n", "a\n");
        assert_eq!(once, "keep\n# >>> x >>>\na\n# <<< x <<<\n");
        let twice = B.replace(&once, "b\n");
        assert_eq!(twice, "keep\n# >>> x >>>\nb\n# <<< x <<<\n");
        assert_eq!(B.remove(&twice), "keep\n");
        // text without a trailing newline gets one before the block
        assert_eq!(
            B.replace("keep", "a"),
            "keep\n# >>> x >>>\na\n# <<< x <<<\n"
        );
    }
}
