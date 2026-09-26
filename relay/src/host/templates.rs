//! The project template, embedded (#234): `sgw init` writes it.
//!
//! The files are `base/examples/sgw-sample/` at the commit this binary was built from, byte for
//! byte. Their pins (the gateway image tag, the base's FROM) are this same version, which
//! `tests/unit/test_base_versions.py` holds them to, so nothing is rewritten on the way out. The
//! sample stays on disk as the human-readable copy until stage 3 of the design removes it; the
//! test below refuses a file that is on disk and not here, or here and not on disk.

use std::path::Path;

use anyhow::{bail, Context};

pub struct Template {
    /// Where it goes, relative to the project root
    pub path: &'static str,
    pub content: &'static str,
    pub executable: bool,
}

macro_rules! sample {
    ($path:literal) => {
        include_str!(concat!("../../../base/examples/sgw-sample/", $path))
    };
}

/// Everything a project starts with. The sample's own READMEs are about the sample, not the
/// project, and stay behind.
pub const FILES: &[Template] = &[
    Template {
        path: ".devcontainer/.env.sample",
        content: sample!(".devcontainer/.env.sample"),
        executable: false,
    },
    Template {
        path: ".devcontainer/.gitignore",
        content: sample!(".devcontainer/.gitignore"),
        executable: false,
    },
    Template {
        path: ".devcontainer/Dockerfile",
        content: sample!(".devcontainer/Dockerfile"),
        executable: false,
    },
    Template {
        path: ".devcontainer/config/config.yml",
        content: sample!(".devcontainer/config/config.yml"),
        executable: false,
    },
    Template {
        path: ".devcontainer/config/squid/squid.conf.template",
        content: sample!(".devcontainer/config/squid/squid.conf.template"),
        executable: false,
    },
    Template {
        path: ".devcontainer/devcontainer.json",
        content: sample!(".devcontainer/devcontainer.json"),
        executable: false,
    },
    Template {
        path: ".devcontainer/docker-compose.relay.yml",
        content: sample!(".devcontainer/docker-compose.relay.yml"),
        executable: false,
    },
    Template {
        path: ".devcontainer/docker-compose.yml",
        content: sample!(".devcontainer/docker-compose.yml"),
        executable: false,
    },
    Template {
        path: ".devcontainer/scripts/post-create.sh",
        content: sample!(".devcontainer/scripts/post-create.sh"),
        executable: true,
    },
    Template {
        path: ".devcontainer/sgw/MANIFEST",
        content: sample!(".devcontainer/sgw/MANIFEST"),
        executable: false,
    },
    Template {
        path: ".devcontainer/sgw/gateway.mise.toml",
        content: sample!(".devcontainer/sgw/gateway.mise.toml"),
        executable: false,
    },
    Template {
        path: ".devcontainer/sgw/post-start.sh",
        content: sample!(".devcontainer/sgw/post-start.sh"),
        executable: true,
    },
    Template {
        path: ".devcontainer/sgw/sgw.sh",
        content: sample!(".devcontainer/sgw/sgw.sh"),
        executable: true,
    },
    Template {
        path: ".devcontainer/sgw/tasks.mise.toml",
        content: sample!(".devcontainer/sgw/tasks.mise.toml"),
        executable: false,
    },
    Template {
        path: ".devcontainer/sgw/upgrade.sh",
        content: sample!(".devcontainer/sgw/upgrade.sh"),
        executable: true,
    },
    Template {
        path: ".devcontainer/sgw/vscode.sh",
        content: sample!(".devcontainer/sgw/vscode.sh"),
        executable: true,
    },
    Template {
        path: ".devcontainer/zsh-config/rc.d/99-splash.zsh",
        content: sample!(".devcontainer/zsh-config/rc.d/99-splash.zsh"),
        executable: false,
    },
    Template {
        path: "mise.toml",
        content: sample!("mise.toml"),
        executable: false,
    },
];

/// `.env` starts as a copy of `.env.sample` (the sample's README's step 3), so the project can
/// open before anyone edits it. It is not a template file: a second `init` must not touch it.
pub const ENV_FROM_SAMPLE: (&str, &str) = (".devcontainer/.env", ".devcontainer/.env.sample");

/// What `init` did: written, and what it left alone because it was there.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub written: Vec<String>,
    pub existed: Vec<String>,
}

/// The files that `init` would have to overwrite in `root`.
pub fn conflicts(root: &Path) -> Vec<String> {
    FILES
        .iter()
        .map(|t| t.path)
        .filter(|p| root.join(p).exists())
        .map(str::to_string)
        .collect()
}

/// Writes the template into `root`. Refuses when any file exists, unless `force`; `.env` is
/// written from `.env.sample` only when absent, force or not.
pub fn write(root: &Path, force: bool) -> anyhow::Result<Report> {
    let existing = conflicts(root);
    if !existing.is_empty() && !force {
        bail!(crate::i18n::tf(
            "sgw.init.exists",
            &[("files", &existing.join(", "))]
        ));
    }
    let mut report = Report::default();
    for t in FILES {
        let dest = root.join(t.path);
        if let Some(dir) = dest.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        }
        std::fs::write(&dest, t.content).with_context(|| format!("write {}", dest.display()))?;
        set_mode(&dest, t.executable)?;
        report.written.push(t.path.to_string());
    }
    let (env, sample) = ENV_FROM_SAMPLE;
    let env_path = root.join(env);
    if env_path.exists() {
        report.existed.push(env.to_string());
    } else {
        let content = FILES
            .iter()
            .find(|t| t.path == sample)
            .map(|t| t.content)
            .unwrap_or_default();
        std::fs::write(&env_path, content)
            .with_context(|| format!("write {}", env_path.display()))?;
        set_mode(&env_path, false)?;
        report.written.push(env.to_string());
    }
    Ok(report)
}

fn set_mode(path: &Path, executable: bool) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o755 } else { 0o644 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {}", path.display()))
}

/// The repository's sample directory, for the test that holds the table to the disk.
#[cfg(test)]
fn sample_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../base/examples/sgw-sample")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                walk(&p, root, out);
            } else {
                out.push(p.strip_prefix(root).unwrap().to_string_lossy().into_owned());
            }
        }
    }

    /// A file added to the sample and not here would be missing from every new project; one here
    /// and not there is a template nothing on disk explains.
    #[test]
    fn the_table_is_the_sample_on_disk() {
        let root = sample_dir();
        let mut on_disk = Vec::new();
        walk(&root, &root, &mut on_disk);
        on_disk.retain(|p| !(p.starts_with("README") && p.ends_with(".md")));
        on_disk.sort();
        let mut here: Vec<String> = FILES.iter().map(|t| t.path.to_string()).collect();
        here.sort();
        assert_eq!(here, on_disk);
        for t in FILES {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(root.join(t.path))
                .unwrap()
                .permissions()
                .mode()
                & 0o111;
            assert_eq!(mode != 0, t.executable, "{}: executable bit", t.path);
            assert_eq!(
                std::fs::read_to_string(root.join(t.path)).unwrap(),
                t.content,
                "{}",
                t.path
            );
        }
    }

    #[test]
    fn the_pins_are_this_version() {
        let v = env!("CARGO_PKG_VERSION");
        let compose = FILES
            .iter()
            .find(|t| t.path == ".devcontainer/docker-compose.yml")
            .unwrap();
        assert!(
            compose
                .content
                .contains(&format!("ghcr.io/amakata/sekimore-gw:{v}")),
            "the sample pins another gateway than this build"
        );
        let dockerfile = FILES
            .iter()
            .find(|t| t.path == ".devcontainer/Dockerfile")
            .unwrap();
        assert!(dockerfile
            .content
            .contains(&format!("ghcr.io/amakata/sgw-devcontainer-base:{v}")));
    }

    #[test]
    fn init_writes_everything_once_and_refuses_the_second_time() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let r = write(tmp.path(), false).unwrap();
        assert_eq!(r.written.len(), FILES.len() + 1, ".env included");
        assert!(r.existed.is_empty());
        assert!(tmp.path().join(".devcontainer/.env").is_file());
        let sgw_sh = tmp.path().join(".devcontainer/sgw/sgw.sh");
        assert_ne!(
            std::fs::metadata(&sgw_sh).unwrap().permissions().mode() & 0o111,
            0
        );
        assert_eq!(
            std::fs::metadata(tmp.path().join("mise.toml"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        // again: refused, and nothing changed
        std::fs::write(tmp.path().join(".devcontainer/.env"), "EDITED=1\n").unwrap();
        let e = write(tmp.path(), false).unwrap_err().to_string();
        assert!(e.contains(".devcontainer/docker-compose.yml"), "{e}");
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(".devcontainer/.env")).unwrap(),
            "EDITED=1\n"
        );
        // forced: the template files are rewritten, .env is not
        let r = write(tmp.path(), true).unwrap();
        assert_eq!(r.existed, vec![".devcontainer/.env"]);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(".devcontainer/.env")).unwrap(),
            "EDITED=1\n"
        );
    }
}
