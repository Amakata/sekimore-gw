//! The project template, embedded (#234): `sgw init` writes it.
//!
//! The files are `relay/templates/devcontainer/` at the commit this binary was built from, byte
//! for byte. Their pins (the gateway image tag, the base's FROM) are this same version, which
//! `tests/unit/test_base_versions.py` holds them to, so nothing is rewritten on the way out. The
//! test below refuses a file that is on disk and not here, or here and not on disk. The
//! directory stays on disk as the readable copy, and `docs/template.md` describes it. Beside them
//! `init` writes `sgw.toml` (host::sgwtoml), the record `update` reads. No mise layer: sgw is the
//! operator's tool, and `.devcontainer/sgw/` is a thing of the past (#234 stage 3).

use std::path::Path;

use anyhow::{bail, Context};

pub struct Template {
    /// Where it goes, relative to the project root
    pub path: &'static str,
    pub content: &'static str,
    pub executable: bool,
}

macro_rules! template {
    ($path:literal) => {
        include_str!(concat!("../../templates/devcontainer/", $path))
    };
}

/// Everything a project starts with. The template's guide is `docs/template.md`, not a file a
/// project gets.
pub const FILES: &[Template] = &[
    Template {
        path: ".devcontainer/.env.sample",
        content: template!(".devcontainer/.env.sample"),
        executable: false,
    },
    Template {
        path: ".devcontainer/.gitignore",
        content: template!(".devcontainer/.gitignore"),
        executable: false,
    },
    Template {
        path: ".devcontainer/Dockerfile",
        content: template!(".devcontainer/Dockerfile"),
        executable: false,
    },
    Template {
        path: ".devcontainer/config/config.sample.yml",
        content: template!(".devcontainer/config/config.sample.yml"),
        executable: false,
    },
    Template {
        path: ".devcontainer/config/squid/squid.conf.template",
        content: template!(".devcontainer/config/squid/squid.conf.template"),
        executable: false,
    },
    Template {
        path: ".devcontainer/devcontainer.json",
        content: template!(".devcontainer/devcontainer.json"),
        executable: false,
    },
    Template {
        path: ".devcontainer/docker-compose.relay.yml",
        content: template!(".devcontainer/docker-compose.relay.yml"),
        executable: false,
    },
    Template {
        path: ".devcontainer/docker-compose.yml",
        content: template!(".devcontainer/docker-compose.yml"),
        executable: false,
    },
    Template {
        path: ".devcontainer/scripts/post-create.sh",
        content: template!(".devcontainer/scripts/post-create.sh"),
        executable: true,
    },
    Template {
        path: ".devcontainer/zsh-config/rc.d/99-splash.zsh",
        content: template!(".devcontainer/zsh-config/rc.d/99-splash.zsh"),
        executable: false,
    },
];

/// The files a project owns, each started from the sample beside it so the project can open
/// before anyone edits it: `.env` from `.env.sample` (the sample's README's step 3), and
/// `config.yml` from `config.sample.yml`. Neither is a template file — they are not in `FILES`,
/// so `sgw update` never writes one, with `--force` or without it, and `sgw.toml` records the
/// sample instead. `init` writes one only when it is absent, force or not: `config.yml` holds
/// the permission list, the repositories and the allowlist, and rewriting it would cut the
/// agent off from GitHub. The sample is what a project diffs its own file against after an
/// update.
pub const FROM_SAMPLE: &[(&str, &str)] = &[
    (".devcontainer/.env", ".devcontainer/.env.sample"),
    (
        ".devcontainer/config/config.yml",
        ".devcontainer/config/config.sample.yml",
    ),
];

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
        .chain(std::iter::once(super::sgwtoml::NAME))
        .filter(|p| root.join(p).exists())
        .map(str::to_string)
        .collect()
}

/// Writes the template into `root`. Refuses when any file exists, unless `force`; the files a
/// project owns (`FROM_SAMPLE`: `.env` and `config.yml`) are written from their samples only
/// when absent, force or not.
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
    for (own, sample) in FROM_SAMPLE {
        let own_path = root.join(own);
        if own_path.exists() {
            report.existed.push((*own).to_string());
            continue;
        }
        let content = FILES
            .iter()
            .find(|t| t.path == *sample)
            .map(|t| t.content)
            .unwrap_or_default();
        if let Some(dir) = own_path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        }
        std::fs::write(&own_path, content)
            .with_context(|| format!("write {}", own_path.display()))?;
        set_mode(&own_path, false)?;
        report.written.push((*own).to_string());
    }
    let toml = root.join(super::sgwtoml::NAME);
    std::fs::write(&toml, super::sgwtoml::SgwToml::of_template().render())
        .with_context(|| format!("write {}", toml.display()))?;
    set_mode(&toml, false)?;
    report.written.push(super::sgwtoml::NAME.to_string());
    Ok(report)
}

fn set_mode(path: &Path, executable: bool) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o755 } else { 0o644 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {}", path.display()))
}

/// The repository's template directory, for the test that holds the table to the disk.
#[cfg(test)]
fn template_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/devcontainer")
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

    /// A file added to the template and not here would be missing from every new project; one
    /// here and not there is a template nothing on disk explains.
    #[test]
    fn the_table_is_the_template_on_disk() {
        let root = template_dir();
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
        assert_eq!(
            r.written.len(),
            FILES.len() + FROM_SAMPLE.len() + 1,
            ".env, config.yml and sgw.toml included"
        );
        assert!(r.existed.is_empty());
        assert!(tmp.path().join(".devcontainer/.env").is_file());
        // init writes both: the project's own config.yml to run with, and the sample beside it
        assert!(tmp.path().join(".devcontainer/config/config.yml").is_file());
        assert!(tmp
            .path()
            .join(".devcontainer/config/config.sample.yml")
            .is_file());
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(".devcontainer/config/config.yml")).unwrap(),
            std::fs::read_to_string(tmp.path().join(".devcontainer/config/config.sample.yml"))
                .unwrap(),
            "the project's file starts as a copy of the sample"
        );
        let post_create = tmp.path().join(".devcontainer/scripts/post-create.sh");
        assert_ne!(
            std::fs::metadata(&post_create)
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
        assert_eq!(
            std::fs::metadata(tmp.path().join("sgw.toml"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert!(!tmp.path().join(".devcontainer/sgw").exists());
        assert!(!tmp.path().join("mise.toml").exists());
        // again: refused, and nothing changed
        std::fs::write(tmp.path().join(".devcontainer/.env"), "EDITED=1\n").unwrap();
        let e = write(tmp.path(), false).unwrap_err().to_string();
        assert!(e.contains(".devcontainer/docker-compose.yml"), "{e}");
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(".devcontainer/.env")).unwrap(),
            "EDITED=1\n"
        );
        // forced: the template files are rewritten, the project's own are not — losing
        // config.yml would take the permissions, the repositories and the allowlist with it
        let config = tmp.path().join(".devcontainer/config/config.yml");
        std::fs::write(&config, "name: mine\n").unwrap();
        let r = write(tmp.path(), true).unwrap();
        assert_eq!(
            r.existed,
            vec![".devcontainer/.env", ".devcontainer/config/config.yml"]
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(".devcontainer/.env")).unwrap(),
            "EDITED=1\n"
        );
        assert_eq!(std::fs::read_to_string(&config).unwrap(), "name: mine\n");
    }
}
