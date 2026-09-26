//! Which project `sgw` is working on: the directory that holds `.devcontainer/`.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};

use crate::i18n::tf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Project {
    /// The project's root: the parent of `.devcontainer/`
    pub root: PathBuf,
    /// Where the compose files are. The compose labels name this directory, so it is how the
    /// stack's containers are found
    pub compose_dir: PathBuf,
}

impl Project {
    /// The name the host's secret stores file the passphrase under: the root's basename, the
    /// way `gw:keychain-set` did (`basename "$MISE_PROJECT_ROOT"`).
    pub fn name(&self) -> String {
        self.root
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.root.display().to_string())
    }

    /// The compose project name the Dev Containers extension gives this stack when it starts it:
    /// `<root's basename>_devcontainer`, normalised the way compose does.
    pub fn compose_project_name(&self) -> String {
        devcontainer_project_name(&self.name())
    }
}

/// `<folder>_devcontainer` as compose normalises it: lower case, only `[a-z0-9_-]` kept, and a
/// leading `-` or `_` dropped. `My Proj.2` starts as `myproj2_devcontainer`.
pub fn devcontainer_project_name(folder: &str) -> String {
    let kept: String = folder
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    let kept = kept.trim_start_matches(['-', '_']);
    format!("{kept}_devcontainer")
}

/// What `sgw` refuses to do from inside the dev container: everything. The stack is run by the
/// Docker on the host, and `docker` in dev is the inner one.
pub fn refuse_inside_devcontainer(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<()> {
    if get("DEVCONTAINER").as_deref() == Some("true") && get("SGW_FORCE").is_none() {
        bail!(crate::i18n::t("sgw.inside"));
    }
    Ok(())
}

/// The root, from `--project`, else `SGW_PROJECT_ROOT` / `MISE_PROJECT_ROOT`, else the first
/// ancestor of `cwd` (itself included) that has `.devcontainer/docker-compose.yml`.
pub fn discover(
    explicit: Option<&Path>,
    cwd: &Path,
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Project> {
    let root = if let Some(p) = explicit {
        p.to_path_buf()
    } else if let Some(v) = get("SGW_PROJECT_ROOT").or_else(|| get("MISE_PROJECT_ROOT")) {
        PathBuf::from(v)
    } else {
        let mut dir = Some(cwd);
        let mut found = None;
        while let Some(d) = dir {
            if d.join(".devcontainer").join("docker-compose.yml").is_file() {
                found = Some(d.to_path_buf());
                break;
            }
            dir = d.parent();
        }
        match found {
            Some(f) => f,
            None => bail!(tf("sgw.no_project", &[("dir", &cwd.display().to_string())])),
        }
    };
    let root = root
        .canonicalize()
        .with_context(|| tf("sgw.no_project", &[("dir", &root.display().to_string())]))?;
    let compose_dir = match get("SGW_COMPOSE_DIR") {
        Some(v) => PathBuf::from(v),
        None => root.join(".devcontainer"),
    };
    if !compose_dir.join("docker-compose.yml").is_file() {
        bail!(tf(
            "sgw.no_compose",
            &[("dir", &compose_dir.display().to_string())]
        ));
    }
    Ok(Project { root, compose_dir })
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_stack_is_named_the_way_dev_containers_names_it() {
        use super::devcontainer_project_name as n;
        assert_eq!(n("sgw-devcontainer"), "sgw-devcontainer_devcontainer");
        assert_eq!(n("My Proj.2"), "myproj2_devcontainer");
        assert_eq!(n("_hidden"), "hidden_devcontainer");
        assert_eq!(n("案件"), "_devcontainer");
    }

    use super::*;

    fn project_at(dir: &Path) {
        std::fs::create_dir_all(dir.join(".devcontainer")).unwrap();
        std::fs::write(
            dir.join(".devcontainer/docker-compose.yml"),
            "services: {}\n",
        )
        .unwrap();
    }

    #[test]
    fn walks_up_from_a_subdirectory() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("proj");
        project_at(&root);
        let deep = root.join("src/deep");
        std::fs::create_dir_all(&deep).unwrap();
        let p = discover(None, &deep, |_| None).unwrap();
        assert_eq!(p.root, root.canonicalize().unwrap());
        assert_eq!(p.compose_dir, p.root.join(".devcontainer"));
        assert_eq!(p.name(), "proj");
    }

    #[test]
    fn the_environment_and_the_flag_win_over_the_walk() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        project_at(&a);
        project_at(&b);
        let by_env = discover(None, &a, |k| {
            (k == "MISE_PROJECT_ROOT").then(|| b.display().to_string())
        })
        .unwrap();
        assert_eq!(by_env.root, b.canonicalize().unwrap());
        let by_flag = discover(Some(&a), &b, |k| {
            (k == "MISE_PROJECT_ROOT").then(|| b.display().to_string())
        })
        .unwrap();
        assert_eq!(by_flag.root, a.canonicalize().unwrap());
    }

    #[test]
    fn nothing_found_is_an_error_that_names_the_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let e = discover(None, tmp.path(), |_| None)
            .unwrap_err()
            .to_string();
        assert!(e.contains(&tmp.path().display().to_string()), "{e}");
    }

    #[test]
    fn inside_the_dev_container_it_refuses_unless_forced() {
        assert!(
            refuse_inside_devcontainer(|k| (k == "DEVCONTAINER").then(|| "true".into())).is_err()
        );
        assert!(refuse_inside_devcontainer(|k| match k {
            "DEVCONTAINER" => Some("true".into()),
            "SGW_FORCE" => Some("1".into()),
            _ => None,
        })
        .is_ok());
        assert!(refuse_inside_devcontainer(|_| None).is_ok());
    }
}
