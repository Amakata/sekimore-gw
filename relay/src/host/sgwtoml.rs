//! `sgw.toml`: what `sgw init` and `sgw update` last wrote to a project — the version, and the
//! sha256 of each template file as written — so `update` can tell a file the project edited from
//! one a new version changes. The project's, committed with the rest; never edited by hand.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

pub const NAME: &str = "sgw.toml";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SgwToml {
    pub version: String,
    /// template path → sha256 of the content sgw wrote
    pub files: BTreeMap<String, String>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

impl SgwToml {
    /// The two shapes this file has: `version = "…"` and, under `[files]`, `"path" = "sha"`.
    /// Anything else is skipped, so a hand edit cannot make parsing fail.
    pub fn parse(text: &str) -> SgwToml {
        let mut t = SgwToml::default();
        let mut in_files = false;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') {
                in_files = line == "[files]";
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let k = k.trim().trim_matches('"');
            let v = v.trim().trim_matches('"');
            if in_files {
                t.files.insert(k.to_string(), v.to_string());
            } else if k == "version" {
                t.version = v.to_string();
            }
        }
        t
    }

    pub fn render(&self) -> String {
        let mut s = String::from(
            "# Written by sgw init and sgw update: the sha256 of each template file as sgw wrote it, so\n\
             # update can tell a file you edited from one a new version changes. Do not edit.\n",
        );
        s.push_str(&format!("version = \"{}\"\n\n[files]\n", self.version));
        for (p, sha) in &self.files {
            s.push_str(&format!("\"{p}\" = \"{sha}\"\n"));
        }
        s
    }

    /// The template of this binary, as `init` writes it.
    pub fn of_template() -> SgwToml {
        SgwToml {
            version: env!("CARGO_PKG_VERSION").to_string(),
            files: super::templates::FILES
                .iter()
                .map(|t| (t.path.to_string(), sha256_hex(t.content.as_bytes())))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_round_trips_and_skips_what_it_does_not_know() {
        let mut t = SgwToml {
            version: "0.2.52".into(),
            files: BTreeMap::new(),
        };
        t.files
            .insert(".devcontainer/Dockerfile".into(), "aa".into());
        t.files
            .insert(".devcontainer/config/config.yml".into(), "bb".into());
        let text = t.render();
        assert!(text.starts_with("# Written by sgw init"));
        assert_eq!(SgwToml::parse(&text), t);
        let hand = "version = \"0.2.52\"\nnote = 1\n[files]\n\".devcontainer/Dockerfile\" = \"aa\"\n[other]\n\"x\" = \"y\"\n";
        let p = SgwToml::parse(hand);
        assert_eq!(p.version, "0.2.52");
        assert_eq!(p.files.len(), 1);
        assert_eq!(SgwToml::parse(""), SgwToml::default());
    }

    #[test]
    fn the_template_of_this_binary_is_every_template_file() {
        let t = SgwToml::of_template();
        assert_eq!(t.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(t.files.len(), super::super::templates::FILES.len());
        assert!(t.files.contains_key(".devcontainer/docker-compose.yml"));
    }
}
