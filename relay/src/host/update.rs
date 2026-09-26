//! `sgw update`: keep a project's gateway, base image and `.devcontainer/sgw/` current — the
//! former `upgrade.sh`, with one difference that removes most of it: what is written is
//! embedded. This build of `sgw` carries the template of its own version and its UPGRADING, so
//! the only question that needs the network is "is there a release newer than this sgw?", and
//! the answer to that is "install the newer sgw first", never a file fetched from a tag.
//!
//! The project's own files (`mise.toml`, `devcontainer.json`, `config.yml`) are never written:
//! what they need is said at the end, the way `upgrade.sh --owned` did.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context};
use sha2::{Digest, Sha256};

use crate::i18n::{lang, t, tf};

use super::docker::{Docker, GATEWAY};
use super::project::Project;
use super::templates;

pub const GW_IMAGE: &str = "ghcr.io/amakata/sekimore-gw";
pub const BASE_IMAGE: &str = "ghcr.io/amakata/sgw-devcontainer-base";
/// The version this sgw moves a project to: its own.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const INSTALL: &str =
    "curl -fsSL https://github.com/Amakata/sekimore-gw/releases/latest/download/install.sh | sh";

const UPGRADING_EN: &str = include_str!("../../../UPGRADING.md");
const UPGRADING_JA: &str = include_str!("../../../UPGRADING.ja.md");
const TASKS_JA: &str = include_str!("../../../base/share/sgw/tasks.mise.ja.toml");
const GATEWAY_TASKS_JA: &str = include_str!("../../../share/gateway.mise.ja.toml");

/// The distributed files, in the order `upgrade.sh` listed them (MANIFEST keeps that order).
pub const DISTRIBUTED: &[&str] = &[
    "sgw.sh",
    "vscode.sh",
    "upgrade.sh",
    "post-start.sh",
    "tasks.mise.toml",
    "gateway.mise.toml",
];

pub struct Dist {
    pub name: &'static str,
    pub content: &'static str,
    pub executable: bool,
}

/// The distributed files of this version, in `lang` (the two task files have a Japanese twin).
pub fn distributed(lang: &str) -> Vec<Dist> {
    DISTRIBUTED
        .iter()
        .map(|name| {
            let ja = match (lang, *name) {
                ("ja", "tasks.mise.toml") => Some(TASKS_JA),
                ("ja", "gateway.mise.toml") => Some(GATEWAY_TASKS_JA),
                _ => None,
            };
            let t = templates::FILES
                .iter()
                .find(|t| t.path == format!(".devcontainer/sgw/{name}"))
                .unwrap_or_else(|| panic!("{name} is not in the template"));
            Dist {
                name,
                content: ja.unwrap_or(t.content),
                executable: t.executable,
            }
        })
        .collect()
}

pub fn upgrading(lang: &str) -> &'static str {
    if lang == "ja" {
        UPGRADING_JA
    } else {
        UPGRADING_EN
    }
}

// ---- versions -------------------------------------------------------------------------------

fn ver_key(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.split('.').map(|p| p.parse::<u64>().ok());
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some(Some(a)), Some(Some(b)), Some(Some(c)), None) => Some((a, b, c)),
        _ => None,
    }
}

/// `a` is an older version than `b`.
pub fn ver_lt(a: &str, b: &str) -> bool {
    match (ver_key(a), ver_key(b)) {
        (Some(x), Some(y)) => x < y,
        _ => false,
    }
}

/// `image: <GW_IMAGE>:X.Y.Z` in the compose file (quotes and a trailing comment allowed).
pub fn pinned_gateway(compose: &str) -> Option<String> {
    compose.lines().find_map(|line| {
        let l = line.split(" #").next().unwrap_or(line).trim();
        let rest = l.strip_prefix("image:")?.trim().trim_matches(['"', '\'']);
        let v = rest.strip_prefix(&format!("{GW_IMAGE}:"))?;
        ver_key(v).map(|_| v.to_string())
    })
}

/// `FROM [--flag …] <BASE_IMAGE>:X.Y.Z [AS name]` in the Dockerfile.
pub fn pinned_base(dockerfile: &str) -> Option<String> {
    dockerfile.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        if words.next()? != "FROM" {
            return None;
        }
        let image = words.find(|w| !w.starts_with("--"))?;
        let v = image.strip_prefix(&format!("{BASE_IMAGE}:"))?;
        ver_key(v).map(|_| v.to_string())
    })
}

/// `image:from` → `image:to`, only where the version ends where the tag ends: moving 0.2.1 →
/// 0.2.10 must leave an `0.2.19` alone.
pub fn retag(text: &str, image: &str, from: &str, to: &str) -> String {
    let needle = format!("{image}:{from}");
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(&needle) {
        let after = &rest[i + needle.len()..];
        let ends = match after.chars().next() {
            None => true,
            Some(c) => !(c.is_ascii_digit() || c == '.'),
        };
        out.push_str(&rest[..i]);
        if ends {
            out.push_str(&format!("{image}:{to}"));
        } else {
            out.push_str(&needle);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// The UPGRADING sections a move between two pairs of versions crosses. Headings are
/// `## X.Y.Z title` (a gateway version) or `## base X.Y.Z title`; ones inside code fences are
/// text. `body` prints them whole, otherwise only the heading.
pub fn sections(
    upgrading: &str,
    cur_gw: &str,
    new_gw: &str,
    cur_base: &str,
    new_base: &str,
    body: bool,
) -> String {
    let mut out = String::new();
    let mut fence = false;
    let mut on = false;
    for line in upgrading.lines() {
        if line.starts_with("```") {
            fence = !fence;
        }
        if !fence && line.starts_with("## ") {
            on = false;
            let mut words = line[3..].split_whitespace();
            let first = words.next().unwrap_or("");
            let (v, lo, hi) = if first == "base" {
                (words.next().unwrap_or(""), cur_base, new_base)
            } else {
                (first, cur_gw, new_gw)
            };
            if ver_key(v).is_some() && !lo.is_empty() && ver_lt(lo, v) && !ver_lt(hi, v) {
                on = true;
                if !body {
                    out.push_str(&line[3..]);
                    out.push('\n');
                    continue;
                }
            }
        }
        if on && body {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

// ---- MANIFEST -------------------------------------------------------------------------------

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    pub base: String,
    pub gateway: String,
    pub lang: String,
    pub files: BTreeMap<String, String>,
}

impl Manifest {
    pub fn parse(text: &str) -> Manifest {
        let mut m = Manifest::default();
        for line in text.lines() {
            let mut w = line.split_whitespace();
            match (w.next(), w.next(), w.next()) {
                (Some("base"), Some(v), None) => m.base = v.into(),
                (Some("gateway"), Some(v), None) => m.gateway = v.into(),
                (Some("lang"), Some(v), None) => m.lang = v.into(),
                (Some("file"), Some(name), Some(sha)) => {
                    m.files.insert(name.into(), sha.into());
                }
                _ => {}
            }
        }
        m
    }

    /// The text `upgrade.sh` wrote, so the two tools can follow each other.
    pub fn render(base: &str, gateway: &str, lang: &str, files: &[(&str, String)]) -> String {
        let mut s = String::from(
            "# Written by upgrade.sh: what it last put in this directory, so an edit by hand can be told\n# apart from a file it wrote. Do not edit.\n",
        );
        s.push_str(&format!("base {base}\ngateway {gateway}\nlang {lang}\n"));
        for (name, sha) in files {
            s.push_str(&format!("file {name} {sha}\n"));
        }
        s
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The file on disk would lose something if overwritten: it matches neither the file about to
/// replace it nor what MANIFEST says was written.
pub fn edited(current: &[u8], new: &str, manifest_sha: Option<&str>) -> bool {
    let h = sha256_hex(current);
    if h == sha256_hex(new.as_bytes()) {
        return false;
    }
    manifest_sha != Some(h.as_str())
}

/// What the project's own files need; `update` never writes them.
pub fn owned_notes(root: &Path) -> Vec<String> {
    let mut notes = Vec::new();
    let mise = std::fs::read_to_string(root.join("mise.toml")).unwrap_or_default();
    let has_sgw_env = mise.lines().any(|l| {
        let l = l.trim_start();
        l.starts_with("SGW") && l.contains('=') && l.contains(".devcontainer/sgw/sgw.sh")
    });
    if !mise.contains(".devcontainer/sgw/tasks.mise.toml")
        || !mise.contains(".devcontainer/sgw/gateway.mise.toml")
        || !has_sgw_env
    {
        notes.push(format!(
            "{}\n        [task_config]\n        includes = [\".devcontainer/sgw/tasks.mise.toml\", \".devcontainer/sgw/gateway.mise.toml\"]\n        [env]\n        SGW = \"{{{{config_root}}}}/.devcontainer/sgw/sgw.sh\"",
            t("sgw.update.r_include")
        ));
    }
    let dcj =
        std::fs::read_to_string(root.join(".devcontainer/devcontainer.json")).unwrap_or_default();
    if dcj.contains("sekimore-agent-setup") && !dcj.contains(".devcontainer/sgw/post-start.sh") {
        notes.push(format!(
            "{}\n        \"postStartCommand\": \"sh /workspace/.devcontainer/sgw/post-start.sh\",",
            t("sgw.update.r_poststart")
        ));
    }
    let left: Vec<&str> = [
        ".devcontainer/scripts/sgw.sh",
        ".devcontainer/scripts/vscode.sh",
        ".devcontainer/gateway.mise.toml",
    ]
    .into_iter()
    .filter(|p| root.join(p).exists())
    .collect();
    if !left.is_empty() {
        notes.push(tf("sgw.update.r_leftover", &[("files", &left.join(" "))]));
    }
    notes
}

// ---- GHCR: is there a newer release than this sgw? ------------------------------------------

/// The newest `X.Y.Z` among tags (`latest`, `0.2`, `sha256-…`, `0.2.11-rc1` are not versions).
pub fn newest_tag(tags: &[String]) -> Option<String> {
    tags.iter()
        .filter(|t| ver_key(t).is_some())
        .max_by_key(|t| ver_key(t))
        .cloned()
}

/// The `rel="next"` target of a Link header.
pub fn next_link(header: &str) -> Option<String> {
    header.split(',').find_map(|part| {
        let part = part.trim();
        if !part.contains("rel=\"next\"") {
            return None;
        }
        let start = part.find('<')? + 1;
        let end = part.find('>')?;
        Some(part[start..end].to_string())
    })
}

pub async fn newest_on_ghcr(image: &str) -> anyhow::Result<Option<String>> {
    let (host, name) = image.split_once('/').context("image without a registry")?;
    if host != "ghcr.io" {
        bail!(tf("sgw.update.registry", &[("image", image)]));
    }
    let base = std::env::var("SGW_REGISTRY_URL").unwrap_or_else(|_| format!("https://{host}"));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let tok: serde_json::Value = client
        .get(format!("{base}/token?scope=repository:{name}:pull"))
        .send()
        .await?
        .json()
        .await?;
    let token = tok["token"].as_str().unwrap_or("").to_string();
    let mut url = Some(format!("{base}/v2/{name}/tags/list?n=1000"));
    let mut tags: Vec<String> = Vec::new();
    let mut pages = 0;
    while let Some(u) = url.take() {
        if pages >= 50 {
            break;
        }
        pages += 1;
        let resp = client.get(&u).bearer_auth(&token).send().await?;
        let link = resp
            .headers()
            .get("link")
            .and_then(|v| v.to_str().ok())
            .and_then(next_link);
        let body: serde_json::Value = resp.json().await?;
        if let Some(arr) = body["tags"].as_array() {
            tags.extend(arr.iter().filter_map(|t| t.as_str()).map(str::to_string));
        }
        // the token goes with every page, so only ever to this registry
        url = link.and_then(|l| {
            if l.starts_with('/') {
                Some(format!("{base}{l}"))
            } else if l.starts_with(&format!("{base}/")) {
                Some(l)
            } else {
                None
            }
        });
    }
    Ok(newest_tag(&tags))
}

// ---- the run ---------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Check,
    Apply,
    Sync,
    Notes,
    Owned,
}

pub struct Options {
    pub mode: Mode,
    /// `--yes`: recreate the gateway without asking
    pub yes: bool,
    /// `--force`: overwrite a distributed file that was edited by hand
    pub force: bool,
    /// `--offline`: do not ask GHCR whether a newer release exists
    pub offline: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FileState {
    New,
    Same,
    Changes,
    Edited,
}

pub fn run(docker: &Docker, project: &Project, opts: Options) -> anyhow::Result<i32> {
    let root = &project.root;
    let compose_path = project.compose_dir.join("docker-compose.yml");
    let dockerfile_path = project.compose_dir.join("Dockerfile");
    let sgw_dir = project.compose_dir.join("sgw");
    let manifest_path = sgw_dir.join("MANIFEST");
    let rel = |p: &Path| p.strip_prefix(root).unwrap_or(p).display().to_string();
    let l = lang();

    if opts.mode == Mode::Owned {
        return print_owned(root);
    }

    let compose = std::fs::read_to_string(&compose_path).unwrap_or_default();
    let dockerfile = std::fs::read_to_string(&dockerfile_path).unwrap_or_default();
    let cur_gw = pinned_gateway(&compose).ok_or_else(|| {
        anyhow::anyhow!(tf(
            "sgw.update.unpinned",
            &[("image", GW_IMAGE), ("file", &rel(&compose_path))]
        ))
    })?;
    let cur_base = pinned_base(&dockerfile).ok_or_else(|| {
        anyhow::anyhow!(tf(
            "sgw.update.unpinned",
            &[("image", BASE_IMAGE), ("file", &rel(&dockerfile_path))]
        ))
    })?;

    // The version this sgw moves to is its own. A project ahead of it is not walked backwards;
    // a registry ahead of it says "install the newer sgw"
    let (new_gw, new_base) = if opts.mode == Mode::Sync {
        (cur_gw.clone(), cur_base.clone())
    } else {
        let v = VERSION.to_string();
        (
            if ver_lt(&v, &cur_gw) {
                cur_gw.clone()
            } else {
                v.clone()
            },
            if ver_lt(&v, &cur_base) {
                cur_base.clone()
            } else {
                v
            },
        )
    };
    let mut newer_sgw: Option<String> = None;
    if !opts.offline && opts.mode != Mode::Sync {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        match rt.block_on(newest_on_ghcr(GW_IMAGE)) {
            Ok(Some(v)) if ver_lt(VERSION, &v) => newer_sgw = Some(v),
            Ok(_) => {}
            Err(e) => eprintln!(
                "{}",
                tf(
                    "sgw.update.no_newest",
                    &[("image", GW_IMAGE), ("error", &format!("{e:#}"))]
                )
            ),
        }
    }

    let manifest = std::fs::read_to_string(&manifest_path)
        .ok()
        .map(|s| Manifest::parse(&s))
        .unwrap_or_default();
    let orig_lang = if manifest.lang.is_empty() {
        l.to_string()
    } else {
        manifest.lang.clone()
    };

    if opts.mode == Mode::Notes {
        let out = sections(upgrading(l), &cur_gw, &new_gw, &cur_base, &new_base, true);
        if out.trim().is_empty() {
            println!("{}", t("sgw.update.notes_none"));
        } else {
            print!("{out}");
        }
        return Ok(0);
    }

    // ---- the report ----
    let state = |cur: &str, new: &str| {
        if cur == new {
            t("sgw.update.up_to_date")
        } else {
            t("sgw.update.update")
        }
    };
    println!(
        "{:<12} {:<10} {:<10}",
        "",
        t("sgw.update.col_pinned"),
        t("sgw.update.col_newest")
    );
    println!(
        "{:<12} {:<10} {:<10} {}",
        "gateway",
        cur_gw,
        new_gw,
        state(&cur_gw, &new_gw)
    );
    println!(
        "{:<12} {:<10} {:<10} {}",
        "base",
        cur_base,
        new_base,
        state(&cur_base, &new_base)
    );
    if let Some(v) = &newer_sgw {
        println!(
            "{}",
            tf(
                "sgw.update.newer_sgw",
                &[("version", v), ("sgw", VERSION), ("install", INSTALL)]
            )
        );
    }
    println!();
    let at = if opts.mode == Mode::Sync {
        t("sgw.update.at_pinned")
    } else {
        t("sgw.update.at_newest")
    };
    println!("{}", tf("sgw.update.files_at", &[("at", &at)]));
    if orig_lang != l {
        println!(
            "  {}",
            tf(
                "sgw.update.lang_changed",
                &[("from", &orig_lang), ("to", l)]
            )
        );
    }
    let dist = distributed(l);
    let mut states: Vec<(&Dist, FileState)> = Vec::new();
    for d in &dist {
        let path = sgw_dir.join(d.name);
        let st = match std::fs::read(&path) {
            Err(_) => FileState::New,
            Ok(cur) => {
                if sha256_hex(&cur) == sha256_hex(d.content.as_bytes()) {
                    FileState::Same
                } else if edited(
                    &cur,
                    d.content,
                    manifest.files.get(d.name).map(String::as_str),
                ) {
                    FileState::Edited
                } else {
                    FileState::Changes
                }
            }
        };
        let word = match st {
            FileState::New => t("sgw.update.f_new"),
            FileState::Same => t("sgw.update.f_same"),
            FileState::Changes => t("sgw.update.f_changes"),
            FileState::Edited => {
                if opts.force {
                    t("sgw.update.f_forced")
                } else {
                    t("sgw.update.f_edited")
                }
            }
        };
        println!("  {:<20} {word}", d.name);
        states.push((d, st));
    }
    println!();
    let notes = sections(upgrading(l), &cur_gw, &new_gw, &cur_base, &new_base, false);
    if notes.trim().is_empty() {
        println!("{}", t("sgw.update.notes_none"));
    } else {
        println!("{}", t("sgw.update.notes_hdr"));
        for line in notes.lines() {
            println!("  {line}");
        }
    }
    println!();

    let files_sha: Vec<(&str, String)> = dist
        .iter()
        .map(|d| (d.name, sha256_hex(d.content.as_bytes())))
        .collect();
    let new_manifest = Manifest::render(&new_base, &new_gw, l, &files_sha);
    let changed: Vec<&str> = states
        .iter()
        .filter(|(_, s)| matches!(s, FileState::New | FileState::Changes))
        .map(|(d, _)| d.name)
        .collect();
    let edited_files: Vec<&str> = states
        .iter()
        .filter(|(_, s)| *s == FileState::Edited)
        .map(|(d, _)| d.name)
        .collect();
    let up_to_date = cur_gw == new_gw
        && cur_base == new_base
        && changed.is_empty()
        && edited_files.is_empty()
        && std::fs::read_to_string(&manifest_path).ok().as_deref() == Some(new_manifest.as_str());

    if opts.mode == Mode::Check {
        let owned = owned_notes(root);
        if !owned.is_empty() {
            println!("{}", t("sgw.update.owned_hdr"));
            for n in &owned {
                println!("  - {n}");
            }
            println!();
        }
        if up_to_date {
            println!("{}", t("sgw.update.all_current"));
        } else if !edited_files.is_empty() && !opts.force {
            println!("{}", t("sgw.update.next_edited"));
        } else if newer_sgw.is_some() && cur_gw == new_gw {
            println!("{}", tf("sgw.update.next_sgw", &[("install", INSTALL)]));
        } else {
            println!("{}", t("sgw.update.next_apply"));
        }
        return Ok(0);
    }

    // ---- apply / sync ----
    if !edited_files.is_empty() && !opts.force {
        for f in &edited_files {
            eprintln!("{}", tf("sgw.update.edited_stop", &[("file", f)]));
        }
        eprintln!("{}", t("sgw.update.edited_how"));
        eprintln!("{}", t("sgw.update.unchanged"));
        return Ok(1);
    }
    if opts.mode == Mode::Apply && newer_sgw.is_some() && cur_gw == new_gw {
        // nothing this sgw can render is newer than what the project has
        println!("{}", tf("sgw.update.next_sgw", &[("install", INSTALL)]));
        return Ok(0);
    }
    let mut remain: Vec<String> = Vec::new();
    if up_to_date {
        println!("{}", t("sgw.update.all_current"));
    } else {
        if cur_gw != new_gw {
            write_in_place(&compose_path, &retag(&compose, GW_IMAGE, &cur_gw, &new_gw))?;
            println!(
                "{}",
                tf(
                    "sgw.update.tag",
                    &[
                        ("what", "gateway"),
                        ("from", &cur_gw),
                        ("to", &new_gw),
                        ("file", &rel(&compose_path))
                    ]
                )
            );
        }
        if cur_base != new_base {
            write_in_place(
                &dockerfile_path,
                &retag(&dockerfile, BASE_IMAGE, &cur_base, &new_base),
            )?;
            println!(
                "{}",
                tf(
                    "sgw.update.tag",
                    &[
                        ("what", "base"),
                        ("from", &cur_base),
                        ("to", &new_base),
                        ("file", &rel(&dockerfile_path))
                    ]
                )
            );
        }
        std::fs::create_dir_all(&sgw_dir)?;
        for (d, st) in &states {
            if *st == FileState::Same {
                continue;
            }
            write_atomic(&sgw_dir, d.name, d.content.as_bytes(), d.executable)?;
            println!("{}", tf("sgw.update.wrote", &[("file", d.name)]));
        }
        write_atomic(&sgw_dir, "MANIFEST", new_manifest.as_bytes(), false)?;
    }
    println!();

    if opts.mode == Mode::Apply && cur_gw != new_gw {
        if docker.find_container(GATEWAY).is_ok() {
            let go = opts.yes || ask(&tf("sgw.update.ask_recreate", &[("version", &new_gw)]));
            if go {
                let rc = super::ops::recreate(docker, &project.name(), false).unwrap_or(1);
                if rc != 0 {
                    remain.push(t("sgw.update.r_unlock"));
                }
            } else {
                remain.push(t("sgw.update.r_recreate"));
                remain.push(t("sgw.update.r_unlock"));
            }
        } else {
            remain.push(tf("sgw.update.r_gw_down", &[("version", &new_gw)]));
        }
    }
    if opts.mode == Mode::Apply && cur_base != new_base {
        remain.push(tf("sgw.update.r_rebuild", &[("version", &new_base)]));
    }
    if !notes.trim().is_empty() {
        remain.push(t("sgw.update.r_notes"));
    }
    if !up_to_date {
        remain.push(t("sgw.update.r_commit"));
    }
    remain.extend(owned_notes(root));
    println!("{}", t("sgw.update.remain"));
    if remain.is_empty() {
        println!("  {}", t("sgw.update.r_none"));
    } else {
        for r in &remain {
            println!("  - {r}");
        }
    }
    Ok(0)
}

fn print_owned(root: &Path) -> anyhow::Result<i32> {
    let owned = owned_notes(root);
    if owned.is_empty() {
        println!("{}", t("sgw.update.owned_none"));
    } else {
        println!("{}", t("sgw.update.owned_hdr"));
        for n in &owned {
            println!("  - {n}");
        }
    }
    Ok(0)
}

/// Written in place (open for writing, not replaced), which keeps the file's owner and mode.
fn write_in_place(path: &Path, text: &str) -> anyhow::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("write {}", path.display()))?;
    f.write_all(text.as_bytes())?;
    Ok(())
}

/// A temporary name beside the file, then a rename over it: atomic, and it leaves an old
/// `upgrade.sh`'s inode to any bash still reading it.
fn write_atomic(dir: &Path, name: &str, content: &[u8], executable: bool) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = dir.join(format!(".{name}.new"));
    std::fs::write(&tmp, content).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::set_permissions(
        &tmp,
        std::fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
    )?;
    std::fs::rename(&tmp, dir.join(name))
        .with_context(|| format!("rename to {}", dir.join(name).display()))?;
    Ok(())
}

fn ask(prompt: &str) -> bool {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return false;
    }
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pins_are_read_the_way_upgrade_sh_read_them() {
        let compose = "services:\n  sekimore-gw:\n    image: \"ghcr.io/amakata/sekimore-gw:0.2.46\"   # pinned\n";
        assert_eq!(pinned_gateway(compose).as_deref(), Some("0.2.46"));
        assert_eq!(
            pinned_gateway("    image: ghcr.io/amakata/sekimore-gw:latest\n"),
            None
        );
        assert_eq!(
            pinned_gateway("    image: ghcr.io/amakata/sekimore-gw@sha256:abc\n"),
            None
        );
        assert_eq!(
            pinned_base("FROM ghcr.io/amakata/sgw-devcontainer-base:0.2.46 AS dev\n").as_deref(),
            Some("0.2.46")
        );
        assert_eq!(
            pinned_base(
                "FROM --platform=linux/arm64 ghcr.io/amakata/sgw-devcontainer-base:0.2.9\n"
            )
            .as_deref(),
            Some("0.2.9")
        );
        assert_eq!(pinned_base("FROM python:3.13\n"), None);
    }

    #[test]
    fn retag_stops_where_the_version_ends() {
        let s = "a: ghcr.io/amakata/sekimore-gw:0.2.1\nb: ghcr.io/amakata/sekimore-gw:0.2.19 # keep\nc: \"ghcr.io/amakata/sekimore-gw:0.2.1\"\n";
        let out = retag(s, GW_IMAGE, "0.2.1", "0.2.10");
        assert_eq!(out, "a: ghcr.io/amakata/sekimore-gw:0.2.10\nb: ghcr.io/amakata/sekimore-gw:0.2.19 # keep\nc: \"ghcr.io/amakata/sekimore-gw:0.2.10\"\n");
    }

    #[test]
    fn versions_compare_numerically() {
        assert!(ver_lt("0.2.9", "0.2.10"));
        assert!(!ver_lt("0.2.10", "0.2.9"));
        assert!(!ver_lt("0.2.10", "0.2.10"));
        assert!(!ver_lt("latest", "0.2.10"));
        assert_eq!(
            newest_tag(
                &[
                    "0.2.1",
                    "0.2.9",
                    "0.2.10",
                    "0.2",
                    "latest",
                    "0.2.11-rc1",
                    "sha256-abc"
                ]
                .map(String::from)
            )
            .as_deref(),
            Some("0.2.10")
        );
        assert_eq!(newest_tag(&[]), None);
    }

    #[test]
    fn the_sections_between_two_versions_and_no_others() {
        let upg = "# Upgrading\n## 0.2.1 old\nbody-0.2.1\n## 0.2.9 nine\nbody-0.2.9\n```bash\n## 0.2.9 not a heading\n```\n## 0.2.10 ten\nbody-0.2.10\n## 0.2.11 eleven\nbody-0.2.11\n## base 0.2.19 b19\n## base 0.2.20 b20\nbody-b20\n";
        let heads = sections(upg, "0.2.1", "0.2.10", "0.2.19", "0.2.20", false);
        assert_eq!(heads, "0.2.9 nine\n0.2.10 ten\nbase 0.2.20 b20\n");
        let body = sections(upg, "0.2.1", "0.2.10", "0.2.19", "0.2.20", true);
        assert!(
            body.contains("body-0.2.9")
                && body.contains("## 0.2.9 not a heading")
                && body.contains("body-b20")
        );
        assert!(
            !body.contains("body-0.2.1\n") && !body.contains("body-0.2.11"),
            "{body}"
        );
        assert_eq!(
            sections(upg, "0.2.10", "0.2.10", "0.2.20", "0.2.20", false),
            ""
        );
    }

    #[test]
    fn manifest_round_trips_and_edits_are_told_apart() {
        let text = Manifest::render(
            "0.2.46",
            "0.2.46",
            "en",
            &[("sgw.sh", "aa".into()), ("upgrade.sh", "bb".into())],
        );
        let m = Manifest::parse(&text);
        assert_eq!(m.base, "0.2.46");
        assert_eq!(m.lang, "en");
        assert_eq!(m.files.get("upgrade.sh").map(String::as_str), Some("bb"));
        let written = "echo old\n";
        let sha = sha256_hex(written.as_bytes());
        assert!(
            !edited(written.as_bytes(), "echo new\n", Some(&sha)),
            "as written: not edited"
        );
        assert!(
            !edited("echo new\n".as_bytes(), "echo new\n", None),
            "already the new one"
        );
        assert!(
            edited("echo mine\n".as_bytes(), "echo new\n", Some(&sha)),
            "neither: edited"
        );
        assert!(
            edited("echo mine\n".as_bytes(), "echo new\n", None),
            "no manifest to vouch for it"
        );
    }

    #[test]
    fn the_distributed_files_of_this_version_in_both_languages() {
        let en = distributed("en");
        assert_eq!(en.iter().map(|d| d.name).collect::<Vec<_>>(), DISTRIBUTED);
        assert!(en.iter().find(|d| d.name == "sgw.sh").unwrap().executable);
        let ja = distributed("ja");
        let t_en = en
            .iter()
            .find(|d| d.name == "tasks.mise.toml")
            .unwrap()
            .content;
        let t_ja = ja
            .iter()
            .find(|d| d.name == "tasks.mise.toml")
            .unwrap()
            .content;
        assert_ne!(t_en, t_ja);
        assert_eq!(
            en.iter().find(|d| d.name == "sgw.sh").unwrap().content,
            ja.iter().find(|d| d.name == "sgw.sh").unwrap().content
        );
        assert!(upgrading("en").starts_with("<!-- reviewed-up-to:"));
        assert!(upgrading("ja").contains("更新"));
    }

    #[test]
    fn the_next_page_comes_out_of_the_link_header() {
        assert_eq!(
            next_link("</v2/amakata/x/tags/list?last=y&n=1000>; rel=\"next\"").as_deref(),
            Some("/v2/amakata/x/tags/list?last=y&n=1000")
        );
        assert_eq!(
            next_link("<https://other/x>; rel=\"prev\", </v2/x?last=1>; rel=\"next\"").as_deref(),
            Some("/v2/x?last=1")
        );
        assert_eq!(next_link(""), None);
    }

    #[test]
    fn owned_notes_name_what_the_project_files_lack() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(".devcontainer/scripts")).unwrap();
        std::fs::write(root.join("mise.toml"), "[tasks]\n").unwrap();
        std::fs::write(root.join(".devcontainer/devcontainer.json"), "{\"postStartCommand\": \"sudo --preserve-env=X /usr/local/bin/sekimore-agent-setup.sh\"}").unwrap();
        std::fs::write(root.join(".devcontainer/scripts/sgw.sh"), "").unwrap();
        let notes = owned_notes(root);
        assert_eq!(notes.len(), 3, "{notes:?}");
        assert!(notes[0].contains("includes = "));
        assert!(notes[1].contains("post-start.sh"));
        assert!(notes[2].contains(".devcontainer/scripts/sgw.sh"));
        // the template's own files need nothing
        let tmp = tempfile::tempdir().unwrap();
        templates::write(tmp.path(), false).unwrap();
        assert!(owned_notes(tmp.path()).is_empty());
    }
}
