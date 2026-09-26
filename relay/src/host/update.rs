//! `sgw update`: keep a project's gateway, base image and `.devcontainer/sgw/` current — the
//! former `upgrade.sh`, with one difference that removes most of it: what is written is
//! embedded. This build of `sgw` carries the template of its own version and its UPGRADING, so
//! the only question that needs the network is "is there a release newer than this sgw?", and
//! the answer to that is "install the newer sgw first", never a file fetched from a tag.
//!
//! The project's own files (`mise.toml`, `devcontainer.json`, `config.yml`) are never written:
//! what they need is said at the end, the way `upgrade.sh --owned` did.

use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context};

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
/// The files the mise-era `.devcontainer/sgw/` held (`upgrade.sh` wrote them). The migration
/// removes that directory only when it holds nothing else.
pub const OLD_DISTRIBUTED: &[&str] = &[
    "sgw.sh",
    "vscode.sh",
    "upgrade.sh",
    "post-start.sh",
    "tasks.mise.toml",
    "gateway.mise.toml",
    "MANIFEST",
];

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

// ---- the template's files -------------------------------------------------------------------

pub use super::sgwtoml::{sha256_hex, SgwToml};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileState {
    /// the file is this version's
    Same,
    /// the file is as sgw wrote it and this version changes it: overwritten
    Changes,
    /// the file was edited and this version does not change it: left alone
    Yours,
    /// the file was edited and this version changes it too: `.sgw-new` beside it (--force overwrites)
    Conflict,
    /// the file is not there (a project may leave one out on purpose): left alone
    Missing,
}

/// Three shas decide: `recorded` (sgw.toml, what sgw wrote last), `current` (disk), `new` (this
/// version). No record is read as "this version is the baseline": a project that never had
/// sgw.toml keeps its files, and only a later change to the template is a conflict.
pub fn file_state(recorded: Option<&str>, current: Option<&str>, new: &str) -> FileState {
    let Some(cur) = current else {
        return FileState::Missing;
    };
    if cur == new {
        return FileState::Same;
    }
    match recorded {
        None => FileState::Yours,
        Some(r) if r == new => FileState::Yours,
        Some(r) if r == cur => FileState::Changes,
        Some(_) => FileState::Conflict,
    }
}

/// mise.toml without the lines the mise layer needed: the includes of `.devcontainer/sgw/` and
/// the `SGW` path. The project's own tasks stay. None when nothing had to go.
pub fn mise_without_sgw(text: &str) -> Option<String> {
    let mut out = String::new();
    let mut dropped = false;
    for line in text.lines() {
        let t = line.trim_start();
        let is_include = t.starts_with("includes") && t.contains(".devcontainer/sgw/");
        let is_sgw = t.starts_with("SGW") && t.contains(".devcontainer/sgw/sgw.sh");
        if is_include || is_sgw {
            dropped = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if dropped {
        Some(out)
    } else {
        None
    }
}

/// Only comments, blank lines and table headers: nothing of the project's own.
pub fn mise_has_nothing_own(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .all(|l| l.is_empty() || l.starts_with('#') || (l.starts_with('[') && l.ends_with(']')))
}

/// Whether the compose file's `sekimore-gw` service has `pid: host`. Without it the gateway
/// runs, but cannot add the host-side rules that confine dev (UPGRADING 0.2.37), and a project
/// whose pins were raised past 0.2.37 without that step is caught by nothing but `sgw verify`.
/// A line-level read of the service block: no YAML parser, the same as `pinned_gateway`.
pub fn compose_has_pid_host(compose: &str) -> bool {
    let mut in_service: Option<usize> = None;
    for line in compose.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - trimmed.len();
        match in_service {
            None => {
                if trimmed.trim_end() == "sekimore-gw:" {
                    in_service = Some(indent);
                }
            }
            Some(svc) => {
                if indent <= svc {
                    return false;
                }
                let key = trimmed.split('#').next().unwrap_or("").trim();
                if key == "pid: host" || key == "pid: \"host\"" || key == "pid: 'host'" {
                    return true;
                }
            }
        }
    }
    false
}

/// What the project's own files need; `update` never writes them.
pub fn owned_notes(root: &Path) -> Vec<String> {
    let mut notes = Vec::new();
    let compose =
        std::fs::read_to_string(root.join(".devcontainer/docker-compose.yml")).unwrap_or_default();
    if compose.contains("sekimore-gw:") && !compose_has_pid_host(&compose) {
        notes.push(format!(
            "{}\n        services:\n          sekimore-gw:\n            pid: host",
            t("sgw.update.r_pid_host")
        ));
    }
    let mise = std::fs::read_to_string(root.join("mise.toml")).unwrap_or_default();
    if mise.contains(".devcontainer/sgw/") {
        notes.push(t("sgw.update.r_include"));
    }
    let dcj =
        std::fs::read_to_string(root.join(".devcontainer/devcontainer.json")).unwrap_or_default();
    if (dcj.contains("sekimore-agent-setup") || dcj.contains(".devcontainer/sgw/post-start.sh"))
        && !dcj.contains("sgw-post-start")
    {
        notes.push(format!(
            "{}\n        \"postStartCommand\": \"sgw-post-start\",",
            t("sgw.update.r_poststart")
        ));
    }
    let left: Vec<&str> = [
        ".devcontainer/sgw",
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
    Notes,
    Owned,
}

pub struct Options {
    pub mode: Mode,
    /// `--yes`: recreate the gateway without asking
    pub yes: bool,
    /// `--force`: overwrite a template file the project edited when this version changes it too
    pub force: bool,
    /// `--offline`: do not ask GHCR whether a newer release exists
    pub offline: bool,
}

pub fn run(docker: &Docker, project: &Project, opts: Options) -> anyhow::Result<i32> {
    let root = &project.root;
    let compose_path = project.compose_dir.join("docker-compose.yml");
    let dockerfile_path = project.compose_dir.join("Dockerfile");
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
    let (new_gw, new_base) = {
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
    if !opts.offline {
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

    let toml_path = root.join(super::sgwtoml::NAME);
    let recorded = std::fs::read_to_string(&toml_path)
        .ok()
        .map(|s| SgwToml::parse(&s));

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
    println!("{}", t("sgw.update.files_hdr"));
    let mut states: Vec<(&templates::Template, FileState, String)> = Vec::new();
    for tpl in templates::FILES {
        let current = std::fs::read(root.join(tpl.path))
            .ok()
            .map(|b| sha256_hex(&b));
        let new = sha256_hex(tpl.content.as_bytes());
        let rec = recorded
            .as_ref()
            .and_then(|r| r.files.get(tpl.path))
            .map(String::as_str);
        let st = file_state(rec, current.as_deref(), &new);
        let word = match st {
            FileState::Same => t("sgw.update.f_same"),
            FileState::Changes => t("sgw.update.f_changes"),
            FileState::Yours => t("sgw.update.f_yours"),
            FileState::Conflict => {
                if opts.force {
                    t("sgw.update.f_forced")
                } else {
                    t("sgw.update.f_conflict")
                }
            }
            FileState::Missing => t("sgw.update.f_missing"),
        };
        println!("  {:<46} {word}", tpl.path);
        states.push((tpl, st, new));
    }
    // the mise layer, where a project still has it
    let old_dir = project.compose_dir.join("sgw");
    let migrate = old_dir.is_dir();
    let mut foreign: Vec<String> = Vec::new();
    if migrate {
        for e in std::fs::read_dir(&old_dir)? {
            let name = e?.file_name().to_string_lossy().into_owned();
            if !OLD_DISTRIBUTED.contains(&name.as_str()) {
                foreign.push(name);
            }
        }
        foreign.sort();
        println!("  {}", t("sgw.update.m_dir"));
        if !foreign.is_empty() {
            println!(
                "  {}",
                tf("sgw.update.m_foreign", &[("files", &foreign.join(" "))])
            );
        }
    }
    let mise_path = root.join("mise.toml");
    let mise_new = std::fs::read_to_string(&mise_path)
        .ok()
        .and_then(|text| mise_without_sgw(&text));
    if mise_new.is_some() {
        println!("  {}", t("sgw.update.m_mise"));
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

    let to_write: Vec<&templates::Template> = states
        .iter()
        .filter(|(_, st, _)| {
            *st == FileState::Changes || (*st == FileState::Conflict && opts.force)
        })
        .map(|(tpl, _, _)| *tpl)
        .collect();
    let conflicts: Vec<&templates::Template> = states
        .iter()
        .filter(|(_, st, _)| *st == FileState::Conflict && !opts.force)
        .map(|(tpl, _, _)| *tpl)
        .collect();
    let toml_new = SgwToml {
        version: VERSION.to_string(),
        files: states
            .iter()
            .filter(|(_, st, _)| *st != FileState::Missing)
            .map(|(tpl, _, new)| (tpl.path.to_string(), new.clone()))
            .collect(),
    };
    let up_to_date = cur_gw == new_gw
        && cur_base == new_base
        && to_write.is_empty()
        && conflicts.is_empty()
        && !migrate
        && mise_new.is_none()
        && std::fs::read_to_string(&toml_path).ok().as_deref() == Some(toml_new.render().as_str());

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
        } else if newer_sgw.is_some() && cur_gw == new_gw {
            println!("{}", tf("sgw.update.next_sgw", &[("install", INSTALL)]));
        } else {
            println!("{}", t("sgw.update.next_apply"));
        }
        return Ok(0);
    }

    // ---- apply ----
    if migrate && !foreign.is_empty() {
        eprintln!(
            "{}",
            tf(
                "sgw.update.m_foreign_stop",
                &[("files", &foreign.join(" "))]
            )
        );
        eprintln!("{}", t("sgw.update.unchanged"));
        return Ok(1);
    }
    if newer_sgw.is_some() && cur_gw == new_gw {
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
        for tpl in &to_write {
            write_file(&root.join(tpl.path), tpl.content.as_bytes(), tpl.executable)?;
            println!("{}", tf("sgw.update.wrote", &[("file", tpl.path)]));
        }
        for tpl in &conflicts {
            let beside = format!("{}.sgw-new", tpl.path);
            write_file(&root.join(&beside), tpl.content.as_bytes(), tpl.executable)?;
            println!("{}", tf("sgw.update.wrote", &[("file", &beside)]));
            remain.push(tf("sgw.update.r_sgw_new", &[("file", tpl.path)]));
        }
        if migrate {
            std::fs::remove_dir_all(&old_dir)
                .with_context(|| format!("remove {}", old_dir.display()))?;
            println!("{}", t("sgw.update.m_removed"));
        }
        if let Some(text) = &mise_new {
            write_in_place(&mise_path, text)?;
            println!("{}", t("sgw.update.m_mise_done"));
            if mise_has_nothing_own(text) {
                remain.push(t("sgw.update.r_mise_empty"));
            }
        }
        write_file(&toml_path, toml_new.render().as_bytes(), false)?;
        println!(
            "{}",
            tf("sgw.update.wrote", &[("file", super::sgwtoml::NAME)])
        );
    }
    println!();

    if cur_gw != new_gw {
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
    if cur_base != new_base {
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

/// A temporary name beside the file, then a rename over it: atomic.
fn write_file(path: &Path, content: &[u8], executable: bool) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.new"));
    std::fs::write(&tmp, content).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::set_permissions(
        &tmp,
        std::fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
    )?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
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
    fn three_shas_decide_what_update_does_with_a_file() {
        use FileState::*;
        assert_eq!(file_state(None, None, "n"), Missing);
        assert_eq!(file_state(Some("n"), Some("n"), "n"), Same);
        assert_eq!(
            file_state(Some("old"), Some("old"), "n"),
            Changes,
            "as written, template changed"
        );
        assert_eq!(
            file_state(Some("n"), Some("mine"), "n"),
            Yours,
            "edited, template unchanged"
        );
        assert_eq!(
            file_state(None, Some("mine"), "n"),
            Yours,
            "no record: this version is the baseline"
        );
        assert_eq!(
            file_state(Some("old"), Some("mine"), "n"),
            Conflict,
            "edited and changed"
        );
    }

    #[test]
    fn the_mise_layer_leaves_mise_toml_and_the_projects_tasks_stay() {
        let text = "# mine\n[task_config]\nincludes = [\".devcontainer/sgw/tasks.mise.toml\", \".devcontainer/sgw/gateway.mise.toml\"]\n\n[env]\nSGW = \"{{config_root}}/.devcontainer/sgw/sgw.sh\"\n\n[tasks.mine]\nrun = \"echo\"\n";
        let out = mise_without_sgw(text).unwrap();
        assert_eq!(
            out,
            "# mine\n[task_config]\n\n[env]\n\n[tasks.mine]\nrun = \"echo\"\n"
        );
        assert!(!mise_has_nothing_own(&out));
        assert!(mise_has_nothing_own("# only\n[task_config]\n\n[env]\n"));
        assert_eq!(mise_without_sgw("[tasks.mine]\nrun = \"echo\"\n"), None);
    }

    #[test]
    fn upgrading_is_embedded_in_both_languages() {
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
    fn pid_host_is_read_off_the_gateway_service_alone() {
        let template =
            include_str!("../../templates/devcontainer/.devcontainer/docker-compose.yml");
        assert!(compose_has_pid_host(template));
        assert!(compose_has_pid_host(
            "services:\n  dev:\n    image: d\n  sekimore-gw:\n    image: g\n    pid: host   # rules\n"
        ));
        assert!(compose_has_pid_host(
            "services:\n  sekimore-gw:\n    pid: \"host\"\n"
        ));
        // on the wrong service, commented out, or absent
        assert!(!compose_has_pid_host(
            "services:\n  dev:\n    pid: host\n  sekimore-gw:\n    image: g\n"
        ));
        assert!(!compose_has_pid_host(
            "services:\n  sekimore-gw:\n    image: g\n    # pid: host\n"
        ));
        assert!(!compose_has_pid_host(
            "services:\n  sekimore-gw:\n    image: g\n"
        ));
        assert!(!compose_has_pid_host(""));
    }

    #[test]
    fn owned_notes_name_what_the_project_files_lack() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(".devcontainer/scripts")).unwrap();
        std::fs::write(
            root.join("mise.toml"),
            "[task_config]\nincludes = [\".devcontainer/sgw/tasks.mise.toml\"]\n",
        )
        .unwrap();
        std::fs::write(root.join(".devcontainer/devcontainer.json"), "{\"postStartCommand\": \"sudo --preserve-env=X /usr/local/bin/sekimore-agent-setup.sh\"}").unwrap();
        std::fs::write(root.join(".devcontainer/scripts/sgw.sh"), "").unwrap();
        std::fs::write(
            root.join(".devcontainer/docker-compose.yml"),
            "services:\n  sekimore-gw:\n    image: x\n  dev:\n    pid: host\n",
        )
        .unwrap();
        let notes = owned_notes(root);
        assert_eq!(notes.len(), 4, "{notes:?}");
        assert!(notes[0].contains("pid: host"), "{}", notes[0]);
        // the wording is the locale's; the path is in both
        assert!(notes[1].contains(".devcontainer/sgw/"), "{}", notes[1]);
        assert!(notes[2].contains("sgw-post-start"), "{}", notes[2]);
        assert!(notes[3].contains(".devcontainer/scripts/sgw.sh"));
        // the template's own files need nothing
        let tmp = tempfile::tempdir().unwrap();
        templates::write(tmp.path(), false).unwrap();
        assert!(owned_notes(tmp.path()).is_empty());
    }
}
