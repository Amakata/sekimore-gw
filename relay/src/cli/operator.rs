//! Operator-facing subcommands (run inside the gateway container).

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context};

use super::BootstrapAction;
use russh::keys::PublicKey;

use crate::audit::{Actor, Audit};
use crate::config::{self, ConfigError, HandlerKind, Resolved, Upstream};
use crate::fsutil::{atomic_write, ensure_dir_0700, read_optional};
use crate::git::agent_check::{auth_sock_from_env, preflight_agent};
use crate::git::upstream_ssh::OpenSshUpstream;
use crate::github::device_flow::DeviceFlow;
use crate::github::http::{build_client, HttpOptions};
use crate::github::upstream_token::UpstreamTokenStore;
use crate::github::GitHub;
use crate::i18n::{t, tf};
use crate::policy::all_permission_keys;
use crate::ssh::authorized_keys::{fingerprint, Added, AuthorizedKeys};
use crate::tokens::TokenStore;

pub const DEVICE_FLOW_SCOPES: &[&str] = &["repo", "project"];

/// Pad a label to `width` display columns (CJK characters count as two).
fn pad_label(label: &str, width: usize) -> String {
    let shown: usize = label.chars().map(|c| if is_wide(c) { 2 } else { 1 }).sum();
    let mut out = label.to_string();
    for _ in shown..width {
        out.push(' ');
    }
    out
}

/// Rough East Asian Wide / Fullwidth test, enough for the labels we print.
fn is_wide(c: char) -> bool {
    matches!(c as u32,
        0x1100..=0x115F | 0x2E80..=0x303E | 0x3041..=0x33FF | 0x3400..=0x4DBF
        | 0x4E00..=0x9FFF | 0xA000..=0xA4CF | 0xAC00..=0xD7A3 | 0xF900..=0xFAFF
        | 0xFE30..=0xFE6F | 0xFF00..=0xFF60 | 0xFFE0..=0xFFE6 | 0x20000..=0x3FFFD)
}

/// For entrypoint.sh. 0 = start / 1 = not needed / 2 = invalid configuration.
pub fn needs_relay(path: &Path) -> anyhow::Result<i32> {
    let loaded = match config::load(path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("sekimore-relay: {e}");
            return Ok(2);
        }
    };
    match loaded.needs_relay() {
        Ok(true) => Ok(0),
        Ok(false) => Ok(1),
        Err(e) => {
            eprintln!("sekimore-relay: {e}");
            Ok(2)
        }
    }
}

pub fn resolve(path: &Path) -> anyhow::Result<Resolved> {
    let loaded = config::load(path)?;
    match loaded.resolve() {
        Ok(r) => Ok(r),
        Err(ConfigError::NoGitRelayDomain) => bail!(
            "{} has no domain_handlers entry with handler: git-relay; add one (and a relay: section) before using the relay",
            path.display()
        ),
        Err(e) => Err(e.into()),
    }
}

pub fn open_audit(r: &Resolved) -> anyhow::Result<Arc<Audit>> {
    ensure_dir_0700(&r.paths.state_dir)
        .with_context(|| format!("state dir {}", r.paths.state_dir.display()))?;
    Ok(Arc::new(Audit::new(Some(&r.paths.audit), false)?))
}

/// GitHub client for one upstream (api_base / graphql_base / upstream_token are that upstream's. 0.2.0).
pub fn build_github_for(
    r: &Resolved,
    up: &Upstream,
    audit: Arc<Audit>,
) -> anyhow::Result<(Arc<GitHub>, Arc<UpstreamTokenStore>, reqwest::Client)> {
    let http = build_client(&HttpOptions {
        ca_file: r.relay.ca_file.as_deref(),
        proxy: r.proxy.as_ref(),
        ..Default::default()
    })?;
    if let Some(dir) = up.upstream_token.parent() {
        ensure_dir_0700(dir).with_context(|| format!("upstream state dir {}", dir.display()))?;
    }
    let store = Arc::new(UpstreamTokenStore::new(
        &up.upstream_token,
        r.relay.upstream_token_cache_ttl,
    ));
    let gh = Arc::new(GitHub::new(
        up.api_base.clone(),
        up.graphql_base.clone(),
        http.clone(),
        store.clone(),
        audit,
    ));
    Ok((gh, store, http))
}

/// Resolves `--upstream`, defaulting to the default upstream when omitted.
pub fn pick_upstream<'a>(r: &'a Resolved, name: Option<&str>) -> anyhow::Result<&'a Upstream> {
    match name {
        None => Ok(r.default_upstream()),
        Some(n) => r.upstream_named(n).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown upstream {n:?}; git-relay domains are: {}",
                r.upstreams
                    .iter()
                    .map(|u| u.domain.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }),
    }
}

pub async fn login(path: &Path, upstream: Option<&str>) -> anyhow::Result<()> {
    let r = resolve(path)?;
    let up = pick_upstream(&r, upstream)?.clone();
    let audit = open_audit(&r)?;
    let (gh, store, http) = build_github_for(&r, &up, audit.clone())?;
    if r.upstreams.len() > 1 {
        let mark = if up.is_default {
            t("op.login.default_mark")
        } else {
            String::new()
        };
        println!(
            "{}",
            tf(
                "op.login.upstream",
                &[
                    ("domain", &up.domain),
                    ("host", &up.host),
                    ("default", &mark),
                ]
            )
        );
    }
    let flow = DeviceFlow::new(&up.host, &up.oauth_client_id, DEVICE_FLOW_SCOPES, http)?;
    let (token, scope) = flow
        .authenticate(|code, url| {
            println!();
            println!("{}", tf("op.login.open", &[("url", url)]));
            println!("{}", tf("op.login.code", &[("code", code)]));
            println!();
        })
        .await?;
    store.save(&up.host, &token, &scope)?;
    println!(
        "{}",
        tf(
            "op.login.stored",
            &[
                ("path", &up.upstream_token.display().to_string()),
                ("scopes", &scope)
            ]
        )
    );
    audit.log(
        "login",
        Actor::Operator,
        &[
            ("host", &up.host),
            ("domain", &up.domain),
            ("scopes", &scope),
        ],
    );

    match gh.meta_ssh_keys().await {
        Ok(keys) if !keys.is_empty() => {
            let n = merge_known_hosts(&up.known_hosts, &up.host, up.upstream_ssh_port, &keys)?;
            println!(
                "{}",
                tf(
                    "op.login.known_hosts",
                    &[
                        ("n", &keys.len().to_string()),
                        ("host", &up.host),
                        ("new", &n.to_string()),
                        ("path", &up.known_hosts.display().to_string()),
                    ]
                )
            );
        }
        Ok(_) => eprintln!(
            "{}",
            tf(
                "op.login.no_meta_keys",
                &[("path", &up.known_hosts.display().to_string())]
            )
        ),
        Err(e) => eprintln!(
            "{}",
            tf(
                "op.login.meta_failed",
                &[
                    ("error", &e.to_string()),
                    ("path", &up.known_hosts.display().to_string())
                ]
            )
        ),
    }
    match gh.whoami().await {
        Ok(login) => println!("{}", tf("op.login.identity", &[("login", &login)])),
        Err(e) => eprintln!(
            "{}",
            tf("op.login.user_failed", &[("error", &e.to_string())])
        ),
    }
    Ok(())
}

/// Adds `<host> <key>` lines to known_hosts, skipping lines already present. Returns the number added.
pub fn merge_known_hosts(
    path: &Path,
    host: &str,
    port: u16,
    keys: &[String],
) -> anyhow::Result<usize> {
    let mut content = read_optional(path)?
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let hostname = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };
    let mut added = 0;
    for key in keys {
        let line = format!("{hostname} {}", key.trim());
        if content.lines().any(|l| l.trim() == line) {
            continue;
        }
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(&line);
        content.push('\n');
        added += 1;
    }
    atomic_write(path, content.as_bytes(), 0o600)?;
    Ok(added)
}

/// Extracts `(host field, "type base64")` pairs from `ssh-keyscan` output. Comment lines (`# …`) are discarded.
pub fn parse_keyscan(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let mut it = l.split_whitespace();
            let host = it.next()?;
            let kind = it.next()?;
            let b64 = it.next()?;
            if !kind.starts_with("ssh-") && !kind.starts_with("ecdsa-") {
                return None;
            }
            Some((host.to_string(), format!("{kind} {b64}")))
        })
        .collect()
}

/// 0.2.1: fetches the host key of an upstream or a bastion (ProxyJump target) and appends it to that upstream's known_hosts.
/// The fingerprint is printed so the operator can compare it against the published value before trusting it (TOFU).
pub fn keyscan(path: &Path, host: &str, port: u16, upstream: Option<&str>) -> anyhow::Result<()> {
    let r = resolve(path)?;
    let up = pick_upstream(&r, upstream)?;
    let audit = open_audit(&r)?;
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() || host.contains(['/', ' ', ',']) {
        bail!("host must be a bare hostname or IP");
    }
    let out = std::process::Command::new("ssh-keyscan")
        .args([
            "-T",
            "5",
            "-t",
            "ed25519,ecdsa,rsa",
            "-p",
            &port.to_string(),
            host,
        ])
        .output()
        .context("run ssh-keyscan (openssh-client)")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let keys: Vec<String> = parse_keyscan(&text).into_iter().map(|(_, k)| k).collect();
    if keys.is_empty() {
        bail!(tf(
            "op.keyscan.none",
            &[
                ("host", host),
                ("port", &port.to_string()),
                ("stderr", String::from_utf8_lossy(&out.stderr).trim()),
            ]
        ));
    }
    println!(
        "{}",
        tf(
            "op.keyscan.header",
            &[("host", host), ("port", &port.to_string())]
        )
    );
    for k in &keys {
        let kind = k.split_whitespace().next().unwrap_or("");
        match PublicKey::from_openssh(k) {
            Ok(pk) => println!("  {kind:<20} {}", fingerprint(&pk)),
            Err(e) => println!(
                "  {kind:<20} {}",
                tf("op.keyscan.unparseable", &[("error", &e.to_string())])
            ),
        }
    }
    if let Some(dir) = up.known_hosts.parent() {
        ensure_dir_0700(dir).with_context(|| format!("state dir {}", dir.display()))?;
    }
    let n = merge_known_hosts(&up.known_hosts, host, port, &keys)?;
    println!(
        "{}",
        tf(
            "op.keyscan.result",
            &[
                ("n", &keys.len().to_string()),
                ("host", host),
                ("port", &port.to_string()),
                ("new", &n.to_string()),
                ("path", &up.known_hosts.display().to_string()),
                ("domain", &up.domain),
            ]
        )
    );
    audit.log(
        "known_hosts_added",
        Actor::Operator,
        &[
            ("host", host),
            ("port", &port.to_string()),
            ("upstream", &up.domain),
            ("added", &n.to_string()),
        ],
    );
    Ok(())
}

pub fn logout(path: &Path, upstream: Option<&str>) -> anyhow::Result<()> {
    let r = resolve(path)?;
    let up = pick_upstream(&r, upstream)?;
    let audit = open_audit(&r)?;
    let store = UpstreamTokenStore::new(&up.upstream_token, r.relay.upstream_token_cache_ttl);
    if store.delete()? {
        println!(
            "{}",
            tf(
                "op.logout.removed",
                &[("path", &up.upstream_token.display().to_string())]
            )
        );
        audit.log(
            "logout",
            Actor::Operator,
            &[("host", &up.host), ("domain", &up.domain)],
        );
    } else {
        println!("{}", tf("op.logout.none", &[("domain", &up.domain)]));
    }
    Ok(())
}

pub async fn whoami(path: &Path, upstream: Option<&str>) -> anyhow::Result<()> {
    let r = resolve(path)?;
    let up = pick_upstream(&r, upstream)?;
    let audit = open_audit(&r)?;
    let (gh, _, _) = build_github_for(&r, up, audit)?;
    let login = gh.whoami().await?;
    println!(
        "{}",
        tf(
            "op.whoami.identity",
            &[("login", &login), ("host", &up.host)]
        )
    );
    println!("{}", t("op.whoami.note1"));
    println!("{}", t("op.whoami.note2"));
    Ok(())
}

pub async fn check(path: &Path) -> anyhow::Result<()> {
    let r = resolve(path)?;
    println!(
        "{}{}",
        pad_label(&t("op.check.project"), 14),
        r.project.name
    );
    let multi = r.upstreams.len() > 1;
    for up in &r.upstreams {
        if multi {
            println!(
                "{}{} (git-relay{})",
                pad_label(&t("op.check.domain"), 14),
                up.domain,
                if up.is_default {
                    t("op.check.default")
                } else {
                    String::new()
                }
            );
        } else {
            println!(
                "{}{} (git-relay)",
                pad_label(&t("op.check.domain"), 14),
                up.domain
            );
        }
        println!(
            "{}{} {}",
            pad_label(&t("op.check.upstream"), 14),
            up.host,
            tf(
                "op.check.ssh_port",
                &[("port", &up.upstream_ssh_port.to_string())]
            )
        );
        println!("{}{}", pad_label(&t("op.check.rest"), 14), up.api_base);
        println!(
            "{}{}",
            pad_label(&t("op.check.graphql"), 14),
            up.graphql_base
        );
        println!("{}{}", pad_label(&t("op.check.ssh_listen"), 14), up.listen);
        if !up.ssh_options.is_empty() {
            println!(
                "{}{}",
                pad_label(&t("op.check.ssh_options"), 14),
                up.ssh_options.join(" ")
            );
        }
    }
    println!(
        "{}{}",
        pad_label(&t("op.check.api_listen"), 14),
        r.relay.api_listen
    );
    println!(
        "{}{}",
        pad_label(&t("op.check.https"), 14),
        tf(
            "op.check.https_on",
            &[
                ("mode", &format!("{:?}", r.relay.https)),
                ("addr", &r.relay.https_listen.to_string()),
            ]
        )
    );
    for target in &r.https_targets {
        let cap = target
            .max_upload
            .map(|c| tf("op.check.bytes", &[("n", &c.to_string())]))
            .unwrap_or_else(|| t("op.check.unlimited"));
        println!(
            "{}{:<32} → {:<28} {} {}",
            pad_label(&t("op.check.target"), 14),
            target.domain,
            target.host,
            match target.kind {
                HandlerKind::HttpsRelay => "(https-relay)",
                _ => "(git-relay)   ",
            },
            tf("op.check.upload_cap", &[("cap", &cap)])
        );
    }
    println!(
        "{}{}",
        pad_label(&t("op.check.state_dir"), 14),
        r.paths.state_dir.display()
    );
    println!(
        "{}{}",
        pad_label(&t("op.check.token_ttl"), 14),
        humantime::format_duration(r.relay.token_ttl)
    );
    println!(
        "{}{:?}{}",
        pad_label(&t("op.check.bootstrap"), 14),
        r.relay.bootstrap,
        if r.paths.bootstrap_disabled.exists() {
            t("op.check.bootstrap_disabled")
        } else {
            String::new()
        }
    );
    // 0.1.9: tags, deletion and permissions are the project default plus the repo's overrides. The effective per-repo values are listed under repos below
    if let Some(px) = &r.proxy {
        println!("{}{}", pad_label(&t("op.check.proxy"), 14), px.url);
    }
    println!("\n{}", t("op.check.permissions"));
    let granted = r.project.granted();
    let denied = r.project.denied();
    for k in all_permission_keys() {
        let mark = if denied.contains(&k) {
            "-"
        } else if granted.contains(&k) {
            "x"
        } else {
            " "
        };
        println!("  [{mark}] {k}");
    }
    if !denied.is_empty() {
        println!("{}", t("op.check.deny_note"));
    }
    // 0.2.1: the upstream layer (between the project default and the repo)
    if !r.relay.project.upstreams.is_empty() {
        println!("\n{}", t("op.check.upstreams"));
        for (name, up) in &r.relay.project.upstreams {
            let mut parts = Vec::new();
            if let Some(p) = &up.permissions {
                if !p.allow().is_empty() {
                    parts.push(format!("+{}", p.allow().join(" +")));
                }
                if !p.deny().is_empty() {
                    parts.push(format!("-{}", p.deny().join(" -")));
                }
            }
            if let Some(v) = &up.push {
                parts.push(format!("push={v:?}"));
            }
            if let Some(v) = &up.tags {
                parts.push(format!("tags={v:?}"));
            }
            if let Some(v) = up.delete {
                parts.push(format!("delete={v}"));
            }
            println!(
                "  {:<40} {} ({} repo(s))",
                name,
                if parts.is_empty() {
                    t("op.check.no_overrides")
                } else {
                    parts.join(" ")
                },
                up.repos.len()
            );
        }
    }
    println!("\n{}", t("op.check.repos"));
    for rp in &r.project.repos {
        let shown = if multi {
            format!("{}/{}", r.project.host_of(rp), rp.full_name)
        } else {
            rp.full_name.clone()
        };
        println!(
            "  {:<40} {:<11} bases={:?} push={:?} tags={:?} delete={}",
            shown,
            rp.mode.as_str(),
            rp.bases,
            rp.push,
            rp.tags,
            rp.delete
        );
        let eff = r.project.effective_keys(rp);
        if eff != granted || !rp.allow.is_empty() || !rp.deny.is_empty() {
            let perms = if eff.is_empty() {
                t("op.check.none")
            } else {
                eff.join(" ")
            };
            println!("{}", tf("op.check.repo_permissions", &[("perms", &perms)]));
        }
    }
    println!("\n{}", t("op.check.state"));
    let sock = auth_sock_from_env();
    match preflight_agent(sock.as_deref()).await {
        Ok(n) => println!(
            "{}",
            tf(
                "op.check.agent_ok",
                &[
                    ("n", &n.to_string()),
                    (
                        "sock",
                        &sock
                            .as_deref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default()
                    ),
                ]
            )
        ),
        Err(e) => println!("{}", tf("op.check.agent_bad", &[("error", &e.to_string())])),
    }
    for u in &r.upstreams {
        if multi {
            println!("  [{}]", u.domain);
        }
        let up = OpenSshUpstream::new(
            &u.host,
            u.upstream_ssh_port,
            &u.known_hosts,
            r.relay.ssh_config.as_deref(),
        )
        .with_options(u.ssh_options.clone());
        if !u.ssh_options.is_empty() {
            println!("  ssh options:     {}", u.ssh_options.join(" "));
        }
        match up.known_hosts_has_upstream() {
            Ok(true) => println!(
                "{}",
                tf(
                    "op.check.known_hosts_ok",
                    &[("path", &u.known_hosts.display().to_string())]
                )
            ),
            Ok(false) => println!(
                "{}",
                tf(
                    "op.check.known_hosts_missing",
                    &[("remedy", &up.known_hosts_remedy())]
                )
            ),
            Err(e) => println!(
                "{}",
                tf("op.check.known_hosts_error", &[("error", &e.to_string())])
            ),
        }
        let store = UpstreamTokenStore::new(&u.upstream_token, r.relay.upstream_token_cache_ttl);
        let login_hint = if u.is_default {
            "sekimore-relay login".to_string()
        } else {
            format!("sekimore-relay login --upstream {}", u.domain)
        };
        match store.load() {
            Ok(Some(tok)) => println!(
                "{}",
                tf(
                    "op.check.token_present",
                    &[
                        ("scope", &tok.scope),
                        (
                            "when",
                            &humantime::format_rfc3339_seconds(tok.obtained_at).to_string()
                        ),
                    ]
                )
            ),
            Ok(None) => println!("{}", tf("op.check.token_missing", &[("hint", &login_hint)])),
            Err(e) => println!(
                "{}",
                tf("op.check.token_error", &[("error", &e.to_string())])
            ),
        }
    }
    let keys = AuthorizedKeys::new(&r.paths.authorized_keys, 64);
    println!(
        "{}",
        tf(
            "op.check.keys",
            &[
                ("n", &keys.count().to_string()),
                ("path", &r.paths.authorized_keys.display().to_string()),
            ]
        )
    );
    let tokens = TokenStore::new(&r.paths.tokens);
    let now = SystemTime::now();
    let list = tokens.list().unwrap_or_default();
    println!(
        "{}",
        tf(
            "op.check.tokens",
            &[
                (
                    "active",
                    &list
                        .iter()
                        .filter(|tok| tok.state(now) == "active")
                        .count()
                        .to_string()
                ),
                ("total", &list.len().to_string()),
            ]
        )
    );
    Ok(())
}

pub fn token(path: &Path, ttl: Option<&str>) -> anyhow::Result<()> {
    let r = resolve(path)?;
    let audit = open_audit(&r)?;
    let ttl: Duration = match ttl {
        Some(s) => humantime::parse_duration(s).with_context(|| format!("--ttl {s}"))?,
        None => r.relay.token_ttl,
    };
    let store = TokenStore::new(&r.paths.tokens);
    let (plain, rec) = store.issue(&r.project.name, ttl)?;
    println!("project: {}", rec.project);
    println!("label:   {}", rec.label);
    println!(
        "expires: {}",
        humantime::format_rfc3339_seconds(rec.expires_at)
    );
    let perms = r.project.granted();
    println!(
        "permissions: {}\n",
        if perms.is_empty() {
            "(none)".to_string()
        } else {
            perms.join(" ")
        }
    );
    println!("  export SEKIMORE_TOKEN={plain}");
    println!(
        "  export SEKIMORE_ENDPOINT=http://<gateway-ip>:{}\n",
        r.relay.api_listen.port()
    );
    println!("this token only works against the gateway; it is invalid upstream.");
    audit.log(
        "token_issued",
        Actor::Operator,
        &[
            ("project", &rec.project),
            ("label", &rec.label),
            (
                "expires",
                &humantime::format_rfc3339_seconds(rec.expires_at).to_string(),
            ),
        ],
    );
    Ok(())
}

pub fn tokens(path: &Path) -> anyhow::Result<()> {
    let r = resolve(path)?;
    let store = TokenStore::new(&r.paths.tokens);
    let list = store.list()?;
    if list.is_empty() {
        println!("no tokens issued");
        return Ok(());
    }
    let now = SystemTime::now();
    println!(
        "{:<16} {:<12} {:<20} {:<6} STATE",
        "LABEL", "PROJECT", "EXPIRES", "USES"
    );
    for t in list {
        println!(
            "{:<16} {:<12} {:<20} {:<6} {}",
            t.label,
            t.project,
            humantime::format_rfc3339_seconds(t.expires_at),
            t.use_count,
            t.state(now)
        );
    }
    Ok(())
}

pub fn revoke(path: &Path, label: &str) -> anyhow::Result<()> {
    let r = resolve(path)?;
    let audit = open_audit(&r)?;
    let store = TokenStore::new(&r.paths.tokens);
    if !store.revoke(label)? {
        bail!("no token with label {label:?} (see `tokens`)");
    }
    println!("revoked {label}");
    audit.log("token_revoked", Actor::Operator, &[("label", label)]);
    Ok(())
}

pub fn revoke_project(path: &Path) -> anyhow::Result<()> {
    let r = resolve(path)?;
    let audit = open_audit(&r)?;
    let store = TokenStore::new(&r.paths.tokens);
    let n = store.revoke_project(&r.project.name)?;
    println!("revoked {n} token(s) for project {}", r.project.name);
    audit.log(
        "project_revoked",
        Actor::Operator,
        &[("project", &r.project.name), ("count", &n.to_string())],
    );
    Ok(())
}

pub fn add_key(path: &Path, line: Option<&str>, file: Option<&Path>) -> anyhow::Result<()> {
    let r = resolve(path)?;
    let audit = open_audit(&r)?;
    let text = match (line, file) {
        (Some(l), None) => l.to_string(),
        (None, Some(f)) => {
            std::fs::read_to_string(f).with_context(|| format!("read {}", f.display()))?
        }
        _ => bail!("give the public key line as an argument or --file <path>"),
    };
    let keys = AuthorizedKeys::new(&r.paths.authorized_keys, 64);
    let mut added = 0;
    for l in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        match keys.add(l).map_err(|e| anyhow!("{e}"))? {
            Added::New { fingerprint } => {
                println!("added {fingerprint}");
                audit.log(
                    "key_added",
                    Actor::Operator,
                    &[("fingerprint", &fingerprint)],
                );
                added += 1;
            }
            Added::AlreadyPresent { fingerprint } => println!("already present {fingerprint}"),
        }
    }
    println!(
        "{added} key(s) added → {}",
        r.paths.authorized_keys.display()
    );
    Ok(())
}

pub fn bootstrap(path: &Path, action: BootstrapAction) -> anyhow::Result<()> {
    let r = resolve(path)?;
    let audit = open_audit(&r)?;
    let flag = &r.paths.bootstrap_disabled;
    match action {
        BootstrapAction::Disable => {
            atomic_write(flag, b"disabled by operator\n", 0o600)?;
            println!("POST /bootstrap disabled ({} created)", flag.display());
            audit.log("bootstrap_disabled", Actor::Operator, &[]);
        }
        BootstrapAction::Enable => {
            match std::fs::remove_file(flag) {
                Ok(()) => println!("POST /bootstrap enabled ({} removed)", flag.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    println!("POST /bootstrap already enabled")
                }
                Err(e) => return Err(e.into()),
            }
            audit.log("bootstrap_enabled", Actor::Operator, &[]);
        }
        BootstrapAction::Status => {
            println!(
                "mode: {:?}; kill-switch: {}",
                r.relay.bootstrap,
                if flag.exists() {
                    "DISABLED"
                } else {
                    "not set (enabled)"
                }
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keyscan_output_keeps_keys_and_drops_comments() {
        let text = "# bastion.example.com:22 SSH-2.0-OpenSSH_9.6\n\
bastion.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n\
[ghe.example.com]:2222 ecdsa-sha2-nistp256 AAAAE2VjZHNh extra-comment\n\
garbage line\n";
        let got = parse_keyscan(text);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, "bastion.example.com");
        assert!(got[0].1.starts_with("ssh-ed25519 AAAAC3"));
        assert_eq!(
            got[1],
            (
                "[ghe.example.com]:2222".to_string(),
                "ecdsa-sha2-nistp256 AAAAE2VjZHNh".to_string()
            )
        );
    }
}
