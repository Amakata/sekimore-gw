//! Operator-facing subcommands (run inside the gateway container).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context};

use super::color::{paint, Tone};
use super::BootstrapAction;
use russh::keys::PublicKey;

use crate::audit::{Actor, Audit};
use crate::config::{self, ConfigError, HandlerKind, ProxySpec, Resolved, Upstream};
use crate::fsutil::{atomic_write, ensure_dir_0700, read_optional};
use crate::git::agent_check::{auth_sock_from_env, preflight_agent};
use crate::git::upstream_ssh::OpenSshUpstream;
use crate::github::device_flow::DeviceFlow;
use crate::github::http::{build_client, HttpOptions};
use crate::github::upstream_token::{SecretSource, UpstreamTokenStore};
use crate::github::GitHub;
use crate::i18n::{t, tf};
use crate::policy::all_permission_keys;
use crate::ssh::authorized_keys::{fingerprint, Added, AuthorizedKeys};
use crate::store;
use crate::tokens::TokenStore;

// 0.2.28: `security_events` is what the Dependabot alerts endpoints want (#132). A token
// issued before it was added lacks it; `security alerts` then gets GitHub's 403 and the way out
// is `gw:login` once more.
pub const DEVICE_FLOW_SCOPES: &[&str] = &["repo", "project", "security_events"];

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

/// Where this process reaches the secret store. `serve` holds it and passes its own; every other
/// subcommand is a separate `docker compose exec` with no passphrase, so it asks the running relay
/// over the control socket.
pub fn secret_source_via_socket(r: &Resolved) -> SecretSource {
    SecretSource::ControlSocket(r.paths.control_sock.clone())
}

/// GitHub client for one upstream (api_base / graphql_base / upstream_token are that upstream's. 0.2.0).
pub fn build_github_for(
    r: &Resolved,
    up: &Upstream,
    audit: Arc<Audit>,
    secrets: SecretSource,
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
        &up.host,
        &up.upstream_token,
        secrets,
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
    // #151: the device flow goes through the proxy when one is set, so take its credential from the
    // store first
    crate::proxy_credential::prime(r.proxy.as_ref(), &secret_source_via_socket(&r)).await;
    let (gh, store, http) = build_github_for(&r, &up, audit.clone(), secret_source_via_socket(&r))?;
    // Before the device flow, not after: it walks a person through authorising on github.com, and
    // discovering at the end that there is nowhere to put the result throws that away and leaves
    // an authorisation granted for a token nobody kept.
    store
        .writable()
        .await
        .context("the upstream token cannot be stored, so there is no point starting a login")?;
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
        .await
        // The device flow is the relay reaching the upstream itself, not relaying for an agent.
        // When `proxy.upstream_proxy` is set every one of those requests goes through it, and a
        // proxy that does not answer looks exactly like the upstream being unreachable. Say which
        // it was, because the two are fixed in completely different places.
        .map_err(|e| match &r.proxy {
            Some(px) => e.context(format!(
                "the relay reaches {} through the proxy {} (proxy.upstream_proxy). \
                 Check that the proxy is reachable from the gateway itself — not from the \
                 docker host, which has a different view of the network. A timeout here with \
                 nothing in the proxy's own log usually means its address falls inside one of \
                 this container's docker subnets, so the container treats it as a neighbour on \
                 the bridge and never routes to it; `ip -4 addr` next to the proxy's address \
                 shows that, and the fix is to point docker at a non-overlapping range \
                 (`default-address-pools` in daemon.json), not a wider allow_ips or \
                 network.allowed_ports. Or unset the proxy if this network does not need one",
                up.host, px.url
            )),
            None => e.context(format!(
                "the relay reaches {} directly (no proxy.upstream_proxy is set). \
                 Check that the gateway itself can leave the network",
                up.host
            )),
        })?;
    store.save(&up.host, &token, &scope).await?;
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

pub async fn logout(path: &Path, upstream: Option<&str>) -> anyhow::Result<()> {
    let r = resolve(path)?;
    let up = pick_upstream(&r, upstream)?;
    let audit = open_audit(&r)?;
    let store = UpstreamTokenStore::new(
        &up.host,
        &up.upstream_token,
        secret_source_via_socket(&r),
        r.relay.upstream_token_cache_ttl,
    );
    if store.delete().await? {
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
    crate::proxy_credential::prime(r.proxy.as_ref(), &secret_source_via_socket(&r)).await;
    let (gh, _, _) = build_github_for(&r, up, audit, secret_source_via_socket(&r))?;
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
    // 0.2.29 (#59): the signing key dev commits with, if the gateway offers one
    match &r.relay.signing_key {
        Some(sk) => {
            println!(
                "{}{}",
                pad_label(&t("op.check.signing"), 14),
                tf(
                    "op.check.signing_on",
                    &[
                        ("fingerprint", &sk.fingerprint),
                        ("namespace", &sk.namespace),
                        ("socket", &sk.socket.display().to_string()),
                        ("uid", &sk.socket_uid.to_string()),
                    ]
                )
            );
        }
        None => println!(
            "{}{}",
            pad_label(&t("op.check.signing"), 14),
            t("op.check.signing_off")
        ),
    }
    // 0.1.9: tags, deletion and permissions are the project default plus the repo's overrides. The effective per-repo values are listed under repos below
    if let Some(px) = &r.proxy {
        // #151: which credential the relay presents — the store's, or the environment's — since
        // Squid reads the store and the two can disagree
        crate::proxy_credential::prime(Some(px), &secret_source_via_socket(&r)).await;
        // #194: `credential_source()` says "none" both for a locked store and an empty one, and
        // the operator's next step differs — `gw:unlock` against `gw:proxy-credential set`. Ask
        // the store which it is, over the same control socket.
        let state = store_state(&r.paths.control_sock).await;
        println!(
            "{}{}",
            pad_label(&t("op.check.proxy"), 14),
            tf(
                "op.check.proxy_credential",
                &[("url", &px.url), ("source", &credential_status(&state, px))]
            )
        );
        // #205: which of the two routes this relay is on, before anything is tried. The line
        // under it means a different thing on each.
        println!(
            "{}{}",
            pad_label(&t("op.check.proxy_route"), 14),
            t(if px.via_squid.is_some() {
                "op.check.proxy_route_squid"
            } else {
                "op.check.proxy_route_direct"
            })
        );
        // #206: until now nothing in `check` ever touched the upstream proxy, so a proxy the
        // relay could not speak TLS to passed every check and surfaced only when real work
        // started. Connect, handshake, say what came back.
        print_proxy_reach(px, &squid_probe_target(&r.https_targets, px)).await;
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
            if let Some(v) = up.signed_tags {
                parts.push(format!("signed_tags={v}"));
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
            "  {:<40} {:<11} bases={:?} push={:?} tags={:?} delete={} signed_tags={}",
            shown,
            rp.mode.as_str(),
            rp.bases,
            rp.push,
            rp.tags,
            rp.delete,
            rp.signed_tags
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
                    ("state", &paint(Tone::Good, &t("op.check.word.ok"))),
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
        Err(e) => println!(
            "{}",
            tf(
                "op.check.agent_bad",
                &[
                    ("state", &paint(Tone::Bad, &t("op.check.word.agent_bad"))),
                    ("error", &e.to_string()),
                ]
            )
        ),
    }
    // Whether the configured signing key is actually in that agent. The fingerprint alone says
    // nothing: the observation in #59 was a key that nobody noticed had gone
    if let Some(sk) = &r.relay.signing_key {
        let audit = Arc::new(crate::audit::Audit::disabled());
        let agent =
            crate::git::agent_proxy::SigningAgent::new(sk, sock.clone().unwrap_or_default(), audit);
        match agent.identity().await {
            Some(id) => println!(
                "{}",
                tf(
                    "op.check.signing_key_ok",
                    &[
                        (
                            "state",
                            &paint(Tone::Good, &t("op.check.word.signing_key_ok"))
                        ),
                        ("key", &id.public_key),
                    ]
                )
            ),
            None => println!(
                "{}",
                tf(
                    "op.check.signing_key_missing",
                    &[
                        (
                            "state",
                            &paint(Tone::Bad, &t("op.check.word.signing_key_missing"))
                        ),
                        ("fingerprint", &sk.fingerprint),
                    ]
                )
            ),
        }
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
                    &[
                        ("state", &paint(Tone::Good, &t("op.check.word.ok"))),
                        ("path", &u.known_hosts.display().to_string()),
                    ]
                )
            ),
            Ok(false) => println!(
                "{}",
                tf(
                    "op.check.known_hosts_missing",
                    &[
                        (
                            "state",
                            &paint(Tone::Bad, &t("op.check.word.known_hosts_missing"))
                        ),
                        ("remedy", &up.known_hosts_remedy()),
                    ]
                )
            ),
            Err(e) => println!(
                "{}",
                tf(
                    "op.check.known_hosts_error",
                    &[
                        ("state", &paint(Tone::Bad, &t("op.check.word.error"))),
                        ("error", &e.to_string()),
                    ]
                )
            ),
        }
        let store = UpstreamTokenStore::new(
            &u.host,
            &u.upstream_token,
            secret_source_via_socket(&r),
            r.relay.upstream_token_cache_ttl,
        );
        let login_hint = if u.is_default {
            "sekimore-relay login".to_string()
        } else {
            format!("sekimore-relay login --upstream {}", u.domain)
        };
        match store.load().await {
            Ok(Some(tok)) => println!(
                "{}",
                tf(
                    "op.check.token_present",
                    &[
                        (
                            "state",
                            &paint(Tone::Good, &t("op.check.word.token_present"))
                        ),
                        ("scope", &tok.scope),
                        (
                            "when",
                            &humantime::format_rfc3339_seconds(tok.obtained_at).to_string()
                        ),
                    ]
                )
            ),
            Ok(None) => println!(
                "{}",
                tf(
                    "op.check.token_missing",
                    &[
                        (
                            "state",
                            &paint(Tone::Bad, &t("op.check.word.token_missing"))
                        ),
                        ("hint", &login_hint),
                    ]
                )
            ),
            Err(e) => println!(
                "{}",
                tf(
                    "op.check.token_error",
                    &[
                        ("state", &paint(Tone::Bad, &t("op.check.word.error"))),
                        ("error", &e.to_string()),
                    ]
                )
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
    }
    Ok(())
}

/// Unlock the secret store, setting the passphrase when there is not one yet.
///
/// 0.2.15: the passphrase is typed here and sent over the relay's control socket, which lives on a
/// volume the dev container does not mount. It is never an argument or an environment variable —
/// either would put it in `ps`, and an argument would put it in shell history too.
///
/// 0.2.29: `--stdin` reads it from a pipe instead, so the host can feed it from its own keychain
/// (`mise run gw:unlock-auto`) and a recreate needs nobody at the keyboard. Only the typing
/// changes — the passphrase still arrives over the same socket, and the gateway still has no way
/// to find it on its own.
pub async fn unlock(path: &Path, from_stdin: bool) -> anyhow::Result<()> {
    let paths = store_paths(path)?;
    let (_, state) = store::control::call(&paths, r#"{"op":"status"}"#).await?;
    match unlock_step(&state, from_stdin)? {
        UnlockStep::AlreadyUnlocked => {
            println!("the secret store is already unlocked");
            Ok(())
        }
        UnlockStep::SetTheFirstPassphrase => {
            eprintln!(
                "No secret store yet. Choose a passphrase.\n\
                 Nothing stored can be read without it, and there is no way to recover it — keep a\n\
                 copy of it somewhere a person can reach, and take an export once there is\n\
                 something in the store."
            );
            let first = store::control::prompt("New passphrase")?;
            let again = store::control::prompt("Again")?;
            if first.as_bytes() != again.as_bytes() {
                anyhow::bail!("the two did not match");
            }
            send_passphrase(&paths, PassphraseFor::NewStore, &first).await
        }
        UnlockStep::Open => {
            let pass = if from_stdin {
                store::control::passphrase_from_stdin()?
            } else {
                store::control::prompt("Passphrase")?
            };
            send_passphrase(&paths, PassphraseFor::ExistingStore, &pass).await
        }
    }
}

/// What `unlock` does with the state the store reports.
#[derive(Debug, PartialEq, Eq)]
enum UnlockStep {
    AlreadyUnlocked,
    SetTheFirstPassphrase,
    Open,
}

/// Separated from `unlock` so the one case that has to be refused can be tested: everything else
/// in `unlock` needs a control socket and a terminal.
///
/// `--stdin` is refused on a store that has no passphrase yet. The first one is chosen rather
/// than recalled, which is why it is typed twice and checked against itself; a pipe has no second
/// copy, and a mistyped passphrase written straight into a keychain hides the mistake rather than
/// catching it — the store would then be sealed with bytes nobody meant to choose.
fn unlock_step(state: &str, from_stdin: bool) -> anyhow::Result<UnlockStep> {
    match state {
        "unlocked" => Ok(UnlockStep::AlreadyUnlocked),
        "not initialised" if from_stdin => anyhow::bail!(
            "there is no secret store yet, and the first passphrase is chosen at a prompt that \
             asks for it twice. Run `mise run gw:unlock` once, then `mise run gw:keychain-set` \
             to store it"
        ),
        "not initialised" => Ok(UnlockStep::SetTheFirstPassphrase),
        _ => Ok(UnlockStep::Open),
    }
}

/// Which of the two a passphrase is being sent for.
///
/// A store with no passphrase yet has nothing to unwrap, so `unlock` fails on parameters that do
/// not exist — which is what 0.2.15 did. An enum rather than a string because sending the wrong one
/// *was* the bug, and the caller cannot be covered by a test: it reads from a terminal.
#[derive(Clone, Copy)]
enum PassphraseFor {
    NewStore,
    ExistingStore,
}

impl PassphraseFor {
    fn op(self) -> &'static str {
        match self {
            PassphraseFor::NewStore => "init",
            PassphraseFor::ExistingStore => "unlock",
        }
    }
}

async fn send_passphrase(
    sock: &Path,
    which: PassphraseFor,
    pass: &store::crypto::Secret,
) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "op": which.op(),
        "passphrase": String::from_utf8_lossy(pass.as_bytes()),
    })
    .to_string();
    let (ok, message) = store::control::call(sock, &body).await?;
    if ok {
        println!("{message}");
        Ok(())
    } else {
        anyhow::bail!("{message}")
    }
}

/// Write the store out as a sealed envelope.
///
/// Defaults to stdout, so the operator's own redirect decides where it lands and the file never
/// has to be fetched back out of the container: `mise run gw:store-export > store.json`. `--out`
/// is for writing it inside the gateway, and creates the file 0600 because the operator's umask
/// is not something to rely on for this.
///
/// Sealed is not secret-free. The envelope is guarded by the passphrase alone — no machine, no
/// keychain — which is the property that makes it portable and the reason to say so on stderr.
pub async fn store_export(path: &Path, out: Option<&Path>) -> anyhow::Result<()> {
    use std::io::Write;

    let sock = store_paths(path)?;
    let (ok, message, data) = store::control::call_data(&sock, r#"{"op":"export"}"#).await?;
    if !ok {
        bail!("{message}");
    }
    let envelope = data.ok_or_else(|| anyhow!("the relay answered an export with no envelope"))?;
    let mut bytes = serde_json::to_vec(&envelope)?;
    bytes.push(b'\n');

    match out {
        Some(p) => {
            atomic_write(p, &bytes, 0o600)?;
            eprintln!("{message} to {}", p.display());
        }
        None => {
            std::io::stdout().write_all(&bytes)?;
            std::io::stdout().flush()?;
            eprintln!("{message}");
        }
    }
    eprintln!(
        "The export is sealed, and the passphrase is the only thing guarding it. \
         Keep it where that passphrase is not."
    );
    Ok(())
}

/// Replace an empty store with an envelope, read from stdin by default.
///
/// The envelope is not verified here and cannot be: verifying means having the key. The next
/// `unlock` with the passphrase the export was taken under is what checks the MAC, so a spliced
/// envelope fails there rather than quietly becoming the store.
pub async fn store_import(path: &Path, file: Option<&Path>) -> anyhow::Result<()> {
    use std::io::Read;

    let sock = store_paths(path)?;
    let text = match file {
        Some(p) => std::fs::read_to_string(p)
            .with_context(|| format!("cannot read the envelope at {}", p.display()))?,
        None => {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .context("cannot read the envelope from stdin. Redirect a file into it, or --in")?;
            s
        }
    };
    let envelope: serde_json::Value =
        serde_json::from_str(&text).context("the envelope is not JSON")?;

    let body = serde_json::json!({ "op": "import", "envelope": envelope }).to_string();
    let (ok, message) = store::control::call(&sock, &body).await?;
    println!("{message}");
    if ok {
        Ok(())
    } else {
        bail!("import refused")
    }
}

/// The namespace and name the upstream proxy credential is filed under. The Python gateway reads
/// the same pair when it generates Squid's config, so changing either is a breaking change across
/// two languages.
pub const PROXY_NAMESPACE: &str = crate::proxy_credential::NAMESPACE;
pub const PROXY_NAME: &str = crate::proxy_credential::NAME;

/// Put the corporate proxy's credential in the store.
///
/// #53: the two documented places for it — `.devcontainer/.env` and `config.yml` — are both in
/// the worktree, so the agent could read them. The store is on a volume dev does not mount and
/// the value is sealed, so a copied volume does not yield it either.
///
/// Typed, not passed as an argument: an argument reaches `ps` and the shell history.
pub async fn proxy_credential_set(path: &Path) -> anyhow::Result<()> {
    let sock = store_paths(path)?;
    eprintln!(
        "The upstream proxy's credential. It is stored sealed, so the gateway has to be\n\
         unlocked (mise run gw:unlock) before Squid and the relay can use it — until then\n\
         they fall back to SEKIMORE_UPSTREAM_PROXY_* or config.yml, if either has one."
    );
    let user = store::control::prompt("Proxy username")?;
    let pass = store::control::prompt("Proxy password")?;
    let value = serde_json::json!({
        "username": String::from_utf8_lossy(user.as_bytes()),
        "password": String::from_utf8_lossy(pass.as_bytes()),
    })
    .to_string();
    let body = serde_json::json!({
        "op": "set", "namespace": PROXY_NAMESPACE, "name": PROXY_NAME, "value": value
    })
    .to_string();
    let (ok, message) = store::control::call(&sock, &body).await?;
    println!("{message}");
    if !ok {
        bail!("the credential was not stored");
    }
    println!(
        "The relay picks it up within seconds of the store being unlocked. Squid does too, when \
         it is unlocked; if it is unlocked already, `mise run gw:restart` applies it to Squid now."
    );
    Ok(())
}

/// Remove it. For a deployment that no longer sits behind a proxy, or one moving the value.
pub async fn proxy_credential_clear(path: &Path) -> anyhow::Result<()> {
    let sock = store_paths(path)?;
    let body = serde_json::json!({
        "op": "delete", "namespace": PROXY_NAMESPACE, "name": PROXY_NAME
    })
    .to_string();
    let (ok, message) = store::control::call(&sock, &body).await?;
    println!("{message}");
    if ok {
        Ok(())
    } else {
        bail!("nothing was removed")
    }
}

/// `lock` and `status`, which need no passphrase.
pub async fn store_control(path: &Path, op: &str) -> anyhow::Result<()> {
    let paths = store_paths(path)?;
    let (ok, message) = store::control::call(&paths, &format!(r#"{{"op":"{op}"}}"#)).await?;
    println!("{}", paint_store_state(&message));
    // #208: one word, and only one. relay:verify and upgrade.sh read this output as the store's
    // state; the proxy credential line that 0.2.39 added here broke both. `check` is the command
    // for people, and it says the credential's state.
    if ok {
        Ok(())
    } else {
        anyhow::bail!("{message}")
    }
}

/// The store's state as `{"op":"status"}` words it: "unlocked" / "locked" / "not initialised".
/// A socket that cannot be reached is not a state — the caller gets the empty string and the
/// wording falls back to what the spec itself knows.
async fn store_state(sock: &Path) -> String {
    match store::control::call(sock, r#"{"op":"status"}"#).await {
        Ok((_, message)) => message,
        Err(_) => String::new(),
    }
}

/// #202: colours the store's own state word, and leaves anything else the socket says alone.
///
/// `lock` and `status` answer with one of three words; every other reply (an error, a message
/// from a future version) is a sentence we do not want to paint a random colour.
fn paint_store_state(message: &str) -> String {
    let tone = match message {
        "unlocked" => Tone::Good,
        "locked" => Tone::Bad,
        "not initialised" => Tone::Warn,
        _ => return message.to_string(),
    };
    paint(tone, message)
}

/// What to print for `credential:` (#194).
///
/// `ProxySpec::credential_source()` cannot tell a locked store from an empty one — both leave the
/// cell `None` — and those need opposite next steps. The store's own state decides, and only when
/// nothing was actually read: a credential already in hand is what the relay will present,
/// whatever the store says a moment later.
fn credential_status(state: &str, spec: &ProxySpec) -> String {
    let source = spec.credential_source();
    if source != "none" {
        // #202: the store is where it belongs (green); the environment and config.yml work but
        // are not what we would recommend (yellow). Ask the spec, not its wording — that is what
        // `credential_source()` itself branches on, and it can be reworded without notice.
        let tone = if spec.stored.get().is_some() {
            Tone::Good
        } else {
            Tone::Warn
        };
        return paint(tone, source);
    }
    // #202: only the leading word is painted — the remedy after the dash stays plain so it reads.
    let none = paint(Tone::Bad, &t("op.check.word.credential_none"));
    match state {
        "locked" | "not initialised" => tf(
            "op.check.proxy_credential_locked",
            &[("state", none.as_str())],
        ),
        "unlocked" => tf(
            "op.check.proxy_credential_unset",
            &[("state", none.as_str())],
        ),
        // No answer from the socket: no relay running, so there is no store to advise about.
        _ => none,
    }
}

/// The `reach:` line under `proxy:` in `check` (#206).
///
/// `store-status` does not get this: it answers a question about the secret store, and a network
/// round trip does not belong in it. `check` is the place that is meant to try things.
async fn print_proxy_reach(px: &ProxySpec, target: &str) {
    // #205: on the via-Squid route the relay never speaks TLS to the upstream, so a rustls
    // handshake here would report a HandshakeFailure that no longer matters — and would call a
    // working path UNREACHABLE. Probe what the relay actually does: one CONNECT to the local
    // Squid, end to end through it.
    if let Some(sq) = px.via_squid {
        let outcome = crate::netutil::probe_via_squid(sq, target).await;
        println!("{}", squid_reach_line(&outcome));
        // Only when the path is broken is what the upstream offers worth the five seconds: a
        // working route has already proved the question moot.
        if squid_probe_failed(&outcome) {
            print_openssl_offers(px).await;
        }
        return;
    }
    let outcome = crate::netutil::probe_proxy(px).await;
    println!("{}", proxy_reach_line(&outcome));
    // #205: the bare alert says only "no". Say what the "no" means and how to get out of it, then
    // let OpenSSL — which does have the RSA key exchange — report what the upstream actually
    // negotiates, so the operator need not run s_client by hand.
    if let Err(e) = &outcome {
        if crate::netutil::is_handshake_failure(e) {
            println!("{}", t("op.check.proxy_handshake_hint"));
            print_openssl_offers(px).await;
        }
    }
}

/// The host the via-Squid probe sends its CONNECT to (#205).
///
/// The point is to walk the path real traffic walks, so it has to be a host the relay would
/// actually ask for: `api.github.com` when it is one of the passthrough's targets (it is the one
/// the GitHub API client uses, and the first thing an operator misses when this breaks),
/// otherwise the first target there is. With no targets at all, the upstream proxy's own host —
/// Squid will still try, and its answer still tells us whether the peer is reachable.
fn squid_probe_target(targets: &[crate::config::HttpsTarget], px: &ProxySpec) -> String {
    const PREFERRED: &str = "api.github.com";
    if targets.iter().any(|t| t.host == PREFERRED) {
        return PREFERRED.to_string();
    }
    if let Some(first) = targets.first() {
        return first.host.clone();
    }
    url::Url::parse(&px.url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| PREFERRED.to_string())
}

/// Whether the via-Squid probe says the path is broken, i.e. anything but an open tunnel (#205).
fn squid_probe_failed(outcome: &Result<crate::netutil::SquidProbe, String>) -> bool {
    !matches!(outcome, Ok(p) if p.status == "200")
}

/// The `reach:` line on the via-Squid route (#205), apart from the socket so it can be tested.
fn squid_reach_line(outcome: &Result<crate::netutil::SquidProbe, String>) -> String {
    let label = pad_label(&t("op.check.proxy_reach"), 14);
    let body = match outcome {
        Ok(p) if p.status == "200" => {
            let word = paint(Tone::Good, &t("op.check.word.proxy_reachable"));
            tf(
                "op.check.proxy_reach_squid",
                &[
                    ("state", word.as_str()),
                    ("endpoint", &p.endpoint),
                    ("target", &p.target),
                ],
            )
        }
        Ok(p) => {
            let word = paint(Tone::Bad, &t("op.check.word.proxy_unreachable"));
            // 502 / 503 is Squid saying it could not reach its peer — a different fault from
            // "Squid refused this request", and a different place to look.
            let key = if p.status.starts_with('5') {
                "op.check.proxy_reach_squid_peer"
            } else {
                "op.check.proxy_reach_squid_refused"
            };
            tf(
                key,
                &[
                    ("state", word.as_str()),
                    ("endpoint", &p.endpoint),
                    ("target", &p.target),
                    ("status", &p.status_line),
                ],
            )
        }
        Err(e) => {
            let word = paint(Tone::Bad, &t("op.check.word.proxy_unreachable"));
            tf(
                "op.check.proxy_reach_squid_down",
                &[("state", word.as_str()), ("error", e)],
            )
        }
    };
    format!("{label}{body}")
}

/// The `reach:` line itself, apart from the socket, so its wording can be tested (#206).
fn proxy_reach_line(outcome: &Result<crate::netutil::ProbeReport, String>) -> String {
    let label = pad_label(&t("op.check.proxy_reach"), 14);
    let body = match outcome {
        Ok(report) => {
            // #202: paint the state word alone, never the values after it.
            let word = paint(Tone::Good, &t("op.check.word.proxy_reachable"));
            if report.tls {
                tf(
                    "op.check.proxy_reach_tls",
                    &[
                        ("state", word.as_str()),
                        ("protocol", &tls_version_name(report.protocol.as_deref())),
                        ("cipher", report.cipher.as_deref().unwrap_or("?")),
                    ],
                )
            } else {
                tf("op.check.proxy_reach_plain", &[("state", word.as_str())])
            }
        }
        Err(e) => {
            let word = paint(Tone::Bad, &t("op.check.word.proxy_unreachable"));
            tf(
                "op.check.proxy_reach_failed",
                &[("state", word.as_str()), ("error", e)],
            )
        }
    };
    format!("{label}{body}")
}

/// `rustls::ProtocolVersion`'s `Debug` spells TLS 1.3 `TLSv1_3`; the operator reads `TLS 1.3`.
fn tls_version_name(v: Option<&str>) -> String {
    match v {
        Some("TLSv1_3") => "TLS 1.3".into(),
        Some("TLSv1_2") => "TLS 1.2".into(),
        Some(other) => other.into(),
        None => "?".into(),
    }
}

/// Asks the `openssl` CLI what the upstream proxy negotiates with it (#206).
///
/// OpenSSL implements the RSA key exchange rustls does not, so where the relay gets
/// `HandshakeFailure` this still completes and names the protocol and cipher the proxy chose —
/// exactly the two lines the reporter got by hand. Best effort: no openssl, a timeout or a
/// non-zero exit all just leave the section out with a note.
async fn print_openssl_offers(px: &ProxySpec) {
    let Ok(url) = url::Url::parse(&px.url) else {
        return;
    };
    let Some(host) = url.host_str() else { return };
    let port = url.port_or_known_default().unwrap_or(3128);
    let endpoint = format!("{host}:{port}");
    // Not installed, or it hung: `openssl_brief` gives nothing, and we say where to look instead.
    let lines = crate::netutil::openssl_brief(host, port).await;
    if lines.is_empty() {
        println!(
            "{}",
            tf(
                "op.check.proxy_offers_none",
                &[("endpoint", &endpoint), ("host", host)]
            )
        );
        return;
    }
    println!("{}", t("op.check.proxy_offers"));
    for l in lines {
        println!("    {l}");
    }
}

fn store_paths(config: &Path) -> anyhow::Result<PathBuf> {
    Ok(resolve(config)?.paths.control_sock)
}

/// Change the store's passphrase, and with it the KDF if asked.
///
/// The KDF parameters are stored beside the wrapped DEK, so switching between Argon2id and PBKDF2
/// is the same one-row write. The records are not touched: their `alg` is a separate thing, and
/// changing *that* would mean re-sealing every value.
pub async fn change_passphrase(path: &Path, kdf: Option<&str>) -> anyhow::Result<()> {
    let sock = store_paths(path)?;
    let old = store::control::prompt("Current passphrase")?;
    let new = store::control::prompt("New passphrase")?;
    let again = store::control::prompt("Again")?;
    if new.as_bytes() != again.as_bytes() {
        anyhow::bail!("the two did not match");
    }
    if new.as_bytes() == old.as_bytes() {
        anyhow::bail!("the new passphrase is the old one");
    }
    let body = serde_json::json!({
        "op": "passphrase",
        "old": String::from_utf8_lossy(old.as_bytes()),
        "new": String::from_utf8_lossy(new.as_bytes()),
        "kdf": kdf,
    })
    .to_string();
    let (ok, message) = store::control::call(&sock, &body).await?;
    println!("{message}");
    if ok {
        Ok(())
    } else {
        anyhow::bail!("{message}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The adversarial case for `--stdin`: a passphrase nobody confirmed becoming the one the
    /// store is created with. Nothing would look wrong at the time — the store opens with it —
    /// and the mistake surfaces as a keychain entry nobody can reproduce.
    #[test]
    fn a_piped_passphrase_is_refused_on_a_store_that_has_none_yet() {
        let err = unlock_step("not initialised", true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("gw:unlock"), "say what to run instead: {err}");
        // and the three that are allowed through
        assert_eq!(
            unlock_step("not initialised", false).unwrap(),
            UnlockStep::SetTheFirstPassphrase
        );
        assert_eq!(unlock_step("locked", true).unwrap(), UnlockStep::Open);
        assert_eq!(
            unlock_step("unlocked", true).unwrap(),
            UnlockStep::AlreadyUnlocked
        );
    }

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

    /// #194: the reporter's `check` said "credential: none" while the store held one and was
    /// merely locked, which reads as "nothing registered" and sends the operator to the wrong
    /// command. The store's state is what tells the two apart.
    #[test]
    fn a_locked_store_and_an_empty_one_do_not_read_the_same() {
        let bare = |user: Option<&str>| ProxySpec {
            url: "http://proxy.example:8080".into(),
            username: user.map(str::to_string),
            password: None,
            stored: Default::default(),
            via_squid: None,
        };

        let locked = credential_status("locked", &bare(None));
        let unset = credential_status("unlocked", &bare(None));
        assert_ne!(locked, unset);
        assert!(locked.contains("gw:unlock"), "say what to run: {locked}");
        assert!(
            unset.contains("gw:proxy-credential"),
            "say what to run: {unset}"
        );
        // A store that was never created is as unreadable as a locked one, and the way out is
        // the same command.
        assert_eq!(credential_status("not initialised", &bare(None)), locked);

        // No relay answering at all: there is no store to advise about, so the bare word and no
        // remedy. #202 took the word out of the locale, so read it from there too.
        assert_eq!(
            credential_status("", &bare(None)),
            t("op.check.word.credential_none")
        );

        // A credential in hand is what gets presented, whatever the store says a moment later.
        let from_env = bare(Some("alice"));
        assert_eq!(
            credential_status("locked", &from_env),
            from_env.credential_source()
        );
        let from_store = bare(None);
        from_store.stored.set(Some(("bob".into(), "sekret".into())));
        assert_eq!(
            credential_status("unlocked", &from_store),
            "the secret store (gw:proxy-credential)"
        );
    }

    /// #202: the state words carry a colour when stdout is a terminal, and the line is
    /// byte-identical without one. `check` and `store-status` are read by scripts too.
    #[test]
    fn the_state_words_are_coloured_only_when_colour_is_on() {
        use super::super::color::set_for_tests;

        set_for_tests(Some(false));
        assert_eq!(paint_store_state("unlocked"), "unlocked");
        assert_eq!(paint_store_state("locked"), "locked");
        assert_eq!(paint_store_state("not initialised"), "not initialised");

        set_for_tests(Some(true));
        assert_eq!(paint_store_state("unlocked"), "\x1b[32munlocked\x1b[0m");
        assert_eq!(paint_store_state("locked"), "\x1b[31mlocked\x1b[0m");
        assert_eq!(
            paint_store_state("not initialised"),
            "\x1b[33mnot initialised\x1b[0m"
        );
        // Anything the socket says that is not one of the three states stays plain.
        assert_eq!(paint_store_state("no such op"), "no such op");

        let bare = |user: Option<&str>| ProxySpec {
            url: "http://proxy.example:8080".into(),
            username: user.map(str::to_string),
            password: None,
            stored: Default::default(),
            via_squid: None,
        };
        // The store is where the credential belongs; the environment works but is not advised.
        let from_store = bare(None);
        from_store.stored.set(Some(("bob".into(), "sekret".into())));
        assert_eq!(
            credential_status("unlocked", &from_store),
            "\x1b[32mthe secret store (gw:proxy-credential)\x1b[0m"
        );
        assert_eq!(
            credential_status("unlocked", &bare(Some("alice"))),
            "\x1b[33mSEKIMORE_UPSTREAM_PROXY_* or config.yml\x1b[0m"
        );
        // Only the leading word is painted; the remedy after the dash stays plain.
        let locked = credential_status("locked", &bare(None));
        assert!(
            locked.starts_with("\x1b[31m") && locked.contains("\x1b[0m — "),
            "paint the word, not the remedy: {locked:?}"
        );
        assert!(!locked.trim_end().ends_with("\x1b[0m"), "{locked:?}");

        set_for_tests(None);
    }

    /// #206: `check` used never to touch the upstream proxy. The line it prints now.
    #[test]
    fn the_reach_line_says_what_the_handshake_got() {
        use super::super::color::set_for_tests;
        use crate::netutil::ProbeReport;
        set_for_tests(Some(true));

        // The state word is whatever the locale calls it; the shape around it is what is fixed.
        let ok_word = t("op.check.word.proxy_reachable");
        let bad_word = t("op.check.word.proxy_unreachable");

        let good = Ok(ProbeReport {
            endpoint: "gw.example:3129".into(),
            tls: true,
            protocol: Some("TLSv1_3".into()),
            cipher: Some("TLS13_AES_256_GCM_SHA384".into()),
        });
        let line = proxy_reach_line(&good);
        assert_eq!(
            line,
            format!(
                "  reach:      \u{1b}[32m{ok_word}\u{1b}[0m (TLS 1.3, TLS13_AES_256_GCM_SHA384)"
            )
        );

        // An `http://` proxy: TCP only, and the line says so rather than inventing a version.
        let plain = Ok(ProbeReport {
            endpoint: "gw.example:3128".into(),
            tls: false,
            protocol: None,
            cipher: None,
        });
        let line = proxy_reach_line(&plain);
        assert!(
            line.contains(&format!("\u{1b}[32m{ok_word}\u{1b}[0m (")),
            "{line}"
        );
        assert!(line.contains("TCP"), "{line}");
        assert!(
            !line.contains("TLS 1."),
            "a plain proxy has no version: {line}"
        );

        // The failure the reporter hit: red word, plain error after it.
        let bad: Result<ProbeReport, String> =
            Err("TLS to the proxy failed: received fatal alert: HandshakeFailure".into());
        let line = proxy_reach_line(&bad);
        assert!(
            line.starts_with(&format!("  reach:      \u{1b}[31m{bad_word}\u{1b}[0m — ")),
            "{line}"
        );
        assert!(line.contains("HandshakeFailure"), "{line}");
        // Only the state word is painted, so the layout is the same without colour.
        assert!(!line.trim_end().ends_with("\u{1b}[0m"), "{line}");

        set_for_tests(Some(false));
        assert_eq!(
            proxy_reach_line(&good),
            format!("  reach:      {ok_word} (TLS 1.3, TLS13_AES_256_GCM_SHA384)")
        );
        // `proxy:` and `reach:` line up: both labels are padded to the same width.
        assert_eq!(
            pad_label(&t("op.check.proxy"), 14).len(),
            pad_label(&t("op.check.proxy_reach"), 14).len()
        );

        set_for_tests(None);
    }

    /// #205: the via-Squid route's own `reach:` line. A 200 is green; a 5xx says Squid could not
    /// reach its peer, which sends the operator somewhere else entirely than a refusal does.
    #[test]
    fn the_squid_reach_line_says_which_hop_failed() {
        use super::super::color::set_for_tests;
        use crate::netutil::SquidProbe;
        set_for_tests(Some(false));

        let ok_word = t("op.check.word.proxy_reachable");
        let bad_word = t("op.check.word.proxy_unreachable");
        let probe = |status: &str, line: &str| SquidProbe {
            endpoint: "127.0.0.1:3128".into(),
            target: "api.github.com".into(),
            status: status.into(),
            status_line: line.into(),
        };

        let open = Ok(probe("200", "HTTP/1.1 200 Connection established"));
        let line = squid_reach_line(&open);
        assert!(line.starts_with("  reach:      "), "{line}");
        assert!(line.contains(&ok_word), "{line}");
        assert!(line.contains("127.0.0.1:3128"), "{line}");
        assert!(line.contains("api.github.com:443"), "{line}");
        assert!(!squid_probe_failed(&open));
        // No rustls handshake is reported: on this route the relay never takes one, and saying
        // TLS 1.2 / TLS 1.3 here would name a hop the relay does not make.
        assert!(!line.contains("TLS 1."), "{line}");

        // Squid answered, but could not reach the upstream proxy.
        let peer = Ok(probe("503", "HTTP/1.1 503 Service Unavailable"));
        let line = squid_reach_line(&peer);
        assert!(line.contains(&bad_word), "{line}");
        assert!(line.contains("503 Service Unavailable"), "{line}");
        assert!(squid_probe_failed(&peer));

        // Squid refused the request itself: a different remedy, so a different sentence. The
        // wording is the locale's, and only that the two differ is ours to pin down.
        let refused = Ok(probe("403", "HTTP/1.1 403 Forbidden"));
        let other = squid_reach_line(&refused);
        assert!(other.contains("403 Forbidden"), "{other}");
        assert_ne!(
            line.replace("503 Service Unavailable", ""),
            other.replace("403 Forbidden", ""),
            "a 5xx is Squid's peer, a 4xx is Squid itself; say which"
        );
        assert!(squid_probe_failed(&refused));

        // Nothing listening on the loopback port: the error itself, and not a status line.
        let down: Result<SquidProbe, String> = Err("Connection refused (os error 111)".into());
        let line = squid_reach_line(&down);
        assert!(line.contains("Connection refused"), "{line}");
        assert!(line.contains(&bad_word), "{line}");
        assert!(squid_probe_failed(&down));

        // The English wording each case is meant to produce, since the assertions above are
        // deliberately locale-independent and would pass on a sentence that says nothing.
        let en = |k: &str| crate::i18n::t_in("en", k);
        assert!(en("op.check.proxy_reach_squid").contains("via Squid"));
        assert!(
            en("op.check.proxy_reach_squid_peer").contains("could not reach the upstream proxy")
        );
        assert!(en("op.check.proxy_reach_squid_down").contains("Squid is not listening"));
        assert!(en("op.check.proxy_route_squid").contains("via the local Squid"));
        assert!(en("op.check.proxy_route_direct").contains("rustls"));

        // Only the state word carries colour, as on the direct route.
        set_for_tests(Some(true));
        let line = squid_reach_line(&open);
        assert!(
            line.starts_with(&format!("  reach:      \u{1b}[32m{ok_word}\u{1b}[0m")),
            "{line}"
        );
        assert!(!line.trim_end().ends_with("\u{1b}[0m"), "{line}");

        set_for_tests(None);
    }

    /// #205: the probe has to ask for a host the relay would really ask for, or it proves nothing
    /// about the path real traffic takes.
    #[test]
    fn the_squid_probe_prefers_the_github_api_host() {
        use crate::config::{HandlerKind, HttpsTarget};
        let target = |domain: &str, host: &str| HttpsTarget {
            domain: domain.into(),
            host: host.into(),
            max_upload: None,
            kind: HandlerKind::Github,
        };
        let px = ProxySpec {
            url: "https://gw.example.net:3129".into(),
            username: None,
            password: None,
            stored: Default::default(),
            via_squid: Some(3128),
        };
        let with = |targets: Vec<HttpsTarget>| squid_probe_target(&targets, &px);

        // The one the GitHub API client uses, wherever it sits in the list.
        assert_eq!(
            with(vec![
                target("registry.npmjs.org", "registry.npmjs.org"),
                target("github.com", "api.github.com"),
            ]),
            "api.github.com"
        );
        // Otherwise the first target there is.
        assert_eq!(
            with(vec![target("registry.npmjs.org", "registry.npmjs.org")]),
            "registry.npmjs.org"
        );
        // Nothing relayed at all: ask for the upstream proxy's own host, so Squid still has to
        // reach its peer to answer.
        assert_eq!(with(Vec::new()), "gw.example.net");
    }

    #[test]
    fn rustls_version_names_are_spelled_for_a_person() {
        assert_eq!(tls_version_name(Some("TLSv1_3")), "TLS 1.3");
        assert_eq!(tls_version_name(Some("TLSv1_2")), "TLS 1.2");
        // Anything rustls starts reporting later goes through as it is, rather than becoming "?".
        assert_eq!(tls_version_name(Some("TLSv1_4")), "TLSv1_4");
        assert_eq!(tls_version_name(None), "?");
    }
}
