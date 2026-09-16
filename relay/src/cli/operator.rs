//! 操作者向けサブコマンド（gateway コンテナ内で実行する）。

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context};

use super::BootstrapAction;
use crate::audit::{Actor, Audit};
use crate::config::{self, ConfigError, Resolved, Upstream};
use crate::fsutil::{atomic_write, ensure_dir_0700, read_optional};
use crate::git::agent_check::{auth_sock_from_env, preflight_agent};
use crate::git::upstream_ssh::OpenSshUpstream;
use crate::github::device_flow::DeviceFlow;
use crate::github::http::{build_client, HttpOptions};
use crate::github::upstream_token::UpstreamTokenStore;
use crate::github::GitHub;
use crate::policy::all_permission_keys;
use crate::ssh::authorized_keys::{Added, AuthorizedKeys};
use crate::tokens::TokenStore;

pub const DEVICE_FLOW_SCOPES: &[&str] = &["repo", "project"];

/// entrypoint.sh 用。0 = 起動 / 1 = 不要 / 2 = 設定不正。
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

/// 既定上流の GitHub client（0.1.x 互換）。
pub fn build_github(
    r: &Resolved,
    audit: Arc<Audit>,
) -> anyhow::Result<(Arc<GitHub>, Arc<UpstreamTokenStore>, reqwest::Client)> {
    build_github_for(r, r.default_upstream(), audit)
}

/// 上流ごとの GitHub client（api_base / graphql_base / upstream_token はその上流のもの。0.2.0）。
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

/// `--upstream` の解決。省略時は既定上流。
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
        println!(
            "upstream: {} ({}){}",
            up.domain,
            up.host,
            if up.is_default { " [default]" } else { "" }
        );
    }
    let flow = DeviceFlow::new(&up.host, &up.oauth_client_id, DEVICE_FLOW_SCOPES, http)?;
    let (token, scope) = flow
        .authenticate(|code, url| {
            println!();
            println!("  Open: {url}");
            println!("  Code: {code}");
            println!();
        })
        .await?;
    store.save(&up.host, &token, &scope)?;
    println!(
        "stored upstream token in {} (scopes={scope})",
        up.upstream_token.display()
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
                "known_hosts: {} host key(s) for {} ({} new) → {}",
                keys.len(),
                up.host,
                n,
                up.known_hosts.display()
            );
        }
        Ok(_) => eprintln!(
            "warning: GET /meta returned no ssh_keys; populate {} with ssh-keyscan",
            up.known_hosts.display()
        ),
        Err(e) => eprintln!(
            "warning: could not fetch upstream ssh host keys ({e}); populate {} with ssh-keyscan",
            up.known_hosts.display()
        ),
    }
    match gh.whoami().await {
        Ok(login) => println!("upstream identity: {login}"),
        Err(e) => eprintln!("warning: token stored but /user failed: {e}"),
    }
    Ok(())
}

/// known_hosts に `<host> <key>` 行を追加する（既にある行は足さない）。追加した行数を返す。
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

pub fn logout(path: &Path, upstream: Option<&str>) -> anyhow::Result<()> {
    let r = resolve(path)?;
    let up = pick_upstream(&r, upstream)?;
    let audit = open_audit(&r)?;
    let store = UpstreamTokenStore::new(&up.upstream_token, r.relay.upstream_token_cache_ttl);
    if store.delete()? {
        println!("removed upstream token {}", up.upstream_token.display());
        audit.log(
            "logout",
            Actor::Operator,
            &[("host", &up.host), ("domain", &up.domain)],
        );
    } else {
        println!("no upstream token stored for {}", up.domain);
    }
    Ok(())
}

pub async fn whoami(path: &Path, upstream: Option<&str>) -> anyhow::Result<()> {
    let r = resolve(path)?;
    let up = pick_upstream(&r, upstream)?;
    let audit = open_audit(&r)?;
    let (gh, _, _) = build_github_for(&r, up, audit)?;
    let login = gh.whoami().await?;
    println!("upstream identity: {login} (host={})", up.host);
    println!("note: the gateway acts as this identity. GitHub cannot distinguish");
    println!("      agent actions from yours — the gateway audit log is the only record.");
    Ok(())
}

pub async fn check(path: &Path) -> anyhow::Result<()> {
    let r = resolve(path)?;
    println!("project:      {}", r.project.name);
    let multi = r.upstreams.len() > 1;
    for up in &r.upstreams {
        if multi {
            println!(
                "domain:       {} (git-relay{})",
                up.domain,
                if up.is_default { ", default" } else { "" }
            );
        } else {
            println!("domain:       {} (git-relay)", up.domain);
        }
        println!(
            "  upstream:   {} (ssh port {})",
            up.host, up.upstream_ssh_port
        );
        println!("  rest:       {}", up.api_base);
        println!("  graphql:    {}", up.graphql_base);
        println!("  ssh listen: {}", up.listen);
    }
    println!("api listen:   {}", r.relay.api_listen);
    println!(
        "https:        {:?} on {}",
        r.relay.https, r.relay.https_listen
    );
    println!("state dir:    {}", r.paths.state_dir.display());
    println!(
        "token ttl:    {}",
        humantime::format_duration(r.relay.token_ttl)
    );
    println!(
        "bootstrap:    {:?}{}",
        r.relay.bootstrap,
        if r.paths.bootstrap_disabled.exists() {
            " (DISABLED by kill-switch)"
        } else {
            ""
        }
    );
    // 0.1.9: タグ / 削除 / 権限は案件の既定 + repo の差分。repo ごとの実効値は下の repos に出す
    if let Some(px) = &r.proxy {
        println!("proxy:        {}", px.url);
    }
    println!("\npermissions (default deny):");
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
        println!("  ([-] = project deny; wins over any allow)");
    }
    println!("\nrepos (effective = project defaults + repo allow - deny):");
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
            println!(
                "    permissions: {}",
                if eff.is_empty() {
                    "(none)".to_string()
                } else {
                    eff.join(" ")
                }
            );
        }
    }
    println!("\nstate:");
    let sock = auth_sock_from_env();
    match preflight_agent(sock.as_deref()).await {
        Ok(n) => println!(
            "  ssh-agent:       ok ({n} identities at {})",
            sock.as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ),
        Err(e) => println!("  ssh-agent:       NOT USABLE — {e}"),
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
        );
        match up.known_hosts_has_upstream() {
            Ok(true) => println!("  known_hosts:     ok ({})", u.known_hosts.display()),
            Ok(false) => println!("  known_hosts:     MISSING — {}", up.known_hosts_remedy()),
            Err(e) => println!("  known_hosts:     ERROR — {e}"),
        }
        let store = UpstreamTokenStore::new(&u.upstream_token, r.relay.upstream_token_cache_ttl);
        let login_hint = if u.is_default {
            "sekimore-relay login".to_string()
        } else {
            format!("sekimore-relay login --upstream {}", u.domain)
        };
        match store.load() {
            Ok(Some(t)) => println!(
                "  upstream token:  present (scope={}, obtained {})",
                t.scope,
                humantime::format_rfc3339_seconds(t.obtained_at)
            ),
            Ok(None) => println!("  upstream token:  MISSING — run `{login_hint}`"),
            Err(e) => println!("  upstream token:  ERROR — {e}"),
        }
    }
    let keys = AuthorizedKeys::new(&r.paths.authorized_keys, 64);
    println!(
        "  authorized_keys: {} key(s) ({})",
        keys.count(),
        r.paths.authorized_keys.display()
    );
    let tokens = TokenStore::new(&r.paths.tokens);
    let now = SystemTime::now();
    let list = tokens.list().unwrap_or_default();
    println!(
        "  project tokens:  {} active / {} total",
        list.iter().filter(|t| t.state(now) == "active").count(),
        list.len()
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
