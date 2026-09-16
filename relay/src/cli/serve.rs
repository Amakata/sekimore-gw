//! `serve`: SSH（git）+ HTTP（API）+ 443 passthrough を起動する。
//!
//! 0.2.0: git-relay ドメイン（上流）ごとに SSH listener を 1 本ずつ持つ。SSH の exec にはホスト名が
//! 無いので、接続を受けたポートで上流を決め、その上流専用の `GitContext`（上流 git / GitHub client /
//! known_hosts）でセッションを処理する。上流が 1 つなら 0.1.x と同じ構成になる。

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::operator::{build_github_for, open_audit, resolve};
use crate::api::types::GitDomain;
use crate::api::{self, ApiContext};
use crate::audit::Actor;
use crate::config::{HttpsMode, Resolved, Upstream};
use crate::git::agent_check::{auth_sock_from_env, preflight_agent};
use crate::git::upstream_ssh::OpenSshUpstream;
use crate::git::{GitContext, UpstreamGit};
use crate::github::GitHub;
use crate::passthrough::{Passthrough, SniTarget};
use crate::ssh::authorized_keys::AuthorizedKeys;
use crate::ssh::{load_or_create_host_key, server_config, SshServer};
use crate::tokens::TokenStore;

pub const MAX_AUTHORIZED_KEYS: usize = 64;

pub async fn serve(path: &Path) -> anyhow::Result<()> {
    let r = resolve(path)?;
    let audit = open_audit(&r)?;
    let upstreams_summary = r
        .upstreams
        .iter()
        .map(|u| format!("{}→{} (ssh :{})", u.domain, u.host, u.listen.port()))
        .collect::<Vec<_>>()
        .join(", ");
    log::info!(
        "sekimore-relay {} starting (project={}, upstreams: {})",
        env!("CARGO_PKG_VERSION"),
        r.project.name,
        upstreams_summary
    );

    let host_key = load_or_create_host_key(&r.paths.host_key)?;
    let keys = Arc::new(AuthorizedKeys::new(
        &r.paths.authorized_keys,
        MAX_AUTHORIZED_KEYS,
    ));

    // 起動を止めない警告（agent / keys。上流ごとのものは下のループで）
    let sock = auth_sock_from_env();
    match preflight_agent(sock.as_deref()).await {
        Ok(n) => log::info!("ssh-agent: {n} identities"),
        Err(e) => log::warn!("ssh-agent not usable yet: {e}"),
    }
    if keys.count() == 0 {
        log::warn!("authorized_keys is empty; agents must bootstrap (POST /bootstrap) or the operator must `add-key`");
    }

    // 上流ごと: GitHub client / 上流 git / SSH listener。russh 設定・鍵・セッション上限は共有
    let ssh_config = Arc::new(server_config(host_key, r.relay.limits.session_timeout));
    let sessions = Arc::new(Semaphore::new(r.relay.limits.max_sessions.max(1)));
    let mut githubs: HashMap<String, Arc<GitHub>> = HashMap::new();
    let mut ssh_servers = Vec::new();
    for up in &r.upstreams {
        let (github, upstream_tokens, _http) = build_github_for(&r, up, audit.clone())?;
        if upstream_tokens.load()?.is_none() {
            log::warn!(
                "[{}] no upstream API token in {}; PR/API operations will fail until `sekimore-relay login{}`",
                up.domain,
                up.upstream_token.display(),
                if up.is_default {
                    String::new()
                } else {
                    format!(" --upstream {}", up.domain)
                }
            );
        }
        let upstream: Arc<dyn UpstreamGit> = build_upstream(&r, up);
        if let Err(e) = upstream.preflight().await {
            log::warn!("[{}] upstream preflight: {}", up.domain, e.message);
        }
        githubs.insert(up.domain.clone(), github.clone());

        let git_ctx = Arc::new(GitContext {
            project: r.project.clone(),
            host: up.domain.clone(),
            upstream,
            github: Some(github),
            audit: audit.clone(),
            limits: r.relay.limits.clone(),
        });
        let ssh = SshServer::shared(
            ssh_config.clone(),
            git_ctx,
            keys.clone(),
            audit.clone(),
            sessions.clone(),
        );
        let listener = TcpListener::bind(up.listen)
            .await
            .with_context(|| format!("bind ssh {} for {}", up.listen, up.domain))?;
        log::info!(
            "ssh listening on {} for {} → {}:{} (git-upload-pack / git-receive-pack only)",
            up.listen,
            up.domain,
            up.host,
            up.upstream_ssh_port
        );
        ssh_servers.push((ssh, listener));
    }

    let api_ctx = Arc::new(ApiContext {
        project: r.project.clone(),
        tokens: TokenStore::new(&r.paths.tokens),
        githubs,
        audit: audit.clone(),
        keys,
        bootstrap: r.relay.bootstrap,
        bootstrap_disabled_path: r.paths.bootstrap_disabled.clone(),
        token_ttl: r.relay.token_ttl,
        body_cap: r.relay.limits.api_body_max_bytes,
        rate: Mutex::new(VecDeque::new()),
        git_domain: r.domain.clone(),
        upstream: r.upstream.clone(),
        git_domains: git_domains(&r),
    });
    let api_listener = TcpListener::bind(r.relay.api_listen)
        .await
        .with_context(|| format!("bind api {}", r.relay.api_listen))?;
    log::info!(
        "api listening on {} (bootstrap={:?})",
        r.relay.api_listen,
        r.relay.bootstrap
    );

    // 443: 複数上流なら ClientHello の SNI で上流を選ぶ。無い / 一致しなければ既定上流
    let pt = Arc::new(Passthrough {
        upstream: r.upstream.clone(),
        port: 443,
        upstreams: r
            .upstreams
            .iter()
            .map(|u| SniTarget {
                domain: u.domain.clone(),
                host: u.host.clone(),
                port: 443,
            })
            .collect(),
        mode: r.relay.https,
        proxy: r.proxy.clone(),
        idle: r.relay.limits.idle_timeout,
        conns: tokio::sync::Semaphore::new(r.relay.limits.max_passthrough_conns.max(1)),
        audit: audit.clone(),
        allow_local: false,
    });
    let https_listener = TcpListener::bind(r.relay.https_listen)
        .await
        .with_context(|| format!("bind https {}", r.relay.https_listen))?;
    log::info!(
        "https on {}: {}",
        r.relay.https_listen,
        match r.relay.https {
            HttpsMode::Passthrough if r.upstreams.len() > 1 =>
                "TCP passthrough to <upstream by SNI>:443",
            HttpsMode::Passthrough => "TCP passthrough to upstream:443",
            HttpsMode::Reject => "reject (RST + audit)",
        }
    );
    audit.log(
        "serve_started",
        Actor::System,
        &[
            ("project", &r.project.name),
            ("domain", &r.domain),
            ("upstream", &r.upstream),
            ("upstreams", &upstreams_summary),
        ],
    );

    let mut ssh_tasks = JoinSet::new();
    for (ssh, listener) in ssh_servers {
        ssh_tasks.spawn(ssh.run(listener));
    }
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        Some(r) = ssh_tasks.join_next() => r.context("ssh task")?.context("ssh server")?,
        r = api::serve(api_ctx, api_listener) => r.context("api server")?,
        r = pt.run(https_listener) => r.context("https passthrough")?,
        _ = tokio::signal::ctrl_c() => log::info!("SIGINT: shutting down"),
        _ = sigterm.recv() => log::info!("SIGTERM: shutting down"),
    }
    audit.log("serve_stopped", Actor::System, &[]);
    Ok(())
}

/// `/bootstrap` の応答に載せる全 git ドメイン（先頭が既定上流）。
fn git_domains(r: &Resolved) -> Vec<GitDomain> {
    r.upstreams
        .iter()
        .map(|u| GitDomain {
            domain: u.domain.clone(),
            ssh_port: u.listen.port(),
            upstream: u.host.clone(),
            default: u.is_default,
        })
        .collect()
}

fn build_upstream(r: &Resolved, up: &Upstream) -> Arc<dyn UpstreamGit> {
    #[cfg(feature = "test-hooks")]
    {
        let root = r
            .relay
            .upstream_local_roots
            .get(&up.domain)
            .or(r.relay.upstream_local_root.as_ref());
        if let Some(root) = root {
            log::warn!(
                "test-hooks: [{}] using local git upstream under {}",
                up.domain,
                root.display()
            );
            return Arc::new(crate::git::upstream_local::LocalGitUpstream::new(root));
        }
    }
    Arc::new(
        OpenSshUpstream::new(
            &up.host,
            up.upstream_ssh_port,
            &up.known_hosts,
            r.relay.ssh_config.as_deref(),
        )
        .with_options(up.ssh_options.clone()),
    )
}
