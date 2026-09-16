//! `serve`: SSH（git）+ HTTP（API）+ 443 passthrough を起動する。

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use tokio::net::TcpListener;

use super::operator::{build_github, open_audit, resolve};
use crate::api::{self, ApiContext};
use crate::audit::Actor;
use crate::config::HttpsMode;
use crate::git::agent_check::{auth_sock_from_env, preflight_agent};
use crate::git::upstream_ssh::OpenSshUpstream;
use crate::git::{GitContext, UpstreamGit};
use crate::passthrough::Passthrough;
use crate::ssh::authorized_keys::AuthorizedKeys;
use crate::ssh::{load_or_create_host_key, server_config, SshServer};
use crate::tokens::TokenStore;

pub const MAX_AUTHORIZED_KEYS: usize = 64;

pub async fn serve(path: &Path) -> anyhow::Result<()> {
    let r = resolve(path)?;
    let audit = open_audit(&r)?;
    log::info!(
        "sekimore-relay {} starting (project={}, domain={}, upstream={})",
        env!("CARGO_PKG_VERSION"),
        r.project.name,
        r.domain,
        r.upstream
    );

    let host_key = load_or_create_host_key(&r.paths.host_key)?;
    let keys = Arc::new(AuthorizedKeys::new(
        &r.paths.authorized_keys,
        MAX_AUTHORIZED_KEYS,
    ));
    let (github, upstream_tokens, _http) = build_github(&r, audit.clone())?;

    // 起動を止めない警告（agent / known_hosts / token / keys）
    let sock = auth_sock_from_env();
    match preflight_agent(sock.as_deref()).await {
        Ok(n) => log::info!("ssh-agent: {n} identities"),
        Err(e) => log::warn!("ssh-agent not usable yet: {e}"),
    }
    let upstream: Arc<dyn UpstreamGit> = build_upstream(&r);
    if let Err(e) = upstream.preflight().await {
        log::warn!("upstream preflight: {}", e.message);
    }
    if upstream_tokens.load()?.is_none() {
        log::warn!(
            "no upstream API token in {}; PR/API operations will fail until `sekimore-relay login`",
            r.paths.upstream_token.display()
        );
    }
    if keys.count() == 0 {
        log::warn!("authorized_keys is empty; agents must bootstrap (POST /bootstrap) or the operator must `add-key`");
    }

    let git_ctx = Arc::new(GitContext {
        project: r.project.clone(),
        upstream,
        github: Some(github.clone()),
        audit: audit.clone(),
        limits: r.relay.limits.clone(),
    });
    let ssh = SshServer::new(
        server_config(host_key, r.relay.limits.session_timeout),
        git_ctx,
        keys.clone(),
        audit.clone(),
        r.relay.limits.max_sessions,
    );
    let ssh_listener = TcpListener::bind(r.relay.ssh_listen)
        .await
        .with_context(|| format!("bind ssh {}", r.relay.ssh_listen))?;
    log::info!(
        "ssh listening on {} (git-upload-pack / git-receive-pack only)",
        r.relay.ssh_listen
    );

    let api_ctx = Arc::new(ApiContext {
        project: r.project.clone(),
        tokens: TokenStore::new(&r.paths.tokens),
        github: Some(github),
        audit: audit.clone(),
        keys,
        bootstrap: r.relay.bootstrap,
        bootstrap_disabled_path: r.paths.bootstrap_disabled.clone(),
        token_ttl: r.relay.token_ttl,
        body_cap: r.relay.limits.api_body_max_bytes,
        rate: Mutex::new(VecDeque::new()),
        git_domain: r.domain.clone(),
        upstream: r.upstream.clone(),
    });
    let api_listener = TcpListener::bind(r.relay.api_listen)
        .await
        .with_context(|| format!("bind api {}", r.relay.api_listen))?;
    log::info!(
        "api listening on {} (bootstrap={:?})",
        r.relay.api_listen,
        r.relay.bootstrap
    );

    let pt = Arc::new(Passthrough {
        upstream: r.upstream.clone(),
        port: 443,
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
        ],
    );

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        r = ssh.run(ssh_listener) => r.context("ssh server")?,
        r = api::serve(api_ctx, api_listener) => r.context("api server")?,
        r = pt.run(https_listener) => r.context("https passthrough")?,
        _ = tokio::signal::ctrl_c() => log::info!("SIGINT: shutting down"),
        _ = sigterm.recv() => log::info!("SIGTERM: shutting down"),
    }
    audit.log("serve_stopped", Actor::System, &[]);
    Ok(())
}

fn build_upstream(r: &crate::config::Resolved) -> Arc<dyn UpstreamGit> {
    #[cfg(feature = "test-hooks")]
    if let Some(root) = &r.relay.upstream_local_root {
        log::warn!(
            "test-hooks: using local git upstream under {}",
            root.display()
        );
        return Arc::new(crate::git::upstream_local::LocalGitUpstream::new(root));
    }
    Arc::new(OpenSshUpstream::new(
        &r.upstream,
        r.relay.upstream_ssh_port,
        &r.paths.known_hosts,
        r.relay.ssh_config.as_deref(),
    ))
}
