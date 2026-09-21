//! `serve`: starts SSH (git), HTTP (the API) and the 443 passthrough.
//!
//! 0.2.0: one SSH listener per git-relay domain (i.e. per upstream). An SSH exec carries no hostname,
//! so the upstream is determined by the port the connection arrived on, and the session is handled with that
//! upstream's own `GitContext` (upstream git, GitHub client, known_hosts). With a single upstream this is the same setup as 0.1.x.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::operator::{build_github_for, open_audit, resolve};
use crate::api::types::GitDomain;
use crate::api::{self, ApiContext, ProjectBoards};
use crate::audit::Actor;
use crate::config::{HttpsMode, Resolved, Upstream};
use crate::git::agent_check::{auth_sock_from_env, preflight_agent};
use crate::git::upstream_ssh::OpenSshUpstream;
use crate::git::{GitContext, UpstreamGit};
use crate::github::upstream_token::SecretSource;
use crate::github::GitHub;
use crate::passthrough::{Passthrough, SniTarget};
use crate::ssh::authorized_keys::AuthorizedKeys;
use crate::ssh::{load_or_create_host_key, server_config, SshServer};
use crate::store;
use crate::tokens::TokenStore;

pub const MAX_AUTHORIZED_KEYS: usize = 64;

/// Open the secret store and unlock it if the deployment said to. Returns where the rest of the
/// process should read secrets from, and the store itself when there is one to serve.
///
/// This runs before the upstream loop because the upstream token lives in the store now (0.2.18):
/// the loop needs something to read it through, and `serve` is the one process that holds the key.
/// The control socket is started *after* the loop instead — it has to be able to tell the token
/// caches to drop what they hold when someone locks the store, and those caches do not exist yet.
fn open_secret_store(
    r: &Resolved,
) -> (
    SecretSource,
    Option<Arc<tokio::sync::Mutex<store::SecretStore>>>,
) {
    // The store starts locked. The control socket is what a person unlocks it through, and it
    // lives beside the state rather than on the agent-facing API — an agent able to ask the relay
    // to unlock itself would make the passphrase pointless.
    let mut store = match store::SecretStore::open(&r.paths.secrets) {
        Ok(s) => s,
        Err(e) => {
            log::error!("secret store unavailable ({e}); no secret can be read");
            return (SecretSource::Unavailable(e.to_string()), None);
        }
    };
    // 0.2.17: unlock without a person, when the deployment asked for that. The passphrase comes
    // from outside the worktree either way — the agent can write `.devcontainer/.env`, so anything
    // reachable from there would be its own passphrase.
    match store_passphrase(&r.relay.store.unlock) {
        Ok(None) => {}
        Ok(Some(pass)) => {
            let outcome = match store.is_initialised() {
                // Not `unwrap_or(false)`: a database that cannot be read would then be treated as
                // a new store, and the error the operator needs to see would be replaced by
                // "already initialised" from the attempt to create one.
                Err(e) => Err(e),
                Ok(true) => store.unlock(&pass),
                Ok(false) => store.initialise(
                    &pass,
                    store::crypto::Kdf::Argon2id,
                    store::crypto::KdfParams::default(),
                ),
            };
            match outcome {
                // Loud on purpose: a passphrase that lives in a file or an environment is a
                // development convenience, and a deployment that ends up with one should find it
                // in the log rather than in a review a year later.
                Ok(()) => log::warn!(
                    "secret store unlocked from configuration — the passphrase is at rest; \
                     relay.store.unlock: prompt is what a deployment wants"
                ),
                Err(e) => log::error!("secret store stays locked: {e}"),
            }
        }
        Err(e) => log::error!("secret store stays locked: {e}"),
    }
    let store = Arc::new(tokio::sync::Mutex::new(store));
    (SecretSource::InProcess(store.clone()), Some(store))
}

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

    // Warnings that do not stop startup (agent / keys; the per-upstream ones are in the loop below)
    let sock = auth_sock_from_env();
    match preflight_agent(sock.as_deref()).await {
        Ok(n) => log::info!("ssh-agent: {n} identities"),
        Err(e) => log::warn!("ssh-agent not usable yet: {e}"),
    }
    if keys.count() == 0 {
        log::warn!("authorized_keys is empty; agents must bootstrap (POST /bootstrap) or the operator must `add-key`");
    }

    // The secret store before the loop: the upstream token lives in it (0.2.18), so each upstream
    // needs somewhere to read it from.
    let (secrets, secret_store) = open_secret_store(&r);
    let mut token_caches: Vec<Arc<crate::github::upstream_token::UpstreamTokenStore>> = Vec::new();

    // Per upstream: GitHub client, upstream git, SSH listener. The russh config, keys and session limit are shared
    let ssh_config = Arc::new(server_config(host_key, r.relay.limits.session_timeout));
    let sessions = Arc::new(Semaphore::new(r.relay.limits.max_sessions.max(1)));
    let mut githubs: HashMap<String, Arc<GitHub>> = HashMap::new();
    let mut ssh_servers = Vec::new();
    for up in &r.upstreams {
        let (github, upstream_tokens, _http) =
            build_github_for(&r, up, audit.clone(), secrets.clone())?;
        token_caches.push(upstream_tokens.clone());
        // A locked store is not "no token" — it is a token nobody can read yet, and the answer is
        // the passphrase rather than a login. Say which, because they send the operator to
        // different commands.
        let which_upstream = if up.is_default {
            String::new()
        } else {
            format!(" --upstream {}", up.domain)
        };
        match upstream_tokens.load().await {
            Ok(Some(_)) => {}
            Ok(None) => log::warn!(
                "[{}] no upstream API token; PR/API operations will fail until `sekimore-relay login{}`",
                up.domain,
                which_upstream
            ),
            Err(e) => log::warn!(
                "[{}] the upstream API token cannot be read yet: {e}",
                up.domain
            ),
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

    // 0.2.7: the boards a project may touch. Resolving one to its node id is a GraphQL call, so
    // it needs the upstream API token — which since 0.2.19 lives in the secret store, locked at
    // start-up. Doing it here meant every board failed to resolve and stayed refused for the life
    // of the process, even after someone unlocked (#99). `ProjectBoards` does it on first use.
    if r.relay.project.boards.is_empty()
        && r.project
            .granted()
            .iter()
            .any(|k| k.starts_with("project:"))
    {
        log::warn!(
            "project:* is granted but relay.project.boards is empty; every Projects operation will be refused"
        );
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
        project_boards: ProjectBoards::new(r.relay.project.boards.clone()),
    });
    // The control socket last, now that the token caches exist. `lock` has to reach them: a key
    // dropped from the store while a decrypted token sits in a cache is a lock that leaves that
    // token usable for the rest of the cache TTL — two hours by default.
    if let Some(store) = secret_store {
        let sock = r.paths.control_sock.clone();
        let caches = token_caches;
        let on_lock: store::control::OnLock = Arc::new(move || {
            for c in &caches {
                c.forget();
            }
        });
        tokio::spawn(async move {
            if let Err(e) = store::control::serve(sock, store, on_lock).await {
                log::error!("control socket: {e}");
            }
        });
    }

    let api_listener = TcpListener::bind(r.relay.api_listen)
        .await
        .with_context(|| format!("bind api {}", r.relay.api_listen))?;
    log::info!(
        "api listening on {} (bootstrap={:?})",
        r.relay.api_listen,
        r.relay.bootstrap
    );

    // 443: with multiple upstreams, pick by the ClientHello SNI; fall back to the default when absent or unmatched
    let pt = Arc::new(Passthrough {
        upstream: r.upstream.clone(),
        port: 443,
        upstreams: r
            .https_targets
            .iter()
            .map(|t| SniTarget {
                domain: t.domain.clone(),
                host: t.host.clone(),
                port: 443,
                max_upload: t.max_upload,
            })
            .collect(),
        max_upload: r.default_upstream().max_upload,
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
            HttpsMode::Passthrough if r.https_targets.len() > 1 =>
                "TCP passthrough to <target by SNI>:443",
            HttpsMode::Passthrough => "TCP passthrough to upstream:443",
            HttpsMode::Reject => "reject (RST + audit)",
        }
    );
    if r.relay.https == HttpsMode::Passthrough {
        for t in &r.https_targets {
            log::info!(
                "https target {} → {}:443 ({:?}, upload cap {})",
                t.domain,
                t.host,
                t.kind,
                t.max_upload
                    .map(|c| format!("{c} bytes"))
                    .unwrap_or_else(|| "unlimited".to_string())
            );
        }
    }
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

/// Every git domain to report in the `/bootstrap` response (the first is the default upstream).
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

/// Say so when the passphrase file is readable by anyone but its owner.
///
/// A warning rather than a refusal: the relay cannot tell a deliberately shared mount from a
/// mistake, and refusing to start over a file mode would be a poor trade. Being unable to read the
/// mode at all is not worth reporting — the read that follows will fail with something better.
fn warn_if_readable_by_others(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(md) = std::fs::metadata(path) {
        let mode = md.permissions().mode() & 0o077;
        if mode != 0 {
            log::warn!(
                "the store passphrase at {} is readable by others (mode {:o}); chmod 600 it",
                path.display(),
                md.permissions().mode() & 0o777
            );
        }
    }
}

/// The passphrase the configuration points at, or `None` when a person is meant to type it.
///
/// A missing file or an unset variable is an error rather than a silent fall back to locked: the
/// deployment said where the passphrase is, so not finding it is worth saying out loud.
fn store_passphrase(
    unlock: &crate::config::StoreUnlock,
) -> anyhow::Result<Option<store::crypto::Secret>> {
    use crate::config::StoreUnlock;
    let raw = match unlock {
        StoreUnlock::Prompt => return Ok(None),
        StoreUnlock::File { path } => {
            warn_if_readable_by_others(path);
            std::fs::read_to_string(path)
                .with_context(|| format!("read the store passphrase from {}", path.display()))?
        }
        StoreUnlock::Env { var } => {
            std::env::var(var).with_context(|| format!("read the store passphrase from ${var}"))?
        }
    };
    // A file written with an editor ends in a newline; a passphrase does not.
    let trimmed = raw.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        anyhow::bail!("the configured store passphrase is empty");
    }
    Ok(Some(store::crypto::Secret::new(
        trimmed.as_bytes().to_vec(),
    )))
}

#[cfg(test)]
mod store_unlock_tests {
    use super::store_passphrase;
    use crate::config::StoreUnlock;

    #[test]
    fn prompt_asks_for_nothing() {
        assert!(store_passphrase(&StoreUnlock::Prompt).unwrap().is_none());
    }

    #[test]
    fn a_file_is_read_without_its_trailing_newline() {
        // An editor adds one and a passphrase does not have one, so a file written by hand would
        // otherwise derive a different key than the same passphrase typed at the prompt.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pass");
        std::fs::write(&p, "correct horse\n").unwrap();
        let got = store_passphrase(&StoreUnlock::File { path: p })
            .unwrap()
            .unwrap();
        assert_eq!(got.as_bytes(), b"correct horse");
    }

    #[test]
    fn a_missing_file_is_an_error_not_a_silent_lock() {
        // The deployment said where the passphrase is. Not finding it is worth saying.
        let dir = tempfile::tempdir().unwrap();
        let err = store_passphrase(&StoreUnlock::File {
            path: dir.path().join("absent"),
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("absent"), "{err}");
    }

    #[test]
    fn an_empty_file_is_refused() {
        // Otherwise the store would be initialised under an empty passphrase, silently.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pass");
        std::fs::write(&p, "\n").unwrap();
        assert!(store_passphrase(&StoreUnlock::File { path: p }).is_err());
    }

    #[test]
    fn an_unset_variable_is_an_error() {
        let err = store_passphrase(&StoreUnlock::Env {
            var: "SEKIMORE_TEST_UNSET_PASSPHRASE".into(),
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("SEKIMORE_TEST_UNSET_PASSPHRASE"), "{err}");
    }
}
