//! SSH server (russh). Public-key authentication only, and only `exec` on a `session` channel.
//!
//! The dependency on russh stays confined to this module. Git work is handed to `git::handle_exec` via `GitIo`.

pub mod authorized_keys;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::LineEnding;
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, MethodKind, MethodSet};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::audit::{Actor, Audit};
use crate::fsutil::atomic_write;
use crate::git::{handle_exec, GitContext, GitIo};
use crate::paths;
use authorized_keys::{fingerprint, AuthorizedKeys};

pub const GIT_USER: &str = "git";

/// How many session channels one connection may hold open at once. A git client opens one and
/// execs on it; anything beyond a couple is a client that is not doing git.
const MAX_OPEN_CHANNELS: usize = 4;

/// Loads the host key, generating an ed25519 key and saving it with mode 0600 if there is none.
pub fn load_or_create_host_key(path: &Path) -> anyhow::Result<PrivateKey> {
    match std::fs::read(path) {
        Ok(bytes) => PrivateKey::from_openssh(&bytes)
            .with_context(|| format!("parse host key {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
            let mut key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
            key.set_comment("sekimore-relay host key");
            let pem = key.to_openssh(LineEnding::LF).context("encode host key")?;
            atomic_write(path, pem.as_bytes(), 0o600)
                .with_context(|| format!("write host key {}", path.display()))?;
            log::info!("generated host key {}", path.display());
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("read host key {}", path.display())),
    }
}

pub fn server_config(host_key: PrivateKey, session_timeout: Duration) -> russh::server::Config {
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::PublicKey);
    russh::server::Config {
        server_id: russh::SshId::Standard(
            concat!("SSH-2.0-sekimore-relay_", env!("CARGO_PKG_VERSION")).into(),
        ),
        methods,
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![host_key],
        max_auth_attempts: 3,
        inactivity_timeout: Some(session_timeout),
        nodelay: true,
        ..Default::default()
    }
}

pub struct SshServer {
    pub config: Arc<russh::server::Config>,
    pub ctx: Arc<GitContext>,
    pub keys: Arc<AuthorizedKeys>,
    pub audit: Arc<Audit>,
    pub sessions: Arc<Semaphore>,
}

impl SshServer {
    pub fn new(
        config: russh::server::Config,
        ctx: Arc<GitContext>,
        keys: Arc<AuthorizedKeys>,
        audit: Arc<Audit>,
        max_sessions: usize,
    ) -> Arc<Self> {
        Arc::new(SshServer {
            config: Arc::new(config),
            ctx,
            keys,
            audit,
            sessions: Arc::new(Semaphore::new(max_sessions.max(1))),
        })
    }

    /// 0.2.0: share the russh config, authorized_keys and session limit across several listeners (one per upstream).
    pub fn shared(
        config: Arc<russh::server::Config>,
        ctx: Arc<GitContext>,
        keys: Arc<AuthorizedKeys>,
        audit: Arc<Audit>,
        sessions: Arc<Semaphore>,
    ) -> Arc<Self> {
        Arc::new(SshServer {
            config,
            ctx,
            keys,
            audit,
            sessions,
        })
    }

    /// Accept loop. Spawns a russh session per connection.
    pub async fn run(self: Arc<Self>, listener: TcpListener) -> anyhow::Result<()> {
        loop {
            let (stream, peer) = listener.accept().await.context("ssh accept")?;
            let permit = match self.sessions.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    log::warn!("ssh: too many sessions, dropping {peer}");
                    self.audit.deny_edge(
                        paths::DEV_RELAY_SSH,
                        "ssh_rejected",
                        Actor::Agent,
                        "too many sessions",
                        &[("peer", &peer.to_string())],
                    );
                    drop(stream);
                    continue;
                }
            };
            let handler = ClientHandler::new(self.clone(), peer);
            let config = self.config.clone();
            tokio::spawn(async move {
                let _permit = permit;
                match russh::server::run_stream(config, stream, handler).await {
                    Ok(session) => {
                        if let Err(e) = session.await {
                            log::debug!("ssh session {peer} ended: {e}");
                        }
                    }
                    Err(e) => log::debug!("ssh handshake with {peer} failed: {e}"),
                }
            });
        }
    }
}

pub struct ClientHandler {
    server: Arc<SshServer>,
    peer: String,
    channels: HashMap<ChannelId, Channel<Msg>>,
    exec_started: bool,
}

impl ClientHandler {
    fn new(server: Arc<SshServer>, peer: SocketAddr) -> Self {
        ClientHandler {
            server,
            peer: peer.to_string(),
            channels: HashMap::new(),
            exec_started: false,
        }
    }

    fn accepts(&self, user: &str, key: &PublicKey) -> bool {
        user == GIT_USER && self.server.keys.contains(key)
    }
}

impl Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        // Reject before the signature round trip (an unregistered key is denied outright). ssh offers keys one by one, so denials are audited too
        if self.accepts(user, key) {
            Ok(Auth::Accept)
        } else {
            let reason = if user != GIT_USER {
                "user is not git"
            } else {
                "public key not registered"
            };
            self.server.audit.deny_edge(
                paths::DEV_RELAY_SSH,
                "ssh_auth_denied",
                Actor::Agent,
                reason,
                &[
                    ("fingerprint", &fingerprint(key)),
                    ("user", user),
                    ("peer", &self.peer),
                ],
            );
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        let fp = fingerprint(key);
        if self.accepts(user, key) {
            self.server.audit.log_edge(
                paths::DEV_RELAY_SSH,
                "ssh_auth_ok",
                Actor::Agent,
                &[("fingerprint", &fp), ("peer", &self.peer)],
            );
            Ok(Auth::Accept)
        } else {
            let reason = if user != GIT_USER {
                "user is not git"
            } else {
                "public key not registered"
            };
            self.server.audit.deny_edge(
                paths::DEV_RELAY_SSH,
                "ssh_auth_denied",
                Actor::Agent,
                reason,
                &[("fingerprint", &fp), ("user", user), ("peer", &self.peer)],
            );
            Ok(Auth::reject())
        }
    }

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        // The banner would be sent unconditionally before authentication, showing up on every connection with a registered key, so we skip it.
        // Unregistered keys learn the reason from the audit log (ssh_auth_denied), the agent-setup guidance and the README table
        Ok(None)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // One exec per connection, so a handful of open sessions is already more than the
        // protocol needs. Without a bound an authenticated client can open and abandon
        // channels indefinitely, and each one holds its receive buffer.
        if self.exec_started || self.channels.len() >= MAX_OPEN_CHANNELS {
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        }
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    /// Release a channel the client opened and closed without running anything. `exec_request`
    /// removes the one it takes over; these two cover the rest, which otherwise accumulate for
    /// the life of the connection.
    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host: &str,
        _port: u32,
        _oaddr: &str,
        _oport: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.server.audit.deny_edge(
            paths::DEV_RELAY_SSH,
            "ssh_channel_rejected",
            Actor::Agent,
            "direct-tcpip not allowed",
            &[("peer", &self.peer)],
        );
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host: &str,
        _port: u32,
        _oaddr: &str,
        _oport: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _oaddr: &str,
        _oport: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmdline = String::from_utf8_lossy(data).into_owned();
        let Some(channel) = self.channels.remove(&id) else {
            session.channel_failure(id)?;
            return Ok(());
        };
        if self.exec_started {
            self.server.audit.deny_edge(
                paths::DEV_RELAY_SSH,
                "ssh_exec_rejected",
                Actor::Agent,
                "second exec on one connection",
                &[("peer", &self.peer)],
            );
            session.channel_failure(id)?;
            return Ok(());
        }
        self.exec_started = true;
        session.channel_success(id)?;
        let ctx = self.server.ctx.clone();
        let peer = self.peer.clone();
        tokio::spawn(async move {
            let (mut rx, tx) = channel.split();
            let status = {
                let stdout = tx.make_writer();
                let stderr = tx.make_writer_ext(Some(1));
                let stdin = rx.make_reader();
                let io = GitIo {
                    stdin: Box::new(stdin),
                    stdout: Box::new(stdout),
                    stderr: Box::new(stderr),
                };
                handle_exec(io, &cmdline, &ctx, &peer).await
            };
            let _ = tx.exit_status(status).await;
            let _ = tx.eof().await;
            let _ = tx.close().await;
        });
        Ok(())
    }

    async fn env_request(
        &mut self,
        id: ChannelId,
        _name: &str,
        _value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // GIT_PROTOCOL and friends are not accepted → the client falls back to v0
        session.channel_failure(id)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.server.audit.deny_edge(
            paths::DEV_RELAY_SSH,
            "ssh_request_rejected",
            Actor::Agent,
            "shell",
            &[("peer", &self.peer)],
        );
        session.channel_failure(id)?;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        id: ChannelId,
        _term: &str,
        _cw: u32,
        _rh: u32,
        _pw: u32,
        _ph: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.server.audit.deny_edge(
            paths::DEV_RELAY_SSH,
            "ssh_request_rejected",
            Actor::Agent,
            "subsystem",
            &[("name", name), ("peer", &self.peer)],
        );
        session.channel_failure(id)?;
        Ok(())
    }

    async fn x11_request(
        &mut self,
        id: ChannelId,
        _single: bool,
        _proto: &str,
        _cookie: &str,
        _screen: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        id: ChannelId,
        _cw: u32,
        _rh: u32,
        _pw: u32,
        _ph: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)?;
        Ok(())
    }

    async fn agent_request(
        &mut self,
        _id: ChannelId,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Server-side agent forwarding is not accepted (brief §4)
        Ok(false)
    }

    async fn tcpip_forward(
        &mut self,
        addr: &str,
        port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Remote port forwarding (-R) is not accepted either. The denial is audited
        self.server.audit.deny_edge(
            paths::DEV_RELAY_SSH,
            "ssh_request_rejected",
            Actor::Agent,
            "tcpip-forward (remote port forwarding) not allowed",
            &[("peer", &self.peer), ("bind", &format!("{addr}:{port}"))],
        );
        Ok(false)
    }
}
