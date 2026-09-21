//! The git path: take an SSH exec request, run the policy check, then relay to the upstream git.
//!
//! The flow (the receive-pack state machine):
//!   P0 parse exec → P1 `authorize_git` → P2 preflight → P3 spawn upstream → relay → P9 exit code
//!
//! `UpstreamGit::spawn`, the only way to reach upstream, accepts nothing but a `GitAuthorized`.
//!
//! ```compile_fail
//! # use sekimore_relay::git::UpstreamGit;
//! # async fn f(up: &dyn UpstreamGit) {
//! // You cannot spawn the upstream with just a repository name, bypassing the policy check.
//! let _ = up.spawn("Attacker/evil").await;
//! # }
//! ```

pub mod agent_check;
pub mod agent_proxy;
pub mod pack;
pub mod receive_pack;
pub mod response;
pub mod upload_pack;
#[cfg(any(test, feature = "test-hooks"))]
pub mod upstream_local;
pub mod upstream_ssh;

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};

use crate::audit::{Actor, Audit};
use crate::config::Limits;
use crate::github::GitHub;
pub use crate::policy::GitVerb;
use crate::policy::{Denied, GitAuthorized, Project};

/// stdin/stdout/stderr of the SSH channel. The dependency on russh stops here.
pub struct GitIo<'a> {
    pub stdin: Box<dyn AsyncRead + Send + Unpin + 'a>,
    pub stdout: Box<dyn AsyncWrite + Send + Unpin + 'a>,
    pub stderr: Box<dyn AsyncWrite + Send + Unpin + 'a>,
}

/// Why spawning the upstream git failed. `message` is for humans, so it never shows up as `Permission denied (publickey)`.
#[derive(Debug, Clone)]
pub struct UpstreamError {
    /// A short kind for the audit log (agent_unset, agent_missing, known_hosts, spawn, ...)
    pub kind: &'static str,
    pub message: String,
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UpstreamError {}

/// A spawned upstream process. The relay owns its stdio.
pub struct UpstreamProcess {
    pub child: Child,
    pub stdin: ChildStdin,
    pub stdout: ChildStdout,
    pub stderr: Option<ChildStderr>,
}

impl UpstreamProcess {
    pub fn from_child(mut child: Child) -> std::io::Result<Self> {
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("upstream stdin not piped"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("upstream stdout not piped"))?;
        let stderr = child.stderr.take();
        Ok(UpstreamProcess {
            child,
            stdin,
            stdout,
            stderr,
        })
    }
}

/// How to spawn the upstream git: an OpenSSH child process in production, a local bare repo in tests.
#[async_trait]
pub trait UpstreamGit: Send + Sync {
    /// Checks run before connecting upstream (agent reachability, known_hosts, and so on).
    async fn preflight(&self) -> Result<(), UpstreamError>;
    /// Spawn the upstream `git-<verb>`. The argument is the **canonical name from config**, never client input.
    async fn spawn(&self, auth: &GitAuthorized<'_>) -> Result<UpstreamProcess, UpstreamError>;
    /// A description for logging.
    fn describe(&self) -> String;
}

/// Shared context for the git path.
pub struct GitContext {
    pub project: Project,
    /// 0.2.0: the upstream this listener serves (the git-relay domain). Empty means upstreams are not distinguished (single-upstream tests)
    pub host: String,
    pub upstream: Arc<dyn UpstreamGit>,
    /// Used to create PRs. When None, `refs/for` reports that the push went through but no PR could be created
    pub github: Option<Arc<GitHub>>,
    pub audit: Arc<Audit>,
    pub limits: Limits,
}

/// Split apart a `git-upload-pack 'Org/Repo.git'` command line.
pub fn parse_exec_command(cmdline: &str) -> Result<(GitVerb, String), Denied> {
    let deny = || Denied::UnsupportedCommand {
        cmdline: cmdline.trim().to_string(),
    };
    let trimmed = cmdline.trim();
    let (verb, rest) = trimmed.split_once(char::is_whitespace).ok_or_else(deny)?;
    let verb = match verb {
        "git-upload-pack" => GitVerb::UploadPack,
        "git-receive-pack" => GitVerb::ReceivePack,
        _ => return Err(deny()),
    };
    let arg = rest.trim();
    let arg = arg
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .or_else(|| arg.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
        .unwrap_or(arg);
    if arg.is_empty()
        || arg.starts_with('-')
        || arg.contains("..")
        || arg.bytes().any(|b| {
            b < 0x21
                || b == 0x7f
                || matches!(
                    b,
                    b'\'' | b'"' | b'`' | b'$' | b';' | b'&' | b'|' | b'<' | b'>' | b'\\'
                )
        })
    {
        return Err(deny());
    }
    Ok((verb, arg.trim_start_matches('/').to_string()))
}

/// Idle watchdog: the copy loop calls `touch()`, and `expired()` completes once the idle limit is exceeded.
pub struct Watchdog {
    start: Instant,
    last_ms: AtomicU64,
    idle: Duration,
}

impl Watchdog {
    pub fn new(idle: Duration) -> Arc<Self> {
        Arc::new(Watchdog {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
            idle,
        })
    }
    pub fn touch(&self) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    pub async fn expired(&self) {
        loop {
            let last = Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
            let since = self.start.elapsed().saturating_sub(last);
            if since >= self.idle {
                return;
            }
            tokio::time::sleep((self.idle - since).min(Duration::from_secs(5))).await;
        }
    }
}

/// Copy `reader` → `writer` in 64 KiB chunks, reporting activity to the watchdog. Returns the number of bytes transferred.
pub async fn copy_touch<R, W>(
    reader: R,
    writer: W,
    wd: &Watchdog,
    close_writer: bool,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    copy_touch_counted(reader, writer, wd, close_writer, &AtomicU64::new(0)).await
}

/// `copy_touch`, reporting progress into `seen` as it goes.
///
/// An idle timeout drops this future, and a dropped future's return value is gone — so a
/// transfer cut short would be audited as zero bytes. That matters here: the byte count is
/// the exfiltration record, and going quiet mid-upload would be a way to erase it. The cap
/// itself is enforced before each write and is unaffected either way.
pub async fn copy_touch_counted<R, W>(
    mut reader: R,
    mut writer: W,
    wd: &Watchdog,
    close_writer: bool,
    seen: &AtomicU64,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).await?;
        total += n as u64;
        seen.store(total, Ordering::Relaxed);
        wd.touch();
    }
    writer.flush().await?;
    if close_writer {
        writer.shutdown().await?;
    }
    Ok(total)
}

async fn say(stderr: &mut (dyn AsyncWrite + Send + Unpin), msg: &str) {
    let _ = stderr
        .write_all(format!("sekimore: {msg}\n").as_bytes())
        .await;
    let _ = stderr.flush().await;
}

/// Handle one exec request and return its exit code.
pub async fn handle_exec(mut io: GitIo<'_>, cmdline: &str, ctx: &GitContext, peer: &str) -> u32 {
    let started = Instant::now();
    // P0
    let (verb, repo_path) = match parse_exec_command(cmdline) {
        Ok(v) => v,
        Err(d) => {
            say(&mut *io.stderr, &d.to_string()).await;
            ctx.audit.deny(
                "cmd_rejected",
                Actor::Agent,
                &d.to_string(),
                &[("cmdline", cmdline.trim()), ("peer", peer)],
            );
            return 1;
        }
    };
    // P1 (the single barrier that denies reaching a repository outside the project)
    let auth = match ctx.project.authorize_git_on(&ctx.host, verb, &repo_path) {
        Ok(a) => a,
        Err(d) => {
            say(&mut *io.stderr, &d.to_string()).await;
            ctx.audit.deny(
                "repo_denied",
                Actor::Agent,
                &d.to_string(),
                &[
                    ("repo", &repo_path),
                    ("upstream", &ctx.host),
                    ("verb", verb.as_str()),
                    ("kind", d.kind()),
                    ("peer", peer),
                ],
            );
            return 1;
        }
    };
    // P2
    if let Err(e) = ctx.upstream.preflight().await {
        say(&mut *io.stderr, &e.message).await;
        ctx.audit.deny(
            "upstream_preflight_failed",
            Actor::Agent,
            &e.message,
            &[("repo", auth.repo()), ("kind", e.kind)],
        );
        return 1;
    }
    // P3
    let proc = match ctx.upstream.spawn(&auth).await {
        Ok(p) => p,
        Err(e) => {
            say(&mut *io.stderr, &e.message).await;
            ctx.audit.deny(
                "upstream_spawn_failed",
                Actor::Agent,
                &e.message,
                &[("repo", auth.repo()), ("kind", e.kind)],
            );
            return 1;
        }
    };

    let session_timeout = ctx.limits.session_timeout;
    let result = tokio::time::timeout(session_timeout, async {
        match verb {
            GitVerb::UploadPack => upload_pack::relay_upload_pack(&mut io, proc, ctx).await,
            GitVerb::ReceivePack => {
                receive_pack::relay_receive_pack(&mut io, proc, ctx, &auth).await
            }
        }
    })
    .await;

    let outcome = match result {
        Ok(o) => o,
        Err(_) => {
            say(
                &mut *io.stderr,
                &format!(
                    "session exceeded {} and was terminated",
                    humantime::format_duration(session_timeout)
                ),
            )
            .await;
            RelayOutcome {
                status: 1,
                bytes_in: 0,
                bytes_out: 0,
                note: Some("session_timeout".into()),
            }
        }
    };
    let ms = started.elapsed().as_millis().to_string();
    let event = if outcome.status == 0 {
        "relay_ok"
    } else {
        "relay_failed"
    };
    let mut fields: Vec<(&str, &str)> = vec![
        ("repo", auth.repo()),
        ("upstream", &ctx.host),
        ("verb", verb.as_str()),
        ("peer", peer),
        ("ms", &ms),
    ];
    let (bi, bo, st) = (
        outcome.bytes_in.to_string(),
        outcome.bytes_out.to_string(),
        outcome.status.to_string(),
    );
    fields.push(("bytes_in", &bi));
    fields.push(("bytes_out", &bo));
    fields.push(("status", &st));
    if let Some(n) = &outcome.note {
        fields.push(("note", n));
    }
    ctx.audit.log(event, Actor::Agent, &fields);
    outcome.status
}

/// The outcome of a relay.
pub struct RelayOutcome {
    pub status: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub note: Option<String>,
}

/// Turn a child process's termination into an exit code. From ssh, 255 means the connection failed.
pub fn exit_code_of(status: std::process::ExitStatus) -> u32 {
    match status.code() {
        Some(c) if c >= 0 => c as u32,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_exec_command_cases() {
        assert_eq!(
            parse_exec_command("git-upload-pack 'Org/Repo.git'").unwrap(),
            (GitVerb::UploadPack, "Org/Repo.git".to_string())
        );
        assert_eq!(
            parse_exec_command("git-receive-pack '/Org/Repo.git'").unwrap(),
            (GitVerb::ReceivePack, "Org/Repo.git".to_string())
        );
        assert_eq!(
            parse_exec_command("git-upload-pack Org/Repo").unwrap().1,
            "Org/Repo"
        );
        for bad in [
            "git-upload-archive 'Org/Repo.git'",
            "rm -rf /",
            "git-upload-pack",
            "git-upload-pack ''",
            "git-upload-pack '../x'",
            "git-upload-pack '--help'",
            "git-upload-pack 'a;b'",
            "git-upload-pack 'a b'",
            "git-upload-pack 'a' 'b'",
        ] {
            assert!(
                matches!(
                    parse_exec_command(bad),
                    Err(Denied::UnsupportedCommand { .. })
                ),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn watchdog_expires_only_when_idle() {
        let wd = Watchdog::new(Duration::from_millis(50));
        let t = Instant::now();
        wd.expired().await;
        assert!(t.elapsed() >= Duration::from_millis(45));
        let wd2 = Watchdog::new(Duration::from_millis(100));
        let w = wd2.clone();
        let toucher = tokio::spawn(async move {
            for _ in 0..5 {
                tokio::time::sleep(Duration::from_millis(30)).await;
                w.touch();
            }
        });
        let t = Instant::now();
        wd2.expired().await;
        assert!(t.elapsed() >= Duration::from_millis(200));
        toucher.await.unwrap();
    }
}
