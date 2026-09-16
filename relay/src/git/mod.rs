//! git 経路: SSH の exec 要求を受け、ポリシー検査 → 上流 git へ中継する。
//!
//! 流れ（`doc/sekimore-gw/design/relay.md` の状態機械）:
//!   P0 exec 解析 → P1 `authorize_git` → P2 プリフライト → P3 上流起動 → 中継 → P9 終了コード
//!
//! 上流を叩く `UpstreamGit::spawn` は `GitAuthorized` しか受け取らない。
//!
//! ```compile_fail
//! # use sekimore_relay::git::UpstreamGit;
//! # async fn f(up: &dyn UpstreamGit) {
//! // 検査を通さずリポジトリ名だけで上流を起動することはできない
//! let _ = up.spawn("Attacker/evil").await;
//! # }
//! ```

pub mod agent_check;
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

/// SSH チャネルの stdin/stdout/stderr。russh への依存はここで切れる。
pub struct GitIo<'a> {
    pub stdin: Box<dyn AsyncRead + Send + Unpin + 'a>,
    pub stdout: Box<dyn AsyncWrite + Send + Unpin + 'a>,
    pub stderr: Box<dyn AsyncWrite + Send + Unpin + 'a>,
}

/// 上流 git の起動に失敗した理由。`message` は人間向け（`Permission denied (publickey)` に見せない）。
#[derive(Debug, Clone)]
pub struct UpstreamError {
    /// 監査ログ用の短い種別（agent_unset, agent_missing, known_hosts, spawn ...）
    pub kind: &'static str,
    pub message: String,
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UpstreamError {}

/// 起動した上流プロセス。stdio は relay が握る。
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

/// 上流 git の起動方法。本番は OpenSSH 子プロセス、テストはローカル bare repo。
#[async_trait]
pub trait UpstreamGit: Send + Sync {
    /// 上流に接続する前の検査（agent 到達性、known_hosts など）。
    async fn preflight(&self) -> Result<(), UpstreamError>;
    /// 上流 `git-<verb>` を起動する。引数は **config の正規名**（クライアント入力を使わない）。
    async fn spawn(&self, auth: &GitAuthorized<'_>) -> Result<UpstreamProcess, UpstreamError>;
    /// ログ用の説明。
    fn describe(&self) -> String;
}

/// git 経路の共有コンテキスト。
pub struct GitContext {
    pub project: Project,
    pub upstream: Arc<dyn UpstreamGit>,
    /// PR 作成に使う。None なら `refs/for` は「push は通るが PR は作れない」旨を返す
    pub github: Option<Arc<GitHub>>,
    pub audit: Arc<Audit>,
    pub limits: Limits,
}

/// `git-upload-pack 'Org/Repo.git'` を分解する。
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

/// 無通信の監視。コピー側が `touch()` し、`expired()` が idle 超過で完了する。
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

/// `reader` → `writer` を 64 KiB 単位でコピーし、活動を watchdog に伝える。転送バイト数を返す。
pub async fn copy_touch<R, W>(
    mut reader: R,
    mut writer: W,
    wd: &Watchdog,
    close_writer: bool,
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

/// exec 要求 1 件を処理し、終了コードを返す。
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
    // P1（案件外リポジトリへの到達を拒否する唯一の防壁）
    let auth = match ctx.project.authorize_git(verb, &repo_path) {
        Ok(a) => a,
        Err(d) => {
            say(&mut *io.stderr, &d.to_string()).await;
            ctx.audit.deny(
                "repo_denied",
                Actor::Agent,
                &d.to_string(),
                &[
                    ("repo", &repo_path),
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

/// 中継結果。
pub struct RelayOutcome {
    pub status: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub note: Option<String>,
}

/// 子プロセスの終了を終了コードに変換する。ssh の 255 は接続失敗。
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
