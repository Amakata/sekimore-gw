//! ssh-agent への到達性のプリフライト。
//!
//! 上流 ssh を起動する **前** に検査し、`Permission denied (publickey)` という誤解を招くエラーに
//! なる前に、何が悪いのかを個別に言う（brief §5-i / §5-j）。依存を増やさず agent プロトコルを直接話す。

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENT_FAILURE: u8 = 5;

#[derive(Debug)]
pub enum AgentError {
    Unset,
    Missing(PathBuf),
    Connect(PathBuf, std::io::Error),
    NoIdentities,
    Protocol(String),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::Unset => write!(
                f,
                "SSH_AUTH_SOCK is not set in the gateway container; mount the operator's agent socket \
                 (compose: volumes ${{SEKIMORE_AGENT_SOCK:-/run/host-services/ssh-auth.sock}}:/ssh-agent/agent.sock:ro, environment SSH_AUTH_SOCK=/ssh-agent/agent.sock)"
            ),
            AgentError::Missing(p) => write!(
                f,
                "ssh-agent socket {} does not exist; the host session that owned it probably ended \
                 (reconnect the agent forwarding session)",
                p.display()
            ),
            AgentError::Connect(p, e) => {
                let hint = match e.raw_os_error() {
                    Some(libc::ECONNREFUSED) => "the host agent is gone; reconnect the forwarding session",
                    Some(libc::EACCES) | Some(libc::EPERM) => {
                        "socket owner/mode does not allow the relay uid; check userns-remap and the socket permissions"
                    }
                    _ => "",
                };
                write!(f, "cannot connect to ssh-agent socket {}: {e}{}{hint}", p.display(), if hint.is_empty() { "" } else { "; " })
            }
            AgentError::NoIdentities => {
                write!(f, "ssh-agent is reachable but holds no identities; run `ssh-add` on the host")
            }
            AgentError::Protocol(m) => write!(f, "unexpected reply from ssh-agent: {m}"),
        }
    }
}

impl std::error::Error for AgentError {}

/// agent に REQUEST_IDENTITIES を送り、鍵の数を返す。
pub async fn preflight_agent(sock: Option<&Path>) -> Result<usize, AgentError> {
    let sock = sock.ok_or(AgentError::Unset)?;
    if !sock.exists() {
        return Err(AgentError::Missing(sock.to_path_buf()));
    }
    let fut = async {
        let mut s = tokio::net::UnixStream::connect(sock)
            .await
            .map_err(|e| AgentError::Connect(sock.to_path_buf(), e))?;
        s.write_all(&[0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES])
            .await
            .map_err(|e| AgentError::Connect(sock.to_path_buf(), e))?;
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr)
            .await
            .map_err(|e| AgentError::Protocol(format!("short read: {e}")))?;
        let len = u32::from_be_bytes(hdr) as usize;
        if len == 0 || len > (1 << 20) {
            return Err(AgentError::Protocol(format!("bad message length {len}")));
        }
        let mut body = vec![0u8; len];
        s.read_exact(&mut body)
            .await
            .map_err(|e| AgentError::Protocol(format!("short read: {e}")))?;
        match body[0] {
            SSH_AGENT_IDENTITIES_ANSWER => {
                if body.len() < 5 {
                    return Err(AgentError::Protocol("truncated identities answer".into()));
                }
                let n = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
                if n == 0 {
                    return Err(AgentError::NoIdentities);
                }
                Ok(n)
            }
            SSH_AGENT_FAILURE => Err(AgentError::Protocol("agent returned FAILURE".into())),
            other => Err(AgentError::Protocol(format!("message type {other}"))),
        }
    };
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .map_err(|_| AgentError::Protocol("timed out waiting for the agent".into()))?
}

/// `SSH_AUTH_SOCK` を読む。
pub fn auth_sock_from_env() -> Option<PathBuf> {
    std::env::var_os("SSH_AUTH_SOCK")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    async fn fake_agent(dir: &Path, nkeys: u32) -> PathBuf {
        let path = dir.join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut hdr = [0u8; 5];
                    if s.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let mut body = vec![SSH_AGENT_IDENTITIES_ANSWER];
                    body.extend_from_slice(&nkeys.to_be_bytes());
                    for _ in 0..nkeys {
                        // key blob + comment（中身は見ないので空文字列 2 つ）
                        body.extend_from_slice(&0u32.to_be_bytes());
                        body.extend_from_slice(&0u32.to_be_bytes());
                    }
                    let mut msg = (body.len() as u32).to_be_bytes().to_vec();
                    msg.extend_from_slice(&body);
                    let _ = s.write_all(&msg).await;
                });
            }
        });
        path
    }

    #[tokio::test]
    async fn sock_unset_and_missing() {
        assert!(matches!(
            preflight_agent(None).await,
            Err(AgentError::Unset)
        ));
        let e = preflight_agent(Some(Path::new("/nonexistent/agent.sock")))
            .await
            .unwrap_err();
        assert!(matches!(e, AgentError::Missing(_)));
        assert!(e.to_string().contains("does not exist"));
    }

    #[tokio::test]
    async fn refused_when_nothing_listens() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("dead.sock");
        // socket ファイルだけ作る（listener 無し）
        drop(UnixListener::bind(&p).unwrap());
        let e = preflight_agent(Some(&p)).await.unwrap_err();
        assert!(matches!(e, AgentError::Connect(..)), "{e}");
        assert!(e.to_string().contains("cannot connect"));
    }

    #[tokio::test]
    async fn zero_identities_via_fake_agent() {
        let dir = tempfile::tempdir().unwrap();
        let p = fake_agent(dir.path(), 0).await;
        assert!(matches!(
            preflight_agent(Some(&p)).await,
            Err(AgentError::NoIdentities)
        ));
        let dir2 = tempfile::tempdir().unwrap();
        let p2 = fake_agent(dir2.path(), 2).await;
        assert_eq!(preflight_agent(Some(&p2)).await.unwrap(), 2);
    }
}
