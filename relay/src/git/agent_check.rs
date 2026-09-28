//! Preflight check for reachability of the ssh-agent.
//!
//! Checking **before** spawning the upstream ssh lets us say precisely what is wrong instead of surfacing the
//! misleading `Permission denied (publickey)` (brief §5-i / §5-j). We speak the agent protocol directly rather than adding a dependency.

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

/// Send REQUEST_IDENTITIES to the agent and return the number of keys.
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

/// Read `SSH_AUTH_SOCK`, resolving a directory to the socket inside it (#272).
pub fn auth_sock_from_env() -> Option<PathBuf> {
    std::env::var_os("SSH_AUTH_SOCK")
        .filter(|s| !s.is_empty())
        .map(|s| resolve_auth_sock(PathBuf::from(s)))
}

/// The socket file `agent.sock` inside a directory, or the path as it is (#272).
///
/// On a Linux host the operator's agent arrives by `ssh -R` from their Mac, and sshd recreates
/// the socket on every reconnect. A file bind-mount pins the inode the container started with,
/// so the gateway kept talking to a dead socket until `sgw recreate`; and a path that did not
/// exist at start became a directory Docker made. Mounting the socket's directory instead
/// (`SEKIMORE_AGENT_SOCK=/home/<user>/.sekimore`) survives both: the directory is stable, and
/// the socket inside it is looked up by name on every connection.
pub fn resolve_auth_sock(path: PathBuf) -> PathBuf {
    if path.is_dir() {
        path.join("agent.sock")
    } else {
        path
    }
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
                        // key blob + comment (we never inspect them, so two empty strings)
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

    /// #272: a directory names the socket inside it; a file, or a path that is not there yet,
    /// is taken as it is.
    #[tokio::test]
    async fn a_directory_resolves_to_the_socket_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_auth_sock(dir.path().to_path_buf()),
            dir.path().join("agent.sock")
        );
        let sock = fake_agent(dir.path(), 2).await;
        assert_eq!(resolve_auth_sock(sock.clone()), sock);
        assert_eq!(
            preflight_agent(Some(&resolve_auth_sock(dir.path().to_path_buf())))
                .await
                .unwrap(),
            2
        );
        let missing = dir.path().join("not-yet");
        assert_eq!(resolve_auth_sock(missing.clone()), missing);
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
        // Create only the socket file, with nothing listening on it.
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
