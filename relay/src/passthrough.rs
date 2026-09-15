//! 同じドメインの 443。`github.com` を関所に向けると HTTPS も来る。INPUT DROP のまま放置すると
//! 無言タイムアウトになる（最悪ケース）。既定は実 upstream:443 への TCP 素通し（TLS は終端しない）、
//! `relay.https: reject` なら即時切断 + ログ。

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::audit::{Actor, Audit};
use crate::config::{HttpsMode, ProxySpec};
use crate::git::{copy_touch, Watchdog};
use crate::netutil::http_connect_tunnel;

pub struct Passthrough {
    pub upstream: String,
    pub port: u16,
    pub mode: HttpsMode,
    pub proxy: Option<ProxySpec>,
    pub idle: Duration,
    pub conns: Semaphore,
    pub audit: Arc<Audit>,
    /// テスト用: 解決先がこのホスト自身でも接続する
    pub allow_local: bool,
}

/// `ip` がこのホスト自身のアドレスか（DNS 自己参照ループの検知）。
pub fn is_local_ip(ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    let bind: std::net::SocketAddr = if ip.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let Ok(sock) = std::net::UdpSocket::bind(bind) else {
        return false;
    };
    if sock.connect((ip, 443)).is_err() {
        return false;
    }
    sock.local_addr().map(|a| a.ip() == ip).unwrap_or(false)
}

impl Passthrough {
    pub async fn connect_upstream(&self) -> std::io::Result<TcpStream> {
        if let Some(px) = &self.proxy {
            return http_connect_tunnel(px, &self.upstream, self.port)
                .await
                .map_err(|e| {
                    std::io::Error::new(e.kind(), format!("via upstream proxy {}: {e}", px.url))
                });
        }
        let addrs = tokio::net::lookup_host((self.upstream.as_str(), self.port)).await?;
        let mut last: Option<std::io::Error> = None;
        let mut skipped_self = false;
        for addr in addrs {
            if !self.allow_local && is_local_ip(addr.ip()) {
                skipped_self = true;
                continue;
            }
            match tokio::time::timeout(Duration::from_secs(20), TcpStream::connect(addr)).await {
                Ok(Ok(s)) => return Ok(s),
                Ok(Err(e)) => last = Some(e),
                Err(_) => {
                    last = Some(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "connect timed out",
                    ))
                }
            }
        }
        if skipped_self && last.is_none() {
            return Err(std::io::Error::other(format!(
                "{} resolves to this gateway itself (DNS self-reference loop); the gateway must resolve the upstream via the real resolver",
                self.upstream
            )));
        }
        Err(last.unwrap_or_else(|| {
            std::io::Error::other(format!("{} did not resolve to any address", self.upstream))
        }))
    }

    pub async fn run(self: Arc<Self>, listener: TcpListener) -> anyhow::Result<()> {
        loop {
            let (stream, peer) = listener.accept().await.context("https accept")?;
            let peer_s = peer.to_string();
            if self.mode == HttpsMode::Reject {
                self.audit.deny(
                    "https_rejected",
                    Actor::Agent,
                    "relay.https is reject; use the API route for GitHub operations",
                    &[("peer", &peer_s), ("upstream", &self.upstream)],
                );
                drop(stream);
                continue;
            }
            let this = self.clone();
            tokio::spawn(async move {
                let Ok(_permit) = this.conns.try_acquire() else {
                    this.audit.deny(
                        "https_rejected",
                        Actor::Agent,
                        "too many passthrough connections",
                        &[("peer", &peer_s)],
                    );
                    return;
                };
                match this.connect_upstream().await {
                    Ok(up) => {
                        let (bi, bo) = this.pump(stream, up).await;
                        this.audit.log(
                            "https_passthrough",
                            Actor::Agent,
                            &[
                                ("peer", &peer_s),
                                ("upstream", &this.upstream),
                                ("bytes_in", &bi.to_string()),
                                ("bytes_out", &bo.to_string()),
                            ],
                        );
                    }
                    Err(e) => {
                        this.audit.deny(
                            "https_failed",
                            Actor::Agent,
                            &e.to_string(),
                            &[("peer", &peer_s), ("upstream", &this.upstream)],
                        );
                        log::warn!(
                            "https passthrough to {} failed for {peer_s}: {e}",
                            this.upstream
                        );
                    }
                }
            });
        }
    }

    async fn pump(&self, client: TcpStream, upstream: TcpStream) -> (u64, u64) {
        let wd = Watchdog::new(self.idle);
        wd.touch();
        let (mut cr, mut cw) = client.into_split();
        let (mut ur, mut uw) = upstream.into_split();
        let a = copy_touch(&mut cr, &mut uw, &wd, true);
        let b = copy_touch(&mut ur, &mut cw, &wd, true);
        tokio::select! {
            r = async { tokio::join!(a, b) } => (r.0.unwrap_or(0), r.1.unwrap_or(0)),
            _ = wd.expired() => (0, 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn pt(upstream: &str, port: u16, allow_local: bool) -> Arc<Passthrough> {
        Arc::new(Passthrough {
            upstream: upstream.to_string(),
            port,
            mode: HttpsMode::Passthrough,
            proxy: None,
            idle: Duration::from_secs(5),
            conns: Semaphore::new(4),
            audit: Arc::new(Audit::disabled()),
            allow_local,
        })
    }

    #[tokio::test]
    async fn forwards_to_local_echo_upstream() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = echo.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let p = pt("127.0.0.1", echo_port, true);
        tokio::spawn(p.run(listener));

        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(b"hello through relay").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = c.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello through relay");
    }

    #[tokio::test]
    async fn refuses_self_loop() {
        let p = pt("127.0.0.1", 443, false);
        let e = p.connect_upstream().await.unwrap_err();
        assert!(e.to_string().contains("self-reference"), "{e}");
        assert!(is_local_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_local_ip("192.0.2.1".parse().unwrap()));
    }
}
