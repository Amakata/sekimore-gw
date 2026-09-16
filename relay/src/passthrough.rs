//! 同じドメインの 443。`github.com` を関所に向けると HTTPS も来る。INPUT DROP のまま放置すると
//! 無言タイムアウトになる（最悪ケース）。既定は実 upstream:443 への TCP 素通し（TLS は終端しない）、
//! `relay.https: reject` なら即時切断 + ログ。
//!
//! 0.2.0: 複数上流のときは **ClientHello の SNI** を先読みして上流を選ぶ（TLS は終端しないので
//! 平文のまま読める）。SNI が無い / どの上流にも一致しなければ既定上流（0.1.x と同じ）。

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::audit::{Actor, Audit};
use crate::config::{HttpsMode, ProxySpec};
use crate::git::{copy_touch, Watchdog};
use crate::netutil::http_connect_tunnel;

/// SNI で選べる上流 1 つ分。`domain` は DNS で関所に向けられる名前（= SNI に来る名前）、`host` は実上流。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniTarget {
    pub domain: String,
    pub host: String,
    pub port: u16,
}

/// ClientHello を待つ上限。TLS でない / 遅いクライアントは読めた分だけで既定上流へ流す。
pub const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// 先読みの上限（TLS レコード最大 16 KiB + ヘッダ）。
const CLIENT_HELLO_CAP: usize = 16 * 1024 + 5 + 256;

pub struct Passthrough {
    /// 既定上流（SNI が無い / 一致しないときの接続先）
    pub upstream: String,
    pub port: u16,
    /// 0.2.0: SNI で選ぶ上流の一覧（既定上流も含めてよい）。空なら常に既定上流
    pub upstreams: Vec<SniTarget>,
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

/// TLS ClientHello から SNI（server_name 拡張の host_name）を取り出す。
/// TLS でない、ClientHello でない、拡張が無い、途中で切れている場合は None。名前は小文字・末尾 `.` 無し。
pub fn parse_sni(buf: &[u8]) -> Option<String> {
    // TLS record: content_type(1)=handshake(0x16) version(2) length(2)
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let rec = buf.get(5..5 + rec_len)?;
    // Handshake: msg_type(1)=client_hello(1) length(3) version(2) random(32) session_id
    if rec.len() < 4 || rec[0] != 0x01 {
        return None;
    }
    let hs_len = ((rec[1] as usize) << 16) | ((rec[2] as usize) << 8) | rec[3] as usize;
    let hs = rec.get(4..4 + hs_len)?;
    let mut p = 2 + 32;
    let sid_len = *hs.get(p)? as usize;
    p += 1 + sid_len;
    let cs_len = u16::from_be_bytes([*hs.get(p)?, *hs.get(p + 1)?]) as usize;
    p += 2 + cs_len;
    let comp_len = *hs.get(p)? as usize;
    p += 1 + comp_len;
    let ext_len = u16::from_be_bytes([*hs.get(p)?, *hs.get(p + 1)?]) as usize;
    p += 2;
    let exts = hs.get(p..p + ext_len)?;
    let mut q = 0;
    while q + 4 <= exts.len() {
        let ext_type = u16::from_be_bytes([exts[q], exts[q + 1]]);
        let len = u16::from_be_bytes([exts[q + 2], exts[q + 3]]) as usize;
        q += 4;
        let body = exts.get(q..q + len)?;
        if ext_type == 0 {
            // server_name: list_length(2) then (name_type(1)=host_name(0), length(2), name)
            let mut r = 2;
            while r + 3 <= body.len() {
                let name_type = body[r];
                let name_len = u16::from_be_bytes([body[r + 1], body[r + 2]]) as usize;
                r += 3;
                let name = body.get(r..r + name_len)?;
                if name_type == 0 {
                    let s = std::str::from_utf8(name).ok()?;
                    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
                    return (!s.is_empty()).then_some(s);
                }
                r += name_len;
            }
            return None;
        }
        q += len;
    }
    None
}

/// 先頭の TLS レコード（ClientHello）を読み、(SNI, 読んだバイト列) を返す。
/// TLS でなければ最初に読めた分で止める。タイムアウト / エラー時も読めた分をそのまま返す（上流へ前送する）。
async fn read_client_hello(stream: &mut TcpStream, timeout: Duration) -> (Option<String>, Vec<u8>) {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let _ = tokio::time::timeout(timeout, async {
        let mut tmp = [0u8; 4096];
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf[0] != 0x16 || buf.len() >= CLIENT_HELLO_CAP {
                break;
            }
            if buf.len() >= 5 {
                let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
                if buf.len() >= 5 + rec_len {
                    break;
                }
            }
        }
        Ok::<(), std::io::Error>(())
    })
    .await;
    (parse_sni(&buf), buf)
}

impl Passthrough {
    /// SNI から接続先を選ぶ。(host, port, 一致したか)。
    pub fn select(&self, sni: Option<&str>) -> (&str, u16, bool) {
        if let Some(name) = sni {
            for t in &self.upstreams {
                if t.domain.eq_ignore_ascii_case(name) || t.host.eq_ignore_ascii_case(name) {
                    return (&t.host, t.port, true);
                }
            }
        }
        (&self.upstream, self.port, false)
    }

    /// 既定上流へ接続する（0.1.x 互換）。
    pub async fn connect_upstream(&self) -> std::io::Result<TcpStream> {
        self.connect_upstream_to(&self.upstream, self.port).await
    }

    pub async fn connect_upstream_to(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        if let Some(px) = &self.proxy {
            return http_connect_tunnel(px, host, port).await.map_err(|e| {
                std::io::Error::new(e.kind(), format!("via upstream proxy {}: {e}", px.url))
            });
        }
        let addrs = tokio::net::lookup_host((host, port)).await?;
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
                "{host} resolves to this gateway itself (DNS self-reference loop); the gateway must resolve the upstream via the real resolver"
            )));
        }
        Err(last.unwrap_or_else(|| {
            std::io::Error::other(format!("{host} did not resolve to any address"))
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
                let mut stream = stream;
                // 上流が 1 つなら先読みは不要（0.1.x と同じ挙動）
                let (sni, prefix) = if this.upstreams.len() > 1 {
                    read_client_hello(&mut stream, CLIENT_HELLO_TIMEOUT).await
                } else {
                    (None, Vec::new())
                };
                let (host, port, _matched) = this.select(sni.as_deref());
                let host = host.to_string();
                let sni_s = sni.clone().unwrap_or_else(|| "-".to_string());
                match this.connect_upstream_to(&host, port).await {
                    Ok(mut up) => {
                        if !prefix.is_empty() {
                            if let Err(e) = up.write_all(&prefix).await {
                                this.audit.deny(
                                    "https_failed",
                                    Actor::Agent,
                                    &e.to_string(),
                                    &[("peer", &peer_s), ("upstream", &host), ("sni", &sni_s)],
                                );
                                return;
                            }
                        }
                        let (bi, bo) = this.pump(stream, up).await;
                        this.audit.log(
                            "https_passthrough",
                            Actor::Agent,
                            &[
                                ("peer", &peer_s),
                                ("upstream", &host),
                                ("sni", &sni_s),
                                ("bytes_in", &(bi + prefix.len() as u64).to_string()),
                                ("bytes_out", &bo.to_string()),
                            ],
                        );
                    }
                    Err(e) => {
                        this.audit.deny(
                            "https_failed",
                            Actor::Agent,
                            &e.to_string(),
                            &[("peer", &peer_s), ("upstream", &host), ("sni", &sni_s)],
                        );
                        log::warn!("https passthrough to {host} failed for {peer_s}: {e}");
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

    fn pt(upstream: &str, port: u16, allow_local: bool) -> Arc<Passthrough> {
        Arc::new(Passthrough {
            upstream: upstream.to_string(),
            port,
            upstreams: Vec::new(),
            mode: HttpsMode::Passthrough,
            proxy: None,
            idle: Duration::from_secs(5),
            conns: Semaphore::new(4),
            audit: Arc::new(Audit::disabled()),
            allow_local,
        })
    }

    /// 最小の TLS 1.2 ClientHello（拡張は SNI だけ、あれば）。
    fn client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(name) = sni {
            let n = name.as_bytes();
            let mut list = vec![0u8]; // name_type host_name
            list.extend_from_slice(&(n.len() as u16).to_be_bytes());
            list.extend_from_slice(n);
            let mut body = (list.len() as u16).to_be_bytes().to_vec();
            body.extend_from_slice(&list);
            exts.extend_from_slice(&0u16.to_be_bytes()); // server_name
            exts.extend_from_slice(&(body.len() as u16).to_be_bytes());
            exts.extend_from_slice(&body);
        }
        // もう 1 つダミー拡張（supported_versions 相当）を後ろに足して走査を確かめる
        exts.extend_from_slice(&43u16.to_be_bytes());
        exts.extend_from_slice(&3u16.to_be_bytes());
        exts.extend_from_slice(&[2, 3, 4]);
        let mut hs = vec![3, 3]; // version
        hs.extend_from_slice(&[7u8; 32]); // random
        hs.push(0); // session id len
        hs.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        hs.extend_from_slice(&[0x13, 0x01]);
        hs.push(1); // compression len
        hs.push(0);
        hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs.extend_from_slice(&exts);
        let mut msg = vec![1u8]; // client_hello
        msg.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&hs);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        rec.extend_from_slice(&msg);
        rec
    }

    #[test]
    fn sni_is_parsed_from_client_hello_and_only_from_client_hello() {
        assert_eq!(
            parse_sni(&client_hello(Some("GHE.Example.com."))).as_deref(),
            Some("ghe.example.com")
        );
        assert_eq!(parse_sni(&client_hello(None)), None);
        assert_eq!(parse_sni(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(parse_sni(b""), None);
        // 途中で切れていれば None（読み足す側の判断に任せる）
        let full = client_hello(Some("a.test"));
        assert_eq!(parse_sni(&full[..full.len() - 3]), None);
        // ClientHello 以外のハンドシェイク
        let mut sh = full.clone();
        sh[5] = 0x02;
        assert_eq!(parse_sni(&sh), None);
    }

    /// 接続直後に tag を書いて閉じるサーバ。返り値はポート。
    async fn tag_server(tag: &'static str) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf).await;
                    let _ = s.write_all(tag.as_bytes()).await;
                });
            }
        });
        port
    }

    async fn roundtrip(addr: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(payload).await.unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            match tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => {
                    out.extend_from_slice(&buf[..n]);
                    if out.ends_with(b"A") || out.ends_with(b"B") {
                        break;
                    }
                }
                Ok(Err(_)) => break,
            }
        }
        out
    }

    #[tokio::test]
    async fn sni_selects_the_upstream_and_unknown_or_missing_sni_goes_to_default() {
        let a = tag_server("A").await;
        let b = tag_server("B").await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let p = Arc::new(Passthrough {
            upstream: "127.0.0.1".into(),
            port: a,
            upstreams: vec![
                SniTarget {
                    domain: "a.test".into(),
                    host: "127.0.0.1".into(),
                    port: a,
                },
                SniTarget {
                    domain: "b.test".into(),
                    host: "127.0.0.1".into(),
                    port: b,
                },
            ],
            mode: HttpsMode::Passthrough,
            proxy: None,
            idle: Duration::from_secs(5),
            conns: Semaphore::new(8),
            audit: Arc::new(Audit::disabled()),
            allow_local: true,
        });
        assert_eq!(p.select(Some("b.test")), ("127.0.0.1", b, true));
        assert_eq!(p.select(Some("nope.test")), ("127.0.0.1", a, false));
        assert_eq!(p.select(None), ("127.0.0.1", a, false));
        tokio::spawn(p.run(listener));

        assert_eq!(roundtrip(addr, &client_hello(Some("b.test"))).await, b"B");
        assert_eq!(roundtrip(addr, &client_hello(Some("a.test"))).await, b"A");
        assert_eq!(
            roundtrip(addr, &client_hello(Some("nope.test"))).await,
            b"A"
        );
        assert_eq!(roundtrip(addr, &client_hello(None)).await, b"A");
        // TLS でない平文も既定上流へ
        assert_eq!(roundtrip(addr, b"GET / HTTP/1.0\r\n\r\n").await, b"A");
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
    async fn client_hello_prefix_is_forwarded_before_the_rest_of_the_stream() {
        // 2 上流構成（先読みが走る）で echo に流し、ClientHello + 続きのバイトが順序どおり届くこと
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
        let mut p = pt("127.0.0.1", echo_port, true);
        Arc::get_mut(&mut p).unwrap().upstreams = vec![
            SniTarget {
                domain: "x.test".into(),
                host: "127.0.0.1".into(),
                port: echo_port,
            },
            SniTarget {
                domain: "y.test".into(),
                host: "127.0.0.1".into(),
                port: echo_port,
            },
        ];
        tokio::spawn(p.run(listener));

        let hello = client_hello(Some("x.test"));
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(&hello).await.unwrap();
        c.write_all(b" and more").await.unwrap();
        let want = [hello.as_slice(), b" and more"].concat();
        let mut got = Vec::new();
        let mut buf = [0u8; 512];
        while got.len() < want.len() {
            let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert!(n > 0);
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, want);
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
