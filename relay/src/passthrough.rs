//! Port 443 for the same domain. Pointing `github.com` at the relay brings HTTPS along with it. Leaving it
//! at INPUT DROP gives a silent timeout (the worst outcome). By default the TCP stream is passed through unchanged
//! to the real upstream:443 (TLS is not terminated); with `relay.https: reject` it is closed immediately and logged.
//!
//! 0.2.0: with multiple upstreams, the **SNI in the ClientHello** is peeked at to pick one (TLS is not terminated,
//! so it can be read in the clear). Without an SNI, or with no matching upstream, the default upstream is used (same as 0.1.x).

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::audit::{Actor, Audit};
use crate::config::{HttpsMode, ProxySpec};
use crate::git::{copy_touch, Watchdog};
use crate::netutil::http_connect_tunnel;

/// One upstream selectable by SNI. `domain` is the name DNS points at the relay (i.e. the name that arrives in the SNI); `host` is the real upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniTarget {
    pub domain: String,
    pub host: String,
    pub port: u16,
    /// 0.2.2: upload cap for this destination (None = unlimited)
    pub max_upload: Option<u64>,
}

/// How long to wait for a ClientHello. Non-TLS or slow clients are forwarded to the default upstream with whatever was read.
pub const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// Cap on the peeked bytes (maximum TLS record of 16 KiB plus the header).
const CLIENT_HELLO_CAP: usize = 16 * 1024 + 5 + 256;

pub struct Passthrough {
    /// Default upstream (used when there is no SNI, or no match)
    pub upstream: String,
    pub port: u16,
    /// 0.2.0: upstreams selectable by SNI (the default upstream may be included). Empty means always use the default
    pub upstreams: Vec<SniTarget>,
    /// 0.2.2: upload cap for the default upstream (no SNI or no match). None = unlimited
    pub max_upload: Option<u64>,
    pub mode: HttpsMode,
    pub proxy: Option<ProxySpec>,
    pub idle: Duration,
    pub conns: Semaphore,
    pub audit: Arc<Audit>,
    /// For tests: connect even when the name resolves to this host itself
    pub allow_local: bool,
}

/// #178: whether `ip` is a destination no allowed name may reach.
///
/// The DNS path and Squid refuse these already, but the passthrough resolves the upstream name
/// itself and never sees either answer — the same gap that made Squid's own deny necessary. A
/// domain given `https-relay` and pointed at 169.254.169.254 would otherwise reach the metadata
/// service, which serves credentials, through the one component holding the upstream token.
///
/// Deliberately not configurable here: `is_local_ip` below already covers the gateway's own
/// addresses, and the ranges named here are ones no public upstream has a reason to sit in.
pub fn is_denied_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local() // 169.254.0.0/16: IMDS lives here
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 0
                // 100.64.0.0/10, carrier-grade NAT
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            // An IPv4 address in an IPv6 shape is the same destination
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_denied_destination(IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                // fe80::/10 link-local, fc00::/7 unique-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Whether `ip` is an address of this host (detects a DNS self-loop).
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

/// Extracts the SNI (the host_name of the server_name extension) from a TLS ClientHello.
/// Returns None if this is not TLS, not a ClientHello, has no extensions, or is truncated. The name is lowercased with no trailing `.`.
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

/// Reads the first TLS record (the ClientHello) and returns (SNI, bytes read).
/// For non-TLS traffic it stops at the first successful read. On timeout or error it still returns what was read (to forward upstream).
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
    /// Picks the destination from the SNI. Returns (host, port, upload cap, whether it matched).
    ///
    /// With no usable SNI the destination is the default upstream, but the cap is the
    /// tightest of all of them. The cap is what limits how much leaves, and it is chosen from
    /// a name the client supplies: leaving the default's cap in place means a client that
    /// omits the SNI, or sends one that matches nothing, gets whichever cap happens to be
    /// loosest. Here `github.com` is held to 256 KiB and the default is 1 MiB, so omitting
    /// the name would be a fourfold raise for the asking.
    pub fn select(&self, sni: Option<&str>) -> (&str, u16, Option<u64>, bool) {
        if let Some(name) = sni {
            for t in &self.upstreams {
                if t.domain.eq_ignore_ascii_case(name) || t.host.eq_ignore_ascii_case(name) {
                    return (&t.host, t.port, t.max_upload, true);
                }
            }
        }
        (&self.upstream, self.port, self.strictest_cap(), false)
    }

    /// The tightest cap among the default and every configured target. `None` (unlimited)
    /// only when nothing sets one.
    fn strictest_cap(&self) -> Option<u64> {
        // Any target that is capped binds an unnamed connection; unlimited loses to a number.
        std::iter::once(self.max_upload)
            .chain(self.upstreams.iter().map(|t| t.max_upload))
            .flatten()
            .min()
    }

    /// Connects to the default upstream (0.1.x compatible).
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
        let mut refused: Vec<String> = Vec::new();
        for addr in addrs {
            // Self-loop first: it is a configuration mistake with a diagnostic of its own, and
            // the gateway's own addresses are private ones, so #178 would otherwise swallow it
            if !self.allow_local && is_local_ip(addr.ip()) {
                skipped_self = true;
                continue;
            }
            // #178: an allowed name is not an allowed destination. Checked here, where the name
            // has just been resolved, because this is the last point before the connection.
            if !self.allow_local && is_denied_destination(addr.ip()) {
                refused.push(addr.ip().to_string());
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
        if !refused.is_empty() {
            self.audit.deny(
                "resolved_address_refused",
                Actor::System,
                "an allowed name may not resolve into this range",
                &[("host", host), ("addresses", &refused.join(","))],
            );
        }
        if skipped_self && last.is_none() {
            return Err(std::io::Error::other(format!(
                "{host} resolves to this gateway itself (DNS self-reference loop); the gateway must resolve the upstream via the real resolver"
            )));
        }
        if !refused.is_empty() && last.is_none() {
            // Said plainly: "the gateway refused" and "it did not resolve" are different facts,
            // and only the first one means someone pointed an allowed name somewhere it may not go
            return Err(std::io::Error::other(format!(
                "{host} resolves to {}, which this gateway refuses to reach (link-local, loopback or a private range)",
                refused.join(", ")
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
                // With a single upstream there is nothing to peek at (same behaviour as 0.1.x)
                let (sni, prefix) = if this.upstreams.len() > 1 {
                    read_client_hello(&mut stream, CLIENT_HELLO_TIMEOUT).await
                } else {
                    (None, Vec::new())
                };
                let (host, port, cap, _matched) = this.select(sni.as_deref());
                let host = host.to_string();
                let cap_s = cap
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "unlimited".to_string());
                let sni_s = sni.clone().unwrap_or_else(|| "-".to_string());
                match this.connect_upstream_to(&host, port).await {
                    Ok(mut up) => {
                        // If the peeked ClientHello alone exceeds the cap, close without sending anything upstream
                        if cap.is_some_and(|c| prefix.len() as u64 > c) {
                            this.audit.deny(
                                "https_upload_capped",
                                Actor::Agent,
                                "upload exceeded max_upload_bytes; connection closed",
                                &[
                                    ("peer", &peer_s),
                                    ("upstream", &host),
                                    ("sni", &sni_s),
                                    ("bytes_in", &prefix.len().to_string()),
                                    ("cap", &cap_s),
                                ],
                            );
                            return;
                        }
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
                        let already = prefix.len() as u64;
                        let (bi, bo, capped) = this.pump(stream, up, already, cap).await;
                        let bytes_in = (bi + already).to_string();
                        if capped {
                            this.audit.deny(
                                "https_upload_capped",
                                Actor::Agent,
                                "upload exceeded max_upload_bytes; connection closed",
                                &[
                                    ("peer", &peer_s),
                                    ("upstream", &host),
                                    ("sni", &sni_s),
                                    ("bytes_in", &bytes_in),
                                    ("cap", &cap_s),
                                ],
                            );
                            log::warn!(
                                "https passthrough to {host} from {peer_s}: upload exceeded {cap_s} bytes; closed"
                            );
                            return;
                        }
                        this.audit.log(
                            "https_passthrough",
                            Actor::Agent,
                            &[
                                ("peer", &peer_s),
                                ("upstream", &host),
                                ("sni", &sni_s),
                                ("bytes_in", &bytes_in),
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

    /// Pumps both directions. Returns (bytes dev → upstream, bytes upstream → dev, whether the cap cut it off).
    /// `already` is the number of bytes the peeked ClientHello already sent upstream, and counts against the cap. A `cap` of None is unlimited.
    async fn pump(
        &self,
        client: TcpStream,
        upstream: TcpStream,
        already: u64,
        cap: Option<u64>,
    ) -> (u64, u64, bool) {
        let wd = Watchdog::new(self.idle);
        wd.touch();
        let (cr, cw) = client.into_split();
        let (ur, uw) = upstream.into_split();
        let wd_down = wd.clone();
        // upstream → dev keeps flowing in its own task (aborted, closing the connection, once the cap is hit)
        let down =
            tokio::spawn(async move { copy_touch(ur, cw, &wd_down, true).await.unwrap_or(0) });
        // Read from outside the future: an idle timeout drops it, and the bytes it had already
        // forwarded are the record of what left. Zero there would let a pause erase them.
        let sent_up = AtomicU64::new(0);
        let up = copy_capped(cr, uw, &wd, cap, already, &sent_up);
        tokio::select! {
            (sent, capped) = up => {
                if capped {
                    down.abort();
                    return (sent, 0, true);
                }
                // The dev side is done sending. Wait for the response to drain (with the idle watchdog running)
                tokio::select! {
                    r = down => (sent, r.unwrap_or(0), false),
                    _ = wd.expired() => (sent, 0, false),
                }
            }
            _ = wd.expired() => {
                down.abort();
                (sent_up.load(Ordering::Relaxed), 0, false)
            }
        }
    }
}

/// Copies dev → upstream. Stops without sending anything beyond `cap` (None = unlimited) and returns (bytes sent, whether the cap was hit).
/// `already` is what has already been sent (and counts against the cap).
async fn copy_capped<R, W>(
    mut reader: R,
    mut writer: W,
    wd: &Watchdog,
    cap: Option<u64>,
    already: u64,
    seen: &AtomicU64,
) -> (u64, bool)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = already;
    seen.store(0, Ordering::Relaxed);
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if let Some(cap) = cap {
            if total + n as u64 > cap {
                let _ = writer.shutdown().await;
                return (total - already, true);
            }
        }
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
        total += n as u64;
        seen.store(total - already, Ordering::Relaxed);
        wd.touch();
    }
    let _ = writer.shutdown().await;
    (total - already, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(upstream: &str, port: u16, allow_local: bool) -> Arc<Passthrough> {
        Arc::new(Passthrough {
            upstream: upstream.to_string(),
            port,
            upstreams: Vec::new(),
            max_upload: None,
            mode: HttpsMode::Passthrough,
            proxy: None,
            idle: Duration::from_secs(5),
            conns: Semaphore::new(4),
            audit: Arc::new(Audit::disabled()),
            allow_local,
        })
    }

    /// The cap is what limits how much leaves, and it is picked from a name the client sends.
    /// Falling back to the default's cap when the name matches nothing means a client that
    /// omits it gets whichever cap is loosest — here the deployment holds github.com to
    /// 256 KiB while the default is 1 MiB, so leaving the name out would be a fourfold raise
    /// for the asking.
    /// #178: the passthrough resolves the upstream name itself, so the refusals made in the DNS
    /// path and in Squid never reach it. Without this check a domain given `https-relay` and
    /// pointed at 169.254.169.254 reaches the metadata service — which serves credentials —
    /// through the component that holds the upstream token.
    #[test]
    fn a_name_may_not_resolve_into_a_denied_range() {
        for ip in [
            "169.254.169.254", // the metadata service itself
            "169.254.0.1",     // the rest of link-local, not only the well-known address
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "0.0.0.0",
            "100.64.0.1", // carrier-grade NAT
        ] {
            assert!(
                is_denied_destination(ip.parse().unwrap()),
                "{ip} must be refused"
            );
        }
    }

    /// The traffic the gateway exists to carry is not refused, including the addresses just
    /// outside each denied range: one written slightly too wide would break real upstreams.
    #[test]
    fn ordinary_public_addresses_are_still_reachable() {
        for ip in [
            "140.82.114.4", // github.com
            "8.8.8.8",
            "9.255.255.255",  // just below 10.0.0.0/8
            "11.0.0.0",       // just above it
            "172.15.255.255", // just below 172.16.0.0/12
            "172.32.0.0",     // just above it
            "192.167.255.255",
            "192.169.0.0",
            "169.253.255.255", // just below 169.254.0.0/16
            "169.255.0.0",     // just above it
            "100.63.255.255",  // just below 100.64.0.0/10
            "100.128.0.0",     // just above it
        ] {
            assert!(
                !is_denied_destination(ip.parse().unwrap()),
                "{ip} must stay reachable"
            );
        }
    }

    /// An IPv4 destination in an IPv6 shape is the same destination: ::ffff:169.254.169.254
    /// would otherwise walk past a check written in IPv4.
    #[test]
    fn an_ipv4_address_in_an_ipv6_shape_is_judged_as_ipv4() {
        assert!(is_denied_destination(
            "::ffff:169.254.169.254".parse().unwrap()
        ));
        assert!(is_denied_destination("::ffff:10.0.0.5".parse().unwrap()));
        // …and the same shape carrying a public address is still allowed
        assert!(!is_denied_destination(
            "::ffff:140.82.114.4".parse().unwrap()
        ));
    }

    #[test]
    fn the_ipv6_private_ranges_are_refused() {
        for ip in ["::1", "fe80::1", "fc00::1", "fd00::1", "::"] {
            assert!(
                is_denied_destination(ip.parse().unwrap()),
                "{ip} must be refused"
            );
        }
        // A public IPv6 address is not
        assert!(!is_denied_destination("2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn an_unnamed_connection_gets_the_tightest_cap_not_the_default() {
        let mut p = pt("upstream.test", 443, true);
        {
            let p = Arc::get_mut(&mut p).unwrap();
            p.max_upload = Some(1024 * 1024); // relay.https_max_upload_bytes
            p.upstreams = vec![
                SniTarget {
                    domain: "github.com".into(),
                    host: "github.com".into(),
                    port: 443,
                    max_upload: Some(256 * 1024),
                },
                SniTarget {
                    domain: "api.github.com".into(),
                    host: "api.github.com".into(),
                    port: 443,
                    max_upload: Some(16 * 1024 * 1024),
                },
            ];
        }
        // A name that matches still gets its own cap, loose or tight.
        assert_eq!(p.select(Some("github.com")).2, Some(256 * 1024));
        assert_eq!(p.select(Some("api.github.com")).2, Some(16 * 1024 * 1024));
        // No name, or one that matches nothing, gets the tightest of them all.
        assert_eq!(p.select(None).2, Some(256 * 1024));
        assert_eq!(p.select(Some("nothing.test")).2, Some(256 * 1024));
        assert_eq!(p.select(Some("")).2, Some(256 * 1024));
    }

    #[test]
    fn an_uncapped_target_does_not_loosen_the_unnamed_cap() {
        // One target left unlimited must not become the cap every unnamed connection gets.
        let mut p = pt("upstream.test", 443, true);
        {
            let p = Arc::get_mut(&mut p).unwrap();
            p.max_upload = None; // the default itself is unlimited
            p.upstreams = vec![
                SniTarget {
                    domain: "ghcr.io".into(),
                    host: "ghcr.io".into(),
                    port: 443,
                    max_upload: None,
                },
                SniTarget {
                    domain: "github.com".into(),
                    host: "github.com".into(),
                    port: 443,
                    max_upload: Some(4096),
                },
            ];
        }
        assert_eq!(p.select(None).2, Some(4096));
        assert_eq!(p.select(Some("ghcr.io")).2, None);
    }

    #[test]
    fn with_nothing_capped_an_unnamed_connection_stays_uncapped() {
        // Otherwise adding the rule would cap a deployment that had deliberately set none.
        let mut p = pt("upstream.test", 443, true);
        {
            let p = Arc::get_mut(&mut p).unwrap();
            p.max_upload = None;
            p.upstreams = vec![SniTarget {
                domain: "a.test".into(),
                host: "a.test".into(),
                port: 443,
                max_upload: None,
            }];
        }
        assert_eq!(p.select(None).2, None);
    }

    async fn echo_server() -> u16 {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = echo.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn upload_cap_closes_the_connection_and_forwards_at_most_cap_bytes() {
        let echo_port = echo_server().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut p = pt("127.0.0.1", echo_port, true);
        Arc::get_mut(&mut p).unwrap().max_upload = Some(1024);
        tokio::spawn(p.run(listener));

        let mut c = TcpStream::connect(addr).await.unwrap();
        // 700 bytes get through; the next 700 push past the cap of 1024 → disconnect
        let chunk = vec![b'x'; 700];
        c.write_all(&chunk).await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while got.len() < 700 {
            let n = tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert!(n > 0);
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got.len(), 700);
        let _ = c.write_all(&chunk).await;
        // The second chunk is not forwarded and the connection is closed (read ends with 0 or an error)
        let mut extra = 0usize;
        loop {
            match tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => extra += n,
            }
        }
        assert_eq!(extra, 0, "bytes beyond the cap must not be forwarded");
    }

    #[tokio::test]
    async fn per_target_cap_is_chosen_by_sni() {
        let echo_port = echo_server().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut p = pt("127.0.0.1", echo_port, true);
        {
            let p = Arc::get_mut(&mut p).unwrap();
            p.max_upload = Some(64);
            p.upstreams = vec![
                SniTarget {
                    domain: "small.test".into(),
                    host: "127.0.0.1".into(),
                    port: echo_port,
                    max_upload: Some(64),
                },
                SniTarget {
                    domain: "big.test".into(),
                    host: "127.0.0.1".into(),
                    port: echo_port,
                    max_upload: None,
                },
            ];
        }
        assert_eq!(p.select(Some("big.test")).2, None);
        assert_eq!(p.select(Some("small.test")).2, Some(64));
        assert_eq!(p.select(None).2, Some(64));
        tokio::spawn(p.run(listener));

        // big.test: the ClientHello (>64 bytes) and everything after it are echoed back
        let hello = client_hello(Some("big.test"));
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(&hello).await.unwrap();
        c.write_all(&vec![b'y'; 3000]).await.unwrap();
        let want = hello.len() + 3000;
        let mut got = 0usize;
        let mut buf = [0u8; 4096];
        while got < want {
            let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert!(n > 0);
            got += n;
        }
        assert_eq!(got, want);
        // small.test: the ClientHello alone exceeds 64 bytes, so the connection is cut immediately
        let hello = client_hello(Some("small.test"));
        let mut c = TcpStream::connect(addr).await.unwrap();
        let _ = c.write_all(&hello).await;
        let mut extra = 0usize;
        loop {
            match tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => extra += n,
            }
        }
        assert_eq!(extra, 0);
    }

    /// A minimal TLS 1.2 ClientHello (SNI is the only extension, when given).
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
        // Append one more dummy extension (standing in for supported_versions) to exercise the scan
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
        // Truncated input yields None (it is up to the caller to read more)
        let full = client_hello(Some("a.test"));
        assert_eq!(parse_sni(&full[..full.len() - 3]), None);
        // A handshake message other than ClientHello
        let mut sh = full.clone();
        sh[5] = 0x02;
        assert_eq!(parse_sni(&sh), None);
    }

    /// A server that writes tag and closes as soon as it accepts. Returns the port.
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
                    max_upload: None,
                },
                SniTarget {
                    domain: "b.test".into(),
                    host: "127.0.0.1".into(),
                    port: b,
                    max_upload: None,
                },
            ],
            max_upload: None,
            mode: HttpsMode::Passthrough,
            proxy: None,
            idle: Duration::from_secs(5),
            conns: Semaphore::new(8),
            audit: Arc::new(Audit::disabled()),
            allow_local: true,
        });
        assert_eq!(p.select(Some("b.test")), ("127.0.0.1", b, None, true));
        assert_eq!(p.select(Some("nope.test")), ("127.0.0.1", a, None, false));
        assert_eq!(p.select(None), ("127.0.0.1", a, None, false));
        tokio::spawn(p.run(listener));

        assert_eq!(roundtrip(addr, &client_hello(Some("b.test"))).await, b"B");
        assert_eq!(roundtrip(addr, &client_hello(Some("a.test"))).await, b"A");
        assert_eq!(
            roundtrip(addr, &client_hello(Some("nope.test"))).await,
            b"A"
        );
        assert_eq!(roundtrip(addr, &client_hello(None)).await, b"A");
        // Non-TLS plaintext also goes to the default upstream
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
        // With two upstreams (so the peek runs), stream to echo and check the ClientHello and following bytes arrive in order
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
                max_upload: None,
            },
            SniTarget {
                domain: "y.test".into(),
                host: "127.0.0.1".into(),
                port: echo_port,
                max_upload: None,
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
