//! Construction of the upstream HTTPS client.
//!
//! By default `reqwest` uses rustls and **ignores the OS certificate store**, so TLS verification fails behind a corporate MITM proxy.
//! We therefore explicitly trust native roots (`rustls-tls-native-roots`) plus the PEM bundles from `SSL_CERT_FILE` and `relay.ca_file`,
//! and use `proxy.upstream_proxy` from `config.yml` when it is set.

use std::path::Path;
use std::time::Duration;

use anyhow::Context;

use crate::config::ProxySpec;

pub const USER_AGENT: &str = concat!("sekimore-relay/", env!("CARGO_PKG_VERSION"));

pub struct HttpOptions<'a> {
    pub ca_file: Option<&'a Path>,
    pub proxy: Option<&'a ProxySpec>,
    pub timeout: Duration,
}

impl Default for HttpOptions<'_> {
    fn default() -> Self {
        HttpOptions {
            ca_file: None,
            proxy: None,
            timeout: Duration::from_secs(30),
        }
    }
}

pub fn build_client(opts: &HttpOptions<'_>) -> anyhow::Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .user_agent(USER_AGENT)
        .timeout(opts.timeout)
        .connect_timeout(Duration::from_secs(20));

    // SSL_CERT_FILE (rustls-native-certs picks it up too, but be explicit) and relay.ca_file
    let mut bundles: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(p) = std::env::var("SSL_CERT_FILE") {
        if !p.trim().is_empty() {
            bundles.push(p.into());
        }
    }
    if let Some(p) = opts.ca_file {
        bundles.push(p.to_path_buf());
    }
    for p in bundles {
        let pem = std::fs::read(&p).with_context(|| format!("read CA bundle {}", p.display()))?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .with_context(|| format!("parse CA bundle {}", p.display()))?;
        for c in certs {
            b = b.add_root_certificate(c);
        }
    }

    if let Some(px) = opts.proxy {
        // #151: the credential is looked up per request, not fixed here. The client is built at
        // start, while the secret store is still locked; a static basic_auth would have kept the
        // environment's credential (or none) for the life of the process. The URL carries it as
        // userinfo, which reqwest turns into Proxy-Authorization; `url` percent-encodes it.
        // #205: `connect_url()`, not `url`: on the via-Squid route the requests go to the local
        // Squid and `credential()` is None there, so nothing of the upstream's is put on the wire.
        let dial = px.connect_url();
        let base = url::Url::parse(&dial).with_context(|| format!("proxy url {dial}"))?;
        let px = px.clone();
        let proxy = reqwest::Proxy::custom(move |_| {
            let mut u = base.clone();
            if let Some((user, pass)) = px.credential() {
                let _ = u.set_username(&user);
                let _ = u.set_password(Some(&pass));
            }
            Some(u)
        });
        b = b.proxy(proxy);
    }
    b.build().context("build http client")
}

/// Read a response body up to a cap, so a huge response cannot eat memory.
pub async fn read_limited(resp: reqwest::Response, cap: usize) -> reqwest::Result<Vec<u8>> {
    let mut resp = resp;
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if out.len() + chunk.len() > cap {
            out.extend_from_slice(&chunk[..cap - out.len()]);
            break;
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Shorten a body for use in an error message.
pub fn truncate(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    if s.len() <= 200 {
        return s.into_owned();
    }
    // Cut on a character boundary. `s[..200]` panics mid-character, and the strings reaching
    // here are upstream error bodies, which echo back what the agent sent — a Japanese label
    // name is enough to land a multi-byte character across byte 200.
    let mut end = 200;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::truncate;

    /// Upstream error bodies echo back what the agent sent, so a multi-byte character can
    /// land across the cut. `&s[..200]` panics there, and the panic is reachable by asking
    /// for a label with a Japanese name.
    #[test]
    fn a_multibyte_character_across_the_cut_does_not_panic() {
        for pad in 195..=205 {
            let mut v = vec![b'a'; pad];
            v.extend_from_slice("あいうえお".as_bytes());
            let out = truncate(&v);
            assert!(out.ends_with("..."), "pad={pad}");
            // and what comes back is still valid text
            assert!(out.chars().count() > 0);
        }
    }

    #[test]
    fn a_short_body_is_returned_whole() {
        assert_eq!(truncate(b"boom"), "boom");
        assert_eq!(truncate("短い".as_bytes()), "短い");
        assert_eq!(truncate(b""), "");
    }

    #[test]
    fn a_long_body_is_cut_and_marked() {
        let out = truncate(&vec![b'x'; 500]);
        assert_eq!(out.len(), 203);
        assert!(out.ends_with("..."));
    }

    #[test]
    fn invalid_utf8_is_replaced_rather_than_refused() {
        // read_limited cuts on a byte boundary, so the body can end mid-character.
        let mut v = vec![b'a'; 199];
        v.push(0xE3); // first byte of a 3-byte sequence, truncated
        let out = truncate(&v);
        assert!(!out.is_empty());
    }
}

#[cfg(test)]
mod proxy_tests {
    use super::*;
    use crate::netutil::base64_encode;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A proxy that answers every request with 200 and reports the Proxy-Authorization it saw
    /// (or "-" for none), one line per request.
    async fn fake_proxy() -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut b = [0u8; 1];
                    while !buf.ends_with(b"\r\n\r\n") {
                        if s.read(&mut b).await.unwrap_or(0) == 0 {
                            return;
                        }
                        buf.push(b[0]);
                    }
                    let head = String::from_utf8_lossy(&buf).to_string();
                    let auth = head
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("proxy-authorization: ")
                                .or_else(|| l.strip_prefix("Proxy-Authorization: "))
                        })
                        .unwrap_or("-")
                        .to_string();
                    let _ = tx.send(auth);
                    let _ = s
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                });
            }
        });
        (format!("http://{addr}"), rx)
    }

    fn basic(user: &str, pass: &str) -> String {
        format!(
            "Basic {}",
            base64_encode(format!("{user}:{pass}").as_bytes())
        )
    }

    /// `fake_proxy`, but behind TLS: what an `https://` upstream proxy looks like (#192).
    async fn fake_tls_proxy() -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
        use crate::netutil::test_tls;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let acceptor = test_tls::acceptor();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = l.accept().await else {
                    return;
                };
                let tx = tx.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut s) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = Vec::new();
                    let mut b = [0u8; 1];
                    while !buf.ends_with(b"\r\n\r\n") {
                        if s.read(&mut b).await.unwrap_or(0) == 0 {
                            return;
                        }
                        buf.push(b[0]);
                    }
                    let head = String::from_utf8_lossy(&buf).to_string();
                    let _ = tx.send(head.lines().next().unwrap_or("").to_string());
                    let _ = s
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = s.shutdown().await;
                });
            }
        });
        (format!("https://127.0.0.1:{}", addr.port()), rx)
    }

    #[tokio::test]
    async fn an_https_proxy_is_reached_over_tls_by_the_api_client_too() {
        // #192 was the passthrough; this pins down that reqwest, which carries the GitHub API
        // calls, speaks TLS to an `https://` proxy with the same CA bundle the relay trusts
        let (url, mut seen) = fake_tls_proxy().await;
        let ca = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(ca.path(), crate::netutil::test_tls::CA_PEM).unwrap();
        let spec = ProxySpec {
            url,
            username: None,
            password: None,
            stored: Default::default(),
            via_squid: None,
            direct_egress: crate::config::DirectEgress::Allow,
        };
        let client = build_client(&HttpOptions {
            proxy: Some(&spec),
            ca_file: Some(ca.path()),
            ..Default::default()
        })
        .unwrap();
        let resp = client
            .get("http://upstream.invalid/x")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let line = seen.recv().await.unwrap();
        assert!(line.starts_with("GET http://upstream.invalid/x"), "{line}");
    }

    #[tokio::test]
    async fn the_proxy_gets_whatever_credential_is_current_at_each_request() {
        // #151: the client is built at start, while the store is locked. What reaches the proxy
        // has to follow the store as it is unlocked and changed, and fall back to the environment's
        // credential when the store has none.
        let (url, mut seen) = fake_proxy().await;
        let spec = ProxySpec {
            url,
            username: Some("env-user".into()),
            password: Some("env-pass".into()),
            stored: Default::default(),
            via_squid: None,
            direct_egress: crate::config::DirectEgress::Allow,
        };
        let client = build_client(&HttpOptions {
            proxy: Some(&spec),
            ..Default::default()
        })
        .unwrap();
        let get = || client.get("http://upstream.invalid/x").send();

        get().await.unwrap();
        assert_eq!(
            seen.recv().await.unwrap(),
            basic("env-user", "env-pass"),
            "store empty: the environment's"
        );

        // the store is unlocked and holds one; characters that mean something in a URL survive
        spec.stored
            .set(Some(("store-user".into(), "p@ss:w/rd%".into())));
        get().await.unwrap();
        assert_eq!(
            seen.recv().await.unwrap(),
            basic("store-user", "p@ss:w/rd%"),
            "the store's wins"
        );

        // changed with gw:proxy-credential, no restart
        spec.stored
            .set(Some(("store-user".into(), "rotated".into())));
        get().await.unwrap();
        assert_eq!(seen.recv().await.unwrap(), basic("store-user", "rotated"));

        // locked again: back to the environment's
        spec.stored.set(None);
        get().await.unwrap();
        assert_eq!(seen.recv().await.unwrap(), basic("env-user", "env-pass"));
    }

    #[tokio::test]
    async fn no_credential_anywhere_sends_none() {
        let (url, mut seen) = fake_proxy().await;
        let spec = ProxySpec {
            url,
            username: None,
            password: None,
            stored: Default::default(),
            via_squid: None,
            direct_egress: crate::config::DirectEgress::Allow,
        };
        let client = build_client(&HttpOptions {
            proxy: Some(&spec),
            ..Default::default()
        })
        .unwrap();
        client
            .get("http://upstream.invalid/x")
            .send()
            .await
            .unwrap();
        assert_eq!(seen.recv().await.unwrap(), "-");
    }
}
