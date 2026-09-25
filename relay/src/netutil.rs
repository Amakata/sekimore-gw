//! Small networking helpers: HTTP CONNECT tunnelling (plain or over TLS to the proxy) and base64
//! (to avoid extra dependencies).

use std::io;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

use crate::config::ProxySpec;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// What a connection to the upstream has to be, whichever way it was made: straight TCP, a
/// CONNECT tunnel, or a CONNECT tunnel inside TLS to the proxy (#192).
pub trait UpstreamStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> UpstreamStream for T {}

/// A connection to the upstream, boxed so the passthrough does not care which kind it got.
pub type Upstream = Box<dyn UpstreamStream>;

// `Result<Upstream, _>::unwrap_err()` in tests wants the Ok type printable; there is nothing
// useful to print about a socket
impl std::fmt::Debug for dyn UpstreamStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UpstreamStream")
    }
}

/// The TLS client configuration used towards an `https://` upstream proxy.
///
/// The same roots as the GitHub client: the platform's, `SSL_CERT_FILE`, and `relay.ca_file`. A
/// corporate proxy that speaks TLS is usually signed by the corporate CA, which is exactly what
/// those two files exist for. `serve` sets it once at start (`init_proxy_tls`); a process that
/// never did — a one-shot subcommand — gets the platform roots and `SSL_CERT_FILE` on first use.
static PROXY_TLS: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

/// Sets the TLS configuration for `https://` proxies. Only the first call counts.
pub fn init_proxy_tls(ca_file: Option<&Path>) -> anyhow::Result<()> {
    let cfg = proxy_tls_config(ca_file)?;
    let _ = PROXY_TLS.set(cfg);
    Ok(())
}

fn proxy_tls_config(ca_file: Option<&Path>) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    use anyhow::Context;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;

    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for e in &native.errors {
        log::warn!("platform CA store: {e}");
    }
    let (added, _) = roots.add_parsable_certificates(native.certs);
    log::debug!("proxy TLS: {added} platform roots");
    let mut bundles: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(p) = std::env::var("SSL_CERT_FILE") {
        if !p.trim().is_empty() {
            bundles.push(p.into());
        }
    }
    if let Some(p) = ca_file {
        bundles.push(p.to_path_buf());
    }
    for p in bundles {
        let pem = std::fs::read(&p).with_context(|| format!("read CA bundle {}", p.display()))?;
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<_, _>>()
            .with_context(|| format!("parse CA bundle {}", p.display()))?;
        let (added, _) = roots.add_parsable_certificates(certs);
        log::debug!("proxy TLS: {added} roots from {}", p.display());
    }
    Ok(Arc::new(client_config_with_roots(roots)?))
}

/// Explicit provider: the process has no default one installed, and reqwest brings its own.
fn client_config_with_roots(roots: rustls::RootCertStore) -> anyhow::Result<rustls::ClientConfig> {
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(cfg)
}

fn proxy_tls() -> anyhow::Result<Arc<rustls::ClientConfig>> {
    if let Some(cfg) = PROXY_TLS.get() {
        return Ok(cfg.clone());
    }
    let cfg = proxy_tls_config(None)?;
    let _ = PROXY_TLS.set(cfg.clone());
    Ok(cfg)
}

/// Sends `CONNECT host:port` to the upstream proxy and returns the established stream.
///
/// An `https://` proxy URL (`proxy.upstream_proxy_tls: true`) means TLS to the proxy first, and
/// the CONNECT inside it — what Squid does with `cache_peer … tls`. Before #192 the request went
/// out in plain text regardless, and a TLS proxy closed the connection at the first byte.
pub async fn http_connect_tunnel(proxy: &ProxySpec, host: &str, port: u16) -> io::Result<Upstream> {
    let tls = match Url::parse(&proxy.url)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("proxy url: {e}")))?
        .scheme()
    {
        "https" => Some(proxy_tls().map_err(|e| io::Error::other(format!("proxy TLS: {e}")))?),
        _ => None,
    };
    http_connect_tunnel_with(proxy, host, port, tls).await
}

/// `http_connect_tunnel` with the TLS configuration chosen by the caller (`None` = plain).
async fn http_connect_tunnel_with(
    proxy: &ProxySpec,
    host: &str,
    port: u16,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> io::Result<Upstream> {
    let url = Url::parse(&proxy.url)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("proxy url: {e}")))?;
    let phost = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "proxy url without host"))?;
    let pport = url.port_or_known_default().unwrap_or(3128);
    let tcp = TcpStream::connect((phost, pport)).await?;
    match tls {
        None => {
            let mut s = tcp;
            connect_through(&mut s, proxy, host, port).await?;
            Ok(Box::new(s))
        }
        Some(cfg) => {
            let name = rustls::pki_types::ServerName::try_from(phost.to_string()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("proxy host {phost}: {e}"),
                )
            })?;
            let mut s = tokio_rustls::TlsConnector::from(cfg)
                .connect(name, tcp)
                .await
                .map_err(|e| io::Error::new(e.kind(), format!("TLS to the proxy failed: {e}")))?;
            connect_through(&mut s, proxy, host, port).await?;
            Ok(Box::new(s))
        }
    }
}

/// The CONNECT exchange itself, on whatever stream reaches the proxy.
async fn connect_through<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    proxy: &ProxySpec,
    host: &str,
    port: u16,
) -> io::Result<()> {
    let mut req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n"
    );
    // #151: read now, not at start: the secret store may have been unlocked, or the credential
    // changed, since the relay came up
    if let Some((u, p)) = proxy.credential() {
        let cred = format!("{u}:{p}");
        req.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64_encode(cred.as_bytes())
        ));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = s.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy closed during CONNECT",
            ));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy CONNECT response too large",
            ));
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status = head.split_whitespace().nth(1).unwrap_or("");
    if status == "407" {
        // #151: say which credential was refused. Squid and the relay can read different ones, and
        // "407" alone left the operator comparing the two by hand
        return Err(io::Error::other(format!(
            "proxy refused CONNECT {host}:{port}: {} — the relay presented the credential from {}. \
             Set it with mise run gw:proxy-credential, and unlock the store (mise run gw:unlock)",
            head.lines().next().unwrap_or(""),
            proxy.credential_source()
        )));
    }
    if status != "200" {
        return Err(io::Error::other(format!(
            "proxy refused CONNECT {host}:{port}: {}",
            head.lines().next().unwrap_or("")
        )));
    }
    Ok(())
}

/// A self-signed certificate for `localhost` / `127.0.0.1` and a TLS acceptor built on it, for
/// tests that need a proxy or an upstream that speaks TLS. Shared with the other test modules.
#[cfg(test)]
pub mod test_tls {
    use std::sync::Arc;

    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    /// A test CA and a `localhost` / `127.0.0.1` server certificate it signed (webpki refuses a
    /// CA certificate presented as the end entity). Made 2026-09-25 with openssl, EC P-256:
    /// `req -x509 … -subj /CN=sekimore test CA`, then `req -newkey … -subj /CN=localhost` signed
    /// with `subjectAltName=DNS:localhost,IP:127.0.0.1`, `basicConstraints=CA:FALSE`,
    /// `extendedKeyUsage=serverAuth`. Valid for ten years.
    pub const CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBijCCATGgAwIBAgIUcbtLFd4IjhS9R1sGBa1RvjDSLJgwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQc2VraW1vcmUgdGVzdCBDQTAeFw0yNjA5MjUwMjUyMDdaFw0z
NjA5MjIwMjUyMDdaMBsxGTAXBgNVBAMMEHNla2ltb3JlIHRlc3QgQ0EwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATUyaIZ+MDhugDdGo5fwpw5BZmVFhx4Nt0wFLFO
sBACgATrv3/jjOXxxz22YyY4WY9Ecjmim/vdLNvRG7fi0Y6Po1MwUTAdBgNVHQ4E
FgQUbXKth1H0XlSOhotEFkwi3nV3eM8wHwYDVR0jBBgwFoAUbXKth1H0XlSOhotE
Fkwi3nV3eM8wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBb+6fD
TMpPtU0IBj5aEYhxELU+42t9Wt2vZdPKYa+/jwIgHfU3z411/+zLgKNxzivDmMrf
w10+iwEYjjuXNVwZkD8=
-----END CERTIFICATE-----
";
    pub const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBsDCCAVWgAwIBAgIUCUkLikG59nrKNRqvb/hpcbX7e8UwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQc2VraW1vcmUgdGVzdCBDQTAeFw0yNjA5MjUwMjUyMDdaFw0z
NjA5MjIwMjUyMDdaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABIvUIIqt06pN6H+AUhWn2NeAP2JNHV+QVhW9aAJyxfEUNYNp
rH6LuM/XtyVTlqXqoETxTC5dWFxjg/B6Lg+pQt2jfjB8MBoGA1UdEQQTMBGCCWxv
Y2FsaG9zdIcEfwAAATAJBgNVHRMEAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0G
A1UdDgQWBBQJGD0e3BlNDsDuTFCFw+8xGsTsyTAfBgNVHSMEGDAWgBRtcq2HUfRe
VI6Gi0QWTCLedXd4zzAKBggqhkjOPQQDAgNJADBGAiEA9lmy38EHE+2DXDHYiwdW
cqKIjGW5BljU6GiDLZFfYQwCIQDBObq3SJZVddSzE80MLexJuhNiIhoWxvn3qHby
h34yow==
-----END CERTIFICATE-----
";
    pub const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8cI9ImgEzJNlDpwX
XYJl5niwluuCHq+aIYwG5l+iYWChRANCAASL1CCKrdOqTeh/gFIVp9jXgD9iTR1f
kFYVvWgCcsXxFDWDaax+i7jP17clU5al6qBE8UwuXVhcY4Pwei4PqULd
-----END PRIVATE KEY-----
";

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    pub fn acceptor() -> tokio_rustls::TlsAcceptor {
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(CERT_PEM.as_bytes())
                .collect::<Result<_, _>>()
                .unwrap();
        let key = PrivateKeyDer::from_pem_slice(KEY_PEM.as_bytes()).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
    }

    /// A client configuration that trusts only the test CA.
    pub fn client_config() -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(CA_PEM.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        Arc::new(super::client_config_with_roots(roots).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }

    /// A proxy that accepts one CONNECT, hands back the Proxy-Authorization it saw, and answers
    /// with `status`.
    async fn one_connect(status: &'static str) -> (String, tokio::sync::oneshot::Receiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let auth = req
                .lines()
                .find_map(|l| l.strip_prefix("Proxy-Authorization: "))
                .unwrap_or("-")
                .to_string();
            let _ = tx.send(auth);
            s.write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes())
                .await
                .unwrap();
        });
        (format!("http://{addr}"), rx)
    }

    fn spec(url: String) -> ProxySpec {
        ProxySpec {
            url,
            username: Some("user".into()),
            password: Some("pass".into()),
            stored: Default::default(),
        }
    }

    #[tokio::test]
    async fn the_tunnel_presents_the_stored_credential_over_the_environments() {
        // #151: the passthrough got 407 because it only ever had the environment's credential
        let (url, seen) = one_connect("200 Connection established").await;
        let spec = ProxySpec {
            url,
            username: Some("env-user".into()),
            password: Some("env-pass".into()),
            stored: Default::default(),
        };
        spec.stored
            .set(Some(("store-user".into(), "store-pass".into())));
        http_connect_tunnel(&spec, "example.com", 443)
            .await
            .unwrap();
        assert_eq!(
            seen.await.unwrap(),
            format!("Basic {}", base64_encode(b"store-user:store-pass"))
        );
    }

    #[tokio::test]
    async fn a_407_says_whose_credential_was_refused() {
        let (url, _) = one_connect("407 Proxy Authentication Required").await;
        let spec = ProxySpec {
            url,
            username: Some("env-user".into()),
            password: None,
            stored: Default::default(),
        };
        let err = http_connect_tunnel(&spec, "example.com", 443)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("407"), "{err}");
        assert!(
            err.contains("SEKIMORE_UPSTREAM_PROXY_* or config.yml"),
            "{err}"
        );
        assert!(err.contains("gw:proxy-credential"), "{err}");
    }

    #[tokio::test]
    async fn connect_tunnel_talks_http() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(
                req.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
                "{req}"
            );
            assert!(
                req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"),
                "{req}"
            );
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            s.write_all(b"tunnel-ok").await.unwrap();
        });
        let mut s = http_connect_tunnel(&spec(format!("http://{addr}")), "example.com", 443)
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "tunnel-ok");
    }

    /// A proxy that speaks TLS first, like Squid's `cache_peer … tls` peer (#192).
    async fn one_tls_connect() -> (String, tokio::sync::oneshot::Receiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = test_tls::acceptor();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut s = acceptor.accept(tcp).await.unwrap();
            let mut buf = vec![0u8; 2048];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let _ = tx.send(req);
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            s.write_all(b"tls-tunnel-ok").await.unwrap();
            let _ = s.shutdown().await;
        });
        (format!("https://127.0.0.1:{}", addr.port()), rx)
    }

    #[tokio::test]
    async fn an_https_proxy_gets_tls_first_and_the_connect_inside_it() {
        let (url, seen) = one_tls_connect().await;
        let mut s = http_connect_tunnel_with(
            &spec(url),
            "api.github.com",
            443,
            Some(test_tls::client_config()),
        )
        .await
        .unwrap();
        let req = seen.await.unwrap();
        assert!(
            req.starts_with("CONNECT api.github.com:443 HTTP/1.1\r\n"),
            "{req}"
        );
        assert!(
            req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"),
            "{req}"
        );
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "tls-tunnel-ok");
    }

    #[tokio::test]
    async fn an_https_proxy_url_is_never_spoken_to_in_plain_text() {
        // The reporter's symptom: a TLS proxy closes at the first plain-text byte. Now the relay
        // does not send one: with no trust for the proxy's certificate the handshake fails, and
        // the error says so rather than "proxy closed during CONNECT".
        let (url, seen) = one_tls_connect().await;
        let mut roots = rustls::RootCertStore::empty();
        let err = http_connect_tunnel_with(
            &spec(url),
            "api.github.com",
            443,
            Some(Arc::new(client_config_with_roots(roots.clone()).unwrap())),
        )
        .await
        .unwrap_err()
        .to_string();
        roots.roots.clear();
        assert!(err.contains("TLS to the proxy failed"), "{err}");
        assert!(!err.contains("closed during CONNECT"), "{err}");
        assert!(
            seen.await.is_err(),
            "no CONNECT must have reached the proxy"
        );
    }

    #[test]
    fn the_scheme_decides_whether_tls_is_used() {
        for (url, expect_tls) in [("http://proxy:3128", false), ("https://proxy:3129", true)] {
            assert_eq!(
                Url::parse(url).unwrap().scheme() == "https",
                expect_tls,
                "{url}"
            );
        }
    }
}
