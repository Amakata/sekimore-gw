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
///
/// #205: on the via-Squid route `connect_url()` is the local Squid, so this dials loopback in
/// plain text and Squid takes the TLS hop with OpenSSL.
pub async fn http_connect_tunnel(proxy: &ProxySpec, host: &str, port: u16) -> io::Result<Upstream> {
    let tls = match Url::parse(&proxy.connect_url())
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
    let url = Url::parse(&proxy.connect_url())
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
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        with_handshake_hint(format!("TLS to the proxy failed: {e}")),
                    )
                })?;
            connect_through(&mut s, proxy, host, port).await?;
            Ok(Box::new(s))
        }
    }
}

/// What `probe_proxy` found out about the upstream proxy (#206).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    /// The proxy `host:port` that was dialled.
    pub endpoint: String,
    /// `true` when the probe did a TLS handshake — an `https://` proxy.
    pub tls: bool,
    /// The negotiated protocol version, e.g. `TLSv1_3`. `None` for a plain `http://` proxy.
    pub protocol: Option<String>,
    /// The negotiated cipher suite, e.g. `TLS13_AES_256_GCM_SHA384`. `None` for `http://`.
    pub cipher: Option<String>,
}

/// The sentence appended to a `HandshakeFailure`, in one place so the passthrough and the GitHub
/// API client say the same thing (#205, #206).
pub const HANDSHAKE_HINT: &str = " — the proxy accepted none of the relay's cipher suites \
(it must offer TLS 1.3 or ECDHE; a Squid https_port needs tls-dh=); see `sekimore-relay check`";

/// Whether an error text is the alert a proxy sends when it shares no cipher suite with the
/// relay (#205).
///
/// rustls words it `received fatal alert: HandshakeFailure`; that is the string the reporter saw
/// in `gw:logs`. reqwest wraps its own chain, so the lower-case spellings are matched too.
pub fn is_handshake_failure(err: &str) -> bool {
    // Only the alert's own names. A bare "handshake failed" is any TLS error at all — an expired
    // certificate, a reset — and those want a different remedy than "offer another cipher suite".
    err.contains("HandshakeFailure")
        || err.contains("handshake_failure")
        || err.contains("alert handshake failure")
}

/// Appends the diagnosis to a TLS error that was a `HandshakeFailure`, and hands anything else
/// back untouched (#205, #206).
///
/// The bare alert says only "no", and learning what the "no" meant cost the reporter an afternoon
/// of `openssl s_client`: rustls implements no RSA key exchange, so a proxy offering only TLS 1.2
/// with RSA — a Squid `https_port` without `tls-dh=` — has no suite in common with it.
pub fn with_handshake_hint(msg: String) -> String {
    if !is_handshake_failure(&msg) {
        return msg;
    }
    format!("{msg}{HANDSHAKE_HINT}")
}

/// Connects to the upstream proxy the way the passthrough would, and reports what it found (#206).
///
/// For an `https://` proxy this is a full rustls handshake with the same client configuration the
/// CONNECT tunnel uses, so a proxy the relay cannot speak TLS to fails here too, and not only when
/// real work starts. No CONNECT is sent — the point is reachability and the handshake, not a
/// tunnel — and the connection is dropped as soon as the report is in hand.
pub async fn probe_proxy(proxy: &ProxySpec) -> Result<ProbeReport, String> {
    let url = Url::parse(&proxy.connect_url()).map_err(|e| format!("proxy url: {e}"))?;
    let phost = url
        .host_str()
        .ok_or_else(|| "proxy url without host".to_string())?
        .to_string();
    let pport = url.port_or_known_default().unwrap_or(3128);
    let tls = match url.scheme() {
        "https" => Some(proxy_tls().map_err(|e| format!("proxy TLS: {e}"))?),
        _ => None,
    };
    probe_proxy_with(&phost, pport, tls).await
}

/// How long the probe waits. A proxy that accepts the TCP connection and then says nothing is one
/// of the shapes this is meant to catch, and without a bound it would hang `check` rather than
/// report it. Generous: a handshake over a slow corporate link is still a working proxy.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// `probe_proxy` with the host, port and TLS configuration chosen by the caller (`None` = plain).
async fn probe_proxy_with(
    phost: &str,
    pport: u16,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> Result<ProbeReport, String> {
    probe_proxy_within(phost, pport, tls, PROBE_TIMEOUT).await
}

/// `probe_proxy_with` with the bound chosen by the caller, so a test need not wait ten seconds.
async fn probe_proxy_within(
    phost: &str,
    pport: u16,
    tls: Option<Arc<rustls::ClientConfig>>,
    limit: std::time::Duration,
) -> Result<ProbeReport, String> {
    let endpoint = format!("{phost}:{pport}");
    tokio::time::timeout(limit, probe_inner(phost, pport, tls, &endpoint))
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "no answer from {endpoint} within {}s",
                limit.as_secs_f32()
            ))
        })
}

async fn probe_inner(
    phost: &str,
    pport: u16,
    tls: Option<Arc<rustls::ClientConfig>>,
    endpoint: &str,
) -> Result<ProbeReport, String> {
    let tcp = TcpStream::connect((phost, pport))
        .await
        .map_err(|e| e.to_string())?;
    let Some(cfg) = tls else {
        return Ok(ProbeReport {
            endpoint: endpoint.to_string(),
            tls: false,
            protocol: None,
            cipher: None,
        });
    };
    let name = rustls::pki_types::ServerName::try_from(phost.to_string())
        .map_err(|e| format!("proxy host {phost}: {e}"))?;
    // No `with_handshake_hint` here: that one-line hint is for a log, where there is no room for
    // more. `check` has room, and prints the fuller diagnosis and the openssl reading under the
    // line instead — appending both would say the same thing twice.
    let conn = tokio_rustls::TlsConnector::from(cfg)
        .connect(name, tcp)
        .await
        .map_err(|e| format!("TLS to the proxy failed: {e}"))?;
    let session = &conn.get_ref().1;
    let protocol = session.protocol_version().map(|v| format!("{v:?}"));
    let cipher = session
        .negotiated_cipher_suite()
        .map(|c| format!("{:?}", c.suite()));
    Ok(ProbeReport {
        endpoint: endpoint.to_string(),
        tls: true,
        protocol,
        cipher,
    })
}

/// What `probe_via_squid` got back: Squid's own status line for the CONNECT (#205).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SquidProbe {
    /// The Squid endpoint that was dialled, e.g. `127.0.0.1:3128`.
    pub endpoint: String,
    /// The host the CONNECT named, e.g. `api.github.com`.
    pub target: String,
    /// Squid's status code: `200` when the tunnel is open.
    pub status: String,
    /// Squid's whole status line, for a failure worth quoting.
    pub status_line: String,
}

/// Sends one `CONNECT <target>:443` to the local Squid and reports its status line (#205).
///
/// This is the actual path the relay takes on the via-Squid route, end to end: loopback to Squid,
/// Squid's `cache_peer … tls` to the upstream proxy, the upstream's CONNECT to the target. A
/// rustls handshake with the upstream would tell `check` nothing here — it is exactly the
/// handshake this route exists to avoid.
pub async fn probe_via_squid(port: u16, target: &str) -> Result<SquidProbe, String> {
    let endpoint = format!("127.0.0.1:{port}");
    tokio::time::timeout(PROBE_TIMEOUT, probe_via_squid_at(&endpoint, target))
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "no answer from Squid at {endpoint} within {}s",
                PROBE_TIMEOUT.as_secs_f32()
            ))
        })
}

/// `probe_via_squid` against a given endpoint, so a test can point it at a listener of its own.
pub async fn probe_via_squid_at(endpoint: &str, target: &str) -> Result<SquidProbe, String> {
    let mut s = TcpStream::connect(endpoint)
        .await
        .map_err(|e| e.to_string())?;
    // No Proxy-Authorization: the local Squid asks for none, and the upstream's credential is
    // Squid's to present (`cache_peer … login=`), not ours to put on this hop (#205).
    let req = format!(
        "CONNECT {target}:443 HTTP/1.1\r\nHost: {target}:443\r\nProxy-Connection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let line = read_status_line(&mut s).await?;
    let status = line.split_whitespace().nth(1).unwrap_or("").to_string();
    Ok(SquidProbe {
        endpoint: endpoint.to_string(),
        target: target.to_string(),
        status,
        status_line: line,
    })
}

/// Reads up to the end of the response head and hands back its first line.
async fn read_status_line<S: AsyncRead + Unpin>(s: &mut S) -> Result<String, String> {
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = s.read(&mut byte).await.map_err(|e| e.to_string())?;
        if n == 0 {
            if buf.is_empty() {
                return Err("Squid closed the connection without answering".into());
            }
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") || buf.ends_with(b"\n\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err("Squid's CONNECT response is too large".into());
        }
    }
    Ok(String::from_utf8_lossy(&buf)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string())
}

/// Asks the `openssl` CLI what an endpoint negotiates with it, as `Protocol version:` /
/// `Ciphersuite:` lines (#206, #205).
///
/// OpenSSL implements the RSA key exchange rustls does not, so where the relay gets
/// `HandshakeFailure` this still completes and names what the upstream chose. Best effort: no
/// openssl in PATH, a timeout or a non-zero exit all give an empty vector, and every caller has
/// something sensible to do with that.
pub async fn openssl_brief(host: &str, port: u16) -> Vec<String> {
    let endpoint = format!("{host}:{port}");
    let out = tokio::time::timeout(
        OPENSSL_TIMEOUT,
        tokio::process::Command::new("openssl")
            .args([
                "s_client",
                "-connect",
                &endpoint,
                "-servername",
                host,
                "-brief",
            ])
            .stdin(std::process::Stdio::null())
            .output(),
    )
    .await;
    // `-brief` writes its summary to stderr; take both and keep only the two lines that matter.
    match out {
        Ok(Ok(o)) => [
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        ]
        .concat()
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("Protocol version:") || l.starts_with("Ciphersuite:"))
        .map(str::to_string)
        .collect(),
        _ => Vec::new(),
    }
}

/// How long `openssl_brief` waits. Long enough for a slow corporate link, short enough that a
/// silent endpoint does not hold up `serve`'s startup or `check`'s output.
const OPENSSL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Whether `openssl_brief`'s reading is a suite with no forward secrecy (#205).
///
/// TLS 1.3 has ephemeral key agreement in every suite it defines, so its `Ciphersuite:` line needs
/// no ECDHE in the name. Under TLS 1.2 the key exchange is spelled out: `ECDHE-RSA-…` and
/// `DHE-…` are ephemeral, a bare `AES256-GCM-SHA384` is the static RSA key exchange — the
/// reporter's upstream, and the one rustls will not speak.
pub fn is_rsa_key_exchange(lines: &[String]) -> bool {
    let cipher = lines
        .iter()
        .find_map(|l| l.strip_prefix("Ciphersuite:"))
        .map(str::trim);
    let Some(cipher) = cipher else {
        return false;
    };
    // Reading nothing at all is not a finding.
    if cipher.is_empty() {
        return false;
    }
    if cipher.starts_with("TLS_") {
        // TLS 1.3 spells its suites `TLS_AES_256_GCM_SHA384`: always ephemeral.
        return false;
    }
    !(cipher.contains("ECDHE") || cipher.contains("DHE"))
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
        let line = head.lines().next().unwrap_or("");
        // #205: on the via-Squid route the relay presents nothing, by design — the credential is
        // Squid's to present to the upstream (`cache_peer … login=`). Telling the operator "the
        // relay presented X" would send them to the wrong half of the path.
        if proxy.via_squid.is_some() {
            return Err(io::Error::other(format!(
                "proxy refused CONNECT {host}:{port}: {line} — the relay went through the local \
                 Squid, which presents the stored credential to the upstream itself. Set it with \
                 sgw proxy-credential, and unlock the store (sgw unlock)"
            )));
        }
        // #151: say which credential was refused. Squid and the relay can read different ones, and
        // "407" alone left the operator comparing the two by hand
        return Err(io::Error::other(format!(
            "proxy refused CONNECT {host}:{port}: {line} — the relay presented the credential from {}. \
             Set it with sgw proxy-credential, and unlock the store (sgw unlock)",
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
            via_squid: None,
            direct_egress: crate::config::DirectEgress::Allow,
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
            via_squid: None,
            direct_egress: crate::config::DirectEgress::Allow,
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
            via_squid: None,
            direct_egress: crate::config::DirectEgress::Allow,
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
        assert!(err.contains("sgw proxy-credential"), "{err}");
    }

    /// #205: the reporter's upstream offers only TLS 1.2 with RSA key exchange, which rustls
    /// cannot speak. On that route the tunnel must go to the local Squid in plain text, and
    /// present nothing of the upstream's credential there.
    #[tokio::test]
    async fn the_via_squid_route_tunnels_through_the_local_squid_with_no_credential() {
        let (url, seen) = one_connect("200 Connection established").await;
        let squid_port = Url::parse(&url).unwrap().port().unwrap();
        let spec = ProxySpec {
            // The configured proxy is somewhere else entirely, and speaks TLS the relay cannot.
            url: "https://gw.example.net:3129".into(),
            username: Some("env-user".into()),
            password: Some("env-pass".into()),
            stored: Default::default(),
            via_squid: Some(squid_port),
            direct_egress: crate::config::DirectEgress::Allow,
        };
        spec.stored
            .set(Some(("store-user".into(), "store-pass".into())));
        // No TLS is attempted towards gw.example.net — the listener above is plain HTTP on
        // loopback, and a rustls handshake against it would fail here rather than connect.
        http_connect_tunnel(&spec, "api.github.com", 443)
            .await
            .unwrap();
        assert_eq!(
            seen.await.unwrap(),
            "-",
            "the local Squid gets no credential"
        );
    }

    /// #205: a 407 on the via-Squid route is not the relay's credential being refused — it
    /// presented none. #151's wording would send the operator to compare a credential the relay
    /// never sent.
    #[tokio::test]
    async fn a_407_through_squid_does_not_blame_the_relays_credential() {
        let (url, _) = one_connect("407 Proxy Authentication Required").await;
        let squid_port = Url::parse(&url).unwrap().port().unwrap();
        let spec = ProxySpec {
            url: "https://gw.example.net:3129".into(),
            username: Some("env-user".into()),
            password: Some("env-pass".into()),
            stored: Default::default(),
            via_squid: Some(squid_port),
            direct_egress: crate::config::DirectEgress::Allow,
        };
        let err = http_connect_tunnel(&spec, "api.github.com", 443)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("407"), "{err}");
        assert!(err.contains("the local Squid"), "name the hop: {err}");
        assert!(
            !err.contains("the relay presented"),
            "the relay presented nothing on this route: {err}"
        );
        // The remedy is still the same command, because the credential Squid presents is the
        // one in the store.
        assert!(err.contains("sgw proxy-credential"), "{err}");
    }

    /// #205: `check`'s probe on the via-Squid route walks the real path, so what it reports is
    /// Squid's own answer to a CONNECT.
    #[tokio::test]
    async fn the_squid_probe_reports_squids_status_line() {
        async fn squid(status: &'static str) -> String {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 1024];
                let n = s.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                assert!(
                    req.starts_with("CONNECT api.github.com:443 HTTP/1.1\r\n"),
                    "{req}"
                );
                assert!(
                    !req.contains("Proxy-Authorization"),
                    "nothing of the upstream's goes on this hop: {req}"
                );
                let _ = s
                    .write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes())
                    .await;
            });
            addr.to_string()
        }

        let open = probe_via_squid_at(&squid("200 Connection established").await, "api.github.com")
            .await
            .unwrap();
        assert_eq!(open.status, "200");
        assert_eq!(open.target, "api.github.com");

        // Squid could not reach its peer: a 5xx, and the status line is what says so.
        let peer = probe_via_squid_at(&squid("503 Service Unavailable").await, "api.github.com")
            .await
            .unwrap();
        assert_eq!(peer.status, "503");
        assert!(
            peer.status_line.contains("503 Service Unavailable"),
            "{peer:?}"
        );

        // Squid refused the request itself.
        let refused = probe_via_squid_at(&squid("403 Forbidden").await, "api.github.com")
            .await
            .unwrap();
        assert_eq!(refused.status, "403");

        // Nothing listening at all: an error, not a status.
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = dead.local_addr().unwrap().to_string();
        drop(dead);
        assert!(probe_via_squid_at(&addr, "api.github.com").await.is_err());
    }

    /// #205: the WARN is about the key exchange, which only a TLS 1.2 suite name spells out.
    #[test]
    fn rsa_key_exchange_is_read_off_the_cipher_name() {
        let brief = |c: &str| {
            vec![
                "Protocol version: TLSv1.2".to_string(),
                format!("Ciphersuite: {c}"),
            ]
        };
        // The reporter's proxy: no ECDHE in the name, so the key exchange is static RSA.
        assert!(is_rsa_key_exchange(&brief("AES256-GCM-SHA384")));
        assert!(is_rsa_key_exchange(&brief("AES128-SHA")));
        // Ephemeral, either spelling.
        assert!(!is_rsa_key_exchange(&brief("ECDHE-RSA-AES256-GCM-SHA384")));
        assert!(!is_rsa_key_exchange(&brief("DHE-RSA-AES256-GCM-SHA384")));
        // TLS 1.3 names no key exchange because every suite it defines is ephemeral.
        assert!(!is_rsa_key_exchange(&[
            "Protocol version: TLSv1.3".to_string(),
            "Ciphersuite: TLS_AES_256_GCM_SHA384".to_string(),
        ]));
        // No reading is not a finding: openssl missing, or the endpoint silent.
        assert!(!is_rsa_key_exchange(&[]));
        assert!(!is_rsa_key_exchange(&brief("")));
        assert!(!is_rsa_key_exchange(&[
            "Protocol version: TLSv1.2".to_string()
        ]));
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

    /// A listener that does the TLS handshake and then says nothing — the shape `probe_proxy`
    /// expects of a healthy `https://` proxy, minus the CONNECT it never sends.
    async fn tls_listener() -> (u16, tokio::task::JoinHandle<bool>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = test_tls::acceptor();
        let h = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let Ok(mut s) = acceptor.accept(tcp).await else {
                return false;
            };
            // Whatever the client does next: the probe must not send a CONNECT.
            let mut buf = vec![0u8; 64];
            let n = tokio::time::timeout(std::time::Duration::from_millis(200), s.read(&mut buf))
                .await
                .unwrap_or(Ok(0))
                .unwrap_or(0);
            n == 0
        });
        (port, h)
    }

    #[tokio::test]
    async fn the_probe_handshakes_with_an_https_proxy_and_reports_what_it_got() {
        let (port, served) = tls_listener().await;
        let r = probe_proxy_with("localhost", port, Some(test_tls::client_config()))
            .await
            .unwrap();
        assert!(r.tls);
        assert_eq!(r.endpoint, format!("localhost:{port}"));
        // rustls' defaults negotiate TLS 1.3 against a rustls server; whatever it picks, both
        // fields must be filled in, because that is what `check` prints.
        assert!(r.protocol.is_some(), "{r:?}");
        assert!(r.cipher.is_some(), "{r:?}");
        assert!(
            r.cipher.as_deref().unwrap().contains("TLS13"),
            "{:?}",
            r.cipher
        );
        assert!(
            served.await.unwrap(),
            "the probe must send no CONNECT after the handshake"
        );
    }

    #[tokio::test]
    async fn the_probe_of_a_plain_proxy_only_connects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let r = probe_proxy_with("127.0.0.1", port, None).await.unwrap();
        assert!(!r.tls);
        assert_eq!(r.protocol, None);
        assert_eq!(r.cipher, None);
    }

    #[tokio::test]
    async fn a_listener_that_closes_is_reported_as_an_error() {
        // A port nothing listens on: bind one, learn the number, drop it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let err = probe_proxy_with("127.0.0.1", port, None)
            .await
            .unwrap_err()
            .to_lowercase();
        assert!(err.contains("refused") || err.contains("connect"), "{err}");
    }

    #[tokio::test]
    async fn a_proxy_whose_certificate_is_not_trusted_fails_the_probe() {
        let (port, _served) = tls_listener().await;
        let empty = Arc::new(client_config_with_roots(rustls::RootCertStore::empty()).unwrap());
        let err = probe_proxy_with("localhost", port, Some(empty))
            .await
            .unwrap_err();
        assert!(err.contains("TLS to the proxy failed"), "{err}");
        // Not a HandshakeFailure, so no cipher-suite advice: that would be the wrong remedy.
        assert!(!err.contains("cipher suites"), "{err}");
    }

    /// A TLS server that refuses the client's suites cannot be built with rustls (it implements
    /// no RSA key exchange either), so the alert is synthesised — the hint is a pure function of
    /// the error text (#205).
    #[test]
    fn a_handshake_failure_gets_the_cipher_suite_diagnosis() {
        let msg = with_handshake_hint(
            "TLS to the proxy failed: received fatal alert: HandshakeFailure".into(),
        );
        // The prefix a test elsewhere asserts on must survive.
        assert!(msg.starts_with("TLS to the proxy failed"), "{msg}");
        assert!(
            msg.contains("accepted none of the relay's cipher suites"),
            "{msg}"
        );
        assert!(msg.contains("TLS 1.3 or ECDHE"), "{msg}");
        assert!(msg.contains("tls-dh="), "{msg}");
        assert!(msg.contains("sekimore-relay check"), "{msg}");
    }

    #[test]
    fn other_tls_errors_get_no_diagnosis() {
        for msg in [
            "TLS to the proxy failed: invalid peer certificate: UnknownIssuer",
            "proxy closed during CONNECT",
            "TLS to the proxy failed: received fatal alert: BadCertificate",
        ] {
            assert_eq!(with_handshake_hint(msg.to_string()), msg);
            assert!(!is_handshake_failure(msg), "{msg}");
        }
    }

    #[test]
    fn the_alert_is_recognised_however_it_is_spelled() {
        // rustls, a raw alert name, and what OpenSSL prints.
        assert!(is_handshake_failure(
            "received fatal alert: HandshakeFailure"
        ));
        assert!(is_handshake_failure("tls handshake_failure (alert 40)"));
        assert!(is_handshake_failure("ssl/tls alert handshake failure"));
        // Just outside the boundary: a TLS error that is *not* this alert must not be told to go
        // and change its cipher suites. That is a different fault with a different remedy.
        assert!(!is_handshake_failure("TLS handshake failed: timed out"));
        assert!(!is_handshake_failure("handshake timed out"));
        assert!(!is_handshake_failure(
            "invalid peer certificate: CertExpired"
        ));
    }

    #[tokio::test]
    async fn a_proxy_that_accepts_and_then_says_nothing_is_not_waited_on_for_ever() {
        // The shape `check` exists to catch: the TCP connection succeeds, and the handshake never
        // finishes. Without the bound this hangs instead of reporting.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let held = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            // Keep the connection open and send nothing.
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            drop(s);
        });
        let err = probe_proxy_within(
            "localhost",
            port,
            Some(test_tls::client_config()),
            std::time::Duration::from_millis(150),
        )
        .await
        .unwrap_err();
        assert!(err.contains("no answer from"), "{err}");
        assert!(err.contains(&format!("localhost:{port}")), "{err}");
        held.abort();
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
