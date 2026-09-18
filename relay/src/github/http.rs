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
        let mut proxy =
            reqwest::Proxy::all(&px.url).with_context(|| format!("proxy url {}", px.url))?;
        if let Some(u) = &px.username {
            proxy = proxy.basic_auth(u, px.password.as_deref().unwrap_or(""));
        }
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
