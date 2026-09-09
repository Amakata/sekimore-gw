//! 上流 HTTPS クライアントの組み立て。
//!
//! `reqwest` は既定で rustls を使い **OS の証明書ストアを見ない**。企業 MITM プロキシ配下では TLS 検証で落ちる。
//! そのため: native roots（`rustls-tls-native-roots`）+ `SSL_CERT_FILE` + `relay.ca_file` の PEM を明示的に信頼し、
//! `config.yml` の `proxy.upstream_proxy` があればそれを使う。

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

    // SSL_CERT_FILE（rustls-native-certs も見るが、明示しておく）と relay.ca_file
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

/// レスポンス本文を上限付きで読む（巨大応答でメモリを食わない）。
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

/// エラーメッセージ用に本文を短く切る。
pub fn truncate(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    if s.len() > 200 {
        format!("{}...", &s[..200])
    } else {
        s.into_owned()
    }
}
