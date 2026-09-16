//! Our own implementation of the OAuth 2.0 Device Authorization Grant.
//!
//! It does not go through the `gh` CLI, so no token is left behind in gh's keychain or config files.
//! A human approves it in a browser; no organization approval request is involved.

use std::time::Duration;

use anyhow::{anyhow, Context};
use serde::Deserialize;
use url::Url;

use super::http::{read_limited, truncate};

pub struct DeviceFlow {
    base: Url,
    client_id: String,
    scopes: Vec<String>,
    http: reqwest::Client,
    min_interval: Duration,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub expires_in: u64,
    #[serde(default)]
    pub interval: u64,
}

#[derive(Debug, Deserialize, Default)]
struct TokenResp {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    error_description: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Poll {
    Token { access_token: String, scope: String },
    Pending,
    SlowDown,
    Expired,
    Denied,
}

impl DeviceFlow {
    /// `upstream` is `github.com` or a GHES host; the login URL is that host's `/login/...`.
    pub fn new(
        upstream: &str,
        client_id: &str,
        scopes: &[&str],
        http: reqwest::Client,
    ) -> anyhow::Result<Self> {
        let host = if upstream == "api.github.com" {
            "github.com"
        } else {
            upstream
        };
        let base = Url::parse(&format!("https://{host}")).context("device flow base url")?;
        Ok(DeviceFlow {
            base,
            client_id: client_id.to_string(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            http,
            min_interval: Duration::from_secs(5),
        })
    }

    /// Override the base URL, for tests.
    pub fn with_base(mut self, base: Url) -> Self {
        self.base = base;
        self
    }

    pub fn with_min_interval(mut self, d: Duration) -> Self {
        self.min_interval = d;
        self
    }

    pub async fn request_code(&self) -> anyhow::Result<DeviceCode> {
        let url = self.base.join("/login/device/code")?;
        let body = self
            .post_form(
                url,
                &[
                    ("client_id", self.client_id.as_str()),
                    ("scope", &self.scopes.join(" ")),
                ],
            )
            .await?;
        let dc: DeviceCode = serde_json::from_slice(&body)
            .with_context(|| format!("parse device code response: {}", truncate(&body)))?;
        if dc.device_code.is_empty() {
            return Err(anyhow!("no device_code in response: {}", truncate(&body)));
        }
        Ok(dc)
    }

    pub async fn poll_once(&self, device_code: &str) -> anyhow::Result<Poll> {
        let url = self.base.join("/login/oauth/access_token")?;
        let body = self
            .post_form(
                url,
                &[
                    ("client_id", self.client_id.as_str()),
                    ("device_code", device_code),
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ],
            )
            .await?;
        let tok: TokenResp = serde_json::from_slice(&body)
            .with_context(|| format!("parse token response: {}", truncate(&body)))?;
        Ok(match tok.error.as_str() {
            "" if !tok.access_token.is_empty() => Poll::Token {
                access_token: tok.access_token,
                scope: tok.scope,
            },
            "" => {
                return Err(anyhow!(
                    "token response without access_token: {}",
                    truncate(&body)
                ))
            }
            "authorization_pending" => Poll::Pending,
            "slow_down" => Poll::SlowDown,
            "expired_token" => Poll::Expired,
            "access_denied" => Poll::Denied,
            other => {
                return Err(anyhow!(
                    "device flow error: {other} ({})",
                    tok.error_description
                ))
            }
        })
    }

    /// Run the device flow and return the access token and its scopes. `prompt(user_code, url)` walks the human through it.
    pub async fn authenticate(
        &self,
        prompt: impl Fn(&str, &str),
    ) -> anyhow::Result<(String, String)> {
        let dc = self.request_code().await?;
        prompt(&dc.user_code, &dc.verification_uri);
        let mut interval = Duration::from_secs(dc.interval).max(self.min_interval);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(dc.expires_in.max(1));
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(interval).await;
            match self.poll_once(&dc.device_code).await? {
                Poll::Token {
                    access_token,
                    scope,
                } => return Ok((access_token, scope)),
                Poll::Pending => {}
                Poll::SlowDown => interval += Duration::from_secs(5).min(self.min_interval),
                Poll::Expired => return Err(anyhow!("device code expired; retry authentication")),
                Poll::Denied => return Err(anyhow!("authorization denied by user")),
            }
        }
        Err(anyhow!("device flow timed out"))
    }

    async fn post_form(&self, url: Url, form: &[(&str, &str)]) -> anyhow::Result<Vec<u8>> {
        let resp = self
            .http
            .post(url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .form(form)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        let body = read_limited(resp, 1 << 20).await?;
        if status.as_u16() >= 400 && body.is_empty() {
            return Err(anyhow!("{url} returned {status}"));
        }
        Ok(body)
    }
}
