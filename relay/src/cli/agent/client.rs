//! The HTTP call to the relay.
//!
//! Its own module because it is the only part that knows about transport — the endpoint, the
//! token and the timeout. Everything else in `agent` deals in paths and `ApiRequest` values.

use anyhow::{anyhow, Context};

use crate::api::types::{ApiRequest, ApiResponse};

pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:8420";

pub struct AgentClient {
    endpoint: String,
    token: Option<String>,
    http: reqwest::Client,
}

impl AgentClient {
    pub fn from_env() -> anyhow::Result<Self> {
        let endpoint = std::env::var("SEKIMORE_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
        let token = std::env::var("SEKIMORE_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());
        Self::new(&endpoint, token)
    }

    pub fn new(endpoint: &str, token: Option<String>) -> anyhow::Result<Self> {
        // The relay sits inside the same isolation boundary, so proxy environment variables are ignored
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(60))
            .build()?;
        Ok(AgentClient {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            token,
            http,
        })
    }

    pub async fn call(&self, path: &str, req: &ApiRequest) -> anyhow::Result<ApiResponse> {
        let token = self.token.as_deref().ok_or_else(|| {
            anyhow!(
                "SEKIMORE_TOKEN is not set (source /etc/sekimore-agent/env or re-run agent-setup)"
            )
        })?;
        let resp = self
            .http
            .post(format!("{}{}", self.endpoint, path))
            .bearer_auth(token)
            .json(req)
            .send()
            .await
            .with_context(|| format!("cannot reach the gateway at {}", self.endpoint))?;
        let status = resp.status();
        let body = resp.bytes().await?;
        serde_json::from_slice::<ApiResponse>(&body)
            .map_err(|_| anyhow!("gateway returned HTTP {status} (unparseable body)"))
    }
}
