//! HTTP API requests and responses (shared with the agent CLI). gh compatibility is not a goal.

use serde::{Deserialize, Serialize};
use serde_json::Value;

fn is_zero(n: &u64) -> bool {
    *n == 0
}
fn is_zero32(n: &u32) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ApiRequest {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub repo: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub number: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub body: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub base: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub head: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assignees: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub event: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub project_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub item_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub field_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "is_zero32")]
    pub first: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub job_id: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub run_id: u64,
    /// Tag name / branch name / SHA (ci runs)
    #[serde(default, rename = "ref", skip_serializing_if = "String::is_empty")]
    pub git_ref: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub window: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<u64>,
    /// 0.2.6: releases. `tag` names the release; `generate_notes` asks GitHub to write the body
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub generate_notes: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub draft: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub prerelease: bool,
    /// 0.2.7: people asked to review a pull request, and teams asked the same
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reviewers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub team_reviewers: Vec<String>,
    /// 0.2.7: a search query, in GitHub's search syntax. The relay appends the project's
    /// repositories to it and filters the results again
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub query: String,
    /// 0.2.8: filters for `issue list` / `pr list`. `state` is open / closed / all; the list
    /// reuses `labels`, `base` and `first`
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub state: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub assignee: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ApiResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ApiResponse {
    pub fn ok() -> Self {
        ApiResponse {
            ok: true,
            ..Default::default()
        }
    }
    pub fn error(msg: impl Into<String>) -> Self {
        ApiResponse {
            ok: false,
            error: Some(msg.into()),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BootstrapRequest {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BootstrapResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub added: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<String>,
    /// The domain DNS points at the relay (the agent uses this name in known_hosts and its ssh config)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_domain: Option<String>,
    /// Upstream host (for display)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    /// 0.2.0: every git domain the relay serves (with each domain's SSH port). The first is the default upstream
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub git_domains: Vec<GitDomain>,
}

/// 0.2.0: one git domain the relay serves (agent-setup uses it to write `Host <domain>` and `Port`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct GitDomain {
    pub domain: String,
    pub ssh_port: u16,
    #[serde(default)]
    pub upstream: String,
    #[serde(default)]
    pub default: bool,
}
