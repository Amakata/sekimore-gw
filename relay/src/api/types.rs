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
    /// 0.2.15: the board's number, the way `relay.project.boards` and the URL write it. An
    /// alternative to `project_id`, which the agent cannot look up on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub board: Option<u32>,
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
    /// 0.2.9: merge options. `method` is merge / squash / rebase; `delete_branch` removes the head
    /// branch after a merge that succeeded (the name comes from the upstream, never from here)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub delete_branch: bool,
    /// 0.2.9: `release edit` / `pr update`. Three-valued on purpose: absent leaves the field alone,
    /// which is what tells `release edit` whether the call actually flips draft to false
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_draft: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_prerelease: Option<bool>,
    /// 0.2.28: why a Dependabot alert is dismissed (`security dismiss --reason`); the comment
    /// travels in `body`
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// 0.2.9: `ci rerun --all` re-runs every job instead of only the failed ones
    #[serde(default, skip_serializing_if = "is_false")]
    pub all: bool,
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
    /// 0.2.29 (#59): the signing key the gateway offers through its filtered agent socket.
    /// Absent means there is none, and `agent-setup.sh` falls back to generating one
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<SigningBlock>,
}

/// 0.2.29 (#59): what the dev container needs in order to sign with the operator's key without
/// ever holding it — the socket to set `SSH_AUTH_SOCK` to, and the public half of the one key
/// behind it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SigningBlock {
    /// Path of the filtered agent socket, on the volume the gateway and dev share
    pub socket: String,
    pub fingerprint: String,
    /// The SSHSIG namespace the socket admits (`git`)
    pub namespace: String,
    /// `ssh-ed25519 AAAA… comment`, for `user.signingkey` and `allowed_signers`
    pub public_key: String,
    /// 0.2.29 (#59): the strictest `signing` any repository in this project asks for —
    /// `required` | `optional` | `off`. `agent-setup.sh` writes the guide's signing section only
    /// when it is `required`, so an agent is not told about a rule that does not apply to it
    #[serde(default)]
    pub mode: String,
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
