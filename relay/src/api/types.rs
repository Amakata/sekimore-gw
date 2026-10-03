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
    /// #339: the dev container user's uid, for `/signing/owner`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub job_id: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub run_id: u64,
    /// 0.2.33 (#165): the line comment `pr reply` answers
    #[serde(default, skip_serializing_if = "is_zero")]
    pub comment_id: u64,
    /// 0.2.33 (#167): the line comments a review carries
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<ReviewComment>,
    /// 0.2.33 (#169): open the pull request as a draft, or which way `pr draft` / `pr ready`
    /// moves it. Its own field: `draft` above belongs to a release, and a pull request being a
    /// draft has nothing to do with a release being one
    #[serde(default, skip_serializing_if = "is_false")]
    pub pr_draft: bool,
    /// 0.2.34 (#172): the comment named by id is on a line of the diff, not in the conversation.
    /// GitHub serves the two from different endpoints, and an id from one does not exist in the
    /// other, so the caller has to say which
    #[serde(default, skip_serializing_if = "is_false")]
    pub inline: bool,
    /// 0.2.59: the review conversation `pr resolve` settles, as a GraphQL node id. `pr comments`
    /// prints it beside the line comment it belongs to; it is the only place to get one, because
    /// REST never carries it
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub thread_id: String,
    /// 0.2.59: open the conversation again instead of settling it. A flag on the same request
    /// rather than a second one, the way `pr_draft` carries which way `pr draft` / `pr ready` move
    #[serde(default, skip_serializing_if = "is_false")]
    pub unresolve: bool,
    /// #345: the task-list item `issue check` / `pr check` ticks: text it contains, the heading it
    /// sits under, the item it is nested in, or the id `issue tasks` printed. And which way
    #[serde(default, rename = "match", skip_serializing_if = "String::is_empty")]
    pub task_match: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub under: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub parent: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub task_id: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub uncheck: bool,
    /// 0.2.33 (#168): the workflow file `ci dispatch` starts
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub workflow: String,
    /// 0.2.33 (#168): its inputs
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub inputs: std::collections::BTreeMap<String, String>,
    /// Tag name / branch name / SHA (ci runs)
    #[serde(default, rename = "ref", skip_serializing_if = "String::is_empty")]
    pub git_ref: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub window: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<u64>,
    /// 0.2.35 (#173): which file of a pull request `pr diff` reads. Without one it takes the
    /// first, so a caller holding only the number still gets a diff to read
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub file_path: String,
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
    /// 0.2.9: `ci rerun --all` re-runs every job instead of only the failed ones. #344: and
    /// `project list --all` follows every page
    #[serde(default, skip_serializing_if = "is_false")]
    pub all: bool,
    /// #344: where `project list` continues — the cursor the previous page ended at
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub after: String,
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

/// 0.2.33 (#167): one note a review leaves on a line of the diff.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReviewComment {
    pub path: String,
    pub line: u64,
    /// 0.2.59: the first line of a range, when the note covers several lines; `line` is then its
    /// last. Absent for a note on a single line — an absent key is not the same as a null one to
    /// GitHub, so it is left out rather than sent empty
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u64>,
    pub body: String,
}

impl ReviewComment {
    /// `path:line:body` — the form `--comment` takes. Split from the left twice and no further,
    /// so a body may contain colons, which prose about code invariably does.
    ///
    /// The line field is either `N` or `START-END`, the second a note that covers the whole
    /// range. A range whose ends are equal is one line, and GitHub refuses a range that says so,
    /// so it becomes a plain single-line note rather than an error the caller can do nothing with.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (path, rest) = s
            .split_once(':')
            .ok_or_else(|| format!("expected path:line:body, got {s:?}"))?;
        let (line, body) = rest
            .split_once(':')
            .ok_or_else(|| format!("expected path:line:body, got {s:?}"))?;
        if path.is_empty() {
            return Err(format!("no path in {s:?}"));
        }
        let num = |n: &str| -> Result<u64, String> {
            let v: u64 = n
                .parse()
                .map_err(|_| format!("line {n:?} is not a number, in {s:?}"))?;
            if v == 0 {
                return Err(format!("line 0 does not exist, in {s:?}"));
            }
            Ok(v)
        };
        let (start_line, line) = match line.split_once('-') {
            Some((start, end)) => {
                let (start, end) = (num(start)?, num(end)?);
                if start > end {
                    return Err(format!(
                        "line range {line:?} ends before it starts, in {s:?}"
                    ));
                }
                // One line is not a range: GitHub refuses start_line == line
                (if start == end { None } else { Some(start) }, end)
            }
            None => (None, num(line)?),
        };
        if body.trim().is_empty() {
            return Err(format!("no comment body in {s:?}"));
        }
        Ok(ReviewComment {
            path: path.to_string(),
            line,
            start_line,
            body: body.to_string(),
        })
    }
}

#[cfg(test)]
mod review_comment_parsing {
    use super::ReviewComment;

    #[test]
    fn a_body_may_contain_colons() {
        let c =
            ReviewComment::parse("src/main.rs:40:see RFC 3339: the offset is required").unwrap();
        assert_eq!(c.path, "src/main.rs");
        assert_eq!(c.line, 40);
        assert_eq!(c.body, "see RFC 3339: the offset is required");
    }

    #[test]
    fn a_windows_looking_path_is_not_special() {
        // The first colon wins, so a path is whatever precedes it; this is the form the guide
        // documents, and a path with a colon in it cannot be expressed. Said, not silently wrong.
        let c = ReviewComment::parse("a/b.rs:1:x").unwrap();
        assert_eq!((c.path.as_str(), c.line), ("a/b.rs", 1));
    }

    #[test]
    fn one_line_carries_no_range() {
        let c = ReviewComment::parse("src/main.rs:212:this should be >=").unwrap();
        assert_eq!(c.line, 212);
        assert_eq!(c.start_line, None, "a single line is not a range");
    }

    #[test]
    fn a_range_is_its_first_and_last_line() {
        let c = ReviewComment::parse("src/main.rs:207-212:the whole match is unreachable").unwrap();
        assert_eq!(c.path, "src/main.rs");
        assert_eq!(c.start_line, Some(207), "start_line is the range's first");
        assert_eq!(c.line, 212, "line is the range's last");
    }

    #[test]
    fn a_body_may_contain_colons_with_a_range_too() {
        let c = ReviewComment::parse("src/main.rs:207-212:see RFC 3339: required").unwrap();
        assert_eq!((c.start_line, c.line), (Some(207), 212));
        assert_eq!(c.body, "see RFC 3339: required");
    }

    #[test]
    fn a_range_of_one_line_is_one_line() {
        // GitHub refuses start_line == line. The caller said a range covering a single line,
        // which is what a single-line note is, so it becomes one instead of an error.
        let c = ReviewComment::parse("src/main.rs:40-40:x").unwrap();
        assert_eq!((c.start_line, c.line), (None, 40));
    }

    #[test]
    fn what_is_refused() {
        for bad in [
            "src/main.rs",           // no line, no body
            "src/main.rs:40",        // no body
            "src/main.rs:forty:x",   // line is not a number
            "src/main.rs:0:x",       // there is no line 0
            ":40:x",                 // no path
            "src/main.rs:40:   ",    // a body of spaces says nothing
            "src/main.rs:212-207:x", // a range that ends before it starts
            "src/main.rs:0-212:x",   // there is no line 0, at either end
            "src/main.rs:207-0:x",
            "src/main.rs:207-x:x", // the end is not a number
            "src/main.rs:x-212:x", // nor is the start
            "src/main.rs:207-:x",  // no end at all
            "src/main.rs:-212:x",  // no start at all
        ] {
            assert!(
                ReviewComment::parse(bad).is_err(),
                "{bad:?} should be refused"
            );
        }
    }
}
