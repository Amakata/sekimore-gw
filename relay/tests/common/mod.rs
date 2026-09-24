//! Shared fixtures for the integration tests: a temp state dir, a mock GitHub, API server startup, and HTTP helpers.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sekimore_relay::api::types::{ApiRequest, ApiResponse, BootstrapRequest, BootstrapResponse};
use sekimore_relay::api::{self, ApiContext, ResolvedBoard};
use sekimore_relay::audit::Audit;
use sekimore_relay::config::BootstrapMode;
use sekimore_relay::github::upstream_token::UpstreamTokenStore;
use sekimore_relay::github::GitHub;
use sekimore_relay::policy::{Mode, Project};
use sekimore_relay::ssh::authorized_keys::AuthorizedKeys;
use sekimore_relay::tokens::TokenStore;
use tokio::net::TcpListener;
use url::Url;

#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: serde_json::Value,
}

pub type Recorder = Arc<Mutex<Vec<Recorded>>>;

/// Mock GitHub API: records requests and returns canned JSON.
pub async fn mock_github() -> (Url, Recorder) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let rec: Recorder = Arc::new(Mutex::new(Vec::new()));
    let rec2 = rec.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let rec = rec2.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let rec = rec.clone();
                    async move {
                        let method = req.method().to_string();
                        let path = req
                            .uri()
                            .path_and_query()
                            .map(|p| p.to_string())
                            .unwrap_or_default();
                        let headers: Vec<(String, String)> = req
                            .headers()
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                            .collect();
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map(|c| c.to_bytes())
                            .unwrap_or_default();
                        let body: serde_json::Value =
                            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                        rec.lock().unwrap().push(Recorded {
                            method: method.clone(),
                            path: path.clone(),
                            headers,
                            body: body.clone(),
                        });
                        let (status, json) = canned(&method, &path, &body);
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(json.to_string())))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (Url::parse(&format!("http://{addr}/api/v3")).unwrap(), rec)
}

/// Percent-decode a path so the mock can match on the tag or ref the caller meant. Real GitHub
/// decodes the segment too; what matters for the traversal tests is the *raw* path recorded in the
/// recorder, which stays encoded.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v as char);
                i += 3;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// Commits the mock upstream claims to hold (#59: `GET /repos/{repo}/git/commits/{sha}`).
///
/// A set rather than a canned answer because the two cases a test needs are opposites: a sha the
/// upstream really has, and one it does not. Shas are unique per test, so one set is enough for
/// the whole binary.
static UPSTREAM_COMMITS: std::sync::LazyLock<Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

/// Tell the mock that the upstream holds this commit.
pub fn upstream_holds_commit(sha: &str) {
    UPSTREAM_COMMITS
        .lock()
        .unwrap()
        .insert(sha.to_ascii_lowercase());
}

fn canned(method: &str, path: &str, body: &serde_json::Value) -> (StatusCode, serde_json::Value) {
    let decoded = percent_decode(path);
    let p = decoded.split('?').next().unwrap_or(&decoded);
    // 0.2.29 (#59): the boundary lookup. 404 unless a test said the upstream has it, which is
    // what a real upstream answers for a sha it does not hold.
    if method == "GET" {
        if let Some((_, sha)) = p.split_once("/git/commits/") {
            if UPSTREAM_COMMITS
                .lock()
                .unwrap()
                .contains(&sha.to_ascii_lowercase())
            {
                return (StatusCode::OK, serde_json::json!({"sha": sha}));
            }
            return (
                StatusCode::NOT_FOUND,
                serde_json::json!({"message": "Not Found"}),
            );
        }
    }
    // 0.2.7: search. The answer deliberately mixes in a repository outside the project, so the
    // filter in the client is actually exercised rather than assumed.
    if method == "GET" && p == "/api/v3/search/issues" {
        return (
            StatusCode::OK,
            serde_json::json!({"total_count": 3, "items": [
                {"number": 7, "title": "in project, an issue", "state": "open",
                 "repository_url": "https://api.github.example/repos/LibOrg/awesome-lib",
                 "user": {"login": "alice"}, "html_url": "https://github.example/LibOrg/awesome-lib/issues/7",
                 "updated_at": "2026-09-17T00:00:00Z"},
                {"number": 9, "title": "in project, a pull request", "state": "open",
                 "pull_request": {"url": "…"},
                 "repository_url": "https://api.github.example/repos/LibOrg/awesome-lib",
                 "user": {"login": "bob"}, "html_url": "https://github.example/LibOrg/awesome-lib/pull/9",
                 "updated_at": "2026-09-17T01:00:00Z"},
                {"number": 1, "title": "OUTSIDE the project", "state": "open",
                 "repository_url": "https://api.github.example/repos/Other/Secret",
                 "user": {"login": "mallory"}, "html_url": "https://github.example/Other/Secret/issues/1",
                 "updated_at": "2026-09-17T02:00:00Z"}
            ]}),
        );
    }
    // #172: who the upstream token belongs to, so the relay can tell the agent's own comments
    // from a person's before editing or deleting one.
    if method == "GET" && p.ends_with("/user") {
        return (StatusCode::OK, serde_json::json!({"login": "agent-bot"}));
    }
    // #172: one comment, read before a write so its author can be checked. 4242 is the agent's
    // own; anything else belongs to a person and must be refused. Every comment sits on #8 (a
    // pull request), so an id named with another number must be refused too.
    if method == "GET" {
        if let Some((_, id)) = p.split_once("/comments/") {
            let login = if id == "4242" {
                "agent-bot"
            } else {
                "a-person"
            };
            return (
                StatusCode::OK,
                serde_json::json!({"id": id.parse::<u64>().unwrap_or(0),
                                   "user": {"login": login}, "body": "…",
                                   "issue_url": "https://github.example/api/repos/LibOrg/awesome-lib/issues/8",
                                   "pull_request_url": "https://github.example/api/repos/LibOrg/awesome-lib/pulls/8"}),
            );
        }
    }
    // #173: the files of a pull request, with their patches. logo.png has none (binary), which is
    // what the relay must say rather than render as empty.
    if method == "GET" && p.contains("/pulls/") && p.ends_with("/files") {
        return (
            StatusCode::OK,
            serde_json::json!([
                {"filename": "src/main.rs", "status": "modified", "additions": 2, "deletions": 1,
                 "patch": "@@ -38,4 +38,5 @@ fn check()\n ctx one\n-gone\n+added\n+more\n ctx two"},
                {"filename": "logo.png", "status": "modified", "additions": 0, "deletions": 0},
                {"filename": "README.md", "status": "added", "additions": 1, "deletions": 0,
                 "patch": "@@ -0,0 +1,1 @@\n+hello"}
            ]),
        );
    }
    // #158: the repository itself, read by `refs/pr/<branch>` to learn the base it opens against.
    // The path has exactly two segments after /repos/, which is what tells it apart from the
    // sub-resources below.
    if method == "GET" {
        if let Some(rest) = p.split_once("/repos/").map(|(_, r)| r) {
            if rest.split('/').count() == 2 {
                return (
                    StatusCode::OK,
                    serde_json::json!({"default_branch": "main"}),
                );
            }
        }
    }
    if method == "POST" && p.ends_with("/pulls") {
        if body.get("head").and_then(|h| h.as_str()) == Some("sekimore/main-dup0000") {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({"message": "Validation Failed", "errors": [{"message": "A pull request already exists"}]}),
            );
        }
        return (
            StatusCode::CREATED,
            serde_json::json!({"number": 42, "html_url": "https://github.example/pr/42", "node_id": "PR_42"}),
        );
    }
    // 0.2.8: reading a PR. The three comment sources are distinct paths, so they are matched
    // before the plain /pulls and /pulls/{n} below.
    if method == "GET" && p.ends_with("/reviews") {
        return (
            StatusCode::OK,
            serde_json::json!([
                // Out of order on purpose: the relay has to sort the three sources into one timeline.
                {"id": 901, "user": {"login": "alice"}, "state": "CHANGES_REQUESTED",
                 "body": "the null check is inverted", "submitted_at": "2026-09-17T10:00:00Z"},
                // No body and COMMENTED: only the envelope around its inline comments. It is kept
                // so they have somewhere to hang, and dropped again when it turns out to have none.
                {"id": 902, "user": {"login": "alice"}, "state": "COMMENTED",
                 "body": "", "submitted_at": "2026-09-17T10:05:00Z"}
            ]),
        );
    }
    if method == "GET" && p.ends_with("/pulls/7/comments") {
        return (
            StatusCode::OK,
            serde_json::json!([
                {"id": 2451, "user": {"login": "alice"}, "body": "this should be >=",
                 "created_at": "2026-09-17T10:05:00Z", "path": "src/main.rs", "line": 40,
                 "in_reply_to_id": 555, "pull_request_review_id": 902}
            ]),
        );
    }
    if method == "GET" && p.ends_with("/issues/7/comments") {
        return (
            StatusCode::OK,
            serde_json::json!([
                {"user": {"login": "bob"}, "body": "CI is red", "created_at": "2026-09-17T11:00:00Z"},
                {"user": {"login": "carol"}, "body": "first", "created_at": "2026-09-17T09:00:00Z"}
            ]),
        );
    }
    if method == "GET" && p.ends_with("/pulls/7") {
        return (
            StatusCode::OK,
            serde_json::json!({
                "number": 7, "title": "Add the thing", "body": "why it is needed",
                "state": "open", "draft": false, "merged": false,
                "head": {"ref": "sekimore/topic"}, "base": {"ref": "main"},
                "user": {"login": "alice"}, "html_url": "https://github.example/pr/7",
                "comments": 2, "review_comments": 1, "changed_files": 3,
                "additions": 40, "deletions": 5,
                "node_id": "PR_kwDO7"
            }),
        );
    }
    // 0.2.8: the issues endpoint serves pull requests too; #8 is one, and issue list must drop it.
    if method == "GET" && p.ends_with("/issues/8") {
        return (
            StatusCode::OK,
            serde_json::json!({
                "number": 8, "title": "Really a PR", "body": "", "state": "open",
                "user": {"login": "alice"}, "labels": [], "assignees": [],
                "html_url": "https://github.example/pr/8", "comments": 0,
                "node_id": "PR_kwDO8",
                "pull_request": {"url": "https://github.example/api/pulls/8"}
            }),
        );
    }
    // 0.2.28: Dependabot alerts (#132)
    if method == "GET" && p.contains("/dependabot/alerts/") {
        return (
            StatusCode::OK,
            serde_json::json!({
                "number": 7, "state": "open",
                "dependency": {"package": {"ecosystem": "pip", "name": "urllib3"},
                               "manifest_path": "uv.lock", "scope": "runtime"},
                "security_advisory": {"ghsa_id": "GHSA-xxxx-yyyy-zzzz", "cve_id": "CVE-2026-0001",
                                      "severity": "high", "summary": "urllib3 redirects leak headers"},
                "security_vulnerability": {"first_patched_version": {"identifier": "2.6.0"}},
                "html_url": "https://github.example/security/dependabot/7"
            }),
        );
    }
    if method == "GET" && p.contains("/dependabot/alerts") {
        return (
            StatusCode::OK,
            serde_json::json!([
                {"number": 7, "state": "open",
                 "dependency": {"package": {"ecosystem": "pip", "name": "urllib3"},
                                "manifest_path": "uv.lock", "scope": "runtime"},
                 "security_advisory": {"ghsa_id": "GHSA-xxxx-yyyy-zzzz", "cve_id": "CVE-2026-0001",
                                       "severity": "high", "summary": "urllib3 redirects leak headers"},
                 "security_vulnerability": {"first_patched_version": {"identifier": "2.6.0"}},
                 "html_url": "https://github.example/security/dependabot/7"},
                {"number": 3, "state": "open",
                 "dependency": {"package": {"ecosystem": "cargo", "name": "rustls"},
                                "manifest_path": "relay/Cargo.lock", "scope": null},
                 "security_advisory": {"ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": null,
                                       "severity": "low", "summary": "rustls panics on a malformed hello"},
                 "security_vulnerability": {"first_patched_version": null},
                 "html_url": "https://github.example/security/dependabot/3"}
            ]),
        );
    }
    if method == "PATCH" && p.contains("/dependabot/alerts/") {
        return (
            StatusCode::OK,
            serde_json::json!({"number": 7, "state": body.get("state").cloned().unwrap_or_default()}),
        );
    }
    if method == "GET" && p.contains("/issues/") && !p.ends_with("/comments") {
        return (
            StatusCode::OK,
            serde_json::json!({
                "number": 47, "title": "Crash on empty input", "body": "steps to reproduce",
                "state": "open", "user": {"login": "alice"},
                "labels": [{"name": "bug"}, {"name": "p1"}],
                "assignees": [{"login": "bob"}],
                "html_url": "https://github.example/issues/47", "comments": 3,
                "node_id": "I_kwDO47"
            }),
        );
    }
    if method == "GET" && p.ends_with("/issues") {
        return (
            StatusCode::OK,
            serde_json::json!([
                {"number": 47, "title": "Crash on empty input", "state": "open",
                 "user": {"login": "alice"}, "labels": [{"name": "bug"}], "comments": 3,
                 "html_url": "https://github.example/issues/47"},
                // A pull request served from the issues endpoint. issue list must not show it.
                {"number": 38, "title": "Add the thing", "state": "open",
                 "user": {"login": "alice"}, "labels": [], "comments": 0,
                 "html_url": "https://github.example/pr/38",
                 "pull_request": {"url": "https://github.example/api/pulls/38"}}
            ]),
        );
    }
    if method == "GET" && p.ends_with("/pulls") {
        return (
            StatusCode::OK,
            serde_json::json!([{"number": 41, "html_url": "https://github.example/pr/41", "node_id": "PR_41",
                               "title": "Older change", "state": "open", "draft": false,
                               "user": {"login": "alice"},
                               "head": {"ref": "sekimore/topic"}, "base": {"ref": "main"}}]),
        );
    }
    // 0.2.6: releases
    if method == "POST" && p.ends_with("/releases") {
        if body.get("tag_name").and_then(|t| t.as_str()) == Some("v9.9.9-missing") {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({"message": "Validation Failed", "errors": [{"code": "invalid", "field": "tag_name"}]}),
            );
        }
        let tag = body
            .get("tag_name")
            .and_then(|t| t.as_str())
            .unwrap_or("v0.0.0");
        return (
            StatusCode::CREATED,
            serde_json::json!({
                "id": 900,
                "tag_name": tag,
                "name": body.get("name").and_then(|n| n.as_str()).unwrap_or(tag),
                "html_url": format!("https://github.example/releases/{tag}"),
                "draft": body.get("draft").and_then(|d| d.as_bool()).unwrap_or(false),
                "prerelease": body.get("prerelease").and_then(|d| d.as_bool()).unwrap_or(false),
            }),
        );
    }
    if method == "GET" && p.contains("/releases/tags/") {
        if p.ends_with("/v0.0.0-none") {
            return (
                StatusCode::NOT_FOUND,
                serde_json::json!({"message": "Not Found"}),
            );
        }
        let tag = p.rsplit('/').next().unwrap_or("v1.0.0");
        // 0.2.9: one tag whose release is still a draft, so `release edit` has something to publish.
        let draft = tag == "v2.0.0-draft";
        let id = if draft { 903 } else { 901 };
        return (
            StatusCode::OK,
            serde_json::json!({"id": id, "tag_name": tag, "name": tag, "html_url": format!("https://github.example/releases/{tag}"), "draft": draft, "prerelease": false}),
        );
    }
    if method == "GET" && p.ends_with("/releases") {
        return (
            StatusCode::OK,
            serde_json::json!([
                {"id": 902, "tag_name": "v1.1.0", "name": "v1.1.0", "html_url": "https://github.example/releases/v1.1.0", "draft": false, "prerelease": false},
                {"id": 901, "tag_name": "v1.0.0", "name": "v1.0.0", "html_url": "https://github.example/releases/v1.0.0", "draft": true, "prerelease": false}
            ]),
        );
    }
    if method == "POST" && p.ends_with("/issues") {
        return (
            StatusCode::CREATED,
            serde_json::json!({"number": 7, "html_url": "https://github.example/issues/7", "node_id": "I_7"}),
        );
    }
    if p == "/api/v3/user" {
        return (StatusCode::OK, serde_json::json!({"login": "operator"}));
    }
    if p == "/api/v3/meta" {
        return (
            StatusCode::OK,
            serde_json::json!({"ssh_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"]}),
        );
    }
    if p == "/api/graphql" {
        // 0.2.7: the fields query asks for `fields(`; the items query does not.
        // 0.2.15: the items query now asks for `fieldValues(`, which must not be read as the
        // fields query — the two answers have different shapes.
        let query = body.get("query").and_then(|q| q.as_str()).unwrap_or("");
        // 0.2.21: resolving a declared board to its node id. Asked on the first Projects request
        // now rather than at start-up, so the mock has to answer it (#99).
        if query.contains("projectV2(number:$number){ id }") {
            let owner = if query.contains("organization(login:") {
                "organization"
            } else {
                "user"
            };
            return (
                StatusCode::OK,
                serde_json::json!({"data": {owner: {"projectV2": {"id": "PVT_board2"}}}}),
            );
        }
        let asks_for_fields = query.contains(" fields(first:");
        if asks_for_fields {
            return (
                StatusCode::OK,
                serde_json::json!({"data": {"node": {"title": "Board", "fields": {"nodes": [
                    {"id": "PVTF_status", "name": "Status", "dataType": "SINGLE_SELECT",
                     "options": [{"id": "OPT_todo", "name": "Todo"}, {"id": "OPT_done", "name": "Done"}]},
                    {"id": "PVTF_text", "name": "Notes", "dataType": "TEXT"}
                ]}}}}),
            );
        }
        return (
            StatusCode::OK,
            serde_json::json!({"data": {"addProjectV2ItemById": {"item": {"id": "PVTI_1"}}, "node": {"title": "Board", "items": {"nodes": [
                {"id": "PVTI_1", "type": "ISSUE",
                 "content": {"number": 7, "title": "in project, an issue"},
                 "fieldValues": {"nodes": [
                    // The built-in Title field repeats the title, and is dropped when rendering
                    {"__typename": "ProjectV2ItemFieldTextValue", "text": "in project, an issue", "field": {"name": "Title"}},
                    {"__typename": "ProjectV2ItemFieldSingleSelectValue", "name": "Todo", "field": {"name": "Status"}},
                    // A value type the query did not ask for: __typename alone, no field
                    {"__typename": "ProjectV2ItemFieldLabelValue"}
                 ]}}
            ]}}}}),
        );
    }
    // 0.2.9: merging with options, and deleting the head branch afterwards.
    if method == "PUT" && p.ends_with("/merge") {
        // A squash-only repository: exactly the case that made the old literal `{}` unusable.
        if p.contains("/pulls/405/")
            && body.get("merge_method").and_then(|m| m.as_str()) != Some("squash")
        {
            return (
                StatusCode::METHOD_NOT_ALLOWED,
                serde_json::json!({"message": "Merge commits are not allowed on this repository"}),
            );
        }
        return (
            StatusCode::OK,
            serde_json::json!({"merged": true, "sha": "deadbeef", "message": "Pull Request successfully merged"}),
        );
    }
    if method == "DELETE" && p.contains("/git/refs/heads/") {
        return (StatusCode::NO_CONTENT, serde_json::Value::Null);
    }
    // 0.2.9: reopening and editing. PATCH on a pull request or an issue answers the new state.
    if method == "PATCH" && (p.contains("/pulls/") || p.contains("/issues/")) {
        return (
            StatusCode::OK,
            serde_json::json!({
                "number": 42,
                "state": body.get("state").and_then(|v| v.as_str()).unwrap_or("open"),
                "html_url": "https://github.example/pr/42"
            }),
        );
    }
    // 0.2.9: removing a label, and removing assignees.
    if method == "DELETE" && p.contains("/labels/") {
        return (StatusCode::OK, serde_json::json!([]));
    }
    if method == "DELETE" && p.ends_with("/assignees") {
        return (
            StatusCode::OK,
            serde_json::json!({"number": 47, "assignees": []}),
        );
    }
    // 0.2.9: editing a release. `id` 903 is the draft the edit tests publish.
    if method == "PATCH" && p.contains("/releases/") {
        let id: u64 = p
            .rsplit('/')
            .next()
            .and_then(|x| x.parse().ok())
            .unwrap_or(0);
        return (
            StatusCode::OK,
            serde_json::json!({
                "id": id,
                "tag_name": "v2.0.0",
                "name": body.get("name").and_then(|n| n.as_str()).unwrap_or("v2.0.0"),
                "html_url": "https://github.example/releases/v2.0.0",
                "draft": body.get("draft").and_then(|d| d.as_bool()).unwrap_or(false),
                "prerelease": body.get("prerelease").and_then(|d| d.as_bool()).unwrap_or(false),
            }),
        );
    }
    // 0.2.9: re-running and cancelling a workflow run.
    if method == "POST"
        && (p.ends_with("/rerun") || p.ends_with("/rerun-failed-jobs") || p.ends_with("/cancel"))
    {
        return (StatusCode::CREATED, serde_json::json!({}));
    }
    if method == "POST" && p.ends_with("/requested_reviewers") {
        return (
            StatusCode::CREATED,
            serde_json::json!({"number": 42, "requested_reviewers": [{"login": "alice"}]}),
        );
    }
    (StatusCode::OK, serde_json::json!({}))
}

pub fn project_case_a(grants: &[&str]) -> Project {
    let mut p = Project::new("case-a")
        .with_repo("LibOrg/awesome-lib", Mode::ReadWrite, &["main"])
        .with_repo("VendorOrg/reference-impl", Mode::ReadOnly, &[]);
    for g in grants {
        p = p.grant(g);
    }
    p
}

/// 0.2.9: the same project, but with `delete_merged_branch` on for the read-write repo — the
/// operator switch `pr merge --delete-branch` needs.
pub fn project_case_a_deleting_merged_branches(grants: &[&str]) -> Project {
    let mut p = project_case_a(grants);
    p.repos[0].delete_merged_branch = true;
    p
}

pub struct ApiFixture {
    pub dir: tempfile::TempDir,
    pub addr: SocketAddr,
    pub ctx: Arc<ApiContext>,
    pub recorder: Recorder,
    pub token: String,
    pub audit_path: std::path::PathBuf,
    /// The upstream token store, so a test can give the relay a token after start-up — which is
    /// what unlocking the secret store looks like from the relay's side (#99).
    pub tokens: Arc<UpstreamTokenStore>,
}

/// The Projects v2 board the fixture allows by default, so tests that are not about board scoping
/// do not have to care. Use `start_api_with_boards` to vary it.
pub const TEST_BOARD: &str = "PVT_board";
/// Its number, the way `relay.project.boards` and the board's URL write it.
pub const TEST_BOARD_NUMBER: u32 = 2;

/// A resolved board, as start-up would have produced it from `relay.project.boards`.
pub fn board(number: u32, id: &str) -> ResolvedBoard {
    ResolvedBoard {
        id: id.to_string(),
        number,
        label: format!("users/tester/projects/{number}"),
    }
}

pub async fn start_api(
    project: Project,
    bootstrap: BootstrapMode,
    upstream_token: bool,
) -> ApiFixture {
    start_api_with_boards(
        project,
        bootstrap,
        upstream_token,
        vec![board(TEST_BOARD_NUMBER, TEST_BOARD)],
    )
    .await
}

pub async fn start_api_with_boards(
    project: Project,
    bootstrap: BootstrapMode,
    upstream_token: bool,
    project_boards: Vec<ResolvedBoard>,
) -> ApiFixture {
    start_api_full(project, bootstrap, upstream_token, project_boards, None).await
}

/// As `start_api_with_boards`, and `locked` hands back the store so a test can lock it. Used by
/// the #99 regression: resolving a board needs the upstream token, so a locked store has to be
/// something the request path recovers from rather than a state it caches forever.
pub async fn start_api_full(
    project: Project,
    bootstrap: BootstrapMode,
    upstream_token: bool,
    project_boards: Vec<ResolvedBoard>,
    declared: Option<Vec<sekimore_relay::config::BoardRef>>,
) -> ApiFixture {
    let dir = tempfile::tempdir().unwrap();
    let (api_base, recorder) = mock_github().await;
    let graphql = Url::parse(&format!(
        "{}/graphql",
        api_base.as_str().trim_end_matches("/api/v3").to_string() + "/api"
    ))
    .unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(Audit::new(Some(&audit_path), false).unwrap());
    // The token lives in the secret store (0.2.18). An unlocked in-memory one is the fixture's
    // equivalent of a gateway somebody has unlocked.
    let store = Arc::new(UpstreamTokenStore::in_memory(
        "upstream.test",
        &dir.path().join("upstream_token"),
    ));
    if upstream_token {
        store
            .save("upstream.test", "gho_test", "repo")
            .await
            .unwrap();
    }
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let gh = Arc::new(GitHub::new(
        api_base,
        graphql,
        http,
        store.clone(),
        audit.clone(),
    ));
    let tokens = TokenStore::new(&dir.path().join("tokens.json"));
    let (token, _) = tokens
        .issue(&project.name, Duration::from_secs(3600))
        .unwrap();
    let ctx = Arc::new(ApiContext {
        project,
        tokens,
        githubs: HashMap::from([("github.com".to_string(), gh)]),
        audit,
        keys: Arc::new(AuthorizedKeys::new(&dir.path().join("authorized_keys"), 8)),
        bootstrap,
        bootstrap_disabled_path: dir.path().join("bootstrap.disabled"),
        token_ttl: Duration::from_secs(3600),
        body_cap: 64 * 1024,
        rate: Mutex::new(VecDeque::new()),
        git_domain: "github.com".into(),
        upstream: "github.com".into(),
        git_domains: vec![],
        project_boards: match declared {
            Some(d) => sekimore_relay::api::ProjectBoards::new(d),
            None => sekimore_relay::api::ProjectBoards::already_resolved(project_boards),
        },
        signing: None,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(api::serve(ctx.clone(), listener));
    ApiFixture {
        dir,
        addr,
        ctx,
        recorder,
        token,
        audit_path,
        tokens: store,
    }
}

pub fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

pub async fn post(
    addr: SocketAddr,
    path: &str,
    token: Option<&str>,
    body: &ApiRequest,
) -> (u16, ApiResponse) {
    let mut req = http().post(format!("http://{addr}{path}")).json(body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let body: ApiResponse = resp.json().await.unwrap();
    (status, body)
}

pub async fn post_bootstrap(addr: SocketAddr, key: &str) -> (u16, BootstrapResponse) {
    let resp = http()
        .post(format!("http://{addr}/bootstrap"))
        .json(&BootstrapRequest {
            public_key: key.to_string(),
            label: Some("test".into()),
        })
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap())
}

pub fn gen_pubkey() -> String {
    use russh::keys::ssh_key::private::Ed25519Keypair;
    use russh::keys::PrivateKey;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    PrivateKey::from(Ed25519Keypair::from_seed(&seed))
        .public_key()
        .to_openssh()
        .unwrap()
}

pub fn recorded(rec: &Recorder) -> Vec<Recorded> {
    rec.lock().unwrap().clone()
}
