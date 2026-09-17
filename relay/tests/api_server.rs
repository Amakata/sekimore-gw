mod common;

use common::*;
use sekimore_relay::api::types::ApiRequest;
use sekimore_relay::config::BootstrapMode;

fn req(repo: &str) -> ApiRequest {
    ApiRequest {
        repo: repo.to_string(),
        ..Default::default()
    }
}

#[tokio::test]
async fn requires_token() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let (code, resp) = post(f.addr, "/pr/create", None, &req("LibOrg/awesome-lib")).await;
    assert_eq!(code, 401);
    assert!(!resp.ok);
    let (code, _) = post(
        f.addr,
        "/pr/create",
        Some("skm_bogus"),
        &req("LibOrg/awesome-lib"),
    )
    .await;
    assert_eq!(code, 401);
    assert!(
        recorded(&f.recorder).is_empty(),
        "nothing must reach upstream"
    );
}

#[tokio::test]
async fn denies_out_of_project_repo() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let mut r = req("Attacker/evil");
    r.head = "x".into();
    r.base = "main".into();
    r.title = "t".into();
    let (code, resp) = post(f.addr, "/pr/create", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    assert!(resp.error.unwrap().contains("not in project"));
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn denies_read_only_repo_and_disallowed_base() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let mut r = req("VendorOrg/reference-impl");
    r.head = "x".into();
    r.base = "main".into();
    r.title = "t".into();
    let (code, resp) = post(f.addr, "/pr/create", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    assert!(resp.error.unwrap().contains("read-only"));

    let mut r = req("LibOrg/awesome-lib");
    r.head = "x".into();
    r.base = "production".into();
    r.title = "t".into();
    let (_, resp) = post(f.addr, "/pr/create", Some(&f.token), &r).await;
    assert!(resp.error.unwrap().contains("not allowed"));
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn default_deny_never_reaches_upstream() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let cases: Vec<(&str, ApiRequest, &str)> = vec![
        (
            "/pr/comment",
            ApiRequest {
                number: 1,
                body: "hi".into(),
                ..req("LibOrg/awesome-lib")
            },
            "pr:comment",
        ),
        (
            "/issue/create",
            ApiRequest {
                title: "t".into(),
                ..req("LibOrg/awesome-lib")
            },
            "issue:create",
        ),
        (
            "/project/add-item",
            ApiRequest {
                project_id: "P".into(),
                content_id: "C".into(),
                ..req("LibOrg/awesome-lib")
            },
            "project:add_item",
        ),
        (
            "/pr/merge",
            ApiRequest {
                number: 1,
                ..req("LibOrg/awesome-lib")
            },
            "pr:merge",
        ),
    ];
    for (path, r, want) in cases {
        let (code, resp) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(code, 403, "{path}");
        assert!(!resp.ok);
        assert!(
            resp.error.as_deref().unwrap_or("").contains(want),
            "{path}: {:?}",
            resp.error
        );
    }
    assert!(
        recorded(&f.recorder).is_empty(),
        "policy denials must not reach upstream"
    );
}

#[tokio::test]
async fn rejects_other_project_token() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let (other, _) = f
        .ctx
        .tokens
        .issue("case-b", std::time::Duration::from_secs(60))
        .unwrap();
    let mut r = req("LibOrg/awesome-lib");
    r.head = "x".into();
    r.base = "main".into();
    r.title = "t".into();
    let (code, resp) = post(f.addr, "/pr/create", Some(&other), &r).await;
    assert_eq!(code, 403);
    assert!(resp.error.unwrap().contains("another project"));
}

#[tokio::test]
async fn whoami_lists_permissions_and_repos() {
    let f = start_api(
        project_case_a(&["pr:create", "issue:comment"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let (code, resp) = post(f.addr, "/whoami", Some(&f.token), &ApiRequest::default()).await;
    assert_eq!(code, 200);
    let msg = resp.message.unwrap();
    assert!(
        msg.contains("pr:create") && msg.contains("issue:comment"),
        "{msg}"
    );
    assert!(msg.contains("LibOrg/awesome-lib (read-write)"), "{msg}");
    assert!(
        msg.contains("VendorOrg/reference-impl (read-only)"),
        "{msg}"
    );
}

#[tokio::test]
async fn issue_labels_need_label_permission() {
    let f = start_api(project_case_a(&["issue:create"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        title: "t".into(),
        labels: vec!["bug".into()],
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/create", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    assert!(resp.error.unwrap().contains("issue:label"));
    assert!(recorded(&f.recorder).is_empty());
    // Without labels it goes through
    let r = ApiRequest {
        title: "t".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/create", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert_eq!(resp.number, Some(7));
}

#[tokio::test]
async fn pr_create_reaches_mock_with_required_headers() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        head: "sekimore/main-abc1234".into(),
        base: "main".into(),
        title: "t".into(),
        body: "b".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/create", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert!(resp.ok);
    assert_eq!(resp.number, Some(42));
    assert_eq!(resp.url.as_deref(), Some("https://github.example/pr/42"));
    let rec = recorded(&f.recorder);
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0].method, "POST");
    assert_eq!(rec[0].path, "/api/v3/repos/LibOrg/awesome-lib/pulls");
    let h = |name: &str| {
        rec[0]
            .headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    assert_eq!(h("authorization"), "Bearer gho_test");
    assert!(
        h("user-agent").starts_with("sekimore-relay/"),
        "{}",
        h("user-agent")
    );
    assert_eq!(h("x-github-api-version"), "2022-11-28");
    assert_eq!(rec[0].body["head"], "sekimore/main-abc1234");
    assert_eq!(rec[0].body["base"], "main");
}

#[tokio::test]
async fn missing_upstream_token_is_503_not_a_crash() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, false).await;
    let r = ApiRequest {
        head: "h".into(),
        base: "main".into(),
        title: "t".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/create", Some(&f.token), &r).await;
    assert_eq!(code, 503);
    assert!(resp.error.unwrap().contains("sekimore-relay login"));
}

#[tokio::test]
async fn bootstrap_registers_key_and_issues_token() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let key = gen_pubkey();
    let (code, resp) = post_bootstrap(f.addr, &key).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert!(resp.ok && resp.added);
    let token = resp.token.clone().unwrap();
    assert!(token.starts_with("skm_"));
    assert_eq!(resp.project.as_deref(), Some("case-a"));
    assert_eq!(resp.repos.len(), 2);
    assert_eq!(resp.git_domain.as_deref(), Some("github.com"));
    assert_eq!(resp.upstream.as_deref(), Some("github.com"));
    assert!(resp.fingerprint.unwrap().starts_with("SHA256:"));
    // The issued token works against the API
    let (code, _) = post(f.addr, "/whoami", Some(&token), &ApiRequest::default()).await;
    assert_eq!(code, 200);
    // Re-registering is idempotent
    let (code, resp2) = post_bootstrap(f.addr, &key).await;
    assert_eq!(code, 200);
    assert!(!resp2.added);
    assert_eq!(f.ctx.keys.count(), 1);
    // Malformed key
    let (code, resp3) = post_bootstrap(f.addr, "not a key").await;
    assert_eq!(code, 400);
    assert!(!resp3.ok);
}

#[tokio::test]
async fn bootstrap_manual_and_kill_switch() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Manual, true).await;
    let (code, resp) = post_bootstrap(f.addr, &gen_pubkey()).await;
    assert_eq!(code, 404);
    assert!(resp.error.unwrap().contains("manual"));

    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    std::fs::write(&f.ctx.bootstrap_disabled_path, "x").unwrap();
    let (code, resp) = post_bootstrap(f.addr, &gen_pubkey()).await;
    assert_eq!(code, 403);
    assert!(resp.error.unwrap().contains("disabled"));
}

#[tokio::test]
async fn audit_has_no_plaintext_token() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let (_, resp) = post_bootstrap(f.addr, &gen_pubkey()).await;
    let token = resp.token.unwrap();
    let _ = post(f.addr, "/whoami", Some(&token), &ApiRequest::default()).await;
    let _ = post(
        f.addr,
        "/pr/merge",
        Some(&token),
        &ApiRequest {
            number: 1,
            ..req("LibOrg/awesome-lib")
        },
    )
    .await;
    let _ = post(f.addr, "/whoami", Some("skm_bogus"), &ApiRequest::default()).await;
    let text = std::fs::read_to_string(&f.audit_path).unwrap();
    assert!(text.contains("\"event\":\"bootstrap_ok\""));
    assert!(text.contains("\"event\":\"api_error\""));
    assert!(text.contains("\"event\":\"token_denied\""));
    assert!(
        !text.contains(&token),
        "plaintext token leaked into audit log"
    );
    assert!(!text.contains(&f.token));
    let tokens_json = std::fs::read_to_string(f.dir.path().join("tokens.json")).unwrap();
    assert!(!tokens_json.contains(&token));
}

#[tokio::test]
async fn healthz_and_method_checks() {
    let f = start_api(project_case_a(&[]), BootstrapMode::Auto, true).await;
    let resp = http()
        .get(format!("http://{}/healthz", f.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let resp = http()
        .get(format!("http://{}/whoami", f.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 405);
    let resp = http()
        .post(format!("http://{}/nope", f.addr))
        .bearer_auth(&f.token)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}

// ---- releases (0.2.6) ----

#[tokio::test]
async fn release_create_needs_the_permission() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        tag: "v1.2.3".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/release/create", Some(&f.token), &r).await;
    assert_eq!(code, 403, "{:?}", resp.error);
    assert!(!resp.ok);
    assert!(
        recorded(&f.recorder).is_empty(),
        "a denied release must not reach upstream"
    );
}

#[tokio::test]
async fn release_create_asks_github_to_write_the_notes_by_default() {
    let f = start_api(
        project_case_a(&["release:create"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        tag: "v1.2.3".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/release/create", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert_eq!(
        resp.url.as_deref(),
        Some("https://github.example/releases/v1.2.3")
    );
    let rec = recorded(&f.recorder);
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0].path, "/api/v3/repos/LibOrg/awesome-lib/releases");
    assert_eq!(rec[0].body["tag_name"], "v1.2.3");
    assert_eq!(rec[0].body["generate_release_notes"], true);
    // The tag is the title when none is given, so a release is never untitled.
    assert_eq!(rec[0].body["name"], "v1.2.3");
    assert_eq!(rec[0].body["draft"], false);
    assert_eq!(rec[0].body["prerelease"], false);
}

#[tokio::test]
async fn release_create_keeps_an_explicit_body_and_title() {
    let f = start_api(
        project_case_a(&["release:create"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        tag: "v1.2.3".into(),
        title: "Big one".into(),
        body: "handwritten".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/release/create", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let rec = recorded(&f.recorder);
    assert_eq!(rec[0].body["name"], "Big one");
    assert_eq!(rec[0].body["body"], "handwritten");
    // A body of one's own means no generated notes unless they were asked for.
    assert_eq!(rec[0].body["generate_release_notes"], false);
}

#[tokio::test]
async fn release_create_can_combine_a_body_with_generated_notes() {
    let f = start_api(
        project_case_a(&["release:create"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        tag: "v1.2.3".into(),
        body: "intro".into(),
        generate_notes: true,
        draft: true,
        prerelease: true,
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/release/create", Some(&f.token), &r).await;
    assert_eq!(code, 200);
    let rec = recorded(&f.recorder);
    assert_eq!(rec[0].body["body"], "intro");
    assert_eq!(rec[0].body["generate_release_notes"], true);
    assert_eq!(rec[0].body["draft"], true);
    assert_eq!(rec[0].body["prerelease"], true);
}

#[tokio::test]
async fn release_create_reports_a_missing_tag_instead_of_crashing() {
    let f = start_api(
        project_case_a(&["release:create"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        tag: "v9.9.9-missing".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/release/create", Some(&f.token), &r).await;
    assert!(code >= 400, "unpushed tag must fail, got {code}");
    assert!(!resp.ok);
}

#[tokio::test]
async fn release_view_and_list_need_only_read() {
    let f = start_api(project_case_a(&["release:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        tag: "v1.0.0".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/release/view", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert_eq!(
        resp.url.as_deref(),
        Some("https://github.example/releases/v1.0.0")
    );

    let (code, resp) = post(
        f.addr,
        "/release/list",
        Some(&f.token),
        &req("LibOrg/awesome-lib"),
    )
    .await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let msg = resp.message.unwrap_or_default();
    assert!(msg.contains("v1.1.0") && msg.contains("v1.0.0"), "{msg}");
    assert!(msg.contains("[draft]"), "a draft should be marked: {msg}");

    // read does not grant create
    let r = ApiRequest {
        tag: "v2.0.0".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/release/create", Some(&f.token), &r).await;
    assert_eq!(code, 403);
}

#[tokio::test]
async fn release_view_says_so_when_the_tag_has_none() {
    let f = start_api(project_case_a(&["release:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        tag: "v0.0.0-none".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/release/view", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert!(resp.ok);
    assert!(resp.url.is_none());
    assert!(
        resp.message.unwrap_or_default().contains("no release"),
        "should say there is none"
    );
}

#[tokio::test]
async fn a_release_outside_the_project_is_refused() {
    let f = start_api(
        project_case_a(&["release:create"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        tag: "v1.2.3".into(),
        ..req("Other/elsewhere")
    };
    let (code, resp) = post(f.addr, "/release/create", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    assert!(!resp.ok);
    assert!(recorded(&f.recorder).is_empty());
}

// ---- path traversal (0.2.7) ----

/// A tag or ref is agent-supplied text that lands in the request path. The URL parser resolves
/// `..` when it builds the request, so an unescaped `../` would walk out of the project's repo and
/// reach another one with the operator's token. Both must stay inside `/repos/<repo>/`.
#[tokio::test]
async fn an_agent_cannot_escape_its_repository_through_a_tag() {
    let f = start_api(
        project_case_a(&["release:read", "ci:read"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    for evil in [
        "../../../Other/Secret/releases",
        "..%2f..%2fOther/Secret",
        "v1.0.0/../../../Other/Secret",
    ] {
        let r = ApiRequest {
            tag: evil.to_string(),
            ..req("LibOrg/awesome-lib")
        };
        let (_, _) = post(f.addr, "/release/view", Some(&f.token), &r).await;
        for call in recorded(&f.recorder) {
            assert!(
                call.path.starts_with("/api/v3/repos/LibOrg/awesome-lib/"),
                "tag {evil:?} reached {} — outside the project",
                call.path
            );
        }
    }
}

#[tokio::test]
async fn an_agent_cannot_escape_its_repository_through_a_ci_ref() {
    let f = start_api(project_case_a(&["ci:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        git_ref: "../../../Other/Secret/commits/main".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (_, _) = post(f.addr, "/ci/runs", Some(&f.token), &r).await;
    for call in recorded(&f.recorder) {
        assert!(
            call.path.starts_with("/api/v3/repos/LibOrg/awesome-lib/"),
            "ref reached {} — outside the project",
            call.path
        );
    }
}

// ---- reviewer requests and project fields (0.2.7) ----

#[tokio::test]
async fn requesting_a_review_is_its_own_permission() {
    // pr:review submits an opinion; pr:request_review notifies a human. Granting one must not
    // grant the other.
    let f = start_api(project_case_a(&["pr:review"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 42,
        reviewers: vec!["alice".into()],
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/request-review", Some(&f.token), &r).await;
    assert_eq!(code, 403, "{:?}", resp.error);
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn requesting_a_review_sends_people_and_teams() {
    let f = start_api(
        project_case_a(&["pr:request_review"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        number: 42,
        reviewers: vec!["alice".into(), "bob".into()],
        team_reviewers: vec!["platform".into()],
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/request-review", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let rec = recorded(&f.recorder);
    assert_eq!(rec.len(), 1);
    assert_eq!(
        rec[0].path,
        "/api/v3/repos/LibOrg/awesome-lib/pulls/42/requested_reviewers"
    );
    assert_eq!(rec[0].body["reviewers"][0], "alice");
    assert_eq!(rec[0].body["team_reviewers"][0], "platform");
    let msg = resp.message.unwrap_or_default();
    assert!(msg.contains("alice") && msg.contains("@platform"), "{msg}");
}

#[tokio::test]
async fn requesting_a_review_needs_somebody_to_ask() {
    let f = start_api(
        project_case_a(&["pr:request_review"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        number: 42,
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/pr/request-review", Some(&f.token), &r).await;
    assert_eq!(code, 400);
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn project_fields_returns_the_option_ids_update_item_needs() {
    let f = start_api(project_case_a(&["project:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        project_id: "PVT_board".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/project/fields", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let raw = resp.raw.expect("fields payload");
    let nodes = raw["data"]["node"]["fields"]["nodes"]
        .as_array()
        .expect("field nodes");
    assert_eq!(nodes[0]["id"], "PVTF_status");
    // The option id is the part a human previously had to supply by hand
    assert_eq!(nodes[0]["options"][0]["id"], "OPT_todo");
}

#[tokio::test]
async fn project_fields_needs_project_read() {
    let f = start_api(
        project_case_a(&["project:add_item"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        project_id: "PVT_board".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/project/fields", Some(&f.token), &r).await;
    assert_eq!(code, 403);
}

// ---- project board scoping (0.2.7) ----

/// Every Projects endpoint takes a node id, and a node id says nothing about who owns it. Without
/// a declared list, `project:add_item` on one repo would reach any board the upstream token can
/// see. Each endpoint is listed here so a new one cannot quietly skip the check.
fn project_endpoints() -> Vec<(&'static str, ApiRequest)> {
    let base = |id: &str| ApiRequest {
        repo: "LibOrg/awesome-lib".into(),
        project_id: id.into(),
        ..Default::default()
    };
    vec![
        (
            "/project/add-item",
            ApiRequest {
                content_id: "I_1".into(),
                ..base("PVT_elsewhere")
            },
        ),
        (
            "/project/update-item",
            ApiRequest {
                item_id: "PVTI_1".into(),
                field_id: "PVTF_1".into(),
                value: Some(serde_json::json!("x")),
                ..base("PVT_elsewhere")
            },
        ),
        ("/project/list", base("PVT_elsewhere")),
        ("/project/fields", base("PVT_elsewhere")),
    ]
}

#[tokio::test]
async fn a_board_outside_the_project_is_refused_everywhere() {
    let f = start_api(
        project_case_a(&["project:read", "project:add_item", "project:update_item"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    for (path, r) in project_endpoints() {
        let (code, resp) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(code, 403, "{path} allowed a board outside the project");
        assert!(
            resp.error
                .unwrap_or_default()
                .contains("not in this project"),
            "{path} should say why"
        );
    }
    assert!(
        recorded(&f.recorder).is_empty(),
        "nothing may reach upstream for a board outside the project"
    );
}

#[tokio::test]
async fn without_a_declared_board_every_project_call_is_refused() {
    // Default deny: a project id is unbounded, so an empty list refuses rather than allows.
    let f = start_api_with_boards(
        project_case_a(&["project:read", "project:add_item", "project:update_item"]),
        BootstrapMode::Auto,
        true,
        vec![],
    )
    .await;
    for (path, mut r) in project_endpoints() {
        r.project_id = TEST_BOARD.into();
        let (code, resp) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(code, 403, "{path} should refuse with no board declared");
        assert!(
            resp.error
                .unwrap_or_default()
                .contains("relay.project.boards"),
            "{path} should point at the setting to add"
        );
    }
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn a_declared_board_still_works() {
    let f = start_api(project_case_a(&["project:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        project_id: TEST_BOARD.into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/project/list", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
}

#[tokio::test]
async fn the_permission_is_checked_before_the_board() {
    // An agent without the permission should hear about the permission, not about boards.
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        project_id: "PVT_elsewhere".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/project/list", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    let e = resp.error.unwrap_or_default();
    assert!(e.contains("project:read"), "{e}");
}
