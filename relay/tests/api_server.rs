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
        head: "sekimore/topic".into(),
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

// ---- reading pull requests and issues (0.2.8) ----

#[tokio::test]
async fn reading_a_pull_request_needs_pr_read() {
    // issue:read is a different key and must not open pr view / comments / list.
    let f = start_api(
        project_case_a(&["pr:create", "issue:read"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    for path in ["/pr/view", "/pr/comments", "/pr/list"] {
        let r = ApiRequest {
            number: 7,
            ..req("LibOrg/awesome-lib")
        };
        let (code, resp) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(code, 403, "{path}: {:?}", resp.error);
        assert!(resp.error.unwrap_or_default().contains("pr:read"));
    }
    assert!(
        recorded(&f.recorder).is_empty(),
        "a denied read must not reach upstream"
    );
}

#[tokio::test]
async fn reading_an_issue_needs_issue_read_which_create_does_not_give() {
    // issue:create writes; it says nothing about being allowed to read the tracker.
    let f = start_api(
        project_case_a(&["issue:create", "issue:comment", "pr:read"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    for path in ["/issue/view", "/issue/comments", "/issue/list"] {
        let r = ApiRequest {
            number: 47,
            ..req("LibOrg/awesome-lib")
        };
        let (code, resp) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(code, 403, "{path}: {:?}", resp.error);
        assert!(
            resp.error.unwrap_or_default().contains("issue:read"),
            "{path} should name the permission it wants"
        );
    }
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn pr_view_reports_the_branches_and_the_counts() {
    let f = start_api(project_case_a(&["pr:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/view", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let raw = resp.raw.expect("raw PR");
    assert_eq!(raw["title"], "Add the thing");
    assert_eq!(raw["head"], "sekimore/topic");
    assert_eq!(raw["base"], "main");
    assert_eq!(raw["author"], "alice");
    assert_eq!(raw["changed_files"], 3);
    assert_eq!(raw["additions"], 40);
    assert_eq!(raw["review_comments"], 1);
    let msg = resp.message.unwrap_or_default();
    assert!(msg.contains("main ← sekimore/topic"), "{msg}");
    assert!(
        msg.contains("why it is needed"),
        "the body belongs in it: {msg}"
    );
    // One read, and it stays inside the project's repository.
    let rec = recorded(&f.recorder);
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0].path, "/api/v3/repos/LibOrg/awesome-lib/pulls/7");
}

#[tokio::test]
async fn pr_comments_merges_the_three_sources_in_order() {
    let f = start_api(project_case_a(&["pr:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/comments", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let raw = resp.raw.expect("raw comments");
    let items = raw.as_array().expect("a list");

    // carol 09:00 (comment), alice 10:00 (review), alice 10:05 (inline), bob 11:00 (comment).
    // The empty COMMENTED review at 10:05 is only a container and is left out.
    let got: Vec<(&str, &str)> = items
        .iter()
        .map(|i| {
            (
                i["kind"].as_str().unwrap_or(""),
                i["author"].as_str().unwrap_or(""),
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![
            ("comment", "carol"),
            ("review", "alice"),
            ("inline", "alice"),
            ("comment", "bob"),
        ],
        "the three sources must come back as one timeline"
    );

    // The review carries its state, the inline comment its place in the diff.
    assert_eq!(items[1]["state"], "CHANGES_REQUESTED");
    assert_eq!(items[2]["path"], "src/main.rs");
    assert_eq!(items[2]["line"], 40);
    assert_eq!(items[2]["in_reply_to_id"], 555);
    assert!(
        items[0].get("state").is_none(),
        "a plain comment has no state"
    );

    // All three endpoints were asked, and none of them left the project's repository.
    let paths: Vec<String> = recorded(&f.recorder)
        .iter()
        .map(|c| c.path.clone())
        .collect();
    assert_eq!(paths.len(), 3, "{paths:?}");
    for p in &paths {
        assert!(
            p.starts_with("/api/v3/repos/LibOrg/awesome-lib/"),
            "{p} is outside the project"
        );
    }

    let msg = resp.message.unwrap_or_default();
    assert!(msg.contains("[review CHANGES_REQUESTED]"), "{msg}");
    assert!(msg.contains("src/main.rs:40"), "{msg}");
    assert!(msg.contains("CI is red"), "{msg}");
}

#[tokio::test]
async fn an_empty_commented_review_is_not_listed() {
    // GitHub wraps line comments in a review with no body. It says nothing, so it is noise.
    let f = start_api(project_case_a(&["pr:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        ..req("LibOrg/awesome-lib")
    };
    let (_, resp) = post(f.addr, "/pr/comments", Some(&f.token), &r).await;
    let raw = resp.raw.expect("raw comments");
    let reviews = raw
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["kind"] == "review")
        .count();
    assert_eq!(reviews, 1, "only the review that actually said something");
}

#[tokio::test]
async fn issue_view_says_when_it_is_really_a_pull_request() {
    // The issues endpoint serves PRs too. Returning one silently as an issue would mislead.
    let f = start_api(project_case_a(&["issue:read"]), BootstrapMode::Auto, true).await;

    let r = ApiRequest {
        number: 47,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/view", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let raw = resp.raw.expect("raw issue");
    assert_eq!(raw["title"], "Crash on empty input");
    assert_eq!(raw["labels"][0], "bug");
    assert_eq!(raw["assignees"][0], "bob");
    assert_eq!(raw["is_pull_request"], false);
    assert!(!resp.message.unwrap_or_default().contains("pr view"));

    let r = ApiRequest {
        number: 8,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/view", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let raw = resp.raw.expect("raw issue");
    assert_eq!(raw["is_pull_request"], true, "#8 is a pull request");
    let msg = resp.message.unwrap_or_default();
    assert!(msg.contains("pull request"), "{msg}");
    assert!(
        msg.contains("pr view"),
        "it should point at the right command: {msg}"
    );
}

#[tokio::test]
async fn issue_list_drops_the_pull_requests_github_mixes_in() {
    let f = start_api(project_case_a(&["issue:read"]), BootstrapMode::Auto, true).await;
    let (code, resp) = post(
        f.addr,
        "/issue/list",
        Some(&f.token),
        &req("LibOrg/awesome-lib"),
    )
    .await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let raw = resp.raw.expect("raw issues");
    let items = raw.as_array().expect("a list");
    assert_eq!(
        items.len(),
        1,
        "the pull request must be dropped: {items:?}"
    );
    assert_eq!(items[0]["number"], 47);
    let msg = resp.message.unwrap_or_default();
    assert!(
        msg.contains("#47 [open] Crash on empty input (alice, 3 comments)"),
        "{msg}"
    );
    assert!(!msg.contains("#38"), "a PR belongs to pr list: {msg}");
}

#[tokio::test]
async fn issue_list_passes_its_filters_as_query_values() {
    let f = start_api(project_case_a(&["issue:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        state: "all".into(),
        labels: vec!["bug".into(), "p1".into()],
        assignee: "bob".into(),
        first: 5,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/list", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let path = &recorded(&f.recorder)[0].path;
    assert!(
        path.starts_with("/api/v3/repos/LibOrg/awesome-lib/issues?"),
        "{path}"
    );
    assert!(path.contains("state=all"), "{path}");
    assert!(path.contains("per_page=5"), "{path}");
    assert!(
        path.contains("labels=bug%2Cp1"),
        "a comma is escaped in a query value: {path}"
    );
    assert!(path.contains("assignee=bob"), "{path}");
}

#[tokio::test]
async fn a_bad_state_is_the_agents_mistake_not_an_upstream_call() {
    let f = start_api(
        project_case_a(&["issue:read", "pr:read"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    for path in ["/issue/list", "/pr/list"] {
        let r = ApiRequest {
            state: "banana".into(),
            ..req("LibOrg/awesome-lib")
        };
        let (code, resp) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(code, 400, "{path}: {:?}", resp.error);
        assert!(resp
            .error
            .unwrap_or_default()
            .contains("open, closed or all"));
    }
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn pr_list_shows_the_branches_and_honours_base() {
    let f = start_api(project_case_a(&["pr:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        base: "main".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/list", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let msg = resp.message.unwrap_or_default();
    assert!(
        msg.contains("#41 [open] Older change (alice, main ← sekimore/topic)"),
        "{msg}"
    );
    let path = &recorded(&f.recorder)[0].path;
    assert!(
        path.contains("state=open") && path.contains("base=main"),
        "{path}"
    );
}

#[tokio::test]
async fn a_limit_is_clamped_rather_than_passed_on() {
    let f = start_api(project_case_a(&["issue:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        first: 9999,
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/issue/list", Some(&f.token), &r).await;
    assert_eq!(code, 200);
    let path = &recorded(&f.recorder)[0].path;
    assert!(
        path.contains("per_page=100"),
        "the limit tops out at 100: {path}"
    );
}

#[tokio::test]
async fn reading_a_repository_outside_the_project_is_refused() {
    let f = start_api(
        project_case_a(&["pr:read", "issue:read"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    for path in [
        "/pr/view",
        "/pr/comments",
        "/pr/list",
        "/issue/view",
        "/issue/comments",
        "/issue/list",
    ] {
        let r = ApiRequest {
            number: 7,
            ..req("Other/elsewhere")
        };
        let (code, resp) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(code, 403, "{path}: {:?}", resp.error);
        assert!(resp.error.unwrap_or_default().contains("not in project"));
    }
    assert!(
        recorded(&f.recorder).is_empty(),
        "nothing outside the project may reach upstream"
    );
}

#[tokio::test]
async fn a_read_only_repository_can_still_be_read() {
    // Reading is not a write, so read-only mode is no obstacle.
    let f = start_api(
        project_case_a(&["pr:read", "issue:read"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        number: 7,
        ..req("VendorOrg/reference-impl")
    };
    let (code, resp) = post(f.addr, "/pr/view", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let (code, resp) = post(
        f.addr,
        "/issue/list",
        Some(&f.token),
        &req("VendorOrg/reference-impl"),
    )
    .await;
    assert_eq!(code, 200, "{:?}", resp.error);
}

#[tokio::test]
async fn pr_comments_renders_one_entry_per_block() {
    let f = start_api(project_case_a(&["pr:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        ..req("LibOrg/awesome-lib")
    };
    let (_, resp) = post(f.addr, "/pr/comments", Some(&f.token), &r).await;
    let msg = resp.message.unwrap_or_default();
    // Date, author, then what kind of entry it is; the body indented underneath.
    assert_eq!(
        msg,
        "2026-09-17 carol  [comment]\n  first\n\
         2026-09-17 alice  [review CHANGES_REQUESTED]\n  the null check is inverted\n\
         2026-09-17 alice  src/main.rs:40\n  this should be >=\n\
         2026-09-17 bob    [comment]\n  CI is red"
    );
}

// ---- search (0.2.7) ----

#[tokio::test]
async fn search_needs_its_own_permission() {
    // Reading one issue and searching across repositories are different authorities: a search is
    // the only operation not addressed to a repository.
    let f = start_api(
        project_case_a(&["issue:read", "pr:read"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        query: "is:open".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/search/issues", Some(&f.token), &r).await;
    assert_eq!(code, 403, "{:?}", resp.error);
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn a_search_is_scoped_to_the_project_in_the_query() {
    let f = start_api(project_case_a(&["search:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        query: "is:open label:bug".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/search/issues", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let rec = recorded(&f.recorder);
    assert_eq!(rec.len(), 1);
    // Every repository of the project is named in the query the relay sends
    let sent = rec[0].path.clone();
    for repo in [
        "repo%3ALibOrg/awesome-lib",
        "repo%3AVendorOrg/reference-impl",
    ] {
        assert!(sent.contains(repo), "{repo} missing from {sent}");
    }
    assert!(
        sent.contains("is%3Aopen"),
        "the caller's own query survives"
    );
}

#[tokio::test]
async fn a_result_from_outside_the_project_is_dropped() {
    // The mock answers with one repository the project does not own. Scoping the query is a
    // request; dropping what comes back anyway is the guarantee.
    let f = start_api(project_case_a(&["search:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        query: "is:open".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/search/issues", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);

    let msg = resp.message.clone().unwrap_or_default();
    assert!(!msg.contains("Other/Secret"), "leaked: {msg}");
    assert!(!msg.contains("OUTSIDE"), "leaked: {msg}");
    assert!(msg.contains("LibOrg/awesome-lib#7"), "{msg}");

    let hits = resp.raw.expect("hits");
    let arr = hits.as_array().expect("an array of hits");
    assert_eq!(arr.len(), 2, "only the two in-project hits: {arr:?}");
    for h in arr {
        assert_eq!(h["repository"], "LibOrg/awesome-lib");
    }
    // The search API mixes issues and pull requests; the caller has to be able to tell them apart
    assert_eq!(arr[0]["kind"], "issue");
    assert_eq!(arr[1]["kind"], "pr");
}

#[tokio::test]
async fn a_repo_qualifier_of_the_agents_own_cannot_widen_the_search() {
    // GitHub honours a repo: the caller writes, so the filter on the way back is what holds.
    let f = start_api(project_case_a(&["search:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        query: "is:open repo:Other/Secret".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/search/issues", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let arr = resp.raw.expect("hits");
    for h in arr.as_array().expect("array") {
        assert_eq!(
            h["repository"], "LibOrg/awesome-lib",
            "a hand-written repo: must not widen the answer"
        );
    }
}

#[tokio::test]
async fn a_search_needs_a_query() {
    let f = start_api(project_case_a(&["search:read"]), BootstrapMode::Auto, true).await;
    let (code, _) = post(
        f.addr,
        "/search/issues",
        Some(&f.token),
        &req("LibOrg/awesome-lib"),
    )
    .await;
    assert_eq!(code, 400);
    assert!(recorded(&f.recorder).is_empty());
}

// ---- finishing what the agent can already start (0.2.9) ----

#[tokio::test]
async fn merge_sends_the_method_and_the_commit_message() {
    let f = start_api(project_case_a(&["pr:merge"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 42,
        method: "squash".into(),
        title: "Squashed title".into(),
        body: "the whole story".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/merge", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let rec = recorded(&f.recorder);
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0].method, "PUT");
    assert_eq!(
        rec[0].path,
        "/api/v3/repos/LibOrg/awesome-lib/pulls/42/merge"
    );
    assert_eq!(rec[0].body["merge_method"], "squash");
    assert_eq!(rec[0].body["commit_title"], "Squashed title");
    assert_eq!(rec[0].body["commit_message"], "the whole story");
}

#[tokio::test]
async fn a_squash_only_repository_is_no_longer_a_dead_end() {
    // PR 405 in the mock rejects anything but a squash, the way a squash-only repository does.
    let f = start_api(project_case_a(&["pr:merge"]), BootstrapMode::Auto, true).await;
    let plain = ApiRequest {
        number: 405,
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/pr/merge", Some(&f.token), &plain).await;
    assert_ne!(
        code, 200,
        "the default merge commit should still be refused"
    );

    let squash = ApiRequest {
        number: 405,
        method: "squash".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/merge", Some(&f.token), &squash).await;
    assert_eq!(code, 200, "{:?}", resp.error);
}

#[tokio::test]
async fn merge_without_options_still_sends_an_empty_body() {
    // The old behaviour has to survive: no option given means no key in the request.
    let f = start_api(project_case_a(&["pr:merge"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 42,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/merge", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let rec = recorded(&f.recorder);
    assert_eq!(rec.len(), 1);
    assert!(
        rec[0].body.get("merge_method").is_none(),
        "{:?}",
        rec[0].body
    );
    assert!(rec[0].body.get("commit_title").is_none());
    assert!(rec[0].body.get("commit_message").is_none());
}

#[tokio::test]
async fn an_unknown_merge_method_is_rejected_before_upstream() {
    let f = start_api(project_case_a(&["pr:merge"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 42,
        method: "fast-forward".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/merge", Some(&f.token), &r).await;
    assert_eq!(code, 400, "{:?}", resp.error);
    assert!(
        recorded(&f.recorder).is_empty(),
        "nothing should reach upstream"
    );
}

#[tokio::test]
async fn deleting_the_branch_uses_the_name_the_upstream_gave() {
    // The caller never names the branch: it comes from the pull request, so this cannot become
    // "delete any ref". PR 7 in the mock has head sekimore/topic.
    let f = start_api(
        project_case_a_deleting_merged_branches(&["pr:merge"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        number: 7,
        delete_branch: true,
        // A branch name in a field the handler must ignore for this purpose.
        head: "main".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/merge", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let rec = recorded(&f.recorder);
    let deletes: Vec<_> = rec.iter().filter(|c| c.method == "DELETE").collect();
    assert_eq!(deletes.len(), 1);
    assert_eq!(
        deletes[0].path,
        "/api/v3/repos/LibOrg/awesome-lib/git/refs/heads/sekimore%2Ftopic"
    );
    assert!(resp.message.unwrap_or_default().contains("sekimore/topic"));
}

#[tokio::test]
async fn the_branch_survives_a_merge_that_did_not_happen() {
    // The mock refuses a plain merge commit on 405; nothing may be deleted after that.
    let f = start_api(
        project_case_a_deleting_merged_branches(&["pr:merge"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        number: 405,
        delete_branch: true,
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/pr/merge", Some(&f.token), &r).await;
    assert_ne!(code, 200);
    assert!(
        !recorded(&f.recorder).iter().any(|c| c.method == "DELETE"),
        "a failed merge must not delete the branch"
    );
}

#[tokio::test]
async fn merging_still_needs_pr_merge() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 42,
        method: "squash".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/pr/merge", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn reopening_rides_on_the_permission_that_closes() {
    for (path, grant) in [("/pr/reopen", "pr:close"), ("/issue/reopen", "issue:close")] {
        let f = start_api(project_case_a(&[grant]), BootstrapMode::Auto, true).await;
        let r = ApiRequest {
            number: 42,
            ..req("LibOrg/awesome-lib")
        };
        let (code, resp) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(code, 200, "{path}: {:?}", resp.error);
        let rec = recorded(&f.recorder);
        assert_eq!(rec.len(), 1, "{path}");
        assert_eq!(rec[0].method, "PATCH", "{path}");
        assert_eq!(rec[0].body["state"], "open", "{path}");
    }
}

#[tokio::test]
async fn reopening_is_refused_without_the_close_permission() {
    for (path, other) in [
        ("/pr/reopen", "pr:create"),
        ("/issue/reopen", "issue:create"),
    ] {
        let f = start_api(project_case_a(&[other]), BootstrapMode::Auto, true).await;
        let r = ApiRequest {
            number: 42,
            ..req("LibOrg/awesome-lib")
        };
        let (code, _) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(code, 403, "{path}");
        assert!(recorded(&f.recorder).is_empty(), "{path}");
    }
}

#[tokio::test]
async fn removing_a_label_and_an_assignee_is_the_permission_that_adds_them() {
    let f = start_api(
        project_case_a(&["issue:label", "issue:assign"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        number: 47,
        labels: vec!["bug".into(), "p1".into()],
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/unlabel", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);

    let r = ApiRequest {
        number: 47,
        assignees: vec!["bob".into()],
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/unassign", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);

    let rec = recorded(&f.recorder);
    // GitHub removes one label per request, so two names are two calls.
    let paths: Vec<&str> = rec.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            "/api/v3/repos/LibOrg/awesome-lib/issues/47/labels/bug",
            "/api/v3/repos/LibOrg/awesome-lib/issues/47/labels/p1",
            "/api/v3/repos/LibOrg/awesome-lib/issues/47/assignees",
        ]
    );
    assert!(rec.iter().all(|c| c.method == "DELETE"));
    assert_eq!(rec[2].body["assignees"][0], "bob");
}

#[tokio::test]
async fn removing_a_label_needs_issue_label() {
    let f = start_api(project_case_a(&["issue:create"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 47,
        labels: vec!["bug".into()],
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/issue/unlabel", Some(&f.token), &r).await;
    assert_eq!(code, 403);

    let r = ApiRequest {
        number: 47,
        assignees: vec!["bob".into()],
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/issue/unassign", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn a_label_name_cannot_escape_the_repository_path() {
    // The label goes into the PATH, so it needs path_segment and not url_escape: `/` and `.` have
    // to be encoded or the URL parser resolves `..` and walks out of /repos/<owner>/<repo>/.
    let f = start_api(project_case_a(&["issue:label"]), BootstrapMode::Auto, true).await;
    for evil in [
        "../../../Other/Secret/issues/1/labels/x",
        "..%2f..%2fOther/Secret",
        "bug/../../../../Other/Secret",
        "../../../../user",
    ] {
        let r = ApiRequest {
            number: 47,
            labels: vec![evil.to_string()],
            ..req("LibOrg/awesome-lib")
        };
        let (_, _) = post(f.addr, "/issue/unlabel", Some(&f.token), &r).await;
        for call in recorded(&f.recorder) {
            assert!(
                call.path
                    .starts_with("/api/v3/repos/LibOrg/awesome-lib/issues/47/labels/"),
                "label {evil:?} reached {} — outside the project",
                call.path
            );
        }
    }
    assert!(
        !recorded(&f.recorder).is_empty(),
        "the calls should have been made, just contained"
    );
}

#[tokio::test]
async fn updating_a_pull_request_rides_on_pr_create() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 42,
        title: "A better title".into(),
        body: "a better body".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/update", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let rec = recorded(&f.recorder);
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0].method, "PATCH");
    assert_eq!(rec[0].path, "/api/v3/repos/LibOrg/awesome-lib/pulls/42");
    assert_eq!(rec[0].body["title"], "A better title");
    assert_eq!(rec[0].body["body"], "a better body");
    // Nothing was said about the base, so nothing is sent about it.
    assert!(rec[0].body.get("base").is_none());
}

#[tokio::test]
async fn updating_a_pull_request_needs_pr_create() {
    let f = start_api(project_case_a(&["pr:comment"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 42,
        title: "A better title".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/pr/update", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn a_pull_request_cannot_be_retargeted_at_a_forbidden_base() {
    // LibOrg/awesome-lib allows only `main`, the same rule pr create is held to. Retargeting an
    // existing PR must not be the way around it.
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 42,
        base: "release".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/update", Some(&f.token), &r).await;
    assert_eq!(code, 403, "{:?}", resp.error);
    assert!(recorded(&f.recorder).is_empty());

    // The allowed base still goes through, and reaches upstream.
    let ok = ApiRequest {
        number: 42,
        base: "main".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/update", Some(&f.token), &ok).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let rec = recorded(&f.recorder);
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0].body["base"], "main");
}

#[tokio::test]
async fn pr_update_needs_something_to_change() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 42,
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/pr/update", Some(&f.token), &r).await;
    assert_eq!(code, 400);
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn editing_a_release_that_stays_a_draft_is_release_create() {
    // v2.0.0-draft is a draft in the mock. Editing its notes without publishing needs no more than
    // the permission that made it.
    let f = start_api(
        project_case_a(&["release:create"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        tag: "v2.0.0-draft".into(),
        body: "rewritten notes".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/release/edit", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let rec = recorded(&f.recorder);
    // A lookup to learn the draft state, then the edit itself.
    assert_eq!(rec.len(), 2);
    assert_eq!(rec[1].method, "PATCH");
    assert_eq!(rec[1].path, "/api/v3/repos/LibOrg/awesome-lib/releases/903");
    assert_eq!(rec[1].body["body"], "rewritten notes");
    assert!(rec[1].body.get("draft").is_none());
    assert!(resp.message.unwrap_or_default().starts_with("updated"));
}

#[tokio::test]
async fn publishing_a_draft_needs_release_publish() {
    // release:create made the draft; it must not also be what takes it out of draft, or --draft
    // would stop meaning anything.
    let f = start_api(
        project_case_a(&["release:create"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        tag: "v2.0.0-draft".into(),
        set_draft: Some(false),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/release/edit", Some(&f.token), &r).await;
    assert_eq!(code, 403, "{:?}", resp.error);
    // The lookup happened (it is what tells us this publishes); the edit did not.
    assert!(
        !recorded(&f.recorder).iter().any(|c| c.method == "PATCH"),
        "nothing should have been written"
    );

    let f = start_api(
        project_case_a(&["release:create", "release:publish"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let (code, resp) = post(f.addr, "/release/edit", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let rec = recorded(&f.recorder);
    let patch = rec.iter().find(|c| c.method == "PATCH").expect("the edit");
    assert_eq!(patch.body["draft"], false);
    assert!(resp.message.unwrap_or_default().starts_with("published"));
}

#[tokio::test]
async fn release_publish_is_only_demanded_when_the_draft_really_flips() {
    // v1.0.0 is already published in the mock. Saying --draft false about it changes nothing, so it
    // is an edit, not a publish, and release:create is enough.
    let f = start_api(
        project_case_a(&["release:create"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        tag: "v1.0.0".into(),
        set_draft: Some(false),
        title: "renamed".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/release/edit", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);

    // Turning a published release back into a draft is also not a publish.
    let back = ApiRequest {
        tag: "v1.0.0".into(),
        set_draft: Some(true),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/release/edit", Some(&f.token), &back).await;
    assert_eq!(code, 200, "{:?}", resp.error);
}

#[tokio::test]
async fn editing_a_release_needs_release_create_at_the_very_least() {
    // release:read can look at a release; it cannot change one.
    let f = start_api(project_case_a(&["release:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        tag: "v1.0.0".into(),
        title: "renamed".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/release/edit", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn editing_a_release_that_does_not_exist_says_so() {
    let f = start_api(
        project_case_a(&["release:create"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        tag: "v0.0.0-none".into(),
        title: "renamed".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/release/edit", Some(&f.token), &r).await;
    assert_eq!(code, 400);
    assert!(resp.error.unwrap_or_default().contains("v0.0.0-none"));
}

#[tokio::test]
async fn an_agent_cannot_escape_its_repository_through_a_release_edit_tag() {
    let f = start_api(
        project_case_a(&["release:create"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        tag: "../../../Other/Secret/releases/1".into(),
        title: "renamed".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (_, _) = post(f.addr, "/release/edit", Some(&f.token), &r).await;
    for call in recorded(&f.recorder) {
        assert!(
            call.path.starts_with("/api/v3/repos/LibOrg/awesome-lib/"),
            "tag reached {} — outside the project",
            call.path
        );
    }
}

#[tokio::test]
async fn re_running_ci_is_its_own_permission() {
    // Reading a log and spending Actions minutes with the repository's secrets are not the same
    // authority, so ci:read must not carry ci:rerun.
    let f = start_api(project_case_a(&["ci:read"]), BootstrapMode::Auto, true).await;
    for path in ["/ci/rerun", "/ci/cancel"] {
        let r = ApiRequest {
            run_id: 1234,
            ..req("LibOrg/awesome-lib")
        };
        let (code, _) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(code, 403, "{path}");
    }
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn ci_rerun_picks_the_failed_jobs_unless_asked_for_all() {
    let f = start_api(project_case_a(&["ci:rerun"]), BootstrapMode::Auto, true).await;
    let failed = ApiRequest {
        run_id: 1234,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/ci/rerun", Some(&f.token), &failed).await;
    assert_eq!(code, 200, "{:?}", resp.error);

    let all = ApiRequest {
        run_id: 1234,
        all: true,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/ci/rerun", Some(&f.token), &all).await;
    assert_eq!(code, 200, "{:?}", resp.error);

    let cancel = ApiRequest {
        run_id: 1234,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/ci/cancel", Some(&f.token), &cancel).await;
    assert_eq!(code, 200, "{:?}", resp.error);

    let rec = recorded(&f.recorder);
    let paths: Vec<&str> = rec.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            "/api/v3/repos/LibOrg/awesome-lib/actions/runs/1234/rerun-failed-jobs",
            "/api/v3/repos/LibOrg/awesome-lib/actions/runs/1234/rerun",
            "/api/v3/repos/LibOrg/awesome-lib/actions/runs/1234/cancel",
        ]
    );
}

#[tokio::test]
async fn ci_rerun_needs_a_run_id() {
    let f = start_api(project_case_a(&["ci:rerun"]), BootstrapMode::Auto, true).await;
    let r = req("LibOrg/awesome-lib");
    let (code, _) = post(f.addr, "/ci/rerun", Some(&f.token), &r).await;
    assert_eq!(code, 400);
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn the_new_operations_all_refuse_a_repository_outside_the_project() {
    let f = start_api(
        project_case_a(&[
            "pr:merge",
            "pr:close",
            "pr:create",
            "issue:close",
            "issue:label",
            "issue:assign",
            "release:create",
            "release:publish",
            "ci:rerun",
        ]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let cases: Vec<(&str, ApiRequest)> = vec![
        (
            "/pr/merge",
            ApiRequest {
                number: 1,
                ..req("Other/Secret")
            },
        ),
        (
            "/pr/reopen",
            ApiRequest {
                number: 1,
                ..req("Other/Secret")
            },
        ),
        (
            "/pr/update",
            ApiRequest {
                number: 1,
                title: "x".into(),
                ..req("Other/Secret")
            },
        ),
        (
            "/issue/reopen",
            ApiRequest {
                number: 1,
                ..req("Other/Secret")
            },
        ),
        (
            "/issue/unlabel",
            ApiRequest {
                number: 1,
                labels: vec!["bug".into()],
                ..req("Other/Secret")
            },
        ),
        (
            "/issue/unassign",
            ApiRequest {
                number: 1,
                assignees: vec!["bob".into()],
                ..req("Other/Secret")
            },
        ),
        (
            "/release/edit",
            ApiRequest {
                tag: "v1.0.0".into(),
                title: "x".into(),
                ..req("Other/Secret")
            },
        ),
        (
            "/ci/rerun",
            ApiRequest {
                run_id: 1,
                ..req("Other/Secret")
            },
        ),
        (
            "/ci/cancel",
            ApiRequest {
                run_id: 1,
                ..req("Other/Secret")
            },
        ),
    ];
    for (path, r) in cases {
        let (code, _) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(
            code, 403,
            "{path} should refuse a repository outside the project"
        );
    }
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn deleting_the_merged_branch_needs_the_operator_to_allow_it() {
    // `delete_merged_branch` is the operator's switch. The agent asking for --delete-branch is
    // necessary but not sufficient, and the merge must not happen behind a refusal either.
    let f = start_api(project_case_a(&["pr:merge"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        delete_branch: true,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/merge", Some(&f.token), &r).await;
    assert_eq!(code, 403, "{:?}", resp.error);
    assert!(
        recorded(&f.recorder).is_empty(),
        "not even the merge should run"
    );

    // Without --delete-branch the same repository merges fine; only the deletion was refused. A
    // fresh fixture, so the recorder holds this request alone.
    let f = start_api(project_case_a(&["pr:merge"]), BootstrapMode::Auto, true).await;
    let plain = ApiRequest {
        number: 7,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/merge", Some(&f.token), &plain).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let rec = recorded(&f.recorder);
    assert_eq!(rec.len(), 1, "only the merge itself");
    assert_eq!(rec[0].method, "PUT");
}

/// A pull request's head is meant to be a branch that arrived through the relay — pushed to
/// `refs/for/<base>`, or to a branch `push` allows. GitHub also reads `owner:branch` as a
/// fork, which would put code the relay never saw onto a pull request against a repository
/// in the project; with `pr:merge` granted, it reaches main.
#[tokio::test]
async fn a_pull_request_cannot_be_opened_from_a_fork() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    for head in [
        "attacker/fork:payload",
        "attacker/fork:sekimore/topic", // the branch name alone is not enough
        "OtherOrg:sekimore/topic",
    ] {
        let mut r = req("LibOrg/awesome-lib");
        r.head = head.into();
        r.base = "main".into();
        r.title = "t".into();
        let (code, resp) = post(f.addr, "/pr/create", Some(&f.token), &r).await;
        assert_eq!(code, 403, "{head}");
        assert!(resp.error.unwrap_or_default().contains("head"), "{head}");
    }
    assert!(
        recorded(&f.recorder).is_empty(),
        "nothing must reach upstream"
    );
}

#[tokio::test]
async fn a_pull_request_head_has_to_be_a_branch_the_project_may_push_to() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    // Outside the sekimore/* namespace: the relay never put it there.
    for head in ["main", "develop", "feature/theirs"] {
        let mut r = req("LibOrg/awesome-lib");
        r.head = head.into();
        r.base = "main".into();
        r.title = "t".into();
        let (code, _) = post(f.addr, "/pr/create", Some(&f.token), &r).await;
        assert_eq!(code, 403, "{head}");
    }
    assert!(recorded(&f.recorder).is_empty());
}

#[tokio::test]
async fn the_ordinary_head_still_works() {
    // The check must not break the flow it exists to protect: push to sekimore/<topic>, then
    // open the PR from it.
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    for head in [
        "sekimore/topic",
        "sekimore/main-abcdef1",
        "LibOrg:sekimore/topic",
    ] {
        let mut r = req("LibOrg/awesome-lib");
        r.head = head.into();
        r.base = "main".into();
        r.title = "t".into();
        let (code, _) = post(f.addr, "/pr/create", Some(&f.token), &r).await;
        assert_eq!(code, 200, "{head}");
    }
}

/// `project add-item` takes an issue's node id and nothing handed one out, so an item could
/// join a board only in the same breath as being created — anything already filed could not
/// be put on a board at all.
#[tokio::test]
async fn a_view_carries_the_node_id_that_add_item_needs() {
    let f = start_api(
        project_case_a(&["issue:read", "pr:read"]),
        BootstrapMode::Auto,
        true,
    )
    .await;

    let r = ApiRequest {
        number: 47,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/view", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let raw = resp.raw.expect("issue view returns the object");
    assert_eq!(raw["node_id"], "I_kwDO47");

    let r = ApiRequest {
        number: 7,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/view", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let raw = resp.raw.expect("pr view returns the object");
    assert_eq!(raw["node_id"], "PR_kwDO7");
}

// ---- 0.2.15: naming a board by its number ----

#[tokio::test]
async fn a_board_can_be_named_by_its_number() {
    let f = start_api(project_case_a(&["project:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        board: Some(TEST_BOARD_NUMBER),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/project/list", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
}

#[tokio::test]
async fn the_number_selects_the_board_it_names() {
    // The whole point of keeping the mapping: with two boards, the id that goes upstream has to be
    // the one --board named. Accepting the request is not evidence that it picked the right one.
    let f = start_api_with_boards(
        project_case_a(&["project:read"]),
        BootstrapMode::Auto,
        true,
        vec![board(2, "PVT_two"), board(3, "PVT_three")],
    )
    .await;
    let r = ApiRequest {
        board: Some(3),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/project/list", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let sent = recorded(&f.recorder);
    let call = sent
        .iter()
        .find(|c| c.path.contains("graphql"))
        .expect("a graphql call should have been made");
    assert_eq!(
        call.body
            .pointer("/variables/project")
            .and_then(|v| v.as_str()),
        Some("PVT_three"),
        "--board 3 must resolve to the third board, not merely be accepted"
    );
}

#[tokio::test]
async fn a_number_that_is_not_a_declared_board_is_refused() {
    let f = start_api(project_case_a(&["project:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        board: Some(TEST_BOARD_NUMBER + 1),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/project/list", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    let msg = resp.error.unwrap_or_default();
    assert!(
        msg.contains(&format!("--board {TEST_BOARD_NUMBER}")),
        "the refusal should name the boards this project does have: {msg}"
    );
    assert!(
        recorded(&f.recorder).is_empty(),
        "nothing should reach upstream"
    );
}

#[tokio::test]
async fn a_single_board_is_the_default() {
    let f = start_api(project_case_a(&["project:read"]), BootstrapMode::Auto, true).await;
    let (code, resp) = post(
        f.addr,
        "/project/list",
        Some(&f.token),
        &req("LibOrg/awesome-lib"),
    )
    .await;
    assert_eq!(code, 200, "{:?}", resp.error);
}

#[tokio::test]
async fn with_several_boards_one_has_to_be_named() {
    let f = start_api_with_boards(
        project_case_a(&["project:read"]),
        BootstrapMode::Auto,
        true,
        vec![board(2, "PVT_two"), board(3, "PVT_three")],
    )
    .await;
    let (code, resp) = post(
        f.addr,
        "/project/list",
        Some(&f.token),
        &req("LibOrg/awesome-lib"),
    )
    .await;
    assert_eq!(code, 400);
    let msg = resp.error.unwrap_or_default();
    assert!(
        msg.contains("--board 2") && msg.contains("--board 3"),
        "the caller should be told what it may name: {msg}"
    );
}

#[tokio::test]
async fn naming_a_board_two_ways_at_once_is_refused() {
    let f = start_api(project_case_a(&["project:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        board: Some(TEST_BOARD_NUMBER),
        project_id: TEST_BOARD.into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/project/list", Some(&f.token), &r).await;
    assert_eq!(code, 400, "{:?}", resp.error);
}

#[tokio::test]
async fn a_node_id_outside_the_project_is_still_refused() {
    // The 0.2.7 check has to survive the rewrite: --board must not have opened a way past it.
    let f = start_api(project_case_a(&["project:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        project_id: "PVT_elsewhere".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/project/list", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    assert!(
        recorded(&f.recorder).is_empty(),
        "nothing should reach upstream"
    );
}

#[tokio::test]
async fn list_carries_the_field_values() {
    // 0.2.15: without these a write could not be read back — update-item answered ok and the
    // board stayed invisible.
    let f = start_api(project_case_a(&["project:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        board: Some(TEST_BOARD_NUMBER),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/project/list", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let raw = resp.raw.expect("the listing");
    let status = raw
        .pointer("/data/node/items/nodes/0/fieldValues/nodes/1/name")
        .and_then(|v| v.as_str());
    assert_eq!(status, Some("Todo"), "field values should come back: {raw}");
}
