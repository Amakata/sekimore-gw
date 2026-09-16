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
