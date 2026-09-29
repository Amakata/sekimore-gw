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
async fn whoami_shows_what_a_repository_adds_and_takes_away() {
    // #143: the relay decides per repository (project grants, plus the repo's allow, minus its
    // deny). A whoami that printed only the project line told an agent it could not merge in a
    // repository that granted pr:merge, and would tell it it could comment where the repository
    // denies it.
    let mut p = project_case_a(&["pr:create", "issue:comment"]);
    let lib = p
        .repos
        .iter_mut()
        .find(|r| r.full_name == "LibOrg/awesome-lib")
        .unwrap();
    lib.allow = vec!["pr:merge".into()];
    lib.deny = vec!["issue:comment".into()];
    let f = start_api(p, BootstrapMode::Auto, true).await;
    let (code, resp) = post(f.addr, "/whoami", Some(&f.token), &ApiRequest::default()).await;
    assert_eq!(code, 200);
    let msg = resp.message.unwrap();
    assert!(
        msg.contains("LibOrg/awesome-lib (read-write) +pr:merge -issue:comment"),
        "{msg}"
    );
    // a repository with no delta of its own is its mode alone
    assert!(
        msg.lines()
            .any(|l| l.trim() == "VendorOrg/reference-impl (read-only)"),
        "{msg}"
    );
    // the project line is labelled as the part every repository starts from
    assert!(msg.contains("permissions (every repo;"), "{msg}");
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

/// #228: every API entry — the bootstrap, an allowed call, a refused one and an unknown token —
/// names the agent's edge to the relay's API, so the row in docs/paths.yml can be found from it.
#[tokio::test]
async fn audit_names_the_edge_of_every_api_entry() {
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
    for event in ["bootstrap_ok", "api_ok", "api_error", "token_denied"] {
        let line = text
            .lines()
            .find(|l| l.contains(&format!("\"event\":\"{event}\"")))
            .unwrap_or_else(|| panic!("no {event} in {text}"));
        assert!(line.contains("\"edge\":\"dev.relay.api\""), "{line}");
    }
    // and the operator's own entries carry none
    assert!(!text
        .lines()
        .any(|l| l.contains("token_issued") && l.contains("\"edge\"")));
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
async fn release_view_finds_a_draft_that_the_by_tag_lookup_cannot_see() {
    // `release view` shares the lookup `release edit` uses, so the same fallback applies. This is
    // no wider than release:read already was: `release list` has always shown drafts (#247).
    let f = start_api(project_case_a(&["release:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        tag: "v3.0.0-workflow-draft".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/release/view", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert_eq!(
        resp.url.as_deref(),
        Some("https://github.example/releases/v3.0.0-workflow-draft")
    );
    assert!(
        resp.message.unwrap_or_default().contains("(draft)"),
        "a draft should be marked as one"
    );
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

// ---- Dependabot alerts (0.2.28, #132) ----

#[tokio::test]
async fn security_alerts_are_one_line_each_and_need_security_read() {
    let f = start_api(
        project_case_a(&["security:read"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let (st, resp) = post(
        f.addr,
        "/security/alerts",
        Some(&f.token),
        &req("LibOrg/awesome-lib"),
    )
    .await;
    assert_eq!(st, 200);
    let msg = resp.message.unwrap();
    // severity, ecosystem/package, manifest, advisory, fix — the triage columns, in one line
    assert!(
        msg.contains("#7 [high] pip/urllib3 uv.lock (runtime) GHSA-xxxx-yyyy-zzzz CVE-2026-0001 fixed in 2.6.0 — urllib3"),
        "{msg}"
    );
    assert!(
        msg.contains(
            "#3 [low] cargo/rustls relay/Cargo.lock GHSA-aaaa-bbbb-cccc no fix yet — rustls"
        ),
        "{msg}"
    );
    // The default filter is open alerts, and the call stays inside the repository
    let calls = recorded(&f.recorder);
    let get = calls.iter().find(|c| c.method == "GET").unwrap();
    assert!(
        get.path
            .starts_with("/api/v3/repos/LibOrg/awesome-lib/dependabot/alerts?"),
        "{}",
        get.path
    );
    assert!(get.path.contains("state=open"), "{}", get.path);

    // `all` drops the filter; anything else is refused before reaching GitHub
    let n = calls.len();
    let r = ApiRequest {
        state: "all".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (st, _) = post(f.addr, "/security/alerts", Some(&f.token), &r).await;
    assert_eq!(st, 200);
    let last = recorded(&f.recorder).into_iter().last().unwrap();
    assert!(!last.path.contains("state="), "{}", last.path);
    let r = ApiRequest {
        state: "everything".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (st, resp) = post(f.addr, "/security/alerts", Some(&f.token), &r).await;
    assert_eq!(st, 400);
    assert!(resp.error.unwrap().contains("open / dismissed / fixed"));
    assert_eq!(
        recorded(&f.recorder).len(),
        n + 1,
        "the bad state must not reach GitHub"
    );

    // A project without the key gets nothing, and GitHub is never asked
    let g = start_api(
        project_case_a(&["ci:read", "pr:read"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let (st, _) = post(
        g.addr,
        "/security/alerts",
        Some(&g.token),
        &req("LibOrg/awesome-lib"),
    )
    .await;
    assert_eq!(st, 403);
    assert!(recorded(&g.recorder).is_empty());
}

#[tokio::test]
async fn dismissing_an_alert_is_its_own_permission_and_needs_a_reason() {
    // security:read is not enough: hiding a vulnerability is a different authority from seeing it
    let f = start_api(
        project_case_a(&["security:read"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        number: 7,
        reason: "tolerable_risk".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (st, _) = post(f.addr, "/security/dismiss", Some(&f.token), &r).await;
    assert_eq!(st, 403);
    let (st, _) = post(f.addr, "/security/reopen", Some(&f.token), &r).await;
    assert_eq!(st, 403);
    assert!(
        recorded(&f.recorder).iter().all(|c| c.method != "PATCH"),
        "nothing may be written without security:dismiss"
    );

    let g = start_api(
        project_case_a(&["security:dismiss"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    // The reason has to be one GitHub knows, and the comment stays within its limit
    let bad = ApiRequest {
        number: 7,
        reason: "meh".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (st, resp) = post(g.addr, "/security/dismiss", Some(&g.token), &bad).await;
    assert_eq!(st, 400);
    assert!(resp.error.unwrap().contains("tolerable_risk"));
    let long = ApiRequest {
        number: 7,
        reason: "not_used".into(),
        body: "x".repeat(281),
        ..req("LibOrg/awesome-lib")
    };
    let (st, _) = post(g.addr, "/security/dismiss", Some(&g.token), &long).await;
    assert_eq!(st, 400);
    assert!(recorded(&g.recorder).is_empty(), "refused before GitHub");

    // The real thing: state, reason and comment reach the alert, and nothing else does
    let ok = ApiRequest {
        number: 7,
        reason: "not_used".into(),
        body: "test-only dependency".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (st, resp) = post(g.addr, "/security/dismiss", Some(&g.token), &ok).await;
    assert_eq!(st, 200);
    assert_eq!(resp.message.unwrap(), "dismissed alert #7 (not_used)");
    let patch = recorded(&g.recorder)
        .into_iter()
        .find(|c| c.method == "PATCH")
        .unwrap();
    assert_eq!(
        patch.path,
        "/api/v3/repos/LibOrg/awesome-lib/dependabot/alerts/7"
    );
    assert_eq!(patch.body["state"], "dismissed");
    assert_eq!(patch.body["dismissed_reason"], "not_used");
    assert_eq!(patch.body["dismissed_comment"], "test-only dependency");

    // Reopening under the same key, with no comment carried over
    let (st, resp) = post(
        g.addr,
        "/security/reopen",
        Some(&g.token),
        &ApiRequest {
            number: 7,
            ..req("LibOrg/awesome-lib")
        },
    )
    .await;
    assert_eq!(st, 200);
    assert_eq!(resp.message.unwrap(), "reopened alert #7");
    let last = recorded(&g.recorder).into_iter().last().unwrap();
    assert_eq!(last.body, serde_json::json!({"state": "open"}));

    // The audit knows the difference between the two writes
    let audit = std::fs::read_to_string(&g.audit_path).unwrap();
    assert!(audit.contains("security_alert_dismissed"), "{audit}");
    assert!(
        audit.contains("not_used"),
        "the reason is in the audit: {audit}"
    );
    assert!(audit.contains("security_alert_reopened"), "{audit}");
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
            // #165: an empty COMMENTED review is the envelope its line comments hang from, so it
            // survives the fetch; the renderer is what drops one that turns out to be childless.
            ("review_envelope", "alice"),
            ("inline", "alice"),
            ("comment", "bob"),
        ],
        "the three sources must come back as one timeline"
    );

    // The review carries its state, the inline comment its place in the diff. Found by kind
    // rather than by index, so adding an entry to the timeline does not silently move these.
    let inline = items
        .iter()
        .find(|i| i["kind"] == "inline")
        .expect("an inline comment");
    assert_eq!(items[1]["state"], "CHANGES_REQUESTED");
    assert_eq!(inline["path"], "src/main.rs");
    assert_eq!(inline["line"], 40);
    assert_eq!(inline["in_reply_to_id"], 555);
    // #165: the id `pr reply` needs, and the review it was submitted with.
    assert_eq!(inline["id"], 2451);
    assert_eq!(inline["review_id"], 902);
    assert!(
        items[0].get("state").is_none(),
        "a plain comment has no state"
    );

    // All three endpoints were asked, and none of them left the project's repository.
    let calls = recorded(&f.recorder);
    let paths: Vec<String> = calls
        .iter()
        .map(|c| c.path.clone())
        .filter(|p| !p.contains("graphql"))
        .collect();
    assert_eq!(paths.len(), 3, "{paths:?}");
    for p in &paths {
        assert!(
            p.starts_with("/api/v3/repos/LibOrg/awesome-lib/"),
            "{p} is outside the project"
        );
    }
    // 0.2.59: plus the one query for the review conversations, which REST cannot answer. It names
    // no repository in its path, so the repository it names in its variables is what is checked.
    let gql: Vec<_> = calls
        .iter()
        .filter(|c| c.path.contains("graphql"))
        .collect();
    assert_eq!(gql.len(), 1, "{calls:?}");
    assert_eq!(gql[0].body["variables"]["owner"], "LibOrg");
    assert_eq!(gql[0].body["variables"]["name"], "awesome-lib");

    let msg = resp.message.unwrap_or_default();
    assert!(msg.contains("review CHANGES_REQUESTED"), "{msg}");
    assert!(msg.contains("src/main.rs:40"), "{msg}");
    assert!(msg.contains("CI is red"), "{msg}");
}

/// #172: the check that matters. GitHub lets a token with write access edit or delete anyone's
/// comment, so an agent deleting a reviewer's note is one API call away. The relay reads the
/// author first and refuses everything that is not its own.
#[tokio::test]
async fn a_comment_someone_else_wrote_cannot_be_touched() {
    let f = start_api(
        project_case_a(&["pr:comment_update", "pr:comment_delete"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    // 4242 is the agent's own in the fixture; any other id belongs to a person.
    for (path, id) in [("/pr/comment-edit", 9999u64), ("/pr/comment-delete", 9999)] {
        let r = ApiRequest {
            number: 8,
            comment_id: id,
            body: "rewritten".into(),
            ..req("LibOrg/awesome-lib")
        };
        let (status, resp) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(
            status, 403,
            "{path} must refuse a comment written by someone else"
        );
        let err = resp.error.unwrap_or_default();
        assert!(
            err.contains("not by this agent"),
            "{path} should say whose it is: {err:?}"
        );
    }
    // And nothing reached the upstream: no PATCH, no DELETE.
    let rec = common::recorded(&f.recorder);
    assert!(
        !rec.iter()
            .any(|c| c.method == "PATCH" || c.method == "DELETE"),
        "a refused edit must not touch the upstream: {:?}",
        rec.iter().map(|c| (&c.method, &c.path)).collect::<Vec<_>>()
    );
}

/// Its own comment goes through, on the endpoint the id belongs to.
#[tokio::test]
async fn the_agents_own_comment_can_be_corrected_and_withdrawn() {
    let f = start_api(
        project_case_a(&["pr:comment_update", "pr:comment_delete"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        number: 8,
        comment_id: 4242,
        body: "corrected".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (status, _) = post(f.addr, "/pr/comment-edit", Some(&f.token), &r).await;
    assert_eq!(status, 200);

    let r2 = ApiRequest {
        number: 8,
        comment_id: 4242,
        ..req("LibOrg/awesome-lib")
    };
    let (status, _) = post(f.addr, "/pr/comment-delete", Some(&f.token), &r2).await;
    assert_eq!(status, 200);

    let rec = common::recorded(&f.recorder);
    let patch = rec.iter().find(|c| c.method == "PATCH").expect("an edit");
    assert!(
        patch.path.ends_with("/issues/comments/4242"),
        "{}",
        patch.path
    );
    assert_eq!(patch.body["body"], "corrected");
    assert!(
        rec.iter()
            .any(|c| c.method == "DELETE" && c.path.ends_with("/issues/comments/4242")),
        "a delete was sent"
    );
}

/// A line comment and a conversation comment live in different namespaces; `--inline` says which.
#[tokio::test]
async fn an_inline_comment_is_edited_on_the_pulls_endpoint() {
    let f = start_api(
        project_case_a(&["pr:comment_update"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        number: 8,
        comment_id: 4242,
        body: "corrected".into(),
        inline: true,
        ..req("LibOrg/awesome-lib")
    };
    let (status, _) = post(f.addr, "/pr/comment-edit", Some(&f.token), &r).await;
    assert_eq!(status, 200);
    let rec = common::recorded(&f.recorder);
    let patch = rec.iter().find(|c| c.method == "PATCH").expect("an edit");
    assert!(
        patch.path.ends_with("/pulls/comments/4242"),
        "{}",
        patch.path
    );
}

/// Posting is not the authority to rewrite or remove: pr:comment alone gets neither.
#[tokio::test]
async fn pr_comment_alone_does_not_allow_editing_or_deleting() {
    let f = start_api(project_case_a(&["pr:comment"]), BootstrapMode::Auto, true).await;
    for path in ["/pr/comment-edit", "/pr/comment-delete"] {
        let r = ApiRequest {
            number: 8,
            comment_id: 4242,
            body: "rewritten".into(),
            ..req("LibOrg/awesome-lib")
        };
        let (status, _) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(status, 403, "{path} must need its own permission");
    }
}

/// The conversation on a pull request and on an issue share one namespace, so the command's
/// name proves nothing. pr:comment_update alone must not rewrite a comment on an issue (#47 is
/// an issue in the fixture), and must reach nothing upstream that writes.
#[tokio::test]
async fn pr_comment_update_does_not_reach_an_issue() {
    let f = start_api(
        project_case_a(&["pr:comment_update", "pr:comment_delete"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    for path in ["/pr/comment-edit", "/pr/comment-delete"] {
        let r = ApiRequest {
            number: 47,
            comment_id: 4242,
            body: "rewritten".into(),
            ..req("LibOrg/awesome-lib")
        };
        let (status, _) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(status, 403, "{path} on an issue must need issue:*");
    }
    let rec = common::recorded(&f.recorder);
    assert!(
        !rec.iter()
            .any(|c| c.method == "PATCH" || c.method == "DELETE"),
        "{:?}",
        rec.iter().map(|c| (&c.method, &c.path)).collect::<Vec<_>>()
    );
}

/// The agent's own comment, named with a number it does not sit on. Without this check an id
/// from a pull request would ride on an issue's permission (4242 is on #8, #47 is an issue).
#[tokio::test]
async fn a_comment_on_another_number_is_refused() {
    let f = start_api(
        project_case_a(&["issue:comment_update"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        number: 47,
        comment_id: 4242,
        body: "rewritten".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (status, resp) = post(f.addr, "/issue/comment-edit", Some(&f.token), &r).await;
    assert_eq!(status, 403);
    let err = resp.error.unwrap_or_default();
    assert!(err.contains("not on #47"), "{err:?}");
    let rec = common::recorded(&f.recorder);
    assert!(!rec.iter().any(|c| c.method == "PATCH"));
}

/// A line comment lives on the pulls endpoint, outside anything issue:* grants.
#[tokio::test]
async fn inline_on_an_issue_is_refused() {
    let f = start_api(
        project_case_a(&["issue:comment_update"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        number: 47,
        comment_id: 4242,
        body: "rewritten".into(),
        inline: true,
        ..req("LibOrg/awesome-lib")
    };
    let (status, _) = post(f.addr, "/issue/comment-edit", Some(&f.token), &r).await;
    assert_eq!(status, 400);
    let rec = common::recorded(&f.recorder);
    assert!(!rec.iter().any(|c| c.path.contains("/pulls/comments/")));
}

/// #173: the numbers in a rendered diff are the ones `pr review --comment path:line:body` takes.
/// If they drift, an agent leaves its note on the wrong line, so they are pinned here.
#[tokio::test]
async fn a_diff_carries_githubs_line_numbers() {
    let f = start_api(project_case_a(&["pr:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        ..req("LibOrg/awesome-lib")
    };
    let (status, resp) = post(f.addr, "/pr/diff", Some(&f.token), &r).await;
    assert_eq!(status, 200);
    let raw = resp.raw.expect("a diff page");
    // Without --path it takes the first file, so an agent holding only the number gets a diff
    assert_eq!(raw["path"], "src/main.rs");
    assert_eq!(raw["file_index"], 1);
    assert_eq!(raw["file_count"], 3);
    let got: Vec<(Option<u64>, &str)> = raw["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| (l["line"].as_u64(), l["kind"].as_str().unwrap()))
        .collect();
    assert_eq!(
        got,
        vec![
            (None, "hunk"),
            (Some(38), "ctx"),
            (None, "del"), // deleted: not in the new file, so nothing to comment on
            (Some(39), "add"),
            (Some(40), "add"),
            (Some(41), "ctx"),
        ]
    );
    // The next file is named, so a whole pull request can be read without guessing paths
    assert_eq!(raw["next_path"], "logo.png");
    assert_eq!(raw["has_more_after"], false);
}

/// A file GitHub sends no patch for says so, rather than rendering as an empty diff.
#[tokio::test]
async fn a_binary_file_says_it_has_no_patch() {
    let f = start_api(project_case_a(&["pr:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        file_path: "logo.png".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (status, resp) = post(f.addr, "/pr/diff", Some(&f.token), &r).await;
    assert_eq!(status, 200);
    let raw = resp.raw.expect("a diff page");
    assert!(raw["no_patch"].as_str().unwrap_or("").contains("binary"));
    assert_eq!(raw["lines"].as_array().map(Vec::len), Some(0));
}

/// A path the pull request does not touch is refused, and says how to find the ones it does.
/// Without this the caller gets the first file instead and reviews the wrong one.
#[tokio::test]
async fn a_path_outside_the_pull_request_is_refused() {
    let f = start_api(project_case_a(&["pr:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        file_path: "src/secrets.rs".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (status, resp) = post(f.addr, "/pr/diff", Some(&f.token), &r).await;
    assert_eq!(status, 403);
    let err = resp.error.unwrap_or_default();
    assert!(err.contains("does not touch"), "{err:?}");
    assert!(
        err.contains("pr files"),
        "it should say how to look: {err:?}"
    );
}

/// A window walks forward through one file, and says when there is more.
#[tokio::test]
async fn a_long_file_is_read_a_window_at_a_time() {
    let f = start_api(project_case_a(&["pr:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        window: 2,
        ..req("LibOrg/awesome-lib")
    };
    let (status, resp) = post(f.addr, "/pr/diff", Some(&f.token), &r).await;
    assert_eq!(status, 200);
    let raw = resp.raw.expect("a diff page");
    assert_eq!(raw["lines"].as_array().map(Vec::len), Some(2));
    assert_eq!(raw["has_more_after"], true);
    assert_eq!(raw["end"], 2);

    // The second page starts where the first ended, and the numbering carries on correctly
    let r2 = ApiRequest {
        number: 7,
        window: 2,
        before: Some(2),
        ..req("LibOrg/awesome-lib")
    };
    let (status, resp) = post(f.addr, "/pr/diff", Some(&f.token), &r2).await;
    assert_eq!(status, 200);
    let raw = resp.raw.expect("a diff page");
    let got: Vec<Option<u64>> = raw["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["line"].as_u64())
        .collect();
    assert_eq!(got, vec![None, Some(39)]);
}

/// `pr files` lists what moved, and carries no patches: it is the cheap half of reading a diff.
#[tokio::test]
async fn pr_files_lists_the_paths_without_their_patches() {
    let f = start_api(project_case_a(&["pr:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        ..req("LibOrg/awesome-lib")
    };
    let (status, resp) = post(f.addr, "/pr/files", Some(&f.token), &r).await;
    assert_eq!(status, 200);
    let msg = resp.message.unwrap_or_default();
    assert!(msg.contains("src/main.rs"), "{msg}");
    assert!(msg.contains("3 files, +3 -1"), "{msg}");
    let raw = serde_json::to_string(&resp.raw).unwrap_or_default();
    assert!(
        !raw.contains("ctx one"),
        "pr files must not carry patches: {raw}"
    );
}

/// Reading a diff is reading the pull request: without pr:read there is no diff.
#[tokio::test]
async fn reading_a_diff_needs_pr_read() {
    let f = start_api(project_case_a(&["pr:comment"]), BootstrapMode::Auto, true).await;
    for path in ["/pr/files", "/pr/diff"] {
        let r = ApiRequest {
            number: 7,
            ..req("LibOrg/awesome-lib")
        };
        let (status, _) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(status, 403, "{path} must need pr:read");
    }
}

/// #173: every file's patch rides along on this endpoint whether or not it is wanted, and `rest`
/// truncates at 1 MiB — a response cut mid-JSON does not parse. So the page has to stay well under
/// GitHub's 100, or a wide pull request fails to read at all: exactly the case this is for.
#[tokio::test]
async fn the_file_list_is_asked_for_in_small_pages() {
    let f = start_api(project_case_a(&["pr:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        ..req("LibOrg/awesome-lib")
    };
    let (status, _) = post(f.addr, "/pr/files", Some(&f.token), &r).await;
    assert_eq!(status, 200);
    let rec = common::recorded(&f.recorder);
    let call = rec
        .iter()
        .find(|c| c.path.contains("/pulls/7/files"))
        .expect("the files endpoint");
    let per_page: u32 = call
        .path
        .split("per_page=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(
        per_page > 0 && per_page <= 30,
        "a page of patches must fit under RESPONSE_CAP: {}",
        call.path
    );
    assert!(call.path.contains("page=1"), "{}", call.path);
    // The fixture returns fewer files than a page holds, so the walk stops without asking again
    assert_eq!(
        rec.iter()
            .filter(|c| c.path.contains("/pulls/7/files"))
            .count(),
        1,
        "a short page means there is no more to fetch"
    );
}

/// #167: a review can point at lines of the diff, not only carry a body. The notes ride on the
/// same request GitHub already takes for the verdict.
#[tokio::test]
async fn a_review_carries_its_line_comments_upstream() {
    let f = start_api(project_case_a(&["pr:review"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        event: "REQUEST_CHANGES".into(),
        body: "two things".into(),
        comments: vec![
            sekimore_relay::api::types::ReviewComment {
                path: "src/main.rs".into(),
                line: 40,
                start_line: None,
                body: "this should be >=".into(),
            },
            sekimore_relay::api::types::ReviewComment {
                path: "src/lib.rs".into(),
                line: 7,
                start_line: None,
                body: "see RFC 3339: the offset is required".into(),
            },
            sekimore_relay::api::types::ReviewComment {
                path: "src/api.rs".into(),
                line: 212,
                start_line: Some(207),
                body: "the whole match is unreachable".into(),
            },
        ],
        ..req("LibOrg/awesome-lib")
    };
    let (status, _) = post(f.addr, "/pr/review", Some(&f.token), &r).await;
    assert_eq!(status, 200);

    let rec = common::recorded(&f.recorder);
    let call = rec
        .iter()
        .find(|c| c.path.ends_with("/pulls/7/reviews"))
        .expect("a review was submitted");
    assert_eq!(call.body["event"], "REQUEST_CHANGES");
    let sent = call.body["comments"]
        .as_array()
        .expect("comments were sent");
    assert_eq!(sent.len(), 3, "{:?}", call.body);
    assert_eq!(sent[0]["path"], "src/main.rs");
    assert_eq!(sent[0]["line"], 40);
    // A body with a colon in it survives; prose about code is full of them.
    assert_eq!(sent[1]["body"], "see RFC 3339: the offset is required");
    // 0.2.59: a note over a range names both ends. A note on one line names neither, because
    // GitHub reads start_line: null as a range and refuses it.
    assert_eq!(sent[2]["start_line"], 207);
    assert_eq!(sent[2]["line"], 212);
    for one_line in [&sent[0], &sent[1]] {
        assert!(
            one_line.get("start_line").is_none(),
            "a single-line note must not carry the key at all: {one_line:?}"
        );
    }
}

/// Without comments the request must not grow an empty array: to GitHub that is not the same as
/// the key being absent.
#[tokio::test]
async fn a_review_with_no_line_comments_sends_no_comments_key() {
    let f = start_api(project_case_a(&["pr:review"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        event: "APPROVE".into(),
        body: "lgtm".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (status, _) = post(f.addr, "/pr/review", Some(&f.token), &r).await;
    assert_eq!(status, 200);
    let rec = common::recorded(&f.recorder);
    let call = rec
        .iter()
        .find(|c| c.path.ends_with("/pulls/7/reviews"))
        .expect("a review was submitted");
    assert!(call.body.get("comments").is_none(), "{:?}", call.body);
}

// ---- resolving a review conversation (0.2.59) ----

/// The `reviewThreads` read queries the relay sent, in the order it sent them. The mutations and
/// the unrelated GraphQL calls are not reads, and the walk's shape is counted in reads.
fn reads(rec: &[common::Recorded]) -> Vec<&serde_json::Value> {
    rec.iter()
        .filter(|c| c.path.contains("graphql"))
        .filter(|c| {
            c.body
                .get("query")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|q| q.contains("reviewThreads("))
        })
        .map(|c| &c.body)
        .collect()
}

/// The whole point: the id an agent needs in order to settle a conversation reaches it through
/// `pr comments`, which is where the guide already sends it to read the review. Without this the
/// command would exist with nothing to feed it — REST carries no thread id anywhere.
#[tokio::test]
async fn pr_comments_carries_the_thread_id_a_resolve_needs() {
    let f = start_api(project_case_a(&["pr:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/comments", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);

    let raw = resp.raw.clone().expect("raw comments");
    let line = raw
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["kind"] == "inline")
        .expect("the line comment");
    assert_eq!(line["id"], 2451);
    // joined from GraphQL on databaseId, which is the same number REST calls id
    assert_eq!(line["thread_id"], "PRRT_one");
    assert_eq!(
        line["resolved"], true,
        "a reader must be able to see a conversation is already settled"
    );

    // and it is in what a person reads, not only in the JSON
    let msg = resp.message.unwrap_or_default();
    assert!(msg.contains("thread PRRT_one (resolved)"), "{msg}");

    // the join costs exactly one extra call, and only because there was a line comment to join to
    let rec = common::recorded(&f.recorder);
    assert_eq!(
        rec.iter().filter(|c| c.path.contains("graphql")).count(),
        1,
        "{rec:?}"
    );
}

#[tokio::test]
async fn resolving_and_unresolving_send_the_two_different_mutations() {
    let f = start_api(project_case_a(&["pr:resolve"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        thread_id: "PRRT_one".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/resolve", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert_eq!(
        resp.message.unwrap_or_default(),
        "resolved PRRT_one on #7",
        "the answer says what the thread now is"
    );

    let mutation = |rec: &[common::Recorded]| -> String {
        rec.iter()
            .filter(|c| c.path.contains("graphql"))
            .filter_map(|c| c.body.get("query").and_then(|q| q.as_str()))
            .find(|q| q.starts_with("mutation"))
            .unwrap_or_default()
            .to_string()
    };
    let sent = mutation(&common::recorded(&f.recorder));
    assert!(
        sent.contains("resolveReviewThread(input:{threadId:$thread})")
            && !sent.contains("unresolveReviewThread"),
        "{sent}"
    );

    // the other direction is the other mutation, not the same one with a flag
    let f = start_api(project_case_a(&["pr:resolve"]), BootstrapMode::Auto, true).await;
    let back = ApiRequest {
        unresolve: true,
        ..r.clone()
    };
    let (code, resp) = post(f.addr, "/pr/resolve", Some(&f.token), &back).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert_eq!(
        resp.message.unwrap_or_default(),
        "unresolved PRRT_one on #7"
    );
    let sent = mutation(&common::recorded(&f.recorder));
    assert!(
        sent.contains("unresolveReviewThread(input:{threadId:$thread})"),
        "{sent}"
    );
}

/// A thread id is a global node id: it names its object without naming a repository. An agent
/// holding `pr:resolve` on one pull request must not be able to settle a conversation on another
/// one, so the thread is looked up on the number the caller named before anything is written.
#[tokio::test]
async fn a_thread_from_somewhere_else_is_refused_before_the_mutation() {
    let f = start_api(project_case_a(&["pr:resolve"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        thread_id: "PRRT_elsewhere".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/resolve", Some(&f.token), &r).await;
    assert_eq!(
        code, 403,
        "the relay refused it, as with a foreign comment id"
    );
    let err = resp.error.unwrap_or_default();
    assert!(
        err.contains("PRRT_elsewhere") && err.contains("#7"),
        "the refusal names the thread and the pull request: {err}"
    );
    let rec = common::recorded(&f.recorder);
    assert!(
        rec.iter()
            .filter_map(|c| c.body.get("query").and_then(|q| q.as_str()))
            .all(|q| !q.contains("Mutation") && !q.starts_with("mutation")),
        "nothing was written upstream: {rec:?}"
    );
}

/// `pr:comment` lets the agent answer a review note. Declaring the note settled is a different
/// authority, so it has a key of its own and this is the proof that it is not folded in.
#[tokio::test]
async fn pr_comment_does_not_carry_pr_resolve() {
    let f = start_api(
        project_case_a(&["pr:comment", "pr:read"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        number: 7,
        thread_id: "PRRT_one".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/resolve", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    let err = resp.error.unwrap_or_default();
    assert!(
        err.contains("pr:resolve"),
        "the denial names the key: {err}"
    );
    assert!(
        common::recorded(&f.recorder).is_empty(),
        "a refused call reaches no upstream"
    );
}

/// The ownership check follows the cursor, but not forever. On a pull request with more
/// conversations than the page budget covers, a thread the relay did not see is still refused —
/// but it must not be called foreign, because the relay does not know that it is. The two
/// refusals have to read differently.
#[tokio::test]
async fn a_thread_past_the_page_budget_is_refused_as_unseen_not_as_foreign() {
    let f = start_api(project_case_a(&["pr:resolve"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 408,
        thread_id: "PRRT_far_down".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/resolve", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    let err = resp.error.unwrap_or_default();
    assert!(
        err.contains("reads no further"),
        "the refusal says the relay could not see far enough: {err}"
    );
    assert!(
        !err.contains("is not a review conversation on"),
        "and does not claim the thread belongs elsewhere: {err}"
    );
    // The mock's #408 never runs out of pages, so the walk stopped at the budget and not before:
    // it spent the whole budget and then gave up, rather than reading one page and calling it a day.
    let rec = common::recorded(&f.recorder);
    assert_eq!(
        reads(&rec).len(),
        10,
        "the walk stops at the page budget, having asked for every page of it: {rec:?}"
    );
    // still nothing written
    assert!(rec
        .iter()
        .filter_map(|c| c.body.get("query").and_then(|q| q.as_str()))
        .all(|q| !q.starts_with("mutation")));
}

/// The regression the outer paging exists for: a conversation that GitHub puts on the second
/// page of `reviewThreads`. Before the relay followed the cursor it saw only the first page, so
/// such a thread could never be resolved — the ownership check refused it as one it could not
/// see. It has to be found, and settled.
#[tokio::test]
async fn a_thread_on_the_second_page_is_found_and_resolved() {
    let f = start_api(project_case_a(&["pr:resolve"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 409,
        thread_id: "PRRT_page2".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/resolve", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert_eq!(
        resp.message.unwrap_or_default(),
        "resolved PRRT_page2 on #409"
    );

    // Two reads, and the second one carried the first one's cursor: that is what makes it the
    // *next* page rather than the same page asked for twice.
    let rec = common::recorded(&f.recorder);
    let pages = reads(&rec);
    assert_eq!(pages.len(), 2, "{rec:?}");
    assert!(
        pages[0]
            .pointer("/variables/after")
            .is_none_or(serde_json::Value::is_null),
        "the first page starts from the beginning: {:?}",
        pages[0]
    );
    assert_eq!(
        pages[1].pointer("/variables/after"),
        Some(&serde_json::Value::from("CUR_409_1")),
        "the second page is asked for from where the first one ended: {:?}",
        pages[1]
    );
}

/// The walk costs one request when one request is enough. `pr comments` is a read an agent runs
/// constantly, and most pull requests have their conversations on a single page.
#[tokio::test]
async fn a_pull_request_whose_threads_fit_on_one_page_asks_once() {
    let f = start_api(project_case_a(&["pr:resolve"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        thread_id: "PRRT_one".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/resolve", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let rec = common::recorded(&f.recorder);
    assert_eq!(
        reads(&rec).len(),
        1,
        "a full first page that says there is no next one ends the walk: {rec:?}"
    );
}

/// The ids have to reach the reader, not only the ownership check: a conversation on the second
/// page is one the agent has to be able to see a thread id for in `pr comments`, or it has
/// nothing to pass to `pr resolve`.
#[tokio::test]
async fn a_thread_id_from_the_second_page_reaches_pr_comments() {
    let f = start_api(project_case_a(&["pr:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 409,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/comments", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let raw = resp.raw.clone().expect("raw comments");
    let line = raw
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == 7777)
        .expect("the line comment whose thread is on the second page");
    assert_eq!(line["thread_id"], "PRRT_page2");
    assert_eq!(line["resolved"], false);
    assert!(
        resp.message
            .unwrap_or_default()
            .contains("thread PRRT_page2"),
        "and a person reading the review sees it too"
    );
}

/// The inner window and the display window have to be the same size, pointed at the same end.
///
/// `pr comments` asks REST for one page of at most a hundred line comments and sends no ordering,
/// so it gets the oldest ones on the pull request. The join asks GraphQL for the first hundred
/// comments of each conversation — the same end. That pairing is why a comment a reader is shown
/// always carries a thread id, however long the conversation behind it ran: a displayed comment
/// has fewer than a hundred line comments older than it anywhere on the pull request, so it has
/// fewer than that many older than it inside its own thread.
///
/// #410 is one conversation of 151 comments, longer than either window. The mock honours the
/// count and the end the query names, so reading the wrong end of it shows up here: every
/// displayed comment would come back without an id while the ids sat on comments no reader can
/// reach, and the conversation could not be settled from what `pr comments` printed.
#[tokio::test]
async fn a_long_conversation_keeps_a_thread_id_on_what_is_displayed() {
    let f = start_api(project_case_a(&["pr:read"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 410,
        // The widest window a caller can open, which is the one the two constants are matched at.
        // Asking for the default thirty would leave the interesting boundary untested: the join
        // could be cut to any number above thirty and nothing here would notice.
        first: 100,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/comments", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);

    let raw = resp.raw.clone().expect("raw comments");
    let shown: Vec<&serde_json::Value> = raw
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["kind"] == "inline")
        .collect();
    assert_eq!(
        shown.len(),
        100,
        "the reader got a full window, so the join is tested at the size it is matched at"
    );
    // Not "most of them": every single one, because every single one is on the page a reader got.
    for c in &shown {
        assert_eq!(
            c["thread_id"], "PRRT_long",
            "a displayed comment with no thread id cannot be resolved from what was printed: {c}"
        );
        assert_eq!(c["resolved"], false);
    }
    // and in what a person reads, not only in the JSON
    assert!(
        resp.message
            .unwrap_or_default()
            .contains("thread PRRT_long"),
        "the id reaches the rendered review too"
    );
    // still one request: matching the windows costs no extra round trip
    let rec = common::recorded(&f.recorder);
    assert_eq!(reads(&rec).len(), 1, "{rec:?}");
}

/// And the id that reached the reader is one `pr resolve` accepts: the point of printing it.
#[tokio::test]
async fn a_long_conversation_can_still_be_settled() {
    let f = start_api(project_case_a(&["pr:resolve"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 410,
        thread_id: "PRRT_long".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/resolve", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert_eq!(
        resp.message.unwrap_or_default(),
        "resolved PRRT_long on #410"
    );
}

#[tokio::test]
async fn resolving_without_a_thread_id_says_where_to_find_one() {
    let f = start_api(project_case_a(&["pr:resolve"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        thread_id: "   ".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/pr/resolve", Some(&f.token), &r).await;
    assert_eq!(code, 400);
    let err = resp.error.unwrap_or_default();
    assert!(err.contains("pr comments"), "{err}");
    assert!(common::recorded(&f.recorder).is_empty());
}

/// GitHub refuses a review that says nothing, with a message that does not say which half is
/// missing; the relay answers before spending the call.
#[tokio::test]
async fn a_review_that_says_nothing_is_refused_here() {
    let f = start_api(project_case_a(&["pr:review"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 7,
        event: "COMMENT".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (status, resp) = post(f.addr, "/pr/review", Some(&f.token), &r).await;
    assert_eq!(status, 400);
    let err = resp.error.unwrap_or_default();
    assert!(
        err.contains("body, line comments"),
        "the refusal should name both ways to say something: {err:?}"
    );
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
    // Date, author, then what kind of entry it is; the body indented underneath. #165: a review
    // owns the line comments submitted with it, so they are nested rather than listed beside it,
    // and each carries the id `pr reply` needs. The empty COMMENTED review is kept here because
    // it has one; with none it would print nothing.
    // 0.2.59: and the conversation it belongs to, which is what `pr resolve` takes. This one is
    // already settled upstream, so it is marked — an unmarked conversation is still open.
    assert_eq!(
        msg,
        "2026-09-17 carol  [comment]\n  first\n\n\
         2026-09-17 alice  review CHANGES_REQUESTED\n  the null check is inverted\n\n\
         2026-09-17 alice  review COMMENTED\n    src/main.rs:40  #2451  thread PRRT_one (resolved)\n      this should be >=\n\n\
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
        // 0.2.15: an issue write looks the number up first, to learn whether it names a pull
        // request. /pr/reopen already knows what it is addressing and does not.
        let writes: Vec<_> = rec.iter().filter(|c| c.method == "PATCH").collect();
        assert_eq!(writes.len(), 1, "{path}");
        assert_eq!(writes[0].body["state"], "open", "{path}");
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
    // 0.2.15: each write is preceded by the kind lookup, which is a GET on the issue itself
    let paths: Vec<&str> = rec
        .iter()
        .filter(|c| c.method != "GET")
        .map(|c| c.path.as_str())
        .collect();
    assert_eq!(
        paths,
        vec![
            "/api/v3/repos/LibOrg/awesome-lib/issues/47/labels/bug",
            "/api/v3/repos/LibOrg/awesome-lib/issues/47/labels/p1",
            "/api/v3/repos/LibOrg/awesome-lib/issues/47/assignees",
        ]
    );
    let writes: Vec<_> = rec.iter().filter(|c| c.method != "GET").collect();
    assert!(writes.iter().all(|c| c.method == "DELETE"));
    assert_eq!(writes[2].body["assignees"][0], "bob");
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
            // 0.2.15: the kind lookup (GET .../issues/47) happens first, so the prefix stops
            // at the issue. A label that resolved out of the repository still fails this.
            assert!(
                call.path
                    .starts_with("/api/v3/repos/LibOrg/awesome-lib/issues/47"),
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
async fn publishing_a_draft_the_workflow_made_falls_back_to_the_listing() {
    // GitHub's /releases/tags/ answers with published releases only, so the draft Release the
    // publish workflow leaves behind is invisible there and `release edit --draft false` used to
    // answer "no release for tag" about the one thing it exists to publish (#247).
    let f = start_api(
        project_case_a(&["release:create", "release:publish"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        tag: "v3.0.0-workflow-draft".into(),
        set_draft: Some(false),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/release/edit", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let rec = recorded(&f.recorder);
    // The by-tag lookup (404), then the listing that does see the draft, then the edit itself.
    assert_eq!(rec.len(), 3, "{rec:?}");
    assert!(
        rec[0]
            .path
            .starts_with("/api/v3/repos/LibOrg/awesome-lib/releases/tags/"),
        "{:?}",
        rec[0].path
    );
    assert_eq!(rec[1].method, "GET");
    assert_eq!(
        rec[1].path,
        "/api/v3/repos/LibOrg/awesome-lib/releases?per_page=100"
    );
    assert_eq!(rec[2].method, "PATCH");
    assert_eq!(rec[2].path, "/api/v3/repos/LibOrg/awesome-lib/releases/904");
    assert_eq!(rec[2].body["draft"], false);
    assert!(resp.message.unwrap_or_default().starts_with("published"));
}

#[tokio::test]
async fn a_draft_found_in_the_listing_still_needs_release_publish() {
    // The fallback is a second way to find the release, not a way around the boundary --draft
    // draws: release:create alone must not take it out of draft (#247).
    let f = start_api(
        project_case_a(&["release:create"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        tag: "v3.0.0-workflow-draft".into(),
        set_draft: Some(false),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/release/edit", Some(&f.token), &r).await;
    assert_eq!(code, 403, "{:?}", resp.error);
    assert!(
        !recorded(&f.recorder).iter().any(|c| c.method == "PATCH"),
        "nothing should have been written"
    );
}

#[tokio::test]
async fn a_tag_in_neither_the_by_tag_lookup_nor_the_listing_still_says_so() {
    // The fallback must not turn "no release for tag" into an upstream error, and must not invent
    // a release out of an unrelated entry in the listing (#247).
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
    assert!(resp
        .error
        .unwrap_or_default()
        .contains("no release for tag v0.0.0-none"));
    let rec = recorded(&f.recorder);
    // Both lookups were tried, and neither found it, so nothing was written.
    assert_eq!(rec.len(), 2, "{rec:?}");
    assert_eq!(
        rec[1].path,
        "/api/v3/repos/LibOrg/awesome-lib/releases?per_page=100"
    );
    assert!(!rec.iter().any(|c| c.method == "PATCH"));
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
            "pr:resolve",
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
            "/pr/resolve",
            ApiRequest {
                number: 1,
                thread_id: "PRRT_x".into(),
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

// ---- 0.2.15: a number reaches either kind, and the permission follows what it is ----
// GitHub serves pull requests from the issues endpoints. #8 in the mock is one; #47 is an issue.

#[tokio::test]
async fn closing_a_pull_request_is_refused_by_issue_close_alone() {
    // The whole of #52: a project that withheld pr:close deliberately found issue:close doing it.
    let f = start_api(project_case_a(&["issue:close"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 8,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/close", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    let msg = resp.error.unwrap_or_default();
    assert!(msg.contains("pr:close"), "should name pr:close: {msg}");
    assert!(
        !recorded(&f.recorder).iter().any(|c| c.method == "PATCH"),
        "the pull request must not be touched"
    );
}

#[tokio::test]
async fn closing_a_pull_request_works_with_pr_close() {
    // The case 0.2.13 could not reach: the proof has to be the pr one, and the lookup that decides
    // this cannot itself require issue:read, which is what stalled that attempt.
    let f = start_api(project_case_a(&["pr:close"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 8,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/close", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert!(recorded(&f.recorder).iter().any(|c| c.method == "PATCH"));
}

#[tokio::test]
async fn closing_an_issue_still_needs_issue_close() {
    // The converse: pr:close must not have become a way to close issues.
    let f = start_api(project_case_a(&["pr:close"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 47,
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/close", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    let msg = resp.error.unwrap_or_default();
    assert!(
        msg.contains("issue:close"),
        "should name issue:close: {msg}"
    );
    assert!(!recorded(&f.recorder).iter().any(|c| c.method == "PATCH"));
}

#[tokio::test]
async fn neither_permission_asks_upstream_nothing() {
    // The lookup must not become a way for a caller with nothing to probe what a number is.
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    for path in [
        "/issue/close",
        "/issue/label",
        "/issue/assign",
        "/issue/comment",
    ] {
        let r = ApiRequest {
            number: 8,
            body: "x".into(),
            labels: vec!["bug".into()],
            assignees: vec!["bob".into()],
            ..req("LibOrg/awesome-lib")
        };
        let (code, _) = post(f.addr, path, Some(&f.token), &r).await;
        assert_eq!(code, 403, "{path}");
    }
    assert!(
        recorded(&f.recorder).is_empty(),
        "a caller with neither permission learned nothing about the numbers"
    );
}

#[tokio::test]
async fn labelling_a_pull_request_needs_pr_label() {
    let f = start_api(project_case_a(&["issue:label"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 8,
        labels: vec!["bug".into()],
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/label", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    assert!(resp.error.unwrap_or_default().contains("pr:label"));
    assert!(!recorded(&f.recorder).iter().any(|c| c.method == "POST"));
}

#[tokio::test]
async fn pr_label_can_be_granted_and_labels_a_pull_request() {
    // Resource::Pr gained Label and Assign so the capability stays expressible rather than being
    // removed: a project that wants its agent to label pull requests says pr:label.
    let f = start_api(project_case_a(&["pr:label"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 8,
        labels: vec!["bug".into()],
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/label", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    assert!(recorded(&f.recorder).iter().any(|c| c.method == "POST"));
}

#[tokio::test]
async fn commenting_on_a_pull_request_needs_pr_comment() {
    let f = start_api(
        project_case_a(&["issue:comment"]),
        BootstrapMode::Auto,
        true,
    )
    .await;
    let r = ApiRequest {
        number: 8,
        body: "a note".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/comment", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    assert!(resp.error.unwrap_or_default().contains("pr:comment"));
}

// ---- 0.2.15: correcting an issue ----

#[tokio::test]
async fn updating_an_issue_needs_issue_update() {
    // Not issue:create. An issue body is the change instruction, so a project can want issues
    // opened without wanting what a person wrote rewritable.
    let f = start_api(project_case_a(&["issue:create"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 47,
        body: "corrected".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/update", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    assert!(resp.error.unwrap_or_default().contains("issue:update"));
    assert!(
        recorded(&f.recorder).is_empty(),
        "nothing should reach upstream"
    );
}

#[tokio::test]
async fn updating_an_issue_sends_only_what_was_given() {
    let f = start_api(project_case_a(&["issue:update"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 47,
        body: "corrected".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/update", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let rec = recorded(&f.recorder);
    let patch = rec
        .iter()
        .find(|c| c.method == "PATCH")
        .expect("the correction");
    assert_eq!(patch.body["body"], "corrected");
    // A title that was not given must not be sent: it would blank the existing one
    assert!(patch.body.get("title").is_none(), "{:?}", patch.body);
}

#[tokio::test]
async fn updating_a_pull_request_is_refused_and_names_pr_update() {
    // #8 is a pull request. pr update already edits one; a second way in under a different
    // permission is the shape #52 was about.
    let f = start_api(project_case_a(&["issue:update"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 8,
        title: "renamed".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/issue/update", Some(&f.token), &r).await;
    assert_eq!(code, 400);
    let msg = resp.error.unwrap_or_default();
    assert!(
        msg.contains("pr update"),
        "should point at pr update: {msg}"
    );
    assert!(
        !recorded(&f.recorder).iter().any(|c| c.method == "PATCH"),
        "the pull request must not be touched"
    );
}

#[tokio::test]
async fn updating_needs_a_title_or_a_body() {
    let f = start_api(project_case_a(&["issue:update"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 47,
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/issue/update", Some(&f.token), &r).await;
    assert_eq!(code, 400);
}

#[tokio::test]
async fn updating_an_issue_outside_the_project_is_refused() {
    let f = start_api(project_case_a(&["issue:update"]), BootstrapMode::Auto, true).await;
    let r = ApiRequest {
        number: 47,
        body: "corrected".into(),
        ..req("Other/Secret")
    };
    let (code, _) = post(f.addr, "/issue/update", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    assert!(recorded(&f.recorder).is_empty());
}

/// #99: resolving a declared board to its node id needs the upstream API token, and since 0.2.19
/// that token lives in the secret store, which starts locked. Doing it at start-up meant every
/// board failed to resolve and stayed refused for the life of the process — unlocking afterwards
/// never revisited it, and the denial claimed no board had been configured.
#[tokio::test]
async fn a_declared_board_is_resolved_on_first_use_not_at_start_up() {
    let f = start_api_full(
        project_case_a(&["project:read"]),
        BootstrapMode::Auto,
        true,
        vec![],
        Some(vec![sekimore_relay::config::BoardRef {
            org: None,
            user: Some("Amakata".into()),
            number: 2,
            permissions: None,
            upstream: None,
        }]),
    )
    .await;

    // Nothing resolved anything at start-up, so the first request is what does it.
    let r = ApiRequest {
        board: Some(2),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/project/list", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);

    let sent = recorded(&f.recorder);
    assert!(
        sent.iter().any(|c| c
            .body
            .to_string()
            .contains("projectV2(number:$number){ id }")),
        "the board was never resolved; the id must have come from somewhere it should not"
    );
    assert!(
        sent.iter()
            .any(|c| c.body.to_string().contains("PVT_board2")),
        "the resolved id did not reach the upstream call"
    );
}

/// The other half of #99: a board that could not be resolved must not be remembered as refused.
/// The usual reason is a locked store, and the operator unlocking is meant to fix it without a
/// restart.
#[tokio::test]
async fn a_board_that_could_not_be_resolved_is_tried_again() {
    let f = start_api_full(
        project_case_a(&["project:read"]),
        BootstrapMode::Auto,
        // No upstream token: the resolve call cannot authenticate, exactly as a locked store
        false,
        vec![],
        Some(vec![sekimore_relay::config::BoardRef {
            org: None,
            user: Some("Amakata".into()),
            number: 2,
            permissions: None,
            upstream: None,
        }]),
    )
    .await;
    let r = ApiRequest {
        board: Some(2),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/project/list", Some(&f.token), &r).await;
    assert_eq!(code, 403, "{:?}", resp.error);
    let msg = resp.error.unwrap_or_default();
    assert!(
        msg.contains("sgw unlock"),
        "a declared board that would not resolve must not read as one that was never configured: {msg}"
    );

    // The token arrives (the operator unlocked). The same request has to work now — the failure
    // must not have been cached.
    f.tokens
        .save("upstream.test", "gho_test", "repo")
        .await
        .unwrap();
    let (code, resp) = post(f.addr, "/project/list", Some(&f.token), &r).await;
    assert_eq!(
        code, 200,
        "a failed resolve was remembered: {:?}",
        resp.error
    );
}

// ---- #277: per-board permissions ----

/// Two boards on one project: board 3 adds project:update_item, board 2 takes project:read away.
fn project_with_board_deltas() -> sekimore_relay::policy::Project {
    project_case_a(&["project:read"])
        .with_board("users/tester/projects/2", &[], &["project:read"])
        .with_board("users/tester/projects/3", &["project:update_item"], &[])
}

#[tokio::test]
async fn a_board_may_allow_more_than_the_project_and_the_other_board_does_not_get_it() {
    let f = start_api_with_boards(
        project_with_board_deltas(),
        BootstrapMode::Auto,
        true,
        vec![board(2, "PVT_two"), board(3, "PVT_three")],
    )
    .await;
    let update = |n: u32| ApiRequest {
        board: Some(n),
        item_id: "PVTI_1".into(),
        field_id: "PVTSSF_1".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/project/update-item", Some(&f.token), &update(3)).await;
    assert_eq!(code, 200, "board 3 allows it: {:?}", resp.error);
    assert!(
        recorded(&f.recorder)
            .iter()
            .any(|c| c.path.contains("graphql")),
        "the update reached upstream"
    );
    // the adversarial case is the other declared board, not a foreign one
    let (code, resp) = post(f.addr, "/project/update-item", Some(&f.token), &update(2)).await;
    assert_eq!(code, 403);
    let msg = resp.error.unwrap_or_default();
    assert!(
        msg.contains("users/tester/projects/2") && msg.contains("project:update_item"),
        "the refusal names the board and the key: {msg}"
    );
    assert_eq!(
        recorded(&f.recorder)
            .iter()
            .filter(|c| c.path.contains("graphql"))
            .count(),
        1,
        "nothing more reached upstream"
    );
}

#[tokio::test]
async fn a_board_deny_beats_the_project_wide_allow_by_number_and_by_id() {
    let f = start_api_with_boards(
        project_with_board_deltas(),
        BootstrapMode::Auto,
        true,
        vec![board(2, "PVT_two"), board(3, "PVT_three")],
    )
    .await;
    let by_number = ApiRequest {
        board: Some(2),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/project/list", Some(&f.token), &by_number).await;
    assert_eq!(code, 403, "{:?}", resp.error);
    assert!(
        resp.error
            .unwrap_or_default()
            .contains("users/tester/projects/2"),
        "names the board"
    );
    // --project-id takes the same gate as --board
    let by_id = ApiRequest {
        project_id: "PVT_two".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, _) = post(f.addr, "/project/list", Some(&f.token), &by_id).await;
    assert_eq!(code, 403);
    assert!(recorded(&f.recorder).is_empty(), "nothing reached upstream");
    let other = ApiRequest {
        board: Some(3),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/project/list", Some(&f.token), &other).await;
    assert_eq!(code, 200, "{:?}", resp.error);
}

#[tokio::test]
async fn a_key_no_layer_grants_is_refused_before_any_board_is_named() {
    // project:add_item is granted nowhere: the refusal is about the permission, and says nothing
    // about boards (the_permission_is_checked_before_the_board, kept)
    let f = start_api_with_boards(
        project_with_board_deltas(),
        BootstrapMode::Auto,
        true,
        vec![board(2, "PVT_two"), board(3, "PVT_three")],
    )
    .await;
    let r = ApiRequest {
        board: Some(3),
        content_id: "I_1".into(),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/project/add-item", Some(&f.token), &r).await;
    assert_eq!(code, 403);
    let msg = resp.error.unwrap_or_default();
    assert!(msg.contains("project:add_item"), "{msg}");
    assert!(!msg.contains("projects/"), "no board is named: {msg}");
}

#[tokio::test]
async fn whoami_lists_each_board_with_its_delta() {
    let f = start_api_full(
        project_with_board_deltas(),
        BootstrapMode::Auto,
        true,
        vec![board(2, "PVT_two"), board(3, "PVT_three")],
        Some(vec![
            sekimore_relay::config::BoardRef {
                org: None,
                user: Some("tester".into()),
                number: 2,
                permissions: None,
                upstream: None,
            },
            sekimore_relay::config::BoardRef {
                org: None,
                user: Some("tester".into()),
                number: 3,
                permissions: None,
                upstream: None,
            },
        ]),
    )
    .await;
    let (code, resp) = post(f.addr, "/whoami", Some(&f.token), &ApiRequest::default()).await;
    assert_eq!(code, 200);
    let msg = resp.message.unwrap_or_default();
    assert!(msg.contains("boards (--board <number>"), "{msg}");
    assert!(
        msg.contains("users/tester/projects/2 -project:read"),
        "{msg}"
    );
    assert!(
        msg.contains("users/tester/projects/3 +project:update_item"),
        "{msg}"
    );
}

// ---- #291: a board on another upstream ----

/// A board declared with `upstream: ghe.example.com` is resolved there and asked there, whatever
/// `--repo` / `SEKIMORE_REPO` name (the anchor repository lives on github.com here). Before,
/// the GraphQL call went to the anchor's upstream with the GHE's node id, and github.com
/// answered "could not resolve to a node".
#[tokio::test]
async fn a_board_on_another_upstream_is_asked_there_whatever_repo_names() {
    let f = start_api_full(
        project_case_a(&["project:read"]),
        BootstrapMode::Auto,
        true,
        vec![],
        Some(vec![sekimore_relay::config::BoardRef {
            org: Some("acme".into()),
            user: None,
            number: 1,
            permissions: None,
            upstream: Some("ghe.example.com".into()),
        }]),
    )
    .await;
    let r = ApiRequest {
        board: Some(1),
        ..req("LibOrg/awesome-lib")
    };
    let (code, resp) = post(f.addr, "/project/list", Some(&f.token), &r).await;
    assert_eq!(code, 200, "{:?}", resp.error);
    let ghe = recorded(&f.ghe_recorder);
    assert!(
        ghe.iter().any(|c| c
            .body
            .to_string()
            .contains("projectV2(number:$number){ id }")),
        "the board is resolved on its own upstream"
    );
    assert!(
        ghe.iter()
            .any(|c| c.body.to_string().contains("PVT_board2")),
        "and listed there: {ghe:?}"
    );
    assert!(
        recorded(&f.recorder)
            .iter()
            .all(|c| !c.path.contains("graphql")),
        "nothing about the board reaches the anchor repository's upstream: {:?}",
        recorded(&f.recorder)
    );
    // whoami says where the board lives
    let (code, resp) = post(f.addr, "/whoami", Some(&f.token), &ApiRequest::default()).await;
    assert_eq!(code, 200);
    let msg = resp.message.unwrap_or_default();
    assert!(
        msg.contains("orgs/acme/projects/1 (on ghe.example.com)"),
        "{msg}"
    );
}
