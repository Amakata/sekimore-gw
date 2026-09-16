//! 各エンドポイント。要求の必須項目を確かめ、`Project::authorize` で証明を得て `GitHub` に渡す。

use std::time::SystemTime;

use hyper::body::Incoming;
use hyper::{Request, StatusCode};
use serde_json::Value;

use super::types::{ApiRequest, ApiResponse, BootstrapRequest, BootstrapResponse};
use super::{read_body, ApiContext, ApiError};
use crate::audit::Actor;
use crate::config::BootstrapMode;
use crate::github::GitHub;
use crate::policy::{Action, Authorized, Resource};
use crate::ssh::authorized_keys::Added;
use crate::tokens::TokenRecord;

/// 証明が指す repo の上流の GitHub client（上流ごとに token / API base が違う。0.2.0）。
fn gh<'a>(ctx: &'a ApiContext, auth: &Authorized<'_>) -> Result<&'a GitHub, ApiError> {
    let host = ctx.project.host_of(auth.policy());
    let key = if host.is_empty() {
        ctx.git_domain.as_str()
    } else {
        host
    };
    ctx.githubs
        .get(key)
        .map(|g| g.as_ref())
        .ok_or_else(|| ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: format!("upstream API for {key} is not configured on the gateway"),
        })
}

fn need(cond: bool, msg: &str) -> Result<(), ApiError> {
    if cond {
        Ok(())
    } else {
        Err(ApiError::bad_request(msg))
    }
}

/// Projects v2 は org 単位なので repo 省略可。ポリシーの anchor は案件の先頭リポジトリ。
fn project_anchor<'a>(ctx: &'a ApiContext, req: &'a ApiRequest) -> Result<&'a str, ApiError> {
    if !req.repo.is_empty() {
        return Ok(&req.repo);
    }
    ctx.project
        .repos
        .first()
        .map(|r| r.full_name.as_str())
        .ok_or_else(|| ApiError::forbidden("project has no repositories"))
}

pub async fn dispatch(
    ctx: &ApiContext,
    path: &str,
    req: &ApiRequest,
    rec: &TokenRecord,
) -> Result<ApiResponse, ApiError> {
    match path {
        "/whoami" => whoami(ctx, rec),
        "/pr/create" => pr_create(ctx, req).await,
        "/pr/comment" => pr_comment(ctx, req).await,
        "/pr/review" => pr_review(ctx, req).await,
        "/pr/merge" => pr_merge(ctx, req).await,
        "/pr/close" => pr_close(ctx, req).await,
        "/pr/status" => pr_status(ctx, req).await,
        "/ci/runs" => ci_runs(ctx, req).await,
        "/ci/jobs" => ci_jobs(ctx, req).await,
        "/ci/log" => ci_log(ctx, req).await,
        "/issue/create" => issue_create(ctx, req).await,
        "/issue/comment" => issue_comment(ctx, req).await,
        "/issue/close" => issue_close(ctx, req).await,
        "/issue/label" => issue_label(ctx, req).await,
        "/issue/assign" => issue_assign(ctx, req).await,
        "/project/add-item" => project_add_item(ctx, req).await,
        "/project/update-item" => project_update_item(ctx, req).await,
        "/project/list" => project_list(ctx, req).await,
        _ => Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: format!("unknown endpoint {path}"),
        }),
    }
}

// ---- 権限確認 ----

fn whoami(ctx: &ApiContext, rec: &TokenRecord) -> Result<ApiResponse, ApiError> {
    let repos: Vec<String> = ctx
        .project
        .repos
        .iter()
        .map(|r| format!("{} ({})", r.full_name, r.mode.as_str()))
        .collect();
    let perms = ctx.project.granted();
    let msg = format!(
        "project={} token={} expires={}\npermissions: {}\nrepos:\n  {}",
        rec.project,
        rec.label,
        humantime::format_rfc3339_seconds(rec.expires_at),
        if perms.is_empty() {
            "(none)".to_string()
        } else {
            perms.join(" ")
        },
        repos.join("\n  ")
    );
    Ok(ApiResponse {
        message: Some(msg),
        ..Default::default()
    })
}

// ---- PR ----

async fn pr_create(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.repo.is_empty(), "repo is required")?;
    need(
        !req.head.is_empty() && !req.base.is_empty() && !req.title.is_empty(),
        "head, base and title are required",
    )?;
    let auth = ctx.project.authorize_pr(&req.repo, &req.base)?;
    let pr = gh(ctx, &auth)?
        .create_pull_request(&auth, &req.head, &req.base, &req.title, &req.body)
        .await?;
    Ok(ApiResponse {
        number: Some(pr.number),
        url: Some(pr.html_url),
        node_id: Some(pr.node_id),
        ..Default::default()
    })
}

async fn pr_comment(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.repo.is_empty(), "repo is required")?;
    need(
        req.number != 0 && !req.body.is_empty(),
        "number and body are required",
    )?;
    let auth = ctx
        .project
        .authorize(&req.repo, Resource::Pr, Action::Comment)?;
    gh(ctx, &auth)?
        .comment_pull_request(&auth, req.number, &req.body)
        .await?;
    Ok(ApiResponse::default())
}

async fn pr_review(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.repo.is_empty(), "repo is required")?;
    need(
        req.number != 0 && !req.event.is_empty(),
        "number and event are required",
    )?;
    need(
        matches!(
            req.event.as_str(),
            "APPROVE" | "REQUEST_CHANGES" | "COMMENT"
        ),
        "event must be APPROVE, REQUEST_CHANGES or COMMENT",
    )?;
    let auth = ctx
        .project
        .authorize(&req.repo, Resource::Pr, Action::Review)?;
    gh(ctx, &auth)?
        .review_pull_request(&auth, req.number, &req.event, &req.body)
        .await?;
    Ok(ApiResponse::default())
}

async fn pr_merge(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.repo.is_empty(), "repo is required")?;
    need(req.number != 0, "number is required")?;
    let auth = ctx
        .project
        .authorize(&req.repo, Resource::Pr, Action::Merge)?;
    gh(ctx, &auth)?
        .merge_pull_request(&auth, req.number)
        .await?;
    Ok(ApiResponse::default())
}

async fn pr_close(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.repo.is_empty(), "repo is required")?;
    need(req.number != 0, "number is required")?;
    let auth = ctx
        .project
        .authorize(&req.repo, Resource::Pr, Action::Close)?;
    gh(ctx, &auth)?
        .close_pull_request(&auth, req.number)
        .await?;
    Ok(ApiResponse::default())
}

async fn pr_status(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.repo.is_empty(), "repo is required")?;
    need(req.number != 0, "number is required")?;
    let auth = ctx
        .project
        .authorize(&req.repo, Resource::Pr, Action::Read)?;
    let st = gh(ctx, &auth)?
        .pull_request_status(&auth, req.number)
        .await?;
    let raw = serde_json::to_value(&st).unwrap_or(serde_json::Value::Null);
    let n = st.checks.len();
    let msg = format!(
        "PR #{} [{}{}] checks: {} ({} total)",
        st.number,
        st.state,
        if st.merged { ", merged" } else { "" },
        st.rollup,
        n
    );
    Ok(ApiResponse {
        ok: true,
        number: Some(st.number),
        raw: Some(raw),
        message: Some(msg),
        ..Default::default()
    })
}

async fn ci_runs(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.repo.is_empty(), "repo is required")?;
    need(
        !req.git_ref.is_empty(),
        "ref (tag / branch / sha) is required",
    )?;
    let auth = ctx
        .project
        .authorize(&req.repo, Resource::Ci, Action::Read)?;
    let runs = gh(ctx, &auth)?.ci_runs(&auth, &req.git_ref).await?;
    let raw = serde_json::to_value(&runs).unwrap_or(serde_json::Value::Null);
    let msg = runs
        .iter()
        .map(|r| {
            let st = if r.conclusion.is_empty() {
                r.status.as_str()
            } else {
                r.conclusion.as_str()
            };
            format!(
                "{} [{}] event={} run_id={} {}",
                r.name, st, r.event, r.id, r.created_at
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(ApiResponse {
        ok: true,
        raw: Some(raw),
        message: Some(if msg.is_empty() {
            format!("no workflow runs for ref {}", req.git_ref)
        } else {
            msg
        }),
        ..Default::default()
    })
}

async fn ci_jobs(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.repo.is_empty(), "repo is required")?;
    need(
        req.number != 0 || req.run_id != 0,
        "number or run_id is required",
    )?;
    let auth = ctx
        .project
        .authorize(&req.repo, Resource::Ci, Action::Read)?;
    let jobs = if req.run_id != 0 {
        gh(ctx, &auth)?.ci_jobs_for_run(&auth, req.run_id).await?
    } else {
        gh(ctx, &auth)?.ci_jobs(&auth, req.number).await?
    };
    let raw = serde_json::to_value(&jobs).unwrap_or(serde_json::Value::Null);
    let msg = jobs
        .iter()
        .map(|j| {
            let st = if j.conclusion.is_empty() {
                j.status.as_str()
            } else {
                j.conclusion.as_str()
            };
            format!("{} [{}] job_id={}", j.name, st, j.id)
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(ApiResponse {
        ok: true,
        raw: Some(raw),
        message: Some(if msg.is_empty() {
            "no CI jobs for this PR".into()
        } else {
            msg
        }),
        ..Default::default()
    })
}

async fn ci_log(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.repo.is_empty(), "repo is required")?;
    let auth = ctx
        .project
        .authorize(&req.repo, Resource::Ci, Action::Read)?;
    let window = if req.window == 0 {
        200
    } else {
        req.window as usize
    };
    let before = req.before.map(|b| b as usize);
    // job_id 指定が無ければ、PR の失敗ジョブ (無ければ最後のジョブ) を自動選択
    let (job_id, name, concl) = if req.job_id != 0 {
        (req.job_id, String::new(), String::new())
    } else {
        need(
            req.number != 0 || req.run_id != 0,
            "number, run_id or job_id is required",
        )?;
        let jobs = if req.run_id != 0 {
            gh(ctx, &auth)?.ci_jobs_for_run(&auth, req.run_id).await?
        } else {
            gh(ctx, &auth)?.ci_jobs(&auth, req.number).await?
        };
        let pick = jobs
            .iter()
            .find(|j| j.conclusion == "failure")
            .or_else(|| jobs.last())
            .ok_or_else(|| ApiError::bad_request("no CI jobs for this PR"))?;
        (pick.id, pick.name.clone(), pick.conclusion.clone())
    };
    let page = gh(ctx, &auth)?
        .ci_job_log(&auth, job_id, &name, &concl, window, before)
        .await?;
    let raw = serde_json::to_value(&page).unwrap_or(serde_json::Value::Null);
    Ok(ApiResponse {
        ok: true,
        raw: Some(raw),
        ..Default::default()
    })
}

// ---- Issue ----

async fn issue_create(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.repo.is_empty(), "repo is required")?;
    need(!req.title.is_empty(), "title is required")?;
    let auth = ctx
        .project
        .authorize(&req.repo, Resource::Issue, Action::Create)?;
    // ラベル付与は別権限。付けるなら issue:label が必要
    let label_auth = if req.labels.is_empty() {
        None
    } else {
        Some(
            ctx.project
                .authorize(&req.repo, Resource::Issue, Action::Label)?,
        )
    };
    let labels = label_auth.as_ref().map(|a| (a, req.labels.as_slice()));
    let iss = gh(ctx, &auth)?
        .create_issue(&auth, &req.title, &req.body, labels)
        .await?;
    Ok(ApiResponse {
        number: Some(iss.number),
        url: Some(iss.html_url),
        node_id: Some(iss.node_id),
        ..Default::default()
    })
}

async fn issue_comment(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.repo.is_empty(), "repo is required")?;
    need(
        req.number != 0 && !req.body.is_empty(),
        "number and body are required",
    )?;
    let auth = ctx
        .project
        .authorize(&req.repo, Resource::Issue, Action::Comment)?;
    gh(ctx, &auth)?
        .comment_issue(&auth, req.number, &req.body)
        .await?;
    Ok(ApiResponse::default())
}

async fn issue_close(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.repo.is_empty(), "repo is required")?;
    need(req.number != 0, "number is required")?;
    let auth = ctx
        .project
        .authorize(&req.repo, Resource::Issue, Action::Close)?;
    gh(ctx, &auth)?.close_issue(&auth, req.number).await?;
    Ok(ApiResponse::default())
}

async fn issue_label(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.repo.is_empty(), "repo is required")?;
    need(
        req.number != 0 && !req.labels.is_empty(),
        "number and labels are required",
    )?;
    let auth = ctx
        .project
        .authorize(&req.repo, Resource::Issue, Action::Label)?;
    gh(ctx, &auth)?
        .label_issue(&auth, req.number, &req.labels)
        .await?;
    Ok(ApiResponse::default())
}

async fn issue_assign(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.repo.is_empty(), "repo is required")?;
    need(
        req.number != 0 && !req.assignees.is_empty(),
        "number and assignees are required",
    )?;
    let auth = ctx
        .project
        .authorize(&req.repo, Resource::Issue, Action::Assign)?;
    gh(ctx, &auth)?
        .assign_issue(&auth, req.number, &req.assignees)
        .await?;
    Ok(ApiResponse::default())
}

// ---- Projects ----

async fn project_add_item(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(
        !req.project_id.is_empty() && !req.content_id.is_empty(),
        "project_id and content_id are required",
    )?;
    let anchor = project_anchor(ctx, req)?;
    let auth = ctx
        .project
        .authorize(anchor, Resource::Project, Action::AddItem)?;
    let item = gh(ctx, &auth)?
        .add_project_item(&auth, &req.project_id, &req.content_id)
        .await?;
    Ok(ApiResponse {
        item_id: Some(item),
        ..Default::default()
    })
}

async fn project_update_item(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(
        !req.project_id.is_empty() && !req.item_id.is_empty() && !req.field_id.is_empty(),
        "project_id, item_id and field_id are required",
    )?;
    let anchor = project_anchor(ctx, req)?;
    let auth = ctx
        .project
        .authorize(anchor, Resource::Project, Action::UpdateItem)?;
    let value = req.value.clone().unwrap_or(Value::Null);
    gh(ctx, &auth)?
        .update_project_item_field(&auth, &req.project_id, &req.item_id, &req.field_id, value)
        .await?;
    Ok(ApiResponse::default())
}

async fn project_list(ctx: &ApiContext, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
    need(!req.project_id.is_empty(), "project_id is required")?;
    let anchor = project_anchor(ctx, req)?;
    let auth = ctx
        .project
        .authorize(anchor, Resource::Project, Action::Read)?;
    let first = if req.first == 0 || req.first > 100 {
        20
    } else {
        req.first
    };
    let raw = gh(ctx, &auth)?
        .list_project_items(&auth, &req.project_id, first)
        .await?;
    Ok(ApiResponse {
        raw: Some(raw),
        ..Default::default()
    })
}

// ---- ブートストラップ（認証なし） ----

pub async fn bootstrap(
    ctx: &ApiContext,
    req: Request<Incoming>,
    peer_ip: &str,
) -> Result<BootstrapResponse, ApiError> {
    if ctx.bootstrap == BootstrapMode::Manual {
        ctx.audit.deny(
            "bootstrap_denied",
            Actor::Agent,
            "bootstrap is manual",
            &[("peer", peer_ip)],
        );
        return Err(ApiError { status: StatusCode::NOT_FOUND, message: "bootstrap is disabled (relay.bootstrap: manual); ask the operator to run `sekimore-relay add-key` and `token`".into() });
    }
    if ctx.bootstrap_disabled_path.exists() {
        ctx.audit.deny(
            "bootstrap_denied",
            Actor::Agent,
            "kill-switch",
            &[("peer", peer_ip)],
        );
        return Err(ApiError::forbidden(
            "bootstrap is disabled by the operator (sekimore-relay bootstrap enable to re-allow)",
        ));
    }
    if !ctx.bootstrap_rate_ok() {
        ctx.audit.deny(
            "bootstrap_denied",
            Actor::Agent,
            "rate limited",
            &[("peer", peer_ip)],
        );
        return Err(ApiError {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "too many bootstrap requests; retry later".into(),
        });
    }
    let body = read_body(req, ctx.body_cap).await?;
    let breq: BootstrapRequest = serde_json::from_slice(&body).map_err(|e| {
        ctx.audit.deny(
            "bootstrap_denied",
            Actor::Agent,
            &format!("invalid JSON: {e}"),
            &[("peer", peer_ip)],
        );
        ApiError::bad_request(format!("invalid JSON: {e}"))
    })?;
    let added = ctx.keys.add(&breq.public_key).map_err(|e| {
        ctx.audit.deny(
            "bootstrap_denied",
            Actor::Agent,
            &e.to_string(),
            &[("peer", peer_ip)],
        );
        ApiError::bad_request(e.to_string())
    })?;
    let (fingerprint, is_new) = match added {
        Added::New { fingerprint } => (fingerprint, true),
        Added::AlreadyPresent { fingerprint } => (fingerprint, false),
    };
    // 同じ鍵からの再 bootstrap（コンテナ再作成など）は前のトークンを失効させる: 鍵 1 本につき有効トークンは 1 つ
    let revoked_previous = ctx.tokens.revoke_by_fingerprint(&fingerprint).unwrap_or(0);
    let (token, rec) = ctx
        .tokens
        .issue_for(&ctx.project.name, ctx.token_ttl, Some(&fingerprint))
        .map_err(|e| ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("cannot issue token: {e}"),
        })?;
    let label = breq.label.unwrap_or_default();
    ctx.audit.log(
        "bootstrap_ok",
        Actor::Agent,
        &[
            ("fingerprint", &fingerprint),
            ("key_added", if is_new { "true" } else { "false" }),
            ("token_label", &rec.label),
            ("revoked_previous", &revoked_previous.to_string()),
            ("client_label", &label),
            ("peer", peer_ip),
        ],
    );
    Ok(BootstrapResponse {
        ok: true,
        error: None,
        fingerprint: Some(fingerprint),
        added: is_new,
        token: Some(token),
        token_expires: Some(humantime::format_rfc3339_seconds(rec.expires_at).to_string()),
        project: Some(ctx.project.name.clone()),
        repos: ctx
            .project
            .repos
            .iter()
            .map(|r| r.full_name.clone())
            .collect(),
        git_domain: Some(ctx.git_domain.clone()),
        upstream: Some(ctx.upstream.clone()),
        git_domains: ctx.git_domains.clone(),
    })
}

#[allow(dead_code)]
fn now() -> SystemTime {
    SystemTime::now()
}
