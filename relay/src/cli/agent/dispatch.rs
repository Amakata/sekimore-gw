//! Subcommand → endpoint. Fills an `ApiRequest` from the parsed flags, posts it and prints.
//!
//! Split from the clap tree so that the two sides of an endpoint — what the agent types and where
//! it goes — are each readable on their own.

use anyhow::{anyhow, Context};
use serde_json::Value;

use super::client::AgentClient;
use super::cmd::{AgentCmd, CiCmd, IssueCmd, PrCmd, ProjectCmd, ReleaseCmd, RepoCmd, SecurityCmd};
use super::print::{
    print_ci_log, print_pr_diff, print_pr_status, print_project_items, print_response,
};
use super::NAME;
use crate::api::types::ApiRequest;

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

/// The body of `sekimore guide`. Embedded in the binary so it cannot drift from the CLI version (relay/share/agent-guide.*.md is the source of truth).
pub const AGENT_GUIDE_EN: &str = include_str!("../../../share/agent-guide.en.md");
pub const AGENT_GUIDE_JA: &str = include_str!("../../../share/agent-guide.ja.md");

/// Uses the requested language, or the environment's language when none is given. An unsupported request falls back to English.
pub fn guide_for(lang: Option<&str>) -> &'static str {
    let chosen = lang
        .and_then(crate::i18n::normalize)
        .unwrap_or_else(crate::i18n::lang);
    match chosen {
        "ja" => AGENT_GUIDE_JA,
        _ => AGENT_GUIDE_EN,
    }
}

pub async fn run(repo: Option<&str>, cmd: AgentCmd) -> anyhow::Result<i32> {
    if let AgentCmd::Guide { lang } = &cmd {
        // Needs neither connection details nor a token (it never touches the network)
        print!("{}", guide_for(lang.as_deref()));
        return Ok(0);
    }
    let client = AgentClient::from_env()?;
    let repo = repo.unwrap_or("").to_string();
    let mut req = ApiRequest {
        repo,
        ..Default::default()
    };
    // Endpoints come from the command tree in `cmd.rs`, beside the flags they belong to, so this
    // match only has to fill the request. `group` is the path of a top-level command that has one
    // of its own (whoami, search); the grouping variants answer None and read `leaf` instead.
    let group = cmd.path().unwrap_or_default();
    let path = match cmd {
        AgentCmd::Whoami {} => group,
        AgentCmd::Guide { .. } => unreachable!("guide is handled before connecting"),
        AgentCmd::Pr { cmd } => {
            let leaf = cmd.path();
            match cmd {
                PrCmd::Create {
                    head,
                    base,
                    title,
                    body,
                    draft,
                } => {
                    req.head = head;
                    req.base = base;
                    req.title = title;
                    req.body = body;
                    req.pr_draft = draft;
                    leaf
                }
                PrCmd::Draft { number } => {
                    req.number = number;
                    req.pr_draft = true;
                    leaf
                }
                PrCmd::Ready { number } => {
                    req.number = number;
                    req.pr_draft = false;
                    leaf
                }
                PrCmd::Comment { number, body } => {
                    req.number = number;
                    req.body = body;
                    leaf
                }
                PrCmd::CommentEdit {
                    number,
                    comment_id,
                    body,
                    inline,
                } => {
                    req.number = number;
                    req.comment_id = comment_id;
                    req.body = body;
                    req.inline = inline;
                    leaf
                }
                PrCmd::CommentDelete {
                    number,
                    comment_id,
                    inline,
                } => {
                    req.number = number;
                    req.comment_id = comment_id;
                    req.inline = inline;
                    leaf
                }
                PrCmd::Reply {
                    number,
                    comment_id,
                    body,
                } => {
                    req.number = number;
                    req.comment_id = comment_id;
                    req.body = body;
                    leaf
                }
                PrCmd::Review {
                    number,
                    event,
                    body,
                    comment,
                    comments_file,
                } => {
                    req.number = number;
                    req.event = event;
                    req.body = body;
                    // #167: read here rather than in the relay — the file is the agent's, and a
                    // bad line should say which one before anything is sent upstream.
                    for c in &comment {
                        req.comments.push(
                            crate::api::types::ReviewComment::parse(c).map_err(|e| anyhow!(e))?,
                        );
                    }
                    if !comments_file.is_empty() {
                        let text = std::fs::read_to_string(&comments_file)
                            .with_context(|| format!("reading {comments_file}"))?;
                        let from_file: Vec<crate::api::types::ReviewComment> =
                            serde_json::from_str(&text).with_context(|| {
                                format!("{comments_file} is not [{{path, line, body}}, …]")
                            })?;
                        req.comments.extend(from_file);
                    }
                    leaf
                }
                PrCmd::Merge {
                    number,
                    method,
                    title,
                    message,
                    delete_branch,
                } => {
                    req.number = number;
                    req.method = method.unwrap_or_default();
                    req.title = title.unwrap_or_default();
                    // The merge commit's message rides in `body`, the field every other command uses
                    // for free text.
                    req.body = message.unwrap_or_default();
                    req.delete_branch = delete_branch;
                    leaf
                }
                PrCmd::Close { number } => {
                    req.number = number;
                    leaf
                }
                PrCmd::Reopen { number } => {
                    req.number = number;
                    leaf
                }
                PrCmd::Update {
                    number,
                    title,
                    body,
                    base,
                } => {
                    if title.is_none() && body.is_none() && base.is_none() {
                        eprintln!("{NAME}: pr update needs --title, --body or --base");
                        return Ok(2);
                    }
                    req.number = number;
                    req.title = title.unwrap_or_default();
                    req.body = body.unwrap_or_default();
                    req.base = base.unwrap_or_default();
                    leaf
                }
                PrCmd::RequestReview {
                    number,
                    reviewers,
                    teams,
                } => {
                    req.number = number;
                    req.reviewers = reviewers.map(|r| split_csv(&r)).unwrap_or_default();
                    req.team_reviewers = teams.map(|t| split_csv(&t)).unwrap_or_default();
                    leaf
                }
                PrCmd::Status { number, json } => {
                    req.number = number;
                    let resp = client.call(leaf, &req).await?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&resp.raw)?);
                    } else {
                        print_pr_status(&resp);
                    }
                    return Ok(if resp.ok { 0 } else { 1 });
                }
                PrCmd::View { number, json } => {
                    req.number = number;
                    return call_and_print(&client, leaf, &req, json).await;
                }
                PrCmd::Files { number, json } => {
                    req.number = number;
                    return call_and_print(&client, leaf, &req, json).await;
                }
                PrCmd::Diff {
                    number,
                    path,
                    window,
                    before,
                    json,
                } => {
                    req.number = number;
                    req.file_path = path.unwrap_or_default();
                    req.window = window;
                    req.before = before;
                    let resp = client.call(leaf, &req).await?;
                    if !resp.ok {
                        eprintln!("{NAME}: {}", resp.error.unwrap_or_default());
                        return Ok(1);
                    }
                    if json {
                        println!("{}", serde_json::to_string_pretty(&resp.raw)?);
                    } else {
                        print_pr_diff(&resp);
                    }
                    return Ok(0);
                }
                PrCmd::Comments {
                    number,
                    limit,
                    json,
                } => {
                    req.number = number;
                    req.first = limit;
                    return call_and_print(&client, leaf, &req, json).await;
                }
                PrCmd::List {
                    state,
                    base,
                    limit,
                    json,
                } => {
                    req.state = state;
                    req.base = base.unwrap_or_default();
                    req.first = limit;
                    return call_and_print(&client, leaf, &req, json).await;
                }
            }
        }
        AgentCmd::Ci { cmd } => {
            let leaf = cmd.path();
            match cmd {
                CiCmd::Runs { git_ref } => {
                    req.git_ref = git_ref;
                    leaf
                }
                CiCmd::Jobs { number, run_id } => {
                    if number.is_none() && run_id.is_none() {
                        eprintln!("{NAME}: ci jobs needs --number <pr> or --run-id <run>");
                        return Ok(2);
                    }
                    req.number = number.unwrap_or(0);
                    req.run_id = run_id.unwrap_or(0);
                    leaf
                }
                CiCmd::Rerun { run_id, all } => {
                    req.run_id = run_id;
                    req.all = all;
                    leaf
                }
                CiCmd::Dispatch {
                    workflow,
                    git_ref,
                    input,
                } => {
                    req.workflow = workflow;
                    req.git_ref = git_ref;
                    for kv in &input {
                        let (k, v) = kv
                            .split_once('=')
                            .ok_or_else(|| anyhow!("expected key=value, got {kv:?}"))?;
                        req.inputs.insert(k.to_string(), v.to_string());
                    }
                    leaf
                }
                CiCmd::Cancel { run_id } => {
                    req.run_id = run_id;
                    leaf
                }
                CiCmd::Log {
                    number,
                    run_id,
                    job_id,
                    window,
                    before,
                    json,
                } => {
                    if let Some(n) = number {
                        req.number = n;
                    }
                    if let Some(r) = run_id {
                        req.run_id = r;
                    }
                    if let Some(j) = job_id {
                        req.job_id = j;
                    }
                    req.window = window;
                    req.before = before;
                    let resp = client.call(leaf, &req).await?;
                    if !resp.ok {
                        eprintln!("{NAME}: {}", resp.error.unwrap_or_default());
                        return Ok(1);
                    }
                    if json {
                        println!("{}", serde_json::to_string_pretty(&resp.raw)?);
                    } else {
                        print_ci_log(&resp);
                    }
                    return Ok(0);
                }
            }
        }
        AgentCmd::Issue { cmd } => {
            let leaf = cmd.path();
            match cmd {
                IssueCmd::Create {
                    title,
                    body,
                    labels,
                } => {
                    req.title = title;
                    req.body = body;
                    req.labels = labels.map(|l| split_csv(&l)).unwrap_or_default();
                    leaf
                }
                IssueCmd::Comment { number, body } => {
                    req.number = number;
                    req.body = body;
                    leaf
                }
                IssueCmd::CommentEdit {
                    number,
                    comment_id,
                    body,
                } => {
                    req.number = number;
                    req.comment_id = comment_id;
                    req.body = body;
                    leaf
                }
                IssueCmd::CommentDelete { number, comment_id } => {
                    req.number = number;
                    req.comment_id = comment_id;
                    leaf
                }
                IssueCmd::Update {
                    number,
                    title,
                    body,
                } => {
                    req.number = number;
                    req.title = title.unwrap_or_default();
                    req.body = body.unwrap_or_default();
                    leaf
                }
                IssueCmd::Close { number } => {
                    req.number = number;
                    leaf
                }
                IssueCmd::Reopen { number } => {
                    req.number = number;
                    leaf
                }
                IssueCmd::Label { number, labels } => {
                    req.number = number;
                    req.labels = split_csv(&labels);
                    leaf
                }
                IssueCmd::Unlabel { number, labels } => {
                    req.number = number;
                    req.labels = split_csv(&labels);
                    leaf
                }
                IssueCmd::Assign { number, assignees } => {
                    req.number = number;
                    req.assignees = split_csv(&assignees);
                    leaf
                }
                IssueCmd::Unassign { number, assignees } => {
                    req.number = number;
                    req.assignees = split_csv(&assignees);
                    leaf
                }
                IssueCmd::View { number, json } => {
                    req.number = number;
                    return call_and_print(&client, leaf, &req, json).await;
                }
                IssueCmd::Comments {
                    number,
                    limit,
                    json,
                } => {
                    req.number = number;
                    req.first = limit;
                    return call_and_print(&client, leaf, &req, json).await;
                }
                IssueCmd::List {
                    state,
                    labels,
                    assignee,
                    limit,
                    json,
                } => {
                    req.state = state;
                    req.labels = labels.map(|l| split_csv(&l)).unwrap_or_default();
                    req.assignee = assignee.unwrap_or_default();
                    req.first = limit;
                    return call_and_print(&client, leaf, &req, json).await;
                }
            }
        }
        AgentCmd::Project { cmd } => {
            let leaf = cmd.path();
            match cmd {
                ProjectCmd::AddItem {
                    board,
                    project_id,
                    content_id,
                } => {
                    req.board = board;
                    req.project_id = project_id.unwrap_or_default();
                    req.content_id = content_id;
                    leaf
                }
                ProjectCmd::UpdateItem {
                    board,
                    project_id,
                    item_id,
                    field_id,
                    value,
                } => {
                    req.board = board;
                    req.project_id = project_id.unwrap_or_default();
                    req.item_id = item_id;
                    req.field_id = field_id;
                    req.value = Some(
                        serde_json::from_str::<Value>(&value)
                            .unwrap_or_else(|_| serde_json::json!({"text": value})),
                    );
                    leaf
                }
                ProjectCmd::List {
                    board,
                    project_id,
                    first,
                } => {
                    req.board = board;
                    req.project_id = project_id.unwrap_or_default();
                    req.first = first;
                    leaf
                }
                ProjectCmd::Fields {
                    board,
                    project_id,
                    first,
                } => {
                    req.board = board;
                    req.project_id = project_id.unwrap_or_default();
                    req.first = first;
                    leaf
                }
            }
        }
        AgentCmd::Repo { cmd } => {
            let leaf = cmd.path();
            match cmd {
                RepoCmd::Vocabulary {} => leaf,
            }
        }
        AgentCmd::Security { cmd } => {
            let leaf = cmd.path();
            let json = match cmd {
                SecurityCmd::Alerts { state, json } => {
                    req.state = state;
                    json
                }
                SecurityCmd::View { number, json } => {
                    req.number = number;
                    json
                }
                SecurityCmd::Dismiss {
                    number,
                    reason,
                    comment,
                } => {
                    req.number = number;
                    req.reason = reason;
                    req.body = comment.unwrap_or_default();
                    false
                }
                SecurityCmd::Reopen { number } => {
                    req.number = number;
                    false
                }
            };
            return call_and_print(&client, leaf, &req, json).await;
        }
        AgentCmd::Search { query, limit, json } => {
            req.query = query;
            req.first = limit;
            let resp = client.call(group, &req).await?;
            if !resp.ok {
                eprintln!("{NAME}: denied: {}", resp.error.unwrap_or_default());
                return Ok(1);
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&resp.raw)?);
            } else if let Some(m) = &resp.message {
                println!("{m}");
            }
            return Ok(0);
        }
        AgentCmd::Release { cmd } => {
            let leaf = cmd.path();
            match cmd {
                ReleaseCmd::Create {
                    tag,
                    title,
                    notes,
                    notes_file,
                    generate_notes,
                    draft,
                    prerelease,
                } => {
                    req.tag = tag;
                    req.title = title.unwrap_or_default();
                    // --notes-file is the way to pass a long body without fighting the shell.
                    req.body = match (notes, notes_file) {
                        (Some(_), Some(_)) => {
                            return Err(anyhow!("pass either --notes or --notes-file, not both"))
                        }
                        (Some(n), None) => n,
                        (None, Some(f)) => std::fs::read_to_string(&f)
                            .with_context(|| format!("read {}", f.display()))?,
                        (None, None) => String::new(),
                    };
                    req.generate_notes = generate_notes;
                    req.draft = draft;
                    req.prerelease = prerelease;
                    leaf
                }
                ReleaseCmd::Edit {
                    tag,
                    title,
                    notes,
                    notes_file,
                    draft,
                    prerelease,
                } => {
                    if title.is_none()
                        && notes.is_none()
                        && notes_file.is_none()
                        && draft.is_none()
                        && prerelease.is_none()
                    {
                        eprintln!(
                        "{NAME}: release edit needs --title, --notes, --notes-file, --draft or --prerelease"
                    );
                        return Ok(2);
                    }
                    req.tag = tag;
                    req.title = title.unwrap_or_default();
                    req.body = match (notes, notes_file) {
                        (Some(_), Some(_)) => {
                            return Err(anyhow!("pass either --notes or --notes-file, not both"))
                        }
                        (Some(n), None) => n,
                        (None, Some(f)) => std::fs::read_to_string(&f)
                            .with_context(|| format!("read {}", f.display()))?,
                        (None, None) => String::new(),
                    };
                    req.set_draft = draft;
                    req.set_prerelease = prerelease;
                    leaf
                }
                ReleaseCmd::View { tag } => {
                    req.tag = tag;
                    leaf
                }
                ReleaseCmd::List { limit } => {
                    req.first = limit;
                    leaf
                }
            }
        }
    };
    let resp = client.call(path, &req).await?;
    if !resp.ok {
        eprintln!("{NAME}: denied: {}", resp.error.unwrap_or_default());
        return Ok(1);
    }
    // project list carries the board's field values, which pretty-printed JSON buries
    if path == "/project/list" {
        print_project_items(&resp);
    } else {
        print_response(&resp);
    }
    Ok(0)
}

/// 0.2.8: the read commands all share one shape — call, then print either the raw JSON or the
/// human-readable message the relay already rendered.
async fn call_and_print(
    client: &AgentClient,
    path: &str,
    req: &ApiRequest,
    json: bool,
) -> anyhow::Result<i32> {
    let resp = client.call(path, req).await?;
    if !resp.ok {
        eprintln!("{NAME}: {}", resp.error.unwrap_or_default());
        return Ok(1);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&resp.raw)?);
    } else if let Some(m) = &resp.message {
        println!("{m}");
    }
    Ok(0)
}
