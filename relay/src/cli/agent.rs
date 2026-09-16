//! Agent-side CLI. It just calls the relay's plain endpoints (gh compatibility is not a goal).
//!
//! All the agent holds is a project token (a string that is worthless against the upstream).
//!
//! 0.2.4: help text is looked up at runtime from `relay/locales/*.json` (see `crate::i18n`).

use std::path::PathBuf;

use anyhow::{anyhow, Context};
use clap::{Args, Subcommand};
use serde_json::Value;

use crate::api::types::{ApiRequest, ApiResponse, BootstrapRequest, BootstrapResponse};
use crate::i18n::t;

pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:8420";

#[derive(Subcommand, Debug)]
pub enum AgentCmd {
    #[command(about = t("agent.whoami"))]
    Whoami,
    #[command(about = t("agent.guide"))]
    Guide {
        #[arg(long, help = t("agent.guide.lang"))]
        lang: Option<String>,
    },
    #[command(about = t("agent.pr"))]
    Pr {
        #[command(subcommand)]
        cmd: PrCmd,
    },
    #[command(about = t("agent.issue"))]
    Issue {
        #[command(subcommand)]
        cmd: IssueCmd,
    },
    #[command(about = t("agent.ci"))]
    Ci {
        #[command(subcommand)]
        cmd: CiCmd,
    },
    #[command(about = t("agent.project"))]
    Project {
        #[command(subcommand)]
        cmd: ProjectCmd,
    },
    #[command(about = t("agent.release"))]
    Release {
        #[command(subcommand)]
        cmd: ReleaseCmd,
    },
    #[command(about = t("agent.bootstrap"))]
    Bootstrap {
        #[arg(long, help = t("agent.bootstrap.pubkey_file"))]
        pubkey_file: PathBuf,
        #[arg(long, help = t("agent.bootstrap.label"))]
        label: Option<String>,
    },
}

#[derive(Args, Debug, Default)]
pub struct Number {
    #[arg(long, help = t("agent.number"))]
    pub number: u64,
}

#[derive(Subcommand, Debug)]
pub enum PrCmd {
    #[command(about = t("agent.pr.create"))]
    Create {
        #[arg(long, help = t("agent.pr.create.head"))]
        head: String,
        #[arg(long, help = t("agent.pr.create.base"))]
        base: String,
        #[arg(long, help = t("agent.pr.create.title"))]
        title: String,
        #[arg(long, default_value = "", help = t("agent.pr.create.body"))]
        body: String,
    },
    #[command(about = t("agent.pr.comment"))]
    Comment {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.body"))]
        body: String,
    },
    #[command(about = t("agent.pr.review"))]
    Review {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, default_value = "COMMENT", help = t("agent.pr.review.event"))]
        event: String,
        #[arg(long, default_value = "", help = t("agent.body"))]
        body: String,
    },
    #[command(about = t("agent.pr.merge"))]
    Merge {
        #[arg(long, help = t("agent.number"))]
        number: u64,
    },
    #[command(about = t("agent.pr.close"))]
    Close {
        #[arg(long, help = t("agent.number"))]
        number: u64,
    },
    #[command(about = t("agent.pr.status"))]
    Status {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.pr.status.json"))]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum CiCmd {
    #[command(about = t("agent.ci.runs"))]
    Runs {
        #[arg(long = "ref", help = t("agent.ci.runs.ref"))]
        git_ref: String,
    },
    #[command(about = t("agent.ci.jobs"))]
    Jobs {
        #[arg(long, help = t("agent.number"))]
        number: Option<u64>,
        #[arg(long, help = t("agent.ci.run_id"))]
        run_id: Option<u64>,
    },
    #[command(about = t("agent.ci.log"))]
    Log {
        #[arg(long, help = t("agent.ci.log.number"))]
        number: Option<u64>,
        #[arg(long, help = t("agent.ci.log.run_id"))]
        run_id: Option<u64>,
        #[arg(long, help = t("agent.ci.log.job_id"))]
        job_id: Option<u64>,
        #[arg(long, default_value = "200", help = t("agent.ci.log.window"))]
        window: u64,
        #[arg(long, help = t("agent.ci.log.before"))]
        before: Option<u64>,
        #[arg(long, help = t("agent.ci.log.json"))]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum IssueCmd {
    #[command(about = t("agent.issue.create"))]
    Create {
        #[arg(long, help = t("agent.issue.title"))]
        title: String,
        #[arg(long, default_value = "", help = t("agent.body"))]
        body: String,
        #[arg(long, help = t("agent.issue.labels"))]
        labels: Option<String>,
    },
    #[command(about = t("agent.issue.comment"))]
    Comment {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.body"))]
        body: String,
    },
    #[command(about = t("agent.issue.close"))]
    Close {
        #[arg(long, help = t("agent.number"))]
        number: u64,
    },
    #[command(about = t("agent.issue.label"))]
    Label {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.issue.labels"))]
        labels: String,
    },
    #[command(about = t("agent.issue.assign"))]
    Assign {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.issue.assignees"))]
        assignees: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ReleaseCmd {
    #[command(about = t("agent.release.create"))]
    Create {
        #[arg(long, help = t("agent.release.tag"))]
        tag: String,
        #[arg(long, help = t("agent.release.title"))]
        title: Option<String>,
        #[arg(long, help = t("agent.release.notes"))]
        notes: Option<String>,
        #[arg(long, help = t("agent.release.notes_file"))]
        notes_file: Option<PathBuf>,
        #[arg(long, help = t("agent.release.generate_notes"))]
        generate_notes: bool,
        #[arg(long, help = t("agent.release.draft"))]
        draft: bool,
        #[arg(long, help = t("agent.release.prerelease"))]
        prerelease: bool,
    },
    #[command(about = t("agent.release.view"))]
    View {
        #[arg(long, help = t("agent.release.tag"))]
        tag: String,
    },
    #[command(about = t("agent.release.list"))]
    List {
        #[arg(long, default_value_t = 20, help = t("agent.release.limit"))]
        limit: u32,
    },
}

#[derive(Subcommand, Debug)]
pub enum ProjectCmd {
    #[command(about = t("agent.project.add_item"))]
    AddItem {
        #[arg(long, help = t("agent.project.project_id"))]
        project_id: String,
        #[arg(long, help = t("agent.project.content_id"))]
        content_id: String,
    },
    #[command(about = t("agent.project.update_item"))]
    UpdateItem {
        #[arg(long, help = t("agent.project.project_id"))]
        project_id: String,
        #[arg(long, help = t("agent.project.item_id"))]
        item_id: String,
        #[arg(long, help = t("agent.project.field_id"))]
        field_id: String,
        #[arg(long, help = t("agent.project.update_item.value"))]
        value: String,
    },
    #[command(about = t("agent.project.list"))]
    List {
        #[arg(long, help = t("agent.project.project_id"))]
        project_id: String,
        #[arg(long, default_value_t = 20)]
        first: u32,
    },
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

pub struct AgentClient {
    endpoint: String,
    token: Option<String>,
    http: reqwest::Client,
}

impl AgentClient {
    pub fn from_env() -> anyhow::Result<Self> {
        let endpoint = std::env::var("SEKIMORE_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
        let token = std::env::var("SEKIMORE_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());
        Self::new(&endpoint, token)
    }

    pub fn new(endpoint: &str, token: Option<String>) -> anyhow::Result<Self> {
        // The relay sits inside the same isolation boundary, so proxy environment variables are ignored
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(60))
            .build()?;
        Ok(AgentClient {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            token,
            http,
        })
    }

    pub async fn call(&self, path: &str, req: &ApiRequest) -> anyhow::Result<ApiResponse> {
        let token = self.token.as_deref().ok_or_else(|| {
            anyhow!(
                "SEKIMORE_TOKEN is not set (source /etc/sekimore-agent/env or re-run agent-setup)"
            )
        })?;
        let resp = self
            .http
            .post(format!("{}{}", self.endpoint, path))
            .bearer_auth(token)
            .json(req)
            .send()
            .await
            .with_context(|| format!("cannot reach the gateway at {}", self.endpoint))?;
        let status = resp.status();
        let body = resp.bytes().await?;
        serde_json::from_slice::<ApiResponse>(&body)
            .map_err(|_| anyhow!("gateway returned HTTP {status} (unparseable body)"))
    }

    pub async fn bootstrap(
        &self,
        public_key: &str,
        label: Option<&str>,
    ) -> anyhow::Result<BootstrapResponse> {
        let resp = self
            .http
            .post(format!("{}/bootstrap", self.endpoint))
            .json(&BootstrapRequest {
                public_key: public_key.trim().to_string(),
                label: label.map(str::to_string),
            })
            .send()
            .await
            .with_context(|| format!("cannot reach the gateway at {}", self.endpoint))?;
        let status = resp.status();
        let body = resp.bytes().await?;
        serde_json::from_slice::<BootstrapResponse>(&body)
            .map_err(|_| anyhow!("gateway returned HTTP {status} (unparseable body)"))
    }
}

/// The body of `sekimore guide`. Embedded in the binary so it cannot drift from the CLI version (relay/share/agent-guide.*.md is the source of truth).
pub const AGENT_GUIDE_EN: &str = include_str!("../../share/agent-guide.en.md");
pub const AGENT_GUIDE_JA: &str = include_str!("../../share/agent-guide.ja.md");

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
    let path = match cmd {
        AgentCmd::Whoami => "/whoami",
        AgentCmd::Guide { .. } => unreachable!("guide is handled before connecting"),
        AgentCmd::Bootstrap { pubkey_file, label } => {
            let key = std::fs::read_to_string(&pubkey_file)
                .with_context(|| format!("read {}", pubkey_file.display()))?;
            let resp = client.bootstrap(&key, label.as_deref()).await?;
            if !resp.ok {
                eprintln!(
                    "sekimore: bootstrap denied: {}",
                    resp.error.unwrap_or_default()
                );
                return Ok(1);
            }
            // Machine-readable output for agent-setup.sh to read (the token only ever goes to stdout)
            println!("{}", serde_json::to_string(&resp)?);
            return Ok(0);
        }
        AgentCmd::Pr { cmd } => match cmd {
            PrCmd::Create {
                head,
                base,
                title,
                body,
            } => {
                req.head = head;
                req.base = base;
                req.title = title;
                req.body = body;
                "/pr/create"
            }
            PrCmd::Comment { number, body } => {
                req.number = number;
                req.body = body;
                "/pr/comment"
            }
            PrCmd::Review {
                number,
                event,
                body,
            } => {
                req.number = number;
                req.event = event;
                req.body = body;
                "/pr/review"
            }
            PrCmd::Merge { number } => {
                req.number = number;
                "/pr/merge"
            }
            PrCmd::Close { number } => {
                req.number = number;
                "/pr/close"
            }
            PrCmd::Status { number, json } => {
                req.number = number;
                let resp = client.call("/pr/status", &req).await?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&resp.raw)?);
                } else {
                    print_pr_status(&resp);
                }
                return Ok(if resp.ok { 0 } else { 1 });
            }
        },
        AgentCmd::Ci { cmd } => match cmd {
            CiCmd::Runs { git_ref } => {
                req.git_ref = git_ref;
                "/ci/runs"
            }
            CiCmd::Jobs { number, run_id } => {
                if number.is_none() && run_id.is_none() {
                    eprintln!("sekimore: ci jobs needs --number <pr> or --run-id <run>");
                    return Ok(2);
                }
                req.number = number.unwrap_or(0);
                req.run_id = run_id.unwrap_or(0);
                "/ci/jobs"
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
                let resp = client.call("/ci/log", &req).await?;
                if !resp.ok {
                    eprintln!("sekimore: {}", resp.error.unwrap_or_default());
                    return Ok(1);
                }
                if json {
                    println!("{}", serde_json::to_string_pretty(&resp.raw)?);
                } else {
                    print_ci_log(&resp);
                }
                return Ok(0);
            }
        },
        AgentCmd::Issue { cmd } => match cmd {
            IssueCmd::Create {
                title,
                body,
                labels,
            } => {
                req.title = title;
                req.body = body;
                req.labels = labels.map(|l| split_csv(&l)).unwrap_or_default();
                "/issue/create"
            }
            IssueCmd::Comment { number, body } => {
                req.number = number;
                req.body = body;
                "/issue/comment"
            }
            IssueCmd::Close { number } => {
                req.number = number;
                "/issue/close"
            }
            IssueCmd::Label { number, labels } => {
                req.number = number;
                req.labels = split_csv(&labels);
                "/issue/label"
            }
            IssueCmd::Assign { number, assignees } => {
                req.number = number;
                req.assignees = split_csv(&assignees);
                "/issue/assign"
            }
        },
        AgentCmd::Project { cmd } => match cmd {
            ProjectCmd::AddItem {
                project_id,
                content_id,
            } => {
                req.project_id = project_id;
                req.content_id = content_id;
                "/project/add-item"
            }
            ProjectCmd::UpdateItem {
                project_id,
                item_id,
                field_id,
                value,
            } => {
                req.project_id = project_id;
                req.item_id = item_id;
                req.field_id = field_id;
                req.value = Some(
                    serde_json::from_str::<Value>(&value)
                        .unwrap_or_else(|_| serde_json::json!({"text": value})),
                );
                "/project/update-item"
            }
            ProjectCmd::List { project_id, first } => {
                req.project_id = project_id;
                req.first = first;
                "/project/list"
            }
        },
        AgentCmd::Release { cmd } => match cmd {
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
                "/release/create"
            }
            ReleaseCmd::View { tag } => {
                req.tag = tag;
                "/release/view"
            }
            ReleaseCmd::List { limit } => {
                req.first = limit;
                "/release/list"
            }
        },
    };
    let resp = client.call(path, &req).await?;
    if !resp.ok {
        eprintln!("sekimore: denied: {}", resp.error.unwrap_or_default());
        return Ok(1);
    }
    print_response(&resp);
    Ok(0)
}

/// Human-readable rendering of `pr status`. raw holds the PrStatus JSON.
fn print_pr_status(resp: &ApiResponse) {
    if let Some(m) = &resp.message {
        println!("{m}");
    }
    let Some(raw) = &resp.raw else { return };
    if let Some(checks) = raw.get("checks").and_then(|v| v.as_array()) {
        for c in checks {
            let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let state = c.get("state").and_then(|v| v.as_str()).unwrap_or("?");
            let mark = match state {
                "success" | "neutral" | "skipped" => "✓",
                "pending" | "queued" | "in_progress" | "expected" => "…",
                _ => "✗",
            };
            println!("  {mark} {state:<12} {name}");
        }
    }
}

/// Human-readable rendering of `ci log`. raw holds the CiLogPage JSON.
fn print_ci_log(resp: &ApiResponse) {
    let Some(raw) = &resp.raw else { return };
    let g = |k: &str| raw.get(k);
    let name = g("job_name").and_then(|v| v.as_str()).unwrap_or("");
    let concl = g("conclusion").and_then(|v| v.as_str()).unwrap_or("");
    let total = g("total_lines").and_then(|v| v.as_u64()).unwrap_or(0);
    let start = g("start").and_then(|v| v.as_u64()).unwrap_or(0);
    let end = g("end").and_then(|v| v.as_u64()).unwrap_or(0);
    let job_id = g("job_id").and_then(|v| v.as_u64()).unwrap_or(0);
    let hdr = if name.is_empty() {
        format!("== job {job_id} lines {start}..{end} / {total}")
    } else {
        format!("== {name} [{concl}] lines {start}..{end} / {total}")
    };
    eprintln!("{hdr}");
    if let Some(lines) = g("lines").and_then(|v| v.as_array()) {
        for l in lines {
            if let Some(s) = l.as_str() {
                println!("{s}");
            }
        }
    }
    if g("has_more_before")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        eprintln!(
            "-- more above. next: sekimore ci log --job-id {job_id} --before {start} --window <n>"
        );
    }
}

pub fn print_response(resp: &ApiResponse) {
    if let Some(m) = &resp.message {
        println!("{m}");
    } else if let Some(url) = &resp.url {
        println!("#{} {url}", resp.number.unwrap_or(0));
    } else if let Some(item) = &resp.item_id {
        println!("item: {item}");
    } else if let Some(raw) = &resp.raw {
        println!("{}", serde_json::to_string_pretty(raw).unwrap_or_default());
    } else {
        println!("ok");
    }
}
