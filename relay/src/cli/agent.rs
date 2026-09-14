//! エージェント側 CLI。関所の素直なエンドポイントを叩くだけ（gh 互換は目指さない）。
//!
//! エージェントが持つのは案件トークンのみ（上流では無効な文字列）。

use std::path::PathBuf;

use anyhow::{anyhow, Context};
use clap::{Args, Subcommand};
use serde_json::Value;

use crate::api::types::{ApiRequest, ApiResponse, BootstrapRequest, BootstrapResponse};

pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:8420";

#[derive(Subcommand, Debug)]
pub enum AgentCmd {
    /// 自分の案件・権限・リポジトリを確認する
    Whoami,
    /// Pull Request 操作
    Pr {
        #[command(subcommand)]
        cmd: PrCmd,
    },
    /// Issue 操作
    Issue {
        #[command(subcommand)]
        cmd: IssueCmd,
    },
    /// Projects v2 操作（関所が GraphQL を組み立てる）
    Project {
        #[command(subcommand)]
        cmd: ProjectCmd,
    },
    /// 使い捨て SSH 公開鍵を登録し、案件トークンを受け取る（agent-setup.sh が使う）
    Bootstrap {
        #[arg(long)]
        pubkey_file: PathBuf,
        #[arg(long)]
        label: Option<String>,
    },
}

#[derive(Args, Debug, Default)]
pub struct Number {
    #[arg(long)]
    pub number: u64,
}

#[derive(Subcommand, Debug)]
pub enum PrCmd {
    Create {
        #[arg(long)]
        head: String,
        #[arg(long)]
        base: String,
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "")]
        body: String,
    },
    Comment {
        #[arg(long)]
        number: u64,
        #[arg(long)]
        body: String,
    },
    Review {
        #[arg(long)]
        number: u64,
        /// APPROVE / REQUEST_CHANGES / COMMENT
        #[arg(long, default_value = "COMMENT")]
        event: String,
        #[arg(long, default_value = "")]
        body: String,
    },
    Merge {
        #[arg(long)]
        number: u64,
    },
    Close {
        #[arg(long)]
        number: u64,
    },
}

#[derive(Subcommand, Debug)]
pub enum IssueCmd {
    Create {
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "")]
        body: String,
        /// カンマ区切り
        #[arg(long)]
        labels: Option<String>,
    },
    Comment {
        #[arg(long)]
        number: u64,
        #[arg(long)]
        body: String,
    },
    Close {
        #[arg(long)]
        number: u64,
    },
    Label {
        #[arg(long)]
        number: u64,
        #[arg(long)]
        labels: String,
    },
    Assign {
        #[arg(long)]
        number: u64,
        #[arg(long)]
        assignees: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ProjectCmd {
    AddItem {
        #[arg(long)]
        project_id: String,
        #[arg(long)]
        content_id: String,
    },
    UpdateItem {
        #[arg(long)]
        project_id: String,
        #[arg(long)]
        item_id: String,
        #[arg(long)]
        field_id: String,
        /// JSON か文字列（文字列は {"text": …} になる）
        #[arg(long)]
        value: String,
    },
    List {
        #[arg(long)]
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
        // 関所は同じ隔離境界の内側。プロキシ環境変数は無視する
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

pub async fn run(repo: Option<&str>, cmd: AgentCmd) -> anyhow::Result<i32> {
    let client = AgentClient::from_env()?;
    let repo = repo.unwrap_or("").to_string();
    let mut req = ApiRequest {
        repo,
        ..Default::default()
    };
    let path = match cmd {
        AgentCmd::Whoami => "/whoami",
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
            // agent-setup.sh が読む機械可読出力（トークンは stdout にしか出さない）
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
    };
    let resp = client.call(path, &req).await?;
    if !resp.ok {
        eprintln!("sekimore: denied: {}", resp.error.unwrap_or_default());
        return Ok(1);
    }
    print_response(&resp);
    Ok(0)
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
