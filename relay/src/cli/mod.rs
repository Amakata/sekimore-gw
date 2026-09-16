//! コマンドライン。操作者向け（gateway 内で `docker compose exec sekimore-gw sekimore-relay …`）と
//! エージェント向け（devcontainer 内で `sekimore-relay agent …`）。

pub mod agent;
pub mod operator;
pub mod serve;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::DEFAULT_CONFIG_PATH;

#[derive(Parser, Debug)]
#[command(
    name = "sekimore-relay",
    version,
    about = "Policy-enforcing relay for AI agents: git over SSH, GitHub API over HTTP"
)]
pub struct Cli {
    /// 設定ファイル（Python と共有）
    #[arg(long, global = true, default_value = DEFAULT_CONFIG_PATH, env = "SEKIMORE_CONFIG_PATH")]
    pub config: PathBuf,
    /// ログを詳しく（-v info, -vv debug）
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// git-relay handler が設定されていれば 0、無ければ 1、設定不正なら 2（entrypoint.sh 用）
    NeedsRelay,
    /// SSH（git）と HTTP（API）、443 passthrough を起動する
    Serve,
    /// device flow で上流に認証し、トークンと known_hosts を保存する
    Login {
        /// 対象の上流（git-relay ドメイン）。省略時は既定上流。複数上流のときに使う（0.2.0）
        #[arg(long)]
        upstream: Option<String>,
    },
    /// 上流トークンを削除する
    Logout {
        #[arg(long)]
        upstream: Option<String>,
    },
    /// 関所がどの上流 identity として動くか
    Whoami {
        #[arg(long)]
        upstream: Option<String>,
    },
    /// 解決済みポリシーと状態（agent / known_hosts / token / keys）を表示する
    Check,
    /// 案件トークンを発行する
    Token {
        /// 有効期間（例: 12h, 30m）。省略時は relay.token_ttl
        #[arg(long)]
        ttl: Option<String>,
    },
    /// 発行済みトークンの一覧
    Tokens,
    /// ラベルを指定してトークンを失効させる（`tokens` で確認）
    Revoke {
        #[arg(long)]
        label: String,
    },
    /// 案件の全トークンを失効させる（案件終了時）
    RevokeProject,
    /// 使い捨て SSH 鍵の公開鍵を手で登録する（OpenSSH 1 行、または --file）
    AddKey {
        line: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// 上流や ProxyJump 先（踏み台）のホスト鍵を ssh-keyscan で取り、その上流の known_hosts に追記する（fingerprint を表示）
    Keyscan {
        /// ホスト名または IP
        host: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// どの上流の known_hosts に入れるか（git-relay ドメイン。省略時は既定上流）
        #[arg(long)]
        upstream: Option<String>,
    },
    /// POST /bootstrap の kill-switch
    Bootstrap {
        #[command(subcommand)]
        action: BootstrapAction,
    },
    /// エージェント側 CLI（設定ファイルは読まない。SEKIMORE_ENDPOINT / SEKIMORE_TOKEN / SEKIMORE_REPO）
    Agent {
        /// 既定リポジトリ Org/Repo
        #[arg(long, global = true, env = "SEKIMORE_REPO")]
        repo: Option<String>,
        #[command(subcommand)]
        cmd: agent::AgentCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum BootstrapAction {
    Disable,
    Enable,
    Status,
}

/// 実行して終了コードを返す。
pub async fn run(cli: Cli) -> i32 {
    let result: anyhow::Result<i32> = match cli.cmd {
        Command::NeedsRelay => operator::needs_relay(&cli.config),
        Command::Serve => serve::serve(&cli.config).await.map(|_| 0),
        Command::Login { upstream } => operator::login(&cli.config, upstream.as_deref())
            .await
            .map(|_| 0),
        Command::Logout { upstream } => {
            operator::logout(&cli.config, upstream.as_deref()).map(|_| 0)
        }
        Command::Whoami { upstream } => operator::whoami(&cli.config, upstream.as_deref())
            .await
            .map(|_| 0),
        Command::Check => operator::check(&cli.config).await.map(|_| 0),
        Command::Token { ttl } => operator::token(&cli.config, ttl.as_deref()).map(|_| 0),
        Command::Tokens => operator::tokens(&cli.config).map(|_| 0),
        Command::Revoke { label } => operator::revoke(&cli.config, &label).map(|_| 0),
        Command::RevokeProject => operator::revoke_project(&cli.config).map(|_| 0),
        Command::AddKey { line, file } => {
            operator::add_key(&cli.config, line.as_deref(), file.as_deref()).map(|_| 0)
        }
        Command::Keyscan {
            host,
            port,
            upstream,
        } => operator::keyscan(&cli.config, &host, port, upstream.as_deref()).map(|_| 0),
        Command::Bootstrap { action } => operator::bootstrap(&cli.config, action).map(|_| 0),
        Command::Agent { repo, cmd } => agent::run(repo.as_deref(), cmd).await,
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sekimore-relay: {e:#}");
            1
        }
    }
}
