//! Command line. Operator-facing (run inside the gateway as `docker compose exec sekimore-gw sekimore-relay …`)
//! and agent-facing (run inside the devcontainer as `sekimore-relay agent …`).
//!
//! 0.2.4: help text is looked up at runtime from `relay/locales/*.json` (see `crate::i18n`). clap's doc comments
//! are not used because they would be baked in at compile time.

pub mod agent;
pub mod operator;
pub mod serve;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::DEFAULT_CONFIG_PATH;
use crate::i18n::t;

#[derive(Parser, Debug)]
#[command(name = "sekimore-relay", version, about = t("cli.about"))]
pub struct Cli {
    #[arg(long, global = true, default_value = DEFAULT_CONFIG_PATH, env = "SEKIMORE_CONFIG_PATH", help = t("cli.config"))]
    pub config: PathBuf,
    #[arg(short, long, global = true, action = clap::ArgAction::Count, help = t("cli.verbose"))]
    pub verbose: u8,
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    #[command(about = t("cli.needs_relay"))]
    NeedsRelay,
    #[command(about = t("cli.serve"))]
    Serve,
    #[command(about = t("cli.login"))]
    Login {
        #[arg(long, help = t("cli.login.upstream"))]
        upstream: Option<String>,
    },
    #[command(about = t("cli.logout"))]
    Logout {
        #[arg(long, help = t("cli.upstream"))]
        upstream: Option<String>,
    },
    #[command(about = t("cli.whoami"))]
    Whoami {
        #[arg(long, help = t("cli.upstream"))]
        upstream: Option<String>,
    },
    #[command(about = t("cli.check"))]
    Check,
    #[command(about = t("cli.token"))]
    Token {
        #[arg(long, help = t("cli.token.ttl"))]
        ttl: Option<String>,
    },
    #[command(about = t("cli.tokens"))]
    Tokens,
    #[command(about = t("cli.revoke"))]
    Revoke {
        #[arg(long, help = t("cli.revoke.label"))]
        label: String,
    },
    #[command(about = t("cli.revoke_project"))]
    RevokeProject,
    #[command(about = t("cli.add_key"))]
    AddKey {
        #[arg(help = t("cli.add_key.line"))]
        line: Option<String>,
        #[arg(long, help = t("cli.add_key.file"))]
        file: Option<PathBuf>,
    },
    #[command(about = t("cli.keyscan"))]
    Keyscan {
        #[arg(help = t("cli.keyscan.host"))]
        host: String,
        #[arg(long, default_value_t = 22, help = t("cli.keyscan.port"))]
        port: u16,
        #[arg(long, help = t("cli.keyscan.upstream"))]
        upstream: Option<String>,
    },
    #[command(about = t("cli.bootstrap"))]
    Bootstrap {
        #[command(subcommand)]
        action: BootstrapAction,
    },
    #[command(about = t("cli.agent"))]
    Agent {
        #[arg(long, global = true, env = "SEKIMORE_REPO", help = t("cli.agent.repo"))]
        repo: Option<String>,
        #[command(subcommand)]
        cmd: agent::AgentCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum BootstrapAction {
    #[command(about = t("cli.bootstrap.disable"))]
    Disable,
    #[command(about = t("cli.bootstrap.enable"))]
    Enable,
}

/// Runs the command and returns the exit code.
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
