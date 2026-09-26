//! The `sgw` command line. Help text comes from `relay/locales/*.json` at runtime, like the
//! relay's (`crate::i18n`).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::cli::color::{paint_err, Tone};
use crate::i18n::t;

use super::docker::{Docker, Tty};
use super::{open, ops, passphrase, project};

#[derive(Parser, Debug)]
#[command(name = "sgw", version, about = t("sgw.about"), disable_help_subcommand = true)]
pub struct Cli {
    /// The project (the directory that holds .devcontainer/). Default: found from the current directory
    #[arg(long, global = true, value_name = "DIR", env = "SGW_PROJECT_ROOT", help = t("sgw.project"))]
    pub project: Option<PathBuf>,
    #[arg(long = "no-tty", global = true, help = t("sgw.no_tty"))]
    pub no_tty: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// `args…` on a relay passthrough: handed to `sekimore-relay <sub>` as they are.
macro_rules! passthrough {
    ($($name:ident => $key:literal),* $(,)?) => {
        #[derive(Subcommand, Debug)]
        pub enum Cmd {
            $(
                #[command(about = t($key))]
                $name {
                    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
                    args: Vec<String>,
                },
            )*
            #[command(about = t("sgw.cmd.relay"))]
            Relay {
                #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
                args: Vec<String>,
            },
            #[command(name = "unlock-auto", about = t("sgw.cmd.unlock_auto"))]
            UnlockAuto,
            #[command(name = "keychain-set", about = t("sgw.cmd.keychain_set"))]
            KeychainSet,
            #[command(about = t("sgw.cmd.recreate"))]
            Recreate {
                #[arg(long = "no-unlock", help = t("sgw.cmd.recreate.no_unlock"))]
                no_unlock: bool,
            },
            #[command(about = t("sgw.cmd.restart"))]
            Restart,
            #[command(about = t("sgw.cmd.logs"))]
            Logs {
                #[arg(long, default_value_t = 100, help = t("sgw.cmd.logs.tail"))]
                tail: u32,
            },
            #[command(about = t("sgw.cmd.audit"))]
            Audit,
            #[command(about = t("sgw.cmd.shell"))]
            Shell,
            #[command(name = "db-stats", about = t("sgw.cmd.db_stats"))]
            DbStats {
                #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
                args: Vec<String>,
            },
            #[command(name = "db-prune", about = t("sgw.cmd.db_prune"))]
            DbPrune {
                #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
                args: Vec<String>,
            },
            #[command(name = "db-reset", about = t("sgw.cmd.db_reset"))]
            DbReset {
                #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
                args: Vec<String>,
            },
            #[command(name = "reload-status", about = t("sgw.cmd.reload_status"))]
            ReloadStatus,
            #[command(name = "reload-follow", about = t("sgw.cmd.reload_follow"))]
            ReloadFollow {
                #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
                args: Vec<String>,
            },
            #[command(name = "reload-freeze", about = t("sgw.cmd.reload_freeze"))]
            ReloadFreeze,
            #[command(about = t("sgw.cmd.dev"))]
            Dev {
                #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
                args: Vec<String>,
            },
            #[command(name = "agent-setup", about = t("sgw.cmd.agent_setup"))]
            AgentSetup,
            #[command(name = "signing-key", about = t("sgw.cmd.signing_key"))]
            SigningKey,
            #[command(about = t("sgw.cmd.refresh"))]
            Refresh,
            #[command(about = t("sgw.cmd.verify"))]
            Verify,
            #[command(about = t("sgw.cmd.web"))]
            Web,
            #[command(about = t("sgw.cmd.ps"))]
            Ps,
            #[command(about = t("sgw.cmd.port"))]
            Port {
                service: String,
                #[arg(default_value_t = 8080)]
                container_port: u16,
            },
            #[command(about = t("sgw.cmd.id"))]
            Id { service: String },
            #[command(name = "project", about = t("sgw.cmd.project"))]
            ProjectName,
            #[command(about = t("sgw.cmd.down"))]
            Down,
            #[command(about = t("sgw.cmd.open"))]
            Open {
                #[arg(long, help = t("sgw.cmd.open.check"))]
                check: bool,
                #[arg(long = "restore-agent-env", help = t("sgw.cmd.open.restore"))]
                restore_agent_env: bool,
            },
        }
    };
}

passthrough! {
    Check => "sgw.cmd.check",
    Whoami => "sgw.cmd.whoami",
    Login => "sgw.cmd.login",
    Logout => "sgw.cmd.logout",
    Unlock => "sgw.cmd.unlock",
    Lock => "sgw.cmd.lock",
    StoreStatus => "sgw.cmd.store_status",
    Passphrase => "sgw.cmd.passphrase",
    ProxyCredential => "sgw.cmd.proxy_credential",
    StoreExport => "sgw.cmd.store_export",
    StoreImport => "sgw.cmd.store_import",
    Tokens => "sgw.cmd.tokens",
    Revoke => "sgw.cmd.revoke",
    RevokeProject => "sgw.cmd.revoke_project",
    Bootstrap => "sgw.cmd.bootstrap",
    Keyscan => "sgw.cmd.keyscan",
}

fn relay_sub(sub: &str, args: &[String]) -> Vec<String> {
    let mut v = vec![sub.to_string()];
    v.extend(args.iter().cloned());
    v
}

pub fn main() -> i32 {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{} {e:#}", paint_err(Tone::Bad, "sgw:"));
            1
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    let env = |k: &str| std::env::var(k).ok();
    project::refuse_inside_devcontainer(env)?;
    let cwd = std::env::current_dir()?;
    let proj = project::discover(cli.project.as_deref(), &cwd, env)?;
    let docker = Docker::new(proj.compose_dir.clone());
    let no_tty = cli.no_tty;
    let tty = if no_tty { Tty::Never } else { Tty::Auto };
    use Cmd::*;
    match cli.cmd {
        Check { args } => ops::relay(&docker, &relay_sub("check", &args), no_tty),
        Whoami { args } => ops::relay(&docker, &relay_sub("whoami", &args), no_tty),
        Login { args } => ops::relay(&docker, &relay_sub("login", &args), no_tty),
        Logout { args } => ops::relay(&docker, &relay_sub("logout", &args), no_tty),
        Unlock { args } => ops::relay(&docker, &relay_sub("unlock", &args), no_tty),
        Lock { args } => ops::relay(&docker, &relay_sub("lock", &args), no_tty),
        StoreStatus { args } => ops::relay(&docker, &relay_sub("store-status", &args), no_tty),
        Passphrase { args } => ops::relay(&docker, &relay_sub("passphrase", &args), no_tty),
        ProxyCredential { args } => {
            ops::relay(&docker, &relay_sub("proxy-credential", &args), no_tty)
        }
        StoreExport { args } => ops::relay(&docker, &relay_sub("store-export", &args), no_tty),
        StoreImport { args } => ops::relay(&docker, &relay_sub("store-import", &args), no_tty),
        Tokens { args } => ops::relay(&docker, &relay_sub("tokens", &args), no_tty),
        Revoke { args } => ops::relay(&docker, &relay_sub("revoke", &args), no_tty),
        RevokeProject { args } => ops::relay(&docker, &relay_sub("revoke-project", &args), no_tty),
        Bootstrap { args } => ops::relay(&docker, &relay_sub("bootstrap", &args), no_tty),
        Keyscan { args } => ops::relay(&docker, &relay_sub("keyscan", &args), no_tty),
        Relay { args } => ops::relay(&docker, &args, no_tty),
        UnlockAuto => passphrase::unlock_auto(&docker, &proj.name()),
        KeychainSet => passphrase::keychain_set(&proj.name()),
        Recreate { no_unlock } => ops::recreate(&docker, &proj.name(), no_unlock),
        Restart => ops::restart(&docker),
        Logs { tail } => ops::logs(&docker, tail),
        Audit => ops::gateway(
            &docker,
            &[
                "tail".into(),
                "-n".into(),
                "50".into(),
                "-f".into(),
                "/data/relay/audit.jsonl".into(),
            ],
            tty,
        ),
        Shell => ops::gateway(
            &docker,
            &["bash".into()],
            if no_tty { Tty::Never } else { Tty::Interactive },
        ),
        DbStats { args } => ops::maint(&docker, "db-stats", &args, no_tty),
        DbPrune { args } => ops::maint(&docker, "db-prune", &args, no_tty),
        DbReset { args } => ops::maint(&docker, "db-reset", &args, no_tty),
        ReloadStatus => ops::maint(&docker, "reload-status", &[], no_tty),
        ReloadFollow { args } => ops::maint(&docker, "reload-follow", &args, no_tty),
        ReloadFreeze => ops::maint(&docker, "reload-freeze", &[], no_tty),
        Dev { args } => ops::dev(&docker, &args, no_tty),
        AgentSetup => ops::dev(
            &docker,
            &[
                "sudo".into(),
                "/usr/local/bin/sekimore-agent-setup.sh".into(),
            ],
            no_tty,
        ),
        SigningKey => ops::dev(
            &docker,
            &[
                "cat".into(),
                "/home/vscode/.ssh/sekimore/signing_ed25519.pub".into(),
            ],
            true,
        ),
        Refresh => ops::refresh(&docker),
        Verify => super::verify::run(&docker, &proj, super::target::Target::DEFAULT),
        Web => ops::web(&docker),
        Ps => docker.ps(),
        Port {
            service,
            container_port,
        } => {
            println!("{}", docker.port(&service, container_port)?);
            Ok(0)
        }
        Id { service } => {
            println!("{}", docker.find_container(&service)?);
            Ok(0)
        }
        ProjectName => {
            println!("{}", docker.compose_project()?);
            Ok(0)
        }
        Down => ops::down(&docker),
        Open {
            check,
            restore_agent_env,
        } => {
            let mode = if check {
                Some("--check")
            } else if restore_agent_env {
                Some("--restore-agent-env")
            } else {
                None
            };
            open::run(&proj.root, mode)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_line_parses_and_passes_arguments_through() {
        let cli = Cli::try_parse_from(["sgw", "revoke", "--label", "skm_x"]).unwrap();
        match cli.cmd {
            Cmd::Revoke { args } => assert_eq!(args, vec!["--label", "skm_x"]),
            other => panic!("{other:?}"),
        }
        let cli =
            Cli::try_parse_from(["sgw", "--no-tty", "relay", "keyscan", "h", "--port", "2222"])
                .unwrap();
        assert!(cli.no_tty);
        match cli.cmd {
            Cmd::Relay { args } => assert_eq!(args, vec!["keyscan", "h", "--port", "2222"]),
            other => panic!("{other:?}"),
        }
        let cli = Cli::try_parse_from(["sgw", "port", "sekimore-gw"]).unwrap();
        match cli.cmd {
            Cmd::Port {
                service,
                container_port,
            } => {
                assert_eq!(service, "sekimore-gw");
                assert_eq!(container_port, 8080);
            }
            other => panic!("{other:?}"),
        }
        assert!(
            Cli::try_parse_from(["sgw"]).is_err(),
            "a subcommand is required"
        );
    }

    #[test]
    fn every_command_has_help_in_both_languages() {
        // clap resolves the `about` strings at parse time; a key missing from the locale would
        // print the key itself. Both tables are held to the same set by tests/unit on the Python
        // side; here, that no about is a bare key.
        use clap::CommandFactory;
        let cmd = Cli::command();
        for sub in cmd.get_subcommands() {
            let about = sub.get_about().map(|a| a.to_string()).unwrap_or_default();
            assert!(
                !about.starts_with("sgw."),
                "{}: about is the bare key {about}",
                sub.get_name()
            );
        }
    }
}
