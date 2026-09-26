//! The operations, each a thin layer over `docker exec` into the gateway or the dev container.
//!
//! The commands that used to be `gw:*` and `relay:*` / `dev:*` mise tasks. A relay subcommand is
//! passed through with its arguments as they are; the only thing decided here is whether it
//! reads from the terminal (`Tty::Interactive`).

use anyhow::bail;

use crate::i18n::t;

use super::docker::{color_env, Docker, Tty, DEV, GATEWAY};

/// The relay's subcommands that read from the person's terminal — a passphrase, a yes/no —
/// and so need `-t` whenever stdin is a terminal and refuse a pipe (#230). Everything else
/// follows the general rule.
pub const INTERACTIVE: &[&str] = &[
    "login",
    "logout",
    "unlock",
    "passphrase",
    "proxy-credential",
];

/// `unlock --stdin` is the one interactive command deliberately fed from a pipe.
pub fn relay_tty(argv: &[String]) -> Tty {
    match argv.first().map(String::as_str) {
        Some(sub) if INTERACTIVE.contains(&sub) => {
            if sub == "unlock" && argv.iter().any(|a| a == "--stdin") {
                Tty::Auto
            } else {
                Tty::Interactive
            }
        }
        _ => Tty::Auto,
    }
}

fn colours() -> Vec<(String, String)> {
    use std::io::IsTerminal;
    color_env(
        std::io::stdout().is_terminal(),
        std::env::var("SEKIMORE_COLOR").ok().as_deref(),
        std::env::var("NO_COLOR").ok().as_deref(),
    )
}

/// `sekimore-relay <argv…>` in the gateway. Empty argv is `check`, the way `sgw.sh gw` was.
pub fn relay(docker: &Docker, argv: &[String], no_tty: bool) -> anyhow::Result<i32> {
    let argv: Vec<String> = if argv.is_empty() {
        vec!["check".into()]
    } else {
        argv.to_vec()
    };
    let tty = if no_tty { Tty::Never } else { relay_tty(&argv) };
    let cid = docker.find_container(GATEWAY)?;
    let mut full = vec!["sekimore-relay".to_string()];
    full.extend(argv);
    docker.exec(&cid, None, tty, &colours(), &full)
}

/// Any command in the gateway, as root (`sgw shell`, the maintenance scripts, the audit log).
pub fn gateway(docker: &Docker, argv: &[String], tty: Tty) -> anyhow::Result<i32> {
    let cid = docker.find_container(GATEWAY)?;
    docker.exec(&cid, None, tty, &colours(), argv)
}

/// `python -m src.maint <name> <args…>` in the gateway: the log DB and the reload window.
pub fn maint(docker: &Docker, name: &str, args: &[String], no_tty: bool) -> anyhow::Result<i32> {
    let mut argv: Vec<String> = vec![
        "python".into(),
        "-m".into(),
        "src.maint".into(),
        name.into(),
    ];
    argv.extend(args.iter().cloned());
    gateway(docker, &argv, if no_tty { Tty::Never } else { Tty::Auto })
}

/// A command in the dev container as the vscode user; empty is a zsh.
pub fn dev(docker: &Docker, argv: &[String], no_tty: bool) -> anyhow::Result<i32> {
    let argv: Vec<String> = if argv.is_empty() {
        vec!["zsh".into()]
    } else {
        argv.to_vec()
    };
    let cid = docker.find_container(DEV)?;
    docker.exec(
        &cid,
        Some("vscode"),
        if no_tty { Tty::Never } else { Tty::Auto },
        &[],
        &argv,
    )
}

fn dev_sh(docker: &Docker, script: &str) -> anyhow::Result<i32> {
    dev(
        docker,
        &["sh".to_string(), "-c".to_string(), script.to_string()],
        true,
    )
}

pub fn logs(docker: &Docker, tail: u32) -> anyhow::Result<i32> {
    let cid = docker.find_container(GATEWAY)?;
    docker.run(&[
        "logs".into(),
        "-f".into(),
        "--tail".into(),
        tail.to_string(),
        cid,
    ])
}

pub fn restart(docker: &Docker) -> anyhow::Result<i32> {
    let cid = docker.find_container(GATEWAY)?;
    docker.run(&["restart".into(), cid])
}

/// `recreate`, then the automatic unlock unless told not to (`--no-unlock`, or
/// `SGW_NO_AUTO_UNLOCK` in the environment).
pub fn recreate(docker: &Docker, project: &str, no_unlock: bool) -> anyhow::Result<i32> {
    docker.recreate_gateway()?;
    if no_unlock || std::env::var_os("SGW_NO_AUTO_UNLOCK").is_some() {
        println!("{}", t("sgw.recreate.left_locked"));
        return Ok(0);
    }
    match super::passphrase::unlock_auto(docker, project) {
        Ok(0) => Ok(0),
        Ok(rc) => bail!("{} (exit {rc})", t("sgw.recreate.unlock_failed")),
        Err(e) => bail!("{}: {e:#}", t("sgw.recreate.unlock_failed")),
    }
}

pub fn down(docker: &Docker) -> anyhow::Result<i32> {
    let proj = docker.compose_project()?;
    docker.run(&["compose".into(), "-p".into(), proj, "down".into()])
}

/// The Web UI in a browser, at whatever host port the gateway publishes 8080 on.
pub fn web(docker: &Docker) -> anyhow::Result<i32> {
    let port = docker.port(GATEWAY, 8080)?;
    let url = format!("http://localhost:{port}");
    println!("{url}");
    for opener in ["open", "xdg-open"] {
        if let Ok(st) = std::process::Command::new(opener).arg(&url).status() {
            if st.success() {
                return Ok(0);
            }
        }
    }
    Ok(0)
}

/// Run the gateway's agent setup again in dev, the way post-start.sh does, so the ~/.ssh/config
/// Host blocks and the upstream proxy environment follow config.yml without Rebuild Container
/// (base #97).
pub fn refresh(docker: &Docker) -> anyhow::Result<i32> {
    println!("{}", t("sgw.refresh.setup"));
    // The same invocation as post-start.sh: agent-setup as root, with every SEKIMORE_* variable
    // dev has. sudo resets the environment, so a variable reaches agent-setup only if
    // --preserve-env= names it; the names are taken from dev's own environment
    let rc = dev_sh(
        docker,
        r#"set -e
agent_setup=${SGW_AGENT_SETUP:-/usr/local/bin/sekimore-agent-setup.sh}
vars=$(env | sed -n "s/^\(SEKIMORE_[A-Za-z0-9_]*\)=.*/\1/p" | sort -u | paste -sd, -)
if [ -n "$vars" ]; then sudo --preserve-env="$vars" "$agent_setup"; else sudo "$agent_setup"; fi"#,
    )?;
    if rc != 0 {
        bail!(t("sgw.refresh.failed"));
    }
    println!();
    println!("{}", t("sgw.refresh.hosts"));
    let rc = dev_sh(
        docker,
        r#"b=$(sed -n "/^# >>> sekimore-relay >>>/,/^# <<< sekimore-relay <<</p" ~/.ssh/config 2>/dev/null)
if [ -n "$b" ]; then printf '%s\n' "$b"; printf '%s\n' "$b" | sed -n 's/^Host /wrote: Host /p'; else exit 3; fi"#,
    )?;
    if rc == 3 {
        println!("{}", t("sgw.refresh.no_hosts"));
    }
    println!();
    println!("{}", t("sgw.refresh.proxy"));
    let rc = dev_sh(
        docker,
        r#"test -f /etc/profile.d/sekimore-proxy.sh || exit 3
grep -E "^export (HTTP_PROXY|NO_PROXY)=" /etc/profile.d/sekimore-proxy.sh || true"#,
    )?;
    if rc == 3 {
        println!("{}", t("sgw.refresh.no_proxy"));
    } else {
        println!("{}", t("sgw.refresh.proxy_present"));
    }
    println!();
    println!("{}", t("sgw.refresh.done"));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_commands_that_read_from_the_terminal_are_interactive() {
        assert_eq!(
            relay_tty(&v(&["login", "--upstream", "x"])),
            Tty::Interactive
        );
        assert_eq!(relay_tty(&v(&["unlock"])), Tty::Interactive);
        assert_eq!(relay_tty(&v(&["passphrase"])), Tty::Interactive);
        assert_eq!(
            relay_tty(&v(&["proxy-credential", "set"])),
            Tty::Interactive
        );
        assert_eq!(relay_tty(&v(&["check"])), Tty::Auto);
        assert_eq!(relay_tty(&v(&["keyscan", "h"])), Tty::Auto);
        assert_eq!(
            relay_tty(&v(&["store-import"])),
            Tty::Auto,
            "fed from a pipe by design"
        );
    }

    #[test]
    fn unlock_from_stdin_is_the_exception() {
        assert_eq!(relay_tty(&v(&["unlock", "--stdin"])), Tty::Auto);
    }
}
