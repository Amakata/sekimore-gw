//! The secret store's passphrase, from wherever this host already keeps secrets (0.2.29).
//!
//! `unlock-auto` reads it and feeds it to `sekimore-relay unlock --stdin` down a pipe: never an
//! argument, never an environment variable. `keychain-set` puts it there once. The gateway learns
//! nothing new — the passphrase still arrives over the control socket, exactly as when typed.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Context};
use zeroize::Zeroizing;

use crate::i18n::{t, tf};

use super::docker::{Docker, GATEWAY};

pub const SERVICE: &str = "sekimore-gw";
pub const DEFAULT_DIR: &str = "/etc/sekimore";

/// Where a passphrase was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub value: Zeroizing<String>,
    pub from: String,
}

/// The backends, asked in this order: the macOS Keychain, the Secret Service, a
/// `systemd-creds` file (tied to this machine's TPM or host key, so a copied disk carries no
/// usable passphrase), a plain root-owned file (the file itself is the secret, so it is last).
/// `run` is the command runner, injected for the tests: it returns stdout when the command
/// succeeds with output, None otherwise. `tried` lists what was consulted, because a backend that
/// is installed but answered nothing wants a different remedy than a host with no backend.
pub fn lookup(
    project: &str,
    dir: &Path,
    have: impl Fn(&str) -> bool,
    exists: impl Fn(&Path) -> bool,
    run: impl Fn(&str, &[&str]) -> Option<String>,
) -> (Option<Found>, Vec<String>) {
    let mut tried = Vec::new();
    let found = |value: Option<String>, from: &str| {
        value
            .map(|v| v.trim_end_matches(['\n', '\r']).to_string())
            .filter(|v| !v.is_empty())
            .map(|v| Found {
                value: Zeroizing::new(v),
                from: from.to_string(),
            })
    };
    if have("security") {
        tried.push("the macOS Keychain".to_string());
        if let Some(f) = found(
            run(
                "security",
                &["find-generic-password", "-s", SERVICE, "-a", project, "-w"],
            ),
            "the macOS Keychain",
        ) {
            return (Some(f), tried);
        }
    }
    if have("secret-tool") {
        tried.push("the Secret Service".to_string());
        if let Some(f) = found(
            run(
                "secret-tool",
                &["lookup", "service", SERVICE, "project", project],
            ),
            "the Secret Service",
        ) {
            return (Some(f), tried);
        }
    }
    let cred = dir.join(format!("{project}.passphrase.cred"));
    if exists(&cred) {
        let c = cred.display().to_string();
        tried.push(c.clone());
        // read as ourselves first, sudo -n after; never an interactive sudo, this runs inside
        // recreate where a password prompt would hang an unattended restart
        let out = run(
            "systemd-creds",
            &["decrypt", &format!("--name={SERVICE}"), &c, "-"],
        )
        .or_else(|| {
            run(
                "sudo",
                &[
                    "-n",
                    "systemd-creds",
                    "decrypt",
                    &format!("--name={SERVICE}"),
                    &c,
                    "-",
                ],
            )
        });
        if let Some(f) = found(out, &c) {
            return (Some(f), tried);
        }
    }
    let plain = dir.join(format!("{project}.passphrase"));
    if exists(&plain) {
        let p = plain.display().to_string();
        tried.push(p.clone());
        let out = run("cat", &[&p]).or_else(|| run("sudo", &["-n", "cat", &p]));
        if let Some(f) = found(out, &p) {
            return (Some(f), tried);
        }
    }
    (None, tried)
}

/// The command runner `lookup` uses for real: stdout of a command that exited 0 with output.
pub fn run_capture(program: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !o.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&o.stdout).into_owned();
    (!s.trim().is_empty()).then_some(s)
}

pub fn have(program: &str) -> bool {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path).any(|d| d.join(program).is_file())
}

pub fn passphrase_dir() -> std::path::PathBuf {
    std::env::var("SGW_PASSPHRASE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(DEFAULT_DIR))
}

/// The argv `unlock-auto` runs in the gateway, and what goes down its stdin. Separate from the
/// running so a test can hold the shape: the passphrase is in the input and nowhere in argv.
pub fn unlock_invocation(found: &Found) -> (Vec<String>, Zeroizing<Vec<u8>>) {
    let argv = vec![
        "sekimore-relay".to_string(),
        "unlock".to_string(),
        "--stdin".to_string(),
    ];
    let mut input = Zeroizing::new(found.value.as_bytes().to_vec());
    input.push(b'\n');
    (argv, input)
}

/// Exit 0 with nothing stored: `recreate` runs this unconditionally, and a host that never set
/// a passphrase up is not a failed recreate.
pub fn unlock_auto(docker: &Docker, project: &str) -> anyhow::Result<i32> {
    let dir = passphrase_dir();
    let (found, tried) = lookup(project, &dir, have, |p| p.exists(), run_capture);
    let Some(found) = found else {
        let asked = if tried.is_empty() {
            String::new()
        } else {
            format!(" (asked: {})", tried.join(", "))
        };
        println!(
            "{}",
            tf(
                "sgw.unlock_auto.none",
                &[("project", project), ("asked", &asked)]
            )
        );
        return Ok(0);
    };
    println!("{}", tf("sgw.unlock_auto.from", &[("from", &found.from)]));
    let cid = docker.find_container(GATEWAY)?;
    let (argv, input) = unlock_invocation(&found);
    docker.exec_with_stdin(&cid, &argv, &input)
}

/// Reads a line with the terminal's echo off. Only for a terminal: the callers refuse a pipe.
fn read_secret(prompt: &str) -> anyhow::Result<Zeroizing<String>> {
    use std::io::{BufRead, Write};
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    // SAFETY: plain termios calls on fd 0, restored before returning on every path
    let restore = unsafe {
        let mut term: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(0, &mut term) != 0 {
            bail!("stdin is not a terminal");
        }
        let orig = term;
        term.c_lflag &= !libc::ECHO;
        libc::tcsetattr(0, libc::TCSANOW, &term);
        orig
    };
    let mut line = String::new();
    let r = std::io::stdin().lock().read_line(&mut line);
    unsafe {
        libc::tcsetattr(0, libc::TCSANOW, &restore);
    }
    eprintln!();
    r?;
    Ok(Zeroizing::new(
        line.trim_end_matches(['\n', '\r']).to_string(),
    ))
}

/// Put the passphrase into this host's own secret store, once. Read back afterwards: a store
/// that silently did not happen looks exactly like one that did, until the next recreate.
pub fn keychain_set(project: &str) -> anyhow::Result<i32> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        bail!(tf("sgw.needs_tty", &[("cmd", "keychain-set")]));
    }
    let dir = passphrase_dir();
    if have("security") {
        // security prompts for the password itself, echo off and with a retype. Handing it over
        // as `-w <value>` would put the passphrase in ps for as long as the command runs.
        let st = Command::new("security")
            .args([
                "add-generic-password",
                "-U",
                "-s",
                SERVICE,
                "-a",
                project,
                "-w",
            ])
            .status()
            .context("run security")?;
        if !st.success() {
            bail!(tf("sgw.keychain.none", &[("project", project)]));
        }
        let stored = run_capture(
            "security",
            &["find-generic-password", "-s", SERVICE, "-a", project, "-w"],
        )
        .map(Zeroizing::new);
        let Some(stored) = stored else {
            bail!(tf("sgw.keychain.none", &[("project", project)]));
        };
        println!(
            "{}",
            tf(
                "sgw.keychain.stored",
                &[
                    ("backend", "the macOS Keychain"),
                    ("project", project),
                    ("n", &stored.trim_end().chars().count().to_string())
                ]
            )
        );
        return Ok(0);
    }
    if have("secret-tool") {
        // Typed twice. Nothing here can tell a mistyped passphrase from the right one, and
        // stored wrong it fails at every recreate from now on rather than at the keyboard.
        let pass = read_secret(&tf("sgw.keychain.prompt", &[("project", project)]))?;
        let again = read_secret(&t("sgw.keychain.again"))?;
        if pass.is_empty() {
            bail!(t("sgw.keychain.empty"));
        }
        if *pass != *again {
            bail!(t("sgw.keychain.mismatch"));
        }
        let mut child = Command::new("secret-tool")
            .args([
                "store",
                &format!("--label={SERVICE} {project}"),
                "service",
                SERVICE,
                "project",
                project,
            ])
            .stdin(Stdio::piped())
            .spawn()
            .context("run secret-tool")?;
        {
            use std::io::Write;
            let mut stdin = child.stdin.take().context("no stdin on secret-tool")?;
            let mut input = Zeroizing::new(pass.as_bytes().to_vec());
            input.push(b'\n');
            stdin.write_all(&input)?;
        }
        child.wait()?;
        let stored = run_capture(
            "secret-tool",
            &["lookup", "service", SERVICE, "project", project],
        )
        .map(Zeroizing::new);
        if stored.as_deref().map(|s| s.trim_end_matches('\n')) != Some(pass.as_str()) {
            bail!(tf("sgw.keychain.readback", &[("project", project)]));
        }
        println!(
            "{}",
            tf(
                "sgw.keychain.stored",
                &[
                    ("backend", "the Secret Service"),
                    ("project", project),
                    ("n", &pass.chars().count().to_string())
                ]
            )
        );
        return Ok(0);
    }
    eprintln!(
        "{}",
        tf(
            "sgw.keychain.no_backend",
            &[("dir", &dir.display().to_string()), ("project", project)]
        )
    );
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backends_are_asked_in_order_and_the_first_answer_wins() {
        let dir = Path::new("/etc/sekimore");
        let (f, tried) = lookup(
            "proj",
            dir,
            |p| p == "security" || p == "secret-tool",
            |_| true,
            |prog, _| match prog {
                "security" => None, // installed, holds nothing
                "secret-tool" => Some("s3cret\n".into()),
                _ => panic!("{prog} must not be asked once one answered"),
            },
        );
        assert_eq!(f.unwrap().from, "the Secret Service");
        assert_eq!(tried, vec!["the macOS Keychain", "the Secret Service"]);
    }

    #[test]
    fn the_files_come_last_and_sudo_is_only_ever_non_interactive() {
        let dir = Path::new("/etc/sekimore");
        let calls: std::cell::RefCell<Vec<String>> = Default::default();
        let (f, tried) = lookup(
            "proj",
            dir,
            |_| false,
            |p| p == Path::new("/etc/sekimore/proj.passphrase"),
            |prog, args| {
                calls
                    .borrow_mut()
                    .push(format!("{prog} {}", args.join(" ")));
                if prog == "sudo" {
                    Some("from-root\n".into())
                } else {
                    None
                }
            },
        );
        assert_eq!(f.unwrap().value.as_str(), "from-root");
        assert_eq!(tried, vec!["/etc/sekimore/proj.passphrase"]);
        let calls = calls.into_inner();
        assert_eq!(calls[0], "cat /etc/sekimore/proj.passphrase");
        assert_eq!(calls[1], "sudo -n cat /etc/sekimore/proj.passphrase");
    }

    #[test]
    fn nothing_stored_says_what_was_asked() {
        let (f, tried) = lookup("proj", Path::new("/x"), |_| false, |_| false, |_, _| None);
        assert!(f.is_none());
        assert!(tried.is_empty());
    }

    /// The adversarial shape: the passphrase must reach only the command's stdin. An argv that
    /// carried it would show it in `ps` for as long as the unlock runs.
    #[test]
    fn the_passphrase_travels_down_stdin_and_nowhere_else() {
        let found = Found {
            value: Zeroizing::new("hunter2".into()),
            from: "test".into(),
        };
        let (argv, input) = unlock_invocation(&found);
        assert_eq!(argv, vec!["sekimore-relay", "unlock", "--stdin"]);
        assert!(!argv.iter().any(|a| a.contains("hunter2")));
        assert_eq!(&**input, b"hunter2\n");
    }
}
