//! `agent-setup.sh`, the shell setup shipped in the gateway image for the standalone compose
//! example and older base images (`sgw-agent setup` is its successor, tested in relay/).
//!
//! As the pytest suites before it: `sekimore_relay_setup` is run by sourcing the script with
//! `SEKIMORE_AGENT_SETUP_SOURCE_ONLY=1`, with fake `curl`, `ssh-keyscan` and `sekimore-relay` on
//! PATH that record every call, a temporary HOME and env file, and the real `git`,
//! `ssh-keygen` and (for signing) a real `ssh-agent`. The proxy-environment functions are cut
//! out of the script at the markers that bracket them and run against a temporary root.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use regex::Regex;
use sekimore_tools::repo_root;

fn script() -> PathBuf {
    repo_root().join("agent-setup.sh")
}

fn system_path() -> String {
    std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn read(p: impl AsRef<Path>) -> String {
    let p = p.as_ref();
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn write_exec(p: &Path, body: &str) {
    std::fs::write(p, body).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

// ---- the script itself ----

#[test]
fn it_is_an_executable_bash_script_that_stops_on_errors() {
    let s = script();
    assert!(s.exists(), "agent-setup.sh should exist");
    assert!(mode(&s) & 0o111 != 0, "agent-setup.sh should be executable");
    let body = read(&s);
    assert!(body.starts_with("#!/bin/bash"), "bash shebang");
    assert!(body.contains("set -e"), "error handling");
}

#[test]
fn it_stops_with_a_hint_when_there_is_no_ip_command() {
    // Run for real with a PATH that has no `ip`: the check comes before anything touches the
    // network or /etc.
    let empty = tempfile::tempdir().unwrap();
    let out = Command::new("/bin/bash")
        .arg(script())
        .env_clear()
        .env("PATH", empty.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ERROR: 'ip' command not found"), "{stdout}");
    assert!(stdout.contains("install iproute2"), "{stdout}");
    assert!(!stdout.contains("Scanning subnet"), "{stdout}");
}

// ---- sekimore_relay_setup, with fake curl / ssh-keyscan ----

const GW: &str = "172.19.0.2";

fn token() -> String {
    format!("skm_{}", "ab12".repeat(16))
}

fn default_bootstrap() -> String {
    format!(
        r#"{{"ok":true,"fingerprint":"SHA256:x","added":true,"token":"{}","token_expires":"2026-01-01T00:00:00Z","project":"case-a","repos":["LibOrg/awesome-lib","VendorOrg/reference-impl"],"git_domain":"ghe.example.com","upstream":"ghe.example.com"}}"#,
        token()
    )
}

struct Shims {
    relay_present: bool,
    valid_token: Option<String>,
    bootstrap_json: Option<String>,
}

impl Default for Shims {
    fn default() -> Self {
        Shims {
            relay_present: true,
            valid_token: None,
            bootstrap_json: None,
        }
    }
}

/// Fake commands placed on PATH; every invocation is recorded in calls.log. Returns the shim
/// directory and the log.
fn shims(dir: &Path, s: Shims) -> (PathBuf, PathBuf) {
    let shim = dir.join("shim");
    std::fs::create_dir_all(&shim).unwrap();
    let log = dir.join("calls.log");
    let bootstrap = s.bootstrap_json.unwrap_or_else(default_bootstrap);
    let healthz = if s.relay_present { "exit 0" } else { "exit 7" };
    let valid = s.valid_token.unwrap_or_else(|| "__none__".into());
    let log_s = log.display();
    write_exec(
        &shim.join("curl"),
        &format!(
            r#"#!/bin/bash
url="${{@: -1}}"
echo "curl $url" >> "{log_s}"
case "$url" in
  */healthz) {healthz} ;;
  */whoami)
    for a in "$@"; do case "$a" in "Authorization: Bearer {valid}") echo whoami-ok >> "{log_s}"; exit 0;; esac; done
    exit 22 ;;
  */bootstrap) echo bootstrap-called >> "{log_s}"; printf '%s' '{bootstrap}' ;;
  *) exit 1 ;;
esac
"#
        ),
    );
    write_exec(
        &shim.join("sekimore-relay"),
        "#!/bin/bash\n\
         if [ \"$1\" = --version ]; then echo \"sekimore-relay 9.9.9\"; exit 0; fi\n\
         if [ \"$1\" = agent ] && [ \"$2\" = guide ]; then printf \"# guide (shim)\\n\\nUse sekimore.\\n\"; exit 0; fi\n\
         exit 1\n",
    );
    write_exec(
        &shim.join("ssh-keyscan"),
        &format!(
            "#!/bin/bash\n\
             host=\"${{@: -1}}\"\n\
             echo \"ssh-keyscan $*\" >> \"{log_s}\"\n\
             echo \"# $host:22 SSH-2.0-sekimore-relay\"\n\
             echo \"$host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\"\n"
        ),
    );
    (shim, log)
}

fn current_user() -> String {
    let out = Command::new("id").arg("-un").output().unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// Sources the script and runs `sekimore_relay_setup <gw>`. Returns the output and HOME.
fn run(dir: &Path, shim: &Path, extra: &[(&str, &str)]) -> (Output, PathBuf) {
    run_traced(dir, shim, extra, true)
}

fn run_traced(dir: &Path, shim: &Path, extra: &[(&str, &str)], xtrace: bool) -> (Output, PathBuf) {
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let trace = if xtrace { "set -x;" } else { "" };
    let mut c = Command::new("bash");
    c.arg("-c")
        .arg(format!(
            "{trace} source '{}'; sekimore_relay_setup {GW}",
            script().display()
        ))
        .env_clear()
        .env("PATH", format!("{}:{}", shim.display(), system_path()))
        .env("HOME", &home)
        .env("SEKIMORE_AGENT_SETUP_SOURCE_ONLY", "1")
        .env("SEKIMORE_AGENT_USER", current_user())
        .env("SEKIMORE_AGENT_HOME", &home)
        .env("SEKIMORE_AGENT_ENV_FILE", dir.join("etc/env"))
        .env("GIT_COMMITTER_EMAIL", "agent@example.invalid");
    for (k, v) in extra {
        c.env(k, v);
    }
    (c.output().unwrap(), home)
}

/// What git in the container would use: every config file, includes followed.
fn git_get(home: &Path, key: &str) -> String {
    let out = Command::new("git")
        .args(["config", "--get", key])
        .env_clear()
        .env("HOME", home)
        .env("PATH", system_path())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// What the Dev Containers extension does after postStart: set the host's value globally.
fn as_the_extension(home: &Path, key: &str, value: &str) {
    let ok = Command::new("git")
        .args(["config", "--global", key, value])
        .env_clear()
        .env("HOME", home)
        .env("PATH", system_path())
        .status()
        .unwrap()
        .success();
    assert!(ok);
}

fn ok(o: &Output) {
    assert!(o.status.success(), "{}", text(o));
}

#[test]
fn it_keeps_signing_when_the_host_gitconfig_is_copied_over_it() {
    // #145: the extension copied the host's user.signingkey over agent-setup's, and commits went
    // to sign with a key the gateway's socket does not hold. The settings the relay needs must
    // survive any later `git config --global` of the same keys.
    let t = tempfile::tempdir().unwrap();
    let (shim, _) = shims(t.path(), Shims::default());
    let (o, home) = run(t.path(), &shim, &[]);
    ok(&o);
    let keydir = home.join(".ssh/sekimore");
    for (key, host_value) in [
        (
            "user.signingkey",
            "key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHOSTKEYHOSTKEYHOSTKEYHOSTKEYHOSTKEY host",
        ),
        ("gpg.format", "openpgp"),
        ("commit.gpgsign", "false"),
        (
            "gpg.ssh.allowedSignersFile",
            "/Users/operator/.ssh/allowed_signers",
        ),
        ("user.name", "The Operator"),
    ] {
        as_the_extension(&home, key, host_value);
    }
    assert_eq!(
        git_get(&home, "user.signingkey"),
        format!("{}/signing_ed25519.pub", keydir.display())
    );
    assert_eq!(git_get(&home, "gpg.format"), "ssh");
    assert_eq!(git_get(&home, "commit.gpgsign"), "true");
    assert_eq!(git_get(&home, "tag.gpgsign"), "true");
    assert_eq!(
        git_get(&home, "gpg.ssh.allowedSignersFile"),
        format!("{}/.config/git/allowed_signers", home.display())
    );
    // what agent-setup does not own is left to whoever set it
    assert_eq!(git_get(&home, "user.name"), "The Operator");
}

#[test]
fn it_keeps_one_include_and_keeps_it_last_across_restarts() {
    // Each start runs agent-setup again. An include left in the middle by the previous start,
    // with the extension's writes below it, would lose to them.
    let t = tempfile::tempdir().unwrap();
    let (shim, _) = shims(t.path(), Shims::default());
    let (_, home) = run(t.path(), &shim, &[]);
    as_the_extension(&home, "user.signingkey", "key::ssh-ed25519 AAAAHOST");
    // a key the file did not have: appended at the end
    as_the_extension(&home, "core.editor", "vim");
    let (o, _) = run(t.path(), &shim, &[]);
    ok(&o);
    let settings = t.path().join("etc/gitconfig");
    let include = format!("path = {}", settings.display());
    let lines: Vec<String> = read(home.join(".gitconfig"))
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(
        lines.iter().filter(|l| **l == include).count(),
        1,
        "{lines:?}"
    );
    assert_eq!(lines.last(), Some(&include), "{lines:?}");
    assert_eq!(
        git_get(&home, "user.signingkey"),
        format!("{}/.ssh/sekimore/signing_ed25519.pub", home.display())
    );
    assert_eq!(git_get(&home, "core.editor"), "vim");
}

#[test]
fn it_puts_the_settings_where_the_agent_cannot_write() {
    let t = tempfile::tempdir().unwrap();
    let (shim, _) = shims(t.path(), Shims::default());
    let (_, home) = run(t.path(), &shim, &[]);
    let settings = t.path().join("etc/gitconfig");
    assert_eq!(mode(&settings), 0o644);
    assert!(!settings.starts_with(&home));
    assert!(read(&settings).contains("signingkey = "));
}

#[test]
fn it_bootstraps_and_configures_everything_once() {
    let t = tempfile::tempdir().unwrap();
    let (shim, log) = shims(t.path(), Shims::default());
    let (o, home) = run(t.path(), &shim, &[]);
    let out = text(&o);
    ok(&o);
    assert!(
        !out.contains(&token()),
        "plaintext token must not appear in stdout or xtrace"
    );
    assert!(out.contains("received a project token"));

    let env_file = t.path().join("etc/env");
    assert_eq!(mode(&env_file), 0o600);
    let env = read(&env_file);
    let keydir = home.join(".ssh/sekimore");
    for want in [
        format!("SEKIMORE_IP={GW}"),
        format!("SEKIMORE_ENDPOINT=http://{GW}:8420"),
        format!("SEKIMORE_TOKEN={}", token()),
        "SEKIMORE_REPO=LibOrg/awesome-lib".into(),
        "SEKIMORE_GIT_DOMAIN=ghe.example.com".into(),
        // used by the `sekimore` wrapper to auto-refresh
        "SEKIMORE_TOKEN_EXPIRES=2026-01-01T00:00:00Z".into(),
        format!("SEKIMORE_AGENT_KEY={}/id_ed25519.pub", keydir.display()),
    ] {
        assert!(env.contains(&want), "{want} in {env}");
    }

    for k in ["id_ed25519", "signing_ed25519"] {
        assert!(keydir.join(k).exists() && keydir.join(format!("{k}.pub")).exists());
        assert_eq!(mode(&keydir.join(k)), 0o600);
    }

    let kh = read(home.join(".ssh/known_hosts"));
    let kh: Vec<&str> = kh.lines().collect();
    assert_eq!(kh.len(), 1, "{kh:?}");
    assert!(
        kh[0].starts_with(&format!(
            "ghe.example.com,{GW} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE"
        )),
        "{}",
        kh[0]
    );

    let cfg = read(home.join(".ssh/config"));
    assert_eq!(cfg.matches("# >>> sekimore-relay >>>").count(), 1);
    assert!(cfg.contains("Host ghe.example.com"));
    assert!(cfg.contains(&format!("IdentityFile {}/id_ed25519", keydir.display())));
    assert!(cfg.contains("IdentitiesOnly yes"));
    assert_eq!(mode(&home.join(".ssh/config")), 0o600);

    let gitconfig = read(home.join(".gitconfig"));
    assert!(gitconfig.contains("format = ssh"));
    assert!(gitconfig.contains(&format!(
        "signingkey = {}/signing_ed25519.pub",
        keydir.display()
    )));
    assert!(gitconfig.contains("gpgsign = true"));
    let signers = read(home.join(".config/git/allowed_signers"));
    let signers: Vec<&str> = signers.lines().collect();
    assert_eq!(signers.len(), 1);
    assert!(signers[0].starts_with("agent@example.invalid namespaces=\"git\" ssh-ed25519 "));

    let calls = read(&log);
    assert_eq!(calls.matches("bootstrap-called").count(), 1);
    assert!(!calls.contains("whoami-ok"));
}

#[test]
fn it_writes_a_host_block_and_known_hosts_entry_per_git_domain() {
    // 0.2.0: from /bootstrap's git_domains (default first), write a Host block per upstream and a
    // per-port known_hosts entry
    let multi = format!(
        r#"{{"ok":true,"fingerprint":"SHA256:x","added":true,"token":"{}","token_expires":"2026-01-01T00:00:00Z","project":"case-m","repos":["LibOrg/awesome-lib","ghe.example.com/Corp/Internal"],"git_domain":"github.com","upstream":"github.com","git_domains":[{{"domain":"github.com","ssh_port":22,"upstream":"github.com","default":true}},{{"domain":"ghe.example.com","ssh_port":2222,"upstream":"ghe.example.com","default":false}}]}}"#,
        token()
    );
    let t = tempfile::tempdir().unwrap();
    let (shim, log) = shims(
        t.path(),
        Shims {
            valid_token: Some(token()),
            bootstrap_json: Some(multi),
            ..Shims::default()
        },
    );
    let (o, home) = run(t.path(), &shim, &[]);
    ok(&o);

    let env = read(t.path().join("etc/env"));
    assert!(env.contains("SEKIMORE_GIT_DOMAIN=github.com"));
    assert!(env.contains("SEKIMORE_GIT_DOMAINS=github.com:22,ghe.example.com:2222"));

    let mut kh: Vec<String> = read(home.join(".ssh/known_hosts"))
        .lines()
        .map(String::from)
        .collect();
    kh.sort();
    assert_eq!(kh.len(), 2, "{kh:?}");
    assert!(kh[0].starts_with(&format!("[ghe.example.com]:2222,[{GW}]:2222 ssh-ed25519 ")));
    assert!(kh[1].starts_with(&format!("github.com,{GW} ssh-ed25519 ")));
    let calls = read(&log);
    assert!(calls.contains(&format!("ssh-keyscan -T 3 -p 22 {GW}")));
    assert!(calls.contains(&format!("ssh-keyscan -T 3 -p 2222 {GW}")));

    let cfg = read(home.join(".ssh/config"));
    assert_eq!(cfg.matches("# >>> sekimore-relay >>>").count(), 1);
    assert_eq!(cfg.matches("# <<< sekimore-relay <<<").count(), 1);
    let blocks: Vec<(String, String)> = Regex::new(r"Host (\S+)\n  User git\n  Port (\d+)\n")
        .unwrap()
        .captures_iter(&cfg)
        .map(|m| (m[1].to_string(), m[2].to_string()))
        .collect();
    assert_eq!(
        blocks,
        [
            ("github.com".to_string(), "22".to_string()),
            ("ghe.example.com".to_string(), "2222".to_string())
        ],
        "{cfg}"
    );

    // A second run (valid token, so no bootstrap) reproduces the same from SEKIMORE_GIT_DOMAINS
    // in the env file, without duplicates
    let (o, home) = run(t.path(), &shim, &[]);
    ok(&o);
    assert_eq!(read(&log).matches("bootstrap-called").count(), 1);
    assert_eq!(read(home.join(".ssh/known_hosts")).lines().count(), 2);
    let cfg = read(home.join(".ssh/config"));
    assert_eq!(cfg.matches("Host ghe.example.com").count(), 1);
    assert_eq!(cfg.matches("Host github.com").count(), 1);
}

#[test]
fn it_writes_agent_instructions_for_claude_and_codex_idempotently() {
    // 0.2.2: install the guide as a Claude Code skill and as a block in Codex's AGENTS.md
    let t = tempfile::tempdir().unwrap();
    let (shim, _) = shims(
        t.path(),
        Shims {
            valid_token: Some(token()),
            ..Shims::default()
        },
    );
    let (o, home) = run(t.path(), &shim, &[]);
    ok(&o);
    let skill = home.join(".claude/skills/sgw-agent/SKILL.md");
    let skill_text = read(&skill);
    assert!(skill_text.starts_with("---\nname: sgw-agent\n"));
    for want in ["sekimore-relay 9.9.9", "# guide (shim)", "Use sekimore."] {
        assert!(skill_text.contains(want), "{want}");
    }
    let agents = home.join(".codex/AGENTS.md");
    let atext = read(&agents);
    assert_eq!(atext.matches("<!-- >>> sekimore-relay >>> -->").count(), 1);
    assert!(atext.contains("`sgw-agent guide`") && atext.contains("sgw-agent whoami"));
    // Existing AGENTS.md content is preserved; only the block is replaced
    std::fs::write(&agents, format!("# my own notes\n\n{atext}")).unwrap();
    let (o, _) = run(t.path(), &shim, &[]);
    ok(&o);
    let atext = read(&agents);
    assert!(atext.starts_with("# my own notes"));
    assert_eq!(atext.matches("<!-- >>> sekimore-relay >>> -->").count(), 1);
    assert_eq!(read(&skill), skill_text);
}

#[test]
fn it_can_skip_agent_instructions() {
    let t = tempfile::tempdir().unwrap();
    let (shim, _) = shims(
        t.path(),
        Shims {
            valid_token: Some(token()),
            ..Shims::default()
        },
    );
    let (o, home) = run(t.path(), &shim, &[("SEKIMORE_AGENT_INSTRUCTIONS", "none")]);
    ok(&o);
    assert!(!home.join(".claude/skills").exists());
    assert!(!home.join(".codex").exists());
}

#[test]
fn it_is_idempotent_and_keeps_a_valid_token() {
    let t = tempfile::tempdir().unwrap();
    let (shim, _) = shims(t.path(), Shims::default());
    let (o, home) = run(t.path(), &shim, &[]);
    ok(&o);
    let keydir = home.join(".ssh/sekimore");
    let pub_before = read(keydir.join("id_ed25519.pub"));
    let sign_before = read(keydir.join("signing_ed25519.pub"));

    // Second run: the existing token passes /whoami, so bootstrap is skipped, the keys stay put,
    // and nothing is appended again
    let (shim, log) = shims(
        t.path(),
        Shims {
            valid_token: Some(token()),
            ..Shims::default()
        },
    );
    std::fs::write(&log, "").unwrap();
    let (o, home) = run(t.path(), &shim, &[]);
    let out = text(&o);
    ok(&o);
    assert!(out.contains("still valid"));
    assert_eq!(read(keydir.join("id_ed25519.pub")), pub_before);
    assert_eq!(read(keydir.join("signing_ed25519.pub")), sign_before);
    assert!(read(t.path().join("etc/env")).contains(&format!("SEKIMORE_TOKEN={}", token())));
    let calls = read(&log);
    assert!(!calls.contains("bootstrap-called") && calls.contains("whoami-ok"));
    assert_eq!(read(home.join(".ssh/known_hosts")).lines().count(), 1);
    assert_eq!(
        read(home.join(".ssh/config"))
            .matches("# >>> sekimore-relay >>>")
            .count(),
        1
    );
    assert_eq!(
        read(home.join(".config/git/allowed_signers"))
            .lines()
            .count(),
        1
    );
    assert!(!out.contains(&token()));
}

#[test]
fn it_skips_when_the_gateway_has_no_relay() {
    let t = tempfile::tempdir().unwrap();
    let (shim, log) = shims(
        t.path(),
        Shims {
            relay_present: false,
            ..Shims::default()
        },
    );
    let (o, home) = run(t.path(), &shim, &[]);
    ok(&o);
    assert!(String::from_utf8_lossy(&o.stdout).contains("skipping"));
    assert!(!t.path().join("etc/env").exists());
    assert!(!home.join(".ssh").exists());
    assert!(!read(&log).contains("bootstrap-called"));
}

#[test]
fn it_does_not_bootstrap_in_manual_mode() {
    let t = tempfile::tempdir().unwrap();
    let (shim, log) = shims(t.path(), Shims::default());
    let (o, home) = run(
        t.path(),
        &shim,
        &[
            ("SEKIMORE_BOOTSTRAP", "manual"),
            ("SEKIMORE_GIT_DOMAIN", "github.com"),
        ],
    );
    ok(&o);
    assert!(text(&o).contains("manual"));
    assert!(!read(&log).contains("bootstrap-called"));
    let env = read(t.path().join("etc/env"));
    assert!(!env.contains("SEKIMORE_TOKEN") && env.contains("SEKIMORE_GIT_DOMAIN=github.com"));
    // Keys, known_hosts, and the ssh config are still created (so the operator can add-key)
    assert!(home.join(".ssh/sekimore/id_ed25519.pub").exists());
    assert!(read(home.join(".ssh/config")).contains("Host github.com"));
}

#[test]
fn it_warns_but_continues_when_bootstrap_is_denied() {
    let t = tempfile::tempdir().unwrap();
    let (shim, _) = shims(
        t.path(),
        Shims {
            bootstrap_json: Some(
                r#"{"ok":false,"error":"bootstrap is disabled by the operator"}"#.into(),
            ),
            ..Shims::default()
        },
    );
    let (o, home) = run(t.path(), &shim, &[]);
    let out = text(&o);
    ok(&o);
    assert!(out.contains("did not return a token") && out.contains("sekimore-relay add-key"));
    assert!(!read(t.path().join("etc/env")).contains("SEKIMORE_TOKEN"));
    assert!(home.join(".ssh/known_hosts").exists());
}

#[test]
fn it_uses_bracketed_known_hosts_for_non_default_port() {
    let t = tempfile::tempdir().unwrap();
    let (shim, log) = shims(t.path(), Shims::default());
    let (o, home) = run(t.path(), &shim, &[("SEKIMORE_RELAY_SSH_PORT", "2222")]);
    ok(&o);
    assert!(read(home.join(".ssh/known_hosts"))
        .starts_with(&format!("[ghe.example.com]:2222,[{GW}]:2222 ssh-ed25519 ")));
    assert!(read(home.join(".ssh/config")).contains("Port 2222"));
    assert!(Regex::new(r"ssh-keyscan .*-p 2222")
        .unwrap()
        .is_match(&read(&log)));
}

/// A real ssh-agent holding one key. From agent-setup.sh's side this is indistinguishable from
/// the gateway's filtered socket, which is the point: dev needs no sekimore-specific code to
/// sign, only SSH_AUTH_SOCK. The private key is removed afterwards, so nothing here can sign
/// without the agent. Killed when dropped.
struct SigningAgent {
    _dir: tempfile::TempDir,
    sock: PathBuf,
    public: String,
    pid: String,
}

impl Drop for SigningAgent {
    fn drop(&mut self) {
        let _ = Command::new("ssh-agent")
            .arg("-k")
            .env("SSH_AGENT_PID", &self.pid)
            .output();
    }
}

fn have(tool: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {tool}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// `None` (the test is skipped) when ssh-agent, ssh-add or ssh-keygen is missing, unless
/// SEKIMORE_E2E_REQUIRED says they must be there (CI and `mise run ci` set it).
fn signing_agent() -> Option<SigningAgent> {
    for tool in ["ssh-agent", "ssh-add", "ssh-keygen"] {
        if !have(tool) {
            assert!(
                std::env::var_os("SEKIMORE_E2E_REQUIRED").is_none(),
                "{tool} is not available and SEKIMORE_E2E_REQUIRED is set"
            );
            eprintln!("skipped: {tool} is not available");
            return None;
        }
    }
    // a Unix socket path is limited to ~100 bytes, so not under a long TMPDIR
    let dir = tempfile::Builder::new()
        .prefix("sa")
        .tempdir_in("/tmp")
        .unwrap();
    let sock = dir.path().join("agent.sock");
    let key = dir.path().join("operator_ed25519");
    let st = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "operator signing key",
            "-f",
        ])
        .arg(&key)
        .output()
        .unwrap();
    assert!(st.status.success(), "{}", text(&st));
    let out = Command::new("ssh-agent")
        .arg("-a")
        .arg(&sock)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let pid = stdout
        .split("SSH_AGENT_PID=")
        .nth(1)
        .and_then(|r| r.split(';').next())
        .expect("ssh-agent prints its pid")
        .to_string();
    let agent = SigningAgent {
        public: read(dir.path().join("operator_ed25519.pub"))
            .trim()
            .to_string(),
        sock,
        pid,
        _dir: dir,
    };
    let add = Command::new("ssh-add")
        .arg(&key)
        .env("SSH_AUTH_SOCK", &agent.sock)
        .output()
        .unwrap();
    assert!(add.status.success(), "{}", text(&add));
    std::fs::remove_file(&key).unwrap();
    Some(agent)
}

fn bootstrap_with_signing(socket: &str, mode: &str) -> String {
    format!(
        r#"{{"ok":true,"fingerprint":"SHA256:x","added":true,"token":"{}","token_expires":"2026-01-01T00:00:00Z","project":"case-a","repos":["LibOrg/awesome-lib"],"git_domain":"ghe.example.com","upstream":"ghe.example.com","signing":{{"socket":"{socket}","fingerprint":"SHA256:opkeyfingerprint","namespace":"git","public_key":"ssh-ed25519 AAAAFAKE operator signing key","mode":"{mode}"}}}}"#,
        token()
    )
}

fn signing_shims(dir: &Path, socket: &str, mode: &str) -> (PathBuf, PathBuf) {
    shims(
        dir,
        Shims {
            bootstrap_json: Some(bootstrap_with_signing(socket, mode)),
            ..Shims::default()
        },
    )
}

#[test]
fn it_writes_the_signing_section_into_the_guide_only_when_it_is_required() {
    // #59: an agent is told about the rule where the relay enforces it. `optional` asks nothing
    // of the agent, and a paragraph about a rule that does not apply is how the paragraphs that
    // do apply stop being read.
    let Some(agent) = signing_agent() else { return };
    let t = tempfile::tempdir().unwrap();
    for (mode, expected) in [("optional", false), ("required", true)] {
        let run_dir = t.path().join(mode);
        std::fs::create_dir_all(&run_dir).unwrap();
        let (shim, _) = signing_shims(&run_dir, &agent.sock.display().to_string(), mode);
        let (o, home) = run(&run_dir, &shim, &[]);
        ok(&o);
        let skill = read(home.join(".claude/skills/sgw-agent/SKILL.md"));
        let codex = read(home.join(".codex/AGENTS.md"));
        assert_eq!(
            skill.contains("Signing is required here"),
            expected,
            "{mode}"
        );
        assert_eq!(skill.contains("git commit -S --amend"), expected, "{mode}");
        assert_eq!(codex.contains("has to be signed"), expected, "{mode}");
        assert!(read(run_dir.join("etc/env")).contains(&format!("SEKIMORE_SIGNING_MODE={mode}")));
    }
}

#[test]
fn it_says_loudly_when_signing_is_required_and_there_is_no_key() {
    // The combination that refuses every push. It must not be something you find out later.
    let t = tempfile::tempdir().unwrap();
    let absent = t.path().join("absent.sock").display().to_string();
    let (shim, _) = signing_shims(t.path(), &absent, "required");
    let (o, home) = run(t.path(), &shim, &[]);
    ok(&o);
    assert!(text(&o).contains("signing: required and there is no key"));
    assert!(read(home.join(".gitconfig")).contains("gpgsign = false"));
}

#[test]
fn it_signs_through_the_gateway_socket_and_generates_no_key_of_its_own() {
    // #59: with a signing socket offered, nothing is generated here and nothing is registered.
    // The key that signs is the operator's, held on the host. What lands in the container is the
    // public half and a socket path — which is what makes the key able to outlive the volume.
    let Some(agent) = signing_agent() else { return };
    let t = tempfile::tempdir().unwrap();
    let sock = agent.sock.display().to_string();
    let (shim, _) = signing_shims(t.path(), &sock, "optional");
    let (o, home) = run(t.path(), &shim, &[]);
    let out = text(&o);
    ok(&o);
    let keydir = home.join(".ssh/sekimore");
    // The disposable auth key is untouched; the signing key is NOT generated
    assert!(keydir.join("id_ed25519").exists());
    assert!(
        !keydir.join("signing_ed25519").exists(),
        "no key may be generated here"
    );
    assert_eq!(read(keydir.join("signing.pub")).trim(), agent.public);
    assert_eq!(mode(&keydir.join("signing.pub")), 0o644);

    let gitconfig = read(home.join(".gitconfig"));
    assert!(gitconfig.contains(&format!("signingkey = {}/signing.pub", keydir.display())));
    assert!(gitconfig.contains("gpgsign = true"));

    let env = read(t.path().join("etc/env"));
    assert!(env.contains(&format!("SSH_AUTH_SOCK={sock}")));
    assert!(env.contains(&format!("SEKIMORE_SIGNING_SOCK={sock}")));
    assert!(env.contains("SEKIMORE_SIGNING_KEY=SHA256:opkeyfingerprint"));

    let signers = read(home.join(".config/git/allowed_signers"));
    let signers: Vec<&str> = signers.lines().collect();
    assert_eq!(signers.len(), 1);
    let key_part: Vec<&str> = agent.public.split_whitespace().take(2).collect();
    assert!(signers[0].ends_with(&key_part.join(" ")));
    assert!(out.contains("filtered agent"));
}

#[test]
fn it_does_not_sign_at_all_when_the_offered_socket_is_missing() {
    // A named socket that is not in the container means the shared volume was not mounted.
    // Falling back to a generated key would quietly reintroduce #59 — an unregistered key
    // signing everything — so signing is turned off instead, loudly.
    let t = tempfile::tempdir().unwrap();
    let absent = t.path().join("absent.sock").display().to_string();
    let (shim, _) = signing_shims(t.path(), &absent, "optional");
    let (o, home) = run(t.path(), &shim, &[]);
    let out = text(&o);
    ok(&o);
    assert!(!home.join(".ssh/sekimore/signing_ed25519").exists());
    assert!(!home.join(".ssh/sekimore/signing.pub").exists());
    let gitconfig = read(home.join(".gitconfig"));
    assert!(gitconfig.contains("gpgsign = false"));
    assert!(!gitconfig.contains("gpgsign = true"));
    assert!(out.contains("not in this container"));
    assert!(out.contains("NOT be signed"));
}

#[test]
fn it_stops_signing_when_the_socket_stops_holding_the_key() {
    // The gateway offers the socket, the host agent has lost the key. This is the state #59 was
    // found in — a key that had silently gone. It has to be said out loud and it must not be
    // replaced by a substitute.
    let Some(agent) = signing_agent() else { return };
    let cleared = Command::new("ssh-add")
        .arg("-D")
        .env("SSH_AUTH_SOCK", &agent.sock)
        .output()
        .unwrap();
    assert!(cleared.status.success(), "{}", text(&cleared));
    let t = tempfile::tempdir().unwrap();
    let (shim, _) = signing_shims(t.path(), &agent.sock.display().to_string(), "optional");
    let (o, home) = run(t.path(), &shim, &[]);
    let out = text(&o);
    ok(&o);
    assert!(!home.join(".ssh/sekimore/signing_ed25519").exists());
    assert!(read(home.join(".gitconfig")).contains("gpgsign = false"));
    assert!(out.contains("holds no key"));
    assert!(out.contains("SHA256:opkeyfingerprint"));
}

#[test]
fn it_remembers_the_signing_socket_across_a_run_that_keeps_its_token() {
    // A run that skips /bootstrap still has to find the socket, or signing would flap off.
    let Some(agent) = signing_agent() else { return };
    let t = tempfile::tempdir().unwrap();
    let sock = agent.sock.display().to_string();
    let (shim, log) = shims(
        t.path(),
        Shims {
            valid_token: Some(token()),
            bootstrap_json: Some(bootstrap_with_signing(&sock, "optional")),
            ..Shims::default()
        },
    );
    // the first run bootstraps and caches; the second keeps its token and never calls /bootstrap
    run(t.path(), &shim, &[]);
    let (o, home) = run(t.path(), &shim, &[]);
    ok(&o);
    assert_eq!(read(&log).matches("bootstrap-called").count(), 1);
    assert_eq!(
        read(home.join(".ssh/sekimore/signing.pub")).trim(),
        agent.public
    );
    assert!(read(t.path().join("etc/env")).contains(&format!("SSH_AUTH_SOCK={sock}")));
    assert!(read(home.join(".gitconfig")).contains("gpgsign = true"));
}

/// `ssh-keygen -c`: change the comment of a key, as the old default did.
fn recomment(key: &Path, comment: &str) {
    let o = Command::new("ssh-keygen")
        .args(["-q", "-c", "-C", comment, "-P", "", "-f"])
        .arg(key)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", text(&o));
}

fn key_part(public: &str) -> String {
    public.split(' ').take(2).collect::<Vec<_>>().join(" ")
}

#[test]
fn it_names_the_signing_key_after_the_operator_and_project() {
    // The signing key comment becomes the Title when registered on GitHub. It carries the project
    // name plus git's user.name / user.email, can be overridden with
    // SEKIMORE_SIGNING_KEY_COMMENT, and an existing key still on the old default (…@<hostname>)
    // is updated to the named form.
    let t = tempfile::tempdir().unwrap();
    let (shim, _) = shims(t.path(), Shims::default());
    let home = t.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    as_the_extension(&home, "user.name", "Taro Test");
    as_the_extension(&home, "user.email", "taro@example.com");
    let keydir = home.join(".ssh/sekimore");
    let named = " sekimore-agent-signing: case-a / Taro Test <taro@example.com>";

    let (o, home) = run(t.path(), &shim, &[("SEKIMORE_PROJECT", "case-a")]);
    ok(&o);
    let public = read(keydir.join("signing_ed25519.pub"))
        .trim_end_matches('\n')
        .to_string();
    assert!(public.ends_with(named), "{public}");
    let key = key_part(&public);
    // allowed_signers holds only the key without the comment (so comments with spaces do not
    // affect it)
    let signers = read(home.join(".config/git/allowed_signers"));
    assert!(signers.contains(&key) && !signers.contains("Taro Test"));

    // A key still carrying the old default comment is updated to the named form on the second
    // run; the key (fingerprint) is unchanged
    recomment(
        &keydir.join("signing_ed25519"),
        "sekimore-agent-signing@oldhost",
    );
    let (shim, _) = shims(
        t.path(),
        Shims {
            valid_token: Some(token()),
            ..Shims::default()
        },
    );
    let (o, _) = run(t.path(), &shim, &[("SEKIMORE_PROJECT", "case-a")]);
    ok(&o);
    let public2 = read(keydir.join("signing_ed25519.pub"))
        .trim_end_matches('\n')
        .to_string();
    assert!(public2.ends_with(named), "{public2}");
    assert_eq!(key_part(&public2), key);

    // An explicit operator-supplied comment is applied to the existing key too (the key is
    // unchanged)
    let (o, _) = run(
        t.path(),
        &shim,
        &[("SEKIMORE_SIGNING_KEY_COMMENT", "my agent key")],
    );
    ok(&o);
    let public3 = read(keydir.join("signing_ed25519.pub"))
        .trim_end_matches('\n')
        .to_string();
    assert!(public3.ends_with(" my agent key"), "{public3}");
    assert_eq!(key_part(&public3), key);
}

#[test]
fn it_falls_back_to_hostname_when_no_identity_is_known() {
    let t = tempfile::tempdir().unwrap();
    let (shim, _) = shims(t.path(), Shims::default());
    let (o, home) = run(t.path(), &shim, &[]);
    ok(&o);
    let public = read(home.join(".ssh/sekimore/signing_ed25519.pub"));
    assert!(
        Regex::new(r" sekimore-agent-signing@\S+$")
            .unwrap()
            .is_match(public.trim_end_matches('\n')),
        "{public}"
    );
}

#[test]
fn it_keeps_the_token_out_of_the_output_without_xtrace_too() {
    let t = tempfile::tempdir().unwrap();
    let (shim, _) = shims(t.path(), Shims::default());
    let (o, _) = run_traced(t.path(), &shim, &[], false);
    ok(&o);
    assert!(!text(&o).contains(&token()));
}

// ---- the proxy environment (#212) ----
//
// The whole script cannot be sourced for these — it discovers the gateway and rewrites
// /etc/resolv.conf at the top level — so the proxy functions are cut out at the markers that
// bracket them and run against a temp root (`SEKIMORE_PROXY_ENV_ROOT`) with the JSON the gateway
// would have answered.

const CONFIGURED: &str = r#"{"configured":true,"port":3128,"no_proxy":["api.github.com","registry.npmjs.org",".test","localhost","127.0.0.1","sekimore-gw"],"direct_egress":"deny"}"#;
const UNCONFIGURED: &str = r#"{"configured":false,"port":3128,"no_proxy":["localhost","127.0.0.1","sekimore-gw"],"direct_egress":"allow"}"#;
const NO_PROXY: &str = "api.github.com,registry.npmjs.org,.test,localhost,127.0.0.1,sekimore-gw";

/// The proxy functions, cut from the script at the markers that bracket them.
fn functions(dir: &Path) -> PathBuf {
    let body = read(script());
    let start = body
        .find("SEKIMORE_PROXY_MARK_BEGIN='")
        .expect("the start marker");
    let end = body
        .find("sekimore_relay_setup() {")
        .expect("the end marker");
    let out = dir.join("fn.sh");
    std::fs::write(&out, &body[start..end]).unwrap();
    out
}

/// Runs the calls with `set -e` against `<dir>/root`; panics if they fail.
fn proxy(dir: &Path, calls: &[String]) -> String {
    let root = dir.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let mut lines = vec![
        "set -e".to_string(),
        format!(". {}", functions(dir).display()),
        format!("export SEKIMORE_PROXY_ENV_ROOT=\"{}\"", root.display()),
    ];
    lines.extend(calls.iter().cloned());
    let o = Command::new("bash")
        .arg("-c")
        .arg(lines.join("\n"))
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", text(&o));
    String::from_utf8(o.stdout).unwrap()
}

fn apply(json: &str, gw: &str) -> String {
    format!("sekimore_proxy_env_apply '{json}' {gw}")
}

#[test]
fn it_writes_both_files_when_a_proxy_is_configured() {
    let t = tempfile::tempdir().unwrap();
    proxy(t.path(), &[apply(CONFIGURED, "10.100.0.2")]);
    let profile = read(t.path().join("root/etc/profile.d/sekimore-proxy.sh"));
    let env = read(t.path().join("root/etc/environment"));
    for var in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        assert!(profile.contains(&format!("export {var}=\"http://10.100.0.2:3128\"")));
        assert!(env.contains(&format!("{var}=\"http://10.100.0.2:3128\"")));
    }
    // Squid refuses CONNECT to the handler targets, so NO_PROXY has to carry them or the GitHub
    // API and npm break with a 403 from the proxy.
    for var in ["NO_PROXY", "no_proxy"] {
        assert!(profile.contains(&format!("{var}=\"{NO_PROXY}\"")));
        assert!(env.contains(&format!("{var}=\"{NO_PROXY}\"")));
    }
}

#[test]
fn it_brackets_the_environment_block_with_markers() {
    let t = tempfile::tempdir().unwrap();
    proxy(t.path(), &[apply(CONFIGURED, "10.100.0.2")]);
    let env = read(t.path().join("root/etc/environment"));
    assert_eq!(env.matches("# sekimore-proxy begin").count(), 1);
    assert_eq!(env.matches("# sekimore-proxy end").count(), 1);
}

#[test]
fn it_replaces_instead_of_appending_on_every_start() {
    // postStartCommand runs on every start; appending would grow the file without bound and
    // leave a stale gateway address above the current one.
    let t = tempfile::tempdir().unwrap();
    proxy(
        t.path(),
        &[
            apply(CONFIGURED, "10.100.0.2"),
            apply(CONFIGURED, "10.100.0.9"),
        ],
    );
    let env = read(t.path().join("root/etc/environment"));
    assert_eq!(env.matches("HTTP_PROXY=\"").count(), 1);
    assert!(env.contains("10.100.0.9"));
    assert!(!env.contains("10.100.0.2"));
}

#[test]
fn it_keeps_what_was_already_in_the_environment_file() {
    let t = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(t.path().join("root/etc")).unwrap();
    std::fs::write(t.path().join("root/etc/environment"), "PATH=\"/usr/bin\"\n").unwrap();
    proxy(t.path(), &[apply(CONFIGURED, "10.100.0.2")]);
    let env = read(t.path().join("root/etc/environment"));
    assert!(env.contains("PATH=\"/usr/bin\""));
    assert!(env.contains("HTTP_PROXY"));
}

#[test]
fn it_removes_both_when_no_proxy_is_configured() {
    // A container that had a proxy and no longer does must stop sending traffic at it.
    let t = tempfile::tempdir().unwrap();
    proxy(
        t.path(),
        &[
            apply(CONFIGURED, "10.100.0.2"),
            apply(UNCONFIGURED, "10.100.0.2"),
        ],
    );
    assert!(!t
        .path()
        .join("root/etc/profile.d/sekimore-proxy.sh")
        .exists());
    assert!(!read(t.path().join("root/etc/environment")).contains("HTTP_PROXY"));
}

#[test]
fn it_says_what_it_set() {
    let t = tempfile::tempdir().unwrap();
    let out = proxy(t.path(), &[apply(CONFIGURED, "10.100.0.2")]);
    assert!(out.contains("HTTP_PROXY=http://10.100.0.2:3128"), "{out}");
    assert!(out.contains("direct_egress: deny"), "{out}");
}

#[test]
fn it_says_when_there_is_nothing_to_set() {
    let t = tempfile::tempdir().unwrap();
    let out = proxy(t.path(), &[apply(UNCONFIGURED, "10.100.0.2")]);
    assert!(out.contains("no upstream proxy configured"), "{out}");
}

#[test]
fn the_profile_file_is_valid_shell() {
    let t = tempfile::tempdir().unwrap();
    proxy(t.path(), &[apply(CONFIGURED, "10.100.0.2")]);
    let profile = t.path().join("root/etc/profile.d/sekimore-proxy.sh");
    let o = Command::new("bash")
        .arg("-n")
        .arg(&profile)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", text(&o));
}

// The JSON is read without jq: the agent image may not have it.

#[test]
fn it_reads_a_string_field() {
    let t = tempfile::tempdir().unwrap();
    let out = proxy(
        t.path(),
        &[format!("sekimore_json_field '{CONFIGURED}' direct_egress")],
    );
    assert_eq!(out.trim(), "deny");
}

#[test]
fn it_reads_a_boolean_and_a_number() {
    let t = tempfile::tempdir().unwrap();
    let out = proxy(
        t.path(),
        &[
            format!("sekimore_json_field '{CONFIGURED}' configured"),
            format!("sekimore_json_field '{CONFIGURED}' port"),
        ],
    );
    assert_eq!(out.split_whitespace().collect::<Vec<_>>(), ["true", "3128"]);
}

#[test]
fn it_joins_the_no_proxy_array_with_commas() {
    let t = tempfile::tempdir().unwrap();
    let out = proxy(
        t.path(),
        &[format!("sekimore_json_no_proxy '{CONFIGURED}'")],
    );
    assert_eq!(out.trim(), NO_PROXY);
}

#[test]
fn it_handles_an_empty_no_proxy_array() {
    let t = tempfile::tempdir().unwrap();
    let out = proxy(
        t.path(),
        &["sekimore_json_no_proxy '{\"no_proxy\":[]}'".to_string()],
    );
    assert_eq!(out.trim(), "");
}
