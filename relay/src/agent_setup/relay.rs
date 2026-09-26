//! Steps 1–9 and 12: everything the relay side of the dev container needs, the way
//! `sekimore_relay_setup` in agent-setup.sh wrote it. Run as root; the agent user owns the result.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context};

use super::files::{
    chmod, chown, chown_all, ensure_dir, hostname, is_root, on_path, read_or_empty, run,
    write_atomic, MarkedBlock, Owner,
};
use super::Settings;
use crate::api::types::{ApiRequest, BootstrapRequest, BootstrapResponse};
use crate::cli::agent::standalone::parse_env;

pub const SSH_CONFIG_MARK: MarkedBlock = MarkedBlock {
    begin: "# >>> sekimore-relay >>>",
    end: "# <<< sekimore-relay <<<",
};

/// One upstream as the ssh config and known_hosts see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub domain: String,
    pub port: u16,
}

/// `domain:port,domain:port` ↔ the list. The first is the default.
pub fn parse_domains(s: &str) -> Vec<Upstream> {
    s.split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(|e| {
            let (d, p) = e.rsplit_once(':').unwrap_or((e, ""));
            Upstream {
                domain: d.to_string(),
                port: p.parse().unwrap_or(22),
            }
        })
        .collect()
}

pub fn domains_string(v: &[Upstream]) -> String {
    v.iter()
        .map(|u| format!("{}:{}", u.domain, u.port))
        .collect::<Vec<_>>()
        .join(",")
}

/// The default domain first; a list that omits it gets it in front.
pub fn with_default_first(mut v: Vec<Upstream>, default: &str, ssh_port: u16) -> Vec<Upstream> {
    if v.is_empty() {
        return vec![Upstream {
            domain: default.to_string(),
            port: ssh_port,
        }];
    }
    if !v.iter().any(|u| u.domain == default) {
        v.insert(
            0,
            Upstream {
                domain: default.to_string(),
                port: ssh_port,
            },
        );
    }
    v
}

/// known_hosts without the entries for `hosts` (a name matches when it is one of the
/// comma-separated names in a line's first field). What `ssh-keygen -R` did, without the
/// `.old` file.
pub fn known_hosts_without(text: &str, hosts: &[String]) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let first = line.split_whitespace().next().unwrap_or("");
        let named = first.split(',').any(|n| hosts.iter().any(|h| h == n));
        if line.starts_with('#') || !named {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// The keyscan output with each key line's first field replaced by `hostnames`.
pub fn known_hosts_lines(keyscan: &str, hostnames: &str) -> String {
    let mut out = String::new();
    for line in keyscan.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut f = line.split_whitespace();
        let _ = f.next();
        let rest: Vec<&str> = f.collect();
        out.push_str(hostnames);
        for r in rest {
            out.push(' ');
            out.push_str(r);
        }
        out.push('\n');
    }
    out
}

pub fn ssh_config_block(ups: &[Upstream], keyfile: &Path) -> String {
    let mut s = String::new();
    for u in ups {
        s.push_str(&format!(
            "Host {}\n  User git\n  Port {}\n  IdentityFile {}\n  IdentitiesOnly yes\n",
            u.domain,
            u.port,
            keyfile.display()
        ));
    }
    s
}

/// The root-owned git config file `~/.gitconfig` includes last (#145).
pub fn signing_gitconfig(signers: &Path, key: Option<&Path>) -> String {
    let gpgsign = key.is_some();
    let mut s = String::from(
        "# Written by sgw-agent setup on every start. ~/.gitconfig includes this last, so\n\
         # these win over anything written above them later (the Dev Containers extension copies the\n\
         # host's user.* in). Do not turn signing off: see the agent guide.\n",
    );
    s.push_str(&format!(
        "[gpg]\n\tformat = ssh\n[gpg \"ssh\"]\n\tallowedSignersFile = {}\n",
        signers.display()
    ));
    if let Some(k) = key {
        s.push_str(&format!("[user]\n\tsigningkey = {}\n", k.display()));
    }
    s.push_str(&format!(
        "[commit]\n\tgpgsign = {gpgsign}\n[tag]\n\tgpgsign = {gpgsign}\n"
    ));
    s
}

/// The signing key's comment, the title GitHub shows: `sekimore-agent-signing: <project> / <name> <email>`.
pub fn signing_key_comment(settings: &Settings, home: &Path) -> String {
    if let Some(c) = &settings.signing_key_comment {
        return c.clone();
    }
    let g = |k: &str| {
        Command::new("git")
            .env("HOME", home)
            .args(["config", "--global", "--get", k])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };
    let who = format!("{} {}", g("user.name"), g("user.email"));
    let who = who.trim();
    match (&settings.project, who.is_empty()) {
        (Some(p), false) => format!("sekimore-agent-signing: {p} / {who}"),
        (Some(p), true) => format!("sekimore-agent-signing: {p}"),
        (None, false) => format!("sekimore-agent-signing: {who}"),
        (None, true) => "sekimore-agent-signing".to_string(),
    }
}

pub struct Outcome {
    pub git_domains: String,
    pub token: bool,
    pub signing: Signing,
    pub sig_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signing {
    Gateway { socket: String, public: String },
    Generated { public: String, path: PathBuf },
    None,
}

fn http(secs: u64) -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(secs))
        .build()?)
}

/// Whether the relay answers on the gateway.
pub async fn relay_present(endpoint: &str) -> bool {
    let Ok(c) = http(3) else { return false };
    match c.get(format!("{endpoint}/healthz")).send().await {
        Ok(r) => r.status().is_success(),
        Err(_) => false,
    }
}

async fn token_valid(endpoint: &str, token: &str) -> bool {
    let Ok(c) = http(5) else { return false };
    matches!(
        c.post(format!("{endpoint}/whoami"))
            .bearer_auth(token)
            .json(&ApiRequest::default())
            .send()
            .await,
        Ok(r) if r.status().is_success()
    )
}

async fn bootstrap(endpoint: &str, public_key: &str) -> Option<BootstrapResponse> {
    let c = http(10).ok()?;
    c.post(format!("{endpoint}/bootstrap"))
        .json(&BootstrapRequest {
            public_key: public_key.to_string(),
            label: Some(hostname()),
        })
        .send()
        .await
        .ok()?
        .json::<BootstrapResponse>()
        .await
        .ok()
}

/// `ssh-add -L` against a socket: the exit status decides, not the output (an empty agent prints
/// "The agent has no identities." on stdout and exits 1).
fn agent_keys(ssh_add: &str, socket: &str) -> Option<String> {
    let o = Command::new(ssh_add)
        .arg("-L")
        .env("SSH_AUTH_SOCK", socket)
        .output()
        .ok()?;
    if !o.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn keygen(ssh_keygen: &str, path: &Path, comment: &str) -> anyhow::Result<()> {
    run(Command::new(ssh_keygen)
        .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(path))
    .with_context(|| format!("ssh-keygen {}", path.display()))?;
    Ok(())
}

/// The generated signing key: made when absent; a comment still on an old default is updated
/// (the fingerprint does not change).
fn ensure_signing_key(ssh_keygen: &str, keydir: &Path, comment: &str) -> anyhow::Result<()> {
    let key = keydir.join("signing_ed25519");
    let pubf = keydir.join("signing_ed25519.pub");
    if !key.is_file() {
        keygen(ssh_keygen, &key, comment)?;
        return Ok(());
    }
    let current = read_or_empty(&pubf);
    let current_comment = current
        .trim()
        .splitn(3, ' ')
        .nth(2)
        .unwrap_or("")
        .to_string();
    let old_default = current_comment.is_empty()
        || current_comment == "sekimore-agent-signing"
        || current_comment.starts_with("sekimore-agent-signing@");
    if old_default && current_comment != comment {
        let _ = Command::new(ssh_keygen)
            .args(["-q", "-c", "-C", comment, "-P", "", "-f"])
            .arg(&key)
            .output();
    }
    Ok(())
}

fn git_global(home: &Path, args: &[&str]) -> anyhow::Result<()> {
    run(Command::new("git")
        .env("HOME", home)
        .arg("config")
        .arg("--global")
        .args(args))
    .with_context(|| format!("git config --global {}", args.join(" ")))?;
    Ok(())
}

/// Step 8: git's signing settings where a later write to ~/.gitconfig cannot undo them (#145).
fn git_signing(owner: &Owner, file: &Path, key: Option<&Path>) -> anyhow::Result<()> {
    let home = &owner.home;
    let signers = home.join(".config/git/allowed_signers");
    write_atomic(file, &signing_gitconfig(&signers, key), 0o644)?;
    if is_root() {
        std::os::unix::fs::chown(file, Some(0), Some(0)).ok();
    }
    let gpgsign = if key.is_some() { "true" } else { "false" };
    git_global(home, &["gpg.format", "ssh"])?;
    git_global(
        home,
        &["gpg.ssh.allowedSignersFile", &signers.display().to_string()],
    )?;
    if let Some(k) = key {
        git_global(home, &["user.signingkey", &k.display().to_string()])?;
    }
    git_global(home, &["commit.gpgsign", gpgsign])?;
    git_global(home, &["tag.gpgsign", gpgsign])?;
    // the include, last and once
    let re = regex_escape(&file.display().to_string());
    let _ = Command::new("git")
        .env("HOME", home)
        .args([
            "config",
            "--global",
            "--unset-all",
            "include.path",
            &format!("^{re}$"),
        ])
        .output();
    let gc = home.join(".gitconfig");
    let mut text = read_or_empty(&gc);
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!("[include]\n\tpath = {}\n", file.display()));
    std::fs::write(&gc, text).context("write ~/.gitconfig")?;
    chown(&gc, owner)?;
    Ok(())
}

fn regex_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if "[]\\.*^$/+?(){}|".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Step 12: the HTTPS git credential helper the Dev Containers extension writes on every start
/// goes; git goes over the gateway's SSH.
pub fn drop_credential_helper(owner: &Owner) {
    let mut removed = Vec::new();
    for scope in ["system", "global"] {
        let mut c = Command::new("git");
        c.env("HOME", &owner.home);
        c.args([
            "config",
            &format!("--{scope}"),
            "--get-all",
            "credential.helper",
        ]);
        let Ok(o) = c.output() else { continue };
        let v = String::from_utf8_lossy(&o.stdout);
        if v.contains("vscode-remote-containers") || v.contains("vscode-server") {
            let _ = Command::new("git")
                .env("HOME", &owner.home)
                .args([
                    "config",
                    &format!("--{scope}"),
                    "--unset-all",
                    "credential.helper",
                ])
                .output();
            let _ = Command::new("git")
                .env("HOME", &owner.home)
                .args(["config", &format!("--{scope}"), "credential.helper", ""])
                .output();
            removed.push(scope);
        }
    }
    if !removed.is_empty() {
        println!(
            "[agent] took out the VS Code HTTPS git credential helper ({}); git goes over the gateway's SSH. SEKIMORE_ALLOW_CREDENTIAL_HELPER=1 keeps it",
            removed.join(" ")
        );
    }
}

pub async fn setup(s: &Settings, gw: Ipv4Addr) -> anyhow::Result<Option<Outcome>> {
    let endpoint = format!("http://{gw}:{}", s.api_port);
    if !relay_present(&endpoint).await {
        println!(
            "[agent] relay: no relay on {gw}:{}, skipping (gateway without git-relay)",
            s.api_port
        );
        return Ok(None);
    }
    for c in [s.ssh_keygen.as_str(), s.ssh_keyscan.as_str(), "git"] {
        if !on_path(c) {
            bail!("'{c}' not found (install openssh-client and git in the agent image)");
        }
    }
    let owner = s.owner()?;
    let home = owner.home.clone();
    let keydir = s.keydir(&home);
    let env_file = &s.env_file;

    ensure_dir(&home.join(".ssh"), 0o700)?;
    ensure_dir(&keydir, 0o700)?;
    chown(&home.join(".ssh"), &owner)?;
    chown(&keydir, &owner)?;
    if let Some(d) = env_file.parent() {
        ensure_dir(d, 0o755)?;
    }

    // ---- the disposable key ----
    let key = keydir.join("id_ed25519");
    if !key.is_file() {
        keygen(
            &s.ssh_keygen,
            &key,
            &format!("sekimore-agent@{}", hostname()),
        )?;
    }
    chown_all(&keydir, &owner)?;
    chmod(&key, 0o600)?;
    chmod(&keydir.join("id_ed25519.pub"), 0o644)?;
    let pub_line = read_or_empty(&keydir.join("id_ed25519.pub"))
        .trim()
        .to_string();

    // ---- the project token ----
    let old: Vec<(String, String)> = parse_env(&read_or_empty(env_file));
    let get = |k: &str| {
        old.iter()
            .find(|(kk, _)| kk == k)
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
    };
    let mut token = get("SEKIMORE_TOKEN");
    let mut token_expires = get("SEKIMORE_TOKEN_EXPIRES");
    let mut repo = get("SEKIMORE_REPO");
    let mut git_domain = get("SEKIMORE_GIT_DOMAIN");
    let mut git_domains = get("SEKIMORE_GIT_DOMAINS")
        .map(|v| parse_domains(&v))
        .unwrap_or_default();
    let mut sig_sock = get("SEKIMORE_SIGNING_SOCK");
    let mut sig_fp = get("SEKIMORE_SIGNING_KEY");
    let mut sig_mode = get("SEKIMORE_SIGNING_MODE");
    match &token {
        Some(t) if token_valid(&endpoint, t).await => {
            println!("[agent] relay: existing project token is still valid, keeping it");
        }
        _ => {
            token = None;
            if s.bootstrap_manual {
                println!(
                    "[agent] relay: bootstrap is manual; the operator must put SEKIMORE_TOKEN into {}",
                    env_file.display()
                );
            } else {
                match bootstrap(&endpoint, &pub_line).await {
                    Some(r) if r.token.as_deref().is_some_and(|t| !t.is_empty()) => {
                        println!("[agent] relay: registered the disposable key and received a project token");
                        token = r.token.clone();
                        token_expires = r.token_expires.clone();
                        if repo.is_none() {
                            repo = r.repos.first().cloned();
                        }
                        if let Some(d) = r.git_domain.clone().filter(|d| !d.is_empty()) {
                            git_domain = Some(d);
                        }
                        if !r.git_domains.is_empty() {
                            git_domains = r
                                .git_domains
                                .iter()
                                .map(|g| Upstream {
                                    domain: g.domain.clone(),
                                    port: g.ssh_port,
                                })
                                .collect();
                        }
                        // assigned unconditionally: a gateway that stopped offering a signing key
                        // clears the cached socket instead of leaving dev pointed at it
                        sig_sock = r
                            .signing
                            .as_ref()
                            .map(|b| b.socket.clone())
                            .filter(|v| !v.is_empty());
                        sig_fp = r
                            .signing
                            .as_ref()
                            .map(|b| b.fingerprint.clone())
                            .filter(|v| !v.is_empty());
                        sig_mode = r
                            .signing
                            .as_ref()
                            .map(|b| b.mode.clone())
                            .filter(|v| !v.is_empty());
                    }
                    other => {
                        let why = other
                            .and_then(|r| r.error)
                            .unwrap_or_else(|| "no answer".to_string());
                        println!("[agent] relay: WARNING: bootstrap did not return a token: {why}");
                        println!("[agent] relay:   the operator can register the key and issue a token on the gateway:");
                        println!("[agent] relay:     sekimore-relay add-key \"{pub_line}\" && sekimore-relay token");
                    }
                }
            }
        }
    }
    let git_domain = git_domain
        .or_else(|| s.git_domain.clone())
        .unwrap_or_else(|| "github.com".to_string());
    let git_domains = with_default_first(git_domains, &git_domain, s.ssh_port);

    // ---- the signing key (#59) ----
    let signing = match &sig_sock {
        Some(sock) if Path::new(sock).exists() && is_socket(sock) => {
            match agent_keys(&s.ssh_add, sock) {
                Some(listed) => {
                    let public = listed.lines().next().unwrap_or("").to_string();
                    let f = keydir.join("signing.pub");
                    std::fs::write(&f, format!("{public}\n"))?;
                    chmod(&f, 0o644)?;
                    chown(&f, &owner)?;
                    Signing::Gateway {
                        socket: sock.clone(),
                        public,
                    }
                }
                None => {
                    println!(
                        "[agent] relay: WARNING: the gateway's signing socket holds no key{}.",
                        sig_fp
                            .as_ref()
                            .map(|f| format!(" ({f})"))
                            .unwrap_or_default()
                    );
                    println!("[agent] relay:   The operator has to ssh-add it on the host. Commits will NOT be signed.");
                    Signing::None
                }
            }
        }
        Some(sock) => {
            println!("[agent] relay: WARNING: the gateway named a signing socket ({sock}) that is not in this container.");
            println!("[agent] relay:   Mount the shared volume into the dev service (docker-compose.relay.yml). Commits will NOT be signed.");
            Signing::None
        }
        None => {
            ensure_signing_key(&s.ssh_keygen, &keydir, &signing_key_comment(s, &home))?;
            let k = keydir.join("signing_ed25519");
            let p = keydir.join("signing_ed25519.pub");
            chmod(&k, 0o600)?;
            chmod(&p, 0o644)?;
            chown(&k, &owner)?;
            chown(&p, &owner)?;
            Signing::Generated {
                public: read_or_empty(&p).trim().to_string(),
                path: p,
            }
        }
    };

    // ---- the env file ----
    let mut text = String::from("# generated by sgw-agent setup — re-run the setup to refresh\n");
    text.push_str(&format!("SEKIMORE_IP={gw}\nSEKIMORE_ENDPOINT={endpoint}\n"));
    text.push_str(&format!("SEKIMORE_GIT_DOMAIN={git_domain}\n"));
    text.push_str(&format!(
        "SEKIMORE_GIT_DOMAINS={}\n",
        domains_string(&git_domains)
    ));
    if let Some(r) = &repo {
        text.push_str(&format!("SEKIMORE_REPO={r}\n"));
    }
    if let Some(t) = &token {
        text.push_str(&format!("SEKIMORE_TOKEN={t}\n"));
        if let Some(e) = &token_expires {
            text.push_str(&format!("SEKIMORE_TOKEN_EXPIRES={e}\n"));
        }
    }
    text.push_str(&format!(
        "SEKIMORE_AGENT_KEY={}\n",
        keydir.join("id_ed25519.pub").display()
    ));
    if let Some(sock) = &sig_sock {
        text.push_str(&format!("SEKIMORE_SIGNING_SOCK={sock}\n"));
        if let Some(f) = &sig_fp {
            text.push_str(&format!("SEKIMORE_SIGNING_KEY={f}\n"));
        }
    }
    if let Some(m) = &sig_mode {
        text.push_str(&format!("SEKIMORE_SIGNING_MODE={m}\n"));
    }
    if let Signing::Gateway { socket, .. } = &signing {
        // not an authentication path: the socket refuses everything that is not an SSHSIG blob
        text.push_str(&format!("SSH_AUTH_SOCK={socket}\n"));
    }
    write_atomic(env_file, &text, 0o600)?;
    chown(env_file, &owner)?;

    // ---- known_hosts ----
    let kh = home.join(".ssh/known_hosts");
    let mut khtext = read_or_empty(&kh);
    let mut drop: Vec<String> = vec![gw.to_string()];
    for u in &git_domains {
        drop.push(u.domain.clone());
        if u.port != 22 {
            drop.push(format!("[{}]:{}", u.domain, u.port));
            drop.push(format!("[{gw}]:{}", u.port));
        }
    }
    khtext = known_hosts_without(&khtext, &drop);
    for u in &git_domains {
        let mut scan = String::new();
        for i in 0..3 {
            if i > 0 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            if let Ok(out) = run(Command::new(&s.ssh_keyscan).args([
                "-T",
                "3",
                "-p",
                &u.port.to_string(),
                &gw.to_string(),
            ])) {
                if !out.trim().is_empty() {
                    scan = out;
                    break;
                }
            }
        }
        if scan.trim().is_empty() {
            bail!(
                "relay on {gw}:{} (for {}) did not answer ssh-keyscan",
                u.port,
                u.domain
            );
        }
        let hostnames = if u.port == 22 {
            format!("{},{gw}", u.domain)
        } else {
            format!("[{}]:{},[{gw}]:{}", u.domain, u.port, u.port)
        };
        khtext.push_str(&known_hosts_lines(&scan, &hostnames));
    }
    std::fs::write(&kh, khtext).context("write known_hosts")?;
    chown(&kh, &owner)?;
    chmod(&kh, 0o644)?;

    // ---- ~/.ssh/config ----
    let cfg = home.join(".ssh/config");
    let block = ssh_config_block(&git_domains, &key);
    write_atomic(
        &cfg,
        &SSH_CONFIG_MARK.replace(&read_or_empty(&cfg), &block),
        0o600,
    )?;
    chown(&cfg, &owner)?;

    // ---- git: sign with the AI key, never the operator's ----
    let gitdir = home.join(".config/git");
    ensure_dir(&gitdir, 0o755)?;
    if home.join(".config").is_dir() {
        chown(&home.join(".config"), &owner)?;
    }
    chown(&gitdir, &owner)?;
    let signers = gitdir.join("allowed_signers");
    if !signers.is_file() {
        std::fs::write(&signers, "")?;
    }
    let (signkey, signing_pub): (Option<PathBuf>, Option<String>) = match &signing {
        Signing::Gateway { public, .. } => (Some(keydir.join("signing.pub")), Some(public.clone())),
        Signing::Generated { public, path } => (Some(path.clone()), Some(public.clone())),
        Signing::None => (None, None),
    };
    let gitconfig = env_file
        .parent()
        .unwrap_or(Path::new("/etc/sekimore-agent"))
        .join("gitconfig");
    git_signing(&owner, &gitconfig, signkey.as_deref())?;
    if let Some(p) = &signing_pub {
        let sigpub: String = p.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        let principal = std::env::var("GIT_COMMITTER_EMAIL")
            .or_else(|_| std::env::var("GIT_AUTHOR_EMAIL"))
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "*".to_string());
        let cur = read_or_empty(&signers);
        if !cur.contains(&sigpub) {
            std::fs::write(
                &signers,
                format!("{cur}{principal} namespaces=\"git\" {sigpub}\n"),
            )?;
        }
    }
    chown(&signers, &owner)?;

    // ---- the agent guide where each tool reads it ----
    let required = sig_mode.as_deref() == Some("required");
    if let Err(e) =
        super::instructions::write(&owner, &s.instructions, s.guide_lang.as_deref(), required)
    {
        println!("[agent] relay: WARNING: could not write agent instructions: {e:#}");
    }

    println!(
        "[agent] relay: ready — git via {} → {gw}, API {endpoint}, env {} {}",
        domains_string(&git_domains),
        env_file.display(),
        if token.is_some() {
            "(token issued)"
        } else {
            "(NO token)"
        }
    );
    if required && signing_pub.is_none() {
        println!("[agent] relay: ERROR: this project is signing: required and there is no key to sign with.");
        println!("[agent] relay:   Every push to a branch will be refused until the operator fixes the signing key above.");
    }
    match &signing {
        Signing::Gateway { socket, public } => {
            println!(
                "[agent] relay: commits are signed through the gateway's filtered agent ({socket})"
            );
            println!("[agent] relay:   {public}");
        }
        Signing::Generated { public, path } => {
            println!("[agent] relay: commits are signed with {}", path.display());
            println!("[agent] relay: register that public key on GitHub as a *Signing Key* (Settings → SSH and GPG keys → New SSH key → Key type: Signing Key):");
            println!("{public}");
            println!("[agent] relay: NOTE: this key is generated in this container and dies with its volume, so it has to be");
            println!("[agent] relay:   registered again every time. relay.signing_key on the gateway replaces it with one key per person (#59).");
        }
        Signing::None => println!(
            "[agent] relay: commits are NOT signed (commit.gpgsign false); see the warning above"
        ),
    }
    Ok(Some(Outcome {
        git_domains: domains_string(&git_domains),
        token: token.is_some(),
        signing,
        sig_mode: sig_mode.unwrap_or_default(),
    }))
}

fn is_socket(path: &str) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path)
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_round_trip_and_the_default_goes_first() {
        let v = parse_domains("github.com:22,ghe.example.com:2222");
        assert_eq!(
            v[1],
            Upstream {
                domain: "ghe.example.com".into(),
                port: 2222
            }
        );
        assert_eq!(domains_string(&v), "github.com:22,ghe.example.com:2222");
        assert_eq!(parse_domains("github.com")[0].port, 22);
        let v = with_default_first(parse_domains("ghe.example.com:2222"), "github.com", 22);
        assert_eq!(domains_string(&v), "github.com:22,ghe.example.com:2222");
        assert_eq!(
            domains_string(&with_default_first(vec![], "github.com", 22)),
            "github.com:22"
        );
    }

    #[test]
    fn known_hosts_entries_are_replaced_by_name_and_keyscan_lines_renamed() {
        let kh = "github.com,10.0.0.2 ssh-ed25519 AAAA1\n# comment\nother.example ssh-ed25519 AAAA2\n[ghe.example.com]:2222,[10.0.0.2]:2222 ssh-ed25519 AAAA3\n";
        let out = known_hosts_without(
            kh,
            &[
                "10.0.0.2".into(),
                "github.com".into(),
                "[ghe.example.com]:2222".into(),
            ],
        );
        assert_eq!(out, "# comment\nother.example ssh-ed25519 AAAA2\n");
        let scan = "# 10.0.0.2:22 SSH-2.0-sekimore-relay\n10.0.0.2 ssh-ed25519 AAAAKEY comment\n";
        assert_eq!(
            known_hosts_lines(scan, "github.com,10.0.0.2"),
            "github.com,10.0.0.2 ssh-ed25519 AAAAKEY comment\n"
        );
    }

    #[test]
    fn the_root_owned_gitconfig_turns_signing_off_without_a_key() {
        let on = signing_gitconfig(
            Path::new("/h/.config/git/allowed_signers"),
            Some(Path::new("/k/signing.pub")),
        );
        assert!(
            on.contains("\tsigningkey = /k/signing.pub\n") && on.contains("\tgpgsign = true\n"),
            "{on}"
        );
        let off = signing_gitconfig(Path::new("/h/.config/git/allowed_signers"), None);
        assert!(
            !off.contains("signingkey") && off.contains("[commit]\n\tgpgsign = false\n"),
            "{off}"
        );
    }
}
