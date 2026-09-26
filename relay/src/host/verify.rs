//! `sgw verify`: the acceptance check of a project — the former `relay:verify`, in Rust.
//!
//! Every item names the rows of the path ledger (`docs/paths.yml`) it probes, so a FAIL points
//! at who resolves, who verifies the peer, what is presented and where it is audited. Every item
//! says which targets it applies to: a Docker Sandbox is not on the gateway's bridge, so the
//! items about DNS, the firewall and the host-side rules have nothing to check there.
//! `tests/unit/test_paths.py` holds the edges named here to the ledger's `verify` attributes.
//!
//! The text is the English of the shell version, deliberately: it is read next to the relay's
//! own diagnostics and copied into bug reports.

use crate::cli::color::{paint, Tone};
use crate::paths;

use super::docker::{Captured, Docker, DEV, GATEWAY};
use super::project::Project;
use super::target::Target;

pub struct Item {
    pub name: &'static str,
    pub title: &'static str,
    /// The ledger rows this item probes (`docs/paths.yml`). Empty for an item about the
    /// project's own files
    pub edges: &'static [&'static str],
    pub applies: fn(&Target) -> bool,
    pub run: fn(&mut Ctx) -> anyhow::Result<()>,
}

fn always(_: &Target) -> bool {
    true
}
fn on_bridge(t: &Target) -> bool {
    t.agent_on_bridge()
}

pub const ITEMS: &[Item] = &[
    Item {
        name: "gateway_check",
        title: "gateway: sekimore-relay check",
        edges: &[],
        applies: always,
        run: gateway_check,
    },
    Item {
        name: "signing_key_only",
        title: "dev: only the gateway's filtered signing key may be reachable",
        edges: &[paths::DEV_SIGNING],
        applies: always,
        run: signing_key_only,
    },
    Item {
        name: "git_signs",
        title: "dev: git signs with the key it is meant to",
        edges: &[paths::DEV_SIGNING],
        applies: always,
        run: git_signs,
    },
    Item {
        name: "env_survives_sudo",
        title: ".env: the setup script's variables must survive sudo",
        edges: &[],
        applies: on_bridge,
        run: env_survives_sudo,
    },
    Item {
        name: "store",
        title: "gateway: the secret store",
        edges: &[paths::OPERATOR_STORE],
        applies: always,
        run: store,
    },
    Item {
        name: "whoami",
        title: "dev: relay token (sekimore whoami)",
        edges: &[paths::DEV_RELAY_API],
        applies: always,
        run: whoami,
    },
    Item {
        name: "git_ls_remote",
        title: "dev: git ls-remote through the relay (first repo of the project)",
        edges: &[paths::DEV_RELAY_SSH, paths::RELAY_SSH_UPSTREAM],
        applies: always,
        run: git_ls_remote,
    },
    Item {
        name: "outside_denied",
        title: "dev: a repository outside the project must be denied",
        edges: &[paths::DEV_RELAY_SSH],
        applies: always,
        run: outside_denied,
    },
    Item {
        name: "https_passthrough",
        title: "dev: HTTPS to a relayed domain must reach the upstream (through the upstream proxy when one is configured)",
        edges: &[paths::DEV_PASSTHROUGH, paths::PASSTHROUGH_UPSTREAM],
        applies: always,
        run: https_passthrough,
    },
    Item {
        name: "api_call",
        title: "dev: one GitHub API call through the relay",
        edges: &[paths::DEV_RELAY_API, paths::RELAY_GITHUB_API],
        applies: always,
        run: api_call,
    },
    Item {
        name: "no_credential_in_api",
        title: "dev: the gateway's API must not hand out the upstream proxy password",
        edges: &["dev.webui"],
        applies: always,
        run: no_credential_in_api,
    },
    Item {
        name: "upstream_proxy_used",
        title: "dev: the upstream proxy is used for ordinary traffic (when one is configured)",
        edges: &["dev.squid", "dev.egress.direct"],
        applies: on_bridge,
        run: upstream_proxy_used,
    },
    Item {
        name: "route_past_gateway",
        title: "dev: a root process must not route past the gateway (host-side FORWARD rules, gateway 0.2.37)",
        edges: &["dev.egress.route_past_gateway"],
        applies: on_bridge,
        run: route_past_gateway,
    },
    Item {
        name: "host_input",
        title: "dev: the host itself must not answer dev (host-side INPUT rules, gateway 0.2.38)",
        edges: &["dev.host_input"],
        applies: on_bridge,
        run: host_input,
    },
];

/// The items that apply to a target, in order.
pub fn applicable(target: &Target) -> Vec<&'static Item> {
    ITEMS.iter().filter(|i| (i.applies)(target)).collect()
}

pub struct Ctx<'a> {
    docker: &'a Docker,
    project: &'a Project,
    colour: bool,
    failed: bool,
    gateway: Option<String>,
    dev: Option<String>,
    /// `sekimore-relay check`, kept whole: the `443 target:` lines pick the HTTPS probe's domain
    gwcheck: String,
    /// `sekimore whoami`, kept whole: the permissions line picks the API probe
    who: String,
    bridge_gw: Option<String>,
}

impl<'a> Ctx<'a> {
    fn ok(&mut self, s: &str) {
        println!("{} {s}", self.paint(Tone::Good, "OK:"));
    }
    fn fail(&mut self, s: &str) {
        println!("{} {s}", self.paint(Tone::Bad, "❌ FAIL:"));
        self.failed = true;
    }
    fn skip(&mut self, s: &str) {
        println!("SKIP: {s}");
    }
    fn warn(&mut self, s: &str) {
        println!("{} {s}", self.paint(Tone::Warn, "WARN:"));
    }
    fn note(&mut self, s: &str) {
        println!("note: {s}");
    }
    fn paint(&self, tone: Tone, s: &str) -> String {
        if self.colour {
            paint(tone, s)
        } else {
            s.to_string()
        }
    }

    fn gateway_cid(&mut self) -> anyhow::Result<String> {
        if let Some(c) = &self.gateway {
            return Ok(c.clone());
        }
        let c = self.docker.find_container(GATEWAY)?;
        self.gateway = Some(c.clone());
        Ok(c)
    }
    fn dev_cid(&mut self) -> anyhow::Result<String> {
        if let Some(c) = &self.dev {
            return Ok(c.clone());
        }
        let c = self.docker.find_container(DEV)?;
        self.dev = Some(c.clone());
        Ok(c)
    }
    fn gw(&mut self, argv: &[&str]) -> anyhow::Result<Captured> {
        let cid = self.gateway_cid()?;
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        self.docker.exec_capture(&cid, None, &argv)
    }
    fn dev(&mut self, argv: &[&str]) -> anyhow::Result<Captured> {
        let cid = self.dev_cid()?;
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        self.docker.exec_capture(&cid, Some("vscode"), &argv)
    }
    fn dev_sh(&mut self, script: &str) -> anyhow::Result<Captured> {
        self.dev(&["sh", "-c", script])
    }
    /// `curl` in dev, the way the shell did it: the exit code apart from the status it writes.
    fn dev_curl(&mut self, args: &[&str]) -> anyhow::Result<Captured> {
        let mut argv = vec!["curl"];
        argv.extend_from_slice(args);
        self.dev(&argv)
    }
}

pub fn run(docker: &Docker, project: &Project, target: Target) -> anyhow::Result<i32> {
    // colour on a terminal; NO_COLOR wins; SEKIMORE_COLOR=always|never forces (color::enabled)
    let colour = crate::cli::color::enabled();
    let mut ctx = Ctx {
        docker,
        project,
        colour,
        failed: false,
        gateway: None,
        dev: None,
        gwcheck: String::new(),
        who: String::new(),
        bridge_gw: None,
    };
    let items = applicable(&target);
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let ids = if item.edges.is_empty() {
            String::new()
        } else {
            format!(" [{}]", item.edges.join(", "))
        };
        println!("== {}{ids}", item.title);
        if let Err(e) = (item.run)(&mut ctx) {
            ctx.fail(&format!("{e:#}"));
        }
    }
    println!();
    if ctx.failed {
        println!("{}", ctx.paint(Tone::Bad, "verify: FAILED"));
        Ok(1)
    } else {
        println!("{}", ctx.paint(Tone::Good, "verify: all checks passed"));
        Ok(0)
    }
}

// ---- the items ---------------------------------------------------------------------------

fn gateway_check(ctx: &mut Ctx) -> anyhow::Result<()> {
    let out = ctx.gw(&["sekimore-relay", "check"])?;
    ctx.gwcheck = out.stdout.clone();
    let mut printing = false;
    for line in out.stdout.lines() {
        if line.starts_with("state:") {
            printing = true;
        }
        if printing {
            println!("{line}");
        }
    }
    if !printing {
        ctx.fail(&format!(
            "sekimore-relay check printed no state (exit {}): {}",
            out.code,
            out.stderr.trim()
        ));
    }
    Ok(())
}

fn signing_key_only(ctx: &mut Ctx) -> anyhow::Result<()> {
    let out = ctx
        .dev_sh("set -a; . /etc/sekimore-agent/env 2>/dev/null; set +a; ssh-add -l 2>/dev/null")?;
    let n = out.stdout.lines().filter(|l| !l.trim().is_empty()).count();
    match n {
        1 => ctx.ok("exactly one key (the signing key, via the gateway's filtered agent)"),
        0 => ctx.ok("no ssh-agent in dev"),
        n => ctx.fail(&format!(
            "ssh-add -l lists {n} keys inside dev — the operator's keys are exposed to the AI. Reopen with: sgw open"
        )),
    }
    Ok(())
}

const GIT_SIGNS_SCRIPT: &str = r#"set -a; . /etc/sekimore-agent/env 2>/dev/null; set +a
[ "$(git config --get commit.gpgsign 2>/dev/null)" = true ] || { echo off; exit; }
k=$(git config --get user.signingkey 2>/dev/null)
case $k in "") echo "unset"; exit ;; key::*) echo inline; exit ;; esac
[ -f "$k" ] || { echo "missing: $k"; exit; }
if [ -n "${SEKIMORE_SIGNING_SOCK:-}" ]; then
  pub=$(cut -d" " -f1,2 "$k")
  if SSH_AUTH_SOCK=$SEKIMORE_SIGNING_SOCK ssh-add -L 2>/dev/null | cut -d" " -f1,2 | grep -qxF "$pub"; then echo ok; else echo "not offered by the signing socket: $k"; fi
else
  echo ok
fi"#;

fn git_signs(ctx: &mut Ctx) -> anyhow::Result<()> {
    // The Dev Containers extension copies the host's user.signingkey over the container's on
    // every start; from gateway 0.2.31 agent-setup's own setting wins. An inline key:: value, or
    // a key the signing socket does not offer, makes every commit fail with "Couldn't find key"
    let out = ctx.dev_sh(GIT_SIGNS_SCRIPT)?;
    let sig = if out.code == 0 {
        out.stdout.trim().to_string()
    } else {
        "dev unavailable".to_string()
    };
    match sig.as_str() {
        "ok" => ctx.ok("user.signingkey is the key the gateway signs with"),
        "off" => ctx.note("commit signing is off in dev"),
        "inline" => ctx.fail(
            "user.signingkey is an inline key:: value — the host's, copied in by the Dev Containers extension. Recreate with gateway 0.2.31 or later",
        ),
        other => ctx.fail(&format!("user.signingkey — {other}")),
    }
    Ok(())
}

/// What `postStartCommand` drops: the `SEKIMORE_*` variables `.env` sets that its
/// `--preserve-env=` list does not name. None when sgw-post-start (sudo -E) or post-start.sh is
/// in use: both pass them all.
pub fn dropped_vars(devcontainer_json: &str, env_text: &str) -> Option<Vec<String>> {
    if devcontainer_json.contains("sgw-post-start")
        || devcontainer_json.contains(".devcontainer/sgw/post-start.sh")
    {
        return None;
    }
    let preserved: Vec<String> = devcontainer_json
        .split("--preserve-env=")
        .nth(1)
        .map(|rest| {
            rest.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ',')
                .collect::<String>()
        })
        .map(|s| s.split(',').map(str::to_string).collect::<Vec<_>>())
        .unwrap_or_default();
    // read by the gateway and post-create.sh, which do not go through sudo
    const OTHERS: &[&str] = &[
        "SEKIMORE_AGENT_SOCK",
        "SEKIMORE_ALLOW_AGENT_FORWARD",
        "SEKIMORE_ALLOW_CREDENTIAL_HELPER",
        "SEKIMORE_SECRET_ENV",
    ];
    let mut dropped = Vec::new();
    for line in env_text.lines() {
        let l = line.trim_start();
        let Some(name) = l.split('=').next() else {
            continue;
        };
        if !name.starts_with("SEKIMORE_")
            || !name[9..]
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_')
        {
            continue;
        }
        if OTHERS.contains(&name) || preserved.iter().any(|p| p == name) {
            continue;
        }
        dropped.push(name.to_string());
    }
    Some(dropped)
}

fn env_survives_sudo(ctx: &mut Ctx) -> anyhow::Result<()> {
    // sudo resets the environment. post-start.sh passes every SEKIMORE_* variable through it;
    // the older postStartCommand named them in --preserve-env=, and one missing from that list is
    // set and then silently ignored
    let dc = std::fs::read_to_string(ctx.project.compose_dir.join("devcontainer.json"))
        .unwrap_or_default();
    let env = std::fs::read_to_string(ctx.project.compose_dir.join(".env")).unwrap_or_default();
    match dropped_vars(&dc, &env) {
        None => ctx.ok("postStartCommand runs sgw-post-start (or post-start.sh), which passes every SEKIMORE_* variable"),
        Some(d) if d.is_empty() => ctx.ok("every setup-script variable in .env survives sudo"),
        Some(d) => ctx.fail(&format!(
            "{} is set in .env but missing from --preserve-env= in devcontainer.json postStartCommand. Make it the one line sgw-post-start",
            d.join(" ")
        )),
    }
    Ok(())
}

fn store(ctx: &mut Ctx) -> anyhow::Result<()> {
    // 0.2.19: the upstream API token lives in the store, so a locked one is not a note — the relay
    // cannot reach the GitHub API at all until someone unlocks it. First line only: a later
    // gateway may print more under it (0.2.39 did)
    let out = ctx.gw(&["sekimore-relay", "store-status"]).ok();
    let state = out
        .and_then(|o| o.stdout.lines().next().map(|l| l.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unavailable".to_string());
    match state.as_str() {
        "unlocked" => ctx.ok("unlocked"),
        "not initialised" => ctx.note("no store yet. sgw unlock sets the passphrase"),
        other => ctx.fail(&format!(
            "the store is {other}, so the relay cannot read the upstream API token. Run: sgw unlock"
        )),
    }
    Ok(())
}

fn whoami(ctx: &mut Ctx) -> anyhow::Result<()> {
    let out = ctx.dev(&["sekimore", "whoami"])?;
    ctx.who = out.stdout.clone();
    print!("{}{}", out.stdout, out.stderr);
    if out.code != 0 {
        ctx.fail(&format!("sekimore whoami exited {}", out.code));
    }
    Ok(())
}

fn git_ls_remote(ctx: &mut Ctx) -> anyhow::Result<()> {
    let out = ctx.dev_sh(
        r#". /etc/sekimore-agent/env && git ls-remote "git@$SEKIMORE_GIT_DOMAIN:$SEKIMORE_REPO.git" HEAD"#,
    )?;
    print!("{}", out.stdout);
    if out.code != 0 {
        let last = out
            .stderr
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("");
        ctx.fail(&format!(
            "git ls-remote through the relay exited {}: {last}",
            out.code
        ));
    }
    Ok(())
}

fn outside_denied(ctx: &mut Ctx) -> anyhow::Result<()> {
    let out = ctx.dev_sh(
        r#". /etc/sekimore-agent/env && git ls-remote "git@$SEKIMORE_GIT_DOMAIN:sekimore-test/not-in-project.git" HEAD 2>&1"#,
    )?;
    if (out.stdout.clone() + &out.stderr).contains("not in project") {
        ctx.ok("denied");
    } else {
        ctx.fail("no 'not in project' denial");
    }
    Ok(())
}

/// The `443 target:` lines of `sekimore-relay check`.
pub fn targets_from_check(check: &str) -> Vec<String> {
    check
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("443 target:"))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// api.github.com when it is among them, else the first.
pub fn pick_target(targets: &[String]) -> Option<String> {
    targets
        .iter()
        .find(|t| *t == "api.github.com")
        .or_else(|| targets.first())
        .cloned()
}

const HTTPS_HINT: &str = "the relay cut the connection — sgw logs for 'TLS to the proxy failed' or 'https_failed', then sgw check (reach:)";

fn https_passthrough(ctx: &mut Ctx) -> anyhow::Result<()> {
    // git through the relay is SSH and never touches the upstream proxy, so it stays green while
    // every HTTPS path through the relay is dead (base #85). This goes the way the API does
    let Some(target) = pick_target(&targets_from_check(&ctx.gwcheck)) else {
        ctx.skip("no 443 target configured");
        return Ok(());
    };
    let url = format!("https://{target}/");
    let out = ctx.dev_curl(&[
        "-sS",
        "-m",
        "10",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        &url,
    ])?;
    let code = out.stdout.trim().to_string();
    if out.code == 0 && !code.is_empty() {
        ctx.ok(&format!(
            "{url} answered HTTP {code} (any status means the upstream was reached)"
        ));
    } else {
        ctx.fail(&format!("{url} — curl exit {}. {HTTPS_HINT}", out.code));
    }
    Ok(())
}

/// The read probe the project's permissions allow, from `sekimore whoami`'s permissions line.
pub fn probe_from_permissions(who: &str) -> Option<Vec<&'static str>> {
    let perms = who
        .lines()
        .find(|l| l.starts_with("permissions"))
        .and_then(|l| l.split_once(':').map(|(_, r)| r))
        .unwrap_or("");
    let has = |p: &str| perms.split_whitespace().any(|x| x == p);
    if has("pr:read") {
        Some(vec!["pr", "list", "--limit", "1"])
    } else if has("issue:read") {
        Some(vec!["issue", "list", "--limit", "1"])
    } else if has("repo:read") {
        Some(vec!["repo", "vocabulary"])
    } else {
        None
    }
}

fn api_call(ctx: &mut Ctx) -> anyhow::Result<()> {
    // sekimore whoami answers out of the gateway's own state and calls no GitHub API; this does
    let Some(probe) = probe_from_permissions(&ctx.who) else {
        ctx.skip("the project grants no read permission to probe with");
        return Ok(());
    };
    let mut argv = vec!["sekimore"];
    argv.extend(probe.iter());
    let out = ctx.dev(&argv)?;
    let shown = probe.join(" ");
    if out.code == 0 {
        ctx.ok(&format!("sekimore {shown} answered"));
    } else {
        let last = out
            .stderr
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("");
        ctx.fail(&format!(
            "sekimore {shown} — exit {}: {last}. {HTTPS_HINT}",
            out.code
        ));
    }
    Ok(())
}

/// A `login=<user>:<password>` in the gateway's config text that is not redacted (#217).
/// Squid's other forms (`login=PASS`, `login=NEGOTIATE`) carry no colon and no secret.
pub fn leaked_login(body: &str) -> Option<String> {
    let stop = |c: char| c == '"' || c.is_whitespace() || c == '\\';
    let mut rest = body;
    while let Some(i) = rest.find("login=") {
        let tail = &rest[i + "login=".len()..];
        let token: String = tail.chars().take_while(|c| !stop(*c)).collect();
        if let Some((user, pass)) = token.split_once(':') {
            if !user.is_empty() && !pass.is_empty() && pass != "***" {
                return Some(format!("login={user}:…"));
            }
        }
        rest = &rest[i + "login=".len()..];
    }
    None
}

fn no_credential_in_api(ctx: &mut Ctx) -> anyhow::Result<()> {
    let out = ctx.dev_curl(&["-sS", "-m", "5", "http://sekimore-gw:8080/api/config"])?;
    if out.stdout.trim().is_empty() {
        ctx.skip("the gateway's API is not reachable from dev");
        return Ok(());
    }
    if leaked_login(&out.stdout).is_some() {
        ctx.fail("the upstream proxy password is readable from dev in /api/config (gateway 0.2.43 or later redacts it; rotate the password after upgrading)");
    } else {
        ctx.ok("no credential in /api/config");
    }
    Ok(())
}

/// The first `"key": "value"` string in a JSON text, the way the shell's sed read it.
pub fn json_string_field(text: &str, key: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    v.get(key)?.as_str().map(str::to_string)
}

/// A string at `path` (`["proxy", "upstream_proxy"]`) in a JSON object.
pub fn json_nested_string(text: &str, path: &[&str]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let mut cur = &v;
    for k in path {
        cur = cur.get(k)?;
    }
    cur.as_str().map(str::to_string)
}

pub fn json_bool_field(text: &str, key: &str) -> Option<bool> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    v.get(key)?.as_bool()
}

/// The first allow_domains entry that is a host rather than a wildcard suffix.
pub fn first_real_domain(text: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) => out.push(s.clone()),
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            serde_json::Value::Object(o) => o.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut all = Vec::new();
    walk(&v, &mut all);
    all.into_iter()
        .find(|s| !s.starts_with('.') && !s.is_empty() && s.contains('.'))
}

fn upstream_proxy_used(ctx: &mut Ctx) -> anyhow::Result<()> {
    // With upstream_proxy set, everything dev sends ought to go through the gateway's Squid and
    // out through that proxy. This checks both halves: dev has the variables, and the way around
    // them is closed (base #89)
    let cfg = ctx
        .dev_curl(&["-sS", "-m", "5", "http://sekimore-gw:8080/api/config"])?
        .stdout;
    let penv = ctx
        .dev_curl(&["-sS", "-m", "5", "http://sekimore-gw:8080/api/proxy-env"])?
        .stdout;
    // /api/config carries the URL under `proxy` (never the credential, #217); /api/proxy-env
    // says whether it is in force (`configured`: proxy.enabled and an upstream) and the egress
    // policy. The URL was once looked for at the top level of both, so this item skipped on
    // every gateway that had a proxy.
    let upstream = json_nested_string(&cfg, &["proxy", "upstream_proxy"])
        .or_else(|| json_string_field(&cfg, "upstream_proxy"))
        .filter(|u| !u.is_empty());
    // a gateway older than /api/proxy-env answers nothing here, and writes no HTTPS_PROXY into
    // dev either: its silence is not a finding
    let direct = json_string_field(&penv, "direct_egress");
    let Some(upstream) = upstream else {
        ctx.skip("no upstream proxy configured");
        return Ok(());
    };
    if json_bool_field(&penv, "configured") == Some(false) {
        ctx.skip(&format!(
            "proxy.upstream_proxy is {upstream}, but proxy.enabled is false: dev is not sent through it"
        ));
        return Ok(());
    }
    let Some(direct) = direct else {
        ctx.skip("the gateway does not report its egress policy (needs gateway 0.2.42 or later)");
        return Ok(());
    };
    let devproxy = ctx
        .dev(&["sh", "-lc", "printf %s \"$HTTPS_PROXY\""])?
        .stdout;
    if devproxy.trim().is_empty() {
        ctx.fail("dev has no HTTPS_PROXY; recreate the dev container / re-run post-start so agent-setup writes it");
    } else {
        ctx.ok(&format!(
            "dev has HTTPS_PROXY={} (upstream {upstream})",
            devproxy.trim()
        ));
    }
    let allowed = ctx
        .dev_curl(&[
            "-sS",
            "-m",
            "5",
            "http://sekimore-gw:8080/api/domains/allowed",
        ])?
        .stdout;
    let Some(host) = first_real_domain(&allowed) else {
        ctx.skip("no non-wildcard allow_domains entry to probe with");
        return Ok(());
    };
    // --noproxy '*' is the bypass itself: it goes straight out, ignoring HTTPS_PROXY
    let url = format!("https://{host}/");
    let out = ctx.dev_curl(&[
        "--noproxy",
        "*",
        "-sS",
        "-m",
        "8",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        &url,
    ])?;
    if out.code == 0 {
        if direct == "allow" {
            ctx.warn("direct egress is allowed: dev's traffic to allow_domains bypasses the upstream (proxy.direct_egress: deny)");
        } else {
            ctx.fail(&format!("direct egress works although the gateway denies it ({url} answered with --noproxy)"));
        }
    } else {
        ctx.ok(&format!(
            "direct egress to {url} is closed; ordinary traffic goes through the upstream"
        ));
    }
    Ok(())
}

const ROUTE_SCRIPT: &str = r#"sudo ip route replace 1.1.1.1/32 via "$1" 2>/dev/null || { echo noroute; exit 0; }
trap "sudo ip route del 1.1.1.1/32 2>/dev/null" EXIT
if curl --noproxy "*" -m 5 -sS -o /dev/null http://1.1.1.1/ 2>/dev/null; then echo reached; else echo blocked; fi"#;

fn route_past_gateway(ctx: &mut Ctx) -> anyhow::Result<()> {
    // The bridge's .1 is Docker's own router. Without the gateway's rules in the host's
    // DOCKER-USER chain, a host route through it reaches the internet by Docker's NAT, around
    // every filter
    let proj = ctx.docker.compose_project()?;
    let gw = ctx.docker.network_gateway(&format!("{proj}_internal-net"));
    ctx.bridge_gw = gw.clone();
    let Some(gw) = gw else {
        ctx.fail("could not find the internal bridge's gateway address");
        return Ok(());
    };
    // one shell in dev, so the route goes away with it whatever curl does
    let out = ctx.dev(&["sh", "-c", ROUTE_SCRIPT, "sh", &gw])?;
    let answer = if out.code == 0 {
        out.stdout.trim().to_string()
    } else {
        "dev unavailable".to_string()
    };
    match answer.as_str() {
        "blocked" => ctx.ok(&format!("blocked (a host route via {gw} leads nowhere)")),
        "reached" => ctx.fail(&format!(
            "dev reached 1.1.1.1 via {gw}, around the gateway. Add pid: host to the sekimore-gw service, then run: sgw recreate"
        )),
        "noroute" => ctx.fail("could not add the test route in dev (sudo ip route)"),
        other => ctx.fail(other),
    }
    Ok(())
}

fn host_input(ctx: &mut Ctx) -> anyhow::Result<()> {
    // The same .1 is the host's own address on the bridge. Two INPUT rules keep it silent:
    // replies to connections the host opened are accepted, everything else from the bridge is
    // dropped. Without them dev reaches the host, every port a container on the machine
    // publishes, and the VM's services
    let Some(gw) = ctx.bridge_gw.clone() else {
        ctx.skip("no bridge address (see the item above)");
        return Ok(());
    };
    let out = ctx.dev(&["ping", "-c1", "-W2", &gw])?;
    if out.code == 0 {
        ctx.fail(&format!(
            "dev reached the host at {gw}. Gateway 0.2.38 or later drops this; run: sgw recreate"
        ));
    } else {
        ctx.ok(&format!("no answer from {gw}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sandbox_skips_the_items_about_the_bridge() {
        let dc: Vec<&str> = applicable(&Target::DEFAULT)
            .iter()
            .map(|i| i.name)
            .collect();
        let sbx: Vec<&str> = applicable(&Target::parse("sbx").unwrap())
            .iter()
            .map(|i| i.name)
            .collect();
        assert_eq!(dc.len(), ITEMS.len());
        for gone in [
            "route_past_gateway",
            "host_input",
            "upstream_proxy_used",
            "env_survives_sudo",
        ] {
            assert!(dc.contains(&gone));
            assert!(!sbx.contains(&gone), "{gone} is about the bridge");
        }
        assert!(
            sbx.contains(&"git_ls_remote"),
            "the relay is reached from a sandbox too"
        );
        assert!(
            sbx.contains(&"signing_key_only"),
            "and this matters most there"
        );
    }

    #[test]
    fn every_item_has_a_distinct_name() {
        let mut names: Vec<&str> = ITEMS.iter().map(|i| i.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ITEMS.len());
    }

    #[test]
    fn the_https_probe_prefers_api_github_com() {
        let check =
            "state:\n  443 target: ghe.example.com (cap 1 MiB)\n  443 target: api.github.com\n";
        let t = targets_from_check(check);
        assert_eq!(t, vec!["ghe.example.com", "api.github.com"]);
        assert_eq!(pick_target(&t).as_deref(), Some("api.github.com"));
        assert_eq!(pick_target(&t[..1]).as_deref(), Some("ghe.example.com"));
        assert_eq!(pick_target(&[]), None);
    }

    #[test]
    fn the_api_probe_follows_the_permissions() {
        let who = "project=x\npermissions (every repo): ci:read pr:read issue:read\n";
        assert_eq!(
            probe_from_permissions(who).unwrap(),
            vec!["pr", "list", "--limit", "1"]
        );
        let who = "permissions: issue:read repo:read\n";
        assert_eq!(probe_from_permissions(who).unwrap()[0], "issue");
        let who = "permissions: repo:read\n";
        assert_eq!(
            probe_from_permissions(who).unwrap(),
            vec!["repo", "vocabulary"]
        );
        assert!(probe_from_permissions("permissions: pr:create\n").is_none());
        // the boundary: pr:read must be the whole word
        assert!(probe_from_permissions("permissions: pr:readonly\n").is_none());
    }

    /// #217's shape, and the boundary: a redacted entry and the colon-less forms pass.
    #[test]
    fn a_password_after_login_is_a_leak_and_a_redacted_one_is_not() {
        assert!(leaked_login(
            r#"{"config_text": "cache_peer x parent 3129 0 tls login=alice:s3cret\n"}"#
        )
        .is_some());
        assert!(
            leaked_login(r#"{"config_text": "cache_peer x parent 3129 0 login=alice:***\n"}"#)
                .is_none()
        );
        assert!(leaked_login("login=PASS login=NEGOTIATE").is_none());
        assert!(
            leaked_login("login=alice:***\" other login=bob:hunter2").is_some(),
            "the second one leaks"
        );
        assert!(leaked_login("").is_none());
    }

    #[test]
    fn the_json_fields_and_the_first_real_domain() {
        let penv = r#"{"upstream_proxy": "http://p:3128", "direct_egress": "deny"}"#;
        assert_eq!(
            json_string_field(penv, "upstream_proxy").as_deref(),
            Some("http://p:3128")
        );
        assert_eq!(
            json_string_field(penv, "direct_egress").as_deref(),
            Some("deny")
        );
        assert_eq!(
            json_string_field(r#"{"upstream_proxy": null}"#, "upstream_proxy"),
            None
        );
        assert_eq!(json_string_field("not json", "x"), None);
        assert_eq!(
            first_real_domain(r#"[".debian.org", "api.anthropic.com"]"#).as_deref(),
            Some("api.anthropic.com")
        );
        assert_eq!(first_real_domain(r#"{"domains": [".x.org"]}"#), None);
    }

    #[test]
    fn the_upstream_proxy_is_read_where_the_gateway_puts_it() {
        // /api/config: under `proxy`, as the Web UI answers (#217 keeps the credential out)
        let cfg = r#"{"versions": {}, "proxy": {"enabled": true, "port": 3128, "upstream_proxy": "https://gw.example:3129", "upstream_auth": "set"}}"#;
        assert_eq!(
            json_nested_string(cfg, &["proxy", "upstream_proxy"]).as_deref(),
            Some("https://gw.example:3129")
        );
        assert_eq!(
            json_string_field(cfg, "upstream_proxy"),
            None,
            "not at the top level"
        );
        // /api/proxy-env: whether it is in force, and the egress policy
        let penv = r#"{"configured": true, "port": 3128, "no_proxy": ["api.github.com"], "direct_egress": "allow"}"#;
        assert_eq!(json_bool_field(penv, "configured"), Some(true));
        assert_eq!(
            json_string_field(penv, "direct_egress").as_deref(),
            Some("allow")
        );
        assert_eq!(json_nested_string(penv, &["proxy", "upstream_proxy"]), None);
        assert_eq!(json_bool_field("not json", "configured"), None);
    }

    #[test]
    fn dropped_variables_are_the_ones_sudo_would_reset() {
        let dc_new = r#"{"postStartCommand": "sgw-post-start"}"#;
        assert_eq!(dropped_vars(dc_new, "SEKIMORE_X=1\n"), None);
        let dc_mise = r#"{"postStartCommand": "sh /workspace/.devcontainer/sgw/post-start.sh"}"#;
        assert_eq!(dropped_vars(dc_mise, "SEKIMORE_X=1\n"), None);
        let dc_old =
            r#"{"postStartCommand": "sudo --preserve-env=SEKIMORE_A,SEKIMORE_B /usr/local/bin/x"}"#;
        let env = "SEKIMORE_A=1\nSEKIMORE_B=2\nSEKIMORE_C=3\nSEKIMORE_AGENT_SOCK=/x\nOTHER=1\n  SEKIMORE_D=4\n";
        assert_eq!(
            dropped_vars(dc_old, env).unwrap(),
            vec!["SEKIMORE_C", "SEKIMORE_D"]
        );
        assert_eq!(
            dropped_vars(dc_old, "SEKIMORE_A=1\n").unwrap(),
            Vec::<String>::new()
        );
        // a lowercase or unrelated name is not a setup variable
        assert_eq!(
            dropped_vars(dc_old, "SEKIMORE_lower=1\nSEKIMOREX=1\n").unwrap(),
            Vec::<String>::new()
        );
    }
}
