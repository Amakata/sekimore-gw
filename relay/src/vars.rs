//! Per-person values (#334): kept in the secret store as key-value pairs and referred to from
//! config.yml as `{name}`.
//!
//! config.yml is shared and committed by the project, but some entries differ per person — the
//! account on a GHE bastion is the case that started this: `ProxyJump=alice@bastion…` in a shared
//! file sends everyone else in as alice. The value goes into the store with `sgw var set
//! bastion`, and the config says `ProxyJump={bastion}`.
//!
//! - **One store, path-shaped keys.** A key is segments of `[A-Za-z0-9._-]` joined by `/`, so a
//!   host name can be one: `{ghe.example.com/bastion}` for one upstream, `{bastion}` shared.
//! - **The key stays in the config; only the value is a variable.** `ProxyJump={bastion}` is
//!   accepted, a whole `{opt}` standing for `Key=Value` is not: that would let an unreviewed
//!   `ProxyCommand` run inside the gateway.
//! - **A value is checked where it is used.** In an ssh option it may hold only
//!   `[A-Za-z0-9._@:,/-]` — no space, `=` or newline that could slip in another option — and the
//!   option is checked again after substitution, as any option is.
//!
//! The store is locked at start-up and can change at any time, so `serve` keeps the values the
//! config refers to in a shared cell (`spawn_refresher`), a one-shot subcommand fills it once
//! (`load`), and the upstream ssh substitutes at the moment it spawns.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::github::upstream_token::{SecretSource, TokenError};

/// The store namespace per-person values are filed under.
pub const NAMESPACE: &str = "var";
/// A key longer than this is a mistake, not a name.
const KEY_MAX: usize = 128;
/// How often `serve` looks at the store again, as for the proxy credential.
const REFRESH: Duration = Duration::from_secs(5);

/// Whether `key` is a key: `/`-separated segments of `[A-Za-z0-9._-]`, none empty, `.` and `..`
/// not segments on their own.
pub fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= KEY_MAX
        && key.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        })
}

/// Every `{key}` in `s`, in order. A brace that does not open or close a valid key is an error:
/// a typo should stop the config, not reach ssh as a literal.
pub fn placeholders(s: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut rest = s;
    loop {
        match (rest.find('{'), rest.find('}')) {
            (None, None) => return Ok(out),
            (Some(o), Some(c)) if o < c => {
                let key = &rest[o + 1..c];
                if !valid_key(key) {
                    return Err(format!(
                        "{{{key}}} is not a variable name; a name is segments of letters, digits, `.`, `_` and `-` joined by `/`"
                    ));
                }
                out.push(key.to_string());
                rest = &rest[c + 1..];
            }
            _ => return Err("has a `{` or `}` that is not part of a {name}".to_string()),
        }
    }
}

/// Whether `value` may be placed in an ssh option. Nothing that could end the value and start
/// another option: no whitespace, no `=`, no newline, no quote, no `%` (ssh's own token syntax).
pub fn fits_ssh_option(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'@' | b':' | b',' | b'/' | b'-')
        })
}

/// `s` with each `{key}` replaced by `value(key)`.
fn replace(s: &str, mut value: impl FnMut(&str) -> String) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let (Some(o), Some(c)) = (rest.find('{'), rest.find('}')) {
        if c < o {
            break;
        }
        out.push_str(&rest[..o]);
        out.push_str(&value(&rest[o + 1..c]));
        rest = &rest[c + 1..];
    }
    out.push_str(rest);
    out
}

/// What the store said about a key when last read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Set(String),
    Missing,
    Locked,
    /// The store could not be read for another reason, carried for the message
    Unavailable(String),
}

impl State {
    /// The word `sgw check` and `sgw var list` print. Never the value.
    pub fn word(&self) -> &'static str {
        match self {
            State::Set(_) => "set",
            State::Missing => "missing",
            State::Locked => "locked",
            State::Unavailable(_) => "unavailable",
        }
    }
}

/// Why a reference could not be filled in. Said for whoever reads it — an agent whose push failed,
/// or the operator — with the command that fixes it, run on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarError {
    Missing(String),
    Locked(String),
    Unavailable(String, String),
    /// The value holds a character the place it goes may not have
    Unfit(String),
    /// The option the substitution produced fails the ordinary ssh option check
    Invalid(String, String),
}

impl fmt::Display for VarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VarError::Missing(k) => write!(
                f,
                "{{{k}}} has no value in the secret store; the operator sets it on the host running docker: sgw var set {k} (or sgw login, which asks for every missing one)"
            ),
            VarError::Locked(k) => write!(
                f,
                "{{{k}}} is in the secret store, which is locked; the operator unlocks it on the host running docker: sgw unlock"
            ),
            VarError::Unavailable(k, why) => {
                write!(f, "{{{k}}} cannot be read from the secret store: {why}")
            }
            VarError::Unfit(k) => write!(
                f,
                "the value of {{{k}}} cannot go into an ssh option: only letters, digits and . _ @ : , / - are allowed there; fix it with sgw var set {k}"
            ),
            VarError::Invalid(k, why) => write!(
                f,
                "with the value of {{{k}}} filled in, the ssh option {why}; fix it with sgw var set {k}"
            ),
        }
    }
}

impl std::error::Error for VarError {}

/// The values the config refers to, as last read. Shared by every clone.
#[derive(Clone, Default)]
pub struct Vars {
    cell: Arc<RwLock<HashMap<String, State>>>,
    /// Wakes the refresher: the store changed (a set, a delete, a lock), read it now
    changed: Arc<tokio::sync::Notify>,
}

impl Vars {
    pub fn new() -> Self {
        Vars::default()
    }

    /// What is known about `key`. One never read counts as missing.
    pub fn state(&self, key: &str) -> State {
        self.cell
            .read()
            .ok()
            .and_then(|m| m.get(key).cloned())
            .unwrap_or(State::Missing)
    }

    /// Replace what is known; true when anything changed.
    pub fn replace_all(&self, now: HashMap<String, State>) -> bool {
        let Ok(mut g) = self.cell.write() else {
            return false;
        };
        if *g == now {
            return false;
        }
        *g = now;
        true
    }

    /// The store changed. Every value is forgotten at once — a lock must take them now, not
    /// within a tick — and the refresher reads the store again straight away, so a value just set
    /// is back within the moment it takes.
    pub fn forget(&self) {
        if let Ok(mut g) = self.cell.write() {
            for v in g.values_mut() {
                *v = State::Locked;
            }
        }
        self.changed.notify_one();
    }

    /// An ssh option with its references filled in, checked as the value fits an ssh option and
    /// the result is an option the config would have accepted.
    pub fn ssh_option(&self, template: &str) -> Result<String, VarError> {
        let keys = placeholders(template).map_err(|e| VarError::Invalid(String::new(), e))?;
        for k in &keys {
            match self.state(k) {
                State::Set(v) if fits_ssh_option(&v) => {}
                State::Set(_) => return Err(VarError::Unfit(k.clone())),
                State::Missing => return Err(VarError::Missing(k.clone())),
                State::Locked => return Err(VarError::Locked(k.clone())),
                State::Unavailable(why) => return Err(VarError::Unavailable(k.clone(), why)),
            }
        }
        let filled = replace(template, |k| match self.state(k) {
            State::Set(v) => v,
            _ => String::new(),
        });
        if let Some(k) = keys.first() {
            crate::config::validate_ssh_option(&filled)
                .map_err(|e| VarError::Invalid(k.clone(), e))?;
        }
        Ok(filled)
    }
}

/// The ssh option a template stands for when checked at load time: each reference as a value that
/// fits, so a template is accepted exactly when some value would make it a valid option.
pub fn ssh_option_shape(template: &str) -> Result<String, String> {
    let (key, _) = template.split_once('=').unwrap_or((template, ""));
    if key.contains(['{', '}']) {
        return Err(
            "may use a {name} in its value only; the option name is written out, so what ssh is told to do stays in review"
                .to_string(),
        );
    }
    placeholders(template)?;
    Ok(replace(template, |_| "x".to_string()))
}

/// The keys `templates` refer to, each once, in order.
pub fn refs<'a>(templates: impl IntoIterator<Item = &'a String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for t in templates {
        for k in placeholders(t).unwrap_or_default() {
            if seen.insert(k.clone()) {
                out.push(k);
            }
        }
    }
    out
}

/// Read `keys` from the store.
pub async fn read(keys: &[String], source: &SecretSource) -> HashMap<String, State> {
    let mut out = HashMap::new();
    for k in keys {
        let st = match source.get_in(NAMESPACE, k).await {
            Ok(Some(v)) => State::Set(v),
            Ok(None) => State::Missing,
            Err(TokenError::Locked(_)) => State::Locked,
            Err(e) => State::Unavailable(e.to_string()),
        };
        out.insert(k.clone(), st);
    }
    out
}

/// For a one-shot subcommand: fill the cell once.
pub async fn load(vars: &Vars, keys: &[String], source: &SecretSource) {
    vars.replace_all(read(keys, source).await);
}

/// For `serve`: keep the cell current for as long as the process runs.
pub fn spawn_refresher(vars: Vars, keys: Vec<String>, source: SecretSource) {
    if keys.is_empty() {
        return;
    }
    tokio::spawn(async move {
        loop {
            let now = read(&keys, &source).await;
            let summary: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{{{k}}}: {}",
                        now.get(k).map(State::word).unwrap_or("missing")
                    )
                })
                .collect();
            if vars.replace_all(now) {
                log::info!("per-person values: {}", summary.join(", "));
            }
            tokio::select! {
                _ = tokio::time::sleep(REFRESH) => {}
                _ = vars.changed.notified() => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, State)]) -> Vars {
        let v = Vars::new();
        v.replace_all(
            pairs
                .iter()
                .map(|(k, s)| (k.to_string(), s.clone()))
                .collect(),
        );
        v
    }

    #[test]
    fn a_key_is_path_shaped() {
        for ok in [
            "bastion",
            "ghe.example.com/bastion",
            "a/b/c",
            "proxy_user",
            "x-1",
        ] {
            assert!(valid_key(ok), "{ok}");
        }
        for bad in [
            "", "a//b", "/a", "a/", "a b", "a=b", "..", "a/../b", "a/./b", "ä", "{a}",
        ] {
            assert!(!valid_key(bad), "{bad:?}");
        }
        assert!(!valid_key(&"a".repeat(KEY_MAX + 1)));
    }

    #[test]
    fn references_are_found_and_a_stray_brace_is_an_error() {
        assert_eq!(
            placeholders("ProxyJump={user}@{host}:22").unwrap(),
            vec!["user", "host"]
        );
        assert!(placeholders("ProxyJump=bastion").unwrap().is_empty());
        for bad in [
            "ProxyJump={",
            "ProxyJump=}",
            "ProxyJump={}",
            "ProxyJump={a b}",
            "ProxyJump=}a{",
        ] {
            assert!(placeholders(bad).is_err(), "{bad}");
        }
    }

    /// The key is written out; only the value may be a variable.
    #[test]
    fn only_the_value_of_an_option_may_be_a_variable() {
        assert_eq!(
            ssh_option_shape("ProxyJump={bastion}").unwrap(),
            "ProxyJump=x"
        );
        for bad in ["{opt}", "{key}=x", "Proxy{x}=y", "{opt}=", "ProxyJump={a"] {
            assert!(ssh_option_shape(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_value_is_filled_in_as_it_is_and_ssh_syntax_is_not_interpreted() {
        let v = vars(&[("bastion", State::Set("alice@h1:2222,bob@h2".into()))]);
        assert_eq!(
            v.ssh_option("ProxyJump={bastion}").unwrap(),
            "ProxyJump=alice@h1:2222,bob@h2"
        );
        let v = vars(&[
            ("u", State::Set("alice".into())),
            (
                "ghe.example.com/h",
                State::Set("bastion.example.com".into()),
            ),
        ]);
        assert_eq!(
            v.ssh_option("ProxyJump={u}@{ghe.example.com/h}").unwrap(),
            "ProxyJump=alice@bastion.example.com"
        );
    }

    /// A value that would end the option and start another — or change what ssh does — is refused,
    /// whatever was typed into the store.
    #[test]
    fn a_value_that_could_slip_in_another_option_is_refused() {
        for evil in [
            "h -oProxyCommand=sh",
            "h\nProxyCommand sh",
            "h=1",
            "h\tx",
            "h'x",
            "h\"x",
            "%h",
            "h;sh",
            "$(sh)",
            "",
        ] {
            let v = vars(&[("bastion", State::Set(evil.into()))]);
            assert_eq!(
                v.ssh_option("ProxyJump={bastion}"),
                Err(VarError::Unfit("bastion".into())),
                "{evil:?}"
            );
        }
    }

    #[test]
    fn a_missing_or_locked_value_says_what_to_run() {
        let v = vars(&[("b", State::Locked)]);
        let e = v.ssh_option("ProxyJump={b}").unwrap_err();
        assert_eq!(e, VarError::Locked("b".into()));
        assert!(e.to_string().contains("sgw unlock"));
        let e = Vars::new().ssh_option("ProxyJump={bastion}").unwrap_err();
        assert_eq!(e, VarError::Missing("bastion".into()));
        assert!(e.to_string().contains("sgw var set bastion"));
    }

    #[test]
    fn a_lock_forgets_every_value() {
        let v = vars(&[("b", State::Set("h".into()))]);
        v.forget();
        assert_eq!(v.state("b"), State::Locked);
        assert!(v.ssh_option("ProxyJump={b}").is_err());
    }

    #[test]
    fn refs_lists_each_key_once() {
        let t = vec![
            "ProxyJump={b}".to_string(),
            "HostKeyAlias={a}".to_string(),
            "User={b}".to_string(),
            "Compression=yes".to_string(),
        ];
        assert_eq!(refs(&t), vec!["b", "a"]);
    }
}
