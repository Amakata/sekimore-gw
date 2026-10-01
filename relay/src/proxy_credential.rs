//! The upstream proxy's credential as the secret store holds it (#151).
//!
//! 0.2.22 (#53) moved the credential out of `.devcontainer/.env` — which the dev container can
//! read — into the store, filed under `proxy/upstream` by sgw proxy-credential. Squid was wired to
//! the store; the relay kept reading `SEKIMORE_UPSTREAM_PROXY_*` and `config.yml`, so once a
//! recreate dropped the old variables its passthrough and its own API calls got 407 while Squid,
//! with the same stored value, got through.
//!
//! The store is locked when the relay starts and unlocked later, and sgw proxy-credential can
//! change the value at any time. So the credential is not read once: `serve` keeps a shared cell
//! current (`spawn_refresher`), a one-shot subcommand fills it once (`prime`), and every user of the
//! proxy reads the cell at the moment it connects (`ProxySpec::credential`).

use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::config::ProxySpec;
use crate::github::upstream_token::SecretSource;

/// The namespace and name the credential is filed under. The Python gateway reads the same entry
/// for Squid, so these are shared with it.
pub const NAMESPACE: &str = "proxy";
pub const NAME: &str = "upstream";

/// How often `serve` looks at the store again. An unlock, a lock, or a new credential set with
/// sgw proxy-credential is picked up within this.
const REFRESH: Duration = Duration::from_secs(5);

/// A username and a password.
pub type Credential = (String, String);

/// What the store held when last read, shared by every clone of the `ProxySpec` it belongs to.
#[derive(Clone, Default)]
pub struct StoredProxyCredential(Arc<RwLock<Option<Credential>>>);

impl StoredProxyCredential {
    pub fn get(&self) -> Option<Credential> {
        self.0.read().map(|g| g.clone()).unwrap_or(None)
    }

    /// Replaces the value; true when it changed, so a caller can say so once rather than every tick.
    pub fn set(&self, value: Option<Credential>) -> bool {
        let Ok(mut g) = self.0.write() else {
            return false;
        };
        if *g == value {
            return false;
        }
        *g = value;
        true
    }
}

impl PartialEq for StoredProxyCredential {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}
impl Eq for StoredProxyCredential {}

/// Never the value: a `ProxySpec` ends up in debug output and logs.
impl fmt::Debug for StoredProxyCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = if self.get().is_some() { "set" } else { "unset" };
        write!(f, "StoredProxyCredential({state})")
    }
}

/// The stored value is the JSON sgw proxy-credential writes: `{"username": …, "password": …}`.
/// Anything else is not a credential this relay can present.
pub fn parse(value: &str) -> Option<Credential> {
    let v: serde_json::Value = serde_json::from_str(value).ok()?;
    let user = v.get("username")?.as_str()?.to_string();
    let pass = v
        .get("password")
        .and_then(|p| p.as_str())
        .unwrap_or("")
        .to_string();
    if user.is_empty() {
        return None;
    }
    Some((user, pass))
}

/// #334: the per-person values the credential lives in. `proxy-credential set` writes these, and a
/// config with no `{name}` in `upstream_proxy_username` / `_password` reads them.
pub const VAR_USER: &str = "proxy_user";
pub const VAR_PASSWORD: &str = "proxy_password";

/// The key a config field refers to: the whole value is `{key}`. A field that is anything else is
/// a literal (the pre-0.2.22 way, readable from dev).
pub fn reference(field: Option<&str>) -> Option<String> {
    let f = field?.trim();
    let key = f.strip_prefix('{')?.strip_suffix('}')?;
    crate::vars::valid_key(key).then(|| key.to_string())
}

/// The two keys the credential is read from: the config's references, or the default pair.
pub fn var_keys(spec: &ProxySpec) -> (String, String) {
    (
        reference(spec.username.as_deref()).unwrap_or_else(|| VAR_USER.to_string()),
        reference(spec.password.as_deref()).unwrap_or_else(|| VAR_PASSWORD.to_string()),
    )
}

/// The store's credential now: the per-person values (#334), else the record `proxy-credential`
/// wrote before them. A locked store, or nothing stored, is `None`: the proxy then gets the
/// environment's or `config.yml`'s literal credential, as before 0.2.22.
pub async fn load(spec: &ProxySpec, source: &SecretSource) -> Option<Credential> {
    let (ku, kp) = var_keys(spec);
    let ns = crate::vars::NAMESPACE;
    if let Ok(Some(user)) = source.get_in(ns, &ku).await {
        if !user.is_empty() {
            let pass = source
                .get_in(ns, &kp)
                .await
                .ok()
                .flatten()
                .unwrap_or_default();
            return Some((user, pass));
        }
    }
    match source.get_in(NAMESPACE, NAME).await {
        Ok(Some(v)) => parse(&v),
        Ok(None) | Err(_) => None,
    }
}

/// #334: move the record `proxy-credential` wrote before the per-person values into them — once,
/// when the store is readable, the way the upstream token moved into the store. A value already
/// under the new keys wins and the old record is only removed. Returns whether anything moved.
pub async fn migrate(source: &SecretSource) -> bool {
    let Ok(Some(old)) = source.get_in(NAMESPACE, NAME).await else {
        return false;
    };
    let ns = crate::vars::NAMESPACE;
    if let Some((user, pass)) = parse(&old) {
        if matches!(source.get_in(ns, VAR_USER).await, Ok(None))
            && (source.set_in(ns, VAR_USER, &user).await.is_err()
                || source.set_in(ns, VAR_PASSWORD, &pass).await.is_err())
        {
            return false;
        }
    }
    source.delete_in(NAMESPACE, NAME).await.is_ok()
}

/// For a one-shot subcommand (`login`, say) that goes through the proxy itself.
pub async fn prime(spec: Option<&ProxySpec>, source: &SecretSource) {
    if let Some(px) = spec {
        px.stored.set(load(px, source).await);
    }
}

/// For `serve`: keep the cell current for as long as the process runs.
pub fn spawn_refresher(spec: Option<&ProxySpec>, source: SecretSource) {
    let Some(px) = spec else {
        return;
    };
    let px = px.clone();
    let cell = px.stored.clone();
    let url = px.url.clone();
    tokio::spawn(async move {
        loop {
            if migrate(&source).await {
                log::info!(
                    "upstream proxy {url}: moved the stored credential to the per-person values {{{VAR_USER}}} / {{{VAR_PASSWORD}}}"
                );
            }
            let now = load(&px, &source).await;
            let present = now.is_some();
            if cell.set(now) {
                if present {
                    log::info!("upstream proxy {url}: using the credential in the secret store");
                } else {
                    log::info!(
                        "upstream proxy {url}: no credential in the secret store (locked, or never set); \
                         falling back to SEKIMORE_UPSTREAM_PROXY_* / config.yml"
                    );
                }
            }
            tokio::time::sleep(REFRESH).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stored_json_is_a_credential_and_little_else_is() {
        assert_eq!(
            parse(r#"{"username":"alice","password":"p@ss:w0rd"}"#),
            Some(("alice".into(), "p@ss:w0rd".into()))
        );
        // a password may be empty; a username may not
        assert_eq!(
            parse(r#"{"username":"alice"}"#),
            Some(("alice".into(), "".into()))
        );
        assert_eq!(parse(r#"{"username":"","password":"x"}"#), None);
        assert_eq!(parse(r#"{"password":"x"}"#), None);
        assert_eq!(parse("alice:secret"), None);
    }

    #[test]
    fn debug_output_never_carries_the_value() {
        let c = StoredProxyCredential::default();
        c.set(Some(("alice".into(), "hunter2".into())));
        let shown = format!("{c:?}");
        assert!(
            !shown.contains("hunter2") && !shown.contains("alice"),
            "{shown}"
        );
        assert!(shown.contains("set"));
    }

    #[test]
    fn clones_share_the_cell_and_set_reports_a_change_once() {
        let a = StoredProxyCredential::default();
        let b = a.clone();
        assert!(a.set(Some(("u".into(), "p".into()))));
        assert_eq!(b.get(), Some(("u".into(), "p".into())));
        assert!(
            !a.set(Some(("u".into(), "p".into()))),
            "the same value is not a change"
        );
        assert!(b.set(None));
        assert_eq!(a.get(), None);
    }

    fn source(locked: bool) -> SecretSource {
        use crate::store::crypto::{Kdf, KdfParams, Secret};
        let mut s = crate::store::SecretStore::open_in_memory().unwrap();
        s.initialise(
            &Secret::new(b"test".to_vec()),
            Kdf::Argon2id,
            KdfParams {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
        )
        .unwrap();
        if locked {
            s.lock();
        }
        SecretSource::InProcess(std::sync::Arc::new(tokio::sync::Mutex::new(s)))
    }

    fn spec(user: Option<&str>, pass: Option<&str>) -> ProxySpec {
        ProxySpec {
            url: "http://proxy.example.com:3128".into(),
            username: user.map(String::from),
            password: pass.map(String::from),
            stored: StoredProxyCredential::default(),
            via_squid: None,
            direct_egress: Default::default(),
        }
    }

    /// #334: a field that is exactly `{key}` refers to the store; anything else is a literal.
    #[test]
    fn a_reference_is_a_whole_field() {
        assert_eq!(reference(Some("{proxy_user}")), Some("proxy_user".into()));
        assert_eq!(reference(Some(" {corp/user} ")), Some("corp/user".into()));
        for literal in ["alice", "{a b}", "x{proxy_user}", "{proxy_user}x", "{}", ""] {
            assert_eq!(reference(Some(literal)), None, "{literal:?}");
        }
        assert_eq!(reference(None), None);
    }

    /// The order: the per-person values (the config's keys, or the default pair), then the record
    /// from before them. A literal `{name}` is never presented as a username.
    #[tokio::test]
    async fn the_credential_comes_from_the_per_person_values_first() {
        let src = source(false);
        let legacy = spec(None, None);
        assert_eq!(load(&legacy, &src).await, None);
        src.set_in(NAMESPACE, NAME, r#"{"username":"old","password":"o"}"#)
            .await
            .unwrap();
        assert_eq!(load(&legacy, &src).await, Some(("old".into(), "o".into())));
        src.set_in(crate::vars::NAMESPACE, VAR_USER, "alice")
            .await
            .unwrap();
        src.set_in(crate::vars::NAMESPACE, VAR_PASSWORD, "p@ss:w0rd %x")
            .await
            .unwrap();
        assert_eq!(
            load(&legacy, &src).await,
            Some(("alice".into(), "p@ss:w0rd %x".into())),
            "the default pair wins over the old record"
        );
        let refs = spec(Some("{corp/user}"), Some("{corp/pass}"));
        src.set_in(crate::vars::NAMESPACE, "corp/user", "bob")
            .await
            .unwrap();
        src.set_in(crate::vars::NAMESPACE, "corp/pass", "b")
            .await
            .unwrap();
        assert_eq!(load(&refs, &src).await, Some(("bob".into(), "b".into())));
        // Unstored, a referring config presents nothing — not "{corp/user}" as a name
        let empty = source(false);
        let px = spec(Some("{corp/user}"), Some("{corp/pass}"));
        px.stored.set(load(&px, &empty).await);
        assert_eq!(px.credential(), None);
        assert_eq!(px.credential_source(), "none");
        // and a literal still works as before 0.2.22
        let lit = spec(Some("carol"), Some("c"));
        assert_eq!(lit.credential(), Some(("carol".into(), "c".into())));
    }

    #[tokio::test]
    async fn a_locked_store_yields_nothing() {
        assert_eq!(load(&spec(None, None), &source(true)).await, None);
    }

    /// The old record moves into the default pair once and is removed; a value already under the
    /// new keys is kept.
    #[tokio::test]
    async fn the_old_record_moves_into_the_per_person_values() {
        let src = source(false);
        src.set_in(NAMESPACE, NAME, r#"{"username":"old","password":"o"}"#)
            .await
            .unwrap();
        assert!(migrate(&src).await);
        assert_eq!(src.get_in(NAMESPACE, NAME).await.unwrap(), None);
        assert_eq!(
            src.get_in(crate::vars::NAMESPACE, VAR_USER).await.unwrap(),
            Some("old".into())
        );
        assert!(!migrate(&src).await, "nothing left to move");

        let src = source(false);
        src.set_in(crate::vars::NAMESPACE, VAR_USER, "new")
            .await
            .unwrap();
        src.set_in(NAMESPACE, NAME, r#"{"username":"old","password":"o"}"#)
            .await
            .unwrap();
        assert!(migrate(&src).await);
        assert_eq!(
            src.get_in(crate::vars::NAMESPACE, VAR_USER).await.unwrap(),
            Some("new".into()),
            "a value already set is not overwritten"
        );
        assert_eq!(src.get_in(NAMESPACE, NAME).await.unwrap(), None);
    }
}
