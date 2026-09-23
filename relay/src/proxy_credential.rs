//! The upstream proxy's credential as the secret store holds it (#151).
//!
//! 0.2.22 (#53) moved the credential out of `.devcontainer/.env` — which the dev container can
//! read — into the store, filed under `proxy/upstream` by `gw:proxy-credential`. Squid was wired to
//! the store; the relay kept reading `SEKIMORE_UPSTREAM_PROXY_*` and `config.yml`, so once a
//! recreate dropped the old variables its passthrough and its own API calls got 407 while Squid,
//! with the same stored value, got through.
//!
//! The store is locked when the relay starts and unlocked later, and `gw:proxy-credential` can
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
/// `gw:proxy-credential` is picked up within this.
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

/// The stored value is the JSON `gw:proxy-credential` writes: `{"username": …, "password": …}`.
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

/// The store's credential now. A locked store, or no entry, is `None`: the proxy then gets the
/// environment's or `config.yml`'s credential, as before 0.2.22.
pub async fn load(source: &SecretSource) -> Option<Credential> {
    match source.get_in(NAMESPACE, NAME).await {
        Ok(Some(v)) => parse(&v),
        Ok(None) | Err(_) => None,
    }
}

/// For a one-shot subcommand (`login`, say) that goes through the proxy itself.
pub async fn prime(spec: Option<&ProxySpec>, source: &SecretSource) {
    if let Some(px) = spec {
        px.stored.set(load(source).await);
    }
}

/// For `serve`: keep the cell current for as long as the process runs.
pub fn spawn_refresher(spec: Option<&ProxySpec>, source: SecretSource) {
    let Some(px) = spec else {
        return;
    };
    let cell = px.stored.clone();
    let url = px.url.clone();
    tokio::spawn(async move {
        loop {
            let now = load(&source).await;
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
}
