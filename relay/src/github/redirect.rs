//! #485: following an upstream API answer that sends the client to another host.
//!
//! `GET /repos/{repo}/actions/jobs/{id}/logs` answers 302 to a storage host. The API client
//! (`http::build_client`) does not follow a redirect off the API's origin; the call hands the
//! `Location` here instead, and this fetches it **in the gateway**, under rules of its own:
//!
//! - **no credential.** The request carries no `Authorization`, no cookie, nothing of the
//!   upstream token. The client is built without default headers, and the caller never adds one.
//! - **https only**, and no `user:pass@` in the URL.
//! - **public addresses only.** A name that resolves to loopback, a private or link-local range,
//!   carrier-grade NAT, or an address of the gateway itself is refused — checked as the connection
//!   is made (the resolver below), so a name that changes its answer between a check and the dial
//!   does not get through. An address written in the URL is checked the same way.
//! - **at most [`MAX_HOPS`] further redirects**, each one checked like the first.
//! - **the existing cap** on what is read, and every hop in the audit: `redirect_fetch` with the
//!   host, the path and the status, or `redirect_refused` with the reason. The query string is
//!   left out: on a storage host it is a signature, good for anyone who has it until it expires.
//!
//! What may hand a URL here: the built-in client, from the upstream's own 3xx; and the gateway's
//! side of a forge sidecar, from the sidecar's reply (`forge::sidecar`, `fetch`). The sidecar has
//! no egress of its own, so the gateway, which does, makes this one request for it.
//!
//! With `proxy.upstream_proxy` set the proxy resolves the name and dials it, so the gateway's own
//! answer is only a pre-check (a name the gateway resolves to a refused address is refused; one it
//! cannot resolve is left to the proxy). An address written in the URL is refused either way.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use url::{Host, Url};

use super::http::{builder, read_limited, truncate, HttpOptions};
use super::GhError;
use crate::audit::{Actor, Audit};

/// How many redirects are followed after the upstream API's own. Storage hosts answer the first
/// request; one more for a CDN in front of them leaves room to spare.
pub const MAX_HOPS: usize = 3;

/// Refuses, at connection time, a name that resolves to an address the gateway must not reach.
struct PublicOnly;

#[derive(Debug)]
struct NotPublic(String);

impl std::fmt::Display for NotPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NotPublic {}

impl reqwest::dns::Resolve for PublicOnly {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            if let Some(bad) = addrs.iter().find(|a| refused_address(a.ip())) {
                return Err(Box::new(NotPublic(format!(
                    "{host} resolves to {}, which is not a public address",
                    bad.ip()
                ))) as _);
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Loopback, private, link-local, CGNAT, unspecified — and any address of this host, which on the
/// gateway is also the address dev reaches it on.
fn refused_address(ip: IpAddr) -> bool {
    crate::passthrough::is_denied_destination(ip) || crate::passthrough::is_local_ip(ip)
}

/// Fetches what an upstream answer points to, under the rules in the module doc.
pub struct Fetcher {
    http: reqwest::Client,
    audit: Arc<Audit>,
    /// The ledger edge these requests take: the gateway's own hop out, as for its API calls
    route: &'static str,
    /// The request goes through `proxy.upstream_proxy`, which resolves the name itself
    proxied: bool,
    /// Tests only: names pinned to a local address are let through, over plain http too.
    /// Everything else — a loopback address written in the URL included — is held to the rules
    #[cfg(any(test, feature = "test-hooks"))]
    local_for_tests: Vec<String>,
}

impl Fetcher {
    /// The gateway's: the same TLS roots and proxy as its API client.
    pub fn new(
        opts: &HttpOptions<'_>,
        audit: Arc<Audit>,
        route: &'static str,
    ) -> anyhow::Result<Self> {
        let proxied = opts.proxy.is_some();
        let mut b = builder(opts)?.redirect(reqwest::redirect::Policy::none());
        if !proxied {
            b = b.dns_resolver(Arc::new(PublicOnly));
        }
        Ok(Fetcher {
            http: b.build()?,
            audit,
            route,
            proxied,
            #[cfg(any(test, feature = "test-hooks"))]
            local_for_tests: Vec::new(),
        })
    }

    /// Tests only: as [`Fetcher::new`], with `local` (name → a loopback address) let through over
    /// plain http.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn for_tests(audit: Arc<Audit>, local: &[(String, SocketAddr)]) -> anyhow::Result<Self> {
        let mut f = Fetcher::new(
            &HttpOptions {
                connect_to: local,
                no_env_proxy: true,
                ..Default::default()
            },
            audit,
            crate::paths::RELAY_GITHUB_API,
        )?;
        f.local_for_tests = local.iter().map(|(n, _)| n.clone()).collect();
        Ok(f)
    }

    #[cfg(any(test, feature = "test-hooks"))]
    fn local_ok(&self, url: &Url) -> bool {
        matches!(url.host(), Some(Host::Domain(d)) if self.local_for_tests.iter().any(|n| n == d))
    }

    #[cfg(not(any(test, feature = "test-hooks")))]
    fn local_ok(&self, _url: &Url) -> bool {
        false
    }

    /// Why `url` may not be fetched, or `None`.
    async fn refusal(&self, url: &Url) -> Option<String> {
        let local = self.local_ok(url);
        if url.scheme() != "https" && !(local && url.scheme() == "http") {
            return Some(format!("{} is not https", url.scheme()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Some("the URL carries a user name or password".into());
        }
        if local {
            return None;
        }
        let ip = match url.host() {
            None => return Some("the URL has no host".into()),
            Some(Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
            Some(Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
            Some(Host::Domain(d)) => {
                let d = d.trim_end_matches('.').to_ascii_lowercase();
                if d == "localhost" || d.ends_with(".localhost") {
                    return Some(format!("{d} is this host"));
                }
                None
            }
        };
        if let Some(ip) = ip {
            if refused_address(ip) {
                return Some(format!("{ip} is not a public address"));
            }
        } else if self.proxied {
            // The proxy resolves it. What the gateway would resolve it to is a pre-check only
            let host = url.host_str().unwrap_or_default();
            if let Ok(addrs) = tokio::net::lookup_host((host, 0)).await {
                for a in addrs {
                    if refused_address(a.ip()) {
                        return Some(format!(
                            "{host} resolves to {}, which is not a public address",
                            a.ip()
                        ));
                    }
                }
            }
        }
        None
    }

    fn refuse(&self, url: &Url, reason: &str, extra: &[(&str, &str)]) -> GhError {
        let host = host_of(url);
        let mut fields: Vec<(&str, &str)> = vec![("host", &host), ("path", url.path())];
        fields.extend_from_slice(extra);
        self.audit.deny_edge(
            self.route,
            "redirect_refused",
            Actor::System,
            reason,
            &fields,
        );
        GhError::Refused(format!(
            "the upstream sent this request on to {host}, which the gateway does not fetch: {reason}"
        ))
    }

    /// GET `start` and whatever it redirects to, up to [`MAX_HOPS`] more, reading at most `cap`
    /// bytes of the answer. `extra` goes into each audit entry (the sidecar that asked, say).
    pub async fn fetch(
        &self,
        start: &Url,
        cap: usize,
        extra: &[(&str, &str)],
    ) -> Result<Vec<u8>, GhError> {
        let mut url = start.clone();
        for hop in 0..=MAX_HOPS {
            if let Some(why) = self.refusal(&url).await {
                return Err(self.refuse(&url, &why, extra));
            }
            let resp = match self
                .http
                .get(url.clone())
                .header(reqwest::header::USER_AGENT, super::http::USER_AGENT)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    if let Some(np) = not_public(&e) {
                        return Err(self.refuse(&url, &np, extra));
                    }
                    return Err(GhError::Http(e));
                }
            };
            let status = resp.status();
            let host = host_of(&url);
            let code = status.as_u16().to_string();
            let mut fields: Vec<(&str, &str)> =
                vec![("host", &host), ("path", url.path()), ("status", &code)];
            fields.extend_from_slice(extra);
            self.audit
                .log_edge(self.route, "redirect_fetch", Actor::System, &fields);
            if status.is_redirection() {
                let Some(next) = location(&resp) else {
                    return Err(self.refuse(&url, "a redirect without a usable Location", extra));
                };
                if hop == MAX_HOPS {
                    return Err(self.refuse(
                        &next,
                        &format!("more than {MAX_HOPS} redirects after the upstream's"),
                        extra,
                    ));
                }
                url = next;
                continue;
            }
            let body = read_limited(resp, cap).await?;
            if status.as_u16() >= 400 {
                return Err(GhError::Status {
                    method: "GET".into(),
                    path: format!("{host}{}", url.path()),
                    status: status.as_u16(),
                    body: truncate(&body),
                });
            }
            return Ok(body);
        }
        unreachable!("the last hop returns or refuses")
    }
}

/// Where a 3xx sends the client: its `Location`, resolved against the URL that answered. `None`
/// for any other answer, or one without a usable `Location`.
pub(crate) fn location(resp: &reqwest::Response) -> Option<Url> {
    if !resp.status().is_redirection() {
        return None;
    }
    let l = resp
        .headers()
        .get(reqwest::header::LOCATION)?
        .to_str()
        .ok()?;
    resp.url().join(l).ok()
}

/// `host[:port]`, without the path and query.
fn host_of(url: &Url) -> String {
    match (url.host_str(), url.port()) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        (Some(h), None) => h.to_string(),
        (None, _) => String::new(),
    }
}

/// The resolver's refusal, if that is what stopped the request.
fn not_public(e: &reqwest::Error) -> Option<String> {
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(s) = src {
        if let Some(np) = s.downcast_ref::<NotPublic>() {
            return Some(np.0.clone());
        }
        src = s.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict() -> Fetcher {
        Fetcher::new(
            &HttpOptions {
                no_env_proxy: true,
                ..Default::default()
            },
            Arc::new(Audit::disabled()),
            crate::paths::RELAY_GITHUB_API,
        )
        .unwrap()
    }

    async fn refused(f: &Fetcher, url: &str) -> String {
        match f.fetch(&Url::parse(url).unwrap(), 1024, &[]).await {
            Err(GhError::Refused(m)) => m,
            other => panic!("{url}: expected a refusal, got {other:?}"),
        }
    }

    /// Each of these is refused before anything is dialled: the scheme, a credential in the URL,
    /// or an address the gateway must not reach — the metadata service, the internal network,
    /// loopback, in either family or written as a mapped IPv6 address.
    #[tokio::test]
    async fn what_the_gateway_must_not_reach_is_refused() {
        let f = strict();
        for (url, why) in [
            ("http://logs.example.com/x", "not https"),
            ("ftp://logs.example.com/x", "not https"),
            (
                "https://user:pw@logs.example.com/x",
                "user name or password",
            ),
            (
                "https://169.254.169.254/latest/meta-data/",
                "not a public address",
            ),
            ("https://10.0.0.5/x", "not a public address"),
            ("https://172.20.0.2/x", "not a public address"),
            ("https://192.168.1.1/x", "not a public address"),
            ("https://100.64.0.1/x", "not a public address"),
            ("https://127.0.0.1:8420/api", "not a public address"),
            ("https://[::1]/x", "not a public address"),
            ("https://[fd00::1]/x", "not a public address"),
            ("https://[::ffff:10.0.0.1]/x", "not a public address"),
            ("https://localhost/x", "this host"),
            ("https://api.localhost/x", "this host"),
        ] {
            let m = refused(&f, url).await;
            assert!(m.contains(why), "{url}: {m}");
        }
    }

    /// A name is checked where it is dialled: one that resolves to loopback is refused by the
    /// resolver, not let through because the spelling check does not know it.
    #[tokio::test]
    async fn a_name_that_resolves_to_loopback_is_refused_when_dialled() {
        let f = strict();
        // In /etc/hosts on Debian and most images, and not a spelling the check knows
        let name = "ip6-localhost";
        if tokio::net::lookup_host((name, 0)).await.is_err() {
            // Not in this host's /etc/hosts: nothing to resolve, nothing to prove here
            return;
        }
        let m = refused(&f, &format!("https://{name}/x")).await;
        assert!(m.contains("not a public address"), "{m}");
    }

    /// The test fetcher lets through only the names it was given — a loopback address written in
    /// the URL is still refused, so the integration tests' refusals are the real rules.
    #[tokio::test]
    async fn the_test_fetcher_lets_through_only_its_pinned_names() {
        let f = Fetcher::for_tests(
            Arc::new(Audit::disabled()),
            &[("storage.test".to_string(), "127.0.0.1:9".parse().unwrap())],
        )
        .unwrap();
        let m = refused(&f, "http://127.0.0.1:9/x").await;
        assert!(m.contains("not https"), "{m}");
        let m = refused(&f, "https://127.0.0.1:9/x").await;
        assert!(m.contains("not a public address"), "{m}");
        assert!(f
            .refusal(&Url::parse("http://storage.test:9/x").unwrap())
            .await
            .is_none());
    }
}
