//! `Rules`: the one resolved structure DNS, the firewall, Squid and the relay are to read, so that
//! none of them reads `allow_domains` or `domain_handlers` itself (0.3.0 plan, "段階 2 のための形").
//!
//! In this step it is filled from today's keys and nothing in production reads it. Every answer
//! it gives is today's answer, worked out the way the Python gateway works it out:
//!
//! | question | today |
//! |---|---|
//! | [`Rules::decide`] | the order of `DNSServer.handle_query` (`src/dns_server.py:616-877`) |
//! | [`Rules::seed_candidates`] | `Orchestrator._domains_to_seed` and `_seed_allow_list` (`src/orchestrator.py`) |
//! | [`Rules::squid_allow`] | `ProxyManager._generate_domain_acls(config.proxy_allow_domains())` |
//! | [`Rules::squid_deny`] | `ProxyManager._generate_relayed_denial(config.proxy_denied_domains())` |
//! | [`Rules::https_targets`] | the relay's `Resolved::https_targets` (`crate::config`) |
//!
//! The routes are internal words. `config.yml` does not have them in this step.

use super::{domain_matches, py, Handler, PyInt, Settings};
use crate::config::{HttpsTarget, Resolved};

/// What a name entry covers, read the way `domain_matches` reads it: lowercased, trailing dots
/// removed, stripped (in that order), then `*.x` and `*x` are `.x` and `x`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// The entry is blank once stripped: it covers nothing
    Nothing,
    Exact(String),
    /// `.base`: `base` and every name under it, on label boundaries
    Suffix(String),
}

impl Pattern {
    pub fn of(entry: &str) -> Pattern {
        let lowered = py::lower(entry);
        let p = py::strip(py::rstrip_dots(&lowered));
        if p.is_empty() {
            return Pattern::Nothing;
        }
        // `*.x` → `.x`; `*x` (no dot) → `x`, the exact name
        let p = p.strip_prefix('*').unwrap_or(p);
        match p.strip_prefix('.') {
            Some(base) => Pattern::Suffix(base.to_string()),
            None => Pattern::Exact(p.to_string()),
        }
    }

    /// `d` is already lowercased with its trailing dots removed.
    pub fn matches_normalized(&self, d: &str) -> bool {
        match self {
            Pattern::Nothing => false,
            Pattern::Exact(p) => d == p,
            Pattern::Suffix(base) => {
                d == base
                    || (d.len() > base.len()
                        && d.ends_with(base.as_str())
                        && d.as_bytes()[d.len() - base.len() - 1] == b'.')
            }
        }
    }
}

/// How traffic for a name leaves the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Straight out, admitted into the ipset by the DNS answer (`allow_domains`)
    Direct,
    /// Only 443, through the relay's passthrough (`handler: https-relay`)
    Relay,
    /// SSH git, the forge API and 443, all taken by the relay (`handler: github`)
    Gateway,
    /// Refused (`handler: deny`)
    Deny,
}

/// The per-connection upload cap on the relay's 443 passthrough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cap {
    /// The direct route has nowhere to apply one
    None,
    /// `max_upload_bytes: -1`
    Unlimited,
    Bytes(PyInt),
    /// `max_upload_bytes` unset: `relay.https_max_upload_bytes`, which is the relay's key
    RelayDefault,
}

/// Where a rule came from, for `sgw config` to say later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// `allow_domains[i]`
    AllowDomains(usize),
    /// `domain_handlers.<normalized key>`
    DomainHandlers(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameRule {
    /// As written
    pub entry: String,
    pub pattern: Pattern,
    pub route: Route,
    pub cap: Cap,
    pub origin: Origin,
}

/// What DNS does with a query for a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// `block_domains`: NXDOMAIN
    Block,
    /// `ignore_domains`: NXDOMAIN, recorded as ignored
    Ignore,
    /// `handler: deny`: NXDOMAIN
    Deny,
    /// A relayed name: answer with the gateway's own address, nothing enters the ipset
    AnswerGateway,
    /// Resolve upstream; `admit` says whether the addresses enter the allow ipset
    Resolve { admit: bool },
    /// Not on the allow list: NXDOMAIN
    NotAllowed,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rules {
    /// `allow_domains` (direct) and the non-splice `domain_handlers` entries, in that order.
    /// A `splice` handler changes nothing today, so it has no rule
    pub names: Vec<NameRule>,
    pub block: Vec<String>,
    pub ignore: Vec<String>,
    pub resolve_deny_cidrs: Vec<String>,
    pub resolve_allow_cidrs: Vec<String>,
    pub allow_ips: Vec<String>,
    pub block_ips: Vec<String>,
    /// Destination ports towards allowed names and IPs; empty is every port
    pub allowed_ports: Vec<u16>,
    /// `proxy.direct_egress: deny` with an upstream proxy: nothing direct enters the ipset
    pub direct_egress_denied: bool,
    /// Opened in INPUT for the relay
    pub relay_input_ports: Vec<PyInt>,
    /// The relay's 443 targets, when the relay's own reading resolved
    https: Vec<HttpsTarget>,
    // the raw lists the questions are answered from, kept exactly as `config.py` holds them
    allow_domains: Vec<String>,
    handlers: Vec<(String, Handler)>,
    proxy_allow: Vec<String>,
    proxy_denied: Vec<String>,
}

impl Rules {
    /// Builds the rules from the Python-owned keys. `relay` is the relay's resolved config, when
    /// it resolves, and supplies the 443 targets and their caps.
    pub fn build(s: &Settings, relay: Option<&Resolved>) -> Rules {
        let mut names: Vec<NameRule> = s
            .allow_domains
            .iter()
            .enumerate()
            .map(|(i, d)| NameRule {
                entry: d.clone(),
                pattern: Pattern::of(d),
                route: Route::Direct,
                cap: Cap::None,
                origin: Origin::AllowDomains(i),
            })
            .collect();
        for (d, h) in &s.domain_handlers {
            let route = match h.handler {
                Handler::Splice => continue,
                Handler::Github => Route::Gateway,
                Handler::HttpsRelay => Route::Relay,
                Handler::Deny => Route::Deny,
            };
            let cap = match (route, h.max_upload_bytes) {
                (Route::Deny, _) => Cap::None,
                (_, Some(-1)) => Cap::Unlimited,
                (_, Some(n)) => Cap::Bytes(n),
                (_, None) => Cap::RelayDefault,
            };
            names.push(NameRule {
                entry: d.clone(),
                pattern: Pattern::Exact(d.clone()),
                route,
                cap,
                origin: Origin::DomainHandlers(d.clone()),
            });
        }
        Rules {
            names,
            block: s.block_domains.clone(),
            ignore: s.ignore_domains.clone(),
            resolve_deny_cidrs: s.resolve_deny_cidrs.clone(),
            resolve_allow_cidrs: s.resolve_allow_cidrs.clone(),
            allow_ips: s.allow_ips.clone(),
            block_ips: s.block_ips.clone(),
            allowed_ports: s.network.allowed_ports.clone(),
            direct_egress_denied: s.proxy.direct_egress_denied(),
            relay_input_ports: s.relay_input_ports(),
            https: relay.map(|r| r.https_targets.clone()).unwrap_or_default(),
            allow_domains: s.allow_domains.clone(),
            handlers: s
                .domain_handlers
                .iter()
                .map(|(d, h)| (d.clone(), h.handler))
                .collect(),
            proxy_allow: s.proxy_allow_domains(),
            proxy_denied: s.proxy_denied_domains(),
        }
    }

    /// The handler for exactly this name (`DNSServer._handler_for`).
    fn handler_for(&self, name: &str) -> Option<Handler> {
        let n = py::lower(name);
        let n = py::rstrip_dots(&n);
        self.handlers.iter().find(|(d, _)| d == n).map(|(_, h)| *h)
    }

    /// Whether the relay answers for `name`: its real address never enters the allow ipset (S2).
    /// The one question the three places in the Python gateway ask (`dns_server.py:847`,
    /// `:960-966`, `orchestrator.py:927`).
    pub fn is_relayed(&self, name: &str) -> bool {
        self.handler_for(name).is_some_and(Handler::is_relayed)
    }

    /// What DNS does with a query for `name`. `from_gateway` is a query the gateway sent itself
    /// (the relay resolving its upstream): a relayed name is resolved for real then, and kept out
    /// of the ipset.
    ///
    /// Two steps are the caller's, because they depend on the running gateway and not on the
    /// config: the gateway's own hostname is answered between [`Decision::Ignore`] and the rest,
    /// and [`Decision::AnswerGateway`] needs the gateway's address — without one, DNS asks again
    /// with `from_gateway: true` (`dns_server.py:734-742`).
    pub fn decide(&self, name: &str, from_gateway: bool) -> Decision {
        let name = py::rstrip_dots(name);
        if domain_matches(name, &self.block) {
            return Decision::Block;
        }
        if domain_matches(name, &self.ignore) {
            return Decision::Ignore;
        }
        match self.handler_for(name) {
            Some(Handler::Deny) => return Decision::Deny,
            Some(h) if h.is_relayed() && !from_gateway => return Decision::AnswerGateway,
            _ => {}
        }
        if !domain_matches(name, &self.allow_domains) {
            return Decision::NotAllowed;
        }
        Decision::Resolve {
            admit: !self.is_relayed(name) && !self.direct_egress_denied,
        }
    }

    /// The names resolved into the ipsets at start-up: the `allow_domains` entries that do not
    /// start with `.` and that the relay does not answer for, in file order. None at all with
    /// `direct_egress: deny`. (`*.x` is not skipped, as today.)
    pub fn seed_candidates(&self) -> Vec<String> {
        if self.direct_egress_denied {
            return Vec::new();
        }
        let relayed: Vec<String> = self
            .handlers
            .iter()
            .filter(|(_, h)| h.is_relayed())
            .map(|(d, _)| py::rstrip_dots(&py::lower(d)).to_string())
            .collect();
        self.allow_domains
            .iter()
            .filter(|d| !d.starts_with('.'))
            .filter(|d| !relayed.iter().any(|r| *r == py::rstrip_dots(&py::lower(d))))
            .cloned()
            .collect()
    }

    /// The names of Squid's `allowed_domains` ACL: `allow_domains` minus the names another
    /// component owns, `*.x` written `.x`, repeats dropped and names a wildcard covers left out
    /// (Squid refuses to start on both).
    pub fn squid_allow(&self) -> Vec<String> {
        let normalized: Vec<&str> = self
            .proxy_allow
            .iter()
            .map(|d| {
                if d.starts_with("*.") {
                    &d[1..]
                } else {
                    d.as_str()
                }
            })
            .collect();
        let covered: Vec<&str> = normalized
            .iter()
            .filter(|n| n.starts_with('.'))
            .map(|n| n.trim_start_matches('.'))
            .collect();
        let mut seen: Vec<&str> = Vec::new();
        let mut out = Vec::new();
        for name in normalized {
            if seen.contains(&name) {
                continue;
            }
            if !name.starts_with('.') {
                // walk up the parents: x.y.z, y.z, z
                let mut parent = name;
                let mut is_covered = false;
                while !parent.is_empty() {
                    if covered.contains(&parent) {
                        is_covered = true;
                        break;
                    }
                    parent = parent.split_once('.').map(|(_, rest)| rest).unwrap_or("");
                }
                if is_covered {
                    continue;
                }
            }
            seen.push(name);
            out.push(name.to_string());
        }
        out
    }

    /// The names of Squid's `relayed_domains` ACL, denied ahead of the allow rule: the github,
    /// https-relay and deny handlers, sorted.
    pub fn squid_deny(&self) -> Vec<String> {
        let mut out = self.proxy_denied.clone();
        out.sort();
        out
    }

    /// The relay's 443 passthrough targets: each git-relay upstream, then each https-relay name,
    /// with its cap. Empty when the relay's own reading does not resolve (no git-relay, no
    /// `relay:` section, or a value it refuses).
    pub fn https_targets(&self) -> &[HttpsTarget] {
        &self.https
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(text: &str) -> Rules {
        let s = super::super::parse(text, &|_| None).unwrap();
        Rules::build(&s, None)
    }

    #[test]
    fn patterns_read_entries_like_domain_matches() {
        assert_eq!(
            Pattern::of(".GitHub.com."),
            Pattern::Suffix("github.com".into())
        );
        assert_eq!(Pattern::of("*.x.com"), Pattern::Suffix("x.com".into()));
        assert_eq!(Pattern::of("*x.com"), Pattern::Exact("x.com".into()));
        assert_eq!(Pattern::of("."), Pattern::Nothing);
        assert_eq!(Pattern::of(" a.com "), Pattern::Exact("a.com".into()));
        // rstrip(".") runs before strip(), so a dot before a space stays
        assert_eq!(Pattern::of("a.com. "), Pattern::Exact("a.com.".into()));
        let p = Pattern::of(".github.com");
        assert!(p.matches_normalized("github.com"));
        assert!(p.matches_normalized("api.github.com"));
        assert!(!p.matches_normalized("evilgithub.com"));
    }

    #[test]
    fn decide_follows_the_dns_order() {
        let r = rules(
            "allow_domains: [.example.com, github.com, api.github.com]\nblock_domains: [bad.example.com]\nignore_domains: [noise.example.com]\ndomain_handlers:\n  github.com: {handler: github}\n  api.github.com: {handler: https-relay}\n  t.example.com: {handler: deny}\n",
        );
        assert_eq!(r.decide("bad.example.com", false), Decision::Block);
        assert_eq!(r.decide("noise.example.com.", false), Decision::Ignore);
        // a handler is stronger than the allow list
        assert_eq!(r.decide("t.example.com", false), Decision::Deny);
        assert_eq!(r.decide("GitHub.com", false), Decision::AnswerGateway);
        assert_eq!(
            r.decide("github.com", true),
            Decision::Resolve { admit: false }
        );
        assert_eq!(
            r.decide("www.example.com", false),
            Decision::Resolve { admit: true }
        );
        assert_eq!(r.decide("example.org", false), Decision::NotAllowed);
    }

    #[test]
    fn seeds_and_squid_lists() {
        let r = rules(
            "allow_domains: [github.com, .debian.org, deb.debian.org, '*.x.com', pypi.org, pypi.org]\ndomain_handlers:\n  github.com: {handler: github}\n  t.example.com: {handler: deny}\n",
        );
        assert_eq!(
            r.seed_candidates(),
            ["deb.debian.org", "*.x.com", "pypi.org", "pypi.org"]
        );
        assert_eq!(r.squid_allow(), [".debian.org", ".x.com", "pypi.org"]);
        assert_eq!(r.squid_deny(), ["github.com", "t.example.com"]);
        assert!(r.is_relayed("github.com."));
        assert_eq!(r.names.len(), 6 + 2);
        assert_eq!(r.names[6].route, Route::Gateway);
        assert_eq!(r.names[6].cap, Cap::RelayDefault);
    }
}
