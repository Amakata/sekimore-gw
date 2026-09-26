//! sekimore-relay — a relay that mediates an AI agent's git / GitHub API operations under per-project policy.
//!
//! See `relay/README.md` for the module layout.

pub mod api;
pub mod audit;
pub mod cli;
pub mod config;
pub mod fsutil;
pub mod git;
pub mod github;
#[cfg(feature = "host")]
pub mod host;
pub mod i18n;
pub mod netutil;
pub mod passthrough;
pub mod paths;
pub mod pktline;
pub mod policy;
pub mod proxy_credential;
pub mod ssh;
pub mod store;
pub mod tokens;
