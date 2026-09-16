//! sekimore-relay — AI エージェントの git / GitHub API 操作を案件単位のポリシーで中継する関所。
//!
//! モジュール構成は `doc/sekimore-gw/design/relay.md` を参照。

pub mod api;
pub mod audit;
pub mod cli;
pub mod config;
pub mod fsutil;
pub mod git;
pub mod github;
pub mod i18n;
pub mod netutil;
pub mod passthrough;
pub mod pktline;
pub mod policy;
pub mod ssh;
pub mod tokens;
