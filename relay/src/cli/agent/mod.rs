//! Agent-side CLI. It just calls the relay's plain endpoints (gh compatibility is not a goal).
//!
//! All the agent holds is a project token (a string that is worthless against the upstream).
//!
//! 0.2.4: help text is looked up at runtime from `relay/locales/*.json` (see `crate::i18n`).
//!
//! Split three ways along what each part has to know: `cmd` is the shape of the CLI, `dispatch`
//! maps a parsed subcommand onto an endpoint, and `print` renders an answer. `client` is the one
//! piece that touches the network.

pub mod client;
pub mod cmd;
pub mod dispatch;
pub mod print;
pub mod standalone;

/// What the agent's own lines on stderr start with. `sgw-agent` from 0.2.50 (#257); the
/// `sekimore` alias prints the same, so an agent that reads either name learns the new one.
pub const NAME: &str = "sgw-agent";

pub use client::{AgentClient, DEFAULT_ENDPOINT};
pub use cmd::AgentCmd;
pub use dispatch::{guide_for, run, AGENT_GUIDE_EN, AGENT_GUIDE_JA};
pub use print::print_response;
