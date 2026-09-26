//! `sgw`, the operator's tool on the host (#234).
//!
//! One binary replaces `sgw.sh`, `upgrade.sh`, `vscode.sh` and the mise task files that used to be
//! distributed into a project. It runs on the Mac / Linux host that runs Docker, finds the
//! project's compose stack by its labels, and reaches the gateway's `sekimore-relay` with
//! `docker exec`, owning the terminal decision itself (which is what #230 was about).
//!
//! Stage 1 of the design (doc: design/sgw-host.md): the skeleton, the operations, the terminal.
//! `verify`, `init` and `update` follow in their own pull requests.

pub mod cli;
pub mod docker;
pub mod open;
pub mod ops;
pub mod passphrase;
pub mod project;
pub mod target;
pub mod templates;
pub mod update;
pub mod verify;
