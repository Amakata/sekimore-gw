//! The repository's own tools and checks (Issue #506), none of which is the gateway.
//!
//! - `lang-plan` (`plan`): which language images the `lang-images.yml` workflow builds
//! - `paths` (`ledger`): questions to the path ledger, `docs/paths.yml`, and a Graphviz drawing
//! - `checks`: the rules `cargo test` holds the repository to — the changelog's shape, the path
//!   ledger against the code, the supply-chain pins, and the UPGRADING marker. The tests under
//!   `tests/` run them on the repository and on broken inputs.
//!
//! A crate of its own: the gateway image copies `relay/` only and `sgw` is built from `relay/`,
//! so nothing here ships, and the relay's build never compiles it.

pub mod checks;
pub mod ledger;
pub mod plan;
pub mod pyfmt;

use std::path::PathBuf;

/// The repository root: the parent of this crate.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tools/ has a parent")
        .to_path_buf()
}
