//! The rules `cargo test` holds the repository to. Each returns what it found wrong, so the tests
//! can run it on the repository and on inputs broken on purpose.

pub mod changelog;
pub mod paths;
pub mod pins;
pub mod upgrading;
