//! UPGRADING has to have been looked at for the gateway the base image takes.
//!
//! Most releases ask nothing of a user, so "there is a section per version" would be the wrong
//! check — it would force an empty entry for every quiet release and teach people to write
//! filler. What has to happen every time is the *decision*: does this release make someone edit a
//! file they own? The marker records that the decision was made, and this fails when it has not
//! been.
//!
//! It went wrong without one. The published sample went four releases without `gw:unlock`, and
//! from gateway 0.2.19 that leaves a user unable to reach the GitHub API and unable to add a task
//! that works — because `sgw.sh` is missing `gw-tty` too.

use std::cmp::Ordering;
use std::sync::LazyLock;

use regex::Regex;

use super::changelog::semver_cmp;

/// UPGRADING sits at the repository root since the move into sekimore-gw (#235).
pub const FILES: [&str; 2] = ["UPGRADING.md", "UPGRADING.ja.md"];
/// The base image's Dockerfile, which names the gateway image it takes.
pub const DOCKERFILE: &str = "base/Dockerfile";

static MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^<!-- reviewed-up-to: (\d+(?:\.\d+)*(?:-[0-9A-Za-z.-]+)?) -->").expect("regex")
});
static PINNED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^ARG SEKIMORE_GW_IMAGE=\S+:(\d+(?:\.\d+)*(?:-[0-9A-Za-z.-]+)?)[ \t]*$")
        .expect("regex")
});

/// The gateway version the base Dockerfile takes.
pub fn pinned(dockerfile: &str) -> Result<String, String> {
    PINNED
        .captures(dockerfile)
        .map(|m| m[1].to_string())
        .ok_or_else(|| "no ARG SEKIMORE_GW_IMAGE=<image>:<version> in base/Dockerfile".into())
}

/// What is wrong with one UPGRADING file, given the version the image takes.
pub fn marker_problem(name: &str, text: &str, pinned: &str) -> Option<String> {
    let first = text.lines().next().unwrap_or("");
    let Some(m) = MARKER.captures(first) else {
        return Some(format!(
            "{name} must start with `<!-- reviewed-up-to: X.Y.Z -->`"
        ));
    };
    let reviewed = &m[1];
    (semver_cmp(reviewed, pinned) == Ordering::Less).then(|| {
        format!(
            "{name} was reviewed up to {reviewed}, but this image takes gateway {pinned}.\n\
             Read what changed between them. If a release makes someone edit a file they own\n\
             (config.yml / mise.toml / sgw.sh / docker-compose.yml), add a section. If none \
             does,\njust move the marker to {pinned} — that is the point of it."
        )
    })
}
