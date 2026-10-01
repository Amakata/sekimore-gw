//! Forge relays (#50, #328): what the relay knows about one kind of forge — GitHub today, GitLab or
//! an SSH-only git server later — behind one interface the gateway calls.
//!
//! The split is where the policy proof is in hand. Before it is the gateway: argument checks, the
//! scope, `Project::authorize`. After it is the forge relay: the upstream calls and the shaping of
//! their answer. A relay never decides a permission; it is handed [`Grant`]s, which only the
//! gateway can make, and only out of an `Authorized` / `GitAuthorized`.
//!
//! Some decisions need an upstream answer first — is this number a pull request, is this release
//! a draft, which node id is board 2. Those are [`Query`]s: the gateway asks, the relay answers,
//! the gateway decides.
//!
//! A relay runs **built in** (this crate, called in process) or, from #329, as a **sidecar** over a
//! Unix socket with the same requests as JSON. The git path and the operator's commands always use
//! the built-in one, so a push does not depend on a sidecar being up.

pub mod github;
pub mod sidecar;

use std::collections::HashMap;
use std::sync::Arc;

use crate::api::types::{ApiRequest, ApiResponse};
use crate::api::ApiError;
use crate::policy::{Action, Authorized, Denied, GitAuthorized, Resource};

/// What a relay may do for one call: the repository and the permission the gateway checked.
///
/// The relay-side counterpart of `Authorized`. It carries no reference into the policy, so it can
/// cross a process boundary; what it keeps is that nothing outside this module can make one. A
/// relay gets them from the gateway and cannot mint its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    repo: String,
    kind: GrantKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantKind {
    Api(Resource, Action),
    /// A push or fetch the git path already authorized: enough to ask the upstream about this
    /// repository's commits and default branch, and nothing else
    Git,
}

impl Grant {
    fn api(auth: &Authorized<'_>) -> Self {
        Grant {
            repo: auth.repo().to_string(),
            kind: GrantKind::Api(auth.resource(), auth.action()),
        }
    }

    /// A grant straight from a proof, for unit tests of the upstream client
    #[cfg(test)]
    pub(crate) fn for_test(auth: &Authorized<'_>) -> Self {
        Grant::api(auth)
    }

    fn git(auth: &GitAuthorized<'_>) -> Self {
        Grant {
            repo: auth.repo().to_string(),
            kind: GrantKind::Git,
        }
    }

    pub fn repo(&self) -> &str {
        &self.repo
    }

    /// Lets the upstream caller confirm it got the right kind of grant, stopping a programming
    /// mistake such as calling `pr:merge` with a `pr:create` grant at runtime.
    pub fn ensure(&self, resource: Resource, action: Action) -> Result<(), Denied> {
        self.ensure_any(&[(resource, action)])
    }

    /// As `ensure`, for a write where the resource depends on what the number turned out to name
    /// (see `numbered_write_scope`).
    pub fn ensure_any(&self, allowed: &[(Resource, Action)]) -> Result<(), Denied> {
        if let GrantKind::Api(r, a) = self.kind {
            if allowed.iter().any(|(rr, aa)| *rr == r && *aa == a) {
                return Ok(());
            }
        }
        let (resource, action) = allowed[0];
        Err(Denied::NotPermitted {
            resource: resource.as_str(),
            action: action.as_str(),
        })
    }

    /// For the reads the git path makes about a repository it is already pushing to or fetching.
    pub fn ensure_git(&self) -> Result<(), Denied> {
        match self.kind {
            GrantKind::Git => Ok(()),
            GrantKind::Api(..) => Err(Denied::NotPermitted {
                resource: "git",
                action: "read",
            }),
        }
    }

    /// Whether this grant is for `resource:action` — for an operation that takes an optional
    /// second grant (labels on `issue create`).
    pub fn is(&self, resource: Resource, action: Action) -> bool {
        self.kind == GrantKind::Api(resource, action)
    }
}

/// What the gateway found out before the call, and the relay is to use rather than look up again.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Resolved {
    /// The board's node id, from the declared board the request named
    pub board_id: String,
    /// The release `release edit` changes, and whether this edit publishes it
    pub release_id: u64,
    pub publishing: bool,
    /// The project's repositories (`Org/Repo`), which a search is scoped to and filtered back to
    pub repos: Vec<String>,
}

/// A question the gateway asks before it can decide.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "query", rename_all = "snake_case")]
pub enum Query {
    /// Is this number a pull request? GitHub serves both from the issues endpoints
    NamesAPullRequest { number: u64 },
    /// The release for a tag, drafts included, for `release edit`
    ReleaseForEdit { tag: String },
    /// A declared board's node id
    BoardId {
        org: Option<String>,
        user: Option<String>,
        number: u32,
    },
    /// The repository's default branch (`refs/pr/` opens against it)
    DefaultBranch,
    /// Whether the upstream has this commit
    CommitExists { sha: String },
    /// Whether `base` is an ancestor of `head` (or the same commit) on the upstream
    IsAncestor { base: String, head: String },
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer {
    Bool(bool),
    Release(Option<ReleaseRef>),
    Id(String),
    Branch(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReleaseRef {
    pub id: u64,
    pub draft: bool,
}

/// A pull request the git path opened for a `refs/for/` / `refs/pr/` push, or found already open.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OpenedPr {
    pub number: u64,
    pub url: String,
    pub existed: bool,
}

#[derive(Debug)]
pub enum OpenPrError {
    /// The upstream refused and no open pull request matches; the reason, for the push's output
    NotOpened(String),
    /// Creating it failed
    CreateFailed(ApiError),
    /// It may exist (the upstream said so), but looking for it failed
    LookupFailed(ApiError),
}

/// One kind of forge.
#[async_trait::async_trait]
pub trait ForgeRelay: Send + Sync {
    /// An agent-facing operation (`/pr/merge`, …). The gateway has authorized it; `grants` are what
    /// it authorized, the first one the operation's own.
    async fn call(
        &self,
        op: &str,
        grants: &[Grant],
        req: &ApiRequest,
        resolved: &Resolved,
    ) -> Result<ApiResponse, ApiError>;

    /// A question the gateway needs answered before it decides. `None` for one that is about the
    /// project's configuration rather than a repository (a board id).
    async fn query(&self, query: &Query, grant: Option<&Grant>) -> Result<Answer, ApiError>;

    /// Open a pull request for a push, or find the one already open for that head and base.
    async fn open_pr(
        &self,
        grant: &Grant,
        head: &str,
        base: &str,
        title: &str,
        body: &str,
    ) -> Result<OpenedPr, OpenPrError>;
}

/// The relay for each upstream (keyed by git-relay domain, as the GitHub clients were).
#[derive(Clone, Default)]
pub struct Relays {
    by_upstream: HashMap<String, Arc<dyn ForgeRelay>>,
}

impl Relays {
    pub fn new() -> Self {
        Relays::default()
    }

    pub fn insert(&mut self, upstream: impl Into<String>, relay: Arc<dyn ForgeRelay>) {
        self.by_upstream.insert(upstream.into(), relay);
    }

    pub fn get(&self, upstream: &str) -> Option<Handle<'_>> {
        self.by_upstream
            .get(upstream)
            .map(|r| Handle { relay: r.as_ref() })
    }

    pub fn is_empty(&self) -> bool {
        self.by_upstream.is_empty()
    }
}

impl<const N: usize> From<[(String, Arc<dyn ForgeRelay>); N]> for Relays {
    fn from(pairs: [(String, Arc<dyn ForgeRelay>); N]) -> Self {
        Relays {
            by_upstream: HashMap::from(pairs),
        }
    }
}

/// The gateway's side of a relay. Every method takes the policy's own proof and turns it into the
/// grant here, so no caller outside this module ever handles one.
#[derive(Clone, Copy)]
pub struct Handle<'a> {
    relay: &'a dyn ForgeRelay,
}

impl<'a> Handle<'a> {
    /// A built-in relay held on its own (the git path keeps one per upstream).
    pub fn of(relay: &'a dyn ForgeRelay) -> Self {
        Handle { relay }
    }

    pub async fn call(
        &self,
        op: &str,
        auths: &[&Authorized<'_>],
        req: &ApiRequest,
        resolved: &Resolved,
    ) -> Result<ApiResponse, ApiError> {
        let grants: Vec<Grant> = auths.iter().map(|a| Grant::api(a)).collect();
        self.relay.call(op, &grants, req, resolved).await
    }

    pub async fn ask(&self, query: &Query, auth: &Authorized<'_>) -> Result<Answer, ApiError> {
        self.relay.query(query, Some(&Grant::api(auth))).await
    }

    pub async fn ask_git(
        &self,
        query: &Query,
        auth: &GitAuthorized<'_>,
    ) -> Result<Answer, ApiError> {
        self.relay.query(query, Some(&Grant::git(auth))).await
    }

    /// A question about the project's configuration, which no repository's permission covers.
    pub async fn ask_unscoped(&self, query: &Query) -> Result<Answer, ApiError> {
        self.relay.query(query, None).await
    }

    pub async fn open_pr(
        &self,
        auth: &Authorized<'_>,
        head: &str,
        base: &str,
        title: &str,
        body: &str,
    ) -> Result<OpenedPr, OpenPrError> {
        self.relay
            .open_pr(&Grant::api(auth), head, base, title, body)
            .await
    }
}

/// An answer of the wrong kind: a relay bug, reported rather than guessed around.
pub fn unexpected(query: &Query, answer: &Answer) -> ApiError {
    ApiError {
        status: hyper::StatusCode::BAD_GATEWAY,
        message: format!("the forge relay answered {query:?} with {answer:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(kind: GrantKind) -> Grant {
        Grant {
            repo: "Org/Repo".into(),
            kind,
        }
    }

    #[test]
    fn a_grant_admits_only_what_was_authorized() {
        let g = grant(GrantKind::Api(Resource::Pr, Action::Create));
        assert!(g.ensure(Resource::Pr, Action::Create).is_ok());
        assert!(g.ensure(Resource::Pr, Action::Merge).is_err());
        assert!(g.ensure(Resource::Issue, Action::Create).is_err());
        assert!(g
            .ensure_any(&[
                (Resource::Issue, Action::Close),
                (Resource::Pr, Action::Create)
            ])
            .is_ok());
        assert!(g.ensure_git().is_err());
    }

    #[test]
    fn a_git_grant_reads_commits_and_nothing_else() {
        let g = grant(GrantKind::Git);
        assert!(g.ensure_git().is_ok());
        assert!(g.ensure(Resource::Pr, Action::Read).is_err());
        assert!(g.ensure_any(&[(Resource::Repo, Action::Read)]).is_err());
    }
}
