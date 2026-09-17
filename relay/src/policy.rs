//! Project policy.
//!
//! This module is the main reason the relay is written in Rust.
//!
//! In the Go version nothing stopped you from ignoring the return value of `FindRepo` and calling
//! upstream anyway. A missing check could not be caught by the type system, so it had to be caught by
//! review and tests instead - too weak when **the relay carries the whole responsibility for access
//! control**.
//!
//! In Rust "already checked" can be a type:
//!   - Functions that call upstream only accept `Authorized<'_>` (API) or `GitAuthorized<'_>` (git)
//!   - Those are only constructed by passing the policy check
//!   - So **forgetting the check does not compile**

use std::collections::HashSet;
use std::fmt;

// ---- resources x actions ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resource {
    Pr,
    Issue,
    Project,
    Repo,
    Ci,
    /// 0.2.6: GitHub releases
    Release,
    /// 0.2.7: searching across repositories. Its own resource because a search is not scoped to one
    /// repository the way every other operation is; results are filtered back to the project
    Search,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Create,
    Comment,
    Review,
    Merge,
    Close,
    Label,
    Assign,
    Read,
    AddItem,
    UpdateItem,
    /// 0.2.7: ask someone to review a pull request. Separate from `Review`, which submits one
    RequestReview,
    /// 0.2.9: take a release out of draft. Separate from `Create`, because `--draft` exists exactly
    /// to leave publishing to a human; folding it into `create` would erase that boundary
    Publish,
    /// 0.2.9: re-run or cancel a workflow run. Separate from `Read`, because re-running spends
    /// Actions minutes and runs workflow code with the repository's secrets
    Rerun,
}

impl Resource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Resource::Pr => "pr",
            Resource::Issue => "issue",
            Resource::Project => "project",
            Resource::Repo => "repo",
            Resource::Ci => "ci",
            Resource::Release => "release",
            Resource::Search => "search",
        }
    }
    /// The actions that exist for this resource. Used to reject typos in the config.
    pub fn valid_actions(&self) -> &'static [Action] {
        use Action::*;
        match self {
            Resource::Pr => &[Create, Comment, Review, Merge, Close, Read, RequestReview],
            Resource::Issue => &[Create, Comment, Close, Label, Assign, Read],
            Resource::Project => &[Read, AddItem, UpdateItem],
            Resource::Repo => &[Read],
            Resource::Ci => &[Read, Rerun],
            Resource::Release => &[Create, Read, Publish],
            Resource::Search => &[Read],
        }
    }
    pub const ALL: [Resource; 7] = [
        Resource::Pr,
        Resource::Issue,
        Resource::Project,
        Resource::Repo,
        Resource::Ci,
        Resource::Release,
        Resource::Search,
    ];
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Comment => "comment",
            Action::Review => "review",
            Action::Merge => "merge",
            Action::Close => "close",
            Action::Label => "label",
            Action::Assign => "assign",
            Action::Read => "read",
            Action::AddItem => "add_item",
            Action::UpdateItem => "update_item",
            Action::RequestReview => "request_review",
            Action::Publish => "publish",
            Action::Rerun => "rerun",
        }
    }
}

/// Parses the "pr:create" form. The Go version used bare string keys, so a combination that does not
/// exist, such as "pr:delete", was silently accepted.
pub fn parse_permission(s: &str) -> Result<(Resource, Action), String> {
    let (r, a) = s
        .split_once(':')
        .ok_or_else(|| format!("{s:?}: must be resource:action"))?;
    let resource = match r.trim() {
        "pr" => Resource::Pr,
        "issue" => Resource::Issue,
        "project" => Resource::Project,
        "repo" => Resource::Repo,
        "ci" => Resource::Ci,
        "release" => Resource::Release,
        "search" => Resource::Search,
        other => {
            return Err(format!(
                "unknown resource {other:?} (known: ci, issue, pr, project, release, repo, search)"
            ))
        }
    };
    let action = match a.trim() {
        "create" => Action::Create,
        "comment" => Action::Comment,
        "review" => Action::Review,
        "merge" => Action::Merge,
        "close" => Action::Close,
        "label" => Action::Label,
        "assign" => Action::Assign,
        "read" => Action::Read,
        "add_item" => Action::AddItem,
        "update_item" => Action::UpdateItem,
        "request_review" => Action::RequestReview,
        "publish" => Action::Publish,
        "rerun" => Action::Rerun,
        other => return Err(format!("unknown action {other:?}")),
    };
    if !resource.valid_actions().contains(&action) {
        return Err(format!(
            "{}:{} is not a valid combination",
            resource.as_str(),
            action.as_str()
        ));
    }
    Ok((resource, action))
}

/// Every valid "resource:action", for listings.
pub fn all_permission_keys() -> Vec<String> {
    let mut v = Vec::new();
    for r in Resource::ALL {
        for a in r.valid_actions() {
            v.push(format!("{}:{}", r.as_str(), a.as_str()));
        }
    }
    v.sort();
    v
}

// ---- git verbs ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitVerb {
    UploadPack,
    ReceivePack,
}

impl GitVerb {
    pub fn as_str(&self) -> &'static str {
        match self {
            GitVerb::UploadPack => "git-upload-pack",
            GitVerb::ReceivePack => "git-receive-pack",
        }
    }
    /// The `git <subcommand>` form, used by the local upstream in tests.
    pub fn as_subcommand(&self) -> &'static str {
        match self {
            GitVerb::UploadPack => "upload-pack",
            GitVerb::ReceivePack => "receive-pack",
        }
    }
    pub fn is_write(&self) -> bool {
        matches!(self, GitVerb::ReceivePack)
    }
}

// ---- repositories and projects ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    ReadOnly,
    ReadWrite,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::ReadOnly => "read-only",
            Mode::ReadWrite => "read-write",
        }
    }
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim() {
            "read-only" => Ok(Mode::ReadOnly),
            "read-write" => Ok(Mode::ReadWrite),
            other => Err(format!("unknown mode {other:?} (read-only | read-write)")),
        }
    }
}

/// Branch globs that direct pushes are allowed to by default: the agent's own namespace.
pub const DEFAULT_PUSH_GLOBS: &[&str] = &["sekimore/*"];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RepoPolicy {
    pub full_name: String,
    /// 0.2.0: which upstream (git-relay domain) this repository lives on. Empty = the project's default upstream
    pub host: String,
    pub mode: Mode,
    /// Branches allowed as the base of a PR. Empty = any
    pub bases: Vec<String>,
    /// Branch globs that direct pushes are allowed to, matched against the name with `refs/heads/` stripped
    pub push: Vec<String>,
    /// Tag globs that pushes are allowed to, matched against the name with `refs/tags/` stripped. Empty = denied
    pub tags: Vec<String>,
    /// Whether deleting branches and tags is allowed
    pub delete: bool,
    /// 0.2.9: delete the head branch once `pr merge` succeeds. Only the branch just merged, which
    /// is why it is not the same authority as `delete`
    pub delete_merged_branch: bool,
    /// Delta on top of the project defaults: permissions to add, and permissions to remove (a deny wins at any layer)
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

impl RepoPolicy {
    pub fn new(full_name: &str, mode: Mode) -> Self {
        RepoPolicy {
            full_name: full_name.to_string(),
            host: String::new(),
            mode,
            bases: Vec::new(),
            push: DEFAULT_PUSH_GLOBS.iter().map(|s| s.to_string()).collect(),
            tags: Vec::new(),
            delete: false,
            delete_merged_branch: false,
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
    /// Whether pushing `refs/tags/<tag>` is allowed.
    pub fn allows_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|g| glob_match(g, tag))
    }
    pub fn allows_base(&self, branch: &str) -> bool {
        self.bases.is_empty() || self.bases.iter().any(|b| b == branch)
    }
    /// Whether a direct push to `refs/heads/<branch>` is allowed.
    pub fn allows_push(&self, branch: &str) -> bool {
        self.push.iter().any(|g| glob_match(g, branch))
    }
    pub fn can_write(&self) -> bool {
        self.mode == Mode::ReadWrite
    }
}

/// Minimal glob: `*` matches any sequence, `/` included, and `?` matches one character. Everything else is literal.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    fn rec(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => rec(&p[1..], t) || (!t.is_empty() && rec(p, &t[1..])),
            (Some(b'?'), Some(_)) => rec(&p[1..], &t[1..]),
            (Some(a), Some(b)) if a == b => rec(&p[1..], &t[1..]),
            _ => false,
        }
    }
    rec(pattern.as_bytes(), text.as_bytes())
}

/// The unit of isolation: a project.
#[derive(Debug, Clone)]
pub struct Project {
    pub name: String,
    pub repos: Vec<RepoPolicy>,
    /// Permissions the project allows by default
    perms: HashSet<(Resource, Action)>,
    /// Permissions the project denies by default; these beat a repo's allow
    denies: HashSet<(Resource, Action)>,
    /// 0.2.0: the upstream domain a repo without a `host`, or a bare `Org/Repo`, refers to. Empty means there is only one upstream
    default_host: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Denied {
    /// Repository is not part of the project
    RepoNotInProject { repo: String, project: String },
    /// Write to a read-only repository
    RepoReadOnly { repo: String, project: String },
    /// Base branch is not allowed
    BaseNotAllowed { branch: String },
    /// Operation is not allowed by policy (denied by default)
    NotPermitted {
        resource: &'static str,
        action: &'static str,
    },
    /// Anything other than git-upload-pack / git-receive-pack
    UnsupportedCommand { cmdline: String },
    /// Ref rejected by the namespace or branch restrictions
    RefNotAllowed { name: String, reason: &'static str },
    /// Deletion is denied by default
    DeleteNotAllowed { name: String },
    /// Not a valid ref name
    InvalidRef { name: String, reason: &'static str },
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denied::RepoNotInProject { repo, project } => {
                write!(f, "repository {repo:?} is not in project {project:?}")
            }
            Denied::RepoReadOnly { repo, project } => {
                write!(f, "{repo} is read-only in project {project}")
            }
            Denied::BaseNotAllowed { branch } => write!(f, "base branch {branch} is not allowed"),
            Denied::NotPermitted { resource, action } => {
                write!(f, "{resource}:{action} is not allowed by policy")
            }
            Denied::UnsupportedCommand { cmdline } => write!(f, "unsupported command: {cmdline}"),
            Denied::RefNotAllowed { name, reason } => {
                write!(f, "push to {name} is not allowed: {reason}")
            }
            Denied::DeleteNotAllowed { name } => {
                write!(
                    f,
                    "deleting {name} is not allowed (relay.allow_delete is false)"
                )
            }
            Denied::InvalidRef { name, reason } => write!(f, "invalid ref {name:?}: {reason}"),
        }
    }
}

impl std::error::Error for Denied {}

impl Denied {
    /// Short kind for the audit log.
    pub fn kind(&self) -> &'static str {
        match self {
            Denied::RepoNotInProject { .. } => "repo_not_in_project",
            Denied::RepoReadOnly { .. } => "repo_read_only",
            Denied::BaseNotAllowed { .. } => "base_not_allowed",
            Denied::NotPermitted { .. } => "not_permitted",
            Denied::UnsupportedCommand { .. } => "unsupported_command",
            Denied::RefNotAllowed { .. } => "ref_not_allowed",
            Denied::DeleteNotAllowed { .. } => "delete_not_allowed",
            Denied::InvalidRef { .. } => "invalid_ref",
        }
    }
}

/// **Proof that an API operation passed the policy check.**
///
/// This lifetime-bound type can only be constructed by `Project::authorize`. Functions that call the
/// upstream API demand one, so a missing check is a compile error.
#[derive(Debug, PartialEq)]
pub struct Authorized<'p> {
    repo: &'p RepoPolicy,
    resource: Resource,
    action: Action,
    project: &'p str,
}

impl<'p> Authorized<'p> {
    pub fn repo(&self) -> &'p str {
        &self.repo.full_name
    }
    pub fn project(&self) -> &'p str {
        self.project
    }
    pub fn policy(&self) -> &'p RepoPolicy {
        self.repo
    }
    /// For the audit log: what exactly was allowed.
    pub fn permission(&self) -> (&'static str, &'static str) {
        (self.resource.as_str(), self.action.as_str())
    }
    /// Lets the upstream caller confirm it got the right kind of proof, stopping a programming mistake
    /// such as calling `pr:merge` with a `pr:create` proof at runtime.
    pub fn ensure(&self, resource: Resource, action: Action) -> Result<(), Denied> {
        if self.resource == resource && self.action == action {
            Ok(())
        } else {
            Err(Denied::NotPermitted {
                resource: resource.as_str(),
                action: action.as_str(),
            })
        }
    }
}

/// **Proof that a git operation passed the policy check.** Only `Project::authorize_git` can construct one.
#[derive(Debug, PartialEq)]
pub struct GitAuthorized<'p> {
    repo: &'p RepoPolicy,
    verb: GitVerb,
    project: &'p str,
}

impl<'p> GitAuthorized<'p> {
    pub fn repo(&self) -> &'p str {
        &self.repo.full_name
    }
    pub fn project(&self) -> &'p str {
        self.project
    }
    pub fn verb(&self) -> GitVerb {
        self.verb
    }
    pub fn policy(&self) -> &'p RepoPolicy {
        self.repo
    }
}

impl Project {
    pub fn new(name: impl Into<String>) -> Self {
        Project {
            name: name.into(),
            repos: Vec::new(),
            perms: HashSet::new(),
            denies: HashSet::new(),
            default_host: String::new(),
        }
    }

    /// 0.2.0: the domain of the default upstream. A repo with an empty `host` is treated as living there.
    pub fn set_default_host(&mut self, host: &str) {
        self.default_host = host.trim().to_ascii_lowercase();
    }
    /// A repo's effective host, falling back to the default upstream when empty.
    pub fn host_of<'a>(&'a self, repo: &'a RepoPolicy) -> &'a str {
        if repo.host.is_empty() {
            &self.default_host
        } else {
            &repo.host
        }
    }

    /// Builds a project from the config. A typo in a permission name is rejected here.
    pub fn try_new(
        name: impl Into<String>,
        repos: Vec<RepoPolicy>,
        permissions: &[String],
    ) -> Result<Self, String> {
        Self::try_new_rules(name, repos, permissions, &[])
    }

    /// Builds a project, validating the project-wide allow / deny and each repo's allow / deny delta.
    pub fn try_new_rules(
        name: impl Into<String>,
        repos: Vec<RepoPolicy>,
        allow: &[String],
        deny: &[String],
    ) -> Result<Self, String> {
        for r in &repos {
            for spec in r.allow.iter().chain(r.deny.iter()) {
                parse_permission(spec).map_err(|e| format!("repo {}: {e}", r.full_name))?;
            }
        }
        let mut p = Self::try_new_allow(name, repos, allow)?;
        for spec in deny {
            let (r, a) = parse_permission(spec)?;
            p.denies.insert((r, a));
        }
        Ok(p)
    }

    fn try_new_allow(
        name: impl Into<String>,
        repos: Vec<RepoPolicy>,
        permissions: &[String],
    ) -> Result<Self, String> {
        let mut p = Project::new(name);
        for r in &repos {
            if r.full_name.split('/').filter(|s| !s.is_empty()).count() != 2 {
                return Err(format!("repo {:?} must be Org/Repo", r.full_name));
            }
            if repos
                .iter()
                .filter(|o| {
                    o.full_name.eq_ignore_ascii_case(&r.full_name)
                        && o.host.eq_ignore_ascii_case(&r.host)
                })
                .count()
                > 1
            {
                return Err(format!(
                    "repo {:?} is listed more than once{}",
                    r.full_name,
                    if r.host.is_empty() {
                        String::new()
                    } else {
                        format!(" on {}", r.host)
                    }
                ));
            }
        }
        p.repos = repos;
        for spec in permissions {
            let (r, a) = parse_permission(spec)?;
            p.perms.insert((r, a));
        }
        Ok(p)
    }

    pub fn with_repo(mut self, full_name: &str, mode: Mode, bases: &[&str]) -> Self {
        let mut rp = RepoPolicy::new(full_name, mode);
        rp.bases = bases.iter().map(|s| s.to_string()).collect();
        self.repos.push(rp);
        self
    }

    pub fn grant(mut self, spec: &str) -> Self {
        let (r, a) = parse_permission(spec).expect("invalid permission spec");
        self.perms.insert((r, a));
        self
    }

    /// Whether the project defaults allow this, ignoring any per-repo delta.
    pub fn is_granted(&self, resource: Resource, action: Action) -> bool {
        self.perms.contains(&(resource, action)) && !self.denies.contains(&(resource, action))
    }

    /// Effective permissions for a repo: (project allow ∪ repo allow) − (project deny ∪ repo deny). A deny wins.
    pub fn effective(&self, repo: &RepoPolicy) -> HashSet<(Resource, Action)> {
        let mut set = self.perms.clone();
        for s in &repo.allow {
            if let Ok(k) = parse_permission(s) {
                set.insert(k);
            }
        }
        for k in &self.denies {
            set.remove(k);
        }
        for s in &repo.deny {
            if let Ok(k) = parse_permission(s) {
                set.remove(&k);
            }
        }
        set
    }

    /// The effective permissions as a list of "resource:action", for `check` and the Web UI.
    pub fn effective_keys(&self, repo: &RepoPolicy) -> Vec<String> {
        let mut v: Vec<String> = self
            .effective(repo)
            .iter()
            .map(|(r, a)| format!("{}:{}", r.as_str(), a.as_str()))
            .collect();
        v.sort();
        v
    }

    /// Whether the permission is allowed anywhere, in the project defaults or on any repo. A coarse check that
    /// keeps the response uniform for repositories outside the project.
    fn granted_anywhere(&self, resource: Resource, action: Action) -> bool {
        if self.is_granted(resource, action) {
            return true;
        }
        self.repos
            .iter()
            .any(|r| self.effective(r).contains(&(resource, action)))
    }

    /// Looks up a repository in the project. Anything else is denied - this is the only barrier that keeps
    /// requests from reaching outside the project.
    ///
    /// For the API path. `host/Org/Repo` narrows by host; a bare `Org/Repo` resolves to the single match, or,
    /// if the name exists on several upstreams, to the one on the default upstream (denied if there is none).
    /// 0.2.7: `repo:` qualifiers naming every repository in the project, for a search.
    ///
    /// A search is not scoped to one repository the way every other operation is, so the query is
    /// rewritten to name the project's repositories explicitly. That is what keeps a result from
    /// outside the project out of the answer; `filter_search_items` then drops anything that comes
    /// back anyway, because a caller can write their own `repo:` and GitHub would honour it.
    pub fn search_scope(&self) -> Vec<String> {
        self.repos
            .iter()
            .map(|r| format!("repo:{}", r.full_name))
            .collect()
    }

    /// Whether a search result belongs to this project. `full_name` is `Org/Repo` as the search
    /// API reports it.
    pub fn owns_repo(&self, full_name: &str) -> bool {
        self.repos
            .iter()
            .any(|r| r.full_name.eq_ignore_ascii_case(full_name))
    }

    pub fn find_repo(&self, path: &str) -> Result<&RepoPolicy, Denied> {
        let want = path.trim_start_matches('/').trim_end_matches(".git");
        let (host, name) = crate::config::split_repo_host(want);
        let denied = || Denied::RepoNotInProject {
            repo: want.to_string(),
            project: self.name.clone(),
        };
        if let Some(h) = host {
            return self
                .repos
                .iter()
                .find(|r| {
                    r.full_name.eq_ignore_ascii_case(name)
                        && self.host_of(r).eq_ignore_ascii_case(h)
                })
                .ok_or_else(denied);
        }
        let mut hits = self
            .repos
            .iter()
            .filter(|r| r.full_name.eq_ignore_ascii_case(name));
        let first = hits.next().ok_or_else(denied)?;
        if hits.next().is_none() {
            return Ok(first);
        }
        // the name exists on several upstreams: only the one on the default upstream can be named as a bare `Org/Repo`
        self.repos
            .iter()
            .find(|r| {
                r.full_name.eq_ignore_ascii_case(name)
                    && self.host_of(r).eq_ignore_ascii_case(&self.default_host)
            })
            .ok_or_else(denied)
    }

    /// For the SSH path (0.2.0). The listening port already fixes the upstream `host`, so only that upstream's
    /// repositories are searched. The `host/Org/Repo` form is not accepted, since the exec request carries only a path.
    pub fn find_repo_on(&self, host: &str, path: &str) -> Result<&RepoPolicy, Denied> {
        let want = path.trim_start_matches('/').trim_end_matches(".git");
        self.repos
            .iter()
            .find(|r| {
                r.full_name.eq_ignore_ascii_case(want) && self.host_of(r).eq_ignore_ascii_case(host)
            })
            .ok_or_else(|| Denied::RepoNotInProject {
                repo: want.to_string(),
                project: self.name.clone(),
            })
    }

    /// The only entry point for API operations: without going through here an `Authorized` cannot exist.
    ///
    /// Write actions are checked against read-only mode automatically.
    pub fn authorize(
        &self,
        repo: &str,
        resource: Resource,
        action: Action,
    ) -> Result<Authorized<'_>, Denied> {
        // 1. coarse default deny: even a repository outside the project fails first as "operation not allowed", leaking nothing
        if !self.granted_anywhere(resource, action) {
            return Err(Denied::NotPermitted {
                resource: resource.as_str(),
                action: action.as_str(),
            });
        }
        // 2. is the repository part of the project?
        let found = self.find_repo(repo)?;
        self.authorize_found(found, resource, action)
    }

    /// Steps 3 and 4 against a repo that has already been found; shared by `authorize` and `authorize_pr_for`.
    fn authorize_found<'p>(
        &'p self,
        found: &'p RepoPolicy,
        resource: Resource,
        action: Action,
    ) -> Result<Authorized<'p>, Denied> {
        // 3. the repo's effective permissions (project defaults + repo allow − deny; a deny wins)
        if !self.effective(found).contains(&(resource, action)) {
            return Err(Denied::NotPermitted {
                resource: resource.as_str(),
                action: action.as_str(),
            });
        }
        // 4. a write action needs read-write
        if is_write(action) && found.mode == Mode::ReadOnly {
            return Err(Denied::RepoReadOnly {
                repo: found.full_name.clone(),
                project: self.name.clone(),
            });
        }
        Ok(Authorized {
            repo: found,
            resource,
            action,
            project: &self.name,
        })
    }

    /// For operations such as creating a PR, where the base branch must be checked too.
    pub fn authorize_pr(&self, repo: &str, base: &str) -> Result<Authorized<'_>, Denied> {
        let auth = self.authorize(repo, Resource::Pr, Action::Create)?;
        if !auth.repo.allows_base(base) {
            return Err(Denied::BaseNotAllowed {
                branch: base.to_string(),
            });
        }
        Ok(auth)
    }

    /// A PR-creation proof for a repo already resolved on the git path (`GitAuthorized`), so a same-named
    /// repo on another upstream cannot be mistaken for it (0.2.0).
    pub fn authorize_pr_for<'p>(
        &'p self,
        git: &GitAuthorized<'p>,
        base: &str,
    ) -> Result<Authorized<'p>, Denied> {
        if !self.granted_anywhere(Resource::Pr, Action::Create) {
            return Err(Denied::NotPermitted {
                resource: Resource::Pr.as_str(),
                action: Action::Create.as_str(),
            });
        }
        let auth = self.authorize_found(git.repo, Resource::Pr, Action::Create)?;
        if !auth.repo.allows_base(base) {
            return Err(Denied::BaseNotAllowed {
                branch: base.to_string(),
            });
        }
        Ok(auth)
    }

    /// The only entry point for the git path; receive-pack requires read-write.
    /// For a single upstream, as in tests. With several upstreams use `authorize_git_on`.
    pub fn authorize_git(
        &self,
        verb: GitVerb,
        repo_path: &str,
    ) -> Result<GitAuthorized<'_>, Denied> {
        let found = self.find_repo(repo_path)?;
        self.authorize_git_found(found, verb)
    }

    /// The git path (0.2.0): considers only repositories on the upstream `host` fixed by the listening port.
    /// An empty `host` does not distinguish upstreams, matching `authorize_git`.
    pub fn authorize_git_on(
        &self,
        host: &str,
        verb: GitVerb,
        repo_path: &str,
    ) -> Result<GitAuthorized<'_>, Denied> {
        let found = if host.is_empty() {
            self.find_repo(repo_path)?
        } else {
            self.find_repo_on(host, repo_path)?
        };
        self.authorize_git_found(found, verb)
    }

    fn authorize_git_found<'p>(
        &'p self,
        found: &'p RepoPolicy,
        verb: GitVerb,
    ) -> Result<GitAuthorized<'p>, Denied> {
        if verb.is_write() && !found.can_write() {
            return Err(Denied::RepoReadOnly {
                repo: found.full_name.clone(),
                project: self.name.clone(),
            });
        }
        Ok(GitAuthorized {
            repo: found,
            verb,
            project: &self.name,
        })
    }

    /// The project's default permissions (allow − deny).
    pub fn granted(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .perms
            .difference(&self.denies)
            .map(|(r, a)| format!("{}:{}", r.as_str(), a.as_str()))
            .collect();
        v.sort();
        v
    }
    /// The project's default denies.
    pub fn denied(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .denies
            .iter()
            .map(|(r, a)| format!("{}:{}", r.as_str(), a.as_str()))
            .collect();
        v.sort();
        v
    }
}

fn is_write(action: Action) -> bool {
    !matches!(action, Action::Read)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case_a() -> Project {
        Project::new("case-a")
            .with_repo("LibOrg/awesome-lib", Mode::ReadWrite, &["main"])
            .with_repo("VendorOrg/reference-impl", Mode::ReadOnly, &[])
            .grant("pr:create")
            .grant("issue:create")
            .grant("project:read")
    }

    #[test]
    fn authorized_path_carries_repo_and_project() {
        let p = case_a();
        let auth = p.authorize_pr("LibOrg/awesome-lib", "main").unwrap();
        assert_eq!(auth.repo(), "LibOrg/awesome-lib");
        assert_eq!(auth.project(), "case-a");
        assert_eq!(auth.permission(), ("pr", "create"));
        assert!(auth.ensure(Resource::Pr, Action::Create).is_ok());
        assert!(auth.ensure(Resource::Pr, Action::Merge).is_err());
    }

    #[test]
    fn out_of_project_repo_is_denied() {
        let p = case_a();
        assert_eq!(
            p.authorize("Attacker/evil", Resource::Issue, Action::Create),
            Err(Denied::RepoNotInProject {
                repo: "Attacker/evil".into(),
                project: "case-a".into()
            })
        );
        // another repository in the same org is denied too
        assert!(p
            .authorize("LibOrg/other", Resource::Issue, Action::Create)
            .is_err());
    }

    #[test]
    fn find_repo_same_org_other_repo_denied() {
        let p = case_a();
        assert!(p.find_repo("LibOrg/other-lib").is_err());
        assert!(p.find_repo("Attacker/evil-repo").is_err());
        assert!(p.find_repo("liborg/AWESOME-LIB.git").is_ok());
    }

    #[test]
    fn repos_with_the_same_name_on_two_upstreams_are_told_apart_by_host() {
        let mut lib = RepoPolicy::new("LibOrg/awesome-lib", Mode::ReadWrite);
        lib.host = "github.com".into();
        let mut ghe = RepoPolicy::new("LibOrg/awesome-lib", Mode::ReadOnly);
        ghe.host = "ghe.example.com".into();
        let mut only_ghe = RepoPolicy::new("Corp/internal", Mode::ReadWrite);
        only_ghe.host = "ghe.example.com".into();
        let mut p = Project::try_new(
            "case-m",
            vec![lib, ghe, only_ghe],
            &["pr:create".to_string()],
        )
        .unwrap();
        p.set_default_host("github.com");
        // a duplicate (host, name) pair is rejected
        let mut dup = RepoPolicy::new("LibOrg/awesome-lib", Mode::ReadOnly);
        dup.host = "github.com".into();
        let mut dup2 = RepoPolicy::new("LibOrg/awesome-lib", Mode::ReadOnly);
        dup2.host = "github.com".into();
        assert!(Project::try_new("d", vec![dup, dup2], &[]).is_err());

        // API: without a host it is the default upstream, with one it is that upstream
        assert_eq!(
            p.find_repo("LibOrg/awesome-lib").unwrap().host,
            "github.com"
        );
        assert_eq!(
            p.find_repo("ghe.example.com/LibOrg/awesome-lib")
                .unwrap()
                .host,
            "ghe.example.com"
        );
        assert_eq!(
            p.find_repo("Corp/internal").unwrap().host,
            "ghe.example.com"
        );
        assert!(p.find_repo("github.com/Corp/internal").is_err());
        assert!(p.find_repo("other.example.com/LibOrg/awesome-lib").is_err());
        // SSH: narrowed to the upstream the connection came in on; only the GHES side is read-only
        assert!(p
            .authorize_git_on(
                "ghe.example.com",
                GitVerb::ReceivePack,
                "LibOrg/awesome-lib.git"
            )
            .is_err());
        assert!(p
            .authorize_git_on("github.com", GitVerb::ReceivePack, "LibOrg/awesome-lib.git")
            .is_ok());
        assert!(matches!(
            p.authorize_git_on("github.com", GitVerb::UploadPack, "Corp/internal"),
            Err(Denied::RepoNotInProject { .. })
        ));
        // an empty host does not distinguish upstreams, for compatibility with single-upstream tests
        assert!(p
            .authorize_git_on("", GitVerb::UploadPack, "Corp/internal")
            .is_ok());
        // a PR proof derived from a GitAuthorized points at the same repo
        let g = p
            .authorize_git_on("ghe.example.com", GitVerb::UploadPack, "LibOrg/awesome-lib")
            .unwrap();
        // read-only, so creating a PR is denied; the read-write repo on github.com is not picked up by mistake
        assert!(matches!(
            p.authorize_pr_for(&g, "main"),
            Err(Denied::RepoReadOnly { .. })
        ));
        let g = p
            .authorize_git_on("github.com", GitVerb::UploadPack, "LibOrg/awesome-lib")
            .unwrap();
        assert_eq!(
            p.authorize_pr_for(&g, "main").unwrap().policy().host,
            "github.com"
        );
    }

    #[test]
    fn repo_suffix_and_slash_are_normalized() {
        let p = case_a();
        for input in [
            "LibOrg/awesome-lib",
            "LibOrg/awesome-lib.git",
            "/LibOrg/awesome-lib.git",
        ] {
            assert!(
                p.authorize(input, Resource::Pr, Action::Create).is_ok(),
                "{input}"
            );
        }
    }

    #[test]
    fn read_only_repo_blocks_writes_but_allows_reads() {
        let p = case_a();
        assert_eq!(
            p.authorize("VendorOrg/reference-impl", Resource::Pr, Action::Create),
            Err(Denied::RepoReadOnly {
                repo: "VendorOrg/reference-impl".into(),
                project: "case-a".into()
            })
        );
        // read goes through, since project:read is granted
        assert!(p
            .authorize("VendorOrg/reference-impl", Resource::Project, Action::Read)
            .is_ok());
    }

    #[test]
    fn default_deny() {
        let p = case_a();
        // pr:comment is not granted
        assert_eq!(
            p.authorize("LibOrg/awesome-lib", Resource::Pr, Action::Comment),
            Err(Denied::NotPermitted {
                resource: "pr",
                action: "comment"
            })
        );
        // the order matters too: the permission check runs first, so even a repository outside the
        // project fails as "operation not allowed", leaking nothing
        assert_eq!(
            p.authorize("Attacker/evil", Resource::Pr, Action::Merge),
            Err(Denied::NotPermitted {
                resource: "pr",
                action: "merge"
            })
        );
    }

    #[test]
    fn disallowed_base_is_denied() {
        let p = case_a();
        assert_eq!(
            p.authorize_pr("LibOrg/awesome-lib", "production"),
            Err(Denied::BaseNotAllowed {
                branch: "production".into()
            })
        );
    }

    #[test]
    fn allows_base_empty_means_all() {
        let mut r = RepoPolicy::new("Org/Repo", Mode::ReadWrite);
        assert!(r.allows_base("anything"));
        r.bases = vec!["main".into(), "develop".into()];
        assert!(r.allows_base("main"));
        assert!(!r.allows_base("production"));
    }

    #[test]
    fn push_glob_default_sekimore_namespace() {
        let r = RepoPolicy::new("Org/Repo", Mode::ReadWrite);
        assert!(r.allows_push("sekimore/main-abc1234"));
        assert!(r.allows_push("sekimore/release/v1-abc1234"));
        assert!(!r.allows_push("main"));
        assert!(!r.allows_push("sekimore"));
        assert!(!r.allows_push("feature/sekimore/x"));
        assert!(glob_match("release/*", "release/v1"));
        assert!(glob_match("v?", "v1"));
        assert!(!glob_match("v?", "v10"));
        assert!(glob_match("main", "main"));
    }

    #[test]
    fn authorize_git_receive_pack_requires_read_write() {
        let p = case_a();
        let a = p
            .authorize_git(GitVerb::UploadPack, "VendorOrg/reference-impl.git")
            .unwrap();
        assert_eq!(a.repo(), "VendorOrg/reference-impl");
        assert_eq!(a.verb(), GitVerb::UploadPack);
        assert!(matches!(
            p.authorize_git(GitVerb::ReceivePack, "VendorOrg/reference-impl.git"),
            Err(Denied::RepoReadOnly { .. })
        ));
        assert!(matches!(
            p.authorize_git(GitVerb::UploadPack, "Attacker/evil.git"),
            Err(Denied::RepoNotInProject { .. })
        ));
        assert!(p
            .authorize_git(GitVerb::ReceivePack, "/LibOrg/awesome-lib.git")
            .is_ok());
    }

    #[test]
    fn per_repo_allow_and_deny_with_deny_winning() {
        let mut lib = RepoPolicy::new("Org/Lib", Mode::ReadWrite);
        lib.allow = vec!["pr:merge".into(), "issue:label".into()];
        lib.deny = vec!["ci:read".into()];
        let app = RepoPolicy::new("Org/App", Mode::ReadWrite);
        let p = Project::try_new_rules(
            "case-a",
            vec![app, lib],
            &["pr:create".into(), "pr:read".into(), "ci:read".into()],
            &["issue:label".into()],
        )
        .unwrap();
        // project defaults
        assert_eq!(p.granted(), vec!["ci:read", "pr:create", "pr:read"]);
        assert_eq!(p.denied(), vec!["issue:label"]);
        // App: the defaults apply
        assert!(p.authorize("Org/App", Resource::Pr, Action::Create).is_ok());
        assert!(p.authorize("Org/App", Resource::Ci, Action::Read).is_ok());
        assert!(p.authorize("Org/App", Resource::Pr, Action::Merge).is_err());
        // Lib: allow adds pr:merge, the repo deny removes ci:read, and the project deny on issue:label cannot be overridden by an allow
        assert!(p.authorize("Org/Lib", Resource::Pr, Action::Merge).is_ok());
        assert!(matches!(
            p.authorize("Org/Lib", Resource::Ci, Action::Read),
            Err(Denied::NotPermitted { .. })
        ));
        assert!(matches!(
            p.authorize("Org/Lib", Resource::Issue, Action::Label),
            Err(Denied::NotPermitted { .. })
        ));
        assert_eq!(
            p.effective_keys(&p.repos[1]),
            vec!["pr:create", "pr:merge", "pr:read"]
        );
        // repo outside the project: RepoNotInProject if the operation is allowed somewhere, NotPermitted if it is allowed nowhere (leaking nothing)
        assert!(matches!(
            p.authorize("Other/Repo", Resource::Pr, Action::Merge),
            Err(Denied::RepoNotInProject { .. })
        ));
        assert!(matches!(
            p.authorize("Other/Repo", Resource::Pr, Action::Close),
            Err(Denied::NotPermitted { .. })
        ));
        // typos in a repo's allow / deny are rejected at startup too
        let mut bad = RepoPolicy::new("Org/Bad", Mode::ReadOnly);
        bad.allow = vec!["pr:delete".into()];
        assert!(Project::try_new_rules("x", vec![bad], &[], &[]).is_err());
    }

    #[test]
    fn tags_glob_per_repo() {
        let mut r = RepoPolicy::new("Org/App", Mode::ReadWrite);
        assert!(!r.allows_tag("v1.0.0")); // denied by default
        r.tags = vec!["v*".into(), "release-?".into()];
        assert!(r.allows_tag("v1.0.0") && r.allows_tag("release-1"));
        assert!(!r.allows_tag("release-10") && !r.allows_tag("nightly"));
        r.tags = vec!["*".into()];
        assert!(r.allows_tag("anything"));
    }

    /// 0.2.7: a search is the one operation not addressed to a repository, so the scoping has to
    /// come from the query and from filtering what comes back.
    #[test]
    fn search_is_scoped_to_the_projects_repositories() {
        let p = Project::try_new(
            "case-a",
            vec![
                RepoPolicy::new("Org/App", Mode::ReadWrite),
                RepoPolicy::new("Org/Lib", Mode::ReadOnly),
            ],
            &["search:read".to_string()],
        )
        .unwrap();
        assert_eq!(p.search_scope(), vec!["repo:Org/App", "repo:Org/Lib"]);
        assert!(p.owns_repo("Org/App"));
        // GitHub is case-insensitive about owner and name, so the filter has to be too
        assert!(p.owns_repo("org/app"));
        assert!(!p.owns_repo("Other/Secret"));
        assert!(!p.owns_repo("Org/AppExtra"));
        assert!(!p.owns_repo(""));

        // A project with no repositories can search nothing, rather than searching everything
        let empty = Project::try_new("empty", vec![], &["search:read".to_string()]).unwrap();
        assert!(empty.search_scope().is_empty());
        assert!(!empty.owns_repo("Org/App"));
    }

    #[test]
    fn invalid_permission_specs_are_rejected() {
        assert!(parse_permission("pr:create").is_ok());
        // combinations the Go version accepted because its keys were plain strings
        assert!(parse_permission("pr:delete").is_err());
        assert!(parse_permission("workflow:run").is_err());
        assert!(parse_permission("repo:merge").is_err()); // combination does not exist
        assert!(parse_permission("prcreate").is_err());
        assert!(Project::try_new("x", vec![], &["pr:delete".to_string()]).is_err());
        assert!(Project::try_new("x", vec![RepoPolicy::new("nope", Mode::ReadOnly)], &[]).is_err());
        // pr:read (0.1.3) + ci:read (0.1.5) + release:create / release:read (0.2.6)
        // + pr:request_review, issue:read, search:read (0.2.7)
        // + release:publish, ci:rerun (0.2.9)
        assert_eq!(all_permission_keys().len(), 23);
        for k in [
            "pr:request_review",
            "issue:read",
            "search:read",
            "release:publish",
            "ci:rerun",
        ] {
            assert!(all_permission_keys().contains(&k.to_string()), "{k}");
        }
        assert!(all_permission_keys().contains(&"release:create".to_string()));
    }
}
