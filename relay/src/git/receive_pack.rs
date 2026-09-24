//! Relaying `git-receive-pack` (push).
//!
//! The Go PoC read all of the client's input before spawning the upstream. In receive-pack the server sends its
//! advertisement first, so that deadlocks against a real git. Instead we do:
//!
//!   A  forward the upstream advertisement to the client unchanged (recording ref → sha)
//!   B  parse and rewrite only the client's command section (up to the flush, with a size cap) and send it upstream
//!   B2 the push-options section is passed through unchanged
//!   C  stream the pack data raw, without buffering — except when the pack itself has to answer a
//!      policy question (a tag push, #89; a branch push under `signing: required`, #59), in which
//!      case it is read on the way through and the trailer is held back until the verdict is in
//!   D  map the upstream report-status back to the original ref names and send it to the client
//!   E  on success, create a PR for each `refs/for`

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::pack::{Object, Objects, PackError, PackScan, TRAILER_LEN};
use super::response::{RefStatus, ResponseRewriter};
use super::{
    copy_touch, copy_touch_counted, exit_code_of, GitContext, GitIo, RelayOutcome, UpstreamProcess,
    Watchdog,
};
use crate::audit::Actor;
use crate::config::OnExists;
use crate::github::GhError;
use crate::pktline::{
    caps_contain, encode_commands, encode_into, parse_receive_pack, validate_ref_name, CommandLine,
    CommandSection, Frame, PktReader, RefUpdate,
};
use crate::policy::{Action, Denied, GitAuthorized, Project, Resource, SigningMode};

/// The agent's branch namespace, and the default a branch template renders to.
pub const SEKIMORE_BRANCH_PREFIX: &str = "sekimore/";

/// Renders a branch template. Unknown placeholders cannot reach here: the template is checked
/// when the configuration loads, and an unchecked one would put `{brnach}` in a branch name.
pub fn render_branch(template: &str, branch: &str, base: &str, sha: &str) -> String {
    let mut out = String::with_capacity(template.len() + branch.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close) => {
                match &after[..close] {
                    "branch" => out.push_str(branch),
                    "base" => out.push_str(base),
                    "sha" => out.push_str(short_sha(sha)),
                    // validate() rejects these, so reaching one means the template was never
                    // checked. Keeping it literal is what the name would have been anyway.
                    other => {
                        out.push('{');
                        out.push_str(other);
                        out.push('}');
                    }
                }
                rest = &after[close + 1..];
            }
            None => {
                out.push('{');
                out.push_str(after);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedCommand {
    Update {
        old: String,
        new: String,
        name: String,
    },
    Shallow(String),
}

/// The intent to create one PR, corresponding to a single `refs/for/<base>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrIntent {
    pub client_ref: String,
    pub upstream_ref: String,
    pub head_branch: String,
    /// The base the pull request opens against. `None` for `refs/pr/<branch>`, which does not
    /// name one: it is resolved to the upstream's default branch when the PR is created, the
    /// step that already talks to the API (#158).
    pub base: Option<String>,
    pub sha: String,
}

/// A tag this push creates, to be judged once the pack has been read (#89).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagCheck {
    pub name: String,
    /// The sha the tag will point at: a tag object if annotated, a commit if lightweight
    pub sha: String,
}

/// A branch this push moves, to be judged once the pack has been read (#59). Only made when the
/// repository's `signing` is `required`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitCheck {
    /// The ref as the client wrote it, for the message
    pub name: String,
    /// The commit the ref will point at
    pub sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushPlan {
    pub commands: Vec<OwnedCommand>,
    pub caps: Option<Vec<u8>>,
    /// upstream ref → client ref
    pub rewrites: HashMap<String, String>,
    pub prs: Vec<PrIntent>,
    /// Tags that must turn out to be signed tag objects. Empty unless the policy asks (`signed_tags`)
    pub tag_checks: Vec<TagCheck>,
    /// 0.2.29 (#59): branches whose new commits must all be signed. Empty unless `signing: required`
    pub commit_checks: Vec<CommitCheck>,
    /// The shas the upstream advertised. A commit walk stops at one of these: it is history the
    /// upstream already has, so this push did not bring it
    pub adv_shas: HashSet<String>,
}

impl PushPlan {
    pub fn encode(&self) -> Result<Vec<u8>, crate::pktline::PktError> {
        let lines: Vec<CommandLine<'_>> = self
            .commands
            .iter()
            .map(|c| match c {
                OwnedCommand::Update { old, new, name } => {
                    CommandLine::Update(RefUpdate { old, new, name })
                }
                OwnedCommand::Shallow(s) => CommandLine::Shallow(s),
            })
            .collect();
        encode_commands(&lines, self.caps.as_deref())
    }
}

pub fn short_sha(sha: &str) -> &str {
    &sha[..sha.len().min(7)]
}

fn zero_like(sha: &str) -> String {
    "0".repeat(sha.len())
}

/// Split apart one advertisement line, `<sha> <ref>[\0caps]`.
pub fn parse_advert_line(payload: &[u8]) -> Option<(String, String, Option<Vec<u8>>)> {
    let (body, caps) = match payload.iter().position(|&b| b == 0) {
        Some(i) => (&payload[..i], Some(payload[i + 1..].to_vec())),
        None => (payload, None),
    };
    let body = match body.last() {
        Some(b'\n') => &body[..body.len() - 1],
        _ => body,
    };
    let text = std::str::from_utf8(body).ok()?;
    let (sha, name) = text.split_once(' ')?;
    Some((
        sha.to_string(),
        name.trim_end().to_string(),
        caps.map(|c| match c.last() {
            Some(b'\n') => c[..c.len() - 1].to_vec(),
            _ => c,
        }),
    ))
}

/// Check the command section against policy and build the rewrite plan. A denial is decided here, before anything is sent upstream.
pub fn plan_push(
    project: &Project,
    auth: &GitAuthorized<'_>,
    section: &CommandSection<'_>,
    adv: &HashMap<String, String>,
) -> Result<PushPlan, Denied> {
    let policy = auth.policy();
    let mut commands = Vec::new();
    let mut rewrites: HashMap<String, String> = HashMap::new();
    let mut prs = Vec::new();
    let mut tag_checks = Vec::new();
    let mut commit_checks = Vec::new();
    // Every upstream ref this plan will update, and the client ref it came from. Two updates
    // to one ref in a single section put the report-status rewriter into a state it cannot
    // represent — its map is one upstream ref to one client ref — so the ok/ng of one would
    // be reported against the other, and stage E would decide whether to open the PR from
    // the wrong result. Rejecting is the only answer that stays truthful.
    // Both directions have to stay one-to-one. Two client refs mapping to one upstream ref is
    // the obvious collision; one client ref mapping to two upstream refs is the same problem
    // seen from the other end, and `refs/for/main` twice with different commits produces it.
    let mut upstream_refs: HashSet<String> = HashSet::new();
    let mut client_refs: HashSet<String> = HashSet::new();
    let mut claim = |upstream: &str, client: &str| -> Result<(), Denied> {
        if !upstream_refs.insert(upstream.to_string()) {
            return Err(Denied::RefNotAllowed {
                name: client.to_string(),
                reason: "two refs in this push update the same upstream branch",
            });
        }
        if !client_refs.insert(client.to_string()) {
            return Err(Denied::RefNotAllowed {
                name: client.to_string(),
                reason: "the same ref is pushed twice in one push",
            });
        }
        Ok(())
    };

    for line in &section.lines {
        let u = match line {
            CommandLine::Shallow(s) => {
                commands.push(OwnedCommand::Shallow(s.to_string()));
                continue;
            }
            CommandLine::Update(u) => u,
        };
        if let Some(base) = u.refs_for_base() {
            if u.is_delete() {
                return Err(Denied::RefNotAllowed {
                    name: u.name.to_string(),
                    reason: "refs/for/* cannot be deleted",
                });
            }
            // pr:create + read-write + an allowed base (the Authorized is dropped here and re-obtained in stage E)
            project.authorize_pr(auth.repo(), base)?;
            // `refs/for/<base>` carries no branch name of its own, so `{branch}` and `{base}`
            // are the same string here. The default template reproduces sekimore/<base>-<sha7>.
            let head_branch = render_branch(&project.branch.template, base, base, u.new);
            let upstream_ref = format!("refs/heads/{head_branch}");
            validate_ref_name(&upstream_ref).map_err(|reason| Denied::InvalidRef {
                name: upstream_ref.clone(),
                reason,
            })?;
            claim(&upstream_ref, u.name)?;
            // A template carrying {sha} names a branch only this commit can land on, so finding
            // it upstream means the same commit is being pushed again — AC-4.5.6 asks that to be
            // idempotent, and on_exists must not change it. A template without {sha} can collide
            // with work that has nothing to do with this push, and that is what it answers (#158).
            if project.branch.on_exists == OnExists::Reject
                && !project.branch.template.contains("{sha}")
                && adv.contains_key(&upstream_ref)
            {
                return Err(Denied::BranchExists {
                    name: u.name.to_string(),
                    branch: head_branch,
                });
            }
            let old = adv
                .get(&upstream_ref)
                .cloned()
                .unwrap_or_else(|| zero_like(u.old));
            rewrites.insert(upstream_ref.clone(), u.name.to_string());
            prs.push(PrIntent {
                client_ref: u.name.to_string(),
                upstream_ref: upstream_ref.clone(),
                head_branch,
                base: Some(base.to_string()),
                sha: u.new.to_string(),
            });
            if policy.signing == SigningMode::Required {
                commit_checks.push(CommitCheck {
                    name: u.name.to_string(),
                    sha: u.new.to_string(),
                });
            }
            commands.push(OwnedCommand::Update {
                old,
                new: u.new.to_string(),
                name: upstream_ref,
            });
        } else if let Some(branch) = u.refs_pr_branch() {
            // 0.3.0 (#158): the agent names the branch, and the project's own push globs say
            // whether that name is one it may use. No base is named here; the pull request opens
            // against the upstream's default branch, resolved in stage E.
            if u.is_delete() {
                return Err(Denied::RefNotAllowed {
                    name: u.name.to_string(),
                    reason: "refs/pr/* cannot be deleted",
                });
            }
            // pr:create + read-write.
            project.authorize(auth.repo(), Resource::Pr, Action::Create)?;
            // `refs/pr/` opens against the upstream's default branch, which is not knowable here:
            // planning is offline, and the receive-pack advertisement carries no symref for HEAD.
            // A project that restricts `bases` would therefore have its base checked only after
            // the branch had already reached upstream — the one thing this function promises not
            // to do. So the spelling is refused outright where it could not be honoured, and the
            // message says which two ways round it there are (#158).
            if !policy.bases.is_empty() {
                return Err(Denied::RefNotAllowed {
                    name: u.name.to_string(),
                    reason: "refs/pr/* opens against the default branch, which this repository's `bases` restricts; push to refs/for/<base>, or to refs/heads/<branch> and open the PR with `sekimore pr create --base`",
                });
            }
            if !policy.allows_push(branch) {
                return Err(Denied::RefNotAllowed {
                    name: u.name.to_string(),
                    reason: "branch is outside the allowed push namespace (repos[].push, default sekimore/*)",
                });
            }
            let upstream_ref = format!("refs/heads/{branch}");
            validate_ref_name(&upstream_ref).map_err(|reason| Denied::InvalidRef {
                name: upstream_ref.clone(),
                reason,
            })?;
            claim(&upstream_ref, u.name)?;
            // The agent chose this name, so an existing one is someone else's work unless the
            // project says otherwise — there is no sha here to make it unique.
            if project.branch.on_exists == OnExists::Reject && adv.contains_key(&upstream_ref) {
                return Err(Denied::BranchExists {
                    name: u.name.to_string(),
                    branch: branch.to_string(),
                });
            }
            let old = adv
                .get(&upstream_ref)
                .cloned()
                .unwrap_or_else(|| zero_like(u.old));
            rewrites.insert(upstream_ref.clone(), u.name.to_string());
            prs.push(PrIntent {
                client_ref: u.name.to_string(),
                upstream_ref: upstream_ref.clone(),
                head_branch: branch.to_string(),
                base: None,
                sha: u.new.to_string(),
            });
            if policy.signing == SigningMode::Required {
                commit_checks.push(CommitCheck {
                    name: u.name.to_string(),
                    sha: u.new.to_string(),
                });
            }
            commands.push(OwnedCommand::Update {
                old,
                new: u.new.to_string(),
                name: upstream_ref,
            });
        } else if let Some(branch) = u.name.strip_prefix("refs/heads/") {
            if u.is_delete() && !policy.delete {
                return Err(Denied::DeleteNotAllowed {
                    name: u.name.to_string(),
                });
            }
            if !policy.allows_push(branch) {
                return Err(Denied::RefNotAllowed {
                    name: u.name.to_string(),
                    reason: "branch is outside the allowed push namespace (repos[].push, default sekimore/*); push to refs/for/<base> to open a PR instead",
                });
            }
            claim(u.name, u.name)?;
            // Whether the commits are signed is in the pack, not here; stage C answers it.
            if !u.is_delete() && policy.signing == SigningMode::Required {
                commit_checks.push(CommitCheck {
                    name: u.name.to_string(),
                    sha: u.new.to_string(),
                });
            }
            commands.push(OwnedCommand::Update {
                old: u.old.to_string(),
                new: u.new.to_string(),
                name: u.name.to_string(),
            });
        } else if let Some(tag) = u.name.strip_prefix("refs/tags/") {
            if u.is_delete() && !policy.delete {
                return Err(Denied::DeleteNotAllowed {
                    name: u.name.to_string(),
                });
            }
            if !policy.allows_tag(tag) {
                return Err(Denied::RefNotAllowed {
                    name: u.name.to_string(),
                    reason: "tag is not allowed for this repository (relay.project.tags / repos[].tags globs; default deny)",
                });
            }
            // A tag the upstream already advertises is one people may already have. Moving it
            // leaves exactly what deleting and recreating it leaves — that name now points at
            // different code — so it needs the same authority, and without `delete` the push is
            // refused. Creating a tag that is not there yet is untouched: the release flow is
            // exactly that. The advertisement is what decides, not the client's `old` value,
            // which a force push is free to fill in from whatever it last saw.
            if !u.is_delete() && !policy.delete && adv.contains_key(u.name) {
                return Err(Denied::TagUpdateNotAllowed {
                    name: u.name.to_string(),
                });
            }
            claim(u.name, u.name)?;
            // Whether it is a signed tag object is in the pack, not here; stage C answers it.
            if !u.is_delete() && policy.signed_tags {
                tag_checks.push(TagCheck {
                    name: u.name.to_string(),
                    sha: u.new.to_string(),
                });
            }
            commands.push(OwnedCommand::Update {
                old: u.old.to_string(),
                new: u.new.to_string(),
                name: u.name.to_string(),
            });
        } else {
            return Err(Denied::RefNotAllowed {
                name: u.name.to_string(),
                reason: "only refs/heads/* and refs/for/* may be pushed",
            });
        }
    }
    Ok(PushPlan {
        commands,
        caps: section.caps.map(|c| c.to_vec()),
        rewrites,
        prs,
        tag_checks,
        commit_checks,
        adv_shas: adv.values().cloned().collect(),
    })
}

/// The pack against everything this push has to be judged on: its tags (#89) and, under
/// `signing: required`, the commits it brings (#59).
///
/// A pack this relay could not read refuses whatever was being asked of it: "cannot tell" fails
/// closed, because the whole point is that nobody could tell before.
pub async fn judge_pack(
    scanned: Result<Objects, PackError>,
    tags: &[TagCheck],
    commits: &[CommitCheck],
    adv_shas: &HashSet<String>,
    upstream: &dyn UpstreamCommits,
) -> Result<(), Denied> {
    let objects = match scanned {
        Ok(o) => o,
        Err(e) => {
            if let Some(c) = tags.first() {
                return Err(Denied::TagNotSigned {
                    name: c.name.clone(),
                    reason: format!("the pack could not be read to find the tag object ({e})"),
                });
            }
            // Nothing to judge means nothing to refuse. Stage C only reads the pack when there
            // is a check, so this cannot happen — and a panic inside the relay is not the way to
            // find out that it can.
            let Some(c) = commits.first() else {
                log::warn!("a pack was judged with no checks ({e})");
                return Ok(());
            };
            return Err(Denied::CommitNotSigned {
                name: c.name.clone(),
                sha: c.sha.clone(),
                reason: format!("could not be read out of the pack ({e})"),
            });
        }
    };
    judge_tags(&objects, tags)?;
    judge_commits(&objects, commits, adv_shas, upstream).await
}

/// How `judge_commits` asks the upstream whether a commit is already there.
///
/// A trait rather than a closure so the tests can answer for a sha without an upstream, and so the
/// only implementation that reaches the network is the one holding a `GitAuthorized`.
#[async_trait::async_trait]
pub trait UpstreamCommits: Sync {
    /// `Ok(true)` when the upstream holds this commit. An `Err` is "cannot tell", and the caller
    /// fails closed on it.
    async fn has_commit(&self, sha: &str) -> Result<bool, String>;
}

/// The real one: the upstream's API, scoped by the authorization this push already passed.
pub struct ApiUpstreamCommits<'a> {
    pub github: Option<&'a crate::github::GitHub>,
    pub auth: &'a GitAuthorized<'a>,
}

#[async_trait::async_trait]
impl UpstreamCommits for ApiUpstreamCommits<'_> {
    async fn has_commit(&self, sha: &str) -> Result<bool, String> {
        let Some(gh) = self.github else {
            return Err("this relay has no API client for the upstream".to_string());
        };
        gh.commit_exists(self.auth, sha)
            .await
            .map_err(|e| e.to_string())
    }
}

/// How many commits one push may make this relay ask the upstream about.
///
/// An honest push asks about one — where its branch left the history the upstream has — or a
/// handful for a merge. The cap is what stops a pack built to make the relay spend calls.
const MAX_UPSTREAM_LOOKUPS: usize = 32;

/// Every commit this push adds, against `signing: required` (#59).
///
/// The walk starts at each updated ref's new sha and follows parents, and every commit it reaches
/// inside the pack has to carry a signature. Where it leaves the pack it has to establish which
/// of two things it is looking at, because from inside the pack they are identical:
///
///   - history the upstream already has, which this push did not bring and is not answerable for
///   - a commit that *is* in this push, hidden behind a delta whose base lives upstream
///
/// The second is not something `git push` produces — `pack-objects` builds thin bases with
/// `add_preferred_base`, which dereferences a commit to its tree, so an external base is a tree or
/// a blob — but the client here is an AI agent and the pack is whatever it chose to send. A
/// hand-built REF_DELTA against any commit the upstream has would otherwise carry an unsigned
/// commit straight through, so the boundary is settled by asking the upstream, which is one or two
/// calls per push however many blob deltas the pack holds.
///
/// A delta against a commit *in* this pack is the other way a commit can hide, and that one is
/// counted exactly (`unresolved_commit_deltas`) and refused without asking anyone.
async fn judge_commits(
    objects: &Objects,
    checks: &[CommitCheck],
    adv_shas: &HashSet<String>,
    upstream: &dyn UpstreamCommits,
) -> Result<(), Denied> {
    // Shared across the checks in one push: two branches off the same base ask once.
    let mut known: HashMap<String, bool> = HashMap::new();
    let mut lookups = 0usize;
    for c in checks {
        if objects.unresolved_commit_deltas > 0 {
            return Err(Denied::CommitNotSigned {
                name: c.name.clone(),
                sha: c.sha.clone(),
                // #140: a delta against a commit in the pack is applied now; what is left is one
                // whose base was too large to keep, or past the budget for one pack. --no-thin
                // does nothing for it (it only stops deltas against objects outside the pack);
                // turning off delta search does.
                reason: "arrived as a delta against another commit in the same pack that this relay did not keep (a commit over 1 MiB, or more than 64 MiB of commits in one push), so it cannot see whether it is signed. `git -c pack.window=0 push` sends every commit whole".to_string(),
            });
        }
        // An advertised sha is a tip the upstream already has; there is no new history under it.
        if adv_shas.contains(&c.sha) {
            continue;
        }
        // Breadth-first from the tip, so the commit named in the denial is the one nearest it —
        // the one the person is most likely looking at.
        let mut queue: VecDeque<String> = VecDeque::from([c.sha.clone()]);
        let mut seen: HashSet<String> = HashSet::from([c.sha.clone()]);
        while let Some(sha) = queue.pop_front() {
            match objects.by_sha.get(&sha) {
                Some(Object::Commit { signed, parents }) => {
                    if !signed {
                        return Err(Denied::CommitNotSigned {
                            name: c.name.clone(),
                            sha: sha.clone(),
                            reason: "carries no signature".to_string(),
                        });
                    }
                    for p in parents {
                        if adv_shas.contains(p) {
                            continue;
                        }
                        if seen.insert(p.clone()) {
                            queue.push_back(p.clone());
                        }
                    }
                }
                // The boundary. Not a commit this pack brought — or not one this pack *admits* to
                // bringing.
                _ => {
                    if let Some(upstream_has) = known.get(&sha) {
                        if *upstream_has {
                            continue;
                        }
                    } else {
                        if lookups >= MAX_UPSTREAM_LOOKUPS {
                            return Err(Denied::CommitNotSigned {
                                name: c.name.clone(),
                                sha: sha.clone(),
                                reason: format!(
                                    "is one of more than {MAX_UPSTREAM_LOOKUPS} commits this push leaves unaccounted for, which is more than this relay will ask the upstream about. `git push --no-thin` sends whole objects"
                                ),
                            });
                        }
                        lookups += 1;
                        let answer = upstream.has_commit(&sha).await.map_err(|e| {
                            // Fail closed. The usual cause is the store being locked after a
                            // restart, and the operator has to hear which command that is.
                            Denied::CommitNotSigned {
                                name: c.name.clone(),
                                sha: sha.clone(),
                                reason: format!(
                                    "could not be looked up on the upstream ({e}); signing: required needs the upstream API, so the gateway has to be unlocked (`mise run gw:unlock`) and logged in"
                                ),
                            }
                        })?;
                        known.insert(sha.clone(), answer);
                        if answer {
                            continue;
                        }
                    }
                    return Err(Denied::CommitNotSigned {
                        name: c.name.clone(),
                        sha: sha.clone(),
                        reason: "is not on the upstream and did not arrive as a whole object, so this relay cannot see whether it is signed — a delta against an object the upstream already has. `git push --no-thin` sends whole objects".to_string(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Each pushed tag against what the pack turned out to hold.
///
/// Every check has to find its sha as a tag object with a signature block. Anything else —
/// a commit under the name (lightweight), a tag object without a signature, an object that is
/// not in the pack at all — is refused, and so is a pack this relay could not read: the answer
/// "cannot tell" fails closed, because the whole point is that nobody could tell before.
pub fn judge_tags(objects: &Objects, checks: &[TagCheck]) -> Result<(), Denied> {
    for c in checks {
        let reason = match objects.by_sha.get(&c.sha) {
            Some(Object::Tag { signed: true }) => continue,
            Some(Object::Tag { signed: false }) => {
                "it is an annotated tag without a signature".to_string()
            }
            Some(Object::Commit { .. }) => {
                "it is a lightweight tag — the name points straight at a commit".to_string()
            }
            Some(Object::Other(kind)) => {
                format!("it is a lightweight tag — the name points straight at a {kind}")
            }
            Some(Object::OversizedTag) => {
                "its tag object is over 1 MiB, more than this relay reads to find a signature"
                    .to_string()
            }
            None if objects.unresolved_deltas > 0 => {
                "its object is not in this push as a whole object; either it is a lightweight tag on a commit the upstream already has, or it arrived as a delta this relay could not resolve (`git push --no-thin` sends whole objects)".to_string()
            }
            None => {
                "its object is not in this push — a lightweight tag on a commit the upstream already has, or a tag object it already has".to_string()
            }
        };
        return Err(Denied::TagNotSigned {
            name: c.name.clone(),
            reason,
        });
    }
    Ok(())
}

/// Stage C for a push the pack itself has to answer for: forward it while reading it, holding
/// back its last `TRAILER_LEN` bytes until the verdict is in.
///
/// The trailer is the pack's checksum, and index-pack refuses a pack that ends without one, so
/// dropping it is how a refusal takes effect after the rest has already gone upstream: nothing is
/// unpacked, no ref moves, and the upstream's own report-status says ng for every one of them.
/// `leftover` is whatever the command-section reader had already pulled off the socket.
///
/// The verdict is given the moment the scan says the pack is complete, not at the client's EOF:
/// git holds its side open until it has read the report-status, and the upstream will not write
/// one until it has the trailer — waiting for EOF here would wait forever (and did, as an idle
/// timeout, in the first version of this).
///
/// Returns the bytes taken from the client and the verdict. `writer` is taken by value because a
/// refusal has to *close* the upstream's stdin — `AsyncWrite::shutdown` on a child's pipe is a
/// no-op in tokio, and only dropping the handle sends the EOF that makes index-pack give up. On
/// success the trailer follows and the handle is dropped at the client's EOF.
#[allow(clippy::too_many_arguments)]
async fn copy_judging_pack<R, W>(
    leftover: &[u8],
    mut reader: R,
    writer: W,
    wd: &Watchdog,
    seen: &AtomicU64,
    tags: &[TagCheck],
    commits: &[CommitCheck],
    adv_shas: &HashSet<String>,
    upstream: &dyn UpstreamCommits,
) -> std::io::Result<(u64, Result<(), Denied>)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut writer = Some(writer);
    let mut scan = Some(PackScan::new());
    let mut verdict: Option<Result<(), Denied>> = None;
    // The last TRAILER_LEN bytes seen so far; everything before them has been forwarded
    let mut tail: Vec<u8> = Vec::with_capacity(TRAILER_LEN + 64 * 1024);
    let mut total = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    let mut chunk: &[u8] = leftover;
    loop {
        if !chunk.is_empty() {
            match (&mut scan, &verdict) {
                (Some(s), _) => {
                    let w = writer.as_mut().expect("open until judged");
                    s.feed(chunk);
                    tail.extend_from_slice(chunk);
                    if tail.len() > TRAILER_LEN {
                        let forward = tail.len() - TRAILER_LEN;
                        w.write_all(&tail[..forward]).await?;
                        tail.drain(..forward);
                    }
                    if s.is_complete() {
                        let v = judge_pack(
                            scan.take().unwrap().finish(),
                            tags,
                            commits,
                            adv_shas,
                            upstream,
                        )
                        .await;
                        if v.is_ok() {
                            w.write_all(&tail).await?;
                            w.flush().await?;
                        } else {
                            // No trailer, then EOF: the upstream fails to unpack and reports ng
                            // for every ref itself
                            w.flush().await?;
                            writer = None;
                        }
                        tail.clear();
                        verdict = Some(v);
                    }
                }
                // Anything after a complete pack is not something git sends; pass it on as the
                // plain path would, or swallow it once the upstream has been closed
                (None, Some(Ok(()))) => {
                    if let Some(w) = writer.as_mut() {
                        w.write_all(chunk).await?;
                    }
                }
                (None, _) => {}
            }
            total += chunk.len() as u64;
            seen.store(total, Ordering::Relaxed);
            wd.touch();
        }
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        chunk = &buf[..n];
    }
    let verdict = match verdict {
        Some(v) => v,
        // EOF before the pack was whole: nothing to judge, and nothing the upstream can use
        None => {
            judge_pack(
                scan.take().unwrap().finish(),
                tags,
                commits,
                adv_shas,
                upstream,
            )
            .await
        }
    };
    if let Some(mut w) = writer.take() {
        w.flush().await?;
    }
    // dropping `writer` (already None on a refusal) is what closes the upstream's stdin
    Ok((total, verdict))
}

async fn say(io: &mut GitIo<'_>, msg: &str) {
    let _ = io
        .stderr
        .write_all(format!("sekimore: {msg}\n").as_bytes())
        .await;
    let _ = io.stderr.flush().await;
}

fn fail(note: &str) -> RelayOutcome {
    RelayOutcome {
        status: 1,
        bytes_in: 0,
        bytes_out: 0,
        note: Some(note.to_string()),
    }
}

pub async fn relay_receive_pack(
    io: &mut GitIo<'_>,
    mut proc: UpstreamProcess,
    ctx: &GitContext,
    auth: &GitAuthorized<'_>,
) -> RelayOutcome {
    let wd = Watchdog::new(ctx.limits.idle_timeout);
    wd.touch();
    // Upstream stderr goes to the client in one batch at the end; the relay's own lines carry the "sekimore: " prefix.
    let stderr_task = proc.stderr.take().map(|mut es| {
        let w = wd.clone();
        tokio::spawn(async move {
            let mut sink = Vec::new();
            let _ = copy_touch(&mut es, &mut sink, &w, false).await;
            sink
        })
    });

    // ---- A: advertisement ----
    let mut up_reader = PktReader::new(&mut proc.stdout);
    let mut adv: HashMap<String, String> = HashMap::new();
    let mut server_caps: Vec<u8> = Vec::new();
    let mut adv_bytes = 0usize;
    let adv_result: Result<(), String> = tokio::time::timeout(ctx.limits.adv_timeout, async {
        loop {
            let frame = match up_reader.next().await {
                Ok(Some(f)) => f,
                Ok(None) => {
                    return Err("upstream closed the connection before advertising refs".to_string())
                }
                Err(e) => return Err(format!("cannot read upstream advertisement: {e}")),
            };
            adv_bytes += frame.raw().len();
            if adv_bytes > ctx.limits.adv_max_bytes {
                return Err(format!(
                    "upstream advertisement exceeds {} bytes",
                    ctx.limits.adv_max_bytes
                ));
            }
            io.stdout
                .write_all(&frame.raw())
                .await
                .map_err(|e| format!("client write: {e}"))?;
            match &frame {
                Frame::Flush => break,
                Frame::Data(_) => {
                    if let Some((sha, name, caps)) = parse_advert_line(frame.payload()) {
                        if let Some(c) = caps {
                            server_caps = c;
                        }
                        if name != "capabilities^{}" {
                            adv.insert(name, sha);
                        }
                    }
                }
                _ => {}
            }
        }
        io.stdout
            .flush()
            .await
            .map_err(|e| format!("client write: {e}"))?;
        Ok(())
    })
    .await
    .unwrap_or_else(|_| {
        Err(format!(
            "upstream did not advertise refs within {}",
            humantime::format_duration(ctx.limits.adv_timeout)
        ))
    });
    if let Err(msg) = adv_result {
        let _ = proc.child.start_kill();
        let _ = proc.child.wait().await;
        flush_upstream_stderr(io, stderr_task).await;
        say(io, &msg).await;
        return fail("advertisement");
    }
    wd.touch();

    // ---- B: client command section ----
    let mut cl_reader = PktReader::new(&mut io.stdin);
    let section_bytes = match tokio::time::timeout(
        ctx.limits.idle_timeout,
        cl_reader.read_section(ctx.limits.cmd_max_bytes),
    )
    .await
    {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            let _ = proc.child.start_kill();
            let msg = format!("cannot read push commands: {e}");
            say_err(&mut io.stderr, &msg).await;
            return fail("commands");
        }
        Err(_) => {
            let _ = proc.child.start_kill();
            say_err(&mut io.stderr, "timed out waiting for push commands").await;
            return fail("commands_timeout");
        }
    };
    wd.touch();
    let section = match parse_receive_pack(&section_bytes) {
        Ok(s) => s,
        Err(e) => {
            let _ = proc.child.start_kill();
            let msg = format!("cannot parse push commands: {e}");
            say_err(&mut io.stderr, &msg).await;
            ctx.audit.deny(
                "push_rejected",
                Actor::Agent,
                &msg,
                &[("repo", auth.repo())],
            );
            return fail("malformed");
        }
    };
    let client_caps = section.caps.unwrap_or(&[]);
    let sideband =
        caps_contain(client_caps, "side-band-64k") || caps_contain(client_caps, "side-band");
    let report_status =
        caps_contain(client_caps, "report-status") || caps_contain(client_caps, "report-status-v2");
    let push_options =
        caps_contain(client_caps, "push-options") && caps_contain(&server_caps, "push-options");

    let plan = match plan_push(&ctx.project, auth, &section, &adv) {
        Ok(p) => p,
        Err(d) => {
            let _ = proc.child.start_kill();
            let _ = proc.child.wait().await;
            let msg = d.to_string();
            say_err(&mut io.stderr, &msg).await;
            ctx.audit.deny(
                &format!("push_denied_{}", d.kind()),
                Actor::Agent,
                &msg,
                &[("repo", auth.repo()), ("project", auth.project())],
            );
            if report_status {
                // The client is waiting for a report-status, so return the denial as an `ng` rather than dropping the connection
                // (git then prints "! [remote rejected] … (reason)" instead of "remote end hung up").
                // The client starts sending the pack right after the commands, so unless we drain it the window fills up and it never reads the report.
                let report = reject_report(&section, &msg, sideband);
                let (stdin, _leftover) = cl_reader.into_parts();
                let _ = io.stdout.write_all(&report).await;
                let _ = io.stdout.flush().await;
                let _ = tokio::time::timeout(
                    ctx.limits.idle_timeout,
                    tokio::io::copy(stdin, &mut tokio::io::sink()),
                )
                .await;
            }
            return fail("policy");
        }
    };
    let encoded = match plan.encode() {
        Ok(e) => e,
        Err(e) => {
            let _ = proc.child.start_kill();
            say_err(
                &mut io.stderr,
                &format!("cannot re-encode push commands: {e}"),
            )
            .await;
            return fail("encode");
        }
    };
    if proc.stdin.write_all(&encoded).await.is_err() {
        say_err(
            &mut io.stderr,
            "upstream closed while receiving push commands",
        )
        .await;
        let _ = proc.child.wait().await;
        flush_upstream_stderr(io, stderr_task).await;
        return fail("upstream_write");
    }
    for pr in &plan.prs {
        ctx.audit.log(
            "refs_for_rewritten",
            Actor::Agent,
            &[
                ("repo", auth.repo()),
                ("from", &pr.client_ref),
                ("to", &pr.upstream_ref),
                ("sha", &pr.sha),
            ],
        );
    }

    // ---- B2: push-options ----
    if push_options && !plan.commands.is_empty() {
        match tokio::time::timeout(ctx.limits.idle_timeout, cl_reader.read_section(64 * 1024)).await
        {
            Ok(Ok(opts)) => {
                if proc.stdin.write_all(&opts).await.is_err() {
                    say_err(
                        &mut io.stderr,
                        "upstream closed while receiving push options",
                    )
                    .await;
                    return fail("upstream_write");
                }
            }
            _ => {
                let _ = proc.child.start_kill();
                say_err(&mut io.stderr, "cannot read push options").await;
                return fail("push_options");
            }
        }
    }
    let (_, leftover) = cl_reader.into_parts();

    // ---- C + D ----
    let mut rewriter = ResponseRewriter::new(plan.rewrites.clone(), sideband);
    let has_commands = !plan.commands.is_empty();
    // Read from outside the future: an idle timeout drops it, taking its return value with
    // it, and the byte count is the exfiltration record. Losing it would make going quiet
    // mid-upload a way to erase what was sent.
    let sent = AtomicU64::new(0);
    // Owned here rather than borrowed from `proc`, so stage C can drop it: on a child's pipe
    // `shutdown()` does nothing in tokio, and dropping the handle is the only way to send EOF
    let mut upstream_stdin = Some(proc.stdin);
    // #59: what settles the boundary of the history this push brings. Built here because it
    // borrows the same `auth` the push was allowed under.
    let upstream_commits = ApiUpstreamCommits {
        github: ctx.github.as_deref(),
        auth,
    };
    let pack_fut = async {
        if !plan.tag_checks.is_empty() || !plan.commit_checks.is_empty() {
            // #89 / #59: read the pack on the way through and hold the trailer until it is judged
            let (n, verdict) = copy_judging_pack(
                &leftover,
                &mut io.stdin,
                upstream_stdin.take().expect("taken once"),
                &wd,
                &sent,
                &plan.tag_checks,
                &plan.commit_checks,
                &plan.adv_shas,
                &upstream_commits,
            )
            .await?;
            return Ok::<(u64, Option<Denied>), std::io::Error>((n, verdict.err()));
        }
        let stdin = upstream_stdin.as_mut().expect("taken once");
        let mut total = 0u64;
        if !leftover.is_empty() {
            stdin.write_all(&leftover).await?;
            total += leftover.len() as u64;
            sent.store(total, Ordering::Relaxed);
            wd.touch();
        }
        if has_commands {
            let base = total;
            let streamed = AtomicU64::new(0);
            let r = async {
                let n = copy_touch_counted(&mut io.stdin, &mut *stdin, &wd, true, &streamed).await;
                sent.store(base + streamed.load(Ordering::Relaxed), Ordering::Relaxed);
                n
            }
            .await;
            total += r?;
        } else {
            stdin.flush().await?;
        }
        // Closes the pipe: the EOF the upstream reads once the client has sent everything
        upstream_stdin.take();
        sent.store(total, Ordering::Relaxed);
        Ok((total, None))
    };
    let stdout = &mut io.stdout;
    let resp_fut = async {
        let mut total = 0u64;
        let mut out = Vec::new();
        loop {
            match up_reader.next().await? {
                Some(frame) => {
                    out.clear();
                    rewriter.feed(&frame, &mut out)?;
                    stdout.write_all(&out).await?;
                    total += out.len() as u64;
                    wd.touch();
                }
                None => {
                    out.clear();
                    rewriter.finish(&mut out)?;
                    stdout.write_all(&out).await?;
                    stdout.flush().await?;
                    total += out.len() as u64;
                    return Ok::<u64, std::io::Error>(total);
                }
            }
        }
    };
    let (bytes_in, bytes_out, note, pack_denied) = tokio::select! {
        r = async { tokio::join!(pack_fut, resp_fut) } => {
            let (i, o) = r;
            let (bytes_in, denied) = i.unwrap_or((0, None));
            (bytes_in, o.unwrap_or(0), None, denied)
        }
        _ = wd.expired() => {
            let _ = proc.child.start_kill();
            // What did reach upstream before it went quiet, not zero.
            (sent.load(Ordering::Relaxed), 0, Some("idle_timeout".to_string()), None)
        }
    };

    // ---- E ----
    let status = match proc.child.wait().await {
        Ok(s) => exit_code_of(s),
        Err(_) => 1,
    };
    flush_upstream_stderr(io, stderr_task).await;
    if note.is_some() {
        say(
            io,
            "push timed out (no data for too long) and was terminated",
        )
        .await;
        return RelayOutcome {
            status: 1,
            bytes_in,
            bytes_out,
            note,
        };
    }
    if let Some(d) = pack_denied {
        // The upstream has already said ng (it got a pack without a trailer); this is the why.
        let msg = d.to_string();
        say(io, &msg).await;
        ctx.audit.deny(
            &format!("push_denied_{}", d.kind()),
            Actor::Agent,
            &msg,
            &[("repo", auth.repo()), ("project", auth.project())],
        );
        return RelayOutcome {
            status: 1,
            bytes_in,
            bytes_out,
            note: Some(format!("policy_{}", d.kind())),
        };
    }
    if status == 255 {
        say(
            io,
            "upstream ssh connection failed (see the ssh error above)",
        )
        .await;
        return RelayOutcome {
            status: 1,
            bytes_in,
            bytes_out,
            note: Some("ssh_failed".into()),
        };
    }
    let mut status = status;
    if status == 0 && !plan.prs.is_empty() {
        let results = rewriter.results();
        for pr in &plan.prs {
            if report_status {
                match results.get(&pr.client_ref) {
                    Some(RefStatus::Ok) => {}
                    Some(RefStatus::Ng(msg)) => {
                        say(
                            io,
                            &format!(
                                "not creating a PR for {}: upstream rejected the push ({msg})",
                                pr.client_ref
                            ),
                        )
                        .await;
                        status = 1;
                        continue;
                    }
                    None => {
                        say(
                            io,
                            &format!(
                                "not creating a PR for {}: no status reported by upstream",
                                pr.client_ref
                            ),
                        )
                        .await;
                        status = 1;
                        continue;
                    }
                }
            }
            if !create_pr(io, ctx, auth, pr).await {
                status = 1;
            }
        }
    }
    RelayOutcome {
        status,
        bytes_in,
        bytes_out,
        note: None,
    }
}

/// The report-status for a push denied by policy: `unpack ok` plus an `ng <ref> <reason>` for every ref.
/// If side-band-64k was requested, wrap it in band 1, one pkt at a time, so a long reason still stays under the limit.
fn reject_report(section: &CommandSection<'_>, reason: &str, sideband: bool) -> Vec<u8> {
    let reason = reason.replace(['\n', '\r'], " ");
    let mut inner: Vec<Vec<u8>> = vec![b"unpack ok\n".to_vec()];
    for u in section.updates() {
        inner.push(format!("ng {} {}\n", u.name, reason).into_bytes());
    }
    let mut out = Vec::new();
    if sideband {
        for line in inner {
            let mut pkt = Vec::new();
            let _ = encode_into(&mut pkt, &line);
            let mut band = vec![1u8];
            band.extend_from_slice(&pkt);
            let _ = encode_into(&mut out, &band);
        }
        let _ = encode_into(&mut out, b"\x010000");
        out.extend_from_slice(b"0000");
    } else {
        for line in inner {
            let _ = encode_into(&mut out, &line);
        }
        out.extend_from_slice(b"0000");
    }
    out
}

/// Report through stderr alone, for use while the client-side reader holds stdin.
async fn say_err(stderr: &mut Box<dyn tokio::io::AsyncWrite + Send + Unpin + '_>, msg: &str) {
    let _ = stderr
        .write_all(format!("sekimore: {msg}\n").as_bytes())
        .await;
    let _ = stderr.flush().await;
}

/// Forward the upstream stderr (collected by a separate task) to the client.
async fn flush_upstream_stderr(io: &mut GitIo<'_>, task: Option<tokio::task::JoinHandle<Vec<u8>>>) {
    if let Some(t) = task {
        if let Ok(sink) = t.await {
            if !sink.is_empty() {
                let _ = io.stderr.write_all(&sink).await;
                let _ = io.stderr.flush().await;
            }
        }
    }
}

/// Create the PR. Returns true on success, including when the PR already exists.
async fn create_pr(
    io: &mut GitIo<'_>,
    ctx: &GitContext,
    auth: &GitAuthorized<'_>,
    pr: &PrIntent,
) -> bool {
    let Some(gh) = &ctx.github else {
        say(
            io,
            &format!(
                "push of {} accepted, but PR creation is not configured on the gateway",
                pr.client_ref
            ),
        )
        .await;
        return false;
    };
    // `refs/pr/<branch>` names no base, so the default branch stands in. Resolved before the
    // proof is taken, because `bases` has to be checked against the base actually used (#158).
    let base = match &pr.base {
        Some(b) => b.clone(),
        None => match gh.default_branch(auth).await {
            Ok(b) => b,
            Err(e) => {
                say(
                    io,
                    &format!("push of {} accepted, but the default branch could not be read, so no PR was opened: {e}", pr.client_ref),
                )
                .await;
                return false;
            }
        },
    };
    // Re-obtain the proof (plan_push already checked it; this can only fail if the policy changed since).
    // For `refs/pr/` this is the first time `bases` sees the base at all, since it was not known
    // when the push was planned.
    let api_auth = match ctx.project.authorize_pr_for(auth, &base) {
        Ok(a) => a,
        Err(d) => {
            say(io, &format!("push ok but PR creation refused: {d}")).await;
            return false;
        }
    };
    let title = format!("[agent] {} → {}", pr.head_branch, base);
    let body = format!(
        "Created via sekimore-relay (`{}`). Pushed by an AI agent through the gateway.\n\nCommit: {}",
        pr.client_ref, pr.sha
    );
    match gh
        .create_pull_request(&api_auth, &pr.head_branch, &base, &title, &body)
        .await
    {
        Ok(r) => {
            say(io, &format!("created PR #{} {}", r.number, r.html_url)).await;
            ctx.audit.log(
                "pr_created",
                Actor::Agent,
                &[
                    ("repo", auth.repo()),
                    ("head", &pr.head_branch),
                    ("base", &base),
                    ("number", &r.number.to_string()),
                ],
            );
            true
        }
        Err(GhError::Status { status: 422, .. }) => match gh
            .find_pull_request(&api_auth, &pr.head_branch, &base)
            .await
        {
            Ok(Some(existing)) => {
                say(
                    io,
                    &format!(
                        "PR already exists: #{} {}",
                        existing.number, existing.html_url
                    ),
                )
                .await;
                ctx.audit.log(
                    "pr_exists",
                    Actor::Agent,
                    &[
                        ("repo", auth.repo()),
                        ("head", &pr.head_branch),
                        ("number", &existing.number.to_string()),
                    ],
                );
                true
            }
            Ok(None) => {
                say(io, "push ok but PR creation failed: upstream returned 422 and no matching open PR was found").await;
                ctx.audit.deny(
                    "pr_failed",
                    Actor::Agent,
                    "422 without existing PR",
                    &[("repo", auth.repo()), ("head", &pr.head_branch)],
                );
                false
            }
            Err(e) => {
                say(io, &format!("push ok but PR lookup failed: {e}")).await;
                ctx.audit.deny(
                    "pr_failed",
                    Actor::Agent,
                    &e.to_string(),
                    &[("repo", auth.repo()), ("head", &pr.head_branch)],
                );
                false
            }
        },
        Err(e) => {
            say(io, &format!("push ok but PR creation failed: {e}")).await;
            ctx.audit.deny(
                "pr_failed",
                Actor::Agent,
                &e.to_string(),
                &[("repo", auth.repo()), ("head", &pr.head_branch)],
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pktline::parse_receive_pack;
    use crate::policy::{GitVerb, Mode};

    const ZERO: &str = "0000000000000000000000000000000000000000";
    const SHA: &str = "abcdef1234567890abcdef1234567890abcdef12";
    const SHA2: &str = "1234567890abcdef1234567890abcdef12345678";

    fn pkt(payload: &str) -> Vec<u8> {
        let mut v = format!("{:04x}", payload.len() + 4).into_bytes();
        v.extend_from_slice(payload.as_bytes());
        v
    }

    fn project() -> Project {
        Project::new("case-a")
            .with_repo("LibOrg/awesome-lib", Mode::ReadWrite, &["main", "develop"])
            .with_repo("VendorOrg/reference-impl", Mode::ReadOnly, &[])
            .grant("pr:create")
    }

    fn section_of(lines: &[String]) -> Vec<u8> {
        let mut data = Vec::new();
        for (i, l) in lines.iter().enumerate() {
            let l = if i == 0 {
                format!("{l}\0report-status side-band-64k\n")
            } else {
                format!("{l}\n")
            };
            data.extend_from_slice(&pkt(&l));
        }
        data.extend_from_slice(b"0000");
        data
    }

    fn plan(lines: &[String], adv: &HashMap<String, String>) -> Result<PushPlan, Denied> {
        plan_opts(lines, adv, false, false)
    }

    fn plan_opts(
        lines: &[String],
        adv: &HashMap<String, String>,
        allow_delete: bool,
        allow_tags: bool,
    ) -> Result<PushPlan, Denied> {
        plan_with_tags(
            lines,
            adv,
            allow_delete,
            if allow_tags { &["*"] } else { &[] },
        )
    }

    /// The rewrite that makes `refs/for/<base>` into `sekimore/<base>-<sha7>` lands in the
    /// same namespace the agent may push to directly, and the sha is its own commit — so it
    /// can name the branch the rewrite is about to produce. Two updates to one upstream ref
    /// leave the report-status rewriter unable to say which result belongs to which client
    /// ref, and stage E would then decide whether to open the PR from the wrong one.
    #[test]
    fn a_direct_push_cannot_collide_with_the_branch_a_refs_for_rewrite_produces() {
        let head = format!("sekimore/main-{}", &SHA[..7]);
        let err = plan(
            &[
                format!("{ZERO} {SHA} refs/for/main"),
                format!("{ZERO} {SHA2} refs/heads/{head}"),
            ],
            &HashMap::new(),
        )
        .unwrap_err();
        assert!(
            matches!(&err, Denied::RefNotAllowed { reason, .. }
                if reason.contains("same upstream branch")),
            "{err}"
        );
        // and in the other order, so it is not an artefact of which one is seen first
        let err = plan(
            &[
                format!("{ZERO} {SHA2} refs/heads/{head}"),
                format!("{ZERO} {SHA} refs/for/main"),
            ],
            &HashMap::new(),
        )
        .unwrap_err();
        assert!(matches!(err, Denied::RefNotAllowed { .. }), "{err}");
    }

    #[test]
    fn the_same_ref_twice_in_one_push_is_refused() {
        for name in [
            "refs/heads/sekimore/topic",
            "refs/for/main",
            "refs/heads/sekimore/x",
        ] {
            let err = plan(
                &[
                    format!("{ZERO} {SHA} {name}"),
                    format!("{SHA} {SHA2} {name}"),
                ],
                &HashMap::new(),
            )
            .unwrap_err();
            assert!(matches!(err, Denied::RefNotAllowed { .. }), "{name}: {err}");
        }
    }

    #[test]
    fn distinct_refs_in_one_push_are_still_allowed() {
        // The check must not catch the ordinary case of pushing several branches at once.
        let plan = plan(
            &[
                format!("{ZERO} {SHA} refs/for/main"),
                format!("{ZERO} {SHA2} refs/for/develop"),
                format!("{ZERO} {SHA} refs/heads/sekimore/unrelated"),
            ],
            &HashMap::new(),
        )
        .expect("distinct refs");
        assert_eq!(plan.commands.len(), 3);
        assert_eq!(plan.prs.len(), 2);
    }

    /// #89: a tag creation is remembered for stage C to judge, unless the policy says not to.
    #[test]
    fn a_tag_creation_is_queued_for_judging_and_a_delete_is_not() {
        let pl = plan_opts(
            &[format!("{ZERO} {SHA} refs/tags/v1")],
            &HashMap::new(),
            false,
            true,
        )
        .unwrap();
        assert_eq!(
            pl.tag_checks,
            vec![TagCheck {
                name: "refs/tags/v1".into(),
                sha: SHA.into()
            }]
        );
        // a delete has no object to judge
        let adv = HashMap::from([("refs/tags/v1".to_string(), SHA.to_string())]);
        let pl = plan_opts(&[format!("{SHA} {ZERO} refs/tags/v1")], &adv, true, true).unwrap();
        assert!(pl.tag_checks.is_empty());
        // a branch push never is
        let pl = plan(
            &[format!("{ZERO} {SHA} refs/heads/sekimore/x")],
            &HashMap::new(),
        )
        .unwrap();
        assert!(pl.tag_checks.is_empty());
    }

    #[test]
    fn signed_tags_off_asks_nothing_of_the_pack() {
        let mut p = project();
        for r in &mut p.repos {
            r.tags = vec!["v*".to_string()];
            r.signed_tags = false;
        }
        let auth = p
            .authorize_git(GitVerb::ReceivePack, "LibOrg/awesome-lib.git")
            .unwrap();
        let data = section_of(&[format!("{ZERO} {SHA} refs/tags/v1")]);
        let sec = parse_receive_pack(&data).unwrap();
        let plan = plan_push(&p, &auth, &sec, &HashMap::new()).unwrap();
        assert!(plan.tag_checks.is_empty());
        assert_eq!(plan.commands.len(), 1);
    }

    #[test]
    fn a_branch_push_is_queued_for_judging_only_when_signing_is_required() {
        use crate::policy::SigningMode;
        let queued = |mode: SigningMode, line: String| {
            let mut p = project();
            for r in &mut p.repos {
                r.signing = mode;
            }
            let auth = p
                .authorize_git(GitVerb::ReceivePack, "LibOrg/awesome-lib.git")
                .unwrap();
            let data = section_of(&[line]);
            let sec = parse_receive_pack(&data).unwrap();
            plan_push(&p, &auth, &sec, &HashMap::new())
                .unwrap()
                .commit_checks
        };
        let branch = format!("{ZERO} {SHA} refs/heads/sekimore/x");
        assert_eq!(
            queued(SigningMode::Required, branch.clone()),
            vec![CommitCheck {
                name: "refs/heads/sekimore/x".into(),
                sha: SHA.into()
            }]
        );
        // refs/for goes to a branch too, so it is judged the same way
        assert_eq!(
            queued(SigningMode::Required, format!("{ZERO} {SHA} refs/for/main")).len(),
            1
        );
        // The default asks nothing of the pack, which is what keeps stage C streaming
        assert!(queued(SigningMode::Optional, branch.clone()).is_empty());
        assert!(queued(SigningMode::Off, branch).is_empty());
        // and a delete brings no commits
        let adv = HashMap::from([("refs/heads/sekimore/x".to_string(), SHA.to_string())]);
        let mut p = project();
        for r in &mut p.repos {
            r.signing = SigningMode::Required;
            r.delete = true;
        }
        let auth = p
            .authorize_git(GitVerb::ReceivePack, "LibOrg/awesome-lib.git")
            .unwrap();
        let data = section_of(&[format!("{SHA} {ZERO} refs/heads/sekimore/x")]);
        let sec = parse_receive_pack(&data).unwrap();
        assert!(plan_push(&p, &auth, &sec, &adv)
            .unwrap()
            .commit_checks
            .is_empty());
    }

    mod judging {
        use super::super::{judge_pack, CommitCheck};
        use super::*;
        use crate::git::pack::testutil::{commit_body, pack, sha_of, tag_body, Entry, COMMIT};
        use crate::git::pack::{PackError, PackScan};

        fn scan(bytes: &[u8]) -> Result<crate::git::pack::Objects, PackError> {
            let mut s = PackScan::new();
            s.feed(bytes);
            s.finish()
        }
        /// An upstream that holds exactly the shas it was given, and can be made to fail.
        struct FakeUpstream {
            has: HashSet<String>,
            error: Option<String>,
            asked: std::sync::Mutex<Vec<String>>,
        }
        impl FakeUpstream {
            fn holding(shas: &[&str]) -> Self {
                FakeUpstream {
                    has: shas.iter().map(|s| s.to_string()).collect(),
                    error: None,
                    asked: std::sync::Mutex::new(Vec::new()),
                }
            }
            fn broken() -> Self {
                FakeUpstream {
                    has: HashSet::new(),
                    error: Some("the secret store is locked".into()),
                    asked: std::sync::Mutex::new(Vec::new()),
                }
            }
            fn asked(&self) -> Vec<String> {
                self.asked.lock().unwrap().clone()
            }
        }
        #[async_trait::async_trait]
        impl super::super::UpstreamCommits for FakeUpstream {
            async fn has_commit(&self, sha: &str) -> Result<bool, String> {
                self.asked.lock().unwrap().push(sha.to_string());
                match &self.error {
                    Some(e) => Err(e.clone()),
                    None => Ok(self.has.contains(sha)),
                }
            }
        }

        /// The tag half of `judge_pack`, which is what these cases are about.
        fn judge_tags(
            scanned: Result<crate::git::pack::Objects, PackError>,
            checks: &[TagCheck],
        ) -> Result<(), Denied> {
            block_on(judge_pack(
                scanned,
                checks,
                &[],
                &HashSet::new(),
                &FakeUpstream::holding(&[]),
            ))
        }
        /// The commit half. The upstream holds nothing unless a case says otherwise, so a walk
        /// that leaves the pack has to justify itself.
        fn judge_commits(
            scanned: Result<crate::git::pack::Objects, PackError>,
            checks: &[CommitCheck],
            adv: &[&str],
        ) -> Result<(), Denied> {
            judge_commits_with(scanned, checks, adv, &FakeUpstream::holding(&[]))
        }
        fn judge_commits_with(
            scanned: Result<crate::git::pack::Objects, PackError>,
            checks: &[CommitCheck],
            adv: &[&str],
            upstream: &dyn super::super::UpstreamCommits,
        ) -> Result<(), Denied> {
            let adv: HashSet<String> = adv.iter().map(|s| s.to_string()).collect();
            block_on(judge_pack(scanned, &[], checks, &adv, upstream))
        }
        /// These cases are about the judgement, not about concurrency; a current-thread runtime
        /// keeps them ordinary `#[test]`s.
        fn block_on<F: std::future::Future>(f: F) -> F::Output {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(f)
        }
        fn branch(sha: &str) -> Vec<CommitCheck> {
            vec![CommitCheck {
                name: "refs/heads/sekimore/topic".into(),
                sha: sha.into(),
            }]
        }
        fn why_commit(r: Result<(), Denied>) -> (String, String) {
            match r {
                Err(Denied::CommitNotSigned { name, sha, reason }) => {
                    assert_eq!(name, "refs/heads/sekimore/topic");
                    (sha, reason)
                }
                other => panic!("expected CommitNotSigned, got {other:?}"),
            }
        }
        fn check(sha: &str) -> Vec<TagCheck> {
            vec![TagCheck {
                name: "refs/tags/v1".into(),
                sha: sha.into(),
            }]
        }
        fn reason(r: Result<(), Denied>) -> String {
            match r {
                Err(Denied::TagNotSigned { name, reason }) => {
                    assert_eq!(name, "refs/tags/v1");
                    reason
                }
                other => panic!("expected TagNotSigned, got {other:?}"),
            }
        }

        #[test]
        fn a_signed_tag_object_passes() {
            let tag = tag_body("v1", &sha_of("commit", COMMIT), true);
            let p = pack(&[Entry::Whole(1, COMMIT), Entry::Whole(4, &tag)]);
            assert_eq!(judge_tags(scan(&p), &check(&sha_of("tag", &tag))), Ok(()));
        }

        #[test]
        fn an_unsigned_annotated_tag_is_named_as_such() {
            let tag = tag_body("v1", &sha_of("commit", COMMIT), false);
            let p = pack(&[Entry::Whole(4, &tag)]);
            let why = reason(judge_tags(scan(&p), &check(&sha_of("tag", &tag))));
            assert!(why.contains("without a signature"), "{why}");
        }

        #[test]
        fn a_lightweight_tag_is_named_as_such() {
            // The name points at the commit itself, which is in the pack
            let p = pack(&[Entry::Whole(1, COMMIT)]);
            let why = reason(judge_tags(scan(&p), &check(&sha_of("commit", COMMIT))));
            assert!(why.contains("lightweight"), "{why}");
            assert!(why.contains("commit"), "{why}");
        }

        #[test]
        fn a_tag_whose_object_is_not_in_the_pack_is_refused_not_assumed() {
            // The common lightweight case: the commit is already upstream, so the pack is empty
            let p = pack(&[]);
            let why = reason(judge_tags(scan(&p), &check(&sha_of("commit", COMMIT))));
            assert!(why.contains("not in this push"), "{why}");
            assert!(!why.contains("--no-thin"), "no delta was involved: {why}");
        }

        #[test]
        fn an_unresolved_delta_earns_the_no_thin_hint() {
            let delta = crate::git::pack::testutil::insert_only_delta(b"base", b"result");
            let p = pack(&[Entry::RefDelta {
                base_sha: [9u8; 20],
                delta: &delta,
            }]);
            let why = reason(judge_tags(scan(&p), &check(&sha_of("tag", b"whatever"))));
            assert!(why.contains("--no-thin"), "{why}");
        }

        #[test]
        fn a_pack_that_cannot_be_read_fails_closed() {
            let why = reason(judge_tags(Err(PackError::Truncated), &check(SHA)));
            assert!(why.contains("could not be read"), "{why}");
            assert!(why.contains("ended early"), "{why}");
        }

        // ---- #59: commits ----

        #[test]
        fn a_branch_of_signed_commits_passes() {
            let a = commit_body(&[], true, "one");
            let b = commit_body(&[&sha_of("commit", &a)], true, "two");
            let p = pack(&[Entry::Whole(1, &a), Entry::Whole(1, &b)]);
            assert_eq!(
                judge_commits(scan(&p), &branch(&sha_of("commit", &b)), &[]),
                Ok(())
            );
        }

        #[test]
        fn one_unsigned_commit_anywhere_in_the_new_history_refuses_the_push() {
            // The tip is signed and the commit under it is not: checking only the tip would let
            // this through, which is the shape a rebase-and-amend leaves behind.
            let a = commit_body(&[], false, "unsigned");
            let b = commit_body(&[&sha_of("commit", &a)], true, "signed tip");
            let p = pack(&[Entry::Whole(1, &a), Entry::Whole(1, &b)]);
            let (sha, why) =
                why_commit(judge_commits(scan(&p), &branch(&sha_of("commit", &b)), &[]));
            assert_eq!(sha, sha_of("commit", &a));
            assert!(why.contains("no signature"), "{why}");
        }

        #[test]
        fn history_the_upstream_already_has_is_not_this_pushs_to_answer_for() {
            // The parent is not in the pack and the upstream confirms it holds it: an unsigned
            // commit from before the policy was turned on must not block every later push. This
            // is "branch off main~3" — the ordinary shape, and the one that must not be refused.
            let old = commit_body(&[], false, "from before");
            let old_sha = sha_of("commit", &old);
            let new = commit_body(&[&old_sha], true, "new work");
            let p = pack(&[Entry::Whole(1, &new)]);
            let up = FakeUpstream::holding(&[&old_sha]);
            assert_eq!(
                judge_commits_with(scan(&p), &branch(&sha_of("commit", &new)), &[], &up),
                Ok(())
            );
            assert_eq!(
                up.asked(),
                vec![old_sha.clone()],
                "one call, at the boundary"
            );

            // and the same when it *is* in the pack but the advertisement names it — no call at
            // all, because the advertisement already said so
            let p = pack(&[Entry::Whole(1, &old), Entry::Whole(1, &new)]);
            let up = FakeUpstream::holding(&[]);
            assert_eq!(
                judge_commits_with(scan(&p), &branch(&sha_of("commit", &new)), &[&old_sha], &up),
                Ok(())
            );
            assert!(up.asked().is_empty(), "{:?}", up.asked());
        }

        #[test]
        fn a_commit_hidden_behind_a_delta_on_an_upstream_base_does_not_pass_for_upstream_history() {
            // The bypass. `git push` does not build this — `pack-objects` only ever offers trees
            // and blobs as thin bases — but the client is an agent and the pack is whatever it
            // sent. A REF_DELTA against any commit the upstream already has leaves the tip absent
            // from `by_sha`, which is indistinguishable from "the upstream has it" unless someone
            // asks. So the relay asks, and the upstream says no.
            let unsigned = commit_body(&[], false, "not signed");
            let tip = sha_of("commit", &unsigned);
            let delta = crate::git::pack::testutil::insert_only_delta(b"base", &unsigned);
            let p = pack(&[Entry::RefDelta {
                base_sha: [7u8; 20],
                delta: &delta,
            }]);
            let up = FakeUpstream::holding(&[]);
            let (sha, why) = why_commit(judge_commits_with(scan(&p), &branch(&tip), &[], &up));
            assert_eq!(sha, tip);
            assert!(why.contains("not on the upstream"), "{why}");
            assert!(why.contains("--no-thin"), "{why}");
            assert_eq!(up.asked(), vec![tip.clone()]);

            // The very same pack is accepted once the upstream confirms the sha is its own
            // history — which is what makes the refusal above about the answer, not the shape
            let up = FakeUpstream::holding(&[&tip]);
            assert_eq!(
                judge_commits_with(scan(&p), &branch(&tip), &[], &up),
                Ok(())
            );
        }

        #[test]
        fn a_boundary_the_upstream_cannot_be_asked_about_fails_closed() {
            // The store is locked after a restart, so the API cannot answer. "Cannot tell" is a
            // refusal, and the message has to send the operator to the command that fixes it.
            let old = commit_body(&[], true, "upstream history");
            let new = commit_body(&[&sha_of("commit", &old)], true, "new work");
            let p = pack(&[Entry::Whole(1, &new)]);
            let (_, why) = why_commit(judge_commits_with(
                scan(&p),
                &branch(&sha_of("commit", &new)),
                &[],
                &FakeUpstream::broken(),
            ));
            assert!(why.contains("the secret store is locked"), "{why}");
            assert!(why.contains("gw:unlock"), "{why}");
        }

        #[test]
        fn a_push_cannot_make_the_relay_ask_the_upstream_without_end() {
            // A pack whose commits all name parents that are nowhere. An honest push asks once.
            let mut entries = Vec::new();
            let bodies: Vec<Vec<u8>> = (0..40)
                .map(|i| commit_body(&[&format!("{:040x}", i + 1)], true, "signed"))
                .collect();
            for b in &bodies {
                entries.push(Entry::Whole(1, b));
            }
            // one ref per commit, so the walk reaches every one of those parents
            let checks: Vec<CommitCheck> = bodies
                .iter()
                .enumerate()
                .map(|(i, b)| CommitCheck {
                    name: format!("refs/heads/sekimore/topic{i}"),
                    sha: sha_of("commit", b),
                })
                .collect();
            let up = FakeUpstream::holding(
                &(0..40)
                    .map(|i| format!("{:040x}", i + 1))
                    .collect::<Vec<_>>()
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>(),
            );
            let p = pack(&entries);
            let e = judge_commits_with(scan(&p), &checks, &[], &up).unwrap_err();
            assert!(e.to_string().contains("more than 32"), "{e}");
            assert!(up.asked().len() <= 32, "{}", up.asked().len());
        }

        #[test]
        fn a_merge_is_walked_down_both_sides() {
            let base = commit_body(&[], true, "base");
            let left = commit_body(&[&sha_of("commit", &base)], true, "left");
            let right = commit_body(&[&sha_of("commit", &base)], false, "right, unsigned");
            let merge = commit_body(
                &[&sha_of("commit", &left), &sha_of("commit", &right)],
                true,
                "merge",
            );
            let p = pack(&[
                Entry::Whole(1, &base),
                Entry::Whole(1, &left),
                Entry::Whole(1, &right),
                Entry::Whole(1, &merge),
            ]);
            let (sha, _) = why_commit(judge_commits(
                scan(&p),
                &branch(&sha_of("commit", &merge)),
                &[],
            ));
            assert_eq!(
                sha,
                sha_of("commit", &right),
                "the second parent counts too"
            );
        }

        #[test]
        fn a_cycle_in_the_parents_does_not_hang_the_walk() {
            // Not something git makes, but the walk reads shas out of a pack the client wrote.
            let a = commit_body(&[], true, "a");
            let sha_a = sha_of("commit", &a);
            let b = commit_body(&[&sha_a], true, "b");
            let a2 = commit_body(&[&sha_of("commit", &b)], true, "a");
            let p = pack(&[Entry::Whole(1, &a2), Entry::Whole(1, &b)]);
            assert_eq!(
                judge_commits_with(
                    scan(&p),
                    &branch(&sha_of("commit", &a2)),
                    &[],
                    &FakeUpstream::holding(&[&sha_a])
                ),
                Ok(())
            );
        }

        #[test]
        fn two_signed_commits_one_a_delta_on_the_other_go_through() {
            // #140: what `git push` of two alike commits sends. It used to be refused whatever
            // the commits were, because the scan had no base to apply the delta to.
            let a = commit_body(&[], true, "one");
            let b = commit_body(&[&sha_of("commit", &a)], true, "two");
            let delta = crate::git::pack::testutil::insert_only_delta(&a, &b);
            let p = pack(&[
                Entry::Whole(1, &a),
                Entry::OfsDelta {
                    back: 1,
                    delta: &delta,
                },
            ]);
            assert_eq!(
                judge_commits(scan(&p), &branch(&sha_of("commit", &b)), &[]),
                Ok(())
            );
        }

        #[test]
        fn an_unsigned_commit_behind_a_delta_on_a_signed_one_is_refused() {
            // Resolving the delta must judge its result: an unsigned commit built from a signed
            // base is an unsigned commit.
            let a = commit_body(&[], true, "one");
            let b = commit_body(&[&sha_of("commit", &a)], false, "two");
            let delta = crate::git::pack::testutil::insert_only_delta(&a, &b);
            let p = pack(&[
                Entry::Whole(1, &a),
                Entry::OfsDelta {
                    back: 1,
                    delta: &delta,
                },
            ]);
            let (sha, why) =
                why_commit(judge_commits(scan(&p), &branch(&sha_of("commit", &b)), &[]));
            assert_eq!(sha, sha_of("commit", &b));
            assert!(why.contains("no signature"), "{why}");
        }

        #[test]
        fn a_commit_delta_on_a_base_too_large_to_keep_fails_closed() {
            // A commit over the keep cap is read from its header block and not kept, so a delta
            // against it cannot be applied — and an unreadable commit must not pass for a signed
            // one. The hint is the one that works for this case, not --no-thin.
            let a = commit_body(&[], true, &"x".repeat(1024 * 1024));
            let b = commit_body(&[&sha_of("commit", &a)], true, "two");
            let delta = crate::git::pack::testutil::insert_only_delta(&a, &b);
            let p = pack(&[
                Entry::Whole(1, &a),
                Entry::OfsDelta {
                    back: 1,
                    delta: &delta,
                },
            ]);
            let (_, why) = why_commit(judge_commits(scan(&p), &branch(&sha_of("commit", &a)), &[]));
            assert!(why.contains("pack.window=0"), "{why}");
            assert!(!why.contains("--no-thin"), "{why}");
        }

        #[test]
        fn an_unresolved_tree_or_blob_delta_is_not_a_commit_and_does_not_refuse() {
            // Thin packs delta against the upstream's trees and blobs on every ordinary push.
            // Treating those as "might be a commit" would refuse nearly everything.
            let a = commit_body(&[], true, "one");
            let delta = crate::git::pack::testutil::insert_only_delta(b"base", b"result");
            let p = pack(&[
                Entry::Whole(1, &a),
                Entry::RefDelta {
                    base_sha: [9u8; 20],
                    delta: &delta,
                },
            ]);
            assert_eq!(
                judge_commits(scan(&p), &branch(&sha_of("commit", &a)), &[]),
                Ok(())
            );
        }

        #[test]
        fn a_pack_that_cannot_be_read_refuses_the_branch_too() {
            let (_, why) = why_commit(judge_commits(Err(PackError::Truncated), &branch(SHA), &[]));
            assert!(why.contains("could not be read"), "{why}");
        }

        #[test]
        fn every_tag_in_the_push_has_to_pass() {
            let target = sha_of("commit", COMMIT);
            let good = tag_body("v1", &target, true);
            let bad = tag_body("v2", &target, false);
            let p = pack(&[Entry::Whole(4, &good), Entry::Whole(4, &bad)]);
            let checks = vec![
                TagCheck {
                    name: "refs/tags/v1".into(),
                    sha: sha_of("tag", &good),
                },
                TagCheck {
                    name: "refs/tags/v2".into(),
                    sha: sha_of("tag", &bad),
                },
            ];
            match judge_tags(scan(&p), &checks) {
                Err(Denied::TagNotSigned { name, .. }) => assert_eq!(name, "refs/tags/v2"),
                other => panic!("{other:?}"),
            }
        }

        #[test]
        fn the_message_tells_the_operator_both_ways_out() {
            let why = Denied::TagNotSigned {
                name: "refs/tags/v1".into(),
                reason: "x".into(),
            }
            .to_string();
            assert!(why.contains("git tag -s"), "{why}");
            assert!(why.contains("signed_tags: false"), "{why}");
        }
    }

    /// 0.1.9: tags and deletes are governed by the repo's policy (project.tags / repos[].tags, delete)
    fn plan_with_tags(
        lines: &[String],
        adv: &HashMap<String, String>,
        allow_delete: bool,
        tag_globs: &[&str],
    ) -> Result<PushPlan, Denied> {
        let mut p = project();
        for r in &mut p.repos {
            r.delete = allow_delete;
            r.tags = tag_globs.iter().map(|s| s.to_string()).collect();
        }
        let auth = p
            .authorize_git(GitVerb::ReceivePack, "LibOrg/awesome-lib.git")
            .unwrap();
        let data = section_of(lines);
        let sec = parse_receive_pack(&data).unwrap();
        plan_push(&p, &auth, &sec, adv)
    }

    /// A plan with the project's branch naming and push globs set (#158).
    fn plan_named(
        lines: &[String],
        adv: &HashMap<String, String>,
        push: &[&str],
        template: &str,
        on_exists: OnExists,
    ) -> Result<PushPlan, Denied> {
        let mut p = project();
        p.branch = crate::config::BranchConfig {
            template: template.to_string(),
            on_exists,
        };
        for r in &mut p.repos {
            r.push = push.iter().map(|s| s.to_string()).collect();
            // `refs/pr/` opens against the default branch, so these cases leave the base open;
            // the one that does not has its own test below.
            r.bases = vec![];
        }
        let auth = p
            .authorize_git(GitVerb::ReceivePack, "LibOrg/awesome-lib.git")
            .unwrap();
        let data = section_of(lines);
        let sec = parse_receive_pack(&data).unwrap();
        plan_push(&p, &auth, &sec, adv)
    }

    const CONV: &[&str] = &["feature/*", "fix/*", "chore/*"];

    /// #158: the agent names the branch, and it is the name that reaches upstream — no prefix
    /// added, no sha appended.
    #[test]
    fn refs_pr_pushes_the_branch_the_agent_named() {
        let pl = plan_named(
            &[format!("{ZERO} {SHA} refs/pr/feature/login")],
            &HashMap::new(),
            CONV,
            "sekimore/{branch}-{sha}",
            OnExists::Reject,
        )
        .unwrap();
        assert_eq!(pl.prs.len(), 1);
        assert_eq!(pl.prs[0].head_branch, "feature/login");
        assert_eq!(pl.prs[0].upstream_ref, "refs/heads/feature/login");
        // No base is named; stage E resolves the default branch.
        assert_eq!(pl.prs[0].base, None);
        assert_eq!(
            pl.rewrites["refs/heads/feature/login"],
            "refs/pr/feature/login"
        );
        assert_eq!(
            pl.commands[0],
            OwnedCommand::Update {
                old: ZERO.into(),
                new: SHA.into(),
                name: "refs/heads/feature/login".into()
            }
        );
    }

    /// A slash in the name is not a separator: everything after the prefix is the branch.
    #[test]
    fn refs_pr_keeps_every_slash_in_the_name() {
        let pl = plan_named(
            &[format!("{ZERO} {SHA} refs/pr/fix/crash/in/parser")],
            &HashMap::new(),
            &["fix/*"],
            "sekimore/{branch}-{sha}",
            OnExists::Reject,
        )
        .unwrap();
        assert_eq!(pl.prs[0].head_branch, "fix/crash/in/parser");
    }

    /// The same globs a direct push goes through decide whether the name may be used.
    #[test]
    fn refs_pr_refuses_a_name_outside_the_push_globs() {
        let err = plan_named(
            &[format!("{ZERO} {SHA} refs/pr/hotfix/x")],
            &HashMap::new(),
            CONV,
            "sekimore/{branch}-{sha}",
            OnExists::Reject,
        )
        .unwrap_err();
        match err {
            Denied::RefNotAllowed { name, .. } => assert_eq!(name, "refs/pr/hotfix/x"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn refs_pr_cannot_be_deleted() {
        let err = plan_named(
            &[format!("{SHA} {ZERO} refs/pr/feature/login")],
            &HashMap::new(),
            CONV,
            "sekimore/{branch}-{sha}",
            OnExists::Reject,
        )
        .unwrap_err();
        match err {
            Denied::RefNotAllowed { reason, .. } => assert!(reason.contains("cannot be deleted")),
            other => panic!("{other:?}"),
        }
    }

    /// The agent chose the name, so an existing one is someone else's work.
    #[test]
    fn refs_pr_refuses_a_name_already_upstream() {
        let adv = HashMap::from([("refs/heads/feature/login".to_string(), SHA2.to_string())]);
        let err = plan_named(
            &[format!("{ZERO} {SHA} refs/pr/feature/login")],
            &adv,
            CONV,
            "sekimore/{branch}-{sha}",
            OnExists::Reject,
        )
        .unwrap_err();
        match err {
            Denied::BranchExists { branch, .. } => assert_eq!(branch, "feature/login"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn refs_pr_updates_a_name_already_upstream_when_asked_to() {
        let adv = HashMap::from([("refs/heads/feature/login".to_string(), SHA2.to_string())]);
        let pl = plan_named(
            &[format!("{ZERO} {SHA} refs/pr/feature/login")],
            &adv,
            CONV,
            "sekimore/{branch}-{sha}",
            OnExists::Update,
        )
        .unwrap();
        // The update starts from what is upstream, not from the zero the client sent.
        assert_eq!(
            pl.commands[0],
            OwnedCommand::Update {
                old: SHA2.into(),
                new: SHA.into(),
                name: "refs/heads/feature/login".into()
            }
        );
    }

    /// #158: the collision `claim` exists to stop, reached the new way round — a `refs/pr/`
    /// name and a direct push naming the same upstream branch. Two updates to one ref leave the
    /// report-status rewriter unable to say which result belongs to which client ref.
    #[test]
    fn a_refs_pr_name_cannot_collide_with_a_direct_push() {
        let err = plan_named(
            &[
                format!("{ZERO} {SHA} refs/pr/feature/login"),
                format!("{ZERO} {SHA2} refs/heads/feature/login"),
            ],
            &HashMap::new(),
            CONV,
            "sekimore/{branch}-{sha}",
            OnExists::Reject,
        )
        .unwrap_err();
        match err {
            Denied::RefNotAllowed { reason, .. } => {
                assert!(reason.contains("same upstream branch"), "{reason}")
            }
            other => panic!("{other:?}"),
        }
    }

    /// A name that git would refuse as a ref must not reach upstream. `..` is caught when the
    /// command section is parsed, the rest when the rewritten name is validated; either way the
    /// push is refused, which is what matters.
    #[test]
    fn refs_pr_refuses_a_name_git_would_not_accept() {
        for bad in ["feature/..x", "feature/x.lock", "feature/.hidden"] {
            let data = section_of(&[format!("{ZERO} {SHA} refs/pr/{bad}")]);
            let refused = match parse_receive_pack(&data) {
                Err(_) => true,
                Ok(sec) => {
                    let mut p = project();
                    for r in &mut p.repos {
                        r.push = CONV.iter().map(|s| s.to_string()).collect();
                        r.bases = vec![];
                    }
                    let auth = p
                        .authorize_git(GitVerb::ReceivePack, "LibOrg/awesome-lib.git")
                        .unwrap();
                    plan_push(&p, &auth, &sec, &HashMap::new()).is_err()
                }
            };
            assert!(refused, "{bad} was not refused");
        }
    }

    /// #158: `refs/pr/` cannot tell, while planning, which base it will open against — the
    /// advertisement carries no symref for HEAD and planning is offline. A repository that
    /// restricts `bases` would have that check land only after the branch reached upstream, so
    /// the spelling is refused before anything is sent.
    #[test]
    fn refs_pr_is_refused_when_bases_is_restricted() {
        let mut p = project();
        for r in &mut p.repos {
            r.push = vec!["feature/*".into()];
            r.bases = vec!["develop".into()];
        }
        let auth = p
            .authorize_git(GitVerb::ReceivePack, "LibOrg/awesome-lib.git")
            .unwrap();
        let data = section_of(&[format!("{ZERO} {SHA} refs/pr/feature/login")]);
        let sec = parse_receive_pack(&data).unwrap();
        match plan_push(&p, &auth, &sec, &HashMap::new()).unwrap_err() {
            Denied::RefNotAllowed { reason, .. } => assert!(reason.contains("bases"), "{reason}"),
            other => panic!("{other:?}"),
        }
    }

    /// #158: a project that does not want the string `sekimore` in its history can say so.
    #[test]
    fn refs_for_follows_the_projects_template() {
        let pl = plan_named(
            &[format!("{ZERO} {SHA} refs/for/main")],
            &HashMap::new(),
            &["agent/*"],
            "agent/{base}-{sha}",
            OnExists::Reject,
        )
        .unwrap();
        assert_eq!(pl.prs[0].head_branch, "agent/main-abcdef1");
        assert_eq!(pl.prs[0].upstream_ref, "refs/heads/agent/main-abcdef1");
        assert_eq!(pl.prs[0].base.as_deref(), Some("main"));
    }

    /// A template with no `{sha}` names a branch that is not unique to this commit, so an
    /// existing one is refused rather than updated.
    #[test]
    fn a_template_without_a_sha_refuses_a_branch_already_upstream() {
        let adv = HashMap::from([("refs/heads/agent/main".to_string(), SHA2.to_string())]);
        let err = plan_named(
            &[format!("{ZERO} {SHA} refs/for/main")],
            &adv,
            &["agent/*"],
            "agent/{branch}",
            OnExists::Reject,
        )
        .unwrap_err();
        match err {
            Denied::BranchExists { branch, .. } => assert_eq!(branch, "agent/main"),
            other => panic!("{other:?}"),
        }
    }

    /// AC-4.5.6 asks that re-pushing the same commit be idempotent. A `{sha}` template names a
    /// branch only that commit can land on, so `on_exists: reject` must not break it.
    #[test]
    fn a_sha_template_still_repushes_the_same_commit() {
        let adv = HashMap::from([(
            "refs/heads/sekimore/main-abcdef1".to_string(),
            SHA.to_string(),
        )]);
        let pl = plan_named(
            &[format!("{ZERO} {SHA} refs/for/main")],
            &adv,
            &["sekimore/*"],
            "sekimore/{branch}-{sha}",
            OnExists::Reject,
        )
        .unwrap();
        assert_eq!(pl.prs[0].head_branch, "sekimore/main-abcdef1");
    }

    #[test]
    fn refs_for_maps_to_sekimore_branch_with_sha7() {
        let pl = plan(&[format!("{ZERO} {SHA} refs/for/main")], &HashMap::new()).unwrap();
        assert_eq!(pl.prs.len(), 1);
        assert_eq!(pl.prs[0].head_branch, "sekimore/main-abcdef1");
        assert_eq!(pl.prs[0].upstream_ref, "refs/heads/sekimore/main-abcdef1");
        assert_eq!(
            pl.rewrites["refs/heads/sekimore/main-abcdef1"],
            "refs/for/main"
        );
        assert_eq!(
            pl.commands[0],
            OwnedCommand::Update {
                old: ZERO.into(),
                new: SHA.into(),
                name: "refs/heads/sekimore/main-abcdef1".into()
            }
        );
        // It can be re-encoded and parsed again, with caps preserved.
        let enc = pl.encode().unwrap();
        let re = parse_receive_pack(&enc).unwrap();
        assert_eq!(
            re.updates().next().unwrap().name,
            "refs/heads/sekimore/main-abcdef1"
        );
        assert_eq!(re.caps, Some(&b"report-status side-band-64k"[..]));
    }

    #[test]
    fn repush_of_same_commit_reuses_existing_branch_sha() {
        let adv = HashMap::from([(
            "refs/heads/sekimore/main-abcdef1".to_string(),
            SHA.to_string(),
        )]);
        let pl = plan(&[format!("{ZERO} {SHA} refs/for/main")], &adv).unwrap();
        match &pl.commands[0] {
            OwnedCommand::Update { old, .. } => assert_eq!(old, SHA),
            _ => panic!(),
        }
    }

    #[test]
    fn multiple_refs_for_in_one_push() {
        let pl = plan(
            &[
                format!("{ZERO} {SHA} refs/for/main"),
                format!("{ZERO} {SHA2} refs/for/develop"),
            ],
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(pl.prs.len(), 2);
        assert_eq!(pl.prs[1].head_branch, "sekimore/develop-1234567");
        assert_eq!(pl.rewrites.len(), 2);
    }

    #[test]
    fn disallowed_base_and_missing_permission_are_denied() {
        assert!(matches!(
            plan(
                &[format!("{ZERO} {SHA} refs/for/production")],
                &HashMap::new()
            ),
            Err(Denied::BaseNotAllowed { .. })
        ));
        // Without pr:create
        let p = Project::new("case-a").with_repo("LibOrg/awesome-lib", Mode::ReadWrite, &["main"]);
        let auth = p
            .authorize_git(GitVerb::ReceivePack, "LibOrg/awesome-lib")
            .unwrap();
        let data = section_of(&[format!("{ZERO} {SHA} refs/for/main")]);
        let sec = parse_receive_pack(&data).unwrap();
        assert!(matches!(
            plan_push(&p, &auth, &sec, &HashMap::new()),
            Err(Denied::NotPermitted {
                resource: "pr",
                action: "create"
            })
        ));
    }

    #[test]
    fn direct_push_policy_is_fail_closed() {
        // A direct push to main is denied by default.
        assert!(matches!(
            plan(&[format!("{ZERO} {SHA} refs/heads/main")], &HashMap::new()),
            Err(Denied::RefNotAllowed { .. })
        ));
        // sekimore/* is allowed.
        let pl = plan(
            &[format!("{SHA} {SHA2} refs/heads/sekimore/main-abcdef1")],
            &HashMap::new(),
        )
        .unwrap();
        assert!(pl.prs.is_empty());
        assert_eq!(pl.commands.len(), 1);
        // Tags and deletes are denied by default.
        assert!(matches!(
            plan(&[format!("{ZERO} {SHA} refs/tags/v1")], &HashMap::new()),
            Err(Denied::RefNotAllowed { .. })
        ));
        // With allow_tags: true a tag push is allowed; deletes still depend on allow_delete.
        let pl = plan_opts(
            &[format!("{ZERO} {SHA} refs/tags/v1")],
            &HashMap::new(),
            false,
            true,
        )
        .unwrap();
        assert_eq!(pl.commands.len(), 1);
        assert!(matches!(
            plan_opts(
                &[format!("{SHA} {ZERO} refs/tags/v1")],
                &HashMap::new(),
                false,
                true
            ),
            Err(Denied::DeleteNotAllowed { .. })
        ));
        // tags are globs: with ["v*"], v1 passes and release-1 is denied.
        assert!(plan_with_tags(
            &[format!("{ZERO} {SHA} refs/tags/v1")],
            &HashMap::new(),
            false,
            &["v*"]
        )
        .is_ok());
        assert!(matches!(
            plan_with_tags(
                &[format!("{ZERO} {SHA} refs/tags/release-1")],
                &HashMap::new(),
                false,
                &["v*"]
            ),
            Err(Denied::RefNotAllowed { .. })
        ));
        assert!(matches!(
            plan(
                &[format!("{SHA} {ZERO} refs/heads/sekimore/x")],
                &HashMap::new()
            ),
            Err(Denied::DeleteNotAllowed { .. })
        ));
        assert!(matches!(
            plan(&[format!("{SHA} {ZERO} refs/for/main")], &HashMap::new()),
            Err(Denied::RefNotAllowed { .. })
        ));
        assert!(matches!(
            plan(&[format!("{ZERO} {SHA} refs/notes/x")], &HashMap::new()),
            Err(Denied::RefNotAllowed { .. })
        ));
    }

    /// #89: deleting `refs/tags/v0.2.18` was refused and `git push --force origin v0.2.18`
    /// went through, which leaves the same result — a tag people already have naming
    /// different code. A tag the upstream already advertises may not be moved.
    #[test]
    fn a_tag_that_already_exists_upstream_cannot_be_moved() {
        let adv = HashMap::from([("refs/tags/v1".to_string(), SHA.to_string())]);
        let err =
            plan_opts(&[format!("{SHA} {SHA2} refs/tags/v1")], &adv, false, true).unwrap_err();
        assert!(matches!(err, Denied::TagUpdateNotAllowed { .. }), "{err}");
        assert!(err.to_string().contains("cut a new version"), "{err}");
        // The advertisement decides, not the `old` the client sent: a force push may name
        // whatever it last saw, zeros included.
        let err =
            plan_opts(&[format!("{ZERO} {SHA2} refs/tags/v1")], &adv, false, true).unwrap_err();
        assert!(matches!(err, Denied::TagUpdateNotAllowed { .. }), "{err}");
    }

    #[test]
    fn creating_a_tag_that_is_not_upstream_yet_is_still_allowed() {
        // Every release cuts a new tag, so only moving a published one is refused.
        let adv = HashMap::from([
            ("refs/heads/main".to_string(), SHA.to_string()),
            ("refs/tags/v1".to_string(), SHA.to_string()),
        ]);
        let pl = plan_opts(&[format!("{ZERO} {SHA2} refs/tags/v2")], &adv, false, true).unwrap();
        assert_eq!(pl.commands.len(), 1);
        // With `delete` the repository may already delete the tag and push it again, so the
        // same authority lets it move one.
        let pl = plan_opts(&[format!("{SHA} {SHA2} refs/tags/v1")], &adv, true, true).unwrap();
        assert_eq!(pl.commands.len(), 1);
        // A branch in the agent's own namespace is not a published name; force-pushing one stays allowed.
        let adv = HashMap::from([("refs/heads/sekimore/topic".to_string(), SHA.to_string())]);
        assert!(plan(&[format!("{SHA} {SHA2} refs/heads/sekimore/topic")], &adv).is_ok());
    }

    #[test]
    fn empty_push_plan_encodes_to_flush() {
        let pl = plan(&[], &HashMap::new()).unwrap();
        assert!(pl.commands.is_empty());
        assert_eq!(pl.encode().unwrap(), b"0000");
    }

    #[test]
    fn advert_line_parsing() {
        let (sha, name, caps) = parse_advert_line(
            format!("{SHA} refs/heads/main\0report-status side-band-64k\n").as_bytes(),
        )
        .unwrap();
        assert_eq!(sha, SHA);
        assert_eq!(name, "refs/heads/main");
        assert_eq!(caps.unwrap(), b"report-status side-band-64k");
        let (_, name, caps) =
            parse_advert_line(format!("{SHA} refs/heads/develop\n").as_bytes()).unwrap();
        assert_eq!(name, "refs/heads/develop");
        assert!(caps.is_none());
    }
}
