//! Relaying `git-receive-pack` (push).
//!
//! The Go PoC read all of the client's input before spawning the upstream. In receive-pack the server sends its
//! advertisement first, so that deadlocks against a real git. Instead we do:
//!
//!   A  forward the upstream advertisement to the client unchanged (recording ref → sha)
//!   B  parse and rewrite only the client's command section (up to the flush, with a size cap) and send it upstream
//!   B2 the push-options section is passed through unchanged
//!   C  stream the pack data raw, without buffering — except for a tag push (#89), which is read on
//!      the way through so that the tag object can be judged, with the trailer held back until it is
//!   D  map the upstream report-status back to the original ref names and send it to the client
//!   E  on success, create a PR for each `refs/for`

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::pack::{Object, Objects, PackError, PackScan, TRAILER_LEN};
use super::response::{RefStatus, ResponseRewriter};
use super::{
    copy_touch, copy_touch_counted, exit_code_of, GitContext, GitIo, RelayOutcome, UpstreamProcess,
    Watchdog,
};
use crate::audit::Actor;
use crate::github::GhError;
use crate::pktline::{
    caps_contain, encode_commands, encode_into, parse_receive_pack, validate_ref_name, CommandLine,
    CommandSection, Frame, PktReader, RefUpdate,
};
use crate::policy::{Denied, GitAuthorized, Project};

/// The agent's branch namespace.
pub const SEKIMORE_BRANCH_PREFIX: &str = "sekimore/";

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
    pub base: String,
    pub sha: String,
}

/// A tag this push creates, to be judged once the pack has been read (#89).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagCheck {
    pub name: String,
    /// The sha the tag will point at: a tag object if annotated, a commit if lightweight
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
            let head_branch = format!("{SEKIMORE_BRANCH_PREFIX}{base}-{}", short_sha(u.new));
            let upstream_ref = format!("refs/heads/{head_branch}");
            validate_ref_name(&upstream_ref).map_err(|reason| Denied::InvalidRef {
                name: upstream_ref.clone(),
                reason,
            })?;
            claim(&upstream_ref, u.name)?;
            // Re-pushing the same commit updates the existing branch rather than failing with "already exists".
            let old = adv
                .get(&upstream_ref)
                .cloned()
                .unwrap_or_else(|| zero_like(u.old));
            rewrites.insert(upstream_ref.clone(), u.name.to_string());
            prs.push(PrIntent {
                client_ref: u.name.to_string(),
                upstream_ref: upstream_ref.clone(),
                head_branch,
                base: base.to_string(),
                sha: u.new.to_string(),
            });
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
    })
}

/// Each pushed tag against what the pack turned out to hold.
///
/// Every check has to find its sha as a tag object with a signature block. Anything else —
/// a commit under the name (lightweight), a tag object without a signature, an object that is
/// not in the pack at all — is refused, and so is a pack this relay could not read: the answer
/// "cannot tell" fails closed, because the whole point is that nobody could tell before.
pub fn judge_tags(scanned: Result<Objects, PackError>, checks: &[TagCheck]) -> Result<(), Denied> {
    let objects = match scanned {
        Ok(o) => o,
        Err(e) => {
            return Err(Denied::TagNotSigned {
                name: checks[0].name.clone(),
                reason: format!("the pack could not be read to find the tag object ({e})"),
            })
        }
    };
    for c in checks {
        let reason = match objects.by_sha.get(&c.sha) {
            Some(Object::Tag { signed: true }) => continue,
            Some(Object::Tag { signed: false }) => {
                "it is an annotated tag without a signature".to_string()
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

/// Stage C for a push with tags to judge: forward the pack while reading it, holding back its
/// last `TRAILER_LEN` bytes until the verdict is in.
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
async fn copy_judging_tags<R, W>(
    leftover: &[u8],
    mut reader: R,
    writer: W,
    wd: &Watchdog,
    seen: &AtomicU64,
    checks: &[TagCheck],
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
                        let v = judge_tags(scan.take().unwrap().finish(), checks);
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
        None => judge_tags(scan.take().unwrap().finish(), checks),
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
    let pack_fut = async {
        if !plan.tag_checks.is_empty() {
            // #89: read the pack on the way through and hold the trailer until the tags are judged
            let (n, verdict) = copy_judging_tags(
                &leftover,
                &mut io.stdin,
                upstream_stdin.take().expect("taken once"),
                &wd,
                &sent,
                &plan.tag_checks,
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
    let (bytes_in, bytes_out, note, tag_denied) = tokio::select! {
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
    if let Some(d) = tag_denied {
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
            note: Some("policy_tag".into()),
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
    // Re-obtain the proof (plan_push already checked it; this can only fail if the policy changed since).
    let api_auth = match ctx.project.authorize_pr_for(auth, &pr.base) {
        Ok(a) => a,
        Err(d) => {
            say(io, &format!("push ok but PR creation refused: {d}")).await;
            return false;
        }
    };
    let title = format!("[agent] {} → {}", pr.head_branch, pr.base);
    let body = format!(
        "Created via sekimore-relay (`refs/for/{}`). Pushed by an AI agent through the gateway.\n\nCommit: {}",
        pr.base, pr.sha
    );
    match gh
        .create_pull_request(&api_auth, &pr.head_branch, &pr.base, &title, &body)
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
                    ("base", &pr.base),
                    ("number", &r.number.to_string()),
                ],
            );
            true
        }
        Err(GhError::Status { status: 422, .. }) => match gh
            .find_pull_request(&api_auth, &pr.head_branch, &pr.base)
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

    mod judging {
        use super::super::judge_tags;
        use super::*;
        use crate::git::pack::testutil::{pack, sha_of, tag_body, Entry, COMMIT};
        use crate::git::pack::{PackError, PackScan};

        fn scan(bytes: &[u8]) -> Result<crate::git::pack::Objects, PackError> {
            let mut s = PackScan::new();
            s.feed(bytes);
            s.finish()
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
