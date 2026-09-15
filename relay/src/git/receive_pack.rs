//! `git-receive-pack`（push）の中継。
//!
//! Go PoC はクライアント入力を全部読んでから上流を起動していた。receive-pack はサーバが先に
//! advertisement を送るプロトコルなので、実 git とはデッドロックする。ここでは:
//!
//!   A  上流 advertisement をクライアントへ無変更転送（ref → sha を記録）
//!   B  クライアントのコマンド部（flush まで、上限付き）だけを解析・書き換えて上流へ
//!   B2 push-options 区間は素通し
//!   C  pack データは生ストリーム転送（バッファしない）
//!   D  上流の report-status を元の ref 名に戻してクライアントへ
//!   E  成功したら `refs/for` ごとに PR を作る

use std::collections::HashMap;

use tokio::io::AsyncWriteExt;

use super::response::{RefStatus, ResponseRewriter};
use super::{copy_touch, exit_code_of, GitContext, GitIo, RelayOutcome, UpstreamProcess, Watchdog};
use crate::audit::Actor;
use crate::github::GhError;
use crate::pktline::{
    caps_contain, encode_commands, encode_into, parse_receive_pack, validate_ref_name, CommandLine,
    CommandSection, Frame, PktReader, RefUpdate,
};
use crate::policy::{Denied, GitAuthorized, Project};

/// エージェントのブランチ名前空間。
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

/// `refs/for/<base>` 1 件に対応する PR 作成の意図。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrIntent {
    pub client_ref: String,
    pub upstream_ref: String,
    pub head_branch: String,
    pub base: String,
    pub sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushPlan {
    pub commands: Vec<OwnedCommand>,
    pub caps: Option<Vec<u8>>,
    /// upstream ref → client ref
    pub rewrites: HashMap<String, String>,
    pub prs: Vec<PrIntent>,
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

/// advertisement の 1 行 `<sha> <ref>[\0caps]` を分解する。
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

/// コマンド部をポリシーに照らして書き換え計画を作る。拒否はここで（上流に何も送る前に）決まる。
pub fn plan_push(
    project: &Project,
    auth: &GitAuthorized<'_>,
    section: &CommandSection<'_>,
    adv: &HashMap<String, String>,
    allow_delete: bool,
) -> Result<PushPlan, Denied> {
    let policy = auth.policy();
    let mut commands = Vec::new();
    let mut rewrites: HashMap<String, String> = HashMap::new();
    let mut prs = Vec::new();

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
            // pr:create + read-write + base 許可（Authorized はここでは捨てる。E 段で再取得する）
            project.authorize_pr(auth.repo(), base)?;
            let head_branch = format!("{SEKIMORE_BRANCH_PREFIX}{base}-{}", short_sha(u.new));
            let upstream_ref = format!("refs/heads/{head_branch}");
            validate_ref_name(&upstream_ref).map_err(|reason| Denied::InvalidRef {
                name: upstream_ref.clone(),
                reason,
            })?;
            if rewrites.contains_key(&upstream_ref) {
                return Err(Denied::RefNotAllowed {
                    name: u.name.to_string(),
                    reason: "two refs/for updates map to the same branch",
                });
            }
            // 同じコミットの再 push は既存ブランチの更新にする（"already exists" にしない）
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
            if u.is_delete() && !allow_delete {
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
            commands.push(OwnedCommand::Update {
                old: u.old.to_string(),
                new: u.new.to_string(),
                name: u.name.to_string(),
            });
        } else if u.name.starts_with("refs/tags/") {
            return Err(Denied::RefNotAllowed {
                name: u.name.to_string(),
                reason: "tags cannot be pushed through the relay",
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
    })
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
    // 上流 stderr は最後にまとめてクライアントへ（relay 自身の行は "sekimore: " 接頭辞）
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

    let plan = match plan_push(&ctx.project, auth, &section, &adv, ctx.allow_delete) {
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
                // client は report-status を待っているので、切断ではなく `ng` で拒否を返す
                // （git は "! [remote rejected] … (reason)" と表示し、"remote end hung up" にならない）。
                // client は commands の直後に pack を送り始めるので、読み捨てないと window が詰まって report を読めない
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
    let pack_fut = async {
        let mut total = 0u64;
        if !leftover.is_empty() {
            proc.stdin.write_all(&leftover).await?;
            total += leftover.len() as u64;
            wd.touch();
        }
        if has_commands {
            total += copy_touch(&mut io.stdin, &mut proc.stdin, &wd, true).await?;
        } else {
            proc.stdin.shutdown().await?;
        }
        Ok::<u64, std::io::Error>(total)
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
    let (bytes_in, bytes_out, note) = tokio::select! {
        r = async { tokio::join!(pack_fut, resp_fut) } => {
            let (i, o) = r;
            (i.unwrap_or(0), o.unwrap_or(0), None)
        }
        _ = wd.expired() => {
            let _ = proc.child.start_kill();
            (0, 0, Some("idle_timeout".to_string()))
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

/// ポリシーで拒否した push への report-status: `unpack ok` + 全 ref に `ng <ref> <reason>`。
/// side-band-64k を要求されていれば band 1 で包む（1 pkt ずつ。理由が長くても上限を超えない）。
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

/// stderr だけを借りて報告する（client 側リーダが stdin を借りている間に使う）。
async fn say_err(stderr: &mut Box<dyn tokio::io::AsyncWrite + Send + Unpin + '_>, msg: &str) {
    let _ = stderr
        .write_all(format!("sekimore: {msg}\n").as_bytes())
        .await;
    let _ = stderr.flush().await;
}

/// 上流 stderr（別タスクで収集）をクライアントへ流す。
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

/// PR を作る。成功（既存を含む）なら true。
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
    // 証明を再取得（plan_push で検査済み。ここで失敗するのはポリシーが変わった場合のみ）
    let api_auth = match ctx.project.authorize_pr(auth.repo(), &pr.base) {
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
        let p = project();
        let auth = p
            .authorize_git(GitVerb::ReceivePack, "LibOrg/awesome-lib.git")
            .unwrap();
        let data = section_of(lines);
        let sec = parse_receive_pack(&data).unwrap();
        plan_push(&p, &auth, &sec, adv, false)
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
        // 再エンコードして解析できる。caps が保持される
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
        // pr:create 無し
        let p = Project::new("case-a").with_repo("LibOrg/awesome-lib", Mode::ReadWrite, &["main"]);
        let auth = p
            .authorize_git(GitVerb::ReceivePack, "LibOrg/awesome-lib")
            .unwrap();
        let data = section_of(&[format!("{ZERO} {SHA} refs/for/main")]);
        let sec = parse_receive_pack(&data).unwrap();
        assert!(matches!(
            plan_push(&p, &auth, &sec, &HashMap::new(), false),
            Err(Denied::NotPermitted {
                resource: "pr",
                action: "create"
            })
        ));
    }

    #[test]
    fn direct_push_policy_is_fail_closed() {
        // main への直接 push は既定拒否
        assert!(matches!(
            plan(&[format!("{ZERO} {SHA} refs/heads/main")], &HashMap::new()),
            Err(Denied::RefNotAllowed { .. })
        ));
        // sekimore/* は許可
        let pl = plan(
            &[format!("{SHA} {SHA2} refs/heads/sekimore/main-abcdef1")],
            &HashMap::new(),
        )
        .unwrap();
        assert!(pl.prs.is_empty());
        assert_eq!(pl.commands.len(), 1);
        // tag と削除は拒否
        assert!(matches!(
            plan(&[format!("{ZERO} {SHA} refs/tags/v1")], &HashMap::new()),
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
