//! Step 11: the agent guide where each tool reads it — a Claude Code skill and a marked block
//! in Codex's AGENTS.md. `SEKIMORE_AGENT_INSTRUCTIONS=claude,codex` (default) or `none`.

use anyhow::Context;

use super::files::{chown_all, ensure_dir, read_or_empty, write_atomic, MarkedBlock, Owner};
use crate::cli::agent::guide_for;

pub const MARK: MarkedBlock = MarkedBlock {
    begin: "<!-- >>> sekimore-relay >>> -->",
    end: "<!-- <<< sekimore-relay <<< -->",
};

const SIGNING_NOTE: &str = "
## Signing is required here

Every commit you push has to carry a signature. The relay reads the pack and refuses the push
otherwise — `pushing refs/heads/... is not allowed: commit <sha> carries no signature`.

This container is already set up to sign: plain `git commit` signs. So if a push is refused for
this, the commit was made in a way that went around that setup (`-c commit.gpgsign=false`, a
`--no-gpg-sign`, or a commit written by a tool of its own).

- Fix the tip with `git commit -S --amend --no-edit`, and older commits with `git rebase --exec 'git commit -S --amend --no-edit' <base>`. That rewrites the commits, so if they were pushed already, push the result as a new branch (`refs/for/<base>`): a push that does not fast-forward is refused unless the repository allows it (`force_push`).
- **Do not turn signing off.** `git config commit.gpgsign false` makes every later commit fail
  the same check, one at a time. If signing itself is broken, say so and stop; it is the
  operator's to fix, not something to work around.
";

/// Where the Claude Code skill goes, under the agent's home. Named after the command the agent
/// runs (#287); `OLD_SKILL_DIR` is the name it had until 0.2.54, which `sgw-agent setup` removes.
pub const SKILL_DIR: &str = ".claude/skills/sgw-agent";
pub const OLD_SKILL_DIR: &str = ".claude/skills/sekimore-relay";

/// #287: the skill under its former name, when it is ours and holds nothing else. Left alone
/// otherwise, with a line saying so: a directory with a person's files in it is not ours to
/// delete because of a rename.
fn remove_old_skill(home: &std::path::Path) {
    let old = home.join(OLD_SKILL_DIR);
    if !old.is_dir() {
        return;
    }
    let entries: Vec<_> = match std::fs::read_dir(&old) {
        Ok(rd) => rd.flatten().map(|e| e.file_name()).collect(),
        Err(_) => return,
    };
    let ours = entries.len() == 1
        && entries[0] == "SKILL.md"
        && read_or_empty(&old.join("SKILL.md")).starts_with("---\nname: sekimore-relay\n");
    if ours {
        match std::fs::remove_dir_all(&old) {
            Ok(()) => println!(
                "[agent] relay: removed the skill under its former name, {}",
                old.display()
            ),
            Err(e) => println!("[agent] WARNING: could not remove {}: {e}", old.display()),
        }
    } else {
        println!(
            "[agent] relay: {} is not the skill this wrote (or holds other files); left alone. The skill is now {}",
            old.display(),
            SKILL_DIR
        );
    }
}

pub fn skill_text(lang: Option<&str>, signing_required: bool, sidecar_guides: &str) -> String {
    let mut s = format!(
        "---\nname: sgw-agent\ndescription: In this environment git push, pull requests, CI checks, issues and the GitHub API all go through sekimore-relay. Read this before pushing, opening a PR, checking CI or calling GitHub. sekimore-relay {}\n---\n\n{}",
        env!("CARGO_PKG_VERSION"),
        guide_for(lang)
    );
    if !s.ends_with('\n') {
        s.push('\n');
    }
    // #330: each connected command sidecar's own guide, after the gateway's
    s.push_str(sidecar_guides);
    if signing_required {
        s.push_str(SIGNING_NOTE);
    }
    s
}

pub fn agents_block(signing_required: bool) -> String {
    let mut s = String::from(
        "## sekimore-relay (git and GitHub go through the relay)\n\n\
         In this environment git push, pull requests, CI checks and the GitHub API all go through sekimore-relay. Run `sgw-agent guide` before you start working.\n\
         In short: push to `HEAD:refs/heads/sekimore/<topic>` (then `sgw-agent pr create`) or to `HEAD:refs/for/<base>`. Direct pushes to main, tags, deletions and HTTPS git are refused.\n\
         Check your permissions and repositories with `sgw-agent whoami`. Denials are printed on stderr as `sgw-agent: …`. The operator's credentials are not in this environment; do not try to work around the relay.\n",
    );
    if signing_required {
        s.push_str("Every commit you push has to be signed; plain `git commit` signs here. If a push is refused for a missing signature, amend with `git commit -S --amend --no-edit` — never turn `commit.gpgsign` off.\n");
    }
    s
}

/// Writes what `targets` names. `signing_required` adds the signing section; an agent that is
/// told about a rule that does not apply stops reading the ones that do (#59).
pub fn write(
    owner: &Owner,
    targets: &str,
    lang: Option<&str>,
    signing_required: bool,
    sidecar_guides: &str,
) -> anyhow::Result<()> {
    let targets: Vec<&str> = targets.split(',').map(str::trim).collect();
    if targets.contains(&"none") {
        return Ok(());
    }
    let home = &owner.home;
    if targets.contains(&"claude") {
        let dir = home.join(SKILL_DIR);
        remove_old_skill(home);
        ensure_dir(&dir, 0o755)?;
        write_atomic(
            &dir.join("SKILL.md"),
            &skill_text(lang, signing_required, sidecar_guides),
            0o644,
        )?;
        chown_all(&home.join(".claude/skills"), owner).context("chown ~/.claude/skills")?;
        println!(
            "[agent] relay: wrote Claude Code skill {}",
            dir.join("SKILL.md").display()
        );
    }
    if targets.contains(&"codex") {
        let dir = home.join(".codex");
        ensure_dir(&dir, 0o755)?;
        let agents = dir.join("AGENTS.md");
        write_atomic(
            &agents,
            &MARK.replace(&read_or_empty(&agents), &agents_block(signing_required)),
            0o644,
        )?;
        chown_all(&dir, owner).context("chown ~/.codex")?;
        println!(
            "[agent] relay: wrote Codex instructions block in {}",
            agents.display()
        );
    }
    Ok(())
}
