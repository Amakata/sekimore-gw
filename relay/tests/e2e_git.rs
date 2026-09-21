//! End-to-end tests that drive the relay with the real git / ssh clients.
//!
//! The upstream is `LocalGitUpstream` (`git receive-pack` / `git upload-pack` against a local bare repo),
//! so the whole pkt-line / side-band rewriting path is exercised over the real protocol.
//! Skipped where `git` and `ssh` are unavailable (fails instead when `SEKIMORE_E2E_REQUIRED=1`).

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;

use sekimore_relay::audit::Audit;
use sekimore_relay::config::Limits;
use sekimore_relay::git::upstream_local::LocalGitUpstream;
use sekimore_relay::git::GitContext;
use sekimore_relay::github::upstream_token::UpstreamTokenStore;
use sekimore_relay::github::GitHub;
use sekimore_relay::policy::{Mode, Project, RepoPolicy};
use sekimore_relay::ssh::authorized_keys::AuthorizedKeys;
use sekimore_relay::ssh::{load_or_create_host_key, server_config, SshServer};
use std::os::unix::fs::PermissionsExt;
use tokio::net::TcpListener;
use url::Url;

fn have(bin: &str) -> bool {
    // Look the name up on PATH rather than run it: the three tools disagree on how to ask for a
    // version (ssh wants -V, ssh-keygen has no such flag and exits 1 on any of them), and a
    // probe that exits non-zero read as "absent" — which made the signed-tag test skip
    // wherever SEKIMORE_E2E_REQUIRED was unset and fail wherever it was set.
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let p = dir.join(bin);
                p.is_file()
                    && std::fs::metadata(&p).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
            })
        })
        .unwrap_or(false)
}

/// Skip when the required tools are missing (CI makes them mandatory).
macro_rules! require_tools {
    () => {
        if !have("git") || !have("ssh") {
            if std::env::var("SEKIMORE_E2E_REQUIRED").is_ok() {
                panic!("git and ssh are required for e2e tests");
            }
            eprintln!("skipping: git/ssh not available");
            return;
        }
    };
}

struct E2e {
    dir: tempfile::TempDir,
    addr: SocketAddr,
    root: PathBuf,
    key_path: PathBuf,
    recorder: common::Recorder,
    audit_path: PathBuf,
}

impl E2e {
    fn url(&self, repo: &str) -> String {
        format!("ssh://git@127.0.0.1:{}/{repo}.git", self.addr.port())
    }
    fn bare(&self, repo: &str) -> PathBuf {
        self.root.join(format!("{repo}.git"))
    }
    fn ssh_cmd(&self) -> String {
        format!(
            "ssh -i {} -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR",
            self.key_path.display()
        )
    }
    /// Run git with an isolated HOME, so none of the user's settings (signing and the like) leak in.
    fn git(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.dir.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_SSH_COMMAND", self.ssh_cmd())
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "e2e")
            .env("GIT_AUTHOR_EMAIL", "e2e@example.invalid")
            .env("GIT_COMMITTER_NAME", "e2e")
            .env("GIT_COMMITTER_EMAIL", "e2e@example.invalid")
            .output()
            .expect("run git")
    }
    fn ok(&self, cwd: &Path, args: &[&str]) -> String {
        let o = self.git(cwd, args);
        assert!(
            o.status.success(),
            "git {:?} failed:\n{}\n{}",
            args,
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).into_owned()
    }
    fn bare_ref(&self, repo: &str, r: &str) -> Option<String> {
        let o = Command::new("git")
            .args(["rev-parse", "--verify", "-q", r])
            .current_dir(self.bare(repo))
            .output()
            .unwrap();
        o.status
            .success()
            .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
    }
    fn commit_file(&self, work: &Path, name: &str, content: &[u8]) -> String {
        std::fs::write(work.join(name), content).unwrap();
        self.ok(work, &["add", name]);
        self.ok(work, &["commit", "-q", "-m", &format!("add {name}")]);
        self.ok(work, &["rev-parse", "HEAD"]).trim().to_string()
    }
}

async fn setup(grants: &[&str]) -> E2e {
    setup_tuned(grants, |_| {}).await
}

/// As `setup`, with a last word on the project — a repository's tag globs, say.
async fn setup_tuned(grants: &[&str], tune: impl FnOnce(&mut Project)) -> E2e {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("upstream");
    for repo in ["LibOrg/awesome-lib", "VendorOrg/reference-impl"] {
        let bare = root.join(format!("{repo}.git"));
        std::fs::create_dir_all(&bare).unwrap();
        let o = Command::new("git")
            .args(["init", "-q", "--bare", "-b", "main"])
            .current_dir(&bare)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        for (k, v) in [
            ("receive.denyNonFastForwards", "true"),
            ("receive.advertisePushOptions", "true"),
        ] {
            Command::new("git")
                .args(["config", k, v])
                .current_dir(&bare)
                .output()
                .unwrap();
        }
    }
    // Client key
    let key_path = dir.path().join("id_ed25519");
    let o = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let pubkey = std::fs::read_to_string(dir.path().join("id_ed25519.pub")).unwrap();

    let keys = Arc::new(AuthorizedKeys::new(&dir.path().join("authorized_keys"), 8));
    keys.add(&pubkey).unwrap();
    let host_key = load_or_create_host_key(&dir.path().join("host_key")).unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(Audit::new(Some(&audit_path), false).unwrap());

    let (api_base, recorder) = common::mock_github().await;
    let graphql = Url::parse(&format!(
        "{}/graphql",
        api_base.as_str().trim_end_matches("/api/v3").to_string() + "/api"
    ))
    .unwrap();
    let store = Arc::new(UpstreamTokenStore::in_memory(
        "upstream.test",
        &dir.path().join("upstream_token"),
    ));
    store
        .save("upstream.test", "gho_test", "repo")
        .await
        .unwrap();
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let gh = Arc::new(GitHub::new(api_base, graphql, http, store, audit.clone()));

    let mut project = Project::new("case-a")
        .with_repo("LibOrg/awesome-lib", Mode::ReadWrite, &["main", "develop"])
        .with_repo("VendorOrg/reference-impl", Mode::ReadOnly, &[]);
    for g in grants {
        project = project.grant(g);
    }
    tune(&mut project);
    let ctx = Arc::new(GitContext {
        project,
        host: String::new(),
        upstream: Arc::new(LocalGitUpstream::new(&root)),
        github: Some(gh),
        audit: audit.clone(),
        limits: Limits {
            idle_timeout: Duration::from_secs(20),
            ..Limits::default()
        },
    });
    let server = SshServer::new(
        server_config(host_key, Duration::from_secs(120)),
        ctx,
        keys,
        audit,
        8,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server.run(listener));
    E2e {
        dir,
        addr,
        root,
        key_path,
        recorder,
        audit_path,
    }
}

/// Seed the upstream bare repo with an initial commit on main, directly over the file transport.
fn seed_main(e: &E2e, repo: &str) -> PathBuf {
    let seed = e
        .dir
        .path()
        .join(format!("seed-{}", repo.replace('/', "_")));
    std::fs::create_dir_all(&seed).unwrap();
    e.ok(&seed, &["init", "-q", "-b", "main"]);
    e.commit_file(&seed, "README.md", b"hello\n");
    let bare = e.bare(repo);
    e.ok(
        &seed,
        &["push", "-q", bare.to_str().unwrap(), "HEAD:refs/heads/main"],
    );
    seed
}

fn clone(e: &E2e, repo: &str, name: &str) -> PathBuf {
    let work = e.dir.path().join(name);
    let o = e.git(
        e.dir.path(),
        &["clone", "-q", &e.url(repo), work.to_str().unwrap()],
    );
    assert!(
        o.status.success(),
        "clone failed:\n{}",
        String::from_utf8_lossy(&o.stderr)
    );
    work
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clone_then_refs_for_push_creates_branch_and_pr() {
    require_tools!();
    let e = setup(&["pr:create"]).await;
    seed_main(&e, "LibOrg/awesome-lib");
    let work = clone(&e, "LibOrg/awesome-lib", "work");
    assert!(work.join("README.md").exists());

    let sha = e.commit_file(&work, "feature.txt", b"feature\n");
    let o = e.git(&work, &["push", "origin", "HEAD:refs/for/main"]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "push failed:\n{err}");
    assert!(err.contains("sekimore: created PR #42"), "{err}");
    assert!(
        !err.contains("unknown ref") && !err.contains("expecting report"),
        "{err}"
    );
    assert!(
        err.contains("refs/for/main"),
        "client output must show the ref it pushed: {err}"
    );

    let branch = format!("refs/heads/sekimore/main-{}", &sha[..7]);
    assert_eq!(
        e.bare_ref("LibOrg/awesome-lib", &branch).as_deref(),
        Some(sha.as_str())
    );
    assert!(
        e.bare_ref("LibOrg/awesome-lib", "refs/for/main").is_none(),
        "refs/for/* must not exist upstream"
    );

    let rec = common::recorded(&e.recorder);
    assert_eq!(rec.len(), 1, "{rec:?}");
    assert_eq!(rec[0].path, "/api/v3/repos/LibOrg/awesome-lib/pulls");
    assert_eq!(rec[0].body["head"], format!("sekimore/main-{}", &sha[..7]));
    assert_eq!(rec[0].body["base"], "main");
    assert!(rec[0]
        .headers
        .iter()
        .any(|(k, v)| k == "user-agent" && v.starts_with("sekimore-relay/")));

    // Re-pushing the same commit is idempotent (no "already exists")
    let o = e.git(&work, &["push", "origin", "HEAD:refs/for/main"]);
    assert!(
        o.status.success(),
        "re-push failed:\n{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(
        e.bare_ref("LibOrg/awesome-lib", &branch).as_deref(),
        Some(sha.as_str())
    );

    // A fetch (upload-pack passed through unchanged) sees the sekimore branch
    let out = e.ok(&work, &["ls-remote", "origin"]);
    assert!(out.contains(&branch), "{out}");
    let audit = std::fs::read_to_string(&e.audit_path).unwrap();
    assert!(audit.contains("\"event\":\"refs_for_rewritten\""));
    assert!(audit.contains("\"event\":\"pr_created\""));
    assert!(audit.contains("\"event\":\"relay_ok\""));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiple_refs_for_and_push_options_and_atomic() {
    require_tools!();
    let e = setup(&["pr:create"]).await;
    seed_main(&e, "LibOrg/awesome-lib");
    // Create develop as well
    let seed = e.dir.path().join("seed-LibOrg_awesome-lib");
    e.ok(
        &seed,
        &[
            "push",
            "-q",
            e.bare("LibOrg/awesome-lib").to_str().unwrap(),
            "HEAD:refs/heads/develop",
        ],
    );
    let work = clone(&e, "LibOrg/awesome-lib", "work");
    let sha = e.commit_file(&work, "two.txt", b"two\n");

    let o = e.git(
        &work,
        &[
            "push",
            "--atomic",
            "--push-option=ci.skip",
            "origin",
            "HEAD:refs/for/main",
            "HEAD:refs/for/develop",
        ],
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "push failed:\n{err}");
    assert!(e
        .bare_ref(
            "LibOrg/awesome-lib",
            &format!("refs/heads/sekimore/main-{}", &sha[..7])
        )
        .is_some());
    assert!(e
        .bare_ref(
            "LibOrg/awesome-lib",
            &format!("refs/heads/sekimore/develop-{}", &sha[..7])
        )
        .is_some());
    let rec = common::recorded(&e.recorder);
    assert_eq!(rec.len(), 2, "{rec:?}");
    let bases: Vec<String> = rec
        .iter()
        .map(|r| r.body["base"].as_str().unwrap().to_string())
        .collect();
    assert!(
        bases.contains(&"main".to_string()) && bases.contains(&"develop".to_string()),
        "{bases:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn policy_denials_are_explicit_and_leave_upstream_untouched() {
    require_tools!();
    let e = setup(&["pr:create"]).await;
    seed_main(&e, "LibOrg/awesome-lib");
    seed_main(&e, "VendorOrg/reference-impl");
    let main_sha = e.bare_ref("LibOrg/awesome-lib", "refs/heads/main").unwrap();
    let work = clone(&e, "LibOrg/awesome-lib", "work");
    e.commit_file(&work, "x.txt", b"x\n");

    let cases: Vec<(Vec<&str>, &str)> = vec![
        (
            vec!["push", "origin", "HEAD:refs/heads/main"],
            "outside the allowed push namespace",
        ),
        (
            vec!["push", "origin", "HEAD:refs/for/production"],
            "base branch production is not allowed",
        ),
        (
            vec!["push", "origin", "HEAD:refs/tags/v1"],
            "tag is not allowed for this repository",
        ),
        (
            vec![
                "push",
                "origin",
                "HEAD:refs/heads/sekimore/x",
                "HEAD:refs/heads/main",
            ],
            "outside the allowed push namespace",
        ),
    ];
    for (args, want) in cases {
        let o = e.git(&work, &args);
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(!o.status.success(), "{args:?} must fail:\n{err}");
        assert!(err.contains(want), "{args:?}: {err}");
        // Rejections come back as an ng in report-status rather than a disconnect, so git prints remote rejected instead of "hung up"
        assert!(err.contains("[remote rejected]"), "{args:?}: {err}");
        assert!(!err.contains("hung up"), "{args:?}: {err}");
    }
    // Deletes are denied by default
    e.ok(&work, &["push", "origin", "HEAD:refs/heads/sekimore/x"]);
    let o = e.git(&work, &["push", "origin", ":refs/heads/sekimore/x"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr)
        .contains("deleting refs/heads/sekimore/x is not allowed"));
    assert!(e
        .bare_ref("LibOrg/awesome-lib", "refs/heads/sekimore/x")
        .is_some());
    // main has not moved
    assert_eq!(
        e.bare_ref("LibOrg/awesome-lib", "refs/heads/main").unwrap(),
        main_sha
    );
    assert!(e.bare_ref("LibOrg/awesome-lib", "refs/tags/v1").is_none());

    // Outside the project
    let o = e.git(e.dir.path(), &["ls-remote", &e.url("Attacker/evil")]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("is not in project"));
    // read-only: clone succeeds, push is denied
    let ro = clone(&e, "VendorOrg/reference-impl", "ro");
    e.commit_file(&ro, "y.txt", b"y\n");
    let o = e.git(&ro, &["push", "origin", "HEAD:refs/heads/sekimore/y"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("read-only"));
    assert!(
        common::recorded(&e.recorder).is_empty(),
        "no PR must be created"
    );
}

/// #89: a tag that is already published may not be moved, while cutting a new one still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_published_tag_cannot_be_moved_but_a_new_one_still_goes_up() {
    require_tools!();
    let e = setup_tuned(&[], |p| {
        for r in &mut p.repos {
            r.tags = vec!["v*".to_string()];
            // This test is about moving a tag, not about what kind of tag; the tags below are
            // plain `-a` ones, which the signed_tags default would refuse first
            r.signed_tags = false;
        }
    })
    .await;
    seed_main(&e, "LibOrg/awesome-lib");
    // The bare upstream here refuses non-fast-forwards; GitHub does not, and in #89 it did not.
    // Turning it off leaves the relay as the only thing between the force push and the tag.
    Command::new("git")
        .args(["config", "receive.denyNonFastForwards", "false"])
        .current_dir(e.bare("LibOrg/awesome-lib"))
        .output()
        .unwrap();
    let work = clone(&e, "LibOrg/awesome-lib", "work");

    e.ok(&work, &["tag", "-a", "v1", "-m", "v1"]);
    e.ok(&work, &["push", "origin", "v1"]);
    let published = e.bare_ref("LibOrg/awesome-lib", "refs/tags/v1").unwrap();

    // Move v1 onto another commit and force it up, exactly as in the issue.
    e.commit_file(&work, "x.txt", b"x\n");
    e.ok(&work, &["tag", "-f", "-a", "v1", "-m", "v1 again"]);
    let o = e.git(&work, &["push", "--force", "origin", "v1"]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!o.status.success(), "moving v1 must fail:\n{err}");
    assert!(
        err.contains("updating refs/tags/v1 is not allowed"),
        "{err}"
    );
    assert!(err.contains("cut a new version"), "{err}");
    assert!(err.contains("[remote rejected]"), "{err}");
    assert_eq!(
        e.bare_ref("LibOrg/awesome-lib", "refs/tags/v1").unwrap(),
        published,
        "the published tag must still name what it named"
    );
    // Its own audit event, not an ordinary push denial.
    let audit = std::fs::read_to_string(&e.audit_path).unwrap();
    assert!(
        audit.contains("push_denied_tag_update_not_allowed"),
        "{audit}"
    );

    // A version that is not there yet still goes up.
    e.ok(&work, &["tag", "-a", "v2", "-m", "v2"]);
    e.ok(&work, &["push", "origin", "v2"]);
    assert!(e.bare_ref("LibOrg/awesome-lib", "refs/tags/v2").is_some());
}

/// #89, second half: a tag goes up only as a signed tag object. Decided from the pack itself,
/// after the command section was already accepted, by withholding the pack's trailer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_a_signed_tag_object_goes_up() {
    require_tools!();
    if !have("ssh-keygen") {
        if std::env::var("SEKIMORE_E2E_REQUIRED").is_ok() {
            panic!("ssh-keygen is required for the signed-tag test");
        }
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    let e = setup_tuned(&[], |p| {
        for r in &mut p.repos {
            r.tags = vec!["v*".to_string()];
        }
    })
    .await;
    seed_main(&e, "LibOrg/awesome-lib");
    let work = clone(&e, "LibOrg/awesome-lib", "work");

    // A lightweight tag: the name points straight at the commit, which the upstream already has
    e.ok(&work, &["tag", "v1"]);
    let o = e.git(&work, &["push", "origin", "v1"]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!o.status.success(), "a lightweight tag must fail:\n{err}");
    assert!(err.contains("pushing refs/tags/v1 is not allowed"), "{err}");
    assert!(err.contains("git tag -s"), "{err}");
    assert!(err.contains("[remote rejected]"), "{err}");
    assert!(!err.contains("hung up"), "{err}");
    assert!(e.bare_ref("LibOrg/awesome-lib", "refs/tags/v1").is_none());

    // An annotated tag without a signature — how 0.2.18 got its first tag
    e.ok(&work, &["tag", "-a", "v2", "-m", "v2"]);
    let o = e.git(&work, &["push", "origin", "v2"]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!o.status.success(), "an unsigned tag must fail:\n{err}");
    assert!(err.contains("without a signature"), "{err}");
    assert!(err.contains("[remote rejected]"), "{err}");
    assert!(e.bare_ref("LibOrg/awesome-lib", "refs/tags/v2").is_none());

    // Its own audit event
    let audit = std::fs::read_to_string(&e.audit_path).unwrap();
    assert!(audit.contains("push_denied_tag_not_signed"), "{audit}");

    // A signed one (SSH format, the one this project uses) goes up
    let key = e.dir.path().join("signing_ed25519");
    let o = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let key_arg = format!("user.signingkey={}", key.display());
    e.ok(
        &work,
        &[
            "-c",
            "gpg.format=ssh",
            "-c",
            &key_arg,
            "tag",
            "-s",
            "v3",
            "-m",
            "v3",
        ],
    );
    e.ok(&work, &["push", "origin", "v3"]);
    assert!(e.bare_ref("LibOrg/awesome-lib", "refs/tags/v3").is_some());

    // and a second signed one, pushed alone, when the first is already upstream: this is the
    // shape a release is, and where a thin pack could have deltified against the first
    e.commit_file(&work, "next.txt", b"next\n");
    e.ok(
        &work,
        &[
            "-c",
            "gpg.format=ssh",
            "-c",
            &key_arg,
            "tag",
            "-s",
            "v4",
            "-m",
            "v4",
        ],
    );
    e.ok(&work, &["push", "origin", "v4"]);
    assert!(e.bare_ref("LibOrg/awesome-lib", "refs/tags/v4").is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_fast_forward_ng_is_visible_through_sideband() {
    require_tools!();
    let e = setup(&["pr:create"]).await;
    seed_main(&e, "LibOrg/awesome-lib");
    let work = clone(&e, "LibOrg/awesome-lib", "work");
    e.commit_file(&work, "a.txt", b"a\n");
    e.ok(&work, &["push", "origin", "HEAD:refs/heads/sekimore/topic"]);
    // Rewind history, make a different commit, then force push; the upstream returns ng via receive.denyNonFastForwards
    e.ok(&work, &["reset", "-q", "--hard", "HEAD~1"]);
    e.commit_file(&work, "b.txt", b"b\n");
    let o = e.git(
        &work,
        &[
            "push",
            "--force",
            "origin",
            "HEAD:refs/heads/sekimore/topic",
        ],
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!o.status.success(), "{err}");
    assert!(
        err.contains("remote rejected") && err.contains("non-fast-forward"),
        "ng from upstream must reach the client: {err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_pack_streams_through() {
    require_tools!();
    let e = setup(&["pr:create"]).await;
    seed_main(&e, "LibOrg/awesome-lib");
    let work = clone(&e, "LibOrg/awesome-lib", "work");
    let mut big = vec![0u8; 24 * 1024 * 1024];
    getrandom::fill(&mut big).unwrap();
    let sha = e.commit_file(&work, "big.bin", &big);
    let o = e.git(&work, &["push", "origin", "HEAD:refs/heads/sekimore/big"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(
        e.bare_ref("LibOrg/awesome-lib", "refs/heads/sekimore/big")
            .as_deref(),
        Some(sha.as_str())
    );
    // A fresh clone gets the content
    let again = clone(&e, "LibOrg/awesome-lib", "again");
    e.ok(
        &again,
        &["fetch", "-q", "origin", "refs/heads/sekimore/big"],
    );
    let out = e.ok(&again, &["cat-file", "-s", &format!("{sha}:big.bin")]);
    assert_eq!(out.trim(), big.len().to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn empty_push_is_harmless() {
    require_tools!();
    let e = setup(&["pr:create"]).await;
    seed_main(&e, "LibOrg/awesome-lib");
    let work = clone(&e, "LibOrg/awesome-lib", "work");
    e.ok(&work, &["push", "origin", "HEAD:refs/heads/sekimore/same"]);
    // A push with nothing to send (up to date)
    let o = e.git(&work, &["push", "origin", "HEAD:refs/heads/sekimore/same"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

// ---- 0.2.0: several upstreams split across ports ----

fn init_bare(bare: &Path) {
    std::fs::create_dir_all(bare).unwrap();
    let o = Command::new("git")
        .args(["init", "-q", "--bare", "-b", "main"])
        .current_dir(bare)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    Command::new("git")
        .args(["config", "receive.advertisePushOptions", "true"])
        .current_dir(bare)
        .output()
        .unwrap();
}

fn bare_ref_at(bare: &Path, r: &str) -> Option<String> {
    let o = Command::new("git")
        .args(["rev-parse", "--verify", "-q", r])
        .current_dir(bare)
        .output()
        .unwrap();
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn seed_main_at(e: &E2e, bare: &Path, name: &str) {
    let seed = e.dir.path().join(name);
    std::fs::create_dir_all(&seed).unwrap();
    e.ok(&seed, &["init", "-q", "-b", "main"]);
    e.commit_file(&seed, "README.md", b"hello\n");
    e.ok(
        &seed,
        &["push", "-q", bare.to_str().unwrap(), "HEAD:refs/heads/main"],
    );
}

/// Two upstreams: `github.test` (the default, `e.addr` / `e.root`) and `ghe.test` (its own port, the returned addr / root).
/// `LibOrg/awesome-lib` exists on both — read-write on github, read-only on ghe. `Corp/internal` only exists on ghe.
async fn setup_multi(grants: &[&str]) -> (E2e, SocketAddr, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("upstream-github");
    let ghe_root = dir.path().join("upstream-ghe");
    init_bare(&root.join("LibOrg/awesome-lib.git"));
    init_bare(&ghe_root.join("Corp/internal.git"));
    init_bare(&ghe_root.join("LibOrg/awesome-lib.git"));

    let key_path = dir.path().join("id_ed25519");
    let o = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let pubkey = std::fs::read_to_string(dir.path().join("id_ed25519.pub")).unwrap();
    let keys = Arc::new(AuthorizedKeys::new(&dir.path().join("authorized_keys"), 8));
    keys.add(&pubkey).unwrap();
    let host_key = load_or_create_host_key(&dir.path().join("host_key")).unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(Audit::new(Some(&audit_path), false).unwrap());

    let (api_base, recorder) = common::mock_github().await;
    let graphql = Url::parse(&format!(
        "{}/graphql",
        api_base.as_str().trim_end_matches("/api/v3").to_string() + "/api"
    ))
    .unwrap();
    let store = Arc::new(UpstreamTokenStore::in_memory(
        "upstream.test",
        &dir.path().join("upstream_token"),
    ));
    store
        .save("upstream.test", "gho_test", "repo")
        .await
        .unwrap();
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let gh = Arc::new(GitHub::new(api_base, graphql, http, store, audit.clone()));

    let mut lib = RepoPolicy::new("LibOrg/awesome-lib", Mode::ReadWrite);
    lib.host = "github.test".into();
    lib.bases = vec!["main".into()];
    let mut internal = RepoPolicy::new("Corp/internal", Mode::ReadWrite);
    internal.host = "ghe.test".into();
    internal.bases = vec!["main".into()];
    let mut lib_ghe = RepoPolicy::new("LibOrg/awesome-lib", Mode::ReadOnly);
    lib_ghe.host = "ghe.test".into();
    let grants: Vec<String> = grants.iter().map(|s| s.to_string()).collect();
    let mut project = Project::try_new("case-m", vec![lib, internal, lib_ghe], &grants).unwrap();
    project.set_default_host("github.test");

    let config = Arc::new(server_config(host_key, Duration::from_secs(120)));
    let sessions = Arc::new(tokio::sync::Semaphore::new(8));
    let mk = |host: &str, root: &Path| {
        Arc::new(GitContext {
            project: project.clone(),
            host: host.into(),
            upstream: Arc::new(LocalGitUpstream::new(root)),
            github: Some(gh.clone()),
            audit: audit.clone(),
            limits: Limits {
                idle_timeout: Duration::from_secs(20),
                ..Limits::default()
            },
        })
    };
    let gh_server = SshServer::shared(
        config.clone(),
        mk("github.test", &root),
        keys.clone(),
        audit.clone(),
        sessions.clone(),
    );
    let ghe_server = SshServer::shared(config, mk("ghe.test", &ghe_root), keys, audit, sessions);
    let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l1.local_addr().unwrap();
    let ghe_addr = l2.local_addr().unwrap();
    tokio::spawn(gh_server.run(l1));
    tokio::spawn(ghe_server.run(l2));
    (
        E2e {
            dir,
            addr,
            root,
            key_path,
            recorder,
            audit_path,
        },
        ghe_addr,
        ghe_root,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_upstreams_are_kept_apart_by_listen_port() {
    require_tools!();
    let (e, ghe_addr, ghe_root) = setup_multi(&["pr:create"]).await;
    let ghe_url = |repo: &str| format!("ssh://git@127.0.0.1:{}/{repo}.git", ghe_addr.port());
    seed_main(&e, "LibOrg/awesome-lib");
    seed_main_at(&e, &ghe_root.join("Corp/internal.git"), "seed-ghe-internal");
    seed_main_at(&e, &ghe_root.join("LibOrg/awesome-lib.git"), "seed-ghe-lib");

    // 1. ghe port: clone Corp/internal, push refs/for/main — the branch appears only in the ghe bare repo and a PR is created
    let work = e.dir.path().join("work-ghe");
    let o = e.git(
        e.dir.path(),
        &[
            "clone",
            "-q",
            &ghe_url("Corp/internal"),
            work.to_str().unwrap(),
        ],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let sha = e.commit_file(&work, "f.txt", b"x\n");
    let o = e.git(&work, &["push", "origin", "HEAD:refs/for/main"]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "{err}");
    assert!(err.contains("sekimore: created PR #42"), "{err}");
    let branch = format!("refs/heads/sekimore/main-{}", &sha[..7]);
    assert_eq!(
        bare_ref_at(&ghe_root.join("Corp/internal.git"), &branch).as_deref(),
        Some(sha.as_str())
    );
    assert!(!e.root.join("Corp/internal.git").exists());

    // 2. github port: Corp/internal is outside the project (another upstream's repos are unreachable)
    let o = e.git(e.dir.path(), &["ls-remote", &e.url("Corp/internal")]);
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("is not in project"), "{err}");

    // 3. Same name on both, LibOrg/awesome-lib: read-write on github (the push lands only in the github bare repo)
    let work2 = clone(&e, "LibOrg/awesome-lib", "work-gh");
    let sha2 = e.commit_file(&work2, "g.txt", b"y\n");
    let o = e.git(
        &work2,
        &["push", "origin", "HEAD:refs/heads/sekimore/topic"],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(
        e.bare_ref("LibOrg/awesome-lib", "refs/heads/sekimore/topic")
            .as_deref(),
        Some(sha2.as_str())
    );
    assert!(bare_ref_at(
        &ghe_root.join("LibOrg/awesome-lib.git"),
        "refs/heads/sekimore/topic"
    )
    .is_none());
    // read-only on ghe: clone succeeds but push is denied (not confused with the read-write github side)
    let work3 = e.dir.path().join("work-ghe-lib");
    let o = e.git(
        e.dir.path(),
        &[
            "clone",
            "-q",
            &ghe_url("LibOrg/awesome-lib"),
            work3.to_str().unwrap(),
        ],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    e.commit_file(&work3, "h.txt", b"z\n");
    let o = e.git(
        &work3,
        &["push", "origin", "HEAD:refs/heads/sekimore/topic"],
    );
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("read-only"), "{err}");
    assert!(bare_ref_at(
        &ghe_root.join("LibOrg/awesome-lib.git"),
        "refs/heads/sekimore/topic"
    )
    .is_none());

    // The audit log records which upstream was used
    let audit = std::fs::read_to_string(&e.audit_path).unwrap();
    assert!(audit.contains("ghe.test"), "{audit}");
    assert!(audit.contains("github.test"), "{audit}");
}
