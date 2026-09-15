//! 実物の git / ssh クライアントで relay を通す end-to-end テスト。
//!
//! 上流は `LocalGitUpstream`（ローカル bare repo に対する `git receive-pack` / `git upload-pack`）なので、
//! pkt-line / side-band の書き換え経路全体が本物のプロトコルで検証される。
//! `git` と `ssh` が無い環境ではスキップする（`SEKIMORE_E2E_REQUIRED=1` なら失敗）。

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
use sekimore_relay::policy::{Mode, Project};
use sekimore_relay::ssh::authorized_keys::AuthorizedKeys;
use sekimore_relay::ssh::{load_or_create_host_key, server_config, SshServer};
use tokio::net::TcpListener;
use url::Url;

fn have(bin: &str) -> bool {
    // ssh は --version を持たない（-V が版表示）
    let flag = if bin == "ssh" { "-V" } else { "--version" };
    Command::new(bin)
        .arg(flag)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 前提ツールが無ければスキップ（CI では必須にする）。
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
    /// git を実行する（HOME を隔離し、署名など利用者の設定を持ち込まない）。
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
    // クライアント鍵
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
    let store = Arc::new(UpstreamTokenStore::new(
        &dir.path().join("upstream_token"),
        Duration::from_secs(60),
    ));
    store.save("upstream.test", "gho_test", "repo").unwrap();
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let gh = Arc::new(GitHub::new(api_base, graphql, http, store, audit.clone()));

    let mut project = Project::new("case-a")
        .with_repo("LibOrg/awesome-lib", Mode::ReadWrite, &["main", "develop"])
        .with_repo("VendorOrg/reference-impl", Mode::ReadOnly, &[]);
    for g in grants {
        project = project.grant(g);
    }
    let ctx = Arc::new(GitContext {
        project,
        upstream: Arc::new(LocalGitUpstream::new(&root)),
        github: Some(gh),
        audit: audit.clone(),
        limits: Limits {
            idle_timeout: Duration::from_secs(20),
            ..Limits::default()
        },
        allow_delete: false,
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

/// 上流 bare に main の初期コミットを直接（file 経由で）入れる。
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

    // 同じコミットの再 push は冪等（already exists にならない）
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

    // fetch（upload-pack 素通し）で sekimore ブランチが見える
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
    // develop も作る
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
            "tags cannot be pushed",
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
        // 切断ではなく report-status の ng で返すので、git は remote rejected と表示し "hung up" にならない
        assert!(err.contains("[remote rejected]"), "{args:?}: {err}");
        assert!(!err.contains("hung up"), "{args:?}: {err}");
    }
    // 削除は既定拒否
    e.ok(&work, &["push", "origin", "HEAD:refs/heads/sekimore/x"]);
    let o = e.git(&work, &["push", "origin", ":refs/heads/sekimore/x"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr)
        .contains("deleting refs/heads/sekimore/x is not allowed"));
    assert!(e
        .bare_ref("LibOrg/awesome-lib", "refs/heads/sekimore/x")
        .is_some());
    // main は動いていない
    assert_eq!(
        e.bare_ref("LibOrg/awesome-lib", "refs/heads/main").unwrap(),
        main_sha
    );
    assert!(e.bare_ref("LibOrg/awesome-lib", "refs/tags/v1").is_none());

    // 案件外
    let o = e.git(e.dir.path(), &["ls-remote", &e.url("Attacker/evil")]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("is not in project"));
    // read-only: clone は通り push は拒否
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_fast_forward_ng_is_visible_through_sideband() {
    require_tools!();
    let e = setup(&["pr:create"]).await;
    seed_main(&e, "LibOrg/awesome-lib");
    let work = clone(&e, "LibOrg/awesome-lib", "work");
    e.commit_file(&work, "a.txt", b"a\n");
    e.ok(&work, &["push", "origin", "HEAD:refs/heads/sekimore/topic"]);
    // 履歴を巻き戻して別コミット → force push。上流は receive.denyNonFastForwards で ng を返す
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
    // clone し直して中身が届く
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
    // 何も変わらない push（up to date）
    let o = e.git(&work, &["push", "origin", "HEAD:refs/heads/sekimore/same"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}
