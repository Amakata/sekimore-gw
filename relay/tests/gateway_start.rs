//! `scripts/start-gateway.sh`: how `entrypoint.sh` keeps `sekimore-relay gateway` (the log
//! followers) running — started again when it exits, with a line naming the exit code, never in
//! a hot loop, and not at all once the script is told to stop. The same level as the tests of
//! `scripts/start-relay.sh` in `webui.rs`: the script run by bash with a stand-in binary.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("scripts/start-gateway.sh")
}

/// A stand-in `sekimore-relay` that logs each start and then runs `body`.
fn stand_in(dir: &Path, body: &str) -> (PathBuf, PathBuf) {
    let calls = dir.join("calls");
    let bin = dir.join("sekimore-relay");
    std::fs::write(
        &bin,
        format!("#!/bin/sh\necho \"$$ $*\" >> {}\n{body}\n", calls.display()),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    (bin, calls)
}

fn run(bin: &Path) -> Child {
    Command::new("bash")
        .arg(script())
        .env("SEKIMORE_RELAY_BIN", bin)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn calls(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect()
}

fn wait_until(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn stop(mut child: Child) -> String {
    send_signal(child.id(), "TERM");
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "the script did not stop on SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    err
}

fn send_signal(pid: u32, sig: &str) {
    Command::new("kill")
        .args([&format!("-{sig}"), &pid.to_string()])
        .status()
        .unwrap();
}

#[test]
fn start_gateway_skips_when_the_binary_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new("bash")
        .arg(script())
        .env("SEKIMORE_RELAY_BIN", dir.path().join("nope"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("missing, skipping"));
}

/// A gateway that exits (a panic aborts it with 134) is started again, with the orchestrator's
/// config.yml, and the exit is said on stderr with its code.
#[test]
fn start_gateway_restarts_it_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let (bin, log) = stand_in(dir.path(), "exit 134");
    let child = run(&bin);
    wait_until("a second start", 10, || calls(&log).len() >= 2);
    let err = stop(child);
    let first = &calls(&log)[0];
    assert!(
        first.ends_with(" -v --config /etc/sekimore/config.yml gateway"),
        "{first}"
    );
    assert!(
        err.contains("[gateway] sekimore-relay gateway exited (rc=134);"),
        "{err}"
    );
    assert!(err.contains("starting it again in 2s"), "{err}");
}

/// One that cannot start (it exits at once, every time) is not run in a hot loop: the delay
/// doubles after each short run, 2s, 4s, 8s… up to 60s. In seven seconds that is three starts
/// (at 0s, 2s, 6s), where a fixed 2s would have made four.
#[test]
fn start_gateway_backs_off_from_one_that_cannot_start() {
    let dir = tempfile::tempdir().unwrap();
    let (bin, log) = stand_in(dir.path(), "exit 1");
    let child = run(&bin);
    std::thread::sleep(Duration::from_secs(7));
    let n = calls(&log).len();
    let err = stop(child);
    assert_eq!(n, 3, "{err}");
    assert!(
        err.contains("again in 2s") && err.contains("again in 4s") && err.contains("again in 8s"),
        "{err}"
    );
}

/// SIGTERM stops the loop at once, the running gateway with it, and nothing is started again —
/// whether it comes while the gateway runs or during the delay.
#[test]
fn start_gateway_stops_on_sigterm_and_starts_nothing_more() {
    let dir = tempfile::tempdir().unwrap();
    // runs until it is told to stop
    let (bin, log) = stand_in(dir.path(), "exec sleep 30");
    let child = run(&bin);
    wait_until("the gateway to start", 10, || !calls(&log).is_empty());
    let started = Instant::now();
    let err = stop(child);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(!err.contains("exited"), "{err}");
    let pid = calls(&log)[0].split(' ').next().unwrap().to_string();
    // the gateway went with it
    wait_until("the gateway to end", 5, || {
        !Path::new(&format!("/proc/{pid}")).exists()
            || std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .is_ok_and(|s| s.contains(") Z "))
    });
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(calls(&log).len(), 1);

    // during the delay
    let dir = tempfile::tempdir().unwrap();
    let (bin, log) = stand_in(dir.path(), "exit 1");
    let child = run(&bin);
    wait_until("the first exit", 10, || !calls(&log).is_empty());
    std::thread::sleep(Duration::from_millis(300));
    let started = Instant::now();
    stop(child);
    assert!(started.elapsed() < Duration::from_secs(2));
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(calls(&log).len(), 1);
}
