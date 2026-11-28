//! `paths` prints what `scripts/paths.py` printed, byte for byte.
//!
//! `fixtures/paths/expected.txt` was recorded by running the Python tool (NetworkX 3.7) on
//! `fixtures/paths/paths.yml`, a copy of docs/paths.yml at the time, for every command: each
//! `edges` filter, `paths` between every node and seven targets with and without `--blocked`
//! (and the corner cases: a node to itself, a target that is not a node, an unknown source),
//! `secret` for every secret and an unknown one, and `dot`. The fixture is a copy so that the
//! ledger can change without re-recording.

mod common;

use std::process::Command;

use common::{fixtures, recorded};

#[test]
fn it_prints_what_the_python_tool_printed() {
    let dir = fixtures().join("paths");
    let text = std::fs::read_to_string(dir.join("expected.txt")).unwrap();
    let runs = recorded(&text);
    assert!(runs.len() > 300, "the recording is there: {}", runs.len());
    let mut wrong = Vec::new();
    for r in &runs {
        let out = Command::new(env!("CARGO_BIN_EXE_paths"))
            .arg("--ledger")
            .arg(dir.join("paths.yml"))
            .args(&r.args)
            .output()
            .unwrap();
        let stdout = String::from_utf8(out.stdout).unwrap();
        let code = out.status.code().unwrap();
        if stdout != r.stdout || (code == 0) != (r.code == 0) {
            wrong.push(format!(
                "{:?}: exit {code} (python {})\n--- rust\n{stdout}--- python\n{}",
                r.args, r.code, r.stdout
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn it_reads_the_ledger_in_the_repository_by_default() {
    for args in [&["edges"][..], &["dot"], &["paths", "dev", "internet"]] {
        let out = Command::new(env!("CARGO_BIN_EXE_paths"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!out.stdout.is_empty(), "{args:?} printed nothing");
    }
}

#[test]
fn it_refuses_what_argparse_refused() {
    for args in [
        &["edges", "--without", "nope"][..],
        &["paths", "dev"],
        &["secret"],
        &["dot", "--blocked"],
        &["nope"],
        &[],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_paths"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
}
