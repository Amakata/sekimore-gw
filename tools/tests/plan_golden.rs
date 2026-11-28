//! `lang-plan` prints what `lang/plan.py` printed, byte for byte, and asks docker the same
//! questions in the same order.
//!
//! Each directory under `fixtures/plan/` is one run recorded from the Python tool: `args`, the
//! files it read (`lang/versions.yml`, `lang/Dockerfile`, `base.yml`, `changed`), what docker
//! answered (`latest`, `registry`, through the `docker` stand-in), and what came out: `expected`
//! (the exit code, then stdout) and `expected-docker` (every docker call). The inputs include
//! the real lang/versions.yml and every earlier form of it (`git log -- lang/versions.yml`).

mod common;

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use common::{fixtures, shell_words};

#[test]
fn it_plans_what_the_python_tool_planned() {
    let root = fixtures().join("plan");
    let shim_dir = tempfile::tempdir().unwrap();
    let shim = shim_dir.path().join("docker");
    std::fs::copy(root.join("docker"), &shim).unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        shim_dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut cases: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    cases.sort();
    assert!(
        cases.len() >= 40,
        "the recordings are there: {}",
        cases.len()
    );

    let mut wrong = Vec::new();
    for case in &cases {
        let name = case.file_name().unwrap().to_string_lossy().to_string();
        let args = shell_words(
            std::fs::read_to_string(case.join("args"))
                .unwrap()
                .trim_end(),
        );
        let log = shim_dir.path().join(format!("{name}.log"));
        std::fs::write(&log, "").unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_lang-plan"))
            .args(&args)
            .current_dir(case)
            .env("PATH", &path)
            .env("DOCKER_LOG", &log)
            .output()
            .unwrap();
        let got = format!(
            "exit {}\n{}",
            out.status.code().unwrap(),
            String::from_utf8(out.stdout).unwrap()
        );
        let want = std::fs::read_to_string(case.join("expected")).unwrap();
        let docker = std::fs::read_to_string(&log).unwrap();
        let want_docker = std::fs::read_to_string(case.join("expected-docker")).unwrap();
        if got != want || docker != want_docker {
            wrong.push(format!(
                "{name}:\n--- rust\n{got}{docker}--- python\n{want}{want_docker}--- stderr\n{}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
