//! Shared by the golden tests: the recorded runs of the Python tools.

#![allow(dead_code)]

use std::path::PathBuf;

pub fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// One recorded run: the arguments, the exit code and what it printed.
#[derive(Debug)]
pub struct Recorded {
    pub args: Vec<String>,
    pub code: i32,
    pub stdout: String,
}

/// Reads `#=# <code> | <shlex-joined args>` headers, each followed by the run's stdout.
pub fn recorded(text: &str) -> Vec<Recorded> {
    let mut out: Vec<Recorded> = Vec::new();
    for line in text.split_inclusive('\n') {
        if let Some(head) = line.strip_prefix("#=# ") {
            let (code, args) = head
                .trim_end_matches('\n')
                .split_once(" | ")
                .expect("header");
            out.push(Recorded {
                args: shell_words(args),
                code: code.parse().expect("exit code"),
                stdout: String::new(),
            });
        } else {
            out.last_mut()
                .expect("a header first")
                .stdout
                .push_str(line);
        }
    }
    out
}

/// Splits what Python's `shlex.join` wrote: words, single-quoted where needed.
pub fn shell_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut started = false;
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '\'' => {
                quoted = !quoted;
                started = true;
            }
            ' ' if !quoted => {
                if started {
                    words.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            c => {
                cur.push(c);
                started = true;
            }
        }
    }
    if started {
        words.push(cur);
    }
    words
}
