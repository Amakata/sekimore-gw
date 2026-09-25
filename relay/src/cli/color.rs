//! Colour for the operator's console (#202).
//!
//! Only the state words are painted — `ok`, `locked`, `missing` and the like — never a label, a
//! path or a value, so the layout is the same with colour and without. The escapes are written
//! here rather than pulled in as a dependency: three colours and a reset is all this needs.
//!
//! Nothing an agent reads is coloured: denial messages (`sekimore: denied: …`), the audit log,
//! `sekimore guide` and every `--json` output stay plain. The decision is made once per process
//! and stdout has to be a terminal, so a pipe or `$(…)` never sees an escape.

use std::io::IsTerminal;
use std::sync::OnceLock;

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

/// What a state word means, not which colour it gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// It is as it should be: `ok`, `unlocked`, `present`.
    Good,
    /// It is broken or shut: `ERROR`, `locked`, `missing`, `denied`.
    Bad,
    /// It works, but it is not what we would recommend: `not initialised`,
    /// a proxy credential out of the environment.
    Warn,
}

impl Tone {
    fn escape(self) -> &'static str {
        match self {
            Tone::Good => GREEN,
            Tone::Bad => RED,
            Tone::Warn => YELLOW,
        }
    }
}

/// `always` → on, `never` / `NO_COLOR` → off, anything else → on only for a terminal.
///
/// `NO_COLOR` wins over `auto` but not over an explicit `always`: the operator who typed
/// `SEKIMORE_COLOR=always` meant that run.
fn decide(var: Option<String>, no_color: bool, stdout_is_tty: bool) -> bool {
    match var.as_deref().map(str::trim) {
        Some("always") => true,
        Some("never") => false,
        _ => !no_color && stdout_is_tty,
    }
}

fn from_env() -> bool {
    decide(
        std::env::var("SEKIMORE_COLOR").ok(),
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    )
}

/// Whether this process colours its output. Decided once, on the first call.
pub fn enabled() -> bool {
    #[cfg(test)]
    if let Some(forced) = test_override() {
        return forced;
    }
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(from_env)
}

/// Wraps `s` in `tone`'s colour, or hands it back untouched when colour is off.
///
/// Callers paint the state word alone and then format it into the line, so the wording is
/// byte-identical to the uncoloured output.
pub fn paint(tone: Tone, s: &str) -> String {
    if !enabled() {
        return s.to_string();
    }
    format!("{}{s}{RESET}", tone.escape())
}

/// `enabled`, decided on stderr instead of stdout: the operator's error lines go there, and
/// `2>/dev/null` or a pipe on stdout alone must not decide for them (#213).
pub fn enabled_on_stderr() -> bool {
    #[cfg(test)]
    if let Some(forced) = test_override() {
        return forced;
    }
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        decide(
            std::env::var("SEKIMORE_COLOR").ok(),
            std::env::var_os("NO_COLOR").is_some(),
            std::io::stderr().is_terminal(),
        )
    })
}

/// `paint` for a line that goes to stderr (#213).
pub fn paint_err(tone: Tone, s: &str) -> String {
    if !enabled_on_stderr() {
        return s.to_string();
    }
    format!("{}{s}{RESET}", tone.escape())
}

#[cfg(test)]
mod force {
    use std::cell::Cell;

    thread_local! {
        /// Per thread, not per process: `cargo test` runs the tests in parallel threads of one
        /// binary, and a global switch here would colour another test's output mid-run.
        static FORCED: Cell<Option<bool>> = const { Cell::new(None) };
    }

    pub fn get() -> Option<bool> {
        FORCED.with(Cell::get)
    }

    pub fn set(on: Option<bool>) {
        FORCED.with(|c| c.set(on));
    }
}

#[cfg(test)]
use force::get as test_override;
#[cfg(test)]
pub use force::set as set_for_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_decision_table() {
        let always = Some("always".to_string());
        let never = Some("never".to_string());
        let auto = Some("auto".to_string());
        // `always` colours even into a pipe, and even under NO_COLOR: it was asked for.
        assert!(decide(always.clone(), false, false));
        assert!(decide(always, true, false));
        // `never` colours nothing, terminal or not.
        assert!(!decide(never.clone(), false, true));
        assert!(!decide(never, true, true));
        // NO_COLOR (any value, including empty) turns auto off.
        assert!(!decide(auto.clone(), true, true));
        assert!(!decide(None, true, true));
        // auto / unset / nonsense: the terminal decides.
        assert!(decide(auto.clone(), false, true));
        assert!(!decide(auto, false, false));
        assert!(decide(None, false, true));
        assert!(!decide(None, false, false));
        assert!(decide(Some("bright pink".to_string()), false, true));
        assert!(!decide(Some("bright pink".to_string()), false, false));
    }

    #[test]
    fn paint_wraps_only_when_it_is_on() {
        set_for_tests(Some(false));
        assert_eq!(paint(Tone::Good, "ok"), "ok");
        assert_eq!(paint(Tone::Bad, "locked"), "locked");
        assert_eq!(paint(Tone::Warn, "not initialised"), "not initialised");
        set_for_tests(Some(true));
        assert_eq!(paint(Tone::Good, "ok"), "\x1b[32mok\x1b[0m");
        assert_eq!(paint(Tone::Bad, "locked"), "\x1b[31mlocked\x1b[0m");
        assert_eq!(
            paint(Tone::Warn, "not initialised"),
            "\x1b[33mnot initialised\x1b[0m"
        );
        set_for_tests(None);
    }
}
