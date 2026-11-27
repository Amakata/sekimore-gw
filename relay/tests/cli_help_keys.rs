//! #480: no help text, anywhere in the three CLIs and in either language, is a message key.
//!
//! `i18n::t` answers a key it cannot find with the key itself, so a typo or a key never added to
//! `locales/*.json` shows up as `--title <TITLE>  agent.title` and nothing fails. This walks every
//! command and argument of `sekimore-relay`, `sgw-agent` and `sgw` and fails on any word that is
//! shaped like one of the dictionary's keys.
//!
//! The language is read from the environment when a command is built, so the test sets
//! `SEKIMORE_LANG`. It is the only test in this binary: nothing else reads the environment while
//! it is changed.

use std::collections::BTreeSet;

use clap::{Command, CommandFactory};

const EN: &str = include_str!("../locales/en.json");

/// The first segment of every key (`agent`, `cli`, `op`, `sgw`).
fn prefixes() -> BTreeSet<String> {
    let keys: serde_json::Map<String, serde_json::Value> = serde_json::from_str(EN).unwrap();
    keys.keys()
        .filter_map(|k| k.split_once('.').map(|(p, _)| p.to_string()))
        .collect()
}

/// A word that reads as an unresolved key: `<prefix>.<segment>…`, lower case, digits and `_`.
fn looks_like_a_key(word: &str, prefixes: &BTreeSet<String>) -> bool {
    let word = word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.');
    let word = word.trim_end_matches('.');
    let Some((first, rest)) = word.split_once('.') else {
        return false;
    };
    prefixes.contains(first)
        && !rest.is_empty()
        && rest
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
}

fn texts(cmd: &Command, path: &str, out: &mut Vec<(String, String)>) {
    let here = format!("{path} {}", cmd.get_name()).trim().to_string();
    for s in [
        cmd.get_about(),
        cmd.get_long_about(),
        cmd.get_before_help(),
        cmd.get_after_help(),
    ]
    .into_iter()
    .flatten()
    {
        out.push((here.clone(), s.to_string()));
    }
    for a in cmd.get_arguments() {
        let at = format!("{here} --{}", a.get_id());
        for s in [a.get_help(), a.get_long_help()].into_iter().flatten() {
            out.push((at.clone(), s.to_string()));
        }
        for v in a.get_possible_values() {
            if let Some(h) = v.get_help() {
                out.push((at.clone(), h.to_string()));
            }
        }
    }
    for sub in cmd.get_subcommands() {
        texts(sub, &here, out);
    }
}

#[test]
fn no_help_text_in_either_language_is_a_message_key() {
    let prefixes = prefixes();
    assert!(prefixes.contains("agent") && prefixes.contains("sgw"));
    // the check itself: the leak #480 found is caught, and ordinary text is not
    assert!(looks_like_a_key("agent.title", &prefixes));
    assert!(looks_like_a_key("(sgw.cmd.recreate)", &prefixes));
    assert!(!looks_like_a_key("api.github.com", &prefixes));
    assert!(!looks_like_a_key("config.yml", &prefixes));
    assert!(!looks_like_a_key("sgw", &prefixes));

    for lang in ["en", "ja"] {
        std::env::set_var("SEKIMORE_LANG", lang);
        let mut found = Vec::new();
        texts(&sekimore_relay::cli::Cli::command(), "", &mut found);
        texts(
            &sekimore_relay::cli::agent::standalone::AgentCli::command(),
            "",
            &mut found,
        );
        #[cfg(feature = "host")]
        {
            use sekimore_relay::host::groups;
            texts(&sekimore_relay::host::cli::Cli::command(), "", &mut found);
            for g in groups::GROUPS {
                found.push((format!("sgw {}", g.name), groups::group_help(g.name)));
            }
        }
        assert!(found.len() > 300, "{lang}: walked only {}", found.len());
        let leaks: Vec<String> = found
            .iter()
            .filter(|(_, text)| {
                text.split_whitespace()
                    .any(|w| looks_like_a_key(w, &prefixes))
            })
            .map(|(at, text)| format!("{at}: {text}"))
            .collect();
        assert!(
            leaks.is_empty(),
            "{lang}: help text that is a message key:\n{}",
            leaks.join("\n")
        );
    }
}
