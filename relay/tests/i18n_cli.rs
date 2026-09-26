//! Localization of the CLI (0.2.4): help strings, the guide, and what stays English on purpose.

use clap::CommandFactory;
use sekimore_relay::cli::agent::{guide_for, AGENT_GUIDE_EN, AGENT_GUIDE_JA};
use sekimore_relay::cli::Cli;
use sekimore_relay::i18n;

fn is_japanese(s: &str) -> bool {
    s.chars()
        .any(|c| matches!(c as u32, 0x3040..=0x30FF | 0x4E00..=0x9FFF))
}

#[test]
fn every_subcommand_and_option_has_a_help_string() {
    let cmd = Cli::command();
    for sub in cmd.get_subcommands() {
        assert!(
            sub.get_about().is_some(),
            "subcommand {} has no about",
            sub.get_name()
        );
        for arg in sub.get_arguments() {
            if arg.get_id() == "help" || arg.get_id() == "version" {
                continue;
            }
            assert!(
                arg.get_help().is_some(),
                "{} --{} has no help",
                sub.get_name(),
                arg.get_id()
            );
        }
    }
}

#[test]
fn help_strings_come_from_the_dictionary_and_never_show_the_raw_key() {
    let cmd = Cli::command();
    let about = cmd.get_about().expect("about").to_string();
    assert!(!about.contains("cli.about"), "{about}");
    for sub in cmd.get_subcommands() {
        let about = sub.get_about().expect("about").to_string();
        assert!(
            !about.starts_with("cli.") && !about.starts_with("agent."),
            "{} shows a raw key: {about}",
            sub.get_name()
        );
    }
}

#[test]
fn the_default_language_is_english() {
    // The test binary inherits the ambient LANG, so check the dictionary itself rather than the
    // built command: `t()` reads the environment at call time.
    assert_eq!(i18n::lang_from(|_| None), "en");
    assert!(!is_japanese(&i18n::t_in("en", "cli.about")));
    assert!(is_japanese(&i18n::t_in("ja", "cli.about")));
}

#[test]
fn the_guide_is_available_in_both_languages() {
    assert!(AGENT_GUIDE_EN.starts_with("# sekimore-relay"));
    assert!(
        !is_japanese(AGENT_GUIDE_EN),
        "the English guide has Japanese in it"
    );
    assert!(is_japanese(AGENT_GUIDE_JA));
    assert_eq!(guide_for(Some("ja")), AGENT_GUIDE_JA);
    assert_eq!(guide_for(Some("en")), AGENT_GUIDE_EN);
    // An unsupported or absent language falls back to the environment, and to English from there.
    assert_eq!(guide_for(Some("fr")), guide_for(None));
    // Both guides describe the same commands, so an agent gets the same rules either way.
    for needle in [
        "refs/for/",
        // #158: the branch namespace is the project's to choose, so the guide names no
        // particular one. What both languages must still describe is the spelling itself.
        "refs/heads/<branch>",
        "refs/pr/",
        "sgw-agent whoami",
        "sgw-agent pr create",
        "sgw-agent ci log",
    ] {
        assert!(AGENT_GUIDE_EN.contains(needle), "en guide misses {needle}");
        assert!(AGENT_GUIDE_JA.contains(needle), "ja guide misses {needle}");
    }
}

#[test]
fn denial_messages_stay_english() {
    // Denials are matched by tooling and read by agents, so they are not translated.
    for key in ["op.check.project", "op.login.stored"] {
        assert!(!i18n::t_in("en", key).is_empty());
    }
    let denial = sekimore_relay::policy::Denied::RepoNotInProject {
        repo: "Org/Repo".into(),
        project: "case-a".into(),
    }
    .to_string();
    assert!(!is_japanese(&denial), "{denial}");
}

/// The guide annotates every command with the permission key it needs, because an agent that sees
/// `sekimore pr update` will otherwise assume a `pr:update` key exists and ask a human for it.
/// A key written there that the policy does not define is worse than no annotation at all.
#[test]
fn every_permission_named_in_the_guide_exists() {
    use sekimore_relay::policy::all_permission_keys;
    let known = all_permission_keys();
    for (lang, guide) in [("en", AGENT_GUIDE_EN), ("ja", AGENT_GUIDE_JA)] {
        let mut named = Vec::new();
        for line in guide.lines() {
            // `[pr:read]` — the bracketed key beside a command
            let mut rest = line;
            while let Some(i) = rest.find('[') {
                rest = &rest[i + 1..];
                if let Some(j) = rest.find(']') {
                    let k = &rest[..j];
                    if k.contains(':') && !k.contains(' ') && !k.contains('|') {
                        named.push(k.to_string());
                    }
                }
            }
        }
        assert!(
            named.len() > 20,
            "{lang}: expected the command list to be annotated, found {}",
            named.len()
        );
        let unknown: Vec<_> = named
            .iter()
            .filter(|k| !known.contains(k))
            .cloned()
            .collect();
        assert!(
            unknown.is_empty(),
            "{lang} guide names permissions the policy does not define: {unknown:?}"
        );
    }
}
