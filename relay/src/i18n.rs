//! CLI strings (0.2.4). `relay/locales/{en,ja}.json` are embedded in the binary and selected by the runtime language.
//!
//! The language comes from `SEKIMORE_LANG` → `LC_ALL` → `LC_MESSAGES` → `LANG`, in that order: `ja*` means Japanese, anything else English.
//! A missing key falls back to English, and to the key itself if English lacks it too.
//!
//! This covers output aimed at humans (the operator) and `--help`. Denial reasons returned to agents (`sekimore: …`) and the audit log
//! stay in English (for machine matching and AI readability).

use std::collections::HashMap;
use std::sync::OnceLock;

const EN: &str = include_str!("../locales/en.json");
const JA: &str = include_str!("../locales/ja.json");

pub const SUPPORTED: &[&str] = &["en", "ja"];
pub const DEFAULT: &str = "en";

fn parse(text: &str) -> HashMap<String, String> {
    serde_json::from_str::<HashMap<String, String>>(text).unwrap_or_default()
}

fn table(lang: &str) -> &'static HashMap<String, String> {
    static EN_TABLE: OnceLock<HashMap<String, String>> = OnceLock::new();
    static JA_TABLE: OnceLock<HashMap<String, String>> = OnceLock::new();
    match lang {
        "ja" => JA_TABLE.get_or_init(|| parse(JA)),
        _ => EN_TABLE.get_or_init(|| parse(EN)),
    }
}

/// Maps `ja` / `ja_JP.UTF-8` / `ja-JP` → `ja`. Unsupported tags, as well as `C` and `POSIX`, give None.
pub fn normalize(tag: &str) -> Option<&'static str> {
    let tag = tag.trim();
    if tag.is_empty() {
        return None;
    }
    let primary: String = tag
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect::<String>()
        .to_ascii_lowercase();
    SUPPORTED.iter().copied().find(|l| *l == primary)
}

/// Determines the language from the environment (the lookup function is injected for tests).
pub fn lang_from(get: impl Fn(&str) -> Option<String>) -> &'static str {
    for var in ["SEKIMORE_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Some(v) = get(var) {
            if let Some(l) = normalize(&v) {
                return l;
            }
        }
    }
    DEFAULT
}

/// The language of the current process.
pub fn lang() -> &'static str {
    lang_from(|k| std::env::var(k).ok())
}

/// Returns the string in the given language (falling back to English, then the key).
pub fn t_in(lang: &str, key: &str) -> String {
    if let Some(s) = table(lang).get(key) {
        return s.clone();
    }
    if lang != DEFAULT {
        if let Some(s) = table(DEFAULT).get(key) {
            return s.clone();
        }
    }
    key.to_string()
}

/// Returns the string in the current language.
pub fn t(key: &str) -> String {
    t_in(lang(), key)
}

/// Fills in `{name}` placeholders and returns the result.
pub fn tf(key: &str, vars: &[(&str, &str)]) -> String {
    let mut s = t(key);
    for (name, value) in vars {
        s = s.replace(&format!("{{{name}}}"), value);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_is_taken_from_the_environment_in_order() {
        let env = |pairs: &[(&str, &str)]| {
            let map: HashMap<String, String> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            move |k: &str| map.get(k).cloned()
        };
        assert_eq!(lang_from(env(&[])), "en");
        assert_eq!(lang_from(env(&[("LANG", "ja_JP.UTF-8")])), "ja");
        assert_eq!(lang_from(env(&[("LANG", "C")])), "en");
        assert_eq!(
            lang_from(env(&[("LANG", "ja_JP.UTF-8"), ("SEKIMORE_LANG", "en")])),
            "en"
        );
        assert_eq!(
            lang_from(env(&[("LANG", "en_US.UTF-8"), ("LC_MESSAGES", "ja")])),
            "ja"
        );
        assert_eq!(lang_from(env(&[("LANG", "fr_FR.UTF-8")])), "en");
    }

    #[test]
    fn both_dictionaries_have_the_same_keys_and_fall_back_to_english() {
        let en = parse(EN);
        let ja = parse(JA);
        assert!(!en.is_empty() && !ja.is_empty());
        let mut only_en: Vec<_> = en.keys().filter(|k| !ja.contains_key(*k)).collect();
        let mut only_ja: Vec<_> = ja.keys().filter(|k| !en.contains_key(*k)).collect();
        only_en.sort();
        only_ja.sort();
        assert!(
            only_en.is_empty() && only_ja.is_empty(),
            "en-only {only_en:?} ja-only {only_ja:?}"
        );
        assert_eq!(t_in("ja", "cli.logout"), "上流トークンを削除する");
        assert_eq!(t_in("en", "cli.logout"), "Delete the upstream token");
        assert_eq!(t_in("fr", "cli.logout"), "Delete the upstream token");
        assert_eq!(t_in("ja", "no.such.key"), "no.such.key");
    }
}
