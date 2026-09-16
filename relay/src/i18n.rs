//! CLI の文言（0.2.4）。`relay/locales/{en,ja}.json` をバイナリに埋め込み、実行時の言語で選ぶ。
//!
//! 言語は `SEKIMORE_LANG` → `LC_ALL` → `LC_MESSAGES` → `LANG` の順で見て、`ja*` なら日本語、それ以外は英語。
//! 足りないキーは英語に落ち、英語にも無ければキーをそのまま返す。
//!
//! 対象は人間（操作者）向けの出力と `--help`。エージェントに返す拒否理由（`sekimore: …`）と監査ログは
//! 英語のまま固定する（機械照合と AI の可読性のため）。

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

/// `ja` / `ja_JP.UTF-8` / `ja-JP` → `ja`。対応外は None。`C` / `POSIX` も None。
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

/// 環境変数から言語を決める（環境の読み取り関数を渡す。テスト用）。
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

/// 現在のプロセスの言語。
pub fn lang() -> &'static str {
    lang_from(|k| std::env::var(k).ok())
}

/// 指定した言語で文言を返す（無ければ英語 → キー）。
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

/// 現在の言語で文言を返す。
pub fn t(key: &str) -> String {
    t_in(lang(), key)
}

/// `{name}` を埋めて返す。
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
