//! The dashboard's strings (`/api/i18n`): the language resolved in the same order as before —
//! `?lang=`, the `sekimore_lang` cookie, `ui.language` unless `auto`, `Accept-Language`, English —
//! and the dictionary for it, laid over the English one.
//!
//! The dictionaries are `locales/{en,ja}.json`, moved here from the Python gateway's
//! `src/locales/`. They keep the `maint.*` keys the Python `maint` command still reads from its own
//! copy until it moves (0.3.0-alpha.5), so `/api/i18n` answers exactly what it answered.

use std::fmt;

use serde::de::{Deserializer, MapAccess, Visitor};

use crate::settings::py;

pub const SUPPORTED: [&str; 2] = ["en", "ja"];
pub const DEFAULT: &str = "en";
pub const COOKIE_NAME: &str = "sekimore_lang";

const EN: &str = include_str!("locales/en.json");
const JA: &str = include_str!("locales/ja.json");

/// A dictionary in file order.
struct Ordered(Vec<(String, String)>);

impl<'de> serde::Deserialize<'de> for Ordered {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Ordered;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a flat object of strings")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Ordered, A::Error> {
                let mut out: Vec<(String, String)> = Vec::new();
                while let Some((k, v)) = m.next_entry::<String, String>()? {
                    match out.iter_mut().find(|(x, _)| *x == k) {
                        Some(slot) => slot.1 = v,
                        None => out.push((k, v)),
                    }
                }
                Ok(Ordered(out))
            }
        }
        d.deserialize_map(V)
    }
}

fn load(lang: &str) -> Vec<(String, String)> {
    let text = match lang {
        "ja" => JA,
        _ => EN,
    };
    serde_json::from_str::<Ordered>(text)
        .map(|o| o.0)
        .unwrap_or_default()
}

/// `strings(lang)`: English, with `lang`'s entries over it.
pub fn strings(lang: &str) -> Vec<(String, String)> {
    let mut merged = load(DEFAULT);
    if lang != DEFAULT {
        for (k, v) in load(lang) {
            match merged.iter_mut().find(|(x, _)| *x == k) {
                Some(slot) => slot.1 = v,
                None => merged.push((k, v)),
            }
        }
    }
    merged
}

/// `normalize(tag)`: `^\s*([A-Za-z]{2,3})` and supported, lower-cased.
pub fn normalize(tag: Option<&str>) -> Option<&'static str> {
    let t = tag?;
    let t = t.trim_start_matches(py::is_space);
    let letters: String = t
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .take(3)
        .collect();
    if letters.len() < 2 {
        return None;
    }
    let lang = letters.to_ascii_lowercase();
    SUPPORTED.iter().copied().find(|s| *s == lang)
}

/// Python's `float(s)`, for a `q=` weight.
fn py_float(s: &str) -> Option<f64> {
    let t = py::strip(s);
    let b = t.as_bytes();
    for (i, c) in b.iter().enumerate() {
        if *c == b'_' {
            let before = i.checked_sub(1).and_then(|j| b.get(j));
            let after = b.get(i + 1);
            if !(before.is_some_and(u8::is_ascii_digit) && after.is_some_and(u8::is_ascii_digit)) {
                return None;
            }
        }
    }
    let clean: String = t.chars().filter(|c| *c != '_').collect();
    clean.parse::<f64>().ok()
}

/// `from_accept_language(header)`: the first supported language, highest weight first.
pub fn from_accept_language(header: Option<&str>) -> Option<&'static str> {
    let header = header.filter(|h| !h.is_empty())?;
    let mut items: Vec<(f64, usize, &str)> = Vec::new();
    for (i, part) in header.split(',').enumerate() {
        let piece = py::strip(part);
        if piece.is_empty() {
            continue;
        }
        let (tag, params) = piece.split_once(';').unwrap_or((piece, ""));
        let mut q = 1.0;
        for p in params.split(';') {
            let p = py::strip(p);
            if let Some(v) = p.strip_prefix("q=") {
                q = py_float(v).unwrap_or(0.0);
            }
        }
        items.push((-q, i, py::strip(tag)));
    }
    items.sort_by(|a, b| {
        a.0.partial_cmp(&b.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.1.cmp(&b.1))
    });
    items
        .into_iter()
        .find_map(|(_, _, tag)| normalize(Some(tag)))
}

/// `resolve_lang`.
pub fn resolve_lang(
    explicit: Option<&str>,
    cookie: Option<&str>,
    accept_language: Option<&str>,
    configured: &str,
) -> &'static str {
    for candidate in [explicit, cookie] {
        if let Some(lang) = normalize(candidate) {
            return lang;
        }
    }
    if !configured.is_empty() && configured != "auto" {
        if let Some(lang) = normalize(Some(configured)) {
            return lang;
        }
    }
    from_accept_language(accept_language).unwrap_or(DEFAULT)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn it_resolves_in_the_documented_order() {
        assert_eq!(resolve_lang(Some("ja"), Some("en"), None, "en"), "ja");
        assert_eq!(resolve_lang(Some("xx"), Some("ja-JP"), None, "en"), "ja");
        assert_eq!(resolve_lang(None, None, Some("ja"), "en"), "en");
        assert_eq!(resolve_lang(None, None, Some("ja"), "auto"), "ja");
        assert_eq!(
            resolve_lang(None, None, Some("fr;q=1, ja;q=0.9, en;q=0.8"), "auto"),
            "ja"
        );
        assert_eq!(resolve_lang(None, None, Some("en;q=0.1, ja"), "auto"), "ja");
        assert_eq!(resolve_lang(None, None, None, "None"), "en");
        assert_eq!(normalize(Some("  ja_JP.UTF-8")), Some("ja"));
        assert_eq!(normalize(Some("jap")), None);
        assert_eq!(normalize(Some("j")), None);
    }

    #[test]
    fn every_language_has_every_english_key() {
        let en = load("en");
        let ja = load("ja");
        assert!(en.len() > 100);
        for (k, _) in &en {
            assert!(ja.iter().any(|(x, _)| x == k), "ja lacks {k}");
        }
        assert_eq!(strings("ja").len(), en.len());
    }
}
