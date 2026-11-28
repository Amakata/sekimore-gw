//! How Python prints a value read with `yaml.safe_load`: `str()`, `repr()`, truthiness and
//! `json.dumps`. The tools were Python, and what they print is read by workflows and people, so
//! the Rust versions print the same bytes.

use serde_yaml_ng::Value;

/// `str(v)`: a string as itself, everything else as its `repr`.
pub fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Tagged(t) => py_str(&t.value),
        other => py_repr(other),
    }
}

/// `repr(v)` of what PyYAML hands back: `None`, `True`, `1`, `1.5`, `'text'`, `[…]`, `{…}`.
pub fn py_repr(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                py_float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Value::String(s) => py_repr_str(s),
        Value::Sequence(items) => {
            let inner: Vec<String> = items.iter().map(py_repr).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Mapping(m) => {
            let inner: Vec<String> = m
                .iter()
                .map(|(k, v)| format!("{}: {}", py_repr(k), py_repr(v)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
        Value::Tagged(t) => py_repr(&t.value),
    }
}

/// `repr(f)` of a float: the shortest digits that round-trip, positional between 1e-4 and 1e16.
pub fn py_float(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if f == 0.0 {
        return if f.is_sign_negative() {
            "-0.0".into()
        } else {
            "0.0".into()
        };
    }
    // `{:e}` gives the shortest round-trip digits: "-1.2345e6"
    let sci = format!("{f:e}");
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let (sign, mantissa) = match mantissa.strip_prefix('-') {
        Some(m) => ("-", m),
        None => ("", mantissa),
    };
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    if (-4..16).contains(&exp) {
        let n = digits.len() as i32;
        let body = if exp < 0 {
            format!("0.{}{}", "0".repeat((-exp - 1) as usize), digits)
        } else if exp + 1 >= n {
            format!("{}{}.0", digits, "0".repeat((exp + 1 - n) as usize))
        } else {
            let (a, b) = digits.split_at((exp + 1) as usize);
            format!("{a}.{b}")
        };
        format!("{sign}{body}")
    } else {
        let (first, rest) = digits.split_at(1);
        let frac = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        let esign = if exp < 0 { '-' } else { '+' };
        format!("{sign}{first}{frac}e{esign}{:02}", exp.abs())
    }
}

/// `repr(s)` of a string: single quotes unless it holds a `'` and no `"`.
pub fn py_repr_str(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if !printable(c) => {
                let n = c as u32;
                if n < 0x100 {
                    out.push_str(&format!("\\x{n:02x}"));
                } else if n < 0x10000 {
                    out.push_str(&format!("\\u{n:04x}"));
                } else {
                    out.push_str(&format!("\\U{n:08x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `str.isprintable()` for the characters a YAML file plausibly holds: controls, the separators
/// other than the space, and the invisible format characters are not printable.
fn printable(c: char) -> bool {
    !(c.is_control()
        || matches!(
            c,
            '\u{a0}'
                | '\u{ad}'
                | '\u{1680}'
                | '\u{2000}'..='\u{200f}'
                | '\u{2028}'..='\u{202f}'
                | '\u{205f}'..='\u{2064}'
                | '\u{3000}'
                | '\u{feff}'
        ))
}

/// Python's truthiness: `None`, `False`, `0`, `0.0`, `""`, `[]` and `{}` are false.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Sequence(s) => !s.is_empty(),
        Value::Mapping(m) => !m.is_empty(),
        Value::Tagged(t) => truthy(&t.value),
    }
}

/// A string as `json.dumps` writes it: ASCII only, the rest as `\uXXXX` (surrogate pairs above
/// the BMP).
pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `str.splitlines()`'s separators, for reading the last line of a command's output.
pub fn last_line(s: &str) -> Option<&str> {
    const SEPARATORS: &[char] = &[
        '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
        '\u{2029}',
    ];
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let last = match s.rfind(SEPARATORS) {
        Some(i) => &s[i + s[i..].chars().next().map_or(1, char::len_utf8)..],
        None => s,
    };
    Some(last.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(s: &str) -> Value {
        serde_yaml_ng::from_str(s).unwrap()
    }

    #[test]
    fn floats_print_as_python_prints_them() {
        for (f, want) in [
            (8.3, "8.3"),
            (8.10, "8.1"),
            (10.0, "10.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1e16, "1e+16"),
            (1234567890123456.0, "1234567890123456.0"),
            (-2.5, "-2.5"),
            (1.5e300, "1.5e+300"),
        ] {
            assert_eq!(py_float(f), want, "{f}");
        }
    }

    #[test]
    fn values_print_as_python_prints_them() {
        assert_eq!(
            py_repr(&yaml("{a: 1, b: [x, true, null], 'c': \"it's\"}")),
            "{'a': 1, 'b': ['x', True, None], 'c': \"it's\"}"
        );
        assert_eq!(py_str(&yaml("plain")), "plain");
        assert_eq!(py_repr_str("a'b\"c\\\n"), "'a\\'b\"c\\\\\\n'");
        assert_eq!(py_repr_str("→ \u{7}"), "'→ \\x07'");
    }

    #[test]
    fn json_strings_are_ascii() {
        assert_eq!(json_str("php"), "\"php\"");
        assert_eq!(json_str("é\"😀"), "\"\\u00e9\\\"\\ud83d\\ude00\"");
    }

    #[test]
    fn the_last_line_is_what_mise_printed_last() {
        assert_eq!(last_line("noise\n8.3.35\n"), Some("8.3.35"));
        assert_eq!(last_line("8.3.35"), Some("8.3.35"));
        assert_eq!(last_line("a\r\n b \r\n"), Some("b"));
        assert_eq!(last_line(" \n"), None);
    }
}
