//! The few Python built-ins `src/config.py` leans on, with their exact behaviour: `str.strip()`,
//! `str.isspace()`, `str.lower()`, `int()`, `str()` of a YAML value, `repr()` of a float, and
//! the `json.dumps(…, sort_keys=True, default=str, ensure_ascii=False)` behind
//! `relay_fingerprint`.

use std::cmp::Ordering;
use std::fmt::Write as _;

use super::yaml11::{int_float_cmp, naive_key, number, utc_key, DateTime, Num, PyValue};

/// `str.isspace()` for one character: Python's whitespace is Unicode's White_Space plus the four
/// information separators U+001C..U+001F.
pub fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.strip()`.
pub fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `str.lower()`. Rust's full Unicode lowercasing, which agrees with Python's (both apply the
/// final-sigma rule and the special casings).
pub fn lower(s: &str) -> String {
    s.to_lowercase()
}

/// `str.rstrip(".")`.
pub fn rstrip_dots(s: &str) -> &str {
    s.trim_end_matches('.')
}

/// `int(s)` for a string, base 10: surrounding whitespace, a sign, digits with single
/// underscores between them. None where Python raises ValueError.
///
/// Python also takes non-ASCII decimal digits (`int("２２")` is 22); this does not (difference
/// ledger). A value outside `i128` is None too.
pub fn int(s: &str) -> Option<i128> {
    let t = strip(s);
    let (neg, digits) = match t.as_bytes().first()? {
        b'-' => (true, &t[1..]),
        b'+' => (false, &t[1..]),
        _ => (false, t),
    };
    let b = digits.as_bytes();
    if b.is_empty() || !b[0].is_ascii_digit() || !b[b.len() - 1].is_ascii_digit() {
        return None;
    }
    if b.windows(2).any(|w| w == b"__") || b.iter().any(|c| !c.is_ascii_digit() && *c != b'_') {
        return None;
    }
    let clean: String = digits.chars().filter(|c| *c != '_').collect();
    let n: i128 = clean.parse().ok()?;
    Some(if neg { -n } else { n })
}

/// `repr(float)`: the shortest digits that read back, in fixed notation from 1e-4 up to 1e16 and
/// in exponent notation outside that.
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    // `{:e}` is the shortest round-trip form too: "1.5e-5", "-0e0", "1.2345e3"
    let e = format!("{f:e}");
    let (mant, exp) = e.split_once('e').unwrap_or((&e, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let (neg, mant) = match mant.strip_prefix('-') {
        Some(m) => (true, m),
        None => (false, mant),
    };
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if !(-4..16).contains(&exp) {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let _ = write!(out, "e{}{:02}", if exp < 0 { '-' } else { '+' }, exp.abs());
    } else if exp >= 0 {
        let int_len = exp as usize + 1;
        if digits.len() <= int_len {
            out.push_str(&digits);
            out.push_str(&"0".repeat(int_len - digits.len()));
            out.push_str(".0");
        } else {
            out.push_str(&digits[..int_len]);
            out.push('.');
            out.push_str(&digits[int_len..]);
        }
    } else {
        out.push_str("0.");
        out.push_str(&"0".repeat((-exp - 1) as usize));
        out.push_str(&digits);
    }
    out
}

fn datetime_str(d: &DateTime) -> String {
    let mut s = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        d.date.year, d.date.month, d.date.day, d.hour, d.minute, d.second
    );
    if d.microsecond != 0 {
        let _ = write!(s, ".{:06}", d.microsecond);
    }
    if let Some(m) = d.offset_minutes {
        let _ = write!(
            s,
            "{}{:02}:{:02}",
            if m < 0 { '-' } else { '+' },
            m.abs() / 60,
            m.abs() % 60
        );
    }
    s
}

/// `str(value)` for a scalar PyYAML can produce. Collections are written like Python's repr
/// closely enough for a message; nothing compares them.
pub fn str_of(v: &PyValue) -> String {
    match v {
        PyValue::None => "None".into(),
        PyValue::Bool(true) => "True".into(),
        PyValue::Bool(false) => "False".into(),
        PyValue::Int(i) => i.to_string(),
        PyValue::Float(f) => float_repr(*f),
        PyValue::Str(s) => s.clone(),
        PyValue::Date(d) => format!("{:04}-{:02}-{:02}", d.year, d.month, d.day),
        PyValue::DateTime(d) => datetime_str(d),
        PyValue::List(_) => "[…]".into(),
        PyValue::Dict(_) => "{…}".into(),
    }
}

/// `json.dumps` raised TypeError: a dict whose keys cannot be ordered against each other
/// (`sort_keys`), or a key JSON cannot hold (a date).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonKeyError(pub String);

/// `json.dumps(v, sort_keys=True, default=str, ensure_ascii=False)`.
pub fn json_dumps(v: &PyValue) -> Result<String, JsonKeyError> {
    let mut out = String::new();
    dump(v, &mut out)?;
    Ok(out)
}

fn json_str(s: &str, out: &mut String) {
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
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_float(f: f64) -> String {
    if f.is_nan() {
        "NaN".into()
    } else if f.is_infinite() {
        if f > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        }
    } else {
        float_repr(f)
    }
}

fn dump(v: &PyValue, out: &mut String) -> Result<(), JsonKeyError> {
    match v {
        PyValue::None => out.push_str("null"),
        PyValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        PyValue::Int(i) => {
            let _ = write!(out, "{i}");
        }
        PyValue::Float(f) => out.push_str(&json_float(*f)),
        PyValue::Str(s) => json_str(s, out),
        PyValue::Date(_) | PyValue::DateTime(_) => json_str(&str_of(v), out),
        PyValue::List(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                dump(item, out)?;
            }
            out.push(']');
        }
        PyValue::Dict(pairs) => {
            let mut sorted: Vec<&(PyValue, PyValue)> = pairs.iter().collect();
            sort_keys(&mut sorted)?;
            out.push('{');
            for (i, (k, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                match k {
                    PyValue::Str(s) => json_str(s, out),
                    PyValue::Int(n) => json_str(&n.to_string(), out),
                    PyValue::Float(f) => json_str(&json_float(*f), out),
                    PyValue::Bool(b) => json_str(if *b { "true" } else { "false" }, out),
                    PyValue::None => json_str("null", out),
                    other => {
                        return Err(JsonKeyError(format!(
                            "keys must be str, int, float, bool or None, not {}",
                            type_name(other)
                        )))
                    }
                }
                out.push_str(": ");
                dump(val, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

pub fn type_name(v: &PyValue) -> &'static str {
    match v {
        PyValue::None => "NoneType",
        PyValue::Bool(_) => "bool",
        PyValue::Int(_) => "int",
        PyValue::Float(_) => "float",
        PyValue::Str(_) => "str",
        PyValue::Date(_) => "date",
        PyValue::DateTime(_) => "datetime",
        PyValue::List(_) => "list",
        PyValue::Dict(_) => "dict",
    }
}

/// Which keys Python can order against each other with `<`.
#[derive(PartialEq, Eq)]
enum Class {
    Number,
    Str,
    Date,
    NaiveDateTime,
    AwareDateTime,
    NoneType,
    Other,
}

fn class(v: &PyValue) -> Class {
    match v {
        PyValue::Bool(_) | PyValue::Int(_) | PyValue::Float(_) => Class::Number,
        PyValue::Str(_) => Class::Str,
        PyValue::Date(_) => Class::Date,
        PyValue::DateTime(d) if d.offset_minutes.is_some() => Class::AwareDateTime,
        PyValue::DateTime(_) => Class::NaiveDateTime,
        PyValue::None => Class::NoneType,
        _ => Class::Other,
    }
}

/// `sorted(d.items())`. Two keys of different classes make Python's sort raise TypeError, and
/// so does a pair of `None` (there is only ever one). A NaN key sorts last here; Python's order
/// for it depends on where it fell, so the fingerprint of such a file may differ from Python's.
fn sort_keys(items: &mut [&(PyValue, PyValue)]) -> Result<(), JsonKeyError> {
    if items.len() < 2 {
        return Ok(());
    }
    let first = class(&items[0].0);
    if first == Class::NoneType || items.iter().any(|(k, _)| class(k) != first) {
        return Err(JsonKeyError(
            "'<' not supported between the keys of one mapping".into(),
        ));
    }
    items.sort_by(|(a, _), (b, _)| key_cmp(a, b));
    Ok(())
}

fn key_cmp(a: &PyValue, b: &PyValue) -> Ordering {
    match (a, b) {
        (PyValue::Str(x), PyValue::Str(y)) => x.cmp(y),
        (PyValue::Date(x), PyValue::Date(y)) => {
            (x.year, x.month, x.day).cmp(&(y.year, y.month, y.day))
        }
        (PyValue::DateTime(x), PyValue::DateTime(y)) => {
            if x.offset_minutes.is_some() {
                utc_key(x).cmp(&utc_key(y))
            } else {
                naive_key(x).cmp(&naive_key(y))
            }
        }
        _ => match (number(a), number(b)) {
            (Some(x), Some(y)) => num_cmp(x, y),
            _ => Ordering::Equal,
        },
    }
}

fn num_cmp(a: Num, b: Num) -> Ordering {
    match (a, b) {
        (Num::I(x), Num::I(y)) => x.cmp(&y),
        (Num::F(x), Num::F(y)) => x.partial_cmp(&y).unwrap_or_else(|| {
            // NaN last
            x.is_nan().cmp(&y.is_nan())
        }),
        (Num::I(i), Num::F(f)) => int_float_cmp(i, f).unwrap_or(Ordering::Less),
        (Num::F(f), Num::I(i)) => int_float_cmp(i, f)
            .map(Ordering::reverse)
            .unwrap_or(Ordering::Greater),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_repr_matches_python() {
        for (f, want) in [
            (1.0, "1.0"),
            (1.5, "1.5"),
            (100.0, "100.0"),
            (0.001, "0.001"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.5e-5, "1.5e-05"),
            (1e16, "1e+16"),
            (1.2345e16, "1.2345e+16"),
            (9999999999999998.0, "9999999999999998.0"),
            (123456789.125, "123456789.125"),
            (-0.0, "-0.0"),
            (0.1, "0.1"),
            (1e100, "1e+100"),
            (f64::INFINITY, "inf"),
        ] {
            assert_eq!(float_repr(f), want, "{f}");
        }
    }

    #[test]
    fn int_matches_python() {
        assert_eq!(int("22"), Some(22));
        assert_eq!(int(" +22\n"), Some(22));
        assert_eq!(int("-5"), Some(-5));
        assert_eq!(int("2_2"), Some(22));
        assert_eq!(int("007"), Some(7));
        assert_eq!(int("2__2"), None);
        assert_eq!(int("_22"), None);
        assert_eq!(int("22_"), None);
        assert_eq!(int(""), None);
        assert_eq!(int("0x10"), None);
        assert_eq!(int("1.0"), None);
        assert_eq!(int("\u{1c}5"), Some(5));
    }

    #[test]
    fn json_dumps_sorts_and_escapes_like_python() {
        let v = PyValue::Dict(vec![
            (PyValue::Str("b".into()), PyValue::Float(1.0)),
            (
                PyValue::Str("a".into()),
                PyValue::Str("x\"\u{1}\u{e9}".into()),
            ),
        ]);
        assert_eq!(
            json_dumps(&v).unwrap(),
            "{\"a\": \"x\\\"\\u0001\u{e9}\", \"b\": 1.0}"
        );
        let mixed = PyValue::Dict(vec![
            (PyValue::Int(1), PyValue::None),
            (PyValue::Str("a".into()), PyValue::None),
        ]);
        assert!(json_dumps(&mixed).is_err());
        let nums = PyValue::Dict(vec![
            (PyValue::Int(2), PyValue::None),
            (PyValue::Bool(true), PyValue::List(vec![])),
            (PyValue::Float(1.5), PyValue::Dict(vec![])),
        ]);
        assert_eq!(
            json_dumps(&nums).unwrap(),
            "{\"true\": [], \"1.5\": {}, \"2\": null}"
        );
    }
}
