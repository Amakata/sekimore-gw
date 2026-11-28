//! The Python built-ins `src/maint.py` printed and parsed with, with their exact behaviour:
//! `float(str)`, `format(f, "g")`, `f"{f:.1f}"`, `datetime.fromtimestamp(ts, UTC)` and
//! `json.dumps(…, indent=2, ensure_ascii=False)`.

use std::fmt::Write as _;

use crate::settings::py::{float_repr, strip};

/// `float(s)` for a string: Python's whitespace around, a sign, `inf` / `infinity` / `nan` in any
/// case, or a decimal with single underscores between digits and an optional exponent. None where
/// Python raises ValueError. Python also takes other scripts' decimal digits; this does not
/// (difference ledger, as for the config's integers).
pub fn float(s: &str) -> Option<f64> {
    let t = strip(s);
    let (neg, body) = match t.as_bytes().first()? {
        b'-' => (true, t.get(1..)?),
        b'+' => (false, t.get(1..)?),
        _ => (false, t),
    };
    let lower = body.to_ascii_lowercase();
    let v = match lower.as_str() {
        "inf" | "infinity" => f64::INFINITY,
        "nan" => f64::NAN,
        _ => {
            if !decimal(body) {
                return None;
            }
            body.replace('_', "").parse::<f64>().ok()?
        }
    };
    Some(if neg { -v } else { v })
}

/// `digitpart ("." digitpart?)? exponent? | "." digitpart exponent?`, where a digitpart is digits
/// with single underscores between them.
fn decimal(s: &str) -> bool {
    fn digitpart(b: &[u8]) -> usize {
        let mut i = 0;
        while i < b.len() && b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
            if b.get(i) == Some(&b'_') && b.get(i + 1).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
        i
    }
    let b = s.as_bytes();
    let mut i = digitpart(b);
    let int_digits = i > 0;
    let mut frac_digits = false;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let n = digitpart(b.get(i..).unwrap_or_default());
        frac_digits = n > 0;
        i += n;
    }
    if !int_digits && !frac_digits {
        return false;
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let n = digitpart(b.get(i..).unwrap_or_default());
        if n == 0 {
            return false;
        }
        i += n;
    }
    i == b.len()
}

/// `format(f, "g")`: six significant digits, trailing zeros removed, exponent notation below
/// 1e-4 and from 1e6.
pub fn g(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    let sign = if f.is_sign_negative() { "-" } else { "" };
    let a = f.abs();
    if a == 0.0 {
        return format!("{sign}0");
    }
    // rounded to six significant digits first: the exponent is the rounded one's
    let e = format!("{a:.5e}");
    let (mant, exp) = e.split_once('e').unwrap_or((&e, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    if (-4..6).contains(&exp) {
        let prec = (5 - exp) as usize;
        let fixed = format!("{a:.prec$}");
        format!("{sign}{}", trim_zeros(&fixed))
    } else {
        format!(
            "{sign}{}e{}{:02}",
            trim_zeros(mant),
            if exp < 0 { '-' } else { '+' },
            exp.abs()
        )
    }
}

fn trim_zeros(s: &str) -> &str {
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.')
    } else {
        s
    }
}

/// `f"{f:.1f}"`. Both round the exact binary value half to even.
pub fn f1(f: f64) -> String {
    format!("{f:.1}")
}

/// `_fmt_bytes` of `src/maint.py`.
pub fn bytes(n: u64) -> String {
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    for unit in ["KiB", "MiB", "GiB"] {
        v /= 1024.0;
        if v < 1024.0 || unit == "GiB" {
            return format!("{} {unit}", f1(v));
        }
    }
    format!("{} GiB", f1(v))
}

/// A number as SQLite handed it to Python: an int or a float.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Num {
    Int(i64),
    Float(f64),
}

/// `datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")`. Err is the exception Python
/// raised: NaN, or a time outside the years 1 to 9999.
pub fn timestamp(ts: Num) -> Result<String, String> {
    let secs: i64 = match ts {
        Num::Int(i) => i,
        Num::Float(f) => {
            if f.is_nan() {
                return Err("Invalid value NaN (not a number)".into());
            }
            // _PyTime_DoubleToDenominator with ROUND_HALF_EVEN, to the microsecond
            let mut int = f.trunc();
            let frac = (f.fract() * 1e6).round_ties_even();
            if frac >= 1e6 {
                int += 1.0;
            } else if frac < 0.0 {
                int -= 1.0;
            }
            if !(-9.2e18..9.2e18).contains(&int) {
                return Err("timestamp out of range for platform time_t".into());
            }
            int as i64
        }
    };
    const MIN: i64 = -62_135_596_800; // 0001-01-01T00:00:00Z
    const MAX: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z
    if !(MIN..=MAX).contains(&secs) {
        return Err("year is out of range".into());
    }
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    Ok(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A value `json.dumps` writes.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

/// `json.dumps(v, ensure_ascii=False, indent=2)`.
pub fn dumps_indent(v: &Json) -> String {
    let mut out = String::new();
    write_json(v, 0, &mut out);
    out
}

fn write_json(v: &Json, level: usize, out: &mut String) {
    let pad = |n: usize| "  ".repeat(n);
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Json::Float(f) if f.is_nan() => out.push_str("NaN"),
        Json::Float(f) if f.is_infinite() => {
            out.push_str(if *f > 0.0 { "Infinity" } else { "-Infinity" })
        }
        Json::Float(f) => out.push_str(&float_repr(*f)),
        Json::Str(s) => write_str(s, out),
        Json::Arr(items) if items.is_empty() => out.push_str("[]"),
        Json::Arr(items) => {
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&pad(level + 1));
                write_json(item, level + 1, out);
            }
            out.push('\n');
            out.push_str(&pad(level));
            out.push(']');
        }
        Json::Obj(fields) if fields.is_empty() => out.push_str("{}"),
        Json::Obj(fields) => {
            out.push_str("{\n");
            for (i, (k, item)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&pad(level + 1));
                write_str(k, out);
                out.push_str(": ");
                write_json(item, level + 1, out);
            }
            out.push('\n');
            out.push_str(&pad(level));
            out.push('}');
        }
    }
}

/// A string as `json.dumps(…, ensure_ascii=False)` writes it.
pub fn write_str(s: &str, out: &mut String) {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn float_reads_what_python_reads() {
        for (s, v) in [
            ("90", 90.0),
            (" 1.5\n", 1.5),
            ("1_000", 1000.0),
            ("1e3", 1000.0),
            ("-.5", -0.5),
            ("5.", 5.0),
            ("+1E-2", 0.01),
            ("1_0.0_1e1_0", 10.01e10),
            ("\u{a0}2\u{1f}", 2.0),
        ] {
            assert_eq!(float(s), Some(v), "{s:?}");
        }
        assert!(float("nan").unwrap().is_nan());
        assert_eq!(float("-Infinity"), Some(f64::NEG_INFINITY));
        assert_eq!(float("iNf"), Some(f64::INFINITY));
        for s in [
            "",
            "x",
            "1__0",
            "_1",
            "1_",
            ".",
            "e3",
            "1e",
            "1e_3",
            "0x10",
            "1.5.2",
            "inf inity",
            "--1",
        ] {
            assert_eq!(float(s), None, "{s:?}");
        }
    }

    #[test]
    fn g_formats_as_python_does() {
        for (f, s) in [
            (90.0, "90"),
            (0.5, "0.5"),
            (1e6, "1e+06"),
            (123456.0, "123456"),
            (1234567.0, "1.23457e+06"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (-0.0, "-0"),
            (999999.5, "1e+06"),
            (1.5e300, "1.5e+300"),
            (-2.25, "-2.25"),
        ] {
            assert_eq!(g(f), s, "{f}");
        }
        assert_eq!(g(f64::NAN), "nan");
        assert_eq!(g(f64::NEG_INFINITY), "-inf");
    }

    #[test]
    fn bytes_formats_as_maint_did() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1024), "1.0 KiB");
        // a tie rounds to even, as Python's format does
        assert_eq!(bytes(1280), "1.2 KiB");
        assert_eq!(bytes(1024 * 1024 * 3 / 2), "1.5 MiB");
        assert_eq!(bytes(5 * 1024 * 1024 * 1024 * 1024), "5120.0 GiB");
    }

    #[test]
    fn timestamps_round_to_the_microsecond_first() {
        assert_eq!(timestamp(Num::Float(0.0)).unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(
            timestamp(Num::Int(1_700_000_000)).unwrap(),
            "2023-11-14T22:13:20Z"
        );
        assert_eq!(
            timestamp(Num::Float(1.9999999)).unwrap(),
            "1970-01-01T00:00:02Z"
        );
        assert_eq!(
            timestamp(Num::Float(1.9999994)).unwrap(),
            "1970-01-01T00:00:01Z"
        );
        assert_eq!(timestamp(Num::Float(-0.5)).unwrap(), "1969-12-31T23:59:59Z");
        assert_eq!(
            timestamp(Num::Int(-62_135_596_800)).unwrap(),
            "0001-01-01T00:00:00Z"
        );
        assert_eq!(
            timestamp(Num::Int(253_402_300_799)).unwrap(),
            "9999-12-31T23:59:59Z"
        );
        assert!(timestamp(Num::Int(253_402_300_800)).is_err());
        assert!(timestamp(Num::Float(f64::NAN)).is_err());
        assert!(timestamp(Num::Float(1e300)).is_err());
        assert_eq!(
            timestamp(Num::Int(951_782_400)).unwrap(),
            "2000-02-29T00:00:00Z"
        );
    }

    #[test]
    fn json_is_written_as_python_indents_it() {
        let v = Json::Obj(vec![
            ("a".into(), Json::Obj(vec![])),
            (
                "b".into(),
                Json::Arr(vec![Json::Str("x\u{1}é".into()), Json::Float(1.0)]),
            ),
            ("c".into(), Json::Float(f64::NAN)),
            ("d".into(), Json::Arr(vec![])),
            ("e".into(), Json::Float(1e16)),
        ]);
        assert_eq!(
            dumps_indent(&v),
            "{\n  \"a\": {},\n  \"b\": [\n    \"x\\u0001é\",\n    1.0\n  ],\n  \"c\": NaN,\n  \"d\": [],\n  \"e\": 1e+16\n}"
        );
    }
}
