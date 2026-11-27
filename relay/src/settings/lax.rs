//! pydantic 2's lax-mode conversions, for the field types `src/config.py` uses.
//!
//! Each was measured against pydantic 2.14 rather than read from its documentation; the cases
//! are in the tests below and in the equivalence corpus (`relay/tests/fixtures/corpus/`).

use super::yaml11::PyValue;

/// Where a value failed, as pydantic writes `loc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loc {
    Key(String),
    Index(usize),
}

impl std::fmt::Display for Loc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Loc::Key(k) => f.write_str(k),
            Loc::Index(i) => write!(f, "{i}"),
        }
    }
}

/// One entry of a pydantic `ValidationError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    pub loc: Vec<Loc>,
    pub message: String,
}

impl FieldError {
    /// `a.b.0`, the dotted form of `loc`.
    pub fn path(&self) -> String {
        self.loc
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }
}

/// Collects errors under a location prefix, as pydantic does while it walks the model.
pub struct Errors {
    pub list: Vec<FieldError>,
}

impl Errors {
    pub fn new() -> Self {
        Errors { list: Vec::new() }
    }
    pub fn push(&mut self, loc: &[Loc], message: impl Into<String>) {
        self.list.push(FieldError {
            loc: loc.to_vec(),
            message: message.into(),
        });
    }
}

impl Default for Errors {
    fn default() -> Self {
        Self::new()
    }
}

pub fn at(loc: &[Loc], key: &str) -> Vec<Loc> {
    let mut l = loc.to_vec();
    l.push(Loc::Key(key.to_string()));
    l
}

fn at_index(loc: &[Loc], i: usize) -> Vec<Loc> {
    let mut l = loc.to_vec();
    l.push(Loc::Index(i));
    l
}

/// `str`: only a string. pydantic 2 does not turn a number or a boolean into one.
pub fn string(v: &PyValue, loc: &[Loc], e: &mut Errors) -> Option<String> {
    match v {
        PyValue::Str(s) => Some(s.clone()),
        _ => {
            e.push(loc, "Input should be a valid string");
            None
        }
    }
}

/// `str | None`. `Some(None)` is a valid None, `None` a failure.
pub fn opt_string(v: &PyValue, loc: &[Loc], e: &mut Errors) -> Option<Option<String>> {
    match v {
        PyValue::None => Some(None),
        _ => string(v, loc, e).map(Some),
    }
}

/// `int`: an int; a bool (as 0 / 1); a float with no fractional part strictly inside ±2**63; a
/// string holding a decimal integer, optionally signed, with single underscores between digits
/// and an optional fraction of zeros (`" 3_128.00 "` is 3128).
pub fn int(v: &PyValue, loc: &[Loc], e: &mut Errors) -> Option<i128> {
    const TWO_63: f64 = 9_223_372_036_854_775_808.0;
    match v {
        PyValue::Bool(b) => Some(*b as i128),
        PyValue::Int(i) => Some(*i),
        PyValue::Float(f) => {
            if !f.is_finite() {
                e.push(loc, "Input should be a finite number");
                None
            } else if f.fract() != 0.0 {
                e.push(
                    loc,
                    "Input should be a valid integer, got a number with a fractional part",
                );
                None
            } else if *f >= TWO_63 || *f <= -TWO_63 {
                e.push(
                    loc,
                    "Unable to parse input string as an integer, exceeded maximum size",
                );
                None
            } else {
                Some(*f as i128)
            }
        }
        PyValue::Str(s) => match int_from_str(s) {
            Some(n) => Some(n),
            None => {
                e.push(
                    loc,
                    "Input should be a valid integer, unable to parse string as an integer",
                );
                None
            }
        },
        _ => {
            e.push(loc, "Input should be a valid integer");
            None
        }
    }
}

fn int_from_str(s: &str) -> Option<i128> {
    // pydantic trims Unicode White_Space (Rust's trim), not Python's isspace
    let t = s.trim();
    let (neg, rest) = match t.as_bytes().first()? {
        b'-' => (true, &t[1..]),
        b'+' => (false, &t[1..]),
        _ => (false, t),
    };
    let (whole, frac) = match rest.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (rest, None),
    };
    if let Some(f) = frac {
        if f.is_empty() || !f.bytes().all(|b| b == b'0') {
            return None;
        }
    }
    let b = whole.as_bytes();
    if b.is_empty() || !b[0].is_ascii_digit() || !b[b.len() - 1].is_ascii_digit() {
        return None;
    }
    if b.windows(2).any(|w| w == b"__") || b.iter().any(|c| !c.is_ascii_digit() && *c != b'_') {
        return None;
    }
    let clean: String = whole.chars().filter(|c| *c != '_').collect();
    let n: i128 = clean.parse().ok()?;
    Some(if neg { -n } else { n })
}

/// `int | None`.
pub fn opt_int(v: &PyValue, loc: &[Loc], e: &mut Errors) -> Option<Option<i128>> {
    match v {
        PyValue::None => Some(None),
        _ => int(v, loc, e).map(Some),
    }
}

/// `bool`: a bool; 0 / 1; 0.0 / 1.0; one of `0 off f false n no 1 on t true y yes` in any case,
/// with no surrounding space.
pub fn boolean(v: &PyValue, loc: &[Loc], e: &mut Errors) -> Option<bool> {
    let fail = |e: &mut Errors| {
        e.push(loc, "Input should be a valid boolean");
        None
    };
    match v {
        PyValue::Bool(b) => Some(*b),
        PyValue::Int(0) => Some(false),
        PyValue::Int(1) => Some(true),
        PyValue::Float(f) if *f == 0.0 => Some(false),
        PyValue::Float(f) if *f == 1.0 => Some(true),
        PyValue::Str(s) => match s.to_ascii_lowercase().as_str() {
            "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
            "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
            _ => fail(e),
        },
        _ => fail(e),
    }
}

/// `list[T]`: a list, each item converted; every failing item is reported.
pub fn list<T>(
    v: &PyValue,
    loc: &[Loc],
    e: &mut Errors,
    item: impl Fn(&PyValue, &[Loc], &mut Errors) -> Option<T>,
) -> Option<Vec<T>> {
    let PyValue::List(items) = v else {
        e.push(loc, "Input should be a valid list");
        return None;
    };
    let mut out = Vec::with_capacity(items.len());
    let mut ok = true;
    for (i, it) in items.iter().enumerate() {
        match item(it, &at_index(loc, i), e) {
            Some(x) => out.push(x),
            None => ok = false,
        }
    }
    ok.then_some(out)
}

/// `Literal[...]` of strings: the exact string, nothing coerced.
pub fn literal<'a>(
    v: &PyValue,
    choices: &[&'a str],
    loc: &[Loc],
    e: &mut Errors,
) -> Option<&'a str> {
    if let PyValue::Str(s) = v {
        if let Some(c) = choices.iter().find(|c| **c == s) {
            return Some(c);
        }
    }
    let quoted: Vec<String> = choices.iter().map(|c| format!("'{c}'")).collect();
    e.push(loc, format!("Input should be {}", quoted.join(" or ")));
    None
}

/// A nested model: its input has to be a dict. Unknown keys, including keys that are not strings,
/// are ignored.
pub fn model<'v>(
    v: &'v PyValue,
    name: &str,
    loc: &[Loc],
    e: &mut Errors,
) -> Option<&'v [(PyValue, PyValue)]> {
    match v {
        PyValue::Dict(pairs) => Some(pairs),
        _ => {
            e.push(
                loc,
                format!("Input should be a valid dictionary or instance of {name}"),
            );
            None
        }
    }
}

/// The value of field `name` in a model's input dict.
pub fn field<'v>(pairs: &'v [(PyValue, PyValue)], name: &str) -> Option<&'v PyValue> {
    pairs
        .iter()
        .find(|(k, _)| matches!(k, PyValue::Str(s) if s == name))
        .map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use PyValue as P;

    fn ok<T>(f: impl Fn(&PyValue, &[Loc], &mut Errors) -> Option<T>, v: PyValue) -> Option<T> {
        f(&v, &[], &mut Errors::new())
    }

    #[test]
    fn int_matches_pydantic() {
        for (v, want) in [
            (P::Bool(true), Some(1)),
            (P::Float(3128.0), Some(3128)),
            (P::Float(-0.0), Some(0)),
            (P::Float(1.5), None),
            (P::Float(f64::INFINITY), None),
            (P::Float(9_223_372_036_854_775_808.0), None),
            (P::Str("3128".into()), Some(3128)),
            (P::Str(" 3128 ".into()), Some(3128)),
            (P::Str("\u{a0}3128".into()), Some(3128)),
            (P::Str("\u{1c}3128".into()), None),
            (P::Str("+3128".into()), Some(3128)),
            (P::Str("3_128".into()), Some(3128)),
            (P::Str("1_0.0".into()), Some(10)),
            (P::Str("3128.00".into()), Some(3128)),
            (P::Str("08".into()), Some(8)),
            (P::Str("3128.".into()), None),
            (P::Str(".0".into()), None),
            (P::Str("1.0_0".into()), None),
            (P::Str("0x10".into()), None),
            (P::Str("1e3".into()), None),
            (P::Str("3__128".into()), None),
            (P::Str("".into()), None),
            (P::None, None),
        ] {
            assert_eq!(ok(int, v.clone()), want, "{v:?}");
        }
    }

    #[test]
    fn bool_matches_pydantic() {
        for (v, want) in [
            (P::Int(0), Some(false)),
            (P::Int(1), Some(true)),
            (P::Int(2), None),
            (P::Float(1.0), Some(true)),
            (P::Float(1.5), None),
            (P::Str("Yes".into()), Some(true)),
            (P::Str("FALSE".into()), Some(false)),
            (P::Str("y".into()), Some(true)),
            (P::Str(" yes ".into()), None),
            (P::Str("2".into()), None),
            (P::None, None),
        ] {
            assert_eq!(ok(boolean, v.clone()), want, "{v:?}");
        }
    }

    #[test]
    fn str_takes_only_strings() {
        assert_eq!(ok(string, P::Str("x".into())), Some("x".into()));
        assert_eq!(ok(string, P::Int(1)), None);
        assert_eq!(ok(string, P::Bool(true)), None);
        assert_eq!(ok(string, P::Float(1.0)), None);
    }

    #[test]
    fn a_list_reports_every_failing_item() {
        let mut e = Errors::new();
        let v = P::List(vec![P::Int(1), P::Str("a".into()), P::Bool(true)]);
        assert_eq!(list(&v, &[Loc::Key("l".into())], &mut e, string), None);
        let paths: Vec<String> = e.list.iter().map(FieldError::path).collect();
        assert_eq!(paths, ["l.0", "l.2"]);
    }
}
