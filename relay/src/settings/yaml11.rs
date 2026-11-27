//! `config.yml` as PyYAML's `yaml.safe_load` reads it (YAML 1.1), on top of `serde_yaml_ng`.
//!
//! `serde_yaml_ng` resolves plain scalars by YAML 1.2: `yes` and `on` are strings, `1e3` is a
//! float, `2026-11-27` is a string. PyYAML does it by YAML 1.1: `yes`/`on`/`off` are booleans,
//! `1e3` is a string (the exponent form needs a dot), `0777` is octal, `1:30` is 90,
//! `2026-11-27` is a date. A duplicate key is an error to `serde_yaml_ng` and the last one wins in
//! PyYAML. The Python gateway reads every file with PyYAML, so a reading that is to accept and
//! refuse the same files has to resolve the way PyYAML does.
//!
//! The parser itself is the same libyaml grammar in both, so the structure is taken from
//! `serde_yaml_ng` and only the resolution is redone here, in two passes over the same events:
//!
//! 1. `deserialize_any` gives the shape: which nodes are mappings, sequences and scalars, and
//!    which scalars `serde_yaml_ng` resolved to something other than a string (those were plain)
//! 2. a second pass guided by that shape asks every scalar for its text (`deserialize_str`, which
//!    hands back the scalar as written). Whether a string scalar was quoted is read from where its
//!    text sits in the input: a quoted scalar is borrowed from between its quotes
//!
//! The text of every plain scalar is then resolved with PyYAML's own regular expressions and
//! constructed with its own rules (`yaml/resolver.py`, `yaml/constructor.py`), merge keys
//! (`<<`) are flattened as `SafeConstructor.flatten_mapping` does, and mappings are built with
//! Python's dict semantics: `1`, `1.0` and `true` are the same key, the first key is kept and the
//! last value wins.
//!
//! What is not reproduced, and why, is listed in the difference ledger of the 0.3.0 plan:
//! explicit standard tags (`!!str 1` reads as the plain `1`), the non-specific tag `!` (refused
//! here, a string to PyYAML), integers outside `i128`, and a plain scalar that spans lines (read
//! as a string; PyYAML would resolve one that folds into a timestamp).

use std::cell::RefCell;
use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, EnumAccess, MapAccess, SeqAccess, Visitor};

/// A value as PyYAML's `safe_load` constructs it.
#[derive(Debug, Clone, PartialEq)]
pub enum PyValue {
    None,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(String),
    /// `datetime.date`
    Date(Date),
    /// `datetime.datetime`
    DateTime(DateTime),
    List(Vec<PyValue>),
    /// A dict, in insertion order. Keys are unique under Python's equality.
    Dict(Vec<(PyValue, PyValue)>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Date {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    pub date: Date,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub microsecond: u32,
    /// The UTC offset in minutes, or None for a naive datetime.
    pub offset_minutes: Option<i32>,
}

/// Why a document could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YamlError {
    /// PyYAML refuses it too: a syntax error, an invalid timestamp, an unknown tag, a merge of a
    /// scalar, an unhashable key …
    Refused(String),
    /// PyYAML would load it and this reading cannot (see the module comment).
    Unsupported(String),
}

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            YamlError::Refused(m) => f.write_str(m),
            YamlError::Unsupported(m) => write!(f, "not supported by this reader: {m}"),
        }
    }
}

/// `yaml.safe_load(text)`. An empty document (or one holding only comments) is `None`.
pub fn safe_load(text: &str) -> Result<PyValue, YamlError> {
    let failure = RefCell::new(None);
    let shape = ShapeSeed { failure: &failure }
        .deserialize(serde_yaml_ng::Deserializer::from_str(text))
        .map_err(|e| failure.take().unwrap_or(YamlError::Refused(e.to_string())))?;
    if let Shape::Void = shape {
        return Ok(PyValue::None);
    }
    let node = TextSeed {
        shape: &shape,
        input: text,
    }
    .deserialize(serde_yaml_ng::Deserializer::from_str(text))
    .map_err(|e| YamlError::Refused(e.to_string()))?;
    construct(&node)
}

// ---- pass 1: the shape -------------------------------------------------------------------------

enum Shape {
    /// No document at all (an empty stream)
    Void,
    /// A scalar `serde_yaml_ng` resolved to a null, a boolean or a number: it was plain
    Resolved,
    /// A scalar `serde_yaml_ng` kept as a string: plain or quoted, pass 2 tells
    Text,
    Seq(Vec<Shape>),
    Map(Vec<(Shape, Shape)>),
}

struct ShapeSeed<'a> {
    failure: &'a RefCell<Option<YamlError>>,
}

impl<'de> DeserializeSeed<'de> for ShapeSeed<'_> {
    type Value = Shape;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Shape, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ShapeSeed<'_> {
    type Value = Shape;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a YAML node")
    }
    fn visit_bool<E>(self, _: bool) -> Result<Shape, E> {
        Ok(Shape::Resolved)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Shape, E> {
        Ok(Shape::Resolved)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Shape, E> {
        Ok(Shape::Resolved)
    }
    fn visit_i128<E>(self, _: i128) -> Result<Shape, E> {
        Ok(Shape::Resolved)
    }
    fn visit_u128<E>(self, _: u128) -> Result<Shape, E> {
        Ok(Shape::Resolved)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Shape, E> {
        Ok(Shape::Resolved)
    }
    fn visit_unit<E>(self) -> Result<Shape, E> {
        Ok(Shape::Resolved)
    }
    fn visit_none<E>(self) -> Result<Shape, E> {
        Ok(Shape::Void)
    }
    fn visit_str<E>(self, _: &str) -> Result<Shape, E> {
        Ok(Shape::Text)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Shape, A::Error> {
        let mut out = Vec::new();
        while let Some(s) = seq.next_element_seed(ShapeSeed {
            failure: self.failure,
        })? {
            out.push(s);
        }
        Ok(Shape::Seq(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Shape, A::Error> {
        let mut out = Vec::new();
        while let Some(k) = map.next_key_seed(ShapeSeed {
            failure: self.failure,
        })? {
            let v = map.next_value_seed(ShapeSeed {
                failure: self.failure,
            })?;
            out.push((k, v));
        }
        Ok(Shape::Map(out))
    }
    /// `serde_yaml_ng` hands a node with a local tag (`!foo`, `!`) over as an enum.
    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<Shape, A::Error> {
        let (tag, _) = data.variant::<String>()?;
        let failure = if tag == "!" {
            // PyYAML reads the non-specific tag as "resolve as a string"
            YamlError::Unsupported("the non-specific tag `!`".into())
        } else {
            // SafeConstructor has no constructor for any local tag
            YamlError::Refused(format!(
                "could not determine a constructor for the tag '!{tag}'"
            ))
        };
        *self.failure.borrow_mut() = Some(failure);
        Err(de::Error::custom("tagged node"))
    }
}

// ---- pass 2: the text of every scalar ----------------------------------------------------------

enum Node {
    Scalar { text: String, plain: bool },
    Seq(Vec<Node>),
    Map(Vec<(Node, Node)>),
}

struct TextSeed<'a, 'de> {
    shape: &'a Shape,
    input: &'de str,
}

impl<'de> DeserializeSeed<'de> for TextSeed<'_, 'de> {
    type Value = Node;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Node, D::Error> {
        match self.shape {
            Shape::Seq(items) => d.deserialize_seq(SeqText {
                items,
                input: self.input,
            }),
            Shape::Map(pairs) => d.deserialize_map(MapText {
                pairs,
                input: self.input,
            }),
            Shape::Resolved => d.deserialize_str(ScalarText {
                known_plain: true,
                input: self.input,
            }),
            Shape::Text | Shape::Void => d.deserialize_str(ScalarText {
                known_plain: false,
                input: self.input,
            }),
        }
    }
}

struct ScalarText<'de> {
    known_plain: bool,
    input: &'de str,
}

impl<'de> Visitor<'de> for ScalarText<'de> {
    type Value = Node;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a scalar")
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Node, E> {
        let plain = self.known_plain || !between_quotes(self.input, v);
        Ok(Node::Scalar {
            text: v.to_string(),
            plain,
        })
    }
    /// Not borrowed from the input: quoted with escapes, a block scalar, or a plain scalar
    /// folded over several lines. Only the last is plain; see the module comment.
    fn visit_str<E>(self, v: &str) -> Result<Node, E> {
        Ok(Node::Scalar {
            text: v.to_string(),
            plain: self.known_plain,
        })
    }
}

/// Whether `s`, a slice of `input`, sits between a pair of matching quotes. `serde_yaml_ng`
/// borrows a quoted scalar's text from inside its quotes and a plain scalar's from where it is.
fn between_quotes(input: &str, s: &str) -> bool {
    let base = input.as_ptr() as usize;
    let at = s.as_ptr() as usize;
    if at < base || at + s.len() > base + input.len() {
        return false;
    }
    let start = at - base;
    let bytes = input.as_bytes();
    let before = start.checked_sub(1).and_then(|i| bytes.get(i));
    let after = bytes.get(start + s.len());
    matches!(
        (before, after),
        (Some(b'\''), Some(b'\'')) | (Some(b'"'), Some(b'"'))
    )
}

struct SeqText<'a, 'de> {
    items: &'a [Shape],
    input: &'de str,
}

impl<'de> Visitor<'de> for SeqText<'_, 'de> {
    type Value = Node;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a sequence")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Node, A::Error> {
        let mut out = Vec::with_capacity(self.items.len());
        for shape in self.items {
            match seq.next_element_seed(TextSeed {
                shape,
                input: self.input,
            })? {
                Some(n) => out.push(n),
                None => return Err(de::Error::custom("the sequence changed between passes")),
            }
        }
        Ok(Node::Seq(out))
    }
}

struct MapText<'a, 'de> {
    pairs: &'a [(Shape, Shape)],
    input: &'de str,
}

impl<'de> Visitor<'de> for MapText<'_, 'de> {
    type Value = Node;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a mapping")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Node, A::Error> {
        let mut out = Vec::with_capacity(self.pairs.len());
        for (ks, vs) in self.pairs {
            let Some(k) = map.next_key_seed(TextSeed {
                shape: ks,
                input: self.input,
            })?
            else {
                return Err(de::Error::custom("the mapping changed between passes"));
            };
            let v = map.next_value_seed(TextSeed {
                shape: vs,
                input: self.input,
            })?;
            out.push((k, v));
        }
        Ok(Node::Map(out))
    }
}

// ---- resolution and construction (PyYAML's SafeLoader) -----------------------------------------

/// The implicit tag PyYAML's resolver gives a plain scalar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Implicit {
    Bool,
    Float,
    Int,
    Merge,
    Null,
    Timestamp,
    Value,
    Str,
}

fn resolve(text: &str) -> Implicit {
    if is_bool(text) {
        Implicit::Bool
    } else if is_float(text) {
        Implicit::Float
    } else if is_int(text) {
        Implicit::Int
    } else if text == "<<" {
        Implicit::Merge
    } else if matches!(text, "" | "~" | "null" | "Null" | "NULL") {
        Implicit::Null
    } else if is_timestamp(text) {
        Implicit::Timestamp
    } else if text == "=" {
        Implicit::Value
    } else {
        Implicit::Str
    }
}

fn is_bool(t: &str) -> bool {
    matches!(
        t,
        "yes"
            | "Yes"
            | "YES"
            | "no"
            | "No"
            | "NO"
            | "true"
            | "True"
            | "TRUE"
            | "false"
            | "False"
            | "FALSE"
            | "on"
            | "On"
            | "ON"
            | "off"
            | "Off"
            | "OFF"
    )
}

/// A tiny cursor for the hand-written forms of PyYAML's regular expressions.
struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    fn new(s: &'a str) -> Self {
        Cur {
            b: s.as_bytes(),
            i: 0,
        }
    }
    fn done(&self) -> bool {
        self.i == self.b.len()
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn eat_if(&mut self, f: impl Fn(u8) -> bool) -> bool {
        match self.peek() {
            Some(c) if f(c) => {
                self.i += 1;
                true
            }
            _ => false,
        }
    }
    /// Zero or more.
    fn eat_while(&mut self, f: impl Fn(u8) -> bool) -> usize {
        let start = self.i;
        while self.eat_if(&f) {}
        self.i - start
    }
    fn sign(&mut self) {
        let _ = self.eat(b'-') || self.eat(b'+');
    }
    fn rest(&self) -> &'a [u8] {
        &self.b[self.i..]
    }
}

fn digit(c: u8) -> bool {
    c.is_ascii_digit()
}
fn digit_or_us(c: u8) -> bool {
    c.is_ascii_digit() || c == b'_'
}

/// `(?::[0-5]?[0-9])+`
fn sexagesimal_tail(c: &mut Cur) -> bool {
    let mut n = 0;
    loop {
        let save = c.i;
        if !c.eat(b':') {
            break;
        }
        // [0-5]?[0-9]: one digit, or two with the first 0-5
        let r = c.rest();
        match (r.first(), r.get(1)) {
            (Some(a), Some(b)) if (b'0'..=b'5').contains(a) && digit(*b) => c.i += 2,
            (Some(a), _) if digit(*a) => c.i += 1,
            _ => {
                c.i = save;
                break;
            }
        }
        n += 1;
    }
    n > 0
}

/// `(?:[eE][-+][0-9]+)?` — the sign is required in YAML 1.1.
fn exponent(c: &mut Cur) -> bool {
    let save = c.i;
    if c.eat(b'e') || c.eat(b'E') {
        if (c.eat(b'-') || c.eat(b'+')) && c.eat_while(digit) > 0 {
            return true;
        }
        c.i = save;
        return false;
    }
    true
}

fn is_float(t: &str) -> bool {
    let alt = |f: &dyn Fn(&mut Cur) -> bool| {
        let mut c = Cur::new(t);
        f(&mut c) && c.done()
    };
    // [-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?
    alt(&|c| {
        c.sign();
        c.eat_if(digit) && {
            c.eat_while(digit_or_us);
            c.eat(b'.')
        } && {
            c.eat_while(digit_or_us);
            exponent(c)
        }
    })
    // \.[0-9][0-9_]*(?:[eE][-+][0-9]+)?
    || alt(&|c| {
        c.eat(b'.') && c.eat_if(digit) && {
            c.eat_while(digit_or_us);
            exponent(c)
        }
    })
    // [-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*
    || alt(&|c| {
        c.sign();
        c.eat_if(digit) && {
            c.eat_while(digit_or_us);
            sexagesimal_tail(c)
        } && c.eat(b'.') && {
            c.eat_while(digit_or_us);
            true
        }
    })
    // [-+]?\.(?:inf|Inf|INF)
    || alt(&|c| {
        c.sign();
        let r = c.rest();
        if matches!(r, b".inf" | b".Inf" | b".INF") {
            c.i += 4;
            true
        } else {
            false
        }
    })
    // \.(?:nan|NaN|NAN)
    || matches!(t, ".nan" | ".NaN" | ".NAN")
}

fn is_int(t: &str) -> bool {
    let alt = |f: &dyn Fn(&mut Cur) -> bool| {
        let mut c = Cur::new(t);
        f(&mut c) && c.done()
    };
    // [-+]?0b[0-1_]+
    alt(&|c| {
        c.sign();
        c.eat(b'0') && c.eat(b'b') && c.eat_while(|x| matches!(x, b'0' | b'1' | b'_')) > 0
    })
    // [-+]?0[0-7_]+
    || alt(&|c| {
        c.sign();
        c.eat(b'0') && c.eat_while(|x| matches!(x, b'0'..=b'7' | b'_')) > 0
    })
    // [-+]?(?:0|[1-9][0-9_]*)
    || alt(&|c| {
        c.sign();
        c.eat(b'0')
            || (c.eat_if(|x| matches!(x, b'1'..=b'9')) && {
                c.eat_while(digit_or_us);
                true
            })
    })
    // [-+]?0x[0-9a-fA-F_]+
    || alt(&|c| {
        c.sign();
        c.eat(b'0') && c.eat(b'x') && c.eat_while(|x| x.is_ascii_hexdigit() || x == b'_') > 0
    })
    // [-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+
    || alt(&|c| {
        c.sign();
        c.eat_if(|x| matches!(x, b'1'..=b'9')) && {
            c.eat_while(digit_or_us);
            sexagesimal_tail(c)
        }
    })
}

/// The parts of a timestamp, as `SafeConstructor.timestamp_regexp` captures them.
struct Stamp<'a> {
    year: &'a str,
    month: &'a str,
    day: &'a str,
    time: Option<StampTime<'a>>,
}
struct StampTime<'a> {
    hour: &'a str,
    minute: &'a str,
    second: &'a str,
    fraction: Option<&'a str>,
    /// None, `Z`, or (sign, hour, minute)
    tz: Option<Option<(u8, &'a str, Option<&'a str>)>>,
}

/// The resolver's timestamp expression: `YYYY-MM-DD`, or the long form with 1-2 digit month and
/// day, a time and an optional zone.
fn is_timestamp(t: &str) -> bool {
    let b = t.as_bytes();
    let date_only = b.len() == 10
        && b[..4].iter().all(|c| c.is_ascii_digit())
        && b[4] == b'-'
        && b[5..7].iter().all(|c| c.is_ascii_digit())
        && b[7] == b'-'
        && b[8..10].iter().all(|c| c.is_ascii_digit());
    date_only || parse_stamp(t, true).is_some()
}

/// `timestamp_regexp`. With `need_time`, the resolver's long form (time required).
fn parse_stamp(t: &str, need_time: bool) -> Option<Stamp<'_>> {
    let mut c = Cur::new(t);
    let s = |c: &Cur, a: usize| &t[a..c.i];
    let a = c.i;
    if c.eat_while(digit) != 4 {
        return None;
    }
    let year = s(&c, a);
    if !c.eat(b'-') {
        return None;
    }
    let a = c.i;
    let n = c.eat_while(digit);
    if !(1..=2).contains(&n) {
        return None;
    }
    let month = s(&c, a);
    if !c.eat(b'-') {
        return None;
    }
    let a = c.i;
    let n = c.eat_while(digit);
    if !(1..=2).contains(&n) {
        return None;
    }
    let day = s(&c, a);
    if c.done() {
        // the resolver's long form needs the time; the date-only form is checked by the caller
        return (!need_time).then_some(Stamp {
            year,
            month,
            day,
            time: None,
        });
    }
    // (?:[Tt]|[ \t]+)
    if !(c.eat(b'T') || c.eat(b't') || c.eat_while(|x| x == b' ' || x == b'\t') > 0) {
        return None;
    }
    let a = c.i;
    let n = c.eat_while(digit);
    if !(1..=2).contains(&n) {
        return None;
    }
    let hour = s(&c, a);
    let two = |c: &mut Cur| -> Option<&str> {
        let a = c.i;
        (c.eat(b':') && c.eat_if(digit) && c.eat_if(digit)).then(|| &t[a + 1..c.i])
    };
    let minute = two(&mut c)?;
    let second = two(&mut c)?;
    let mut fraction = None;
    if c.eat(b'.') {
        let a = c.i;
        c.eat_while(digit);
        fraction = Some(s(&c, a));
    }
    let save = c.i;
    c.eat_while(|x| x == b' ' || x == b'\t');
    let tz = if c.eat(b'Z') {
        Some(None)
    } else if let Some(sign) = c.peek().filter(|x| *x == b'-' || *x == b'+') {
        c.i += 1;
        let a = c.i;
        let n = c.eat_while(digit);
        if !(1..=2).contains(&n) {
            return None;
        }
        let th = s(&c, a);
        let tm = two(&mut c);
        Some(Some((sign, th, tm)))
    } else {
        c.i = save;
        None
    };
    c.done().then_some(Stamp {
        year,
        month,
        day,
        time: Some(StampTime {
            hour,
            minute,
            second,
            fraction,
            tz,
        }),
    })
}

fn construct_timestamp(t: &str) -> Result<PyValue, YamlError> {
    let invalid = |why: &str| YamlError::Refused(format!("timestamp {t:?}: {why}"));
    let st = parse_stamp(t, false).ok_or_else(|| invalid("not a timestamp"))?;
    let num = |s: &str| s.parse::<u32>().unwrap_or(u32::MAX);
    let (year, month, day) = (num(st.year), num(st.month), num(st.day));
    // datetime.date(year, month, day)
    if !(1..=9999).contains(&year) {
        return Err(invalid("year is out of range"));
    }
    if !(1..=12).contains(&month) {
        return Err(invalid("month must be in 1..12"));
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=days).contains(&day) {
        return Err(invalid("day is out of range for month"));
    }
    let date = Date {
        year: year as u16,
        month: month as u8,
        day: day as u8,
    };
    let Some(tm) = st.time else {
        return Ok(PyValue::Date(date));
    };
    let (hour, minute, second) = (num(tm.hour), num(tm.minute), num(tm.second));
    if hour > 23 {
        return Err(invalid("hour must be in 0..23"));
    }
    if minute > 59 {
        return Err(invalid("minute must be in 0..59"));
    }
    if second > 59 {
        return Err(invalid("second must be in 0..59"));
    }
    // fraction[:6], right-padded with zeros
    let microsecond = match tm.fraction {
        Some(f) if !f.is_empty() => {
            let mut s: String = f.chars().take(6).collect();
            while s.len() < 6 {
                s.push('0');
            }
            num(&s)
        }
        _ => 0,
    };
    let offset_minutes = match tm.tz {
        None => None,
        Some(None) => Some(0),
        Some(Some((sign, th, tmin))) => {
            let m = num(th) as i32 * 60 + tmin.map(num).unwrap_or(0) as i32;
            // datetime.timezone() takes strictly less than a day
            if m >= 24 * 60 {
                return Err(invalid("offset must be strictly between -24h and 24h"));
            }
            Some(if sign == b'-' { -m } else { m })
        }
    };
    Ok(PyValue::DateTime(DateTime {
        date,
        hour: hour as u8,
        minute: minute as u8,
        second: second as u8,
        microsecond,
        offset_minutes,
    }))
}

fn too_big(t: &str) -> YamlError {
    YamlError::Unsupported(format!("the integer {t} is outside i128"))
}

/// `SafeConstructor.construct_yaml_int`.
fn construct_int(text: &str) -> Result<PyValue, YamlError> {
    let v: String = text.chars().filter(|c| *c != '_').collect();
    let (sign, v) = match v.as_bytes().first() {
        Some(b'-') => (-1i128, &v[1..]),
        Some(b'+') => (1, &v[1..]),
        _ => (1, &v[..]),
    };
    let radix = |digits: &str, r: u32| -> Result<i128, YamlError> {
        if digits.is_empty() {
            // int('', base) raises ValueError, which escapes safe_load
            return Err(YamlError::Refused(format!(
                "invalid literal for int() with base {r}: ''"
            )));
        }
        i128::from_str_radix(digits, r).map_err(|_| too_big(text))
    };
    let n = if v == "0" {
        0
    } else if let Some(d) = v.strip_prefix("0b") {
        radix(d, 2)?
    } else if let Some(d) = v.strip_prefix("0x") {
        radix(d, 16)?
    } else if v.starts_with('0') {
        radix(v, 8)?
    } else if v.contains(':') {
        let mut total: i128 = 0;
        for part in v.split(':') {
            let d = radix(part, 10)?;
            total = total
                .checked_mul(60)
                .and_then(|t| t.checked_add(d))
                .ok_or_else(|| too_big(text))?;
        }
        total
    } else {
        radix(v, 10)?
    };
    n.checked_mul(sign)
        .map(PyValue::Int)
        .ok_or_else(|| too_big(text))
}

/// `SafeConstructor.construct_yaml_float`.
fn construct_float(text: &str) -> PyValue {
    let v: String = text
        .chars()
        .filter(|c| *c != '_')
        .collect::<String>()
        .to_lowercase();
    let (sign, v) = match v.as_bytes().first() {
        Some(b'-') => (-1.0f64, &v[1..]),
        Some(b'+') => (1.0, &v[1..]),
        _ => (1.0, &v[..]),
    };
    let f = if v == ".inf" {
        sign * f64::INFINITY
    } else if v == ".nan" {
        f64::NAN
    } else if v.contains(':') {
        // digits reversed, each times 60**i, summed from the least significant
        let mut value = 0.0f64;
        let mut base = 1.0f64;
        for part in v.split(':').rev() {
            value += part.parse::<f64>().unwrap_or(f64::NAN) * base;
            base *= 60.0;
        }
        sign * value
    } else {
        // the resolver only lets through what float() reads
        sign * v.parse::<f64>().unwrap_or(f64::NAN)
    };
    PyValue::Float(f)
}

fn construct_scalar(text: &str, plain: bool) -> Result<PyValue, YamlError> {
    if !plain {
        return Ok(PyValue::Str(text.to_string()));
    }
    match resolve(text) {
        Implicit::Bool => Ok(PyValue::Bool(matches!(
            text.to_ascii_lowercase().as_str(),
            "yes" | "true" | "on"
        ))),
        Implicit::Float => Ok(construct_float(text)),
        Implicit::Int => construct_int(text),
        Implicit::Null => Ok(PyValue::None),
        Implicit::Timestamp => construct_timestamp(text),
        Implicit::Str => Ok(PyValue::Str(text.to_string())),
        Implicit::Merge => Err(YamlError::Refused(
            "could not determine a constructor for the tag 'tag:yaml.org,2002:merge'".into(),
        )),
        Implicit::Value => Err(YamlError::Refused(
            "could not determine a constructor for the tag 'tag:yaml.org,2002:value'".into(),
        )),
    }
}

fn is_plain(node: &Node, want: Implicit) -> bool {
    matches!(node, Node::Scalar { text, plain: true } if resolve(text) == want)
}

/// `SafeConstructor.flatten_mapping`: the pairs of a mapping with its merge keys expanded. Merged
/// pairs come first, so the mapping's own keys win; of several merged mappings, the first wins.
fn flatten(pairs: &[(Node, Node)]) -> Result<Vec<(&Node, &Node)>, YamlError> {
    let mut merge: Vec<(&Node, &Node)> = Vec::new();
    let mut own: Vec<(&Node, &Node)> = Vec::new();
    for (k, v) in pairs {
        if is_plain(k, Implicit::Merge) {
            match v {
                Node::Map(sub) => merge.extend(flatten(sub)?),
                Node::Seq(items) => {
                    let mut submerge = Vec::new();
                    for item in items {
                        let Node::Map(sub) = item else {
                            return Err(YamlError::Refused(
                                "expected a mapping for merging".into(),
                            ));
                        };
                        submerge.push(flatten(sub)?);
                    }
                    for value in submerge.into_iter().rev() {
                        merge.extend(value);
                    }
                }
                Node::Scalar { .. } => {
                    return Err(YamlError::Refused(
                        "expected a mapping or list of mappings for merging".into(),
                    ))
                }
            }
        } else {
            own.push((k, v));
        }
    }
    merge.extend(own);
    Ok(merge)
}

fn construct(node: &Node) -> Result<PyValue, YamlError> {
    match node {
        Node::Scalar { text, plain } => construct_scalar(text, *plain),
        Node::Seq(items) => Ok(PyValue::List(
            items.iter().map(construct).collect::<Result<_, _>>()?,
        )),
        Node::Map(pairs) => {
            let mut out: Vec<(PyValue, PyValue)> = Vec::new();
            for (k, v) in flatten(pairs)? {
                // a `=` key is re-tagged as a string by flatten_mapping
                let key = if is_plain(k, Implicit::Value) {
                    PyValue::Str("=".into())
                } else {
                    construct(k)?
                };
                if matches!(key, PyValue::List(_) | PyValue::Dict(_)) {
                    return Err(YamlError::Refused(
                        "while constructing a mapping: found unhashable key".into(),
                    ));
                }
                let value = construct(v)?;
                dict_insert(&mut out, key, value);
            }
            Ok(PyValue::Dict(out))
        }
    }
}

/// `d[key] = value`: an equal key keeps its place and its original object.
pub fn dict_insert(d: &mut Vec<(PyValue, PyValue)>, key: PyValue, value: PyValue) {
    match d.iter_mut().find(|(k, _)| py_eq(k, &key)) {
        Some(slot) => slot.1 = value,
        None => d.push((key, value)),
    }
}

/// Python's `==` between two hashable values, as a dict compares keys. Every NaN PyYAML makes is
/// the same object, so NaN equals NaN here (the dict finds it by identity).
pub fn py_eq(a: &PyValue, b: &PyValue) -> bool {
    use PyValue::*;
    match (a, b) {
        (None, None) => true,
        (Str(x), Str(y)) => x == y,
        (Date(x), Date(y)) => x == y,
        (DateTime(x), DateTime(y)) => match (x.offset_minutes, y.offset_minutes) {
            (Option::None, Option::None) => x == y,
            (Some(_), Some(_)) => utc_key(x) == utc_key(y),
            _ => false,
        },
        _ => match (number(a), number(b)) {
            (Some(x), Some(y)) => num_eq(x, y),
            _ => false,
        },
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Num {
    I(i128),
    F(f64),
}

pub(crate) fn number(v: &PyValue) -> Option<Num> {
    match v {
        PyValue::Bool(b) => Some(Num::I(*b as i128)),
        PyValue::Int(i) => Some(Num::I(*i)),
        PyValue::Float(f) => Some(Num::F(*f)),
        _ => None,
    }
}

fn num_eq(a: Num, b: Num) -> bool {
    match (a, b) {
        (Num::I(x), Num::I(y)) => x == y,
        (Num::F(x), Num::F(y)) => x == y || (x.is_nan() && y.is_nan()),
        (Num::I(i), Num::F(f)) | (Num::F(f), Num::I(i)) => {
            int_float_cmp(i, f) == Some(std::cmp::Ordering::Equal)
        }
    }
}

/// Exact comparison of an int and a float, as Python does it. None for NaN.
pub(crate) fn int_float_cmp(i: i128, f: f64) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;
    if f.is_nan() {
        return Option::None;
    }
    const TWO_127: f64 = 170141183460469231731687303715884105728.0;
    if f >= TWO_127 {
        return Some(Ordering::Less);
    }
    if f < -TWO_127 {
        return Some(Ordering::Greater);
    }
    let fl = f.floor();
    let whole = fl as i128;
    match i.cmp(&whole) {
        Ordering::Equal if f > fl => Some(Ordering::Less),
        o => Some(o),
    }
}

/// An aware datetime as microseconds since 0001-01-01 UTC, for comparison.
pub(crate) fn utc_key(d: &DateTime) -> i128 {
    let days = days_from_civil(d.date.year as i64, d.date.month as i64, d.date.day as i64);
    let secs =
        days as i128 * 86_400 + d.hour as i128 * 3600 + d.minute as i128 * 60 + d.second as i128
            - d.offset_minutes.unwrap_or(0) as i128 * 60;
    secs * 1_000_000 + d.microsecond as i128
}

pub(crate) fn naive_key(d: &DateTime) -> i128 {
    utc_key(&DateTime {
        offset_minutes: Some(0),
        ..*d
    })
}

/// Days from a fixed epoch (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe
}

#[cfg(test)]
mod tests {
    use super::*;
    use PyValue::*;

    fn load(t: &str) -> PyValue {
        safe_load(t).unwrap()
    }
    fn one(t: &str) -> PyValue {
        match load(&format!("k: {t}\n")) {
            Dict(mut p) => p.remove(0).1,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn booleans_are_yaml_1_1() {
        for t in [
            "yes", "Yes", "YES", "on", "On", "ON", "true", "True", "TRUE",
        ] {
            assert_eq!(one(t), Bool(true), "{t}");
        }
        for t in [
            "no", "No", "NO", "off", "Off", "OFF", "false", "False", "FALSE",
        ] {
            assert_eq!(one(t), Bool(false), "{t}");
        }
        // not booleans in PyYAML
        for t in ["y", "n", "yES", "oN", "t", "f"] {
            assert_eq!(one(t), Str(t.into()), "{t}");
        }
        // quoted, always a string
        assert_eq!(one("'yes'"), Str("yes".into()));
        assert_eq!(one("\"on\""), Str("on".into()));
    }

    #[test]
    fn integers_are_yaml_1_1() {
        assert_eq!(one("3128"), Int(3128));
        assert_eq!(one("+12"), Int(12));
        assert_eq!(one("-12"), Int(-12));
        assert_eq!(one("0"), Int(0));
        assert_eq!(one("0777"), Int(0o777));
        assert_eq!(one("0x1F"), Int(31));
        assert_eq!(one("0b101"), Int(5));
        assert_eq!(one("1_000"), Int(1000));
        assert_eq!(one("1:30"), Int(90));
        assert_eq!(one("-1:00:00"), Int(-3600));
        assert_eq!(one("0_"), Int(0));
        // YAML 1.2 forms that 1.1 reads as strings
        assert_eq!(one("0o17"), Str("0o17".into()));
        assert_eq!(one("08"), Str("08".into()));
        // quoted
        assert_eq!(one("'3128'"), Str("3128".into()));
        // int('', 16) raises
        assert!(matches!(safe_load("k: 0x_\n"), Err(YamlError::Refused(_))));
    }

    #[test]
    fn floats_are_yaml_1_1() {
        assert_eq!(one("1.5"), Float(1.5));
        assert_eq!(one("1."), Float(1.0));
        assert_eq!(one(".5"), Float(0.5));
        assert_eq!(one("1.0e+3"), Float(1000.0));
        assert_eq!(one("1:30.5"), Float(90.5));
        assert_eq!(one(".inf"), Float(f64::INFINITY));
        assert_eq!(one("-.INF"), Float(f64::NEG_INFINITY));
        assert!(matches!(one(".nan"), Float(f) if f.is_nan()));
        // the exponent needs a dot and a sign in 1.1
        assert_eq!(one("1e3"), Str("1e3".into()));
        assert_eq!(one("1.0e3"), Str("1.0e3".into()));
    }

    #[test]
    fn nulls_and_timestamps() {
        assert_eq!(one("~"), None);
        assert_eq!(one("null"), None);
        assert_eq!(one(""), None);
        assert_eq!(one("'~'"), Str("~".into()));
        assert_eq!(
            one("2026-11-27"),
            Date(super::Date {
                year: 2026,
                month: 11,
                day: 27
            })
        );
        assert!(
            matches!(one("2001-12-14t21:59:43.10-05:00"), DateTime(d) if d.offset_minutes == Some(-300) && d.microsecond == 100_000)
        );
        assert!(matches!(one("2001-12-14 21:59:43.10"), DateTime(d) if d.offset_minutes.is_none()));
        // the date-only form needs two-digit month and day
        assert_eq!(one("2026-1-2"), Str("2026-1-2".into()));
        // an impossible date is an error, as datetime.date raises
        assert!(matches!(
            safe_load("k: 2026-13-45\n"),
            Err(YamlError::Refused(_))
        ));
        assert!(matches!(
            safe_load("k: 2026-02-29\n"),
            Err(YamlError::Refused(_))
        ));
    }

    #[test]
    fn duplicate_keys_keep_the_first_key_and_the_last_value() {
        assert_eq!(
            load("a: 1\nb: 2\na: 3\n"),
            Dict(vec![(Str("a".into()), Int(3)), (Str("b".into()), Int(2))])
        );
        // 1, 1.0 and true are one key to a dict
        assert_eq!(
            load("1: a\ntrue: b\n1.0: c\n"),
            Dict(vec![(Int(1), Str("c".into()))])
        );
    }

    #[test]
    fn merge_keys_are_flattened() {
        let v = load("base: &b {x: 1, y: 2}\nk:\n  <<: *b\n  y: 3\n");
        let Dict(top) = v else { panic!() };
        assert_eq!(
            top[1].1,
            Dict(vec![(Str("x".into()), Int(1)), (Str("y".into()), Int(3))])
        );
        // of several, the first wins
        let v = load("a: &a {x: 1}\nb: &b {x: 2, z: 0}\nk:\n  <<: [*a, *b]\n");
        let Dict(top) = v else { panic!() };
        assert_eq!(
            top[2].1,
            Dict(vec![(Str("x".into()), Int(1)), (Str("z".into()), Int(0))])
        );
        assert!(safe_load("k:\n  <<: 1\n").is_err());
        assert!(safe_load("k: <<\n").is_err());
    }

    #[test]
    fn documents_and_tags() {
        assert_eq!(load(""), None);
        assert_eq!(load("# only a comment\n"), None);
        assert_eq!(load("---\n"), None);
        assert!(safe_load("a: 1\n---\nb: 2\n").is_err());
        assert!(matches!(
            safe_load("k: !foo x\n"),
            Err(YamlError::Refused(_))
        ));
        assert!(matches!(
            safe_load("k: ! x\n"),
            Err(YamlError::Unsupported(_))
        ));
        assert!(safe_load("? [a]\n: 1\n").is_err());
        assert_eq!(load("=: 1\n"), Dict(vec![(Str("=".into()), Int(1))]));
        assert!(safe_load("k: =\n").is_err());
    }

    #[test]
    fn quoting_is_read_from_the_input() {
        assert_eq!(one("'it''s'"), Str("it's".into()));
        assert_eq!(one("\"a\\tb\""), Str("a\tb".into()));
        assert_eq!(one("''"), Str("".into()));
        assert_eq!(one("|\n  yes\n"), Str("yes\n".into()));
        assert_eq!(
            load("- on\n- 'on'\n"),
            List(vec![Bool(true), Str("on".into())])
        );
        assert_eq!(
            load("[on, \"on\", off]"),
            List(vec![Bool(true), Str("on".into()), Bool(false)])
        );
    }
}
