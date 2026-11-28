//! The JSON the Web UI writes. Its own small type rather than `serde_json::Value` for two reasons:
//! an integer from `config.yml` is Python's unbounded `int`, which `serde_json` cannot hold, and
//! every response is built here field by field from a type of this module (0.3.0 plan, "`serve`
//! の中での分離" 4) — nothing in the Web UI derives `Serialize`.

use std::fmt::Write as _;

use crate::settings::py::float_repr;

/// One JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i128),
    /// Written as Python writes it (`repr`); not finite is `null`, as FastAPI answered
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    /// Keys in the order given
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }

    pub fn opt_str(s: Option<impl Into<String>>) -> Json {
        s.map_or(Json::Null, |s| Json::Str(s.into()))
    }

    pub fn opt_float(f: Option<f64>) -> Json {
        f.map_or(Json::Null, Json::Float)
    }

    pub fn opt_int(i: Option<i128>) -> Json {
        i.map_or(Json::Null, Json::Int)
    }

    pub fn strs<S: AsRef<str>>(items: &[S]) -> Json {
        Json::Arr(items.iter().map(|s| Json::str(s.as_ref())).collect())
    }

    /// The compact text, `separators=(",", ":")` and `ensure_ascii=False` as FastAPI writes it.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(i) => {
                let _ = write!(out, "{i}");
            }
            Json::Float(f) if !f.is_finite() => out.push_str("null"),
            Json::Float(f) => out.push_str(&float_repr(*f)),
            Json::Str(s) => write_str(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_str(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// An object from `(name, value)` pairs.
pub fn obj<const N: usize>(fields: [(&str, Json); N]) -> Json {
    Json::Obj(
        fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

fn write_str(s: &str, out: &mut String) {
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
    fn it_writes_compact_json_that_serde_reads_back() {
        let v = obj([
            ("a", Json::Int(1)),
            ("big", Json::Int(10_i128.pow(30))),
            ("f", Json::Float(1.0)),
            ("inf", Json::Float(f64::INFINITY)),
            ("s", Json::str("é\"\n\u{1}")),
            ("l", Json::Arr(vec![Json::Null, Json::Bool(true)])),
        ]);
        let text = v.to_text();
        assert_eq!(
            text,
            "{\"a\":1,\"big\":1000000000000000000000000000000,\"f\":1.0,\"inf\":null,\"s\":\"é\\\"\\n\\u0001\",\"l\":[null,true]}"
        );
        let back: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(back["s"], "é\"\n\u{1}");
    }
}
