//! A request as the handlers see it, and the responses FastAPI gave: the same status codes and
//! bodies for a path it did not know (404), a method it did not serve (405), a query parameter
//! that is not an integer (422), a handler that raised (500), and a trailing slash (307).

use super::json::{obj, Json};

/// What a handler is given: nothing but the request line and the three headers the UI reads.
#[derive(Debug, Clone, Default)]
pub struct Req {
    /// Percent-decoded, as Starlette routes on it
    pub path: String,
    /// The raw query string
    pub query: String,
    /// `(name, value)` pairs, decoded as `parse_qsl(keep_blank_values=True)`
    pub params: Vec<(String, String)>,
    pub host: Option<String>,
    pub accept_language: Option<String>,
    pub cookie: Option<String>,
}

impl Req {
    pub fn new(
        path: &str,
        query: Option<&str>,
        host: Option<&str>,
        accept_language: Option<&str>,
        cookie: Option<&str>,
    ) -> Req {
        let query = query.unwrap_or_default().to_string();
        Req {
            path: percent_decode(path, false),
            params: parse_qsl(&query),
            query,
            host: host.map(String::from),
            accept_language: accept_language.map(String::from),
            cookie: cookie.map(String::from),
        }
    }

    /// A query parameter: the last one given, as Starlette's `QueryParams.get`.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// A cookie, as Starlette's `cookie_parser` reads the header.
    pub fn cookie_value(&self, name: &str) -> Option<String> {
        let header = self.cookie.as_deref()?;
        let mut found = None;
        for chunk in header.split(';') {
            let (k, v) = match chunk.split_once('=') {
                Some((k, v)) => (k, v),
                None => ("", chunk),
            };
            let (k, v) = (k.trim(), v.trim());
            if (!k.is_empty() || !v.is_empty()) && k == name {
                found = Some(unquote_cookie(v));
            }
        }
        found
    }
}

/// `http.cookies._unquote`: a value in double quotes loses them and its backslash escapes.
fn unquote_cookie(v: &str) -> String {
    let Some(inner) = v
        .strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .filter(|_| v.len() >= 2)
    else {
        return v.to_string();
    };
    let chars: Vec<char> = inner.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        if c != '\\' {
            out.push(c);
            i += 1;
            continue;
        }
        // `\\(?:([0-3][0-7][0-7])|(.))`
        let triple: Option<String> = chars.get(i + 1..i + 4).map(|t| t.iter().collect());
        let octal = triple.as_deref().filter(|t| {
            let b = t.as_bytes();
            matches!(b, [a, x, y] if (b'0'..=b'3').contains(a) && (b'0'..=b'7').contains(x) && (b'0'..=b'7').contains(y))
        });
        if let Some(ch) = octal
            .and_then(|t| u32::from_str_radix(t, 8).ok())
            .and_then(char::from_u32)
        {
            out.push(ch);
            i += 4;
        } else if let Some(&n) = chars.get(i + 1) {
            out.push(n);
            i += 2;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// `urllib.parse.unquote` (with `+` as a space for a query): invalid UTF-8 becomes U+FFFD.
pub fn percent_decode(s: &str, plus_is_space: bool) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let hex = b
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok());
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if plus_is_space && c == b'+' { b' ' } else { c });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `parse_qsl(qs, keep_blank_values=True)`.
pub fn parse_qsl(qs: &str) -> Vec<(String, String)> {
    qs.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (percent_decode(k, true), percent_decode(v, true))
        })
        .collect()
}

/// A response.
#[derive(Debug, Clone, PartialEq)]
pub struct Resp {
    pub status: u16,
    pub content_type: Option<&'static str>,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn json(v: &Json) -> Resp {
        Resp {
            status: 200,
            content_type: Some("application/json"),
            headers: vec![],
            body: v.to_text().into_bytes(),
        }
    }

    pub fn html(text: &str) -> Resp {
        Resp {
            status: 200,
            content_type: Some("text/html; charset=utf-8"),
            headers: vec![],
            body: text.as_bytes().to_vec(),
        }
    }

    fn detail(status: u16, msg: &str) -> Resp {
        Resp {
            status,
            ..Resp::json(&obj([("detail", Json::str(msg))]))
        }
    }

    pub fn not_found() -> Resp {
        Resp::detail(404, "Not Found")
    }

    pub fn method_not_allowed() -> Resp {
        Resp {
            headers: vec![("allow", "GET".into())],
            ..Resp::detail(405, "Method Not Allowed")
        }
    }

    /// FastAPI's answer to a query parameter pydantic could not read as an integer.
    pub fn not_an_int(param: &str, input: &str) -> Resp {
        Resp {
            status: 422,
            ..Resp::json(&obj([(
                "detail",
                Json::Arr(vec![obj([
                    ("type", Json::str("int_parsing")),
                    ("loc", Json::strs(&["query", param])),
                    (
                        "msg",
                        Json::str(
                            "Input should be a valid integer, unable to parse string as an integer",
                        ),
                    ),
                    ("input", Json::str(input)),
                ])]),
            )]))
        }
    }

    /// What Starlette answered when a handler raised.
    pub fn internal_error() -> Resp {
        Resp {
            status: 500,
            content_type: Some("text/plain; charset=utf-8"),
            headers: vec![],
            body: b"Internal Server Error".to_vec(),
        }
    }

    /// `redirect_slashes`: 307 to the same URL with the trailing slash toggled.
    pub fn redirect(req: &Req, path: &str, fallback_host: &str) -> Resp {
        let host = req.host.as_deref().unwrap_or(fallback_host);
        let mut location = format!("http://{host}{path}");
        if !req.query.is_empty() {
            location.push('?');
            location.push_str(&req.query);
        }
        Resp {
            status: 307,
            content_type: None,
            headers: vec![("location", location)],
            body: vec![],
        }
    }

    /// Refusing a WebSocket handshake on a path with no WebSocket route.
    pub fn forbidden() -> Resp {
        Resp {
            status: 403,
            content_type: None,
            headers: vec![],
            body: vec![],
        }
    }
}

/// An `int` query parameter with a default: the value, or FastAPI's 422.
pub fn int_param(req: &Req, name: &str, default: i128) -> Result<i128, Resp> {
    use crate::settings::lax;
    use crate::settings::yaml11::PyValue;
    match req.param(name) {
        None => Ok(default),
        Some(raw) => lax::int(&PyValue::Str(raw.to_string()), &[], &mut lax::Errors::new())
            .ok_or_else(|| Resp::not_an_int(name, raw)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn queries_decode_as_parse_qsl() {
        assert_eq!(
            parse_qsl("a=1&b=&c&&d=x+y%20z&e=%zz"),
            [
                ("a".to_string(), "1".to_string()),
                ("b".into(), "".into()),
                ("c".into(), "".into()),
                ("d".into(), "x y z".into()),
                ("e".into(), "%zz".into())
            ]
        );
        let r = Req::new("/api/%6cogs", Some("limit=1&limit=2"), None, None, None);
        assert_eq!(r.path, "/api/logs");
        assert_eq!(r.param("limit"), Some("2"));
    }

    #[test]
    fn int_params_read_as_pydantic_reads_them() {
        let r = |q: &str| Req::new("/", Some(q), None, None, None);
        assert_eq!(int_param(&r("limit=+5"), "limit", 100), Ok(5));
        assert_eq!(int_param(&r("limit=%205.0%20"), "limit", 100), Ok(5));
        assert_eq!(int_param(&r(""), "limit", 100), Ok(100));
        assert_eq!(
            int_param(&r("limit=1e2"), "limit", 100).unwrap_err().status,
            422
        );
        assert_eq!(
            int_param(&r("limit="), "limit", 100).unwrap_err().status,
            422
        );
    }

    #[test]
    fn cookies_read_as_starlette_reads_them() {
        let r = Req::new("/", None, None, None, Some("a=1; sekimore_lang=\"ja\"; b"));
        assert_eq!(r.cookie_value("sekimore_lang").as_deref(), Some("ja"));
        assert_eq!(r.cookie_value("b"), None);
    }
}
