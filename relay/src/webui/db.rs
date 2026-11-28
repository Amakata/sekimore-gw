//! The log database the Python gateway writes (DNS, the firewall and Squid monitors), read only.
//!
//! The Python UI opened it read-write with `aiosqlite.connect`, which creates an empty file when
//! there is none. Opening it read-only here changes nothing an endpoint answers: a missing file
//! reads as an empty database (an in-memory one), and a missing directory fails as it did.

use std::path::Path;
use std::time::Duration;

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};

use super::cfg::{Py, Raised};
use super::json::Json;
use crate::settings::py::float_repr;

/// One column value, with the type SQLite stored it as.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlVal {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl SqlVal {
    /// `bool(v)`.
    pub fn truthy(&self) -> bool {
        match self {
            SqlVal::Null => false,
            SqlVal::Int(i) => *i != 0,
            SqlVal::Real(f) => *f != 0.0,
            SqlVal::Text(s) => !s.is_empty(),
            SqlVal::Blob(b) => !b.is_empty(),
        }
    }

    /// `v == s` for a string `s`.
    pub fn is_str(&self, s: &str) -> bool {
        matches!(self, SqlVal::Text(t) if t == s)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            SqlVal::Text(t) => Some(t),
            _ => None,
        }
    }

    /// `str(v)`.
    pub fn py_str(&self) -> String {
        match self {
            SqlVal::Null => "None".into(),
            SqlVal::Int(i) => i.to_string(),
            SqlVal::Real(f) => float_repr(*f),
            SqlVal::Text(s) => s.clone(),
            SqlVal::Blob(b) => format!("b{}", super::cfg::repr_str(&String::from_utf8_lossy(b))),
        }
    }

    /// The value as `json.dumps` writes it. Bytes are not JSON (`TypeError`).
    pub fn to_json(&self) -> Py<Json> {
        Ok(match self {
            SqlVal::Null => Json::Null,
            SqlVal::Int(i) => Json::Int(i128::from(*i)),
            SqlVal::Real(f) => Json::Float(*f),
            SqlVal::Text(s) => Json::Str(s.clone()),
            SqlVal::Blob(_) => return Err(Raised("bytes are not JSON serializable")),
        })
    }

    /// `v.split(",")[0] if v else None`: the first of a comma-joined list.
    pub fn first_of_list(&self) -> Py<Option<String>> {
        if !self.truthy() {
            return Ok(None);
        }
        match self {
            SqlVal::Text(s) => Ok(Some(s.split(',').next().unwrap_or_default().to_string())),
            _ => Err(Raised("'.split' on a value that is not a string")),
        }
    }

    // ---- pydantic's lax conversions, for the model fields the UI fills from a row ----

    /// A `float` field.
    pub fn float(&self) -> Py<f64> {
        match self {
            SqlVal::Int(i) => Ok(*i as f64),
            SqlVal::Real(f) => Ok(*f),
            SqlVal::Text(s) => s
                .trim()
                .parse::<f64>()
                .map_err(|_| Raised("Input should be a valid number")),
            _ => Err(Raised("Input should be a valid number")),
        }
    }

    /// An `int` field.
    pub fn int(&self) -> Py<i128> {
        use crate::settings::lax;
        use crate::settings::yaml11::PyValue;
        let v = match self {
            SqlVal::Int(i) => PyValue::Int(i128::from(*i)),
            SqlVal::Real(f) => PyValue::Float(*f),
            SqlVal::Text(s) => PyValue::Str(s.clone()),
            _ => return Err(Raised("Input should be a valid integer")),
        };
        lax::int(&v, &[], &mut lax::Errors::new()).ok_or(Raised("Input should be a valid integer"))
    }

    /// An `int | None` field.
    pub fn opt_int(&self) -> Py<Option<i128>> {
        match self {
            SqlVal::Null => Ok(None),
            v => v.int().map(Some),
        }
    }

    /// A `str` field: only a string (bytes are not stored by the gateway and are refused here).
    pub fn string(&self) -> Py<String> {
        match self {
            SqlVal::Text(s) => Ok(s.clone()),
            _ => Err(Raised("Input should be a valid string")),
        }
    }

    /// A `str | None` field.
    pub fn opt_string(&self) -> Py<Option<String>> {
        match self {
            SqlVal::Null => Ok(None),
            v => v.string().map(Some),
        }
    }
}

/// A row, read by position. A position past the end raises, as `row[i]` would.
pub struct Row(pub Vec<SqlVal>);

impl Row {
    pub fn at(&self, i: usize) -> Py<&SqlVal> {
        self.0.get(i).ok_or(Raised("tuple index out of range"))
    }
}

/// A read-only connection.
pub struct Db(Connection);

impl Db {
    /// `get_db()`: the database at `path`, with the busy timeout the Python UI set.
    pub fn open(path: &Path) -> Py<Db> {
        let conn = if path.exists() {
            Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
        } else {
            // aiosqlite.connect would create it, empty, as long as its directory is there
            match path.parent() {
                Some(dir) if dir.as_os_str().is_empty() || dir.is_dir() => {
                    Connection::open_in_memory()
                }
                _ => return Err(Raised("unable to open database file")),
            }
        };
        let conn = conn.map_err(|_| Raised("unable to open database file"))?;
        let _ = conn.busy_timeout(Duration::from_millis(5000));
        Ok(Db(conn))
    }

    /// Every row of `sql` with `params`.
    pub fn rows(&self, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Py<Vec<Row>> {
        let mut stmt = self.0.prepare(sql).map_err(|_| Raised("sqlite error"))?;
        let n = stmt.column_count();
        let mut rows = stmt.query(params).map_err(|_| Raised("sqlite error"))?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().map_err(|_| Raised("sqlite error"))? {
            let mut vals = Vec::with_capacity(n);
            for i in 0..n {
                let v = r.get_ref(i).map_err(|_| Raised("sqlite error"))?;
                vals.push(match v {
                    ValueRef::Null => SqlVal::Null,
                    ValueRef::Integer(x) => SqlVal::Int(x),
                    ValueRef::Real(x) => SqlVal::Real(x),
                    ValueRef::Text(t) => SqlVal::Text(
                        String::from_utf8(t.to_vec())
                            .map_err(|_| Raised("Could not decode to UTF-8"))?,
                    ),
                    ValueRef::Blob(b) => SqlVal::Blob(b.to_vec()),
                });
            }
            out.push(Row(vals));
        }
        Ok(out)
    }

    /// The first row, if any.
    pub fn one(&self, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Py<Option<Row>> {
        Ok(self.rows(sql, params)?.into_iter().next())
    }

    /// `SELECT COUNT(*) …`: `row[0] if row else 0`.
    pub fn count(&self, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Py<i128> {
        match self.one(sql, params)? {
            Some(r) => r.at(0)?.int(),
            None => Ok(0),
        }
    }
}

/// A `LIMIT ?` parameter: Python's int, which SQLite takes only within 64 bits (`OverflowError`).
pub fn limit_param(limit: i128) -> Py<i64> {
    i64::try_from(limit).map_err(|_| Raised("Python int too large to convert to SQLite INTEGER"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_reads_as_an_empty_database_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("absent.db");
        let db = Db::open(&p).unwrap();
        assert!(db.rows("SELECT 1 FROM dns_queries", &[]).is_err());
        assert!(!p.exists(), "the read-only UI created the database");
        assert!(Db::open(&dir.path().join("no/such/dir.db")).is_err());
    }

    #[test]
    fn it_cannot_write() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.db");
        Connection::open(&p)
            .unwrap()
            .execute_batch("CREATE TABLE t (a)")
            .unwrap();
        let db = Db::open(&p).unwrap();
        assert!(db.rows("INSERT INTO t VALUES (1)", &[]).is_err());
    }

    #[test]
    fn conversions_follow_pydantic() {
        assert_eq!(SqlVal::Int(3).float().unwrap(), 3.0);
        assert_eq!(SqlVal::Real(80.0).opt_int().unwrap(), Some(80));
        assert!(SqlVal::Real(80.5).opt_int().is_err());
        assert_eq!(SqlVal::Text(" 8_0 ".into()).opt_int().unwrap(), Some(80));
        assert!(SqlVal::Int(1).opt_string().is_err());
        assert_eq!(SqlVal::Null.opt_string().unwrap(), None);
    }
}
