//! The reload window as `maint` sees it: the port of `ReloadWindow` (`src/orchestrator.py`) for the
//! operator's commands, which read and write `/data/reload-window.json` (`SEKIMORE_RELOAD_STATE`).
//!
//! The file is the boundary with the Python orchestrator, which reads it on every check
//! (0.3.0 plan, "α5"). What is written here is byte for byte what Python wrote — `{"frozen": true}`,
//! or `{"until": <time.time() + seconds, as repr() writes a float>}` — through a `.tmp` file
//! renamed over it, and it is read the way Python reads it.
//!
//! S7: `freeze` reports a failure to write as a failure. Nothing here says the window is shut
//! unless the file that shuts it was written.

use std::path::{Path, PathBuf};

use super::now;
use crate::settings::py::float_repr;
use crate::settings::PyInt;

/// `constants.RELOAD_STATE_PATH`.
pub fn state_path() -> PathBuf {
    PathBuf::from(
        std::env::var("SEKIMORE_RELOAD_STATE")
            .unwrap_or_else(|_| "/data/reload-window.json".into()),
    )
}

/// An exception Python's `ReloadWindow` let out (the process ended with a traceback).
#[derive(Debug, PartialEq, Eq)]
pub struct Raised(pub String);

/// `ReloadWindow`, for one command's lifetime.
#[derive(Debug)]
pub struct ReloadWindow {
    pub mode: String,
    pub window_seconds: Option<PyInt>,
    opened_at: Option<f64>,
    frozen: bool,
    state_path: PathBuf,
    /// What Python logged through `log_error` (structlog's default prints it on stdout)
    pub logged: Vec<String>,
}

impl ReloadWindow {
    /// `ReloadWindow(mode, window_seconds, state_path)`: reads the override at once, as Python's
    /// constructor does. Like Python's, a window of a duration opens now — this process's now.
    pub fn new(
        mode: &str,
        window_seconds: Option<PyInt>,
        state_path: &Path,
    ) -> Result<Self, Raised> {
        let mut w = ReloadWindow {
            mode: mode.to_string(),
            window_seconds,
            opened_at: window_seconds.filter(|s| *s != 0).map(|_| now()),
            frozen: false,
            state_path: state_path.to_path_buf(),
            logged: Vec::new(),
        };
        w.refresh()?;
        Ok(w)
    }

    fn log(&mut self, msg: String) {
        self.logged.push(msg);
    }

    /// `_refresh_locked`. The mtime check that spares Python a read is not needed here: one
    /// command reads once.
    fn refresh(&mut self) -> Result<(), Raised> {
        if std::fs::metadata(&self.state_path).is_err() {
            return Ok(());
        }
        let text = match std::fs::read(&self.state_path)
            .map_err(|e| e.to_string())
            .and_then(|b| String::from_utf8(b).map_err(|e| e.to_string()))
        {
            Ok(t) => t,
            Err(e) => {
                self.log(format!("Cannot read the reload window state: {e}"));
                return Ok(());
            }
        };
        let raw: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                self.log(format!("Cannot read the reload window state: {e}"));
                return Ok(());
            }
        };
        let Some(obj) = raw.as_object() else {
            let p = self.state_path.display().to_string();
            self.log(format!("Reload window state is not an object: {p}"));
            return Ok(());
        };
        if obj.get("frozen").is_some_and(truthy) {
            self.frozen = true;
            return Ok(());
        }
        let Some(until) = obj.get("until").and_then(to_float) else {
            let p = self.state_path.display().to_string();
            self.log(format!("Reload window state has no usable 'until': {p}"));
            return Ok(());
        };
        let left = until - now();
        if left > 0.0 {
            self.frozen = false;
            self.window_seconds = Some(int(left)?);
            self.opened_at = Some(now());
            self.mode = "windowed".into();
        }
        Ok(())
    }

    /// `is_open()`.
    pub fn is_open(&self) -> bool {
        if self.frozen {
            return false;
        }
        match self.mode.as_str() {
            "auto" => true,
            "manual" => false,
            _ => match (self.opened_at, self.window_seconds) {
                (Some(at), Some(w)) => (now() - at) < w as f64,
                _ => false,
            },
        }
    }

    /// `seconds_left()`.
    pub fn seconds_left(&self) -> Result<Option<PyInt>, Raised> {
        if self.frozen {
            return Ok(None);
        }
        match (self.opened_at, self.window_seconds) {
            (Some(at), Some(w)) => Ok(Some(int(w as f64 - (now() - at))?.max(0))),
            _ => Ok(None),
        }
    }

    /// `describe()`.
    pub fn describe(&self) -> Result<String, Raised> {
        let open_now = self.is_open();
        if self.mode == "auto" && !self.frozen {
            return Ok("auto (applies on save)".into());
        }
        if self.frozen {
            return Ok("frozen (does not apply on save; reload-follow to reopen)".into());
        }
        if self.window_seconds.is_none() {
            return Ok("manual (does not apply on save)".into());
        }
        let left = self.seconds_left()?.unwrap_or(0);
        if !open_now || left <= 0 {
            return Ok("window closed (does not apply on save; reload-follow to reopen)".into());
        }
        Ok(format!(
            "open for {}m {}s (applies on save)",
            left / 60,
            left % 60
        ))
    }

    /// `follow(seconds)`: false when the file could not be written.
    pub fn follow(&mut self, seconds: PyInt) -> bool {
        self.frozen = false;
        self.window_seconds = Some(seconds);
        self.opened_at = Some(now());
        if self.mode == "manual" {
            self.mode = "windowed".into();
        }
        let until = now() + seconds as f64;
        self.write_state(&format!("{{\"until\": {}}}", float_repr(until)))
    }

    /// `freeze()`: false when the file could not be written, and then nothing says it is shut.
    pub fn freeze(&mut self) -> bool {
        self.frozen = true;
        self.write_state("{\"frozen\": true}")
    }

    /// `_write_state`: the parent made, a `.tmp` beside the file written and renamed over it.
    fn write_state(&mut self, payload: &str) -> bool {
        let result = (|| -> std::io::Result<()> {
            if let Some(parent) = self.state_path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let tmp = with_suffix_tmp(&self.state_path);
            std::fs::write(&tmp, payload)?;
            std::fs::rename(&tmp, &self.state_path)
        })();
        match result {
            Ok(()) => true,
            Err(e) => {
                self.log(format!("Cannot record the reload window: {e}"));
                false
            }
        }
    }
}

/// `Path.with_suffix(".tmp")` as Python 3.14 has it: the last suffix replaced (`a.` has the
/// suffix `.`), or `.tmp` added to a name without one (`.a`, `..`).
fn with_suffix_tmp(p: &Path) -> PathBuf {
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = match name.rfind('.') {
        Some(i) if i > 0 && !name.trim_start_matches('.').is_empty() => &name[..i],
        _ => name.as_str(),
    };
    p.with_file_name(format!("{stem}.tmp"))
}

/// `bool(v)` of a JSON value.
fn truthy(v: &serde_json::Value) -> bool {
    use serde_json::Value;
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `float(v)`: a number, a bool, or a string Python's `float()` reads. None where Python raised
/// TypeError or ValueError.
fn to_float(v: &serde_json::Value) -> Option<f64> {
    use serde_json::Value;
    match v {
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Number(n) => n.as_f64(),
        Value::String(s) => super::pyfmt::float(s),
        _ => None,
    }
}

/// `int(f)`: toward zero. Infinity raised OverflowError (and NaN ValueError) out of Python.
fn int(f: f64) -> Result<PyInt, Raised> {
    if f.is_nan() {
        return Err(Raised("cannot convert float NaN to integer".into()));
    }
    if f.is_infinite() {
        return Err(Raised("cannot convert float infinity to integer".into()));
    }
    // beyond i128 Python's int is exact and this saturates (difference ledger)
    Ok(f.trunc() as PyInt)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn state(dir: &tempfile::TempDir, text: Option<&str>) -> PathBuf {
        let p = dir.path().join("reload-window.json");
        if let Some(t) = text {
            std::fs::write(&p, t).unwrap();
        }
        p
    }

    #[test]
    fn the_modes_describe_themselves_as_python_did() {
        let d = tempfile::tempdir().unwrap();
        let p = state(&d, None);
        let w = |m: &str, s: Option<i128>| ReloadWindow::new(m, s, &p).unwrap();
        assert_eq!(
            w("auto", None).describe().unwrap(),
            "auto (applies on save)"
        );
        assert!(w("auto", None).is_open());
        assert_eq!(
            w("manual", None).describe().unwrap(),
            "manual (does not apply on save)"
        );
        assert!(!w("manual", None).is_open());
        // a window opens with the process, as Python's constructor opened it
        let d1800 = w("windowed", Some(1800)).describe().unwrap();
        assert!(
            d1800 == "open for 29m 59s (applies on save)"
                || d1800 == "open for 30m 0s (applies on save)",
            "{d1800}"
        );
        assert_eq!(
            w("windowed", Some(0)).describe().unwrap(),
            "window closed (does not apply on save; reload-follow to reopen)"
        );
    }

    #[test]
    fn what_freeze_and_follow_write_is_what_python_wrote() {
        let d = tempfile::tempdir().unwrap();
        let p = state(&d, None);
        let mut w = ReloadWindow::new("auto", None, &p).unwrap();
        assert!(w.freeze());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\"frozen\": true}");
        assert!(!d.path().join("reload-window.tmp").exists());
        let later = ReloadWindow::new("auto", None, &p).unwrap();
        assert!(!later.is_open());
        assert_eq!(
            later.describe().unwrap(),
            "frozen (does not apply on save; reload-follow to reopen)"
        );

        let mut w = ReloadWindow::new("manual", None, &p).unwrap();
        let before = now();
        assert!(w.follow(600));
        let text = std::fs::read_to_string(&p).unwrap();
        let until: f64 = text
            .strip_prefix("{\"until\": ")
            .and_then(|t| t.strip_suffix('}'))
            .unwrap()
            .parse()
            .unwrap();
        assert!((until - before - 600.0).abs() < 5.0, "{text}");
        // a follow narrows auto to a window, as in Python
        let later = ReloadWindow::new("auto", None, &p).unwrap();
        assert_eq!(later.mode, "windowed");
        assert!(later.is_open());
        assert!(later.describe().unwrap().starts_with("open for 9m 5"));
    }

    #[test]
    fn a_failed_write_says_so() {
        let d = tempfile::tempdir().unwrap();
        // the parent is a file: nothing can be written under it
        let blocker = d.path().join("f");
        std::fs::write(&blocker, "").unwrap();
        let p = blocker.join("reload-window.json");
        let mut w = ReloadWindow::new("auto", None, &p).unwrap();
        assert!(!w.freeze());
        assert!(
            w.logged[0].starts_with("Cannot record the reload window: "),
            "{:?}",
            w.logged
        );
        assert!(!w.follow(60));
    }

    #[test]
    fn it_reads_the_file_as_python_read_it() {
        let d = tempfile::tempdir().unwrap();
        let read = |t: &str| ReloadWindow::new("manual", None, &state(&d, Some(t)));
        // frozen is truthiness
        for t in [
            r#"{"frozen": 1}"#,
            r#"{"frozen": "no"}"#,
            r#"{"frozen": [0]}"#,
        ] {
            assert_eq!(
                read(t).unwrap().describe().unwrap(),
                "frozen (does not apply on save; reload-follow to reopen)",
                "{t}"
            );
        }
        // until: a number, a numeric string, a bool (1.0: long past)
        let future = format!(r#"{{"frozen": 0, "until": " {} "}}"#, now() + 120.0);
        assert!(read(&future).unwrap().is_open());
        let w = read(r#"{"until": true}"#).unwrap();
        assert!(w.logged.is_empty());
        assert!(!w.is_open());
        // the ones Python logged
        for (t, msg) in [
            ("[1]", "Reload window state is not an object"),
            ("{}", "Reload window state has no usable 'until'"),
            (
                r#"{"until": null}"#,
                "Reload window state has no usable 'until'",
            ),
            (
                r#"{"until": "soon"}"#,
                "Reload window state has no usable 'until'",
            ),
            ("not json", "Cannot read the reload window state"),
        ] {
            let w = read(t).unwrap();
            assert!(w.logged[0].starts_with(msg), "{t}: {:?}", w.logged);
            assert!(!w.is_open());
        }
        // an infinite window made Python raise
        assert!(read(r#"{"until": "inf"}"#).is_err());
        // NaN is never in the future
        assert!(!read(r#"{"until": "nan"}"#).unwrap().is_open());
    }

    #[test]
    fn with_suffix_is_pythons() {
        let t = |n: &str| {
            with_suffix_tmp(Path::new(&format!("/x/{n}")))
                .display()
                .to_string()
        };
        assert_eq!(t("reload-window.json"), "/x/reload-window.tmp");
        assert_eq!(t("a"), "/x/a.tmp");
        assert_eq!(t("a.b.json"), "/x/a.b.tmp");
        assert_eq!(t("a."), "/x/a.tmp");
        assert_eq!(t(".a"), "/x/.a.tmp");
    }
}
