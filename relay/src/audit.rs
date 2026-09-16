//! Audit log (JSONL).
//!
//! Because the device flow runs with a human's permissions, GitHub's own audit log cannot tell
//! agent actions apart from human ones. Recording that distinction here is essential to this setup.
//!
//! Conventions: every denial carries a `reason`, agent-initiated events use `actor: agent-via-gateway`,
//! and the operator CLI uses `actor: operator`. Tokens are never written in any form other than `label`.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    /// An action an agent initiated over SSH or the HTTP API
    Agent,
    /// The operator CLI
    Operator,
    /// The relay itself (startup, configuration, and so on)
    System,
}

impl Actor {
    fn as_str(&self) -> &'static str {
        match self {
            Actor::Agent => "agent-via-gateway",
            Actor::Operator => "operator",
            Actor::System => "system",
        }
    }
}

pub struct Audit {
    path: Option<PathBuf>,
    echo: bool,
    mu: Mutex<()>,
}

impl Audit {
    /// If `path` is None, logs go to stderr only (for tests).
    pub fn new(path: Option<&Path>, echo: bool) -> std::io::Result<Self> {
        if let Some(p) = path {
            // Confirm the file opens early so permission errors surface at startup
            OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .open(p)?;
        }
        Ok(Audit {
            path: path.map(|p| p.to_path_buf()),
            echo,
            mu: Mutex::new(()),
        })
    }

    pub fn disabled() -> Self {
        Audit {
            path: None,
            echo: false,
            mu: Mutex::new(()),
        }
    }

    pub fn log(&self, event: &str, actor: Actor, fields: &[(&str, &str)]) {
        let mut entry = Map::new();
        entry.insert(
            "ts".into(),
            Value::String(humantime::format_rfc3339_seconds(SystemTime::now()).to_string()),
        );
        entry.insert("event".into(), Value::String(event.to_string()));
        entry.insert("via".into(), Value::String("sekimore-gateway".into()));
        entry.insert("actor".into(), Value::String(actor.as_str().into()));
        for (k, v) in fields {
            entry.insert((*k).to_string(), Value::String((*v).to_string()));
        }
        let line = Value::Object(entry).to_string();

        let _g = self.mu.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = &self.path {
            if let Ok(mut f) = OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .open(p)
            {
                let _ = f.write_all(line.as_bytes());
                let _ = f.write_all(b"\n");
            }
        }
        if self.echo {
            eprintln!("audit: {line}");
        }
    }

    /// Records a denial. Always carries a `reason`.
    pub fn deny(&self, event: &str, actor: Actor, reason: &str, fields: &[(&str, &str)]) {
        let mut v: Vec<(&str, &str)> = Vec::with_capacity(fields.len() + 1);
        v.push(("reason", reason));
        v.extend_from_slice(fields);
        self.log(event, actor, &v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_jsonl_with_required_fields() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        let a = Audit::new(Some(&p), false).unwrap();
        a.log("relay_ok", Actor::Agent, &[("repo", "Org/Repo")]);
        a.deny(
            "push_denied",
            Actor::Agent,
            "read-only",
            &[("repo", "Org/Repo")],
        );
        let text = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["event"], "relay_ok");
        assert_eq!(lines[0]["actor"], "agent-via-gateway");
        assert_eq!(lines[0]["via"], "sekimore-gateway");
        assert!(lines[0]["ts"].as_str().unwrap().ends_with('Z'));
        assert_eq!(lines[1]["reason"], "read-only");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
