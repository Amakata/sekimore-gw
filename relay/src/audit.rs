//! 監査ログ（JSONL）。
//!
//! device flow で「人の権限」で動くため、GitHub 側の監査ログでは
//! エージェントの操作と人間の操作が区別できない。その区別をここで残すことが、この構成では必須。
//!
//! 規約: 全ての拒否に `reason`、エージェント起点は `actor: agent-via-gateway`、
//! 操作者 CLI は `actor: operator`。トークンは `label` 以外の形で書かない。

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    /// SSH / HTTP API 経由でエージェントが起こした操作
    Agent,
    /// 操作者の CLI
    Operator,
    /// relay 自身（起動、設定など）
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
    /// `path` が None なら stderr のみ（テスト用）。
    pub fn new(path: Option<&Path>, echo: bool) -> std::io::Result<Self> {
        if let Some(p) = path {
            // 早期に開けることを確認する（権限エラーを起動時に出す）
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

    /// 拒否の記録。`reason` を必ず持つ。
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
