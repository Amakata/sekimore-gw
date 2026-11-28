//! `/ws`: the live log (0.2.3's single poller, `src/web_ui/log_stream.py`).
//!
//! - On connect a client gets `{"type": "snapshot", "entries": [the latest 50]}`, and the same
//!   again whenever it sends `{"type": "resync"}`
//! - One poller, shared by every client, reads the rows added since its cursors once a second and
//!   sends them as one `{"type": "logs", "entries": [...]}`
//! - The poller stops when the last client leaves; its cursors stay where they were, so rows
//!   written while nobody watched arrive with the next client's first tick, as before

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::protocol::{Message, Role, WebSocketConfig};
use tokio_tungstenite::WebSocketStream;

use super::cfg::{Py, Raised};
use super::db::{Db, Row, SqlVal};
use super::json::{obj, Json};
use super::logs::{fw_row, proxy_reason};

pub const SNAPSHOT_LIMIT: i64 = 50;
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// uvicorn's `ws_max_size`: the largest message a client may send.
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Table {
    Dns,
    Fw,
    Proxy,
}

const TABLES: [Table; 3] = [Table::Dns, Table::Fw, Table::Proxy];

impl Table {
    fn name(self) -> &'static str {
        match self {
            Table::Dns => "dns_queries",
            Table::Fw => "firewall_blocks",
            Table::Proxy => "proxy_logs",
        }
    }

    fn columns(self) -> &'static str {
        match self {
            Table::Dns => "rowid, timestamp, client_ip, query_domain, response_ips, status",
            Table::Fw => "rowid, timestamp, src_ip, dst_ip, dst_port, protocol",
            Table::Proxy => {
                "rowid, timestamp, client_ip, method, url, status_code, squid_result, action"
            }
        }
    }

    fn new_rows_sql(self) -> String {
        let filter = if self == Table::Dns {
            " AND status != 'ignored'"
        } else {
            ""
        };
        format!(
            "SELECT {} FROM {} WHERE rowid > ?{filter} ORDER BY rowid ASC",
            self.columns(),
            self.name()
        )
    }

    fn snapshot_sql(self) -> String {
        let filter = if self == Table::Dns {
            " WHERE status != 'ignored'"
        } else {
            ""
        };
        format!(
            "SELECT {} FROM {}{filter} ORDER BY timestamp DESC LIMIT ?",
            self.columns(),
            self.name()
        )
    }

    /// The entry for a row without its leading rowid.
    fn entry(self, r: &Row) -> Py<Entry> {
        let at = |i: usize| r.at(i + 1);
        let fields = match self {
            Table::Dns => {
                let status = at(4)?;
                let action = match status.as_str() {
                    _ if !status.truthy() => "ALLOWED",
                    Some("allowed") => "ALLOWED",
                    Some("ignored") => "IGNORED",
                    _ => "BLOCKED",
                };
                [
                    at(0)?.to_json()?,
                    Json::str("DNS"),
                    Json::str(action),
                    at(1)?.to_json()?,
                    Json::opt_str(at(3)?.first_of_list()?),
                    Json::Null,
                    at(2)?.to_json()?,
                    Json::Null,
                ]
            }
            Table::Fw => {
                let fw = fw_row(at(1)?, at(2)?, at(4)?);
                [
                    at(0)?.to_json()?,
                    Json::str("FIREWALL"),
                    Json::str("BLOCKED"),
                    fw.src_ip.to_json()?,
                    fw.dst_ip.to_json()?,
                    at(3)?.to_json()?,
                    Json::Null,
                    Json::str(fw.reason),
                ]
            }
            Table::Proxy => {
                let shifted = Row(r.0.iter().skip(1).cloned().collect());
                let allowed = at(6)?.is_str("allowed");
                [
                    at(0)?.to_json()?,
                    Json::str("PROXY"),
                    Json::str(if allowed { "ALLOWED" } else { "BLOCKED" }),
                    at(1)?.to_json()?,
                    Json::Null,
                    Json::Null,
                    at(3)?.to_json()?,
                    Json::str(proxy_reason(&shifted, allowed)?),
                ]
            }
        };
        let [timestamp, component, action, src_ip, dst_ip, dst_port, domain, reason] = fields;
        Ok(Entry {
            ts: at(0)?.clone(),
            json: obj([
                ("timestamp", timestamp),
                ("component", component),
                ("action", action),
                ("src_ip", src_ip),
                ("dst_ip", dst_ip),
                ("dst_port", dst_port),
                ("domain", domain),
                ("reason", reason),
            ]),
        })
    }
}

/// An entry and the timestamp it is ordered by.
struct Entry {
    ts: SqlVal,
    json: Json,
}

/// `entries.sort(key=lambda e: e["timestamp"])`: stable, and raising where Python cannot order
/// two timestamps (a NULL against anything, a number against text).
fn sort_entries(entries: &mut [Entry]) -> Py<()> {
    if entries.len() < 2 {
        return Ok(());
    }
    let numeric = entries
        .iter()
        .all(|e| matches!(e.ts, SqlVal::Int(_) | SqlVal::Real(_)));
    let textual = entries.iter().all(|e| matches!(e.ts, SqlVal::Text(_)));
    if !numeric && !textual {
        return Err(Raised("'<' not supported between these timestamps"));
    }
    let key = |v: &SqlVal| match v {
        SqlVal::Int(i) => *i as f64,
        SqlVal::Real(f) => *f,
        _ => 0.0,
    };
    entries.sort_by(|a, b| match (&a.ts, &b.ts) {
        (SqlVal::Text(x), SqlVal::Text(y)) => x.cmp(y),
        _ => key(&a.ts)
            .partial_cmp(&key(&b.ts))
            .unwrap_or(std::cmp::Ordering::Equal),
    });
    Ok(())
}

fn message(kind: &str, entries: Vec<Entry>) -> String {
    obj([
        ("type", Json::str(kind)),
        (
            "entries",
            Json::Arr(entries.into_iter().map(|e| e.json).collect()),
        ),
    ])
    .to_text()
}

/// `snapshot()`: the latest `limit` entries across the three tables, oldest first. A table that
/// cannot be read (not there yet) is skipped.
pub fn snapshot(db_path: &Path, limit: i64) -> Py<String> {
    let db = Db::open(db_path)?;
    let mut entries = Vec::new();
    for t in TABLES {
        let Ok(rows) = db.rows(&t.snapshot_sql(), &[&limit]) else {
            continue;
        };
        for r in &rows {
            match t.entry(r) {
                Ok(e) => entries.push(e),
                Err(_) => break,
            }
        }
    }
    sort_entries(&mut entries)?;
    let skip = entries
        .len()
        .saturating_sub(usize::try_from(limit).unwrap_or(0));
    let entries: Vec<Entry> = entries.into_iter().skip(skip).collect();
    Ok(message("snapshot", entries))
}

/// `parse_client_message`: the `type` of a client's JSON object, or None.
pub fn client_message_type(text: &str) -> Option<String> {
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Object(o)) => match o.get("type") {
            Some(serde_json::Value::String(t)) => Some(t.clone()),
            _ => None,
        },
        _ => None,
    }
}

struct PollState {
    clients: usize,
    running: bool,
    cursors: HashMap<Table, i64>,
}

/// The poller every connection shares.
pub struct Streamer {
    db_path: PathBuf,
    state: Mutex<PollState>,
    tx: broadcast::Sender<Arc<String>>,
}

impl Streamer {
    pub fn new(db_path: PathBuf) -> Arc<Streamer> {
        let (tx, _) = broadcast::channel(256);
        Arc::new(Streamer {
            db_path,
            state: Mutex::new(PollState {
                clients: 0,
                running: false,
                cursors: HashMap::new(),
            }),
            tx,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PollState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A client joined: count it, and start the poller unless it runs.
    fn join(self: &Arc<Self>) -> broadcast::Receiver<Arc<String>> {
        let rx = self.tx.subscribe();
        let mut st = self.lock();
        st.clients += 1;
        if !st.running {
            st.running = true;
            let me = self.clone();
            std::thread::spawn(move || me.run());
        }
        rx
    }

    fn leave(&self) {
        let mut st = self.lock();
        st.clients = st.clients.saturating_sub(1);
    }

    /// `_init_cursors`: start from each table's tail as of now; history is the snapshot's.
    fn init_cursors(&self, db: Option<&Db>) {
        let mut st = self.lock();
        for t in TABLES {
            if st.cursors.contains_key(&t) {
                continue;
            }
            let max = db
                .and_then(|db| {
                    db.one(
                        &format!("SELECT COALESCE(MAX(rowid), 0) FROM {}", t.name()),
                        &[],
                    )
                    .ok()
                    .flatten()
                })
                .and_then(|r| r.at(0).ok().and_then(|v| v.int().ok()))
                .and_then(|n| i64::try_from(n).ok())
                .unwrap_or(0);
            st.cursors.insert(t, max);
        }
    }

    /// `poll_once`: the new rows, oldest first; the cursors move past them.
    fn poll_once(&self, db: Option<&Db>) -> Py<Vec<Entry>> {
        self.init_cursors(db);
        let mut entries = Vec::new();
        let Some(db) = db else {
            return Ok(entries);
        };
        for t in TABLES {
            let from = self.lock().cursors.get(&t).copied().unwrap_or(0);
            let Ok(rows) = db.rows(&t.new_rows_sql(), &[&from]) else {
                continue;
            };
            for r in &rows {
                if let Ok(id) = r.at(0).and_then(SqlVal::int) {
                    let id = i64::try_from(id).unwrap_or(i64::MAX);
                    let mut st = self.lock();
                    let c = st.cursors.entry(t).or_insert(0);
                    *c = (*c).max(id);
                }
                match t.entry(r) {
                    Ok(e) => entries.push(e),
                    Err(_) => break,
                }
            }
        }
        sort_entries(&mut entries)?;
        Ok(entries)
    }

    /// The poller's thread: while anyone listens, a tick a second.
    fn run(self: Arc<Self>) {
        let open = |p: &Path| p.exists().then(|| Db::open(p).ok()).flatten();
        let mut db = open(&self.db_path);
        self.init_cursors(db.as_ref());
        loop {
            {
                let mut st = self.lock();
                if st.clients == 0 {
                    st.running = false;
                    return;
                }
            }
            std::thread::sleep(POLL_INTERVAL);
            if db.is_none() {
                db = open(&self.db_path);
            }
            match self.poll_once(db.as_ref()) {
                Ok(entries) if !entries.is_empty() => {
                    let _ = self.tx.send(Arc::new(message("logs", entries)));
                }
                Ok(_) => {}
                Err(e) => log::warn!("webui: log stream poll error: {}", e.0),
            }
        }
    }
}

/// The settings every `/ws` connection gets.
pub fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE))
}

async fn send_snapshot(
    ws: &mut WebSocketStream<TokioIo<Upgraded>>,
    db_path: &Path,
) -> Result<(), ()> {
    let path = db_path.to_path_buf();
    let snap = tokio::task::spawn_blocking(move || snapshot(&path, SNAPSHOT_LIMIT))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    ws.send(Message::text(snap)).await.map_err(|_| ())
}

/// One `/ws` connection, after the handshake.
pub async fn serve_ws(upgraded: Upgraded, streamer: Arc<Streamer>) {
    let mut ws =
        WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, Some(ws_config()))
            .await;
    if send_snapshot(&mut ws, &streamer.db_path).await.is_err() {
        log::warn!("webui: failed to send the initial logs");
    }
    let mut rx = streamer.join();
    loop {
        tokio::select! {
            incoming = ws.next() => match incoming {
                Some(Ok(Message::Text(t))) => {
                    if client_message_type(t.as_str()).as_deref() == Some("resync")
                        && send_snapshot(&mut ws, &streamer.db_path).await.is_err()
                    {
                        break;
                    }
                }
                // ping / pong are answered by the protocol layer
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                // a binary frame is not text (`receive_text` raised), a close is a disconnect
                Some(Ok(Message::Binary(_) | Message::Close(_))) | Some(Err(_)) | None => break,
            },
            msg = rx.recv() => match msg {
                Ok(text) => {
                    if ws.send(Message::text(text.as_str())).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            },
        }
    }
    streamer.leave();
    let _ = ws.close(None).await;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn db_with(rows: &[&str]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.db");
        let c = rusqlite::Connection::open(&p).unwrap();
        c.execute_batch(
            "CREATE TABLE dns_queries (timestamp REAL, client_ip TEXT, query_domain TEXT, response_ips TEXT, ttl INTEGER, query_type TEXT, status TEXT DEFAULT 'allowed');
             CREATE TABLE firewall_blocks (timestamp REAL, src_ip TEXT, dst_ip TEXT, dst_port INTEGER, protocol TEXT, action TEXT DEFAULT 'blocked');
             CREATE TABLE proxy_logs (timestamp REAL, client_ip TEXT, method TEXT, url TEXT, status_code INTEGER, squid_result TEXT, action TEXT DEFAULT 'allowed');",
        )
        .unwrap();
        for r in rows {
            c.execute_batch(r).unwrap();
        }
        (dir, p)
    }

    #[test]
    fn it_builds_a_sorted_snapshot_without_ignored_dns() {
        let (_d, p) = db_with(&[
            "INSERT INTO dns_queries VALUES (3.0,'10.0.0.1','a.example','1.1.1.1,2.2.2.2',300,'A','allowed')",
            "INSERT INTO dns_queries VALUES (1.0,'10.0.0.1','i.example',NULL,300,'A','ignored')",
            "INSERT INTO firewall_blocks VALUES (2.0,'10.0.0.1','9.9.9.9',443,'TCP','blocked')",
            "INSERT INTO proxy_logs VALUES (4.0,'10.0.0.1','GET','http://x/',403,'TCP_DENIED','blocked')",
        ]);
        let v: serde_json::Value = serde_json::from_str(&snapshot(&p, 50).unwrap()).unwrap();
        assert_eq!(v["type"], "snapshot");
        let ts: Vec<f64> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["timestamp"].as_f64().unwrap())
            .collect();
        assert_eq!(ts, [2.0, 3.0, 4.0]);
        assert_eq!(v["entries"][1]["dst_ip"], "1.1.1.1");
        assert_eq!(
            v["entries"][2]["reason"],
            "GET blocked by proxy (TCP_DENIED/403)"
        );
    }

    #[test]
    fn it_survives_missing_tables() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("empty.db");
        rusqlite::Connection::open(&p).unwrap();
        assert_eq!(
            snapshot(&p, 50).unwrap(),
            r#"{"type":"snapshot","entries":[]}"#
        );
        // no file at all: read as an empty database
        assert_eq!(
            snapshot(&dir.path().join("none.db"), 50).unwrap(),
            r#"{"type":"snapshot","entries":[]}"#
        );
    }

    #[test]
    fn it_streams_only_new_rows_as_one_batch() {
        let (_d, p) = db_with(&[
            "INSERT INTO dns_queries VALUES (1.0,'10.0.0.1','old.example',NULL,300,'A','allowed')",
        ]);
        let s = Streamer::new(p.clone());
        let db = Db::open(&p).unwrap();
        assert!(
            s.poll_once(Some(&db)).unwrap().is_empty(),
            "history is the snapshot's"
        );
        let c = rusqlite::Connection::open(&p).unwrap();
        c.execute_batch(
            "INSERT INTO dns_queries VALUES (5.0,'10.0.0.1','new.example',NULL,300,'A','allowed');
             INSERT INTO dns_queries VALUES (6.0,'10.0.0.1','skip.example',NULL,300,'A','ignored');
             INSERT INTO firewall_blocks VALUES (4.0,'blocked','blocked',NULL,'IP','blocked');",
        )
        .unwrap();
        let got = s.poll_once(Some(&db)).unwrap();
        let text = message("logs", got);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let e = v["entries"].as_array().unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0]["component"], "FIREWALL");
        assert_eq!(
            e[0]["reason"],
            "Traffic blocked by firewall (counter-based detection)"
        );
        assert_eq!(e[1]["domain"], "new.example");
        assert!(s.poll_once(Some(&db)).unwrap().is_empty());
    }

    #[test]
    fn the_poller_stops_when_the_last_client_leaves() {
        let (_d, p) = db_with(&[]);
        let s = Streamer::new(p);
        let _rx = s.join();
        assert!(s.lock().running);
        s.leave();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while s.lock().running {
            assert!(
                std::time::Instant::now() < deadline,
                "the poller kept running"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // and a new client starts it again
        let _rx = s.join();
        assert!(s.lock().running);
        s.leave();
    }

    #[test]
    fn it_parses_client_messages() {
        assert_eq!(
            client_message_type(r#"{"type":"resync"}"#).as_deref(),
            Some("resync")
        );
        assert_eq!(client_message_type(r#"{"type":1}"#), None);
        assert_eq!(client_message_type("not json"), None);
        assert_eq!(client_message_type("[]"), None);
    }
}
