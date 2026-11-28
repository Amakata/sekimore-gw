//! The log database, as the two followers write it: the same tables, columns and indexes, opened
//! the way the Python gateway opens it (`src/dns_server.py` `_apply_pragmas`, and the followers'
//! own copies of it before 0.3.0-alpha.5).
//!
//! # Two writers
//!
//! The Python DNS server writes the same file (`dns_queries`, `cache_stats`) for as long as it is
//! the core (until 0.3.0-alpha.6). Both sides open it alike:
//!
//! - `journal_mode=WAL`: readers (the Web UI, `maint stats`) never block a writer, and a writer
//!   never blocks a reader. The mode is stored in the file, so whichever side opens first sets it
//! - `synchronous=NORMAL`
//! - `busy_timeout=5000`: a writer that finds the write lock held waits up to five seconds for it
//!   (Python's `sqlite3.connect` sets the same five seconds as its default `timeout`)
//! - one transaction per row: Python's `sqlite3` opens a deferred transaction before the INSERT
//!   and the caller commits after it. The INSERT is the transaction's first statement, so it asks
//!   for the write lock straight away and the busy timeout applies; there is no read-then-write
//!   upgrade that would fail with `SQLITE_BUSY` without waiting
//!
//! WAL has one writer at a time. The two processes take turns, each holding the lock for one
//! INSERT and its commit. What can still fail is a write that waits more than five seconds: an
//! operator's `maint vacuum` / `reset` holds the lock for as long as the VACUUM takes. Python
//! logged that row's failure and went on; so does this.

use std::path::Path;
use std::time::Duration;

use rusqlite::{params, Connection};

/// The pragmas, in order. A failure is not fatal (a read-only file system), as in Python.
const PRAGMAS: &[&str] = &[
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA busy_timeout=5000",
];

/// `aiosqlite.connect(path)` and the pragmas. The file is created when missing, as Python's
/// `sqlite3.connect` creates it.
pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    // Python's sqlite3.connect: timeout=5.0 is a busy handler of five seconds before any pragma
    conn.busy_timeout(Duration::from_secs(5))?;
    for pragma in PRAGMAS {
        // journal_mode answers with a row; the others do not
        let _ = conn.query_row(pragma, [], |_| Ok(())).or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(()),
            e => Err(e),
        });
    }
    Ok(conn)
}

/// `FirewallMonitor.init_db`: the table and its index.
pub fn init_firewall(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS firewall_blocks (
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                action TEXT DEFAULT 'blocked'
            );
         CREATE INDEX IF NOT EXISTS idx_firewall_timestamp
            ON firewall_blocks(timestamp);",
    )
}

/// `ProxyMonitor.init_db`: the table, its two indexes, and the move of an old `proxy_blocks`
/// table's rows into it (`_migrate_proxy_blocks`), committed together.
pub fn init_proxy(conn: &mut Connection) -> rusqlite::Result<Option<i64>> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS proxy_logs (
                timestamp REAL,
                client_ip TEXT,
                method TEXT,
                url TEXT,
                status_code INTEGER,
                squid_result TEXT,
                action TEXT DEFAULT 'allowed'
            );
         CREATE INDEX IF NOT EXISTS idx_proxy_logs_timestamp
            ON proxy_logs(timestamp);
         CREATE INDEX IF NOT EXISTS idx_proxy_logs_action
            ON proxy_logs(action);",
    )?;
    migrate_proxy_blocks(conn)
}

/// The rows moved, when there were any to move.
fn migrate_proxy_blocks(conn: &mut Connection) -> rusqlite::Result<Option<i64>> {
    let exists = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='proxy_blocks'",
            [],
            |_| Ok(()),
        )
        .map(|_| true)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(false),
            e => Err(e),
        })?;
    if !exists {
        return Ok(None);
    }
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM proxy_blocks", [], |r| r.get(0))?;
    if count == 0 {
        conn.execute_batch("DROP TABLE proxy_blocks")?;
        return Ok(None);
    }
    let existing: i64 = conn.query_row(
        "SELECT COUNT(*) FROM proxy_logs WHERE action = 'blocked'",
        [],
        |r| r.get(0),
    )?;
    if existing > 0 {
        conn.execute_batch("DROP TABLE proxy_blocks")?;
        return Ok(None);
    }
    // Python's sqlite3 opens a transaction before the INSERT; the DROP joins it and the commit at
    // the end of init_db closes it
    let tx = conn.transaction()?;
    tx.execute_batch(
        "INSERT INTO proxy_logs (timestamp, client_ip, method, url, status_code, squid_result, action)
            SELECT timestamp, client_ip, method, url, status_code, 'TCP_DENIED', 'blocked'
            FROM proxy_blocks;
         DROP TABLE proxy_blocks;",
    )?;
    tx.commit()?;
    Ok(Some(count))
}

/// One row of `firewall_blocks`. `action` is left to its default.
pub fn record_block(
    conn: &mut Connection,
    timestamp: f64,
    src_ip: &str,
    dst_ip: &str,
    dst_port: Option<i64>,
    protocol: &str,
) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO firewall_blocks (timestamp, src_ip, dst_ip, dst_port, protocol)
            VALUES (?, ?, ?, ?, ?)",
        params![timestamp, src_ip, dst_ip, dst_port, protocol],
    )?;
    tx.commit()
}

/// One row of `proxy_logs`.
pub struct Access<'a> {
    pub timestamp: f64,
    pub client_ip: &'a str,
    pub method: &'a str,
    pub url: &'a str,
    pub status_code: i64,
    pub squid_result: &'a str,
    pub action: &'a str,
}

pub fn record_access(conn: &mut Connection, a: &Access<'_>) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO proxy_logs
            (timestamp, client_ip, method, url, status_code, squid_result, action)
            VALUES (?, ?, ?, ?, ?, ?, ?)",
        params![
            a.timestamp,
            a.client_ip,
            a.method,
            a.url,
            a.status_code,
            a.squid_result,
            a.action
        ],
    )?;
    tx.commit()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn columns(conn: &Connection, table: &str) -> Vec<(String, String, Option<String>)> {
        let mut st = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        st.query_map([], |r| Ok((r.get(1)?, r.get(2)?, r.get(4)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn indexes(conn: &Connection, table: &str) -> Vec<String> {
        let mut st = conn
            .prepare(&format!("PRAGMA index_list({table})"))
            .unwrap();
        let mut v: Vec<String> = st
            .query_map([], |r| r.get(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        v.sort();
        v
    }

    /// test_firewall_monitor.py `it_initializes_database`, `it_records_block`
    #[test]
    fn the_firewall_table_has_pythons_columns_and_takes_a_row() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = open(&dir.path().join("gw.db")).unwrap();
        init_firewall(&conn).unwrap();
        init_firewall(&conn).unwrap(); // idempotent
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let busy: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(busy, 5000);
        assert_eq!(
            columns(&conn, "firewall_blocks"),
            [
                ("timestamp".into(), "REAL".into(), None),
                ("src_ip".into(), "TEXT".into(), None),
                ("dst_ip".into(), "TEXT".into(), None),
                ("dst_port".into(), "INTEGER".into(), None),
                ("protocol".into(), "TEXT".into(), None),
                ("action".into(), "TEXT".into(), Some("'blocked'".into())),
            ]
        );
        assert_eq!(
            indexes(&conn, "firewall_blocks"),
            ["idx_firewall_timestamp"]
        );
        record_block(&mut conn, 1.5, "192.168.1.100", "8.8.8.8", Some(53), "UDP").unwrap();
        record_block(&mut conn, 2.5, "192.168.1.100", "8.8.4.4", None, "ICMP").unwrap();
        let rows: Vec<(f64, String, String, Option<i64>, String, String)> = conn
            .prepare("SELECT * FROM firewall_blocks ORDER BY timestamp")
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            rows,
            [
                (
                    1.5,
                    "192.168.1.100".into(),
                    "8.8.8.8".into(),
                    Some(53),
                    "UDP".into(),
                    "blocked".into()
                ),
                (
                    2.5,
                    "192.168.1.100".into(),
                    "8.8.4.4".into(),
                    None,
                    "ICMP".into(),
                    "blocked".into()
                ),
            ]
        );
    }

    /// test_proxy_monitor.py `it_initializes_database`, `it_records_blocked_access`,
    /// `it_records_allowed_access`
    #[test]
    fn the_proxy_table_has_pythons_columns_and_takes_rows() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = open(&dir.path().join("gw.db")).unwrap();
        assert_eq!(init_proxy(&mut conn).unwrap(), None);
        assert_eq!(
            columns(&conn, "proxy_logs"),
            [
                ("timestamp".into(), "REAL".into(), None),
                ("client_ip".into(), "TEXT".into(), None),
                ("method".into(), "TEXT".into(), None),
                ("url".into(), "TEXT".into(), None),
                ("status_code".into(), "INTEGER".into(), None),
                ("squid_result".into(), "TEXT".into(), None),
                ("action".into(), "TEXT".into(), Some("'allowed'".into())),
            ]
        );
        assert_eq!(
            indexes(&conn, "proxy_logs"),
            ["idx_proxy_logs_action", "idx_proxy_logs_timestamp"]
        );
        for (result, action) in [("TCP_DENIED", "blocked"), ("TCP_MISS", "allowed")] {
            record_access(
                &mut conn,
                &Access {
                    timestamp: 1.25,
                    client_ip: "192.168.1.100",
                    method: "GET",
                    url: "http://example.com",
                    status_code: 403,
                    squid_result: result,
                    action,
                },
            )
            .unwrap();
        }
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM proxy_logs WHERE url = 'http://example.com'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 2);
    }

    fn proxy_blocks(conn: &Connection, rows: usize) {
        conn.execute_batch(
            "CREATE TABLE proxy_blocks (timestamp REAL, client_ip TEXT, method TEXT, url TEXT, status_code INTEGER)",
        )
        .unwrap();
        for i in 0..rows {
            conn.execute(
                "INSERT INTO proxy_blocks VALUES (?, '10.0.0.2', 'CONNECT', 'x.example:443', 403)",
                [i as f64],
            )
            .unwrap();
        }
    }

    /// test_proxy_monitor.py `describe_proxy_monitor_migration`: the three cases
    #[test]
    fn an_old_proxy_blocks_table_is_moved_once_and_dropped() {
        let dir = tempfile::tempdir().unwrap();
        // rows to move
        let mut conn = open(&dir.path().join("a.db")).unwrap();
        proxy_blocks(&conn, 3);
        assert_eq!(init_proxy(&mut conn).unwrap(), Some(3));
        let rows: Vec<(String, String)> = conn
            .prepare("SELECT squid_result, action FROM proxy_logs")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            rows,
            vec![("TCP_DENIED".to_string(), "blocked".to_string()); 3]
        );
        let gone: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='proxy_blocks'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(gone, 0);
        // an empty one is dropped
        let mut conn = open(&dir.path().join("b.db")).unwrap();
        proxy_blocks(&conn, 0);
        assert_eq!(init_proxy(&mut conn).unwrap(), None);
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='proxy_blocks'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
        // blocked rows already there: dropped without copying
        let mut conn = open(&dir.path().join("c.db")).unwrap();
        init_proxy(&mut conn).unwrap();
        record_access(
            &mut conn,
            &Access {
                timestamp: 9.0,
                client_ip: "c",
                method: "GET",
                url: "u",
                status_code: 403,
                squid_result: "TCP_DENIED",
                action: "blocked",
            },
        )
        .unwrap();
        proxy_blocks(&conn, 2);
        assert_eq!(init_proxy(&mut conn).unwrap(), None);
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM proxy_logs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    /// The Python gateway's DNS writer and these followers on one file, each on its own
    /// connection configured as its side configures it, writing as fast as they can: no row is
    /// lost and no write fails. `relay/tests/equivalence/` does the same with the real Python
    /// writer.
    #[test]
    fn two_writers_on_one_file_lose_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gw.db");
        {
            let conn = open(&path).unwrap();
            init_firewall(&conn).unwrap();
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS dns_queries (timestamp REAL, client_ip TEXT, query_domain TEXT,
                 response_ips TEXT, ttl INTEGER, query_type TEXT, status TEXT DEFAULT 'allowed')",
            )
            .unwrap();
        }
        const N: usize = 400;
        let threads: Vec<_> = (0..4)
            .map(|t| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let mut conn = open(&path).unwrap();
                    for i in 0..N {
                        if t % 2 == 0 {
                            record_block(&mut conn, i as f64, "10.0.0.2", "9.9.9.9", Some(22), "TCP")
                                .unwrap();
                        } else {
                            // DNSMapping.record_query: a deferred transaction around one INSERT
                            let tx = conn.transaction().unwrap();
                            tx.execute(
                                "INSERT INTO dns_queries (timestamp, client_ip, query_domain, response_ips, ttl, query_type, status)
                                 VALUES (?, '10.0.0.2', 'example.com', '1.2.3.4', 300, 'A', 'allowed')",
                                [i as f64],
                            )
                            .unwrap();
                            tx.commit().unwrap();
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let conn = open(&path).unwrap();
        let fw: i64 = conn
            .query_row("SELECT COUNT(*) FROM firewall_blocks", [], |r| r.get(0))
            .unwrap();
        let dns: i64 = conn
            .query_row("SELECT COUNT(*) FROM dns_queries", [], |r| r.get(0))
            .unwrap();
        assert_eq!((fw, dns), (2 * N as i64, 2 * N as i64));
    }
}
