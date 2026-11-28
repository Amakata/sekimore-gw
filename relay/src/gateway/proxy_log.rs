//! The proxy follower: Squid's `/var/log/squid/access.log` into `proxy_logs`, both what Squid let
//! through and what it refused. The port of `src/proxy_monitor.py`.
//!
//! Python opened the file once, went to its end, and read on from there every half second, the way
//! `tail -f` does without `-F`: a rotated file is not followed (the open file keeps being read), and
//! a read that fails ends the follower for good. The ways it fails are kept: a byte that is not
//! UTF-8, or a character cut in half by the writer when the reader reaches the end, stops it
//! (`UnicodeDecodeError`), as does a status code too long for Python's `int()`.
//!
//! One difference comes from the move to a process of its own. Python started the follower after
//! Squid, so the file was there; a file missing at that point ended the follower at once. This
//! process starts beside the orchestrator, before Squid has written its log, so it waits for the
//! file to appear and then opens it as Python did (difference ledger).

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::Path;
use std::time::Duration;

use rusqlite::Connection;

use super::logdb::{self, Access};
use super::pytext::{self, TextReader};
use crate::settings::py::{is_space, strip};

/// `ProxyMonitor`'s default `log_path`.
pub const ACCESS_LOG: &str = "/var/log/squid/access.log";

/// `ALLOWED_RESULTS`.
const ALLOWED: &[&str] = &[
    "TCP_MISS",
    "TCP_HIT",
    "TCP_MEM_HIT",
    "TCP_REFRESH_HIT",
    "TCP_REFRESH_MISS",
    "TCP_TUNNEL",
];

/// `BLOCKED_RESULTS`.
const BLOCKED: &[&str] = &["TCP_DENIED"];

/// What `_parse_squid_log_line` returns, the status code unparsed (Python's `int()` of it can
/// raise, and the INSERT can refuse it).
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub timestamp: f64,
    pub client_ip: String,
    pub method: String,
    pub url: String,
    pub status_code: String,
    pub squid_result: String,
    pub action: &'static str,
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// The runs of non-whitespace in `line`, Python's whitespace (`\s` of a `str` pattern).
fn tokens(line: &str) -> impl Iterator<Item = &str> {
    line.split(is_space).filter(|t| !t.is_empty())
}

/// `SQUID_LOG_PATTERN.match(line)` and the classification:
///
/// `^(\d+\.\d+)\s+\d+\s+(\S+)\s+(\S+)/(\d+)\s+\d+\s+(\S+)\s+(\S+)`
///
/// Every `\S+` here is bounded by whitespace on both sides, so the pattern reads whole tokens: the
/// time, the elapsed time, the client, `result/status` (split at its last `/`, the backtracking
/// `\S+` gives that), the size, the method and the URL. Anything after the URL is ignored. `\d` is
/// ASCII here (difference ledger, as for the config's integers).
pub fn parse(line: &str) -> Option<Entry> {
    // `^` with no whitespace allowed before the time
    if line.starts_with(is_space) {
        return None;
    }
    let mut t = tokens(line);
    let ts = t.next()?;
    let (int, frac) = ts.split_once('.')?;
    if !digits(int) || !digits(frac) {
        return None;
    }
    if !digits(t.next()?) {
        return None;
    }
    let client_ip = t.next()?;
    let (squid_result, status) = t.next()?.rsplit_once('/')?;
    if squid_result.is_empty() || !digits(status) {
        return None;
    }
    if !digits(t.next()?) {
        return None;
    }
    let method = t.next()?;
    let url = t.next()?;
    let action = if ALLOWED.contains(&squid_result) {
        "allowed"
    } else if BLOCKED.contains(&squid_result) {
        "blocked"
    } else {
        return None;
    };
    Some(Entry {
        // digits, a dot, digits: always a float (an overlong one is inf, as for Python)
        timestamp: ts.parse().ok()?,
        client_ip: client_ip.into(),
        method: method.into(),
        url: url.into(),
        status_code: status.into(),
        squid_result: squid_result.into(),
        action,
    })
}

/// What became of one line.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Skipped,
    Recorded,
    /// The INSERT failed; logged, and the follower goes on
    Failed,
    /// `int()` raised outside any handler: Python's follower ended here
    Stop,
}

/// One line as `readline()` gave it.
pub fn handle(conn: &mut Connection, line: &str) -> Outcome {
    let Some(e) = parse(strip(line)) else {
        return Outcome::Skipped;
    };
    if e.status_code.len() > pytext::INT_MAX_STR_DIGITS {
        log::error!("Error following Squid log: Exceeds the limit (4300 digits) for integer string conversion");
        return Outcome::Stop;
    }
    let Ok(status_code) = e.status_code.parse::<i64>() else {
        log::error!(
            "Failed to record proxy access: Python int too large to convert to SQLite INTEGER"
        );
        return Outcome::Failed;
    };
    let access = Access {
        timestamp: e.timestamp,
        client_ip: &e.client_ip,
        method: &e.method,
        url: &e.url,
        status_code,
        squid_result: &e.squid_result,
        action: e.action,
    };
    match logdb::record_access(conn, &access) {
        Ok(()) => {
            if e.action == "blocked" {
                log::info!(
                    "Proxy access blocked client_ip={} url={} status_code={status_code}",
                    e.client_ip,
                    e.url
                );
            }
            Outcome::Recorded
        }
        Err(err) => {
            log::error!("Failed to record proxy access: {err}");
            Outcome::Failed
        }
    }
}

/// Waits for `path` to exist, then follows it from its end until `stop` or a read that Python
/// could not get past.
pub fn follow(conn: &mut Connection, path: &Path, stop: &dyn Fn() -> bool) {
    log::info!("Starting proxy monitor...");
    let file = loop {
        if stop() {
            return;
        }
        match File::open(path) {
            Ok(f) => break f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(e) => {
                log::error!("Error following Squid log: {e}");
                return;
            }
        }
    };
    follow_open(conn, file, stop);
    log::info!("Proxy monitor stopped");
}

/// `_follow_log` once the file is open.
pub fn follow_open(conn: &mut Connection, mut file: File, stop: &dyn Fn() -> bool) {
    if let Err(e) = file.seek(SeekFrom::End(0)) {
        log::error!("Error following Squid log: {e}");
        return;
    }
    let mut reader = TextReader::new(file);
    while !stop() {
        match reader.readline() {
            Ok(Ok(line)) if line.is_empty() => std::thread::sleep(Duration::from_millis(500)),
            Ok(Ok(line)) => {
                if handle(conn, &line) == Outcome::Stop {
                    return;
                }
            }
            Ok(Err(pytext::DecodeError)) => {
                log::error!("Error following Squid log: 'utf-8' codec can't decode the log");
                return;
            }
            Err(e) => {
                log::error!("Error following Squid log: {e}");
                return;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn entry(line: &str) -> Entry {
        parse(line).unwrap()
    }

    /// test_proxy_monitor.py: the parse cases
    #[test]
    fn it_parses_what_python_parsed() {
        let e = entry("1234567890.123 100 192.168.1.5 TCP_DENIED/403 0 CONNECT blocked.com:443 - HIER_NONE/- -");
        assert_eq!(
            e,
            Entry {
                timestamp: 1234567890.123,
                client_ip: "192.168.1.5".into(),
                method: "CONNECT".into(),
                url: "blocked.com:443".into(),
                status_code: "403".into(),
                squid_result: "TCP_DENIED".into(),
                action: "blocked",
            }
        );
        let e = entry("1234567890.456 50 10.0.0.10 TCP_MISS/200 1234 GET http://example.com/page.html - DIRECT/93.184.216.34 text/html");
        assert_eq!(
            (e.status_code.as_str(), e.squid_result.as_str(), e.action),
            ("200", "TCP_MISS", "allowed")
        );
        assert_eq!(
            (e.method.as_str(), e.url.as_str()),
            ("GET", "http://example.com/page.html")
        );
        let e = entry("1234567890.789 5 10.0.0.10 TCP_HIT/200 5678 GET http://cached.com/resource - HIER_DIRECT/- text/html");
        assert_eq!((e.squid_result.as_str(), e.action), ("TCP_HIT", "allowed"));
        let e = entry("1234567890.100 200 172.20.0.5 TCP_TUNNEL/200 12345 CONNECT example.com:443 - HIER_DIRECT/93.184.216.34 -");
        assert_eq!(
            (e.squid_result.as_str(), e.action, e.method.as_str()),
            ("TCP_TUNNEL", "allowed", "CONNECT")
        );
        let e = entry("1234567890.789 200 172.20.0.5 TCP_DENIED/403 0 CONNECT malicious.com:8443 - HIER_NONE/- -");
        assert_eq!(
            (e.url.as_str(), e.status_code.as_str()),
            ("malicious.com:8443", "403")
        );
        assert_eq!(parse("1234567890.456 50 10.0.0.10 TCP_UNKNOWN_THING/500 0 GET http://example.com - DIRECT/- -"), None);
        assert_eq!(parse("Invalid log format"), None);
    }

    #[test]
    fn it_matches_the_way_the_pattern_does() {
        // result/status splits at the last slash: the result is `TCP_MISS/x`, which is neither
        assert_eq!(parse("1.5 0 c TCP_MISS/x/200 0 GET u"), None);
        assert_eq!(parse("1.5 0 c TCP_MISS/200x 0 GET u"), None);
        assert_eq!(parse("1.5 0 c /200 0 GET u"), None);
        // Python's whitespace separates, NBSP and U+001F included; nothing after the URL matters
        let e = entry("1.5\t0\u{a0}c\u{1f}TCP_HIT/200  0 GET u trailing junk");
        assert_eq!((e.client_ip.as_str(), e.url.as_str()), ("c", "u"));
        // the URL is required; leading whitespace is not allowed (the caller strips)
        assert_eq!(parse("1.5 0 c TCP_HIT/200 0 GET"), None);
        assert_eq!(parse(" 1.5 0 c TCP_HIT/200 0 GET u"), None);
        // the time needs digits on both sides of one dot
        assert_eq!(parse("1. 0 c TCP_HIT/200 0 GET u"), None);
        assert_eq!(parse("1.2.3 0 c TCP_HIT/200 0 GET u"), None);
        assert_eq!(entry("007.50 0 c TCP_HIT/200 0 GET u").timestamp, 7.5);
    }

    fn db() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = logdb::open(&dir.path().join("gw.db")).unwrap();
        logdb::init_proxy(&mut conn).unwrap();
        (dir, conn)
    }

    /// test_proxy_monitor.py `it_handles_record_exception`: a failed INSERT is logged and the
    /// follower goes on; and the status codes Python could not take
    #[test]
    fn the_status_code_decides_between_a_row_a_failure_and_the_end() {
        let (_d, mut conn) = db();
        let line = |status: &str| format!("1.5 0 c TCP_DENIED/{status} 0 GET u\n");
        assert_eq!(handle(&mut conn, &line("403")), Outcome::Recorded);
        assert_eq!(
            handle(&mut conn, &line("9223372036854775808")),
            Outcome::Failed
        );
        assert_eq!(handle(&mut conn, &line(&"4".repeat(4301))), Outcome::Stop);
        conn.execute_batch("DROP TABLE proxy_logs").unwrap();
        assert_eq!(handle(&mut conn, &line("403")), Outcome::Failed);
    }

    /// test_proxy_monitor.py `it_stops_monitoring`; and following from the end of the file
    #[test]
    fn it_reads_only_what_is_written_after_it_opened() {
        let (dir, conn) = db();
        let log = dir.path().join("access.log");
        std::fs::write(&log, "1.0 0 old TCP_MISS/200 0 GET u\n").unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (s2, l2) = (stop.clone(), log.clone());
        let file = File::open(&l2).unwrap();
        let t = std::thread::spawn(move || {
            let mut conn = conn;
            follow_open(&mut conn, file, &|| {
                s2.load(std::sync::atomic::Ordering::SeqCst)
            });
        });
        // the seek happens on the thread: give it a moment before appending
        std::thread::sleep(Duration::from_millis(300));
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
            f.write_all(b"2.0 0 new TCP_DENIED/403 0 CONNECT x:443\n")
                .unwrap();
        }
        let check = logdb::open(&dir.path().join("gw.db")).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let n: i64 = check
                .query_row("SELECT COUNT(*) FROM proxy_logs", [], |r| r.get(0))
                .unwrap();
            if n > 0 {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(100));
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        t.join().unwrap();
        let ips: Vec<String> = check
            .prepare("SELECT client_ip FROM proxy_logs")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(ips, ["new"]);
    }
}
