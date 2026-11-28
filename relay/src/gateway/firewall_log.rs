//! The firewall follower: ulogd's log of dropped packets (`/var/log/ulog/firewall.log`, or
//! `SEKIMORE_ULOG_PATH`) into `firewall_blocks`. The port of `src/firewall_monitor.py`.
//!
//! The file is followed the way Python followed it, by running `tail -F -n 0` on it: only lines
//! written after the start, a file that is missing is waited for, and a rotated or truncated one is
//! picked up again. When `tail` exits it is started again at once; when it cannot be started the
//! next try is ten seconds later.
//!
//! What is read from the pipe is cut into lines on `\n` the way asyncio's `StreamReader.readline`
//! cuts them, limit included: a line longer than 64 KiB is dropped, and when the limit is passed
//! before the line ends what was buffered is dropped and the rest of the line, when it comes, is
//! read as a line of its own. Each line is decoded as UTF-8 with the invalid bytes left out
//! (`errors="ignore"`) and stripped of Python's whitespace.
//!
//! A line becomes a row when it has `[FIREWALL-BLOCK]`, an `SRC=`, a `DST=` and a `PROTO=`; the
//! row's time is the time it was written, not the time in the line.

use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use rusqlite::Connection;

use super::{logdb, now, pytext};

/// What `parse_iptables_log` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub src_ip: String,
    pub dst_ip: String,
    /// The digits after `DPT=`, unparsed: Python's `int()` of them can still fail at the INSERT
    pub dst_port: Option<String>,
    pub protocol: String,
}

/// `constants.ULOG_FILE_PATH`.
pub fn ulog_path() -> PathBuf {
    ulog_path_from(|k| std::env::var(k).ok())
}

fn ulog_path_from(env: impl Fn(&str) -> Option<String>) -> PathBuf {
    PathBuf::from(env("SEKIMORE_ULOG_PATH").unwrap_or_else(|| "/var/log/ulog/firewall.log".into()))
}

/// The first `NAME=` in `line` followed by at least one character `ok` takes, and the run of
/// such characters after it: `re.search(r"NAME=(class+)", line)`.
fn search(line: &str, name: &str, ok: impl Fn(char) -> bool) -> Option<String> {
    let mut from = 0;
    while let Some(i) = line.get(from..).and_then(|s| s.find(name)) {
        let start = from + i + name.len();
        let run: String = line.get(start..)?.chars().take_while(|c| ok(*c)).collect();
        if !run.is_empty() {
            return Some(run);
        }
        from = from + i + 1;
    }
    None
}

/// Python's `\w` for a `str` pattern: `isalnum()` or `_`. Rust's alphanumeric also takes the
/// combining marks Unicode counts as Alphabetic, which Python's `isalpha()` does not (difference
/// ledger; ulogd writes the protocol in ASCII).
fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `parse_iptables_log`. `\d` is ASCII here; Python's also takes other scripts' decimal digits
/// (difference ledger, as for the config's integers).
pub fn parse(line: &str) -> Option<Block> {
    if !line.contains("[FIREWALL-BLOCK]") {
        return None;
    }
    let ip = |c: char| c.is_ascii_digit() || c == '.';
    let src_ip = search(line, "SRC=", ip)?;
    let dst_ip = search(line, "DST=", ip)?;
    let protocol = search(line, "PROTO=", is_word)?;
    let dst_port = search(line, "DPT=", |c| c.is_ascii_digit());
    Some(Block {
        src_ip,
        dst_ip,
        dst_port,
        protocol,
    })
}

/// What became of one line.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Not a block, or a block Python could not parse
    Skipped,
    Recorded,
    /// The INSERT failed: Python logged it and slept a second
    Failed(String),
}

/// One decoded, stripped line: parse it and record it.
pub fn handle(conn: &mut Connection, line: &str) -> Outcome {
    let Some(b) = parse(line) else {
        return Outcome::Skipped;
    };
    // int(): more than 4300 digits raises ValueError inside the parser, which returns None
    let port = match &b.dst_port {
        None => None,
        Some(d) if d.len() > pytext::INT_MAX_STR_DIGITS => {
            log::error!("Failed to parse iptables log: Exceeds the limit (4300 digits) for integer string conversion");
            return Outcome::Skipped;
        }
        // beyond i64 the INSERT raises OverflowError
        Some(d) => match d.parse::<i64>() {
            Ok(p) => Some(p),
            Err(_) => {
                return Outcome::Failed("Python int too large to convert to SQLite INTEGER".into())
            }
        },
    };
    match logdb::record_block(conn, now(), &b.src_ip, &b.dst_ip, port, &b.protocol) {
        Ok(()) => {
            log::info!(
                "Firewall block recorded src_ip={} dst_ip={} dst_port={} protocol={}",
                b.src_ip,
                b.dst_ip,
                port.filter(|p| *p != 0)
                    .map_or("N/A".to_string(), |p| p.to_string()),
                b.protocol
            );
            Outcome::Recorded
        }
        Err(e) => Outcome::Failed(e.to_string()),
    }
}

/// asyncio's `StreamReader` limit.
pub const LINE_LIMIT: usize = 64 * 1024;

/// `StreamReader.readline` over a byte stream.
pub struct Lines {
    buf: Vec<u8>,
}

/// One `readline()`.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// A line, without its `\n`
    Line(Vec<u8>),
    /// The limit was passed (`ValueError`); what Python dropped is gone
    Overrun,
    /// No complete line yet
    More,
}

impl Default for Lines {
    fn default() -> Self {
        Self::new()
    }
}

impl Lines {
    pub fn new() -> Self {
        Lines { buf: Vec::new() }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// What is left at EOF (`IncompleteReadError.partial`), emptying the buffer.
    pub fn rest(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    pub fn next_line(&mut self) -> Line {
        match self.buf.iter().position(|b| *b == b'\n') {
            Some(i) if i > LINE_LIMIT => {
                // "Separator is found, but chunk is longer than limit": dropped with its \n
                self.buf.drain(..=i);
                Line::Overrun
            }
            Some(i) => {
                let line: Vec<u8> = self.buf.drain(..=i).take(i).collect();
                Line::Line(line)
            }
            None if self.buf.len() > LINE_LIMIT => {
                // "Separator is not found, and chunk exceed the limit": the buffer is cleared
                self.buf.clear();
                Line::Overrun
            }
            None => Line::More,
        }
    }
}

/// Follows `path` for good, recording into `conn`. Returns only when `stop` says so (checked
/// between lines).
pub fn follow(conn: &mut Connection, path: &Path, stop: &dyn Fn() -> bool) {
    follow_with(conn, path, OsStr::new("tail"), stop);
}

/// [`follow`] with the `tail` to run named (the equivalence harness gives both implementations
/// the same stand-in).
pub fn follow_with(conn: &mut Connection, path: &Path, tail: &OsStr, stop: &dyn Fn() -> bool) {
    log::info!("Starting firewall monitor (ulogd file mode)");
    while !stop() {
        let child = Command::new(tail)
            .args(["-F", "-n", "0"])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                log::error!("Ulog file not found: {}, retrying...", path.display());
                std::thread::sleep(Duration::from_secs(10));
                continue;
            }
            Err(e) => {
                log::error!("Error monitoring ulog: {e}");
                std::thread::sleep(Duration::from_secs(10));
                continue;
            }
        };
        log::info!("Monitoring ulogd file: {}", path.display());
        if let Some(mut out) = child.stdout.take() {
            read_lines(&mut out, conn, stop);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    log::info!("Firewall monitor stopped");
}

/// Reads `out` to its end, a line at a time.
pub fn read_lines(out: &mut dyn Read, conn: &mut Connection, stop: &dyn Fn() -> bool) {
    let mut lines = Lines::new();
    // asyncio's pipe transport reads up to 256 KiB at a time
    let mut chunk = vec![0u8; 256 * 1024];
    loop {
        if stop() {
            return;
        }
        match lines.next_line() {
            Line::Line(bytes) => one(conn, &bytes),
            Line::Overrun => {
                log::error!(
                    "Error reading ulog: Separator is not found, and chunk exceed the limit"
                );
                std::thread::sleep(Duration::from_secs(1));
            }
            Line::More => match out.read(&mut chunk) {
                Ok(0) => {
                    // EOF: readline() returns what is left, then tail is started again
                    let rest = lines.rest();
                    if !rest.is_empty() {
                        one(conn, &rest);
                    }
                    return;
                }
                Ok(n) => lines.feed(chunk.get(..n).unwrap_or_default()),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    log::error!("Error reading ulog: {e}");
                    std::thread::sleep(Duration::from_secs(1));
                    return;
                }
            },
        }
    }
}

fn one(conn: &mut Connection, bytes: &[u8]) {
    let text = pytext::decode_ignore(bytes);
    let line = crate::settings::py::strip(&text);
    if let Outcome::Failed(e) = handle(conn, line) {
        // Python: the exception reached the read loop, which logged it and slept a second
        log::error!("Error reading ulog: {e}");
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn block(src: &str, dst: &str, port: Option<&str>, proto: &str) -> Option<Block> {
        Some(Block {
            src_ip: src.into(),
            dst_ip: dst.into(),
            dst_port: port.map(Into::into),
            protocol: proto.into(),
        })
    }

    /// test_firewall_monitor.py `it_parses_tcp_log`, `it_parses_udp_log`, `it_parses_icmp_log`,
    /// `it_ignores_non_firewall_logs`, `it_handles_malformed_logs`
    #[test]
    fn it_parses_what_python_parsed() {
        assert_eq!(
            parse("[FIREWALL-BLOCK] IN=eth0 OUT=eth1 SRC=172.20.0.5 DST=8.8.8.8 PROTO=TCP SPT=54321 DPT=53"),
            block("172.20.0.5", "8.8.8.8", Some("53"), "TCP")
        );
        assert_eq!(
            parse("[FIREWALL-BLOCK] IN=eth0 OUT=eth1 SRC=10.0.0.10 DST=1.1.1.1 PROTO=UDP SPT=12345 DPT=443"),
            block("10.0.0.10", "1.1.1.1", Some("443"), "UDP")
        );
        assert_eq!(
            parse("[FIREWALL-BLOCK] IN=eth0 OUT=eth1 SRC=192.168.1.5 DST=8.8.4.4 PROTO=ICMP"),
            block("192.168.1.5", "8.8.4.4", None, "ICMP")
        );
        assert_eq!(
            parse("Some other log message without the firewall prefix"),
            None
        );
        assert_eq!(parse("[FIREWALL-BLOCK] IN=eth0 OUT=eth1"), None);
    }

    #[test]
    fn it_searches_the_way_re_search_does() {
        // the first NAME= that is followed by the class wins, wherever it is
        assert_eq!(
            parse("x SRC= SRC=1.2 DST=.. PROTO=_a1 DPT=x DPT=007 [FIREWALL-BLOCK]"),
            block("1.2", "..", Some("007"), "_a1")
        );
        // an IPv6 address gives the digits before its first colon, or nothing
        assert_eq!(
            parse("[FIREWALL-BLOCK] SRC=2001:db8::1 DST=fe80::1 PROTO=TCP"),
            None
        );
        assert_eq!(
            parse("[FIREWALL-BLOCK] SRC=2001:db8::1 DST=2001:db8::2 PROTO=TCP"),
            block("2001", "2001", None, "TCP")
        );
        // MACSRC= is an SRC= too
        assert_eq!(
            parse("[FIREWALL-BLOCK] MACSRC=1.1 DST=2.2 PROTO=UDP"),
            block("1.1", "2.2", None, "UDP")
        );
    }

    fn db() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = logdb::open(&dir.path().join("gw.db")).unwrap();
        logdb::init_firewall(&conn).unwrap();
        (dir, conn)
    }

    fn rows(conn: &Connection) -> Vec<(String, String, Option<i64>, String)> {
        conn.prepare("SELECT src_ip, dst_ip, dst_port, protocol FROM firewall_blocks")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// test_firewall_monitor.py `it_processes_log_lines_and_records_blocks`,
    /// `it_handles_readline_exceptions` (an undecodable byte is left out, not an error)
    #[test]
    fn lines_from_the_pipe_become_rows() {
        let (_d, mut conn) = db();
        let input: &[u8] = b"[FIREWALL-BLOCK] SRC=10.0.0.2 DST=9.9.9.9 PROTO=TCP DPT=22\r\n\
            not a block\n\
            [FIREWALL-BLOCK] S\xffRC=10.0.0.3 DST=9.9.9.9 PROTO=UDP DPT=99999999999999999999\n\
            [FIREWALL-BLOCK] SRC=10.0.0.4 DST=9.9.9.9 PROTO=UDP DPT=0\n\
            [FIREWALL-BLOCK] SRC=10.0.0.5 DST=1.1.1.1 PROTO=ICMP";
        read_lines(&mut &input[..], &mut conn, &|| false);
        assert_eq!(
            rows(&conn),
            [
                ("10.0.0.2".into(), "9.9.9.9".into(), Some(22), "TCP".into()),
                ("10.0.0.4".into(), "9.9.9.9".into(), Some(0), "UDP".into()),
                ("10.0.0.5".into(), "1.1.1.1".into(), None, "ICMP".into()),
            ]
        );
    }

    #[test]
    fn a_port_python_cannot_read_records_nothing() {
        let (_d, mut conn) = db();
        let long = format!(
            "[FIREWALL-BLOCK] SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP DPT={}",
            "1".repeat(4301)
        );
        assert_eq!(handle(&mut conn, &long), Outcome::Skipped);
        let big = "[FIREWALL-BLOCK] SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP DPT=9223372036854775808";
        assert!(matches!(handle(&mut conn, big), Outcome::Failed(_)));
        let max = "[FIREWALL-BLOCK] SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP DPT=9223372036854775807";
        assert_eq!(handle(&mut conn, max), Outcome::Recorded);
        assert_eq!(rows(&conn).len(), 1);
    }

    #[test]
    fn readline_drops_what_passes_the_limit() {
        let mut l = Lines::new();
        l.feed(b"ab\ncd");
        assert_eq!(l.next_line(), Line::Line(b"ab".to_vec()));
        assert_eq!(l.next_line(), Line::More);
        // a whole line one byte over the limit, then a short one
        let mut l = Lines::new();
        let mut data = vec![b'x'; LINE_LIMIT + 1];
        data.extend_from_slice(b"\nok\n");
        l.feed(&data);
        assert_eq!(l.next_line(), Line::Overrun);
        assert_eq!(l.next_line(), Line::Line(b"ok".to_vec()));
        // exactly the limit is a line
        let mut l = Lines::new();
        let mut data = vec![b'y'; LINE_LIMIT];
        data.push(b'\n');
        l.feed(&data);
        assert_eq!(l.next_line(), Line::Line(vec![b'y'; LINE_LIMIT]));
        // past the limit with no \n yet: cleared, and the rest is a line of its own
        let mut l = Lines::new();
        l.feed(&vec![b'z'; LINE_LIMIT + 1]);
        assert_eq!(l.next_line(), Line::Overrun);
        l.feed(b"tail\n");
        assert_eq!(l.next_line(), Line::Line(b"tail".to_vec()));
    }

    /// test_firewall_monitor.py `describe_ulog_path_is_configurable`
    #[test]
    fn the_ulog_path_follows_the_environment() {
        assert_eq!(
            ulog_path_from(|_| None),
            PathBuf::from("/var/log/ulog/firewall.log")
        );
        assert_eq!(
            ulog_path_from(|k| (k == "SEKIMORE_ULOG_PATH").then(|| "/x/fw.log".to_string())),
            PathBuf::from("/x/fw.log")
        );
    }

    /// test_firewall_monitor.py `it_starts_monitoring`, `it_handles_file_not_found`,
    /// `it_terminates_process_on_stop`: `tail` is run on the path, and lines written after the
    /// start become rows.
    #[test]
    fn it_follows_a_file_through_tail() {
        let (dir, conn) = db();
        let log = dir.path().join("firewall.log");
        std::fs::write(
            &log,
            "[FIREWALL-BLOCK] SRC=10.9.9.9 DST=1.1.1.1 PROTO=TCP DPT=1\n",
        )
        .unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = stop.clone();
        let log2 = log.clone();
        let t = std::thread::spawn(move || {
            let mut conn = conn;
            follow(&mut conn, &log2, &|| {
                stop2.load(std::sync::atomic::Ordering::SeqCst)
            });
        });
        let db = dir.path().join("gw.db");
        let check = logdb::open(&db).unwrap();
        let count = || -> i64 {
            check
                .query_row("SELECT COUNT(*) FROM firewall_blocks", [], |r| r.get(0))
                .unwrap()
        };
        // tail -n 0: the line that was there is not read; keep appending until one lands
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while count() == 0 {
            assert!(std::time::Instant::now() < deadline, "nothing was recorded");
            use std::io::Write;
            writeln!(
                f,
                "[FIREWALL-BLOCK] SRC=10.0.0.7 DST=8.8.8.8 PROTO=UDP DPT=53"
            )
            .unwrap();
            std::thread::sleep(Duration::from_millis(200));
        }
        let first: String = check
            .query_row("SELECT src_ip FROM firewall_blocks LIMIT 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(first, "10.0.0.7");
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        // the stop is seen at the next line
        use std::io::Write;
        writeln!(f, "wake").unwrap();
        t.join().unwrap();
    }
}
