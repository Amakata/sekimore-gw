//! `sekimore-relay maint`: the port of `src/maint.py` — the reload window (`reload-status`,
//! `reload-follow`, `reload-freeze`) and the log database (`db-stats`, `db-prune`, `db-reset`,
//! `db-vacuum`).
//!
//! Operators and `sgw` read what it prints, so the output text and the exit codes are Python's:
//! the same lines in both languages, 0 for done, 1 for a failure (a missing database, a window that
//! could not be recorded, and every exception Python let out), 2 for a refused command line and for
//! a destructive command without `--yes`. The command line is read the way `argparse` read it —
//! options before the command name belong to `maint` (`--db`, `--config`), the rest to the
//! command, long options may be shortened to any unique prefix, and a word that starts like a
//! negative number is a value.
//!
//! `python -m src.maint …` runs this (the module is a shim from 0.3.0-alpha.5), so an `sgw` from
//! before this release, which calls it that way, gets the same answers.
//!
//! Only `--help` and the wording of a refusal differ from Python's (the plan's rule keeps meaning,
//! not wording).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::types::ValueRef;
use rusqlite::Connection;

use super::now;
use super::pyfmt::{self, Json, Num};
use super::reload_window::{state_path, Raised, ReloadWindow};
use crate::i18n::t_in;
use crate::settings::yaml11::{self, PyValue};

const PROG: &str = "sekimore-relay maint";

/// Tables that accumulate log records; `cache_stats` is cleared only on reset.
const LOG_TABLES: &[&str] = &["dns_queries", "firewall_blocks", "proxy_logs"];
const RESET_ONLY_TABLES: &[&str] = &["cache_stats"];

const COMMANDS: &[&str] = &[
    "db-stats",
    "db-prune",
    "db-reset",
    "db-vacuum",
    "reload-follow",
    "reload-freeze",
    "reload-status",
];

/// How a run ended other than with an exit code of its own.
#[derive(Debug)]
enum Stop {
    /// `argparse` refused the command line: exit 2
    Usage(String),
    /// `--help`: exit 0
    Help(String),
    /// An exception Python did not catch: exit 1
    Raised(String),
}

impl From<rusqlite::Error> for Stop {
    fn from(e: rusqlite::Error) -> Self {
        Stop::Raised(e.to_string())
    }
}

impl From<std::io::Error> for Stop {
    fn from(e: std::io::Error) -> Self {
        Stop::Raised(e.to_string())
    }
}

impl From<Raised> for Stop {
    fn from(e: Raised) -> Self {
        Stop::Raised(e.0)
    }
}

/// What follows `maint` on the process's command line, as it was typed.
///
/// clap reads `sekimore-relay`'s global options (`--config`, `-v`) wherever they stand, so a
/// `-v` after `maint` would be taken where `python -m src.maint` refused it. The words after
/// `maint` are taken from the raw command line instead; `--config` there is maint's own option
/// as it was Python's. None when the line is not the plain `sekimore-relay [globals] maint …`.
pub fn raw_args(argv: &[String]) -> Option<Vec<String>> {
    let mut i = 1;
    while let Some(w) = argv.get(i) {
        match w.as_str() {
            "maint" => return Some(argv.get(i + 1..).unwrap_or_default().to_vec()),
            "--config" => i += 2,
            w if w.starts_with("--config=") || w == "--verbose" => i += 1,
            w if w.len() > 1 && w.starts_with('-') && w[1..].bytes().all(|b| b == b'v') => i += 1,
            _ => return None,
        }
    }
    None
}

/// Runs `maint` with `args` (what follows `maint` on the command line). `config` is the
/// `config.yml` to read unless `--config` names another; `lang` the language of the output.
pub fn main(args: &[String], config: &Path, lang: &str) -> i32 {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let code = run(
        args,
        config,
        &state_path(),
        lang,
        &mut stdout.lock(),
        &mut stderr.lock(),
    );
    let _ = std::io::stdout().flush();
    code
}

/// [`main`] with the reload window's state file and the two outputs given.
pub fn run(
    args: &[String],
    config: &Path,
    state: &Path,
    lang: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let tr = |key: &str| t_in(lang, key);
    let parsed = match parse(args, lang) {
        Ok(p) => p,
        Err(Stop::Help(text)) => {
            let _ = write!(out, "{text}");
            return 0;
        }
        Err(Stop::Usage(msg)) => {
            let _ = writeln!(err, "{}", usage_line(None));
            let _ = writeln!(err, "{PROG}: error: {msg}");
            return 2;
        }
        Err(Stop::Raised(msg)) => return raised(err, &msg),
    };
    let config = parsed
        .config
        .clone()
        .unwrap_or_else(|| config.to_path_buf());
    let result = if parsed.cmd.starts_with("reload-") {
        reload_cmd(&parsed, &config, state, &tr, out, err)
    } else {
        db_cmd(&parsed, &config, &tr, out, err)
    };
    match result {
        Ok(code) => code,
        Err(Stop::Raised(msg)) => raised(err, &msg),
        Err(Stop::Usage(msg)) => {
            let _ = writeln!(err, "{}", usage_line(Some(&parsed.cmd)));
            let _ = writeln!(err, "{PROG} {}: error: {msg}", parsed.cmd);
            2
        }
        Err(Stop::Help(text)) => {
            let _ = write!(out, "{text}");
            0
        }
    }
}

/// Where Python printed a traceback and exited 1.
fn raised(err: &mut dyn Write, msg: &str) -> i32 {
    let _ = writeln!(err, "{PROG}: failed: {msg}");
    1
}

/// structlog's default rendering of `log_error(ComponentType.ORCHESTRATOR, msg)`, which
/// `ReloadWindow` printed on stdout (the line's format is not kept, its place is).
fn log_line(out: &mut dyn Write, msg: &str) {
    let secs = now() as i64;
    let stamp = pyfmt::timestamp(Num::Int(secs)).unwrap_or_default();
    let stamp = stamp.replace('T', " ").trim_end_matches('Z').to_string();
    let _ = writeln!(out, "{stamp} [error    ] {msg} component=ORCHESTRATOR");
}

// ---------------------------------------------------------------------------------------------
// The command line

#[derive(Debug, Default)]
struct Parsed {
    db: Option<String>,
    config: Option<PathBuf>,
    cmd: String,
    json: bool,
    before_days: Option<f64>,
    before_days_text: Option<String>,
    vacuum: bool,
    yes: bool,
    duration: Option<String>,
}

/// An option of one parser, by its long name. Which of them take a value is the parser's.
struct Opt {
    name: &'static str,
}

const TOP_OPTS: &[Opt] = &[
    Opt { name: "--help" },
    Opt { name: "--db" },
    Opt { name: "--config" },
];

fn sub_opts(cmd: &str) -> &'static [Opt] {
    match cmd {
        "db-stats" => &[Opt { name: "--help" }, Opt { name: "--json" }],
        "db-prune" => &[
            Opt { name: "--help" },
            Opt {
                name: "--before-days",
            },
            Opt { name: "--vacuum" },
            Opt { name: "--yes" },
        ],
        "db-reset" => &[Opt { name: "--help" }, Opt { name: "--yes" }],
        _ => &[Opt { name: "--help" }],
    }
}

/// How `argparse` classifies one word.
enum Word<'a> {
    /// `--`
    Separator,
    /// A value or a command name
    Positional,
    /// A known option, with the value written after `=` if any
    Opt(&'static Opt, Option<&'a str>),
    /// Something that looks like an option and is not one
    Unknown,
}

/// `ArgumentParser._parse_optional`, Python 3.14.
fn classify<'a>(word: &'a str, opts: &'static [Opt]) -> Result<Word<'a>, Stop> {
    if word == "--" {
        return Ok(Word::Separator);
    }
    if !word.starts_with('-') || word == "-" {
        return Ok(Word::Positional);
    }
    if word == "-h" {
        return opt_named(opts, "--help").map(|o| Word::Opt(o, None));
    }
    if let Some(o) = opts.iter().find(|o| o.name == word) {
        return Ok(Word::Opt(o, None));
    }
    let (name, value) = match word.split_once('=') {
        Some((n, v)) => (n, Some(v)),
        None => (word, None),
    };
    if value.is_some() {
        if let Some(o) = opts.iter().find(|o| o.name == name) {
            return Ok(Word::Opt(o, value));
        }
    }
    if name.starts_with("--") {
        let matches: Vec<&'static Opt> = opts.iter().filter(|o| o.name.starts_with(name)).collect();
        match matches.as_slice() {
            [one] => return Ok(Word::Opt(one, value)),
            [] => {}
            many => {
                let names: Vec<&str> = many.iter().map(|o| o.name).collect();
                return Err(Stop::Usage(format!(
                    "ambiguous option: {name} could match {}",
                    names.join(", ")
                )));
            }
        }
    } else if let Some(rest) = word.strip_prefix("-h") {
        // -hX: -h with an explicit argument, which it does not take
        return Err(Stop::Usage(format!(
            "argument -h/--help: ignored explicit argument '{rest}'"
        )));
    }
    // `-\.?\d`: a negative number, and no option here looks like one
    let b = word.as_bytes();
    let digit_at = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    if digit_at(1) || (b.get(1) == Some(&b'.') && digit_at(2)) {
        return Ok(Word::Positional);
    }
    if word.contains(' ') {
        return Ok(Word::Positional);
    }
    Ok(Word::Unknown)
}

fn opt_named(opts: &'static [Opt], name: &str) -> Result<&'static Opt, Stop> {
    opts.iter()
        .find(|o| o.name == name)
        .ok_or_else(|| Stop::Raised(format!("no option {name}")))
}

/// The value of an option that takes one: after `=`, or the next word unless that word is an
/// option (`expected one argument`).
fn value_of<'a>(
    opt: &Opt,
    inline: Option<&'a str>,
    words: &'a [String],
    i: &mut usize,
    opts: &'static [Opt],
) -> Result<&'a str, Stop> {
    if let Some(v) = inline {
        return Ok(v);
    }
    let display = display_name(opt);
    let next = words.get(*i + 1).map(String::as_str);
    match next {
        Some(w) if matches!(classify(w, opts)?, Word::Positional) => {
            *i += 1;
            Ok(w)
        }
        _ => Err(Stop::Usage(format!(
            "argument {display}: expected one argument"
        ))),
    }
}

fn display_name(opt: &Opt) -> &'static str {
    if opt.name == "--help" {
        "-h/--help"
    } else {
        opt.name
    }
}

fn parse(args: &[String], lang: &str) -> Result<Parsed, Stop> {
    let mut p = Parsed::default();
    let mut unknown: Vec<String> = Vec::new();
    let mut i = 0;
    let mut only_positional = false;
    // `maint`'s own options, up to the command name
    while i < args.len() {
        let w = args.get(i).map(String::as_str).unwrap_or_default();
        let word = if only_positional {
            Word::Positional
        } else {
            classify(w, TOP_OPTS)?
        };
        match word {
            Word::Separator => only_positional = true,
            Word::Unknown => unknown.push(w.to_string()),
            Word::Opt(o, inline) => match o.name {
                "--help" => return Err(Stop::Help(top_help(lang))),
                "--db" => p.db = Some(value_of(o, inline, args, &mut i, TOP_OPTS)?.to_string()),
                _ => p.config = Some(PathBuf::from(value_of(o, inline, args, &mut i, TOP_OPTS)?)),
            },
            Word::Positional => {
                if !COMMANDS.contains(&w) {
                    let choices: Vec<String> = COMMANDS.iter().map(|c| format!("'{c}'")).collect();
                    return Err(Stop::Usage(format!(
                        "argument cmd: invalid choice: '{w}' (choose from {})",
                        choices.join(", ")
                    )));
                }
                p.cmd = w.to_string();
                i += 1;
                break;
            }
        }
        i += 1;
    }
    if p.cmd.is_empty() {
        return Err(Stop::Usage(
            "the following arguments are required: cmd".into(),
        ));
    }
    // the command's own
    let opts = sub_opts(&p.cmd);
    let mut positionals: Vec<String> = Vec::new();
    let mut only_positional = false;
    while i < args.len() {
        let w = args.get(i).map(String::as_str).unwrap_or_default();
        let word = if only_positional {
            Word::Positional
        } else {
            classify(w, opts)?
        };
        match word {
            // a command without positionals leaves `--` and what follows it unrecognized
            Word::Separator if p.cmd != "reload-follow" => {
                unknown.extend(args.get(i..).unwrap_or_default().iter().cloned());
                break;
            }
            Word::Separator => only_positional = true,
            Word::Unknown => unknown.push(w.to_string()),
            Word::Positional => positionals.push(w.to_string()),
            Word::Opt(o, inline) => match o.name {
                "--help" => return Err(Stop::Help(sub_help(&p.cmd, lang))),
                "--json" => p.json = true,
                "--vacuum" => p.vacuum = true,
                "--yes" => p.yes = true,
                _ => {
                    let v = value_of(o, inline, args, &mut i, opts)?;
                    let f = pyfmt::float(v).ok_or_else(|| {
                        Stop::Usage(format!(
                            "argument --before-days: invalid float value: '{v}'"
                        ))
                    })?;
                    p.before_days = Some(f);
                    p.before_days_text = Some(v.to_string());
                }
            },
        }
        i += 1;
    }
    if p.cmd == "reload-follow" {
        let mut rest = positionals.into_iter();
        p.duration = Some(rest.next().unwrap_or_else(|| "30m".into()));
        unknown.extend(rest);
    } else {
        unknown.extend(positionals);
    }
    if p.cmd == "db-prune" && p.before_days.is_none() {
        return Err(Stop::Usage(
            "the following arguments are required: --before-days".into(),
        ));
    }
    if !unknown.is_empty() {
        return Err(Stop::Usage(format!(
            "unrecognized arguments: {}",
            unknown.join(" ")
        )));
    }
    Ok(p)
}

fn usage_line(cmd: Option<&str>) -> String {
    match cmd {
        None => format!(
            "usage: {PROG} [-h] [--db DB] [--config CONFIG] {{{}}} ...",
            COMMANDS.join(",")
        ),
        Some(c) => format!("usage: {PROG} {c} {}", sub_usage(c)),
    }
}

fn sub_usage(cmd: &str) -> &'static str {
    match cmd {
        "db-stats" => "[-h] [--json]",
        "db-prune" => "[-h] --before-days BEFORE_DAYS [--vacuum] [--yes]",
        "db-reset" => "[-h] [--yes]",
        "reload-follow" => "[-h] [duration]",
        _ => "[-h]",
    }
}

fn cmd_help_key(cmd: &str) -> &'static str {
    match cmd {
        "db-stats" => "maint.stats",
        "db-prune" => "maint.prune",
        "db-reset" => "maint.reset",
        "db-vacuum" => "maint.vacuum",
        "reload-follow" => "maint.reload_follow",
        "reload-freeze" => "maint.reload_freeze",
        _ => "maint.reload_status",
    }
}

fn row(left: &str, help: &str) -> String {
    if left.chars().count() <= 20 {
        format!("  {left:<22}{help}\n")
    } else {
        format!("  {left}\n{:24}{help}\n", "")
    }
}

fn top_help(lang: &str) -> String {
    let tr = |k: &str| t_in(lang, k);
    let mut s = format!("{}\n\n{}\n\n", usage_line(None), tr("maint.description"));
    s.push_str("commands:\n");
    for c in COMMANDS {
        s.push_str(&row(c, &tr(cmd_help_key(c))));
    }
    s.push_str("\noptions:\n");
    s.push_str(&row("-h, --help", &tr("maint.help")));
    s.push_str(&row("--db DB", &tr("maint.db")));
    s.push_str(&row("--config CONFIG", &tr("maint.config")));
    s
}

fn sub_help(cmd: &str, lang: &str) -> String {
    let tr = |k: &str| t_in(lang, k);
    let mut s = format!("{}\n\n{}\n\n", usage_line(Some(cmd)), tr(cmd_help_key(cmd)));
    if cmd == "reload-follow" {
        s.push_str("positional arguments:\n");
        s.push_str(&row("duration", &tr("maint.reload_duration")));
        s.push('\n');
    }
    s.push_str("options:\n");
    s.push_str(&row("-h, --help", &tr("maint.help")));
    match cmd {
        "db-stats" => s.push_str(&row("--json", &tr("maint.json"))),
        "db-prune" => {
            s.push_str(&row("--before-days BEFORE_DAYS", &tr("maint.before_days")));
            s.push_str(&row("--vacuum", &tr("maint.vacuum_opt")));
            s.push_str(&row("--yes", &tr("maint.yes")));
        }
        "db-reset" => s.push_str(&row("--yes", &tr("maint.yes"))),
        _ => {}
    }
    s
}

// ---------------------------------------------------------------------------------------------
// The reload window

fn reload_cmd(
    p: &Parsed,
    config: &Path,
    state: &Path,
    tr: &dyn Fn(&str) -> String,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<i32, Stop> {
    let cfg = crate::settings::load(config).map_err(|e| Stop::Raised(e.to_string()))?;
    let mode = if cfg.reload_is_windowed() {
        "windowed"
    } else {
        cfg.reload.as_str()
    };
    let mut window = ReloadWindow::new(mode, cfg.reload_window_seconds(), state)?;
    flush(&mut window, out);
    match p.cmd.as_str() {
        "reload-status" => {
            let line = window.describe()?;
            let _ = writeln!(out, "reload: {line}");
            Ok(0)
        }
        "reload-freeze" => {
            let ok = window.freeze();
            flush(&mut window, out);
            if !ok {
                let _ = writeln!(err, "{}", tr("maint.reload_write_failed"));
                return Ok(1);
            }
            let _ = writeln!(out, "{}", tr("maint.reload_frozen"));
            Ok(0)
        }
        _ => {
            let duration = p.duration.clone().unwrap_or_default();
            let Some(seconds) = crate::settings::parse_duration(&duration) else {
                let _ = writeln!(
                    err,
                    "{}",
                    tr("maint.reload_bad_duration").replace("{value}", &duration)
                );
                return Ok(2);
            };
            let ok = window.follow(seconds);
            flush(&mut window, out);
            if !ok {
                let _ = writeln!(err, "{}", tr("maint.reload_write_failed"));
                return Ok(1);
            }
            let _ = writeln!(
                out,
                "{}",
                tr("maint.reload_following").replace("{duration}", &duration)
            );
            Ok(0)
        }
    }
}

/// What the window logged, on stdout where structlog printed it.
fn flush(w: &mut ReloadWindow, out: &mut dyn Write) {
    for m in w.logged.drain(..) {
        log_line(out, &m);
    }
}

// ---------------------------------------------------------------------------------------------
// The log database

/// `default_db_path`: `database_path` from `config.yml` when it is a non-empty string, read with
/// nothing but the YAML loader; anything else is the default.
pub fn default_db_path(config: &Path) -> String {
    const DEFAULT: &str = "/data/security_gateway.db";
    let Ok(bytes) = std::fs::read(config) else {
        return DEFAULT.into();
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return DEFAULT.into();
    };
    match yaml11::safe_load(&text) {
        Ok(PyValue::Dict(items)) => items
            .iter()
            .find(|(k, _)| matches!(k, PyValue::Str(s) if s == "database_path"))
            .and_then(|(_, v)| match v {
                PyValue::Str(s) if !s.is_empty() => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_else(|| DEFAULT.into()),
        _ => DEFAULT.into(),
    }
}

/// `sqlite3.connect(path, timeout=30)` and `PRAGMA busy_timeout=30000`.
fn connect(path: &str) -> Result<Connection, Stop> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(30))?;
    Ok(conn)
}

fn existing_tables(conn: &Connection, names: &[&'static str]) -> Result<Vec<&'static str>, Stop> {
    let mut st = conn.prepare("SELECT name FROM sqlite_master WHERE type='table'")?;
    let have: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<_, _>>()?;
    Ok(names
        .iter()
        .copied()
        .filter(|n| have.iter().any(|h| h == n))
        .collect())
}

/// A value as Python's `sqlite3` returned it.
#[derive(Debug, Clone, PartialEq)]
enum Val {
    Null,
    Int(i64),
    Float(f64),
    Text(String),
    Blob,
}

fn val(v: ValueRef<'_>) -> Val {
    match v {
        ValueRef::Null => Val::Null,
        ValueRef::Integer(i) => Val::Int(i),
        ValueRef::Real(f) => Val::Float(f),
        ValueRef::Text(t) => Val::Text(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(_) => Val::Blob,
    }
}

struct TableInfo {
    rows: i64,
    /// For the log tables: oldest, newest, sorted index names
    range: Option<(Val, Val, Vec<String>)>,
}

struct Stats {
    db_path: String,
    exists: bool,
    size_bytes: u64,
    wal_bytes: u64,
    journal_mode: String,
    page_size: i64,
    freelist_pages: i64,
    tables: Vec<(&'static str, TableInfo)>,
}

/// `stats`.
fn stats(db_path: &str) -> Result<Stats, Stop> {
    let mut s = Stats {
        db_path: db_path.to_string(),
        exists: Path::new(db_path).exists(),
        size_bytes: 0,
        wal_bytes: 0,
        journal_mode: String::new(),
        page_size: 0,
        freelist_pages: 0,
        tables: Vec::new(),
    };
    if !s.exists {
        return Ok(s);
    }
    s.size_bytes = std::fs::metadata(db_path)?.len();
    s.wal_bytes = std::fs::metadata(format!("{db_path}-wal")).map_or(0, |m| m.len());
    let conn = connect(db_path)?;
    s.journal_mode = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    s.page_size = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    s.freelist_pages = conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
    let all: Vec<&'static str> = LOG_TABLES
        .iter()
        .chain(RESET_ONLY_TABLES)
        .copied()
        .collect();
    for table in existing_tables(&conn, &all)? {
        let rows: i64 =
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
        let range = if LOG_TABLES.contains(&table) {
            let (oldest, newest) = conn.query_row(
                &format!("SELECT MIN(timestamp), MAX(timestamp) FROM {table}"),
                [],
                |r| Ok((val(r.get_ref(0)?), val(r.get_ref(1)?))),
            )?;
            let mut st = conn.prepare(&format!("PRAGMA index_list({table})"))?;
            let mut idx: Vec<String> = st
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<Result<_, _>>()?;
            idx.sort();
            Some((oldest, newest, idx))
        } else {
            None
        };
        s.tables.push((table, TableInfo { rows, range }));
    }
    Ok(s)
}

fn val_json(v: &Val) -> Result<Json, Stop> {
    Ok(match v {
        Val::Null => Json::Null,
        Val::Int(i) => Json::Int(*i),
        Val::Float(f) => Json::Float(*f),
        Val::Text(t) => Json::Str(t.clone()),
        Val::Blob => {
            return Err(Stop::Raised(
                "Object of type bytes is not JSON serializable".into(),
            ))
        }
    })
}

fn stats_json(s: &Stats) -> Result<Json, Stop> {
    let mut tables = Vec::new();
    for (name, info) in &s.tables {
        let mut fields = vec![("rows".to_string(), Json::Int(info.rows))];
        if let Some((oldest, newest, idx)) = &info.range {
            fields.push(("oldest".into(), val_json(oldest)?));
            fields.push(("newest".into(), val_json(newest)?));
            fields.push((
                "indexes".into(),
                Json::Arr(idx.iter().map(|i| Json::Str(i.clone())).collect()),
            ));
        }
        tables.push((name.to_string(), Json::Obj(fields)));
    }
    let mut fields = vec![
        ("db_path".to_string(), Json::Str(s.db_path.clone())),
        ("exists".into(), Json::Bool(s.exists)),
        ("tables".into(), Json::Obj(tables)),
    ];
    if s.exists {
        fields.push(("size_bytes".into(), Json::Int(s.size_bytes as i64)));
        fields.push(("wal_bytes".into(), Json::Int(s.wal_bytes as i64)));
        fields.push(("journal_mode".into(), Json::Str(s.journal_mode.clone())));
        fields.push(("page_size".into(), Json::Int(s.page_size)));
        fields.push(("freelist_pages".into(), Json::Int(s.freelist_pages)));
    }
    Ok(Json::Obj(fields))
}

/// `_fmt_ts`.
fn fmt_ts(v: &Val) -> Result<String, Stop> {
    match v {
        Val::Null => Ok("-".into()),
        Val::Int(i) => pyfmt::timestamp(Num::Int(*i)).map_err(Stop::Raised),
        Val::Float(f) => pyfmt::timestamp(Num::Float(*f)).map_err(Stop::Raised),
        Val::Text(_) => Err(Stop::Raised(
            "'str' object cannot be interpreted as an integer".into(),
        )),
        Val::Blob => Err(Stop::Raised(
            "'bytes' object cannot be interpreted as an integer".into(),
        )),
    }
}

/// `_print_stats`. Every line is built before any is printed only where Python would have
/// raised part-way; the lines before the failing one are printed, as Python printed them.
fn print_stats(s: &Stats, tr: &dyn Fn(&str) -> String, out: &mut dyn Write) -> Result<(), Stop> {
    let _ = writeln!(out, "{:<15}{}", tr("maint.stats.db"), s.db_path);
    if !s.exists {
        let _ = writeln!(out, "{:<15}{}", "", tr("maint.stats.not_found"));
        return Ok(());
    }
    let _ = writeln!(
        out,
        "{:<15}{} (+ wal {})",
        tr("maint.stats.size"),
        pyfmt::bytes(s.size_bytes),
        pyfmt::bytes(s.wal_bytes)
    );
    let _ = writeln!(
        out,
        "{:<15}{}   {} {} x {} B",
        tr("maint.stats.journal"),
        s.journal_mode,
        tr("maint.stats.free_pages"),
        s.freelist_pages,
        s.page_size
    );
    let _ = writeln!(out, "{}", tr("maint.stats.tables"));
    for (table, info) in &s.tables {
        let mut line = format!("  {table:<18} {:>10} {}", info.rows, tr("maint.stats.rows"));
        if let Some((oldest, newest, idx)) = &info.range {
            line.push_str(&format!("   {} .. {}", fmt_ts(oldest)?, fmt_ts(newest)?));
            let joined = idx.join(", ");
            line.push_str(&format!(
                "   {} {}",
                tr("maint.stats.indexes"),
                if joined.is_empty() { "-" } else { &joined }
            ));
        }
        let _ = writeln!(out, "{line}");
    }
    Ok(())
}

fn size(path: &str) -> Result<u64, Stop> {
    Ok(std::fs::metadata(path)?.len())
}

fn deleted_line(tr: &dyn Fn(&str) -> String, table: &str, n: usize) -> String {
    tr("maint.deleted")
        .replace("{table}", &format!("{table:<18}"))
        .replace("{n}", &n.to_string())
}

fn db_cmd(
    p: &Parsed,
    config: &Path,
    tr: &dyn Fn(&str) -> String,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<i32, Stop> {
    let db = p.db.clone().unwrap_or_else(|| default_db_path(config));
    if p.cmd == "db-stats" {
        let s = stats(&db)?;
        if p.json {
            let text = pyfmt::dumps_indent(&stats_json(&s)?);
            let _ = writeln!(out, "{text}");
        } else {
            print_stats(&s, tr, out)?;
        }
        return Ok(0);
    }
    if !Path::new(&db).exists() {
        let _ = writeln!(err, "{}", tr("maint.not_found").replace("{db}", &db));
        return Ok(1);
    }
    if (p.cmd == "db-prune" || p.cmd == "db-reset") && !p.yes {
        let what = if p.cmd == "db-prune" {
            tr("maint.confirm_prune_what")
                .replace("{days}", &pyfmt::g(p.before_days.unwrap_or_default()))
        } else {
            tr("maint.confirm_reset_what")
        };
        let _ = writeln!(
            out,
            "{}",
            tr("maint.confirm")
                .replace("{what}", &what)
                .replace("{db}", &db)
        );
        let _ = writeln!(out, "{}", tr("maint.rerun"));
        return Ok(2);
    }
    match p.cmd.as_str() {
        "db-prune" => {
            let days = p.before_days.unwrap_or_default();
            // ValueError before anything is opened
            if days <= 0.0 {
                return Err(Stop::Raised("--before-days must be positive".into()));
            }
            let cutoff = now() - days * 86400.0;
            let mut deleted = Vec::new();
            {
                let mut conn = connect(&db)?;
                let tables = existing_tables(&conn, LOG_TABLES)?;
                let tx = conn.transaction()?;
                for table in tables {
                    let n = tx.execute(
                        &format!("DELETE FROM {table} WHERE timestamp < ?"),
                        [cutoff],
                    )?;
                    deleted.push((table, n));
                }
                tx.commit()?;
                if p.vacuum {
                    conn.execute_batch("VACUUM")?;
                }
            }
            for (table, n) in deleted {
                let _ = writeln!(out, "{}", deleted_line(tr, table, n));
            }
            let _ = writeln!(
                out,
                "{}",
                tr(if p.vacuum {
                    "maint.vacuumed"
                } else {
                    "maint.not_vacuumed"
                })
            );
            Ok(0)
        }
        "db-reset" => {
            let mut deleted = Vec::new();
            {
                let mut conn = connect(&db)?;
                let all: Vec<&'static str> = LOG_TABLES
                    .iter()
                    .chain(RESET_ONLY_TABLES)
                    .copied()
                    .collect();
                let tables = existing_tables(&conn, &all)?;
                let tx = conn.transaction()?;
                for table in tables {
                    let n = tx.execute(&format!("DELETE FROM {table}"), [])?;
                    deleted.push((table, n));
                }
                tx.commit()?;
                conn.execute_batch("VACUUM")?;
            }
            for (table, n) in deleted {
                let _ = writeln!(out, "{}", deleted_line(tr, table, n));
            }
            let _ = writeln!(
                out,
                "{}",
                tr("maint.reset_done")
                    .replace("{db}", &db)
                    .replace("{size}", &pyfmt::bytes(size(&db)?))
            );
            Ok(0)
        }
        _ => {
            let before = size(&db)?;
            {
                let conn = connect(&db)?;
                conn.execute_batch("VACUUM")?;
            }
            let after = size(&db)?;
            let _ = writeln!(
                out,
                "{}",
                tr("maint.vacuum_result")
                    .replace("{before}", &pyfmt::bytes(before))
                    .replace("{after}", &pyfmt::bytes(after))
            );
            Ok(0)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn make_db(path: &Path, rows: usize, age_days: f64) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE dns_queries (timestamp REAL, client_ip TEXT, query_domain TEXT, response_ips TEXT, ttl INTEGER, query_type TEXT, status TEXT);
             CREATE INDEX idx_dns_timestamp ON dns_queries(timestamp);
             CREATE TABLE firewall_blocks (timestamp REAL, src_ip TEXT, dst_ip TEXT, dst_port INTEGER, protocol TEXT, action TEXT);
             CREATE TABLE proxy_logs (timestamp REAL, client_ip TEXT, method TEXT, url TEXT, status_code INTEGER, squid_result TEXT, action TEXT);
             CREATE TABLE cache_stats (hits INTEGER, misses INTEGER);",
        )
        .unwrap();
        let base = now() - age_days * 86400.0;
        for i in 0..rows {
            let ts = base + i as f64;
            conn.execute("INSERT INTO dns_queries VALUES (?, '10.0.0.2', 'example.com', '1.2.3.4', 60, 'A', 'allowed')", [ts]).unwrap();
            conn.execute("INSERT INTO firewall_blocks VALUES (?, '10.0.0.2', '9.9.9.9', 22, 'TCP', 'blocked')", [ts]).unwrap();
            conn.execute("INSERT INTO proxy_logs VALUES (?, '10.0.0.2', 'GET', 'https://x/', 200, 'TCP_MISS', 'allowed')", [ts]).unwrap();
        }
        conn.execute("INSERT INTO cache_stats VALUES (1, 2)", [])
            .unwrap();
    }

    fn maint(args: &[&str]) -> (i32, String, String) {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(
            &args,
            Path::new("/nonexistent/config.yml"),
            Path::new("/nonexistent/reload-window.json"),
            "en",
            &mut out,
            &mut err,
        );
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn rows(db: &Path, table: &str) -> i64 {
        Connection::open(db)
            .unwrap()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    /// test_maint.py `it_reports_rows_range_indexes_and_size`, `it_prints_and_returns_zero`
    #[test]
    fn stats_report_rows_range_indexes_and_size() {
        let d = tempfile::tempdir().unwrap();
        let db = d.path().join("gw.db");
        make_db(&db, 3, 0.0);
        let s = stats(db.to_str().unwrap()).unwrap();
        assert!(s.exists && s.size_bytes > 0);
        assert_eq!(s.tables[0].0, "dns_queries");
        assert_eq!(s.tables[0].1.rows, 3);
        let (oldest, newest, idx) = s.tables[0].1.range.as_ref().unwrap();
        assert!(matches!((oldest, newest), (Val::Float(a), Val::Float(b)) if a <= b));
        assert_eq!(idx, &["idx_dns_timestamp"]);
        assert_eq!(s.tables[3].0, "cache_stats");
        assert!(s.tables[3].1.range.is_none());
        assert!(s.journal_mode == "delete" || s.journal_mode == "wal");

        let (code, out, _) = maint(&["--db", db.to_str().unwrap(), "db-stats"]);
        assert_eq!(code, 0);
        assert!(
            out.contains("dns_queries") && out.contains("3 rows"),
            "{out}"
        );
        assert!(
            out.starts_with(&format!("db:            {}\n", db.display())),
            "{out}"
        );
        let (code, out, _) = maint(&["--db", db.to_str().unwrap(), "db-stats", "--json"]);
        assert_eq!(code, 0);
        assert!(out.contains("\"rows\": 3"), "{out}");
        assert!(
            out.contains("\"cache_stats\": {\n      \"rows\": 1\n    }"),
            "{out}"
        );
    }

    /// test_maint.py `it_handles_a_missing_file`; test_i18n.py `describe_maint_language`
    #[test]
    fn a_missing_database_is_reported_in_the_language_asked_for() {
        let d = tempfile::tempdir().unwrap();
        let db = d.path().join("none.db");
        let db = db.to_str().unwrap();
        let (code, out, _) = maint(&["--db", db, "db-stats"]);
        assert_eq!(
            (code, out.as_str()),
            (
                0,
                format!("db:            {db}\n               (not found)\n").as_str()
            )
        );
        let (code, out, _) = maint(&["--db", db, "db-stats", "--json"]);
        assert_eq!(code, 0);
        assert_eq!(
            out,
            format!("{{\n  \"db_path\": \"{db}\",\n  \"exists\": false,\n  \"tables\": {{}}\n}}\n")
        );
        let args: Vec<String> = ["--db", db, "db-stats"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        run(
            &args,
            Path::new("/x"),
            Path::new("/x"),
            "ja",
            &mut out,
            &mut err,
        );
        assert!(String::from_utf8(out).unwrap().contains("(見つかりません)"));
        let args: Vec<String> = ["--db", db, "db-reset", "--yes"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            run(
                &args,
                Path::new("/x"),
                Path::new("/x"),
                "ja",
                &mut out,
                &mut err
            ),
            1
        );
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("DB が見つかりません"));
        // test_maint.py `it_fails_cleanly_when_the_db_is_missing`
        assert_eq!(maint(&["--db", db, "db-reset", "--yes"]).0, 1);
    }

    /// test_maint.py `it_prunes_only_old_records_and_keeps_tables`
    #[test]
    fn prune_deletes_only_old_records() {
        let d = tempfile::tempdir().unwrap();
        let db = d.path().join("gw.db");
        make_db(&db, 4, 100.0);
        Connection::open(&db)
            .unwrap()
            .execute("INSERT INTO dns_queries VALUES (?, '10.0.0.3', 'new.example', '', 60, 'A', 'allowed')", [now()])
            .unwrap();
        let (code, out, _) = maint(&[
            "--db",
            db.to_str().unwrap(),
            "db-prune",
            "--before-days",
            "30",
            "--yes",
            "--vacuum",
        ]);
        assert_eq!(code, 0);
        assert_eq!(
            out,
            "dns_queries        deleted 4 rows\nfirewall_blocks    deleted 4 rows\nproxy_logs         deleted 4 rows\nvacuumed\n"
        );
        assert_eq!(rows(&db, "dns_queries"), 1);
        assert_eq!(rows(&db, "cache_stats"), 1);
    }

    /// test_maint.py `it_requires_yes_for_destructive_commands`
    #[test]
    fn destructive_commands_want_yes() {
        let d = tempfile::tempdir().unwrap();
        let db = d.path().join("gw.db");
        make_db(&db, 1, 0.0);
        let db_s = db.to_str().unwrap();
        let (code, out, _) = maint(&["--db", db_s, "db-prune", "--before-d", "1.50"]);
        assert_eq!(code, 2);
        assert_eq!(
            out,
            format!("This deletes records older than 1.5 days from {db_s} (DNS / firewall / proxy logs; the relay audit is separate).\nRe-run with --yes to proceed.\n")
        );
        assert_eq!(maint(&["--db", db_s, "db-reset"]).0, 2);
        assert_eq!(rows(&db, "dns_queries"), 1);
        // a negative number is a value; the check comes after the confirmation
        assert_eq!(
            maint(&["--db", db_s, "db-prune", "--before-days", "-1"]).0,
            2
        );
        let (code, _, err) = maint(&["--db", db_s, "db-prune", "--before-days", "-1", "--yes"]);
        assert_eq!(code, 1);
        assert!(err.contains("--before-days must be positive"), "{err}");
    }

    /// test_maint.py `it_resets_everything_and_vacuums`
    #[test]
    fn reset_deletes_everything_and_keeps_the_tables() {
        let d = tempfile::tempdir().unwrap();
        let db = d.path().join("gw.db");
        make_db(&db, 50, 0.0);
        let (code, out, _) = maint(&["--db", db.to_str().unwrap(), "db-reset", "--yes"]);
        assert_eq!(code, 0);
        assert!(out.contains("dns_queries        deleted 50 rows"), "{out}");
        assert!(out.contains("cache_stats        deleted 1 rows"), "{out}");
        assert!(
            out.contains(&format!("vacuumed; {} is now ", db.display())),
            "{out}"
        );
        let s = stats(db.to_str().unwrap()).unwrap();
        assert!(s.tables.iter().all(|(_, i)| i.rows == 0));
        assert_eq!(
            s.tables[0].1.range.as_ref().unwrap().2,
            ["idx_dns_timestamp"]
        );
        let (code, out, _) = maint(&["--db", db.to_str().unwrap(), "db-vacuum"]);
        assert_eq!(code, 0);
        assert!(
            out.starts_with("vacuumed: ") && out.contains(" -> "),
            "{out}"
        );
    }

    /// test_maint.py `it_reads_the_db_path_from_config`
    #[test]
    fn the_database_path_comes_from_the_config() {
        let d = tempfile::tempdir().unwrap();
        let cfg = d.path().join("config.yml");
        std::fs::write(&cfg, "database_path: /tmp/x/gw.db\n").unwrap();
        assert_eq!(default_db_path(&cfg), "/tmp/x/gw.db");
        assert_eq!(
            default_db_path(&d.path().join("missing.yml")),
            "/data/security_gateway.db"
        );
        for bad in [
            "database_path: ''\n",
            "database_path: 3\n",
            "- a\n",
            ": : :\n",
        ] {
            std::fs::write(&cfg, bad).unwrap();
            assert_eq!(default_db_path(&cfg), "/data/security_gateway.db", "{bad}");
        }
    }

    #[test]
    fn the_words_after_maint_are_taken_as_typed() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            raw_args(&v(&["sekimore-relay", "maint", "-v", "db-stats"])),
            Some(v(&["-v", "db-stats"]))
        );
        assert_eq!(
            raw_args(&v(&[
                "x",
                "--config",
                "/c",
                "-vv",
                "--config=/d",
                "maint",
                "--config",
                "/e"
            ])),
            Some(v(&["--config", "/e"]))
        );
        assert_eq!(raw_args(&v(&["x", "--other", "maint"])), None);
        assert_eq!(raw_args(&v(&["x", "maint"])), Some(vec![]));
    }

    #[test]
    fn the_command_line_is_read_as_argparse_read_it() {
        assert_eq!(maint(&[]).0, 2);
        assert_eq!(maint(&["nope"]).0, 2);
        assert_eq!(maint(&["db-stats", "--db", "/x"]).0, 2);
        assert_eq!(maint(&["db-prune", "--yes"]).0, 2);
        assert_eq!(maint(&["db-prune", "--before-days", "x"]).0, 2);
        assert_eq!(maint(&["db-prune", "--before-days"]).0, 2);
        assert_eq!(maint(&["db-prune", "--before-days", "--yes"]).0, 2);
        assert_eq!(maint(&["reload-status", "extra"]).0, 2);
        assert_eq!(maint(&["reload-follow", "1m", "2m"]).0, 2);
        assert_eq!(maint(&["--d"]).0, 2);
        let (code, out, _) = maint(&["--help"]);
        assert_eq!(code, 0);
        assert!(out.starts_with("usage: sekimore-relay maint"), "{out}");
        assert_eq!(maint(&["db-prune", "-h"]).0, 0);
        // a unique prefix is the option
        let p = parse(
            &["--d=/a".into(), "--con".into(), "/c".into(), "db-st".into()],
            "en",
        );
        assert!(p.is_err());
        let p = parse(
            &[
                "--d=/a".into(),
                "--con".into(),
                "/c".into(),
                "db-stats".into(),
                "--j".into(),
            ],
            "en",
        )
        .ok()
        .unwrap();
        assert_eq!(
            (p.db.as_deref(), p.config.as_deref(), p.json),
            (Some("/a"), Some(Path::new("/c")), true)
        );
        // -- makes the rest positional; a word that starts like a negative number is one
        let p = parse(&["reload-follow".into(), "-5m".into()], "en")
            .ok()
            .unwrap();
        assert_eq!(p.duration.as_deref(), Some("-5m"));
        let p = parse(&["reload-follow".into(), "--".into(), "-x".into()], "en")
            .ok()
            .unwrap();
        assert_eq!(p.duration.as_deref(), Some("-x"));
        let p = parse(&["reload-follow".into()], "en").ok().unwrap();
        assert_eq!(p.duration.as_deref(), Some("30m"));
        // `--` once in reload-follow; anywhere else it and the rest are unrecognized
        let p = parse(&["reload-follow".into(), "--".into(), "--".into()], "en")
            .ok()
            .unwrap();
        assert_eq!(p.duration.as_deref(), Some("--"));
        assert_eq!(maint(&["db-stats", "--", "--json"]).0, 2);
        assert_eq!(maint(&["--db", "/nonexistent/x", "--", "db-stats"]).0, 0);
    }

    #[test]
    fn the_reload_commands_answer_as_python_did() {
        let d = tempfile::tempdir().unwrap();
        let cfg = d.path().join("config.yml");
        std::fs::write(&cfg, "reload: manual\n").unwrap();
        let state = d.path().join("state/reload-window.json");
        let run_ = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = run(&args, &cfg, &state, "en", &mut out, &mut err);
            (
                code,
                String::from_utf8(out).unwrap(),
                String::from_utf8(err).unwrap(),
            )
        };
        assert_eq!(
            run_(&["reload-status"]),
            (
                0,
                "reload: manual (does not apply on save)\n".into(),
                String::new()
            )
        );
        assert_eq!(
            run_(&["reload-follow", "10m"]),
            (
                0,
                "reload window open for 10m. Saving config.yml applies until it runs out.\n".into(),
                String::new()
            )
        );
        assert!(run_(&["reload-status"])
            .1
            .starts_with("reload: open for 9m 5"));
        assert_eq!(
            run_(&["reload-follow", "soon"]),
            (
                2,
                String::new(),
                "not a duration: soon. Use something like 30m, 2h, 90s.\n".into()
            )
        );
        assert_eq!(
            run_(&["reload-freeze"]),
            (
                0,
                "reload window closed. Saving config.yml no longer applies.\n".into(),
                String::new()
            )
        );
        assert_eq!(
            std::fs::read_to_string(&state).unwrap(),
            "{\"frozen\": true}"
        );
        assert_eq!(
            run_(&["reload-status"]).1,
            "reload: frozen (does not apply on save; reload-follow to reopen)\n"
        );
        // a state that cannot be written: a failure, on stderr, with the log line on stdout
        std::fs::remove_file(&state).unwrap();
        std::fs::create_dir(d.path().join("state/reload-window.tmp")).unwrap();
        let (code, out, err) = run_(&["reload-freeze"]);
        assert_eq!(code, 1);
        assert!(
            out.contains("[error    ] Cannot record the reload window: "),
            "{out}"
        );
        assert_eq!(
            err,
            "could not record the reload window; it is unchanged. Check the log for the reason.\n"
        );
        // a config the gateway refuses: Python raised
        std::fs::write(&cfg, "reload: sometimes\n").unwrap();
        let (code, _, err) = run_(&["reload-status"]);
        assert_eq!(code, 1);
        assert!(err.starts_with("sekimore-relay maint: failed: "), "{err}");
    }
}
