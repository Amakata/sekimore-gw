//! The endpoints over the log database and the domain lists: `/api/stats`, `/api/cache-stats`,
//! `/api/logs`, `/api/firewall-blocks`, `/api/proxy-logs`, `/api/proxy-blocks`, `/api/blocked-ips`
//! and `/api/domains/*`. Each is the Python handler of the same name (`src/web_ui/app.py`, removed
//! in 0.3.0-alpha.4), query for query and field for field.

use std::collections::BTreeSet;

use super::cfg::{self, Py, Raised};
use super::db::{limit_param, Db, Row, SqlVal};
use super::json::{obj, Json};
use super::UiView;
use crate::settings::py;
use crate::settings::yaml11::PyValue;

/// `LogEntry`, in its field order.
#[allow(clippy::too_many_arguments)]
fn log_entry(
    timestamp: f64,
    component: &str,
    action: &str,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    dst_port: Option<i128>,
    domain: Option<String>,
    reason: Option<String>,
) -> Json {
    obj([
        ("timestamp", Json::Float(timestamp)),
        ("component", Json::str(component)),
        ("action", Json::str(action)),
        ("src_ip", Json::opt_str(src_ip)),
        ("dst_ip", Json::opt_str(dst_ip)),
        ("dst_port", Json::opt_int(dst_port)),
        ("domain", Json::opt_str(domain)),
        ("reason", Json::opt_str(reason)),
    ])
}

/// `GET /api/stats`: the last 24 hours.
pub fn stats(view: &UiView, now: f64) -> Py<Json> {
    let db = Db::open(&view.db_path)?;
    let since = now - 86400.0;
    let count = |sql: &str| db.count(sql, &[&since]);
    let total = count("SELECT COUNT(*) FROM dns_queries WHERE timestamp > ?")?;
    let allowed =
        count("SELECT COUNT(*) FROM dns_queries WHERE timestamp > ? AND status = 'allowed'")?;
    let blocked =
        count("SELECT COUNT(*) FROM dns_queries WHERE timestamp > ? AND status = 'blocked'")?;
    let ignored =
        count("SELECT COUNT(*) FROM dns_queries WHERE timestamp > ? AND status = 'ignored'")?;
    let unique = count("SELECT COUNT(DISTINCT query_domain) FROM dns_queries WHERE timestamp > ?")?;
    let firewall = count("SELECT COUNT(*) FROM firewall_blocks WHERE timestamp > ?")?;
    let (mut proxy_allowed, mut proxy_blocked) = (0, 0);
    // a missing proxy_logs table (the proxy is off) is no error
    if let Ok(rows) = db.rows(
        "SELECT action, COUNT(*) FROM proxy_logs WHERE timestamp > ? GROUP BY action",
        &[&since],
    ) {
        for r in rows {
            let (Ok(action), Ok(n)) = (r.at(0), r.at(1).and_then(SqlVal::int)) else {
                continue;
            };
            if action.is_str("allowed") {
                proxy_allowed = n;
            } else if action.is_str("blocked") {
                proxy_blocked = n;
            }
        }
    }
    Ok(obj([
        ("total", Json::Int(total)),
        ("allowed", Json::Int(allowed)),
        ("blocked", Json::Int(blocked)),
        ("ignored", Json::Int(ignored)),
        ("unique_domains", Json::Int(unique)),
        ("firewall_blocked", Json::Int(firewall)),
        ("proxy_allowed", Json::Int(proxy_allowed)),
        ("proxy_blocked", Json::Int(proxy_blocked)),
    ]))
}

/// `GET /api/cache-stats`. Anything that goes wrong after the database opens reads as a disabled
/// cache, as the Python handler's `except Exception` had it.
pub fn cache_stats(view: &UiView) -> Py<Json> {
    let db = Db::open(&view.db_path)?;
    let enabled = (|| -> Py<Option<Json>> {
        let Some(r) = db.one(
            "SELECT size, hits, misses, hit_rate FROM cache_stats WHERE id = 1",
            &[],
        )?
        else {
            return Ok(None);
        };
        Ok(Some(obj([
            ("enabled", Json::Bool(true)),
            ("size", Json::Int(r.at(0)?.int()?)),
            ("hits", Json::Int(r.at(1)?.int()?)),
            ("misses", Json::Int(r.at(2)?.int()?)),
            ("hit_rate", Json::Float(r.at(3)?.float()?)),
        ])))
    })();
    Ok(match enabled {
        Ok(Some(j)) => j,
        _ => obj([
            ("enabled", Json::Bool(false)),
            ("size", Json::Int(0)),
            ("hits", Json::Int(0)),
            ("misses", Json::Int(0)),
            ("hit_rate", Json::Float(0.0)),
        ]),
    })
}

/// `GET /api/logs?limit=`: DNS, newest first, without the ignored names.
pub fn logs(view: &UiView, limit: i128) -> Py<Json> {
    let db = Db::open(&view.db_path)?;
    let rows = db.rows(
        "SELECT timestamp, client_ip, query_domain, response_ips, status FROM dns_queries \
         WHERE status != 'ignored' ORDER BY timestamp DESC LIMIT ?",
        &[&limit_param(limit)?],
    )?;
    rows.iter()
        .map(|r| {
            let action = match r.at(4)?.as_str() {
                Some("allowed") => "ALLOWED",
                Some("ignored") => "IGNORED",
                // `blocked`, and anything the map does not have
                _ => "BLOCKED",
            };
            Ok(log_entry(
                r.at(0)?.float()?,
                "DNS",
                action,
                r.at(1)?.opt_string()?,
                r.at(3)?.first_of_list()?,
                None,
                r.at(2)?.opt_string()?,
                None,
            ))
        })
        .collect::<Py<Vec<Json>>>()
        .map(Json::Arr)
}

/// The firewall row as the Python handler reshaped it (also the WebSocket's `_fw_entry`).
pub struct FwRow {
    pub src_ip: SqlVal,
    pub dst_ip: SqlVal,
    pub protocol: SqlVal,
    pub reason: String,
}

/// Under Docker the log details are sometimes missing ("counter mode"): `blocked` stands for an
/// unknown address and `IP` for an unknown protocol.
pub fn fw_row(src: &SqlVal, dst: &SqlVal, proto: &SqlVal) -> FwRow {
    let keep = |v: &SqlVal, placeholder: &str| {
        if v.truthy() && !v.is_str(placeholder) {
            v.clone()
        } else {
            SqlVal::Null
        }
    };
    let src_ip = keep(src, "blocked");
    let dst_ip = keep(dst, "blocked");
    let protocol = if proto.truthy() && !proto.is_str("IP") {
        proto.clone()
    } else {
        SqlVal::Text("IP".into())
    };
    let reason = if src_ip.truthy() && dst_ip.truthy() {
        format!("{} traffic blocked by firewall", protocol.py_str())
    } else {
        "Traffic blocked by firewall (counter-based detection)".to_string()
    };
    FwRow {
        src_ip,
        dst_ip,
        protocol,
        reason,
    }
}

/// `GET /api/firewall-blocks?limit=`.
pub fn firewall_blocks(view: &UiView, limit: i128) -> Py<Json> {
    let db = Db::open(&view.db_path)?;
    let rows = db.rows(
        "SELECT timestamp, src_ip, dst_ip, dst_port, protocol FROM firewall_blocks \
         ORDER BY timestamp DESC LIMIT ?",
        &[&limit_param(limit)?],
    )?;
    rows.iter()
        .map(|r| {
            let fw = fw_row(r.at(1)?, r.at(2)?, r.at(4)?);
            Ok(log_entry(
                r.at(0)?.float()?,
                "FIREWALL",
                "BLOCKED",
                fw.src_ip.opt_string()?,
                fw.dst_ip.opt_string()?,
                r.at(3)?.opt_int()?,
                None,
                Some(fw.reason),
            ))
        })
        .collect::<Py<Vec<Json>>>()
        .map(Json::Arr)
}

/// The reason of a proxy row: `<method> via proxy (<result>)` or
/// `<method> blocked by proxy (<result>/<status>)`.
pub fn proxy_reason(r: &Row, allowed: bool) -> Py<String> {
    Ok(if allowed {
        format!("{} via proxy ({})", r.at(2)?.py_str(), r.at(5)?.py_str())
    } else {
        format!(
            "{} blocked by proxy ({}/{})",
            r.at(2)?.py_str(),
            r.at(5)?.py_str(),
            r.at(4)?.py_str()
        )
    })
}

/// `GET /api/proxy-logs?limit=` and `GET /api/proxy-blocks?limit=` (the blocked rows only).
pub fn proxy_logs(view: &UiView, limit: i128, blocked_only: bool) -> Py<Json> {
    let db = Db::open(&view.db_path)?;
    let sql = if blocked_only {
        "SELECT timestamp, client_ip, method, url, status_code, squid_result, action FROM proxy_logs \
         WHERE action = 'blocked' ORDER BY timestamp DESC LIMIT ?"
    } else {
        "SELECT timestamp, client_ip, method, url, status_code, squid_result, action FROM proxy_logs \
         ORDER BY timestamp DESC LIMIT ?"
    };
    let rows = db.rows(sql, &[&limit_param(limit)?])?;
    rows.iter()
        .map(|r| {
            let allowed = !blocked_only && r.at(6)?.is_str("allowed");
            Ok(log_entry(
                r.at(0)?.float()?,
                "PROXY",
                if allowed { "ALLOWED" } else { "BLOCKED" },
                r.at(1)?.opt_string()?,
                None,
                None,
                r.at(3)?.opt_string()?,
                Some(proxy_reason(r, allowed)?),
            ))
        })
        .collect::<Py<Vec<Json>>>()
        .map(Json::Arr)
}

/// `GET /api/blocked-ips?limit=`.
pub fn blocked_ips(view: &UiView, limit: i128) -> Py<Json> {
    let db = Db::open(&view.db_path)?;
    let rows = db.rows(
        "SELECT dst_ip, COUNT(*) as block_count, MAX(timestamp) as last_blocked, \
         GROUP_CONCAT(DISTINCT dst_port) as ports, GROUP_CONCAT(DISTINCT protocol) as protocols \
         FROM firewall_blocks \
         WHERE dst_ip IS NOT NULL AND dst_ip != 'blocked' AND dst_ip != 'unknown' AND dst_ip != '' \
         GROUP BY dst_ip ORDER BY block_count DESC LIMIT ?",
        &[&limit_param(limit)?],
    )?;
    rows.iter()
        .map(|r| {
            let mut ports: BTreeSet<i128> = BTreeSet::new();
            let ports_v = r.at(3)?;
            if ports_v.truthy() {
                for p in comma_text(ports_v)?.split(',') {
                    let p = py::strip(p);
                    if !p.is_empty() && p != "None" {
                        if let Some(n) = py::int(p) {
                            ports.insert(n);
                        }
                    }
                }
            }
            let mut protocols: BTreeSet<String> = BTreeSet::new();
            let protos_v = r.at(4)?;
            if protos_v.truthy() {
                for p in comma_text(protos_v)?.split(',') {
                    let p = py::strip(p);
                    if !p.is_empty() && p != "unknown" && p != "IP" {
                        protocols.insert(p.to_string());
                    }
                }
            }
            Ok(obj([
                ("ip_address", Json::Str(r.at(0)?.string()?)),
                ("block_count", Json::Int(r.at(1)?.int()?)),
                ("last_blocked", Json::Float(r.at(2)?.float()?)),
                (
                    "ports",
                    Json::Arr(ports.into_iter().map(Json::Int).collect()),
                ),
                (
                    "protocols",
                    Json::strs(&protocols.into_iter().collect::<Vec<_>>()),
                ),
            ]))
        })
        .collect::<Py<Vec<Json>>>()
        .map(Json::Arr)
}

/// A `GROUP_CONCAT` result, which is text whenever it is not NULL.
fn comma_text(v: &SqlVal) -> Py<String> {
    match v {
        SqlVal::Text(s) => Ok(s.clone()),
        _ => Err(Raised("'.split' on a value that is not a string")),
    }
}

// ---- the domain lists ----------------------------------------------------------------------------

/// `GET /api/domains/allowed`, `/blocked` and `/ignored-config`: the list as `config.yml` has it.
/// Anything but a list of strings fails the response model (500).
pub fn config_list(view: &UiView, key: &str) -> Py<Json> {
    let config = cfg::load(&view.config_path);
    let v = cfg::get_or(&config, key, PyValue::List(vec![]))?;
    let PyValue::List(items) = v else {
        return Err(Raised("Input should be a valid list"));
    };
    items
        .into_iter()
        .map(|i| match i {
            PyValue::Str(s) => Ok(Json::Str(s)),
            _ => Err(Raised("Input should be a valid string")),
        })
        .collect::<Py<Vec<Json>>>()
        .map(Json::Arr)
}

/// The three lists `get_current_rule` walks, read up front as it read them.
pub struct RuleLists {
    allow: PyValue,
    block: PyValue,
    ignore: PyValue,
}

impl RuleLists {
    pub fn of(config: &PyValue) -> Py<RuleLists> {
        Ok(RuleLists {
            allow: cfg::get_or(config, "allow_domains", PyValue::List(vec![]))?,
            block: cfg::get_or(config, "block_domains", PyValue::List(vec![]))?,
            ignore: cfg::get_or(config, "ignore_domains", PyValue::List(vec![]))?,
        })
    }
}

/// One list's verdict: whether an entry matches, walking it in order. An entry that is not a
/// string raises when it is reached — after an earlier match has already returned.
fn list_matches(list: &PyValue, domain_lower: &str) -> Py<bool> {
    for entry in cfg::iter_items(list)? {
        let PyValue::Str(e) = entry else {
            return Err(Raised("'.startswith' on a value that is not a string"));
        };
        if e == domain_lower {
            return Ok(true);
        }
        // `.example.com` covers the name and its suffix — without a label boundary
        if let Some(bare) = e.strip_prefix('.') {
            if domain_lower.ends_with(e.as_str()) || domain_lower.ends_with(bare) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// `get_current_rule(domain, config)`: block, then ignore, then allow, then denied by default.
pub fn current_rule(domain: &SqlVal, lists: &RuleLists) -> Py<&'static str> {
    let Some(d) = domain.as_str() else {
        return Err(Raised("'.lower' on a value that is not a string"));
    };
    let lower = py::lower(d);
    let d = py::rstrip_dots(&lower);
    if list_matches(&lists.block, d)? {
        return Ok("blocked_explicit");
    }
    if list_matches(&lists.ignore, d)? {
        return Ok("ignored");
    }
    if list_matches(&lists.allow, d)? {
        return Ok("allowed");
    }
    Ok("blocked_default")
}

/// `GET /api/domains/blocked-actual`.
pub fn blocked_actual(view: &UiView) -> Py<Json> {
    let db = Db::open(&view.db_path)?;
    let config = cfg::load(&view.config_path);
    let rows = db.rows(
        "SELECT query_domain, COUNT(*) as query_count, MAX(timestamp) as last_access \
         FROM dns_queries WHERE status = 'blocked' GROUP BY query_domain ORDER BY query_count DESC",
        &[],
    )?;
    if rows.is_empty() {
        return Ok(Json::Arr(vec![]));
    }
    let lists = RuleLists::of(&config)?;
    let mut out = Vec::new();
    for r in &rows {
        let rule = current_rule(r.at(0)?, &lists)?;
        let block_type = match rule {
            "blocked_explicit" => "explicit",
            "blocked_default" => "default",
            _ => continue,
        };
        out.push(obj([
            ("domain", Json::Str(r.at(0)?.string()?)),
            ("block_type", Json::str(block_type)),
            ("query_count", Json::Int(r.at(1)?.int()?)),
            ("last_access", Json::Float(r.at(2)?.float()?)),
        ]));
    }
    Ok(Json::Arr(out))
}

const DOMAIN_STATS: &str = "SELECT query_domain, COUNT(*) as query_count, \
     SUM(CASE WHEN status = 'allowed' THEN 1 ELSE 0 END) as allowed_count, \
     SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked_count, \
     SUM(CASE WHEN status = 'ignored' THEN 1 ELSE 0 END) as ignored_count, \
     MAX(timestamp) as last_access, \
     GROUP_CONCAT(DISTINCT response_ips) as all_response_ips \
     FROM dns_queries";

/// `row[...] or 0`.
fn or_zero(v: &SqlVal) -> Py<i128> {
    if v.truthy() {
        v.int()
    } else {
        Ok(0)
    }
}

/// The distinct addresses of a `GROUP_CONCAT` of comma-joined lists, sorted; None when empty.
fn resolved_ips(v: &SqlVal) -> Py<Option<Vec<String>>> {
    if !v.truthy() {
        return Ok(None);
    }
    let set: BTreeSet<String> = comma_text(v)?
        .split(',')
        .map(py::strip)
        .filter(|ip| !ip.is_empty())
        .map(String::from)
        .collect();
    Ok((!set.is_empty()).then(|| set.into_iter().collect()))
}

#[allow(clippy::too_many_arguments)]
fn domain_info(
    r: &Row,
    allowed: i128,
    blocked: i128,
    ignored: i128,
    status: &str,
    rule: &str,
) -> Py<Json> {
    Ok(obj([
        ("domain", Json::Str(r.at(0)?.string()?)),
        ("query_count", Json::Int(r.at(1)?.int()?)),
        ("allowed_count", Json::Int(allowed)),
        ("blocked_count", Json::Int(blocked)),
        ("ignored_count", Json::Int(ignored)),
        ("last_access", Json::Float(r.at(5)?.float()?)),
        ("status", Json::str(status)),
        ("current_rule", Json::str(rule)),
        (
            "resolved_ips",
            match resolved_ips(r.at(6)?)? {
                Some(ips) => Json::strs(&ips),
                None => Json::Null,
            },
        ),
    ]))
}

/// `GET /api/domains/unique`: every name with its counts, without the ones ignored now.
pub fn unique_domains(view: &UiView) -> Py<Json> {
    let db = Db::open(&view.db_path)?;
    let config = cfg::load(&view.config_path);
    let rows = db.rows(
        &format!("{DOMAIN_STATS} GROUP BY query_domain ORDER BY query_count DESC"),
        &[],
    )?;
    if rows.is_empty() {
        return Ok(Json::Arr(vec![]));
    }
    let lists = RuleLists::of(&config)?;
    let mut out = Vec::new();
    for r in &rows {
        let allowed = or_zero(r.at(2)?)?;
        let blocked = or_zero(r.at(3)?)?;
        let ignored = or_zero(r.at(4)?)?;
        let status = if allowed > 0 && blocked == 0 {
            "allowed"
        } else if blocked > 0 && allowed == 0 {
            "blocked"
        } else {
            "mixed"
        };
        let rule = current_rule(r.at(0)?, &lists)?;
        if rule == "ignored" {
            continue;
        }
        out.push(domain_info(r, allowed, blocked, ignored, status, rule)?);
    }
    Ok(Json::Arr(out))
}

/// `GET /api/domains/ignored`: the names answered as ignored, with the rule that applies now.
pub fn ignored_domains(view: &UiView) -> Py<Json> {
    let db = Db::open(&view.db_path)?;
    let config = cfg::load(&view.config_path);
    let rows = db.rows(
        &format!(
            "{DOMAIN_STATS} WHERE status = 'ignored' GROUP BY query_domain ORDER BY query_count DESC"
        ),
        &[],
    )?;
    if rows.is_empty() {
        return Ok(Json::Arr(vec![]));
    }
    let lists = RuleLists::of(&config)?;
    let mut out = Vec::new();
    for r in &rows {
        let allowed = or_zero(r.at(2)?)?;
        let blocked = or_zero(r.at(3)?)?;
        let ignored = or_zero(r.at(4)?)?;
        let rule = current_rule(r.at(0)?, &lists)?;
        out.push(domain_info(r, allowed, blocked, ignored, "ignored", rule)?);
    }
    Ok(Json::Arr(out))
}
