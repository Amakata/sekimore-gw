//! Human-readable rendering of the relay's answers.
//!
//! Split from the dispatch because it is the one part that does not know about endpoints: it is
//! handed an `ApiResponse` and turns it into lines. The relay already renders most answers into
//! `message`, so only the two paginated shapes (`pr status`, `ci log`) need code here.

use crate::api::types::ApiResponse;

/// Human-readable rendering of `pr status`. raw holds the PrStatus JSON.
pub fn print_pr_status(resp: &ApiResponse) {
    if let Some(m) = &resp.message {
        println!("{m}");
    }
    let Some(raw) = &resp.raw else { return };
    if let Some(checks) = raw.get("checks").and_then(|v| v.as_array()) {
        for c in checks {
            let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let state = c.get("state").and_then(|v| v.as_str()).unwrap_or("?");
            let mark = match state {
                "success" | "neutral" | "skipped" => "✓",
                "pending" | "queued" | "in_progress" | "expected" => "…",
                _ => "✗",
            };
            println!("  {mark} {state:<12} {name}");
        }
    }
}

/// Human-readable rendering of `ci log`. raw holds the CiLogPage JSON.
pub fn print_ci_log(resp: &ApiResponse) {
    let Some(raw) = &resp.raw else { return };
    let g = |k: &str| raw.get(k);
    let name = g("job_name").and_then(|v| v.as_str()).unwrap_or("");
    let concl = g("conclusion").and_then(|v| v.as_str()).unwrap_or("");
    let total = g("total_lines").and_then(|v| v.as_u64()).unwrap_or(0);
    let start = g("start").and_then(|v| v.as_u64()).unwrap_or(0);
    let end = g("end").and_then(|v| v.as_u64()).unwrap_or(0);
    let job_id = g("job_id").and_then(|v| v.as_u64()).unwrap_or(0);
    let hdr = if name.is_empty() {
        format!("== job {job_id} lines {start}..{end} / {total}")
    } else {
        format!("== {name} [{concl}] lines {start}..{end} / {total}")
    };
    eprintln!("{hdr}");
    if let Some(lines) = g("lines").and_then(|v| v.as_array()) {
        for l in lines {
            if let Some(s) = l.as_str() {
                println!("{s}");
            }
        }
    }
    if g("has_more_before")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        eprintln!(
            "-- more above. next: sekimore ci log --job-id {job_id} --before {start} --window <n>"
        );
    }
}

pub fn print_response(resp: &ApiResponse) {
    if let Some(m) = &resp.message {
        println!("{m}");
    } else if let Some(url) = &resp.url {
        println!("#{} {url}", resp.number.unwrap_or(0));
    } else if let Some(item) = &resp.item_id {
        println!("item: {item}");
    } else if let Some(raw) = &resp.raw {
        println!("{}", serde_json::to_string_pretty(raw).unwrap_or_default());
    } else {
        println!("ok");
    }
}
