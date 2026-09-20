//! Human-readable rendering of the relay's answers.
//!
//! Split from the dispatch because it is the one part that does not know about endpoints: it is
//! handed an `ApiResponse` and turns it into lines. The relay already renders most answers into
//! `message`, so only the two paginated shapes (`pr status`, `ci log`) need code here.

use serde_json::Value;

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

/// `Status: Ready  Priority: P1` from one item's `fieldValues`.
///
/// The built-in `Title` field is left out: the title is printed already, and repeating it pushes
/// the values that differ between items off the line.
fn field_values(item: &Value) -> String {
    let Some(nodes) = item.pointer("/fieldValues/nodes").and_then(Value::as_array) else {
        return String::new();
    };
    nodes
        .iter()
        .filter_map(|fv| {
            let field = fv.pointer("/field/name")?.as_str()?;
            if field == "Title" {
                return None;
            }
            // Whichever of the four value shapes this one is. A type we did not ask for arrives as
            // __typename alone, with no field, and is dropped above.
            let value = fv
                .get("name")
                .or_else(|| fv.get("text"))
                .or_else(|| fv.get("date"))
                .or_else(|| fv.get("number"))?;
            let value = match value {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            Some(format!("{field}: {value}"))
        })
        .collect::<Vec<_>>()
        .join("  ")
}

/// Human-readable rendering of `project list`.
///
/// 0.2.15: the field values are shown with each item. Writing a field and having no way to read it
/// back meant `update-item` answering `ok` was the only evidence anything had happened.
pub fn print_project_items(resp: &ApiResponse) {
    let Some(nodes) = resp
        .raw
        .as_ref()
        .and_then(|r| r.pointer("/data/node/items/nodes"))
        .and_then(Value::as_array)
    else {
        print_response(resp);
        return;
    };
    for item in nodes {
        let content = item.get("content");
        let title = content
            .and_then(|c| c.get("title"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let head = match content
            .and_then(|c| c.get("number"))
            .and_then(Value::as_u64)
        {
            Some(n) => format!("#{n}"),
            // A draft item has no issue or pull request behind it, so there is no number to show
            None => item
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("ITEM")
                .to_string(),
        };
        let id = item.get("id").and_then(Value::as_str).unwrap_or("?");
        let fields = field_values(item);
        let fields = if fields.is_empty() {
            String::new()
        } else {
            format!("  {fields}")
        };
        println!("{head:<7} {id}{fields}  {title}");
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

#[cfg(test)]
mod tests {
    use super::field_values;
    use serde_json::json;

    fn item(values: serde_json::Value) -> serde_json::Value {
        json!({"fieldValues": {"nodes": values}})
    }

    #[test]
    fn renders_each_value_shape() {
        let s = field_values(&item(json!([
            {"name": "Ready", "field": {"name": "Status"}},
            {"text": "a note", "field": {"name": "Notes"}},
            {"number": 3, "field": {"name": "Size"}},
            {"date": "2026-09-20", "field": {"name": "Due"}},
        ])));
        assert_eq!(s, "Status: Ready  Notes: a note  Size: 3  Due: 2026-09-20");
    }

    #[test]
    fn drops_the_title_field() {
        // The title is printed beside the values already; repeating it pushes the rest off the line
        let s = field_values(&item(json!([
            {"text": "the issue's title", "field": {"name": "Title"}},
            {"name": "Ready", "field": {"name": "Status"}},
        ])));
        assert_eq!(s, "Status: Ready");
    }

    #[test]
    fn drops_a_value_type_the_query_did_not_ask_for() {
        // GitHub answers those with __typename alone. Rendering "…: null" for them would be noise
        let s = field_values(&item(json!([
            {"__typename": "ProjectV2ItemFieldLabelValue"},
            {"name": "Ready", "field": {"name": "Status"}},
        ])));
        assert_eq!(s, "Status: Ready");
    }

    #[test]
    fn an_item_with_no_field_values_renders_nothing() {
        assert_eq!(field_values(&item(json!([]))), "");
        assert_eq!(field_values(&json!({})), "");
    }
}
