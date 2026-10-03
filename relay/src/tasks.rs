//! Task-list boxes in a pull request's or an issue's text (#345): finding them, picking one, and
//! flipping it — and nothing else.
//!
//! An agent that has done an item could only tick it by sending the whole body back, which risks
//! rewriting what a person wrote. Here the relay reads the text, finds the box, flips the one
//! character, and checks that the one character is all that changed before anything is written.
//!
//! An item is what GitHub renders as a box: a list marker (`-`, `*`, `+`, or `1.` / `1)`) at the
//! start of a line after indentation, then `[ ]` or `[x]`, outside a code fence. A `[ ]` in a
//! sentence or a code block is not an item.
//!
//! An item is picked by its text (`--match`, which has to name exactly one), narrowed by the
//! section it sits in (`--under`, the nearest heading above it) and the item it is nested in
//! (`--parent`). The last resort is an id computed from heading, parent and text — not a position,
//! so an item added elsewhere does not move it, and an item that was itself edited stops matching.

use sha2::{Digest, Sha256};

/// One box.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Task {
    /// Short id from heading, parent, text and, for identical items, which of them it is
    pub id: String,
    pub checked: bool,
    pub text: String,
    /// The nearest heading above, without its `#`s; empty when there is none
    pub heading: String,
    /// The list item this one is nested in; empty at the top level
    pub parent: String,
    /// Index of the line, and byte offset of the box's mark (the space or `x`) within it
    #[serde(skip)]
    line: usize,
    #[serde(skip)]
    mark: usize,
}

/// A list item: (indent width, byte offset just past the marker and its spaces).
fn list_item(line: &str) -> Option<(usize, usize)> {
    let indent_bytes = line.len() - line.trim_start_matches([' ', '\t']).len();
    let indent: usize = line[..indent_bytes]
        .chars()
        .map(|c| if c == '\t' { 4 } else { 1 })
        .sum();
    let rest = &line[indent_bytes..];
    let marker_len = if rest.starts_with(['-', '*', '+']) {
        1
    } else {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 || digits > 9 || !rest[digits..].starts_with(['.', ')']) {
            return None;
        }
        digits + 1
    };
    let after = &rest[marker_len..];
    let spaces = after.len() - after.trim_start_matches([' ', '\t']).len();
    if spaces == 0 {
        return None;
    }
    Some((indent, indent_bytes + marker_len + spaces))
}

/// The text after a list marker: `(checked, mark offset in the rest, text)` when it is a box.
fn task_box(rest: &str) -> Option<(bool, usize, &str)> {
    let b = rest.as_bytes();
    if b.len() < 3 || b[0] != b'[' || b[2] != b']' {
        return None;
    }
    let checked = match b[1] {
        b' ' => false,
        b'x' | b'X' => true,
        _ => return None,
    };
    let text = &rest[3..];
    if !(text.is_empty() || text.starts_with([' ', '\t', '\r', '\n'])) {
        return None;
    }
    Some((checked, 1, text.trim()))
}

fn short_id(heading: &str, parent: &str, text: &str, nth: usize) -> String {
    let mut h = Sha256::new();
    for part in [heading, parent, text, &nth.to_string()] {
        h.update(part.as_bytes());
        h.update([0x1f]);
    }
    hex::encode(h.finalize())[..6].to_string()
}

/// Every box in `text`, in order.
pub fn tasks(text: &str) -> Vec<Task> {
    let mut out: Vec<Task> = Vec::new();
    let mut fence: Option<char> = None;
    let mut heading = String::new();
    // Open list items: (indent, text), so a nested item knows its parent
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut seen: std::collections::HashMap<(String, String, String), usize> = Default::default();
    for (i, raw) in text.split('\n').enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim_start();
        if let Some(f) = fence {
            if trimmed.starts_with(&f.to_string().repeat(3)) {
                fence = None;
            }
            continue;
        }
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            fence = trimmed.chars().next();
            continue;
        }
        if let Some(h) = trimmed.strip_prefix('#') {
            let level_rest = h.trim_start_matches('#');
            if trimmed.len() - level_rest.len() <= 6
                && (level_rest.is_empty() || level_rest.starts_with(' '))
            {
                heading = level_rest.trim().trim_end_matches('#').trim().to_string();
                stack.clear();
                continue;
            }
        }
        let Some((indent, body_at)) = list_item(line) else {
            if line.trim().is_empty() {
                continue;
            }
            // A paragraph that is not indented under a list ends it
            if line.len() == trimmed.len() {
                stack.clear();
            }
            continue;
        };
        while stack.last().is_some_and(|(d, _)| *d >= indent) {
            stack.pop();
        }
        let parent = stack.last().map(|(_, t)| t.clone()).unwrap_or_default();
        let rest = &line[body_at..];
        let item_text = match task_box(rest) {
            Some((checked, mark, t)) => {
                let key = (heading.clone(), parent.clone(), t.to_string());
                let nth = seen.entry(key).or_insert(0);
                out.push(Task {
                    id: short_id(&heading, &parent, t, *nth),
                    checked,
                    text: t.to_string(),
                    heading: heading.clone(),
                    parent: parent.clone(),
                    line: i,
                    mark: body_at + mark,
                });
                *nth += 1;
                t.to_string()
            }
            None => rest.trim().to_string(),
        };
        stack.push((indent, item_text));
    }
    out
}

/// How an item is picked.
#[derive(Debug, Clone, Default)]
pub struct Pick {
    /// Text the item contains (case-insensitive)
    pub matches: String,
    /// Text its heading contains
    pub under: String,
    /// Text its parent item contains
    pub parent: String,
    /// Its id, from `tasks`
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickError {
    NothingAsked,
    NoMatch,
    Several(Vec<Task>),
}

fn contains(hay: &str, needle: &str) -> bool {
    needle.is_empty() || hay.to_lowercase().contains(&needle.trim().to_lowercase())
}

/// The one item `p` names.
pub fn pick<'a>(all: &'a [Task], p: &Pick) -> Result<&'a Task, PickError> {
    if p.matches.trim().is_empty() && p.id.trim().is_empty() {
        return Err(PickError::NothingAsked);
    }
    let found: Vec<&Task> = all
        .iter()
        .filter(|t| p.id.trim().is_empty() || t.id == p.id.trim())
        .filter(|t| contains(&t.text, &p.matches))
        .filter(|t| contains(&t.heading, &p.under))
        .filter(|t| contains(&t.parent, &p.parent))
        .collect();
    match found.as_slice() {
        [] => Err(PickError::NoMatch),
        [one] => Ok(one),
        many => Err(PickError::Several(
            many.iter().map(|t| (*t).clone()).collect(),
        )),
    }
}

/// `text` with `task`'s box set to `checked`. Only that one character differs.
pub fn set(text: &str, task: &Task, checked: bool) -> String {
    let mut lines: Vec<String> = text.split('\n').map(String::from).collect();
    if let Some(line) = lines.get_mut(task.line) {
        if line.is_char_boundary(task.mark) && line.is_char_boundary(task.mark + 1) {
            line.replace_range(task.mark..task.mark + 1, if checked { "x" } else { " " });
        }
    }
    lines.join("\n")
}

/// Whether `new` differs from `old` in nothing but one box mark — the check made before writing.
pub fn only_a_box_changed(old: &str, new: &str) -> bool {
    if old.len() != new.len() {
        return false;
    }
    let diffs: Vec<usize> = old
        .bytes()
        .zip(new.bytes())
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, _)| i)
        .collect();
    match diffs.as_slice() {
        [i] => {
            let (a, b) = (old.as_bytes()[*i], new.as_bytes()[*i]);
            matches!((a, b), (b' ', b'x' | b'X') | (b'x' | b'X', b' '))
                && *i > 0
                && old.as_bytes()[i - 1] == b'['
                && old.as_bytes().get(i + 1) == Some(&b']')
        }
        _ => false,
    }
}

/// One line per box, for `issue tasks` / `pr tasks`.
pub fn render(all: &[Task]) -> String {
    all.iter()
        .map(|t| {
            let mut ctx: Vec<&str> = Vec::new();
            if !t.heading.is_empty() {
                ctx.push(&t.heading);
            }
            if !t.parent.is_empty() {
                ctx.push(&t.parent);
            }
            let ctx = if ctx.is_empty() {
                String::new()
            } else {
                format!("   ({})", ctx.join(" › "))
            };
            format!(
                "{} [{}] {}{ctx}",
                t.id,
                if t.checked { "x" } else { " " },
                t.text
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "Intro with a [ ] in a sentence.\n\n## Deploy\n\n- [ ] build\n- [x] push image\n- Staging\n  - [ ] smoke test\n- Production\n  - [ ] smoke test\n\n```\n- [ ] not a box\n```\n\n## Docs\n\n1. [ ] update README\n* [X] changelog\n";

    #[test]
    fn only_rendered_boxes_are_items() {
        let t = tasks(DOC);
        let texts: Vec<&str> = t.iter().map(|x| x.text.as_str()).collect();
        assert_eq!(
            texts,
            [
                "build",
                "push image",
                "smoke test",
                "smoke test",
                "update README",
                "changelog"
            ]
        );
        assert!(!t.iter().any(|x| x.text.contains("not a box")), "fenced");
        assert!(t[1].checked && t[5].checked && !t[0].checked);
        assert_eq!(t[0].heading, "Deploy");
        assert_eq!(t[2].parent, "Staging");
        assert_eq!(t[3].parent, "Production");
        assert_eq!(t[4].heading, "Docs");
    }

    #[test]
    fn a_match_must_name_exactly_one_and_can_be_narrowed() {
        let t = tasks(DOC);
        let p = |m: &str, under: &str, parent: &str| Pick {
            matches: m.into(),
            under: under.into(),
            parent: parent.into(),
            id: String::new(),
        };
        assert_eq!(pick(&t, &p("BUILD", "", "")).unwrap().text, "build");
        assert!(
            matches!(pick(&t, &p("smoke", "", "")), Err(PickError::Several(v)) if v.len() == 2)
        );
        assert_eq!(
            pick(&t, &p("smoke", "", "prod")).unwrap().parent,
            "Production"
        );
        assert_eq!(
            pick(&t, &p("update", "docs", "")).unwrap().text,
            "update README"
        );
        assert_eq!(pick(&t, &p("build", "docs", "")), Err(PickError::NoMatch));
        assert_eq!(pick(&t, &Pick::default()), Err(PickError::NothingAsked));
    }

    /// The id comes from heading, parent and text: adding an item elsewhere leaves it, editing the
    /// item itself changes it.
    #[test]
    fn an_id_survives_an_item_added_elsewhere_and_not_an_edit() {
        let before = tasks(DOC);
        let id = pick(
            &before,
            &Pick {
                matches: "smoke".into(),
                parent: "Staging".into(),
                ..Default::default()
            },
        )
        .unwrap()
        .id
        .clone();
        let added = DOC.replace("- [ ] build\n", "- [ ] lint\n- [ ] build\n");
        let after = tasks(&added);
        assert_eq!(
            pick(
                &after,
                &Pick {
                    id: id.clone(),
                    ..Default::default()
                }
            )
            .unwrap()
            .parent,
            "Staging"
        );
        let edited = DOC.replace(
            "  - [ ] smoke test\n- Production",
            "  - [ ] smoke tests\n- Production",
        );
        assert_eq!(
            pick(
                &tasks(&edited),
                &Pick {
                    id,
                    ..Default::default()
                }
            ),
            Err(PickError::NoMatch)
        );
        // identical items in one place still get ids of their own
        let twins = tasks("- [ ] a\n- [ ] a\n");
        assert_ne!(twins[0].id, twins[1].id);
    }

    #[test]
    fn setting_a_box_changes_that_box_and_nothing_else() {
        let t = tasks(DOC);
        let target = pick(
            &t,
            &Pick {
                matches: "smoke".into(),
                parent: "prod".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let new = set(DOC, target, true);
        assert!(only_a_box_changed(DOC, &new));
        assert!(new.contains("- Production\n  - [x] smoke test"));
        assert!(
            new.contains("- Staging\n  - [ ] smoke test"),
            "the other one is untouched"
        );
        let back = set(&new, &tasks(&new)[3], false);
        assert_eq!(back, DOC);
        // CRLF text keeps its line endings
        let crlf = "- [ ] a\r\n- [ ] b\r\n";
        let c = set(crlf, &tasks(crlf)[1], true);
        assert_eq!(c, "- [ ] a\r\n- [x] b\r\n");
    }

    #[test]
    fn anything_but_one_box_mark_is_not_a_tick() {
        assert!(only_a_box_changed("- [ ] a", "- [x] a"));
        assert!(only_a_box_changed("- [X] a", "- [ ] a"));
        assert!(!only_a_box_changed("- [ ] a", "- [ ] b"), "the text");
        assert!(
            !only_a_box_changed("- [ ] a [ ]", "- [x] a [x]"),
            "two marks"
        );
        assert!(
            !only_a_box_changed("a b", "axb"),
            "a space that is not in a box"
        );
        assert!(
            !only_a_box_changed("- [ ] a", "- [ ] a\nmore"),
            "added text"
        );
    }
}
