//! #330: the command sidecars' commands, built at run time from the relays agent setup saved.
//!
//! `sgw-agent setup` asks the gateway's `/relays` and saves the answer beside the env file. Every
//! run reads that file and grafts each command sidecar onto the clap tree as `sgw-agent <name>
//! <word>… --<arg> …`, so `--help` lists them without the gateway being asked — or up. A command
//! the project may not run, and a sidecar that is not connected, are left out unless
//! `--show-unavailable` asks for them; the gateway refuses them anyway.

use std::path::PathBuf;

use clap::{Arg, ArgAction, ArgMatches, Command};
use serde_json::{Map, Value};

use super::client::AgentClient;
use super::print::print_response;
use crate::api::types::ApiRequest;
use crate::config::AGENT_COMMANDS;
use crate::forge::command::{ArgKind, GrantedCommand, RelayInfo, RelayList};

pub const DEFAULT_RELAYS_FILE: &str = "/etc/sekimore-agent/relays.json";
pub const SHOW_UNAVAILABLE: &str = "show-unavailable";

/// Where setup saved the relays: `SEKIMORE_RELAYS_FILE`, else beside the env file.
pub fn relays_file() -> PathBuf {
    std::env::var("SEKIMORE_RELAYS_FILE")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_RELAYS_FILE))
}

/// The saved relays. None saved yet (setup never reached the gateway) is an empty list: the CLI
/// then has only its own commands, which is the truth of a container never connected.
pub fn load() -> RelayList {
    std::fs::read(relays_file())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// The command sidecars the CLI can show: connected, and not shadowing a command of its own.
fn sidecars(list: &RelayList, show_unavailable: bool) -> impl Iterator<Item = &RelayInfo> {
    list.relays.iter().filter(move |r| {
        r.kind == "command"
            && !AGENT_COMMANDS.contains(&r.name.as_str())
            && (r.available || show_unavailable)
    })
}

/// `cli` with each command sidecar added as a subcommand.
pub fn graft(mut cli: Command, list: &RelayList, show_unavailable: bool) -> Command {
    for r in sidecars(list, show_unavailable) {
        let mut top = Command::new(r.name.clone())
            .about(about_sidecar(r))
            .subcommand_required(true)
            .arg_required_else_help(true);
        for c in r.commands.iter().filter(|c| c.granted || show_unavailable) {
            let words: Vec<&str> = c.spec.name.split_whitespace().collect();
            top = add(top, &words, c);
        }
        cli = cli.subcommand(top);
    }
    cli
}

fn about_sidecar(r: &RelayInfo) -> String {
    let first = r
        .guide
        .lines()
        .map(|l| l.trim_start_matches('#').trim())
        .find(|l| !l.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{} sidecar", r.name));
    match (&r.reason, r.available) {
        (Some(why), false) => format!("{first} [not available: {why}]"),
        _ => first,
    }
}

/// `words` under `parent`, the last one the command itself.
fn add(parent: Command, words: &[&str], c: &GrantedCommand) -> Command {
    let Some((first, rest)) = words.split_first() else {
        return parent;
    };
    if rest.is_empty() {
        let about = if c.granted {
            c.spec.about.clone()
        } else {
            format!(
                "{} [not allowed: needs {}]",
                c.spec.about, c.spec.permission
            )
        };
        let mut leaf = Command::new(first.to_string()).about(about);
        for a in &c.spec.args {
            let mut arg = Arg::new(a.name.clone())
                .long(a.name.clone())
                .help(a.help.clone());
            arg = match a.kind {
                ArgKind::String => arg.value_parser(clap::value_parser!(String)),
                ArgKind::Int => arg.value_parser(clap::value_parser!(i64)),
                ArgKind::Bool => arg.action(ArgAction::SetTrue),
                ArgKind::List => arg
                    .action(ArgAction::Append)
                    .value_parser(clap::value_parser!(String)),
            };
            leaf = leaf.arg(arg.required(a.required));
        }
        return parent.subcommand(leaf);
    }
    if parent.find_subcommand(first).is_some() {
        parent.mut_subcommand(*first, |g| add(g, rest, c))
    } else {
        let group = Command::new(first.to_string())
            .subcommand_required(true)
            .arg_required_else_help(true);
        parent.subcommand(add(group, rest, c))
    }
}

/// A command sidecar's command, as parsed: which sidecar, its words, its arguments.
#[derive(Debug, PartialEq)]
pub struct Call {
    pub sidecar: String,
    pub words: Vec<String>,
    pub args: Map<String, Value>,
}

/// The call `matches` names, when its first word is a command sidecar.
pub fn matched(matches: &ArgMatches, list: &RelayList) -> Option<Call> {
    let (name, mut m) = matches.subcommand()?;
    let r = list
        .relays
        .iter()
        .find(|r| r.kind == "command" && r.name == name)?;
    let mut words = Vec::new();
    while let Some((w, sub)) = m.subcommand() {
        words.push(w.to_string());
        m = sub;
    }
    let joined = words.join(" ");
    let c = r.commands.iter().find(|c| c.spec.name == joined)?;
    let mut args = Map::new();
    for a in &c.spec.args {
        let v = match a.kind {
            ArgKind::String => m.get_one::<String>(&a.name).map(|s| Value::from(s.clone())),
            ArgKind::Int => m.get_one::<i64>(&a.name).map(|n| Value::from(*n)),
            ArgKind::Bool => m.get_flag(&a.name).then_some(Value::Bool(true)),
            ArgKind::List => m
                .get_many::<String>(&a.name)
                .map(|vs| Value::from(vs.cloned().collect::<Vec<_>>())),
        };
        if let Some(v) = v {
            args.insert(a.name.clone(), v);
        }
    }
    Some(Call {
        sidecar: name.to_string(),
        words,
        args,
    })
}

/// Post the call to the gateway, which checks it and hands it to the sidecar.
pub async fn run(call: Call) -> anyhow::Result<i32> {
    let client = AgentClient::from_env()?;
    let path = format!("/x/{}/{}", call.sidecar, call.words.join("/"));
    let resp = client
        .call(
            &path,
            &ApiRequest {
                args: call.args,
                ..Default::default()
            },
        )
        .await?;
    if !resp.ok {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "failed".into()));
    }
    print_response(&resp);
    Ok(0)
}

/// The connected command sidecars' guides, for `sgw-agent guide` and the agent's skill file.
/// Empty when there are none.
pub fn guides(list: &RelayList) -> String {
    let mut out = String::new();
    for r in sidecars(list, false) {
        out.push_str(&format!(
            "\n\n<!-- the {} sidecar's guide, from its /describe -->\n\n",
            r.name
        ));
        out.push_str(r.guide.trim_end());
        out.push('\n');
        let allowed: Vec<String> = r
            .commands
            .iter()
            .filter(|c| c.granted)
            .map(|c| format!("`sgw-agent {} {}`", r.name, c.spec.name))
            .collect();
        if !allowed.is_empty() {
            out.push_str(&format!(
                "\nAllowed here: {}. `sgw-agent {} --help` lists their arguments.\n",
                allowed.join(", "),
                r.name
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forge::command::{ArgSpec, CommandSpec};

    fn list() -> RelayList {
        let cmd =
            |name: &str, permission: &str, granted: bool, args: Vec<ArgSpec>| GrantedCommand {
                spec: CommandSpec {
                    name: name.into(),
                    about: format!("{name} it"),
                    permission: permission.into(),
                    args,
                },
                granted,
            };
        let arg = |name: &str, kind: ArgKind, required: bool| ArgSpec {
            name: name.into(),
            help: String::new(),
            kind,
            required,
        };
        RelayList {
            relays: vec![
                RelayInfo {
                    name: "github".into(),
                    kind: "forge".into(),
                    available: true,
                    reason: None,
                    version: String::new(),
                    resources: vec![],
                    guide: String::new(),
                    commands: vec![],
                },
                RelayInfo {
                    name: "notes".into(),
                    kind: "command".into(),
                    available: true,
                    reason: None,
                    version: "1".into(),
                    resources: vec!["notes".into()],
                    guide: "## Notes\n\nKeep notes. [notes:write]\n".into(),
                    commands: vec![
                        cmd(
                            "note add",
                            "notes:write",
                            true,
                            vec![
                                arg("text", ArgKind::String, true),
                                arg("tag", ArgKind::List, false),
                                arg("pin", ArgKind::Bool, false),
                                arg("days", ArgKind::Int, false),
                            ],
                        ),
                        cmd("note drop", "notes:delete", false, vec![]),
                    ],
                },
                RelayInfo {
                    name: "s3".into(),
                    kind: "command".into(),
                    available: false,
                    reason: Some("does not answer".into()),
                    version: String::new(),
                    resources: vec![],
                    guide: String::new(),
                    commands: vec![],
                },
            ],
        }
    }

    fn cli(show: bool) -> Command {
        graft(Command::new("sgw-agent"), &list(), show)
    }

    #[test]
    fn a_command_parses_into_the_call_the_gateway_takes() {
        let m = cli(false)
            .try_get_matches_from([
                "sgw-agent",
                "notes",
                "note",
                "add",
                "--text",
                "hi",
                "--tag",
                "a",
                "--tag",
                "b",
                "--pin",
                "--days",
                "3",
            ])
            .unwrap();
        assert_eq!(
            matched(&m, &list()),
            Some(Call {
                sidecar: "notes".into(),
                words: vec!["note".into(), "add".into()],
                args: serde_json::json!({"text": "hi", "tag": ["a", "b"], "pin": true, "days": 3})
                    .as_object()
                    .unwrap()
                    .clone(),
            })
        );
        // a required argument is required on the command line too, and an int is an int
        assert!(cli(false)
            .try_get_matches_from(["sgw-agent", "notes", "note", "add"])
            .is_err());
        assert!(cli(false)
            .try_get_matches_from([
                "sgw-agent",
                "notes",
                "note",
                "add",
                "--text",
                "x",
                "--days",
                "x"
            ])
            .is_err());
    }

    #[test]
    fn what_cannot_be_used_is_hidden_unless_asked_for() {
        let hidden = cli(false);
        let notes = hidden.find_subcommand("notes").unwrap();
        let note = notes.find_subcommand("note").unwrap();
        assert!(note.find_subcommand("add").is_some());
        assert!(note.find_subcommand("drop").is_none(), "not granted");
        assert!(hidden.find_subcommand("s3").is_none(), "not connected");
        let shown = cli(true);
        let drop = shown
            .find_subcommand("notes")
            .and_then(|c| c.find_subcommand("note"))
            .and_then(|c| c.find_subcommand("drop"))
            .unwrap();
        assert!(drop
            .get_about()
            .unwrap()
            .to_string()
            .contains("needs notes:delete"));
        assert!(shown
            .find_subcommand("s3")
            .unwrap()
            .get_about()
            .unwrap()
            .to_string()
            .contains("does not answer"));
    }

    #[test]
    fn the_guide_carries_each_connected_sidecar_s_own_and_what_is_allowed() {
        let g = guides(&list());
        assert!(g.contains("## Notes"), "{g}");
        assert!(g.contains("`sgw-agent notes note add`"), "{g}");
        assert!(!g.contains("note drop"), "{g}");
        assert!(!g.contains("s3"), "{g}");
        assert_eq!(guides(&RelayList::default()), "");
    }

    #[test]
    fn a_sidecar_cannot_take_a_name_the_cli_already_has() {
        let mut l = list();
        l.relays[1].name = "pr".into();
        let c = graft(Command::new("sgw-agent"), &l, false);
        assert!(c.find_subcommand("pr").is_none());
    }
}
