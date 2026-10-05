//! #366: command sidecars — relays with resources and commands of their own, which a third party
//! can write.
//!
//! A forge relay (`github`) answers the gateway's own operations. A command sidecar instead says in
//! its `GET /describe` which commands it has, the permission each needs and the arguments each
//! takes. The gateway holds that against `relay.sidecars.<name>`, and for each call:
//!
//! 1. finds the command in the describe,
//! 2. checks its permission against the project (`Project::authorize_command`),
//! 3. checks the arguments against the declared ones — no unknown name, every required one, each
//!    of its kind,
//! 4. fills in the credentials from the secret store,
//!
//! and only then sends `POST /command`. The sidecar decides nothing: what reaches it is already
//! allowed, and it returns the result and every upstream call it made, which the gateway audits.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use hyper::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::sidecar::{exchange, CallRecord, Describe, WireError};
use crate::api::types::ApiResponse;
use crate::api::ApiError;
use crate::audit::{Actor, Audit};
use crate::config::valid_word;
use crate::paths;
use crate::policy::CommandAuthorized;
use crate::vars::{State, VarError, Vars};

/// The most words a command name may have (`note tag add`).
pub const MAX_WORDS: usize = 3;

/// One command, as `/describe` declares it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandSpec {
    /// Its words, space-separated: `note add`. The agent runs `sgw-agent <sidecar> note add`
    pub name: String,
    /// One line for `--help`
    pub about: String,
    /// What it needs, `<resource>:<action>`, the resource one the sidecar declares
    pub permission: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<ArgSpec>,
}

/// One argument: `--<name> <value>` on the command line, `"<name>": value` on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArgSpec {
    pub name: String,
    #[serde(default)]
    pub help: String,
    #[serde(default)]
    pub kind: ArgKind,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArgKind {
    /// A JSON string
    #[default]
    String,
    /// A JSON integer
    Int,
    /// A JSON `true` / `false`; a flag on the command line
    Bool,
    /// A JSON array of strings; the option repeated on the command line
    List,
}

/// `POST /command`: a call the gateway has already allowed.
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandRequest {
    pub command: String,
    /// The permission the gateway checked, for the sidecar's log
    pub permission: String,
    pub project: String,
    /// Checked against the command's declared arguments
    pub args: Map<String, Value>,
    /// `relay.sidecars.<name>.credentials`, filled in from the secret store
    pub credentials: BTreeMap<String, String>,
}

/// #330: what `/relays` says about one relay — for agent setup to save, and for the CLI to build
/// its commands and the guide from without asking the gateway each time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayInfo {
    pub name: String,
    /// `forge` (the gateway's own operations: `github`) or `command`
    pub kind: String,
    /// Whether it answered and was connected. A command sidecar that is down or refused is listed
    /// with the reason, so `--show-unavailable` can say why it is missing
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub guide: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<GrantedCommand>,
}

/// A command and whether this project may run it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantedCommand {
    #[serde(flatten)]
    pub spec: CommandSpec,
    #[serde(default)]
    pub granted: bool,
}

/// The body of `/relays` and of the file agent setup saves it to.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RelayList {
    pub relays: Vec<RelayInfo>,
}

/// What `POST /command` answers: a result or an error, and every upstream call made.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CommandReply {
    /// For the agent to read: what happened, in a sentence or a few lines
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// For the agent to parse, shown with `--json`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<WireError>,
    #[serde(default)]
    pub calls: Vec<CallRecord>,
}

/// Holds a sidecar's `/describe` to the configuration. A failure says what is wrong, for the
/// operator: the sidecar is then not connected.
pub fn check_describe(d: &Describe, name: &str, declared: &[String]) -> Result<(), String> {
    if d.name != name {
        return Err(format!(
            "it names itself {:?}, and relay.sidecars names it {name:?}",
            d.name
        ));
    }
    let extra: Vec<&String> = d
        .resources
        .iter()
        .filter(|r| !declared.contains(r))
        .collect();
    if !extra.is_empty() {
        return Err(format!(
            "it claims {extra:?}, which relay.sidecars.{name}.resources does not list"
        ));
    }
    if d.guide.trim().is_empty() {
        return Err(
            "it gives no guide, and a relay that cannot say how it is used is not connected".into(),
        );
    }
    // the 0.2.10 rule, kept by every relay: a guide names permissions as `[resource:action]`, and
    // only its own — a sidecar describing how to merge a pull request is claiming what it is not
    for key in bracketed_permissions(&d.guide) {
        let (r, _) = key.split_once(':').unwrap_or_default();
        if !d.resources.iter().any(|x| x == r) {
            return Err(format!(
                "its guide names [{key}], which is not one of its resources ({})",
                d.resources.join(", ")
            ));
        }
    }
    let mut seen: Vec<Vec<&str>> = Vec::new();
    for c in &d.commands {
        let words: Vec<&str> = c.name.split_whitespace().collect();
        if words.is_empty() || words.len() > MAX_WORDS || !words.iter().all(|w| valid_word(w)) {
            return Err(format!(
                "command {:?}: one to {MAX_WORDS} words of lower-case letters, digits, _ and -, each starting with a letter",
                c.name
            ));
        }
        // `note` and `note add` cannot both be commands: on the command line one is the other's group
        if let Some(other) = seen.iter().find(|s| {
            let n = s.len().min(words.len());
            s[..n] == words[..n]
        }) {
            return Err(format!(
                "commands {:?} and {:?} overlap: one is a group of the other",
                other.join(" "),
                c.name
            ));
        }
        seen.push(words);
        let (r, a) = c.permission.split_once(':').ok_or_else(|| {
            format!(
                "command {:?}: permission {:?} must be resource:action",
                c.name, c.permission
            )
        })?;
        if !d.resources.iter().any(|x| x == r) || !valid_word(a) {
            return Err(format!(
                "command {:?}: permission {:?} must be one of its resources ({}) and an action word",
                c.name,
                c.permission,
                d.resources.join(", ")
            ));
        }
        let mut names: Vec<&str> = Vec::new();
        for arg in &c.args {
            if !valid_word(&arg.name) || arg.name == "help" {
                return Err(format!(
                    "command {:?}: argument {:?} must be lower-case letters, digits, _ and -, starting with a letter, and not help",
                    c.name, arg.name
                ));
            }
            if names.contains(&arg.name.as_str()) {
                return Err(format!(
                    "command {:?}: argument {:?} is declared twice",
                    c.name, arg.name
                ));
            }
            if arg.kind == ArgKind::Bool && arg.required {
                return Err(format!(
                    "command {:?}: argument {:?} is a flag and cannot be required",
                    c.name, arg.name
                ));
            }
            names.push(&arg.name);
        }
    }
    Ok(())
}

/// Every `[resource:action]` in a guide.
fn bracketed_permissions(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in text.split('[').skip(1) {
        let Some((inside, _)) = part.split_once(']') else {
            continue;
        };
        if let Some((r, a)) = inside.split_once(':') {
            if valid_word(r) && valid_word(a) {
                out.push(inside.to_string());
            }
        }
    }
    out
}

/// The arguments a call may carry: each declared, every required one present, each of its kind.
/// A JSON `null` is the same as leaving it out.
pub fn check_args(
    spec: &CommandSpec,
    args: &Map<String, Value>,
) -> Result<Map<String, Value>, String> {
    let mut out = Map::new();
    for (k, v) in args {
        let Some(a) = spec.args.iter().find(|a| a.name == *k) else {
            let known: Vec<String> = spec.args.iter().map(|a| format!("--{}", a.name)).collect();
            return Err(format!(
                "{} takes no --{k}; it takes {}",
                spec.name,
                if known.is_empty() {
                    "no arguments".to_string()
                } else {
                    known.join(" ")
                }
            ));
        };
        let fits = match (a.kind, v) {
            (_, Value::Null) => continue,
            (ArgKind::String, Value::String(_)) => true,
            (ArgKind::Int, Value::Number(n)) => n.is_i64(),
            (ArgKind::Bool, Value::Bool(_)) => true,
            (ArgKind::List, Value::Array(xs)) => xs.iter().all(Value::is_string),
            _ => false,
        };
        if !fits {
            return Err(format!(
                "{}: --{k} must be {}",
                spec.name,
                match a.kind {
                    ArgKind::String => "a string",
                    ArgKind::Int => "an integer",
                    ArgKind::Bool => "true or false",
                    ArgKind::List => "a list of strings",
                }
            ));
        }
        out.insert(k.clone(), v.clone());
    }
    if let Some(a) = spec
        .args
        .iter()
        .find(|a| a.required && !out.contains_key(&a.name))
    {
        return Err(format!("{} needs --{}", spec.name, a.name));
    }
    Ok(out)
}

/// A command sidecar, reached over its socket.
pub struct CommandSidecar {
    name: String,
    socket: PathBuf,
    /// `relay.sidecars.<name>.resources`
    declared: Vec<String>,
    /// credential name → secret-store key
    credentials: BTreeMap<String, String>,
    vars: Vars,
    audit: Arc<Audit>,
    /// The checked `/describe`. Not kept when reading or checking it fails: the sidecar may simply
    /// not be up yet, and the next call looks again
    describe: tokio::sync::Mutex<Option<Arc<Describe>>>,
}

impl CommandSidecar {
    pub fn new(
        name: &str,
        socket: &Path,
        declared: Vec<String>,
        credentials: BTreeMap<String, String>,
        vars: Vars,
        audit: Arc<Audit>,
    ) -> Self {
        CommandSidecar {
            name: name.to_string(),
            socket: socket.to_path_buf(),
            declared,
            credentials,
            vars,
            audit,
            describe: tokio::sync::Mutex::new(None),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn unavailable(&self, why: &str) -> ApiError {
        self.audit.deny_edge(
            paths::RELAY_SIDECAR,
            "sidecar_unavailable",
            Actor::System,
            why,
            &[
                ("sidecar", &self.name),
                ("socket", &self.socket.display().to_string()),
            ],
        );
        ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: format!(
                "the {} sidecar does not answer at {} ({why}); ask a human to check the sekimore-{} service on the host running docker",
                self.name,
                self.socket.display(),
                self.name
            ),
        }
    }

    fn refused(&self, why: String) -> ApiError {
        self.audit.deny_edge(
            paths::RELAY_SIDECAR,
            "sidecar_refused",
            Actor::System,
            &why,
            &[("sidecar", &self.name)],
        );
        ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: format!("the {} sidecar is not connected: {why}", self.name),
        }
    }

    /// The sidecar's `/describe`, read and checked once.
    pub async fn describe(&self) -> Result<Arc<Describe>, ApiError> {
        let mut held = self.describe.lock().await;
        if let Some(d) = held.as_ref() {
            return Ok(d.clone());
        }
        let raw = exchange(&self.socket, Method::GET, "/describe", Bytes::new())
            .await
            .map_err(|e| self.unavailable(&e))?;
        let d: Describe = serde_json::from_slice(&raw)
            .map_err(|e| self.refused(format!("its /describe is not readable: {e}")))?;
        check_describe(&d, &self.name, &self.declared).map_err(|e| self.refused(e))?;
        log::info!(
            "{} sidecar {} at {}: {} command(s) on {}",
            self.name,
            d.version,
            self.socket.display(),
            d.commands.len(),
            d.resources.join(" ")
        );
        let d = Arc::new(d);
        *held = Some(d.clone());
        Ok(d)
    }

    /// The command named `name` (its words, space-separated).
    pub async fn command(&self, name: &str) -> Result<CommandSpec, ApiError> {
        let find = |d: &Describe| {
            d.commands
                .iter()
                .find(|c| c.name.split_whitespace().eq(name.split_whitespace()))
                .cloned()
        };
        let mut d = self.describe().await?;
        if find(&d).is_none() {
            // a sidecar updated since its describe was read may have the command now
            *self.describe.lock().await = None;
            d = self.describe().await?;
        }
        find(&d).ok_or_else(|| ApiError {
            status: StatusCode::NOT_FOUND,
            message: format!(
                "the {} sidecar has no command {name:?}; it has: {}",
                self.name,
                d.commands
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        })
    }

    /// The credentials, from the secret store as last read. One that cannot be had stops the
    /// call with the command that fixes it.
    fn credentials(&self) -> Result<BTreeMap<String, String>, ApiError> {
        let mut out = BTreeMap::new();
        for (name, key) in &self.credentials {
            let err = match self.vars.state(key) {
                State::Set(v) => {
                    out.insert(name.clone(), v);
                    continue;
                }
                State::Missing => VarError::Missing(key.clone()),
                State::Locked => VarError::Locked(key.clone()),
                State::Unavailable(why) => VarError::Unavailable(key.clone(), why),
            };
            return Err(ApiError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                message: format!("the {} sidecar's credential {name}: {err}", self.name),
            });
        }
        Ok(out)
    }

    /// Run a command the project allows. The proof is for this command's permission; the arguments
    /// are checked here, so what the sidecar gets is a call it can take as given.
    pub async fn call(
        &self,
        auth: &CommandAuthorized<'_>,
        spec: &CommandSpec,
        args: &Map<String, Value>,
    ) -> Result<ApiResponse, ApiError> {
        if auth.permission() != spec.permission {
            return Err(ApiError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: format!(
                    "authorized {} for a command that needs {}",
                    auth.permission(),
                    spec.permission
                ),
            });
        }
        let args = check_args(spec, args).map_err(ApiError::bad_request)?;
        let body = CommandRequest {
            command: spec.name.clone(),
            permission: spec.permission.clone(),
            project: auth.project().to_string(),
            args,
            credentials: self.credentials()?,
        };
        let bytes = serde_json::to_vec(&body).map_err(|e| ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("encode a request for the {} sidecar: {e}", self.name),
        })?;
        let raw = exchange(&self.socket, Method::POST, "/command", Bytes::from(bytes))
            .await
            .map_err(|e| self.unavailable(&e))?;
        let reply: CommandReply = serde_json::from_slice(&raw).map_err(|e| ApiError {
            status: StatusCode::BAD_GATEWAY,
            message: format!("the {} sidecar's reply is not readable: {e}", self.name),
        })?;
        for c in &reply.calls {
            self.audit.log_edge(
                paths::SIDECAR_API,
                "api_call",
                Actor::System,
                &[
                    ("sidecar", &self.name),
                    ("method", &c.method),
                    ("path", &c.path),
                    ("status", &c.status.to_string()),
                ],
            );
        }
        if let Some(e) = reply.error {
            return Err(ApiError {
                status: StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_GATEWAY),
                message: e.message,
            });
        }
        Ok(ApiResponse {
            ok: true,
            message: reply.message,
            raw: reply.data,
            ..ApiResponse::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> CommandSpec {
        CommandSpec {
            name: "note add".into(),
            about: "Add a note".into(),
            permission: "notes:write".into(),
            args: vec![
                ArgSpec {
                    name: "text".into(),
                    help: String::new(),
                    kind: ArgKind::String,
                    required: true,
                },
                ArgSpec {
                    name: "pin".into(),
                    help: String::new(),
                    kind: ArgKind::Bool,
                    required: false,
                },
                ArgSpec {
                    name: "tag".into(),
                    help: String::new(),
                    kind: ArgKind::List,
                    required: false,
                },
            ],
        }
    }

    fn describe(commands: Vec<CommandSpec>, guide: &str) -> Describe {
        Describe {
            name: "notes".into(),
            version: "1".into(),
            resources: vec!["notes".into()],
            guide: guide.into(),
            commands,
        }
    }

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn arguments_are_held_to_what_the_command_declares() {
        let s = spec();
        let ok = check_args(
            &s,
            &args(serde_json::json!({"text": "hi", "tag": ["a"], "pin": null})),
        )
        .unwrap();
        assert_eq!(ok, args(serde_json::json!({"text": "hi", "tag": ["a"]})));
        for (bad, says) in [
            (serde_json::json!({}), "needs --text"),
            (serde_json::json!({"text": "hi", "x": 1}), "takes no --x"),
            (serde_json::json!({"text": 3}), "--text must be a string"),
            (
                serde_json::json!({"text": "hi", "tag": [1]}),
                "a list of strings",
            ),
            (
                serde_json::json!({"text": "hi", "pin": "yes"}),
                "true or false",
            ),
        ] {
            let e = check_args(&s, &args(bad.clone())).unwrap_err();
            assert!(e.contains(says), "{bad}: {e}");
        }
    }

    #[test]
    fn a_describe_is_held_to_the_configuration_and_to_its_own_resources() {
        let declared = vec!["notes".to_string()];
        assert!(check_describe(
            &describe(vec![spec()], "Notes: [notes:write]"),
            "notes",
            &declared
        )
        .is_ok());
        let cases: Vec<(Describe, &str)> = vec![
            (describe(vec![spec()], ""), "no guide"),
            (
                describe(vec![spec()], "merge with [pr:merge]"),
                "[pr:merge]",
            ),
            (
                describe(
                    vec![CommandSpec {
                        permission: "pr:merge".into(),
                        ..spec()
                    }],
                    "x",
                ),
                "must be one of its resources",
            ),
            (
                describe(
                    vec![
                        CommandSpec {
                            name: "note".into(),
                            ..spec()
                        },
                        spec(),
                    ],
                    "x",
                ),
                "overlap",
            ),
            (
                describe(
                    vec![CommandSpec {
                        name: "Note Add".into(),
                        ..spec()
                    }],
                    "x",
                ),
                "lower-case",
            ),
        ];
        for (d, says) in cases {
            let e = check_describe(&d, "notes", &declared).unwrap_err();
            assert!(e.contains(says), "{e}");
        }
        let mut wider = describe(vec![], "x");
        wider.resources.push("s3".into());
        assert!(check_describe(&wider, "notes", &declared)
            .unwrap_err()
            .contains("does not list"));
        assert!(check_describe(&describe(vec![], "x"), "other", &declared)
            .unwrap_err()
            .contains("names itself"));
    }
}
