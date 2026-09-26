//! The command groups of `sgw`: `sgw store unlock` is `sgw unlock`.
//!
//! The commands stay flat in clap (`cli::Cmd`), which is what runs; the groups are one table
//! here, read before parsing to turn `<group> <leaf>` into the flat name, and read again to
//! print help by group. A flat name therefore keeps working as the shortcut of its grouped
//! form, and nothing is defined twice.

use crate::i18n::{t, tf};

/// One command as the operator types it inside a group.
pub struct Leaf {
    /// The name under the group (`status`)
    pub name: &'static str,
    /// The flat subcommand it runs (`store-status`)
    pub flat: &'static str,
    /// The locale key of its one-line description
    pub key: &'static str,
}

pub struct Group {
    pub name: &'static str,
    /// The locale key of the group's heading
    pub key: &'static str,
    pub leaves: &'static [Leaf],
}

const fn leaf(name: &'static str, flat: &'static str, key: &'static str) -> Leaf {
    Leaf { name, flat, key }
}

/// The commands that stand on their own: a project's lifecycle.
pub const TOP: &[Leaf] = &[
    leaf("init", "init", "sgw.cmd.init"),
    leaf("update", "update", "sgw.cmd.update"),
    leaf("open", "open", "sgw.cmd.open"),
    leaf("verify", "verify", "sgw.cmd.verify"),
    leaf("check", "check", "sgw.cmd.check"),
];

pub const GROUPS: &[Group] = &[
    Group {
        name: "store",
        key: "sgw.group.store",
        leaves: &[
            leaf("unlock", "unlock", "sgw.cmd.unlock"),
            leaf("lock", "lock", "sgw.cmd.lock"),
            leaf("status", "store-status", "sgw.cmd.store_status"),
            leaf("passphrase", "passphrase", "sgw.cmd.passphrase"),
            leaf("keychain-set", "keychain-set", "sgw.cmd.keychain_set"),
            leaf("unlock-auto", "unlock-auto", "sgw.cmd.unlock_auto"),
            leaf(
                "proxy-credential",
                "proxy-credential",
                "sgw.cmd.proxy_credential",
            ),
            leaf("export", "store-export", "sgw.cmd.store_export"),
            leaf("import", "store-import", "sgw.cmd.store_import"),
        ],
    },
    Group {
        name: "github",
        key: "sgw.group.github",
        leaves: &[
            leaf("login", "login", "sgw.cmd.login"),
            leaf("logout", "logout", "sgw.cmd.logout"),
            leaf("whoami", "whoami", "sgw.cmd.whoami"),
            leaf("keyscan", "keyscan", "sgw.cmd.keyscan"),
            leaf("signing-key", "signing-key", "sgw.cmd.signing_key"),
        ],
    },
    Group {
        name: "token",
        key: "sgw.group.token",
        leaves: &[
            leaf("list", "tokens", "sgw.cmd.tokens"),
            leaf("revoke", "revoke", "sgw.cmd.revoke"),
            leaf("revoke-project", "revoke-project", "sgw.cmd.revoke_project"),
            leaf("bootstrap", "bootstrap", "sgw.cmd.bootstrap"),
        ],
    },
    Group {
        name: "gw",
        key: "sgw.group.gw",
        leaves: &[
            leaf("recreate", "recreate", "sgw.cmd.recreate"),
            leaf("restart", "restart", "sgw.cmd.restart"),
            leaf("down", "down", "sgw.cmd.down"),
            leaf("ps", "ps", "sgw.cmd.ps"),
            leaf("logs", "logs", "sgw.cmd.logs"),
            leaf("audit", "audit", "sgw.cmd.audit"),
            leaf("web", "web", "sgw.cmd.web"),
            leaf("shell", "shell", "sgw.cmd.shell"),
            leaf("relay", "relay", "sgw.cmd.relay"),
            leaf("port", "port", "sgw.cmd.port"),
            leaf("id", "id", "sgw.cmd.id"),
            leaf("project", "project", "sgw.cmd.project"),
            leaf("reload-status", "reload-status", "sgw.cmd.reload_status"),
            leaf("reload-follow", "reload-follow", "sgw.cmd.reload_follow"),
            leaf("reload-freeze", "reload-freeze", "sgw.cmd.reload_freeze"),
            leaf("db-stats", "db-stats", "sgw.cmd.db_stats"),
            leaf("db-prune", "db-prune", "sgw.cmd.db_prune"),
            leaf("db-reset", "db-reset", "sgw.cmd.db_reset"),
        ],
    },
    Group {
        name: "dev",
        key: "sgw.group.dev",
        leaves: &[
            leaf("shell", "dev", "sgw.cmd.dev.shell"),
            leaf("agent-setup", "agent-setup", "sgw.cmd.agent_setup"),
            leaf("refresh", "refresh", "sgw.cmd.refresh"),
        ],
    },
];

/// `dev` is also the flat command that runs anything in the dev container (`sgw dev cat …`),
/// so under it only a known leaf is rewritten and everything else is left to that command.
const OPEN_GROUP: &str = "dev";

pub fn group(name: &str) -> Option<&'static Group> {
    GROUPS.iter().find(|g| g.name == name)
}

/// What the argv asks for, once the groups are read.
#[derive(Debug, PartialEq, Eq)]
pub enum Rewritten {
    /// Parse these (the flat form)
    Args(Vec<String>),
    /// `sgw <group>`, `-h` or `--help`: print the group's commands, exit 0
    GroupHelp(&'static str),
    /// `sgw <group> <something else>`: print the group's commands, exit 2
    Unknown { group: &'static str, leaf: String },
}

/// The index of the subcommand in argv: after the program name and the global options that
/// may precede it (`--no-tty`, `--project DIR`, `--project=DIR`). None when there is none, or
/// when what comes first is another option (`--help`, `--version`), which clap handles.
fn command_index(argv: &[String]) -> Option<usize> {
    let mut i = 1;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--no-tty" || a.starts_with("--project=") {
            i += 1;
        } else if a == "--project" {
            i += 2;
        } else if a.starts_with('-') {
            return None;
        } else {
            return Some(i);
        }
    }
    None
}

pub fn rewrite(mut argv: Vec<String>) -> Rewritten {
    let Some(i) = command_index(&argv) else {
        return Rewritten::Args(argv);
    };
    let Some(g) = group(&argv[i]) else {
        return Rewritten::Args(argv);
    };
    match argv.get(i + 1).map(String::as_str) {
        None if g.name == OPEN_GROUP => Rewritten::Args(argv),
        None | Some("-h") | Some("--help") => Rewritten::GroupHelp(g.name),
        Some(next) => {
            if let Some(l) = g.leaves.iter().find(|l| l.name == next) {
                argv[i] = l.flat.to_string();
                argv.remove(i + 1);
                Rewritten::Args(argv)
            } else if g.name == OPEN_GROUP {
                Rewritten::Args(argv)
            } else {
                Rewritten::Unknown {
                    group: g.name,
                    leaf: next.to_string(),
                }
            }
        }
    }
}

const NAME_WIDTH: usize = 18;

fn line(name: &str, about: &str) -> String {
    format!("  {name:<NAME_WIDTH$}{about}\n")
}

/// The commands, by group, for `sgw --help`.
pub fn commands_help() -> String {
    let mut s = format!("{}\n", t("sgw.help.commands"));
    for l in TOP {
        s.push_str(&line(l.name, &t(l.key)));
    }
    for g in GROUPS {
        s.push('\n');
        s.push_str(&format!("{}  {}\n", g.name, t(g.key)));
        for l in g.leaves {
            s.push_str(&line(l.name, &t(l.key)));
        }
    }
    s.push('\n');
    s.push_str(&t("sgw.help.shortcut"));
    s.push_str("\n\n");
    s
}

/// One group's commands, for `sgw <group> --help`.
pub fn group_help(name: &str) -> String {
    let g = group(name).expect("a group of the table");
    let mut s = format!(
        "{}\n\n{}\n\n{}\n",
        tf(
            "sgw.help.group_about",
            &[("group", g.name), ("about", &t(g.key))]
        ),
        tf("sgw.help.group_usage", &[("group", g.name)]),
        t("sgw.help.commands")
    );
    for l in g.leaves {
        s.push_str(&line(l.name, &t(l.key)));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_group_and_a_leaf_become_the_flat_command() {
        assert_eq!(
            rewrite(v(&["sgw", "store", "unlock"])),
            Rewritten::Args(v(&["sgw", "unlock"]))
        );
        assert_eq!(
            rewrite(v(&["sgw", "store", "status", "--json"])),
            Rewritten::Args(v(&["sgw", "store-status", "--json"]))
        );
        assert_eq!(
            rewrite(v(&["sgw", "token", "list"])),
            Rewritten::Args(v(&["sgw", "tokens"]))
        );
        assert_eq!(
            rewrite(v(&["sgw", "gw", "relay", "check", "-v"])),
            Rewritten::Args(v(&["sgw", "relay", "check", "-v"]))
        );
        assert_eq!(
            rewrite(v(&["sgw", "dev", "shell"])),
            Rewritten::Args(v(&["sgw", "dev"]))
        );
    }

    #[test]
    fn the_globals_before_the_command_are_stepped_over() {
        assert_eq!(
            rewrite(v(&["sgw", "--project", "/p", "--no-tty", "store", "lock"])),
            Rewritten::Args(v(&["sgw", "--project", "/p", "--no-tty", "lock"]))
        );
        assert_eq!(
            rewrite(v(&["sgw", "--project=/p", "github", "whoami"])),
            Rewritten::Args(v(&["sgw", "--project=/p", "whoami"]))
        );
    }

    #[test]
    fn what_is_not_a_group_is_left_alone() {
        for a in [
            &["sgw", "unlock"][..],
            &["sgw", "--help"],
            &["sgw", "--version"],
            &["sgw"],
            &["sgw", "dev"],
            &["sgw", "dev", "cat", "/etc/hostname"],
            &["sgw", "--project", "/p"],
        ] {
            assert_eq!(rewrite(v(a)), Rewritten::Args(v(a)), "{a:?}");
        }
    }

    #[test]
    fn a_group_alone_or_with_help_asks_for_its_listing() {
        assert_eq!(rewrite(v(&["sgw", "store"])), Rewritten::GroupHelp("store"));
        assert_eq!(
            rewrite(v(&["sgw", "gw", "--help"])),
            Rewritten::GroupHelp("gw")
        );
        assert_eq!(
            rewrite(v(&["sgw", "dev", "-h"])),
            Rewritten::GroupHelp("dev")
        );
        assert_eq!(
            rewrite(v(&["sgw", "store", "foo"])),
            Rewritten::Unknown {
                group: "store",
                leaf: "foo".into()
            }
        );
    }

    #[test]
    fn every_flat_command_is_in_exactly_one_place_and_every_place_names_a_flat_command() {
        use clap::CommandFactory;
        let cmd = super::super::cli::Cli::command();
        let flat: Vec<String> = cmd
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect();
        let mut placed: Vec<&str> = TOP.iter().map(|l| l.flat).collect();
        placed.extend(GROUPS.iter().flat_map(|g| g.leaves.iter().map(|l| l.flat)));
        for f in &flat {
            let n = placed.iter().filter(|p| *p == f).count();
            assert_eq!(n, 1, "{f} is listed {n} times in the group table");
        }
        for p in &placed {
            assert!(
                flat.iter().any(|f| f == p),
                "{p} is in the table but not a subcommand"
            );
        }
        for g in GROUPS {
            assert!(
                !flat.iter().any(|f| f == g.name) || g.name == OPEN_GROUP,
                "{} is both a group and a flat command",
                g.name
            );
        }
    }
}
