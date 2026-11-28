//! Ask the path ledger (docs/paths.yml) questions, or draw it (#223).
//!
//! ```text
//! paths edges                       every edge, one line each
//! paths edges --switch direct_egress
//! paths edges --without verify      edges no relay:verify item probes
//! paths paths dev internet          every simple path, with the mediating nodes
//! paths secret upstream_proxy_password
//! paths dot | dot -Tsvg > paths.svg  Graphviz
//! ```
//!
//! `--ledger FILE` (before the command) reads another ledger. The rules live in
//! tools/tests/paths_ledger.rs; this is for looking.

use std::path::PathBuf;
use std::process::ExitCode;

use sekimore_tools::ledger;

const USAGE: &str = "usage: paths [--ledger FILE] {edges,paths,secret,dot} ...

  edges [--switch SWITCH] [--without {verify,check,tests,audit}] [-v]
  paths SRC DST [--blocked]     include the edges that must not work with --blocked
  secret NAME
  dot";

enum Cmd {
    Edges {
        switch: Option<String>,
        without: Option<String>,
        verbose: bool,
    },
    Paths {
        src: String,
        dst: String,
        blocked: bool,
    },
    Secret(String),
    Dot,
}

fn parse(argv: &[String]) -> Result<(Option<PathBuf>, Cmd), String> {
    let mut ledger_path = None;
    let mut positional: Vec<String> = Vec::new();
    let (mut switch, mut without, mut verbose, mut blocked) = (None, None, false, false);
    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (arg.as_str(), None),
        };
        let mut value = || {
            inline
                .clone()
                .or_else(|| it.next().cloned())
                .ok_or_else(|| format!("argument {flag}: expected one argument"))
        };
        match flag {
            "--ledger" if positional.is_empty() => ledger_path = Some(PathBuf::from(value()?)),
            "--switch" => switch = Some(value()?),
            "--without" => {
                let w = value()?;
                if !["verify", "check", "tests", "audit"].contains(&w.as_str()) {
                    return Err(format!(
                        "argument --without: invalid choice: '{w}' (choose from 'verify', 'check', 'tests', 'audit')"
                    ));
                }
                without = Some(w);
            }
            "-v" | "--verbose" => verbose = true,
            "--blocked" => blocked = true,
            "-h" | "--help" => return Err(String::new()),
            f if f.starts_with('-') && f.len() > 1 => {
                return Err(format!("unrecognized arguments: {f}"))
            }
            _ => positional.push(arg.clone()),
        }
    }
    let cmd = positional.first().map(String::as_str);
    let rest = positional.get(1..).unwrap_or_default();
    let c = match (cmd, rest) {
        (Some("edges"), []) => Cmd::Edges {
            switch: switch.clone(),
            without: without.clone(),
            verbose,
        },
        (Some("paths"), [src, dst]) => Cmd::Paths {
            src: src.clone(),
            dst: dst.clone(),
            blocked,
        },
        (Some("secret"), [name]) => Cmd::Secret(name.clone()),
        (Some("dot"), []) => Cmd::Dot,
        (Some(c @ ("edges" | "paths" | "secret" | "dot")), _) => {
            return Err(format!("{c}: wrong number of arguments"))
        }
        (Some(c), _) => {
            return Err(format!(
            "argument cmd: invalid choice: '{c}' (choose from 'edges', 'paths', 'secret', 'dot')"
        ))
        }
        (None, _) => return Err("the following arguments are required: cmd".into()),
    };
    // each option belongs to one command, as argparse's subparsers had it
    if !matches!(c, Cmd::Edges { .. }) && (switch.is_some() || without.is_some() || verbose) {
        return Err("unrecognized arguments: --switch/--without/-v".into());
    }
    if blocked && !matches!(c, Cmd::Paths { .. }) {
        return Err("unrecognized arguments: --blocked".into());
    }
    Ok((ledger_path, c))
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (path, cmd) = match parse(&argv) {
        Ok(p) => p,
        Err(e) if e.is_empty() => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("{USAGE}\npaths: error: {e}");
            return ExitCode::from(2);
        }
    };
    let path = path.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("docs")
            .join("paths.yml")
    });
    let out = ledger::load(&path).and_then(|l| match &cmd {
        Cmd::Edges {
            switch,
            without,
            verbose,
        } => ledger::cmd_edges(&l, switch.as_deref(), without.as_deref(), *verbose),
        Cmd::Paths { src, dst, blocked } => ledger::cmd_paths(&l, src, dst, *blocked),
        Cmd::Secret(name) => ledger::cmd_secret(&l, name),
        Cmd::Dot => ledger::cmd_dot(&l),
    });
    match out {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("paths: {e}");
            ExitCode::from(1)
        }
    }
}
