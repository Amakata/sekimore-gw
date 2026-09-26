//! The Docker side of `sgw`: finding the stack's containers and running things in them.
//!
//! Everything goes through the `docker` CLI (the one requirement on the host), by
//! `std::process::Command`. The container of a service is found by the compose labels, the way
//! `sgw.sh` did: the service name and the project's working directory, which is this project's
//! `.devcontainer/`. The project *name* depends on the folder name, so it is not used to find
//! anything.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context};

use crate::i18n::tf;

pub const GATEWAY: &str = "sekimore-gw";
pub const DEV: &str = "dev";

/// The terminal decision for a `docker exec` (#230, #50 of the base).
///
/// `-t` only when both ends are the person's terminal: an interactive shell needs it, and output
/// piped on (`sgw check | sed`) must not get the carriage returns a pty adds. A command that
/// reads a passphrase or a yes/no is `Interactive`: it needs `-t` whenever stdin is a terminal,
/// stdout piped or not, and refuses a piped stdin. `Never` is `--no-tty`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tty {
    Auto,
    Interactive,
    Never,
}

/// `-it` or `-i`, from the mode and the two ends. `None` when an interactive command has no
/// terminal on stdin.
pub fn tty_flag(mode: Tty, stdin_tty: bool, stdout_tty: bool) -> Option<&'static str> {
    match mode {
        Tty::Never => Some("-i"),
        Tty::Auto => Some(if stdin_tty && stdout_tty { "-it" } else { "-i" }),
        Tty::Interactive => stdin_tty.then_some("-it"),
    }
}

/// The colour variables handed to the relay inside the container.
///
/// An explicit `SEKIMORE_COLOR` from the caller wins; otherwise the relay is told to colour when
/// a person is watching (stdout a terminal, `NO_COLOR` unset). `NO_COLOR` is handed through when
/// it is set. Decided here on the host, because inside `docker exec` the relay cannot see whether
/// the host's stdout is a terminal.
pub fn color_env(
    stdout_tty: bool,
    sekimore_color: Option<&str>,
    no_color: Option<&str>,
) -> Vec<(String, String)> {
    let mut env = Vec::new();
    if let Some(v) = sekimore_color {
        env.push(("SEKIMORE_COLOR".to_string(), v.to_string()));
    } else if stdout_tty && no_color.is_none() {
        env.push(("SEKIMORE_COLOR".to_string(), "always".to_string()));
    }
    if let Some(v) = no_color {
        env.push(("NO_COLOR".to_string(), v.to_string()));
    }
    env
}

/// compose's `-f` / `--env-file` arguments for a stack, from the labels of a running container.
///
/// Dev Containers layers several compose files (the project's, the relay overlay, its own
/// generated one), and `up --force-recreate` with one of them missing drops that overlay: without
/// the relay one, the agent socket mount goes. So every file the container was created with is
/// named again (the `config_files` label, relative paths against the working directory), the
/// relay overlay is always added when it exists (a container recreated without it in the past has
/// it in no label), and files that do not exist are skipped.
pub fn compose_args(
    working_dir: &Path,
    config_files: &str,
    env_file: &str,
    exists: impl Fn(&Path) -> bool,
) -> Vec<String> {
    let mut files: Vec<PathBuf> = Vec::new();
    fn add(files: &mut Vec<PathBuf>, exists: &impl Fn(&Path) -> bool, p: PathBuf) {
        if exists(&p) && !files.contains(&p) {
            files.push(p);
        }
    }
    for c in config_files
        .split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        let p = Path::new(c);
        let full = if p.is_absolute() {
            p.to_path_buf()
        } else {
            working_dir.join(p)
        };
        add(&mut files, &exists, full);
    }
    if files.is_empty() {
        add(&mut files, &exists, working_dir.join("docker-compose.yml"));
    }
    add(
        &mut files,
        &exists,
        working_dir.join("docker-compose.relay.yml"),
    );
    let mut args: Vec<String> = files
        .iter()
        .flat_map(|f| ["-f".to_string(), f.display().to_string()])
        .collect();
    if !env_file.is_empty() && exists(Path::new(env_file)) {
        args.push("--env-file".into());
        args.push(env_file.to_string());
    }
    args
}

/// The host port a container publishes for `cport`, out of `docker port`'s first line
/// (`0.0.0.0:8091` or `[::]:8091`).
pub fn parse_port(docker_port_output: &str) -> Option<u16> {
    let first = docker_port_output.lines().next()?.trim();
    first.rsplit(':').next()?.parse().ok()
}

/// What a captured `docker exec` gave back.
pub struct Captured {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub struct Docker {
    bin: String,
    pub compose_dir: PathBuf,
}

impl Docker {
    pub fn new(compose_dir: PathBuf) -> Self {
        Docker {
            bin: "docker".to_string(),
            compose_dir,
        }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(&self.bin);
        // The Docker CLI's "What's next: Try Docker Debug…" hint after `docker exec` landed in
        // the middle of relay:verify's output (base #102)
        c.env("DOCKER_CLI_HINTS", "false");
        c
    }

    /// Runs docker with the output captured; the error carries stderr.
    fn out(&self, args: &[&str]) -> anyhow::Result<String> {
        let o = self
            .cmd()
            .args(args)
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("run {} {}", self.bin, args.join(" ")))?;
        if !o.status.success() {
            bail!(
                "{} {} failed: {}",
                self.bin,
                args.join(" "),
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    }

    /// Runs docker with the terminal inherited; the exit status is the result.
    pub fn run(&self, args: &[String]) -> anyhow::Result<i32> {
        let st = self
            .cmd()
            .args(args)
            .status()
            .with_context(|| format!("run {} {}", self.bin, args.join(" ")))?;
        Ok(st.code().unwrap_or(1))
    }

    fn working_dir_filter(&self) -> String {
        format!(
            "label=com.docker.compose.project.working_dir={}",
            self.compose_dir.display()
        )
    }

    /// The one running container of `service` in this project's stack.
    ///
    /// By the working-directory label first; when that matches nothing (path normalisation can
    /// differ), by the service name alone when it is unique. None is an error that lists what
    /// exists for the service, stopped ones included; several is an error that lists them with
    /// their working directories.
    pub fn find_container(&self, service: &str) -> anyhow::Result<String> {
        let svc = format!("label=com.docker.compose.service={service}");
        let mut ids = self.out(&[
            "ps",
            "-q",
            "--filter",
            &self.working_dir_filter(),
            "--filter",
            &svc,
        ])?;
        if ids.trim().is_empty() {
            ids = self.out(&["ps", "-q", "--filter", &svc])?;
        }
        let ids: Vec<&str> = ids
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        match ids.len() {
            1 => Ok(ids[0].to_string()),
            0 => {
                let listing = self
                    .out(&[
                        "ps",
                        "-a",
                        "--format",
                        "  {{.Names}}  {{.Status}}  ({{.Image}})",
                        "--filter",
                        &svc,
                    ])
                    .unwrap_or_default();
                bail!(
                    "{}{}",
                    tf(
                        "sgw.none",
                        &[
                            ("service", service),
                            ("dir", &self.compose_dir.display().to_string())
                        ]
                    ),
                    if listing.trim().is_empty() {
                        String::new()
                    } else {
                        format!("\n{}", listing.trim_end())
                    }
                )
            }
            _ => {
                let listing = self
                    .out(&[
                        "ps",
                        "--format",
                        "  {{.Names}}  {{.Label \"com.docker.compose.project.working_dir\"}}",
                        "--filter",
                        &svc,
                    ])
                    .unwrap_or_default();
                bail!(
                    "{}\n{}",
                    tf("sgw.several", &[("service", service)]),
                    listing.trim_end()
                )
            }
        }
    }

    /// `docker exec` with the terminal decided here. `env` is handed in as `-e`.
    pub fn exec(
        &self,
        cid: &str,
        user: Option<&str>,
        tty: Tty,
        env: &[(String, String)],
        argv: &[String],
    ) -> anyhow::Result<i32> {
        let flag = match tty_flag(
            tty,
            std::io::stdin().is_terminal(),
            std::io::stdout().is_terminal(),
        ) {
            Some(f) => f,
            None => bail!(tf("sgw.needs_tty", &[("cmd", &argv.join(" "))])),
        };
        let mut args: Vec<String> = vec!["exec".into(), flag.into()];
        if let Some(u) = user {
            args.push("-u".into());
            args.push(u.into());
        }
        for (k, v) in env {
            args.push("-e".into());
            args.push(format!("{k}={v}"));
        }
        args.push(cid.into());
        args.extend(argv.iter().cloned());
        self.run(&args)
    }

    /// `docker exec -i` with `input` on the command's stdin and nothing else: the way a
    /// passphrase travels (`unlock --stdin`). It is never an argument and never an environment
    /// variable; it goes down this pipe and nowhere else.
    pub fn exec_with_stdin(&self, cid: &str, argv: &[String], input: &[u8]) -> anyhow::Result<i32> {
        let mut args: Vec<String> = vec!["exec".into(), "-i".into(), cid.into()];
        args.extend(argv.iter().cloned());
        let mut child = self
            .cmd()
            .args(&args)
            .stdin(Stdio::piped())
            .spawn()
            .with_context(|| format!("run {} exec", self.bin))?;
        {
            let mut stdin = child.stdin.take().context("no stdin on docker exec")?;
            // A relay that refuses before reading (store not initialised, wrong state) closes
            // its end first; the exit status below says what happened, EPIPE would not
            let _ = stdin.write_all(input);
        }
        let st = child.wait()?;
        Ok(st.code().unwrap_or(1))
    }

    /// `docker exec -i` with both outputs captured and stdin closed: for `verify`, which reads
    /// answers rather than showing a terminal.
    pub fn exec_capture(
        &self,
        cid: &str,
        user: Option<&str>,
        argv: &[String],
    ) -> anyhow::Result<Captured> {
        let mut args: Vec<String> = vec!["exec".into(), "-i".into()];
        if let Some(u) = user {
            args.push("-u".into());
            args.push(u.into());
        }
        args.push(cid.into());
        args.extend(argv.iter().cloned());
        let o = self
            .cmd()
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("run {} exec", self.bin))?;
        Ok(Captured {
            code: o.status.code().unwrap_or(1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        })
    }

    /// The gateway address of a Docker network (the bridge's `.1`), or None.
    pub fn network_gateway(&self, network: &str) -> Option<String> {
        let out = self
            .out(&[
                "network",
                "inspect",
                "-f",
                "{{(index .IPAM.Config 0).Gateway}}",
                network,
            ])
            .ok()?;
        let s = out.trim().to_string();
        (!s.is_empty() && s != "<no value>").then_some(s)
    }

    pub fn inspect(&self, cid: &str, format: &str) -> anyhow::Result<String> {
        Ok(self
            .out(&["inspect", "-f", format, cid])?
            .trim()
            .to_string())
    }

    pub fn label(&self, cid: &str, key: &str) -> anyhow::Result<String> {
        self.inspect(cid, &format!("{{{{index .Config.Labels \"{key}\"}}}}"))
    }

    /// The host port `service` publishes for `cport`, asked of the running container rather
    /// than the compose file: a project moves the published port when 8090 is taken, and a
    /// number written down drifts the moment that happens.
    pub fn port(&self, service: &str, cport: u16) -> anyhow::Result<u16> {
        let cid = self.find_container(service)?;
        let out = self
            .out(&["port", &cid, &cport.to_string()])
            .unwrap_or_default();
        parse_port(&out).ok_or_else(|| {
            anyhow::anyhow!(tf(
                "sgw.no_port",
                &[("service", service), ("port", &cport.to_string())]
            ))
        })
    }

    pub fn ps(&self) -> anyhow::Result<i32> {
        self.run(&[
            "ps".into(),
            "--format".into(),
            "table {{.Names}}\t{{.Status}}\t{{.Image}}".into(),
            "--filter".into(),
            self.working_dir_filter(),
        ])
    }

    /// Any container of this stack, stopped ones included, by the working-directory label alone
    /// (never another project's). None when the stack has nothing at all.
    fn stack_container(&self) -> anyhow::Result<Option<String>> {
        let ids = self.out(&["ps", "-a", "-q", "--filter", &self.working_dir_filter()])?;
        Ok(ids
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .map(str::to_string))
    }

    /// `docker compose down --remove-orphans` for the whole stack, dev container included.
    ///
    /// The project name and files come from a container's labels when the stack has one, even
    /// stopped: that is the case this exists for, a start that fails with "network … already
    /// exists" because the previous containers still hold it, when `find_container` (running
    /// ones only) sees nothing. With no container at all, the name is what Dev Containers would
    /// have used (`fallback_project`) and the files are those in the compose directory.
    pub fn down(&self, fallback_project: &str) -> anyhow::Result<i32> {
        let wd = self.compose_dir.display().to_string();
        let (proj, wd, cfgs, envfile) = match self.stack_container()? {
            Some(cid) => (
                self.label(&cid, "com.docker.compose.project")?,
                self.label(&cid, "com.docker.compose.project.working_dir")?,
                self.label(&cid, "com.docker.compose.project.config_files")?,
                self.label(&cid, "com.docker.compose.project.environment_file")?,
            ),
            None => (
                fallback_project.to_string(),
                wd,
                String::new(),
                String::new(),
            ),
        };
        let fargs = compose_args(Path::new(&wd), &cfgs, &envfile, |p| p.is_file());
        println!("project={proj}");
        println!("compose: {}", fargs.join(" "));
        let mut args: Vec<String> = vec![
            "compose".into(),
            "-p".into(),
            proj,
            "--project-directory".into(),
            wd,
        ];
        args.extend(fargs);
        args.extend(["down".into(), "--remove-orphans".into()]);
        self.run(&args)
    }

    /// The compose project of the gateway's container, for `docker compose -p`.
    pub fn compose_project(&self) -> anyhow::Result<String> {
        let cid = self.find_container(GATEWAY)?;
        self.label(&cid, "com.docker.compose.project")
    }

    /// Pull the image compose declares for the gateway and recreate the container on it
    /// (`docker restart` keeps the old image). Waits until the Web UI answers.
    pub fn recreate_gateway(&self) -> anyhow::Result<()> {
        let cid = self.find_container(GATEWAY)?;
        let running = self.inspect(&cid, "{{.Config.Image}}")?;
        let proj = self.label(&cid, "com.docker.compose.project")?;
        let wd = self.label(&cid, "com.docker.compose.project.working_dir")?;
        let cfgs = self.label(&cid, "com.docker.compose.project.config_files")?;
        let envfile = self.label(&cid, "com.docker.compose.project.environment_file")?;
        let fargs = compose_args(Path::new(&wd), &cfgs, &envfile, |p| p.is_file());
        let mut compose: Vec<String> = vec![
            "compose".into(),
            "-p".into(),
            proj.clone(),
            "--project-directory".into(),
            wd.clone(),
        ];
        compose.extend(fargs.iter().cloned());
        // What is pulled is the image compose declares: right after a tag bump it is newer than
        // the running container's. Where compose config is unavailable, the running image
        let mut cfg: Vec<String> = compose.clone();
        cfg.extend(["config".into(), "--images".into(), GATEWAY.into()]);
        let cfg_refs: Vec<&str> = cfg.iter().map(String::as_str).collect();
        let declared = self
            .out(&cfg_refs)
            .ok()
            .and_then(|o| o.lines().next().map(|l| l.trim().to_string()))
            .filter(|s| !s.is_empty());
        let image = declared.unwrap_or_else(|| running.clone());
        if image != running {
            println!("gateway: {running} → {image} (project={proj})");
        } else {
            println!("gateway: {image} (project={proj})");
        }
        println!("compose: {}", fargs.join(" "));
        println!("before:  {}", self.inspect(&cid, "{{.Image}}")?);
        let rc = self.run(&["pull".into(), image.clone()])?;
        if rc != 0 {
            bail!("docker pull {image} failed");
        }
        let mut up = compose.clone();
        up.extend([
            "up".into(),
            "-d".into(),
            "--force-recreate".into(),
            GATEWAY.into(),
        ]);
        let rc = self.run(&up)?;
        if rc != 0 {
            bail!("docker compose up failed");
        }
        let new = self.find_container(GATEWAY)?;
        println!("after:   {}", self.inspect(&new, "{{.Image}}")?);
        print!("{}", crate::i18n::t("sgw.waiting"));
        std::io::stdout().flush().ok();
        for _ in 0..30 {
            // the gateway has no curl; python is always there
            let probe = self
                .cmd()
                .args([
                    "exec",
                    &new,
                    "python",
                    "-c",
                    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/config', timeout=3)",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if matches!(probe, Ok(s) if s.success()) {
                println!(" ok");
                break;
            }
            print!(".");
            std::io::stdout().flush().ok();
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        println!("{}", crate::i18n::t("sgw.recreated"));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_terminal_at_both_ends_gets_a_pty_and_a_pipe_does_not() {
        assert_eq!(tty_flag(Tty::Auto, true, true), Some("-it"));
        assert_eq!(
            tty_flag(Tty::Auto, true, false),
            Some("-i"),
            "piped on: no carriage returns"
        );
        assert_eq!(tty_flag(Tty::Auto, false, true), Some("-i"));
        assert_eq!(tty_flag(Tty::Never, true, true), Some("-i"));
    }

    #[test]
    fn a_command_that_reads_input_needs_stdin_to_be_a_terminal_and_nothing_else() {
        // #230: the passphrase and the yes/no are typed; stdout may well be a pipe
        assert_eq!(tty_flag(Tty::Interactive, true, false), Some("-it"));
        assert_eq!(tty_flag(Tty::Interactive, true, true), Some("-it"));
        assert_eq!(tty_flag(Tty::Interactive, false, true), None);
    }

    #[test]
    fn colour_is_told_to_the_relay_when_a_person_is_watching() {
        assert_eq!(
            color_env(true, None, None),
            vec![("SEKIMORE_COLOR".to_string(), "always".to_string())]
        );
        assert_eq!(color_env(false, None, None), vec![]);
        assert_eq!(
            color_env(true, None, Some("1")),
            vec![("NO_COLOR".to_string(), "1".to_string())],
            "NO_COLOR wins over the terminal"
        );
        assert_eq!(
            color_env(false, Some("never"), None),
            vec![("SEKIMORE_COLOR".to_string(), "never".to_string())],
            "an explicit SEKIMORE_COLOR is handed through as it is"
        );
    }

    #[test]
    fn compose_args_keep_every_overlay_and_skip_what_does_not_exist() {
        let wd = Path::new("/p/.devcontainer");
        let existing = [
            "/p/.devcontainer/docker-compose.yml",
            "/p/.devcontainer/docker-compose.relay.yml",
            "/Users/me/Library/Application Support/Code/docker-compose.devcontainer.yml",
            "/p/.devcontainer/.env",
        ];
        let exists = |p: &Path| existing.contains(&p.to_str().unwrap());
        let args = compose_args(
            wd,
            "docker-compose.yml,docker-compose.relay.yml,/Users/me/Library/Application Support/Code/docker-compose.devcontainer.yml,gone.yml",
            "/p/.devcontainer/.env",
            exists,
        );
        assert_eq!(
            args,
            vec![
                "-f",
                "/p/.devcontainer/docker-compose.yml",
                "-f",
                "/p/.devcontainer/docker-compose.relay.yml",
                "-f",
                "/Users/me/Library/Application Support/Code/docker-compose.devcontainer.yml",
                "--env-file",
                "/p/.devcontainer/.env",
            ]
        );
        // a container recreated in the past without the overlay has it in no label: still added
        let args = compose_args(wd, "docker-compose.yml", "", exists);
        assert_eq!(
            args,
            vec![
                "-f",
                "/p/.devcontainer/docker-compose.yml",
                "-f",
                "/p/.devcontainer/docker-compose.relay.yml",
            ]
        );
        // no label at all: the project's file
        let args = compose_args(wd, "", "", exists);
        assert_eq!(args[1], "/p/.devcontainer/docker-compose.yml");
        // an env file that does not exist is not named
        let args = compose_args(wd, "docker-compose.yml", "/nowhere/.env", exists);
        assert!(!args.contains(&"--env-file".to_string()));
    }

    #[test]
    fn the_host_port_comes_out_of_docker_ports_first_line() {
        assert_eq!(parse_port("0.0.0.0:8091\n[::]:8091\n"), Some(8091));
        assert_eq!(parse_port("[::]:8080"), Some(8080));
        assert_eq!(parse_port(""), None);
    }
}
