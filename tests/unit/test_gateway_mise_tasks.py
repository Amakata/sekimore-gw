"""`share/gateway.mise.{en,ja}.toml` is the gateway's operator interface, and it has to stay in
step with it.

The tasks used to live in each project's own `mise.toml`, one copy per user, in a repository the
gateway does not own. They drifted: the published sample went four releases without `gw:unlock`,
and from 0.2.19 that makes the gateway unusable, because the upstream API token moved into the
secret store and a locked store means no GitHub API at all. Shipping the file in the image fixes
the copying. It does not by itself stop the file from falling behind the relay — a subcommand
added to `sekimore-relay` reaches nobody until a task points at it. That is what these tests are.

There are two files because a task's `description` is what `mise tasks` prints on the operator's
own terminal, the same reason `agent-guide.{en,ja}.md` and `README.ja.md` exist. Only the
descriptions differ, so the pair is held to one task set with identical commands: a project
picking a language must not be picking a different gateway.

The subcommand list is read out of `relay/src/cli/mod.rs` (the `Command` enum is what clap turns
into `sekimore-relay --help`) rather than by running the binary: these are the Python unit tests,
which run without a Rust build.
"""

import re
import shutil
import stat
import subprocess
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TASKS_FILES = {
    "en": ROOT / "share" / "gateway.mise.en.toml",
    "ja": ROOT / "share" / "gateway.mise.ja.toml",
}
LANGS = sorted(TASKS_FILES)
CLI_SOURCE = ROOT / "relay" / "src" / "cli" / "mod.rs"
DOCKERFILE = ROOT / "Dockerfile"
# Where the image puts them. sgw-devcontainer-base COPY --from's these paths, and a project reads
# one with `docker exec sekimore-gw cat …`, so moving them breaks both.
SHIPPED_DIR = "/usr/local/share/sekimore"

# Subcommands that deliberately have no task, and why. A reason is part of the entry: without one
# the list becomes the place where a forgotten command quietly lands.
EXCLUDED = {
    "needs-relay": "an internal probe the entrypoint runs to decide whether to start the relay",
    "serve": "the relay daemon itself, started inside the gateway by scripts/start-relay.sh",
    "agent": "agent-facing — it runs in the devcontainer as `sekimore …`, not on the host",
    "token": (
        "agent-setup's bootstrap issues the project token; by hand only with "
        "SEKIMORE_BOOTSTRAP=manual, and then `mise run gw -- token`"
    ),
    "add-key": (
        "agent-setup registers the disposable key over the bootstrap endpoint; by hand "
        "`mise run gw -- add-key …`"
    ),
    "keyscan": (
        "`login` writes known_hosts for the upstream it logs into; another host by hand is "
        "`mise run gw -- keyscan …`"
    ),
}

# The subcommands that read a passphrase from the terminal. `gw` decides on `-t` by looking at
# stdout too, and mise makes stdout a pipe, so these need sgw.sh's unconditional `gw-tty`.
NEEDS_TERMINAL = {"unlock", "passphrase"}

# The tasks that hand the relay a passphrase down a pipe instead (0.2.29). They run the same
# subcommand as an interactive task and must not be held to `gw-tty`, which refuses a pipe. Named
# one by one rather than detected from `--stdin`: a task that stopped piping and started typing
# would otherwise quietly drop out of the terminal rules above.
PIPES_THE_PASSPHRASE = {"gw:unlock-auto"}

# The one line of `gw:unlock-auto` that the passphrase is allowed to travel on. `printf` is a
# shell builtin, so the value never becomes a process argument on the way.
PASSPHRASE_SINK = 'printf \'%s\\n\' "$pass" | bash "$SGW" gw sekimore-relay unlock --stdin'

# Everything `sgw.sh` offers that these tasks are allowed to use. sgw.sh is the one file that
# cannot come from the image — it is what finds the container — so every line of it is a line each
# user has to patch by hand. A task needing a new primitive is a task that does not get shipped.
SGW_PRIMITIVES = {"gw", "gw-tty", "id", "recreate"}

# Everything of a task except the prose: this is what the two languages must agree on.
SHARED_KEYS = ("run", "raw", "dir", "depends", "env")

_ENUM_START = re.compile(r"^pub enum Command \{")
_VARIANT = re.compile(r"^    ([A-Z]\w*)\s*(?:\{|,|$)")
_EXPLICIT_NAME = re.compile(r'name\s*=\s*"([^"]+)"')
# `bash "$SGW" gw sekimore-relay unlock`, `bash "$SGW" gw-tty sekimore-relay passphrase`
_RELAY_CALL = re.compile(r"sekimore-relay(?:\s+([a-z][\w-]*))?")
_SGW_CALL = re.compile(r'"\$SGW"\s+([\w-]+)')


def _kebab(variant: str) -> str:
    """`StoreExport` → `store-export`, the way clap renames a variant by default."""
    return re.sub(r"(?<!^)(?=[A-Z])", "-", variant).lower()


def _subcommands() -> list[str]:
    """Every subcommand of `sekimore-relay`, as `--help` advertises it."""
    out: list[str] = []
    inside = False
    override: str | None = None
    for line in CLI_SOURCE.read_text(encoding="utf-8").splitlines():
        if not inside:
            inside = bool(_ENUM_START.match(line))
            continue
        if line.startswith("}"):
            break
        if line.lstrip().startswith("#["):
            m = _EXPLICIT_NAME.search(line)
            if m:
                override = m.group(1)
            continue
        m = _VARIANT.match(line)
        if m:
            out.append(override or _kebab(m.group(1)))
            override = None
    return out


def _tasks(lang: str) -> dict[str, dict]:
    """The shipped tasks. In an included task file the names are top-level tables."""
    return tomllib.loads(TASKS_FILES[lang].read_text(encoding="utf-8"))


def _covered(tasks: dict[str, dict]) -> dict[str, list[str]]:
    """subcommand → every task that runs it.

    A list, not one task: since 0.2.29 `unlock` has both an interactive task and a piped one, and
    keeping only the first would let whichever came later in the file escape the checks below.
    """
    out: dict[str, list[str]] = {}
    for name, body in tasks.items():
        for m in _RELAY_CALL.finditer(str(body.get("run", ""))):
            if m.group(1):
                out.setdefault(m.group(1), []).append(name)
    return out


def describe_gateway_mise_tasks():
    @pytest.mark.parametrize("lang", LANGS)
    def it_ships_a_task_file_that_parses(lang):
        # A rename or a move would otherwise make every test below pass by having nothing to read
        path = TASKS_FILES[lang]
        assert path.exists(), f"{path} is gone; this test is looking in the wrong place"
        assert CLI_SOURCE.exists(), f"{CLI_SOURCE} is gone; the subcommand list cannot be read"
        tasks = _tasks(lang)
        assert len(tasks) >= 20, f"only {len(tasks)} tasks parsed from {path.name}; shape changed"

    def it_finds_the_subcommands_of_the_relay():
        subs = _subcommands()
        # Anchors: if the parser silently stops matching, this is what says so rather than an
        # empty coverage check passing.
        assert len(subs) >= 15, f"only {len(subs)} subcommands parsed out of {CLI_SOURCE.name}"
        for anchor in ("unlock", "store-export", "revoke-project", "login"):
            assert anchor in subs, f"{anchor} not parsed; the enum's shape changed"

    @pytest.mark.parametrize("lang", LANGS)
    def it_has_a_task_for_every_operator_subcommand(lang):
        covered = _covered(_tasks(lang))
        missing = [s for s in _subcommands() if s not in covered and s not in EXCLUDED]
        assert missing == [], (
            f"`sekimore-relay` has subcommands that {TASKS_FILES[lang].name} does not: "
            f'{missing}. Add a task (`bash "$SGW" gw sekimore-relay <name>`, or `gw-tty` when it '
            "reads a passphrase), or put the name in EXCLUDED here with the reason it is not an "
            "operator command. A project only gets what this file ships."
        )

    def it_keeps_the_exclusions_real():
        # An exclusion for a subcommand that no longer exists hides the next one that does.
        subs = set(_subcommands())
        stale = sorted(name for name in EXCLUDED if name not in subs)
        assert stale == [], f"EXCLUDED names subcommands the relay no longer has: {stale}"

    @pytest.mark.parametrize("lang", LANGS)
    def it_runs_no_subcommand_the_relay_does_not_have(lang):
        subs = set(_subcommands())
        unknown = sorted(s for s in _covered(_tasks(lang)) if s not in subs)
        assert unknown == [], (
            f"{TASKS_FILES[lang].name} calls subcommands `sekimore-relay --help` does not list: "
            f"{unknown}. Renamed or removed in the relay, and the task was left behind."
        )

    @pytest.mark.parametrize("lang", LANGS)
    def it_reads_passphrases_through_gw_tty(lang):
        # The plain `gw` looks at stdout as well when it decides on `docker exec -t`, and mise
        # makes stdout a pipe. The prompt then has no terminal — which is how gw:unlock breaks.
        tasks = _tasks(lang)
        covered = _covered(tasks)
        typed = [
            name
            for sub in NEEDS_TERMINAL
            for name in covered.get(sub, [])
            if name not in PIPES_THE_PASSPHRASE
        ]
        assert typed, f"no task types a passphrase in {TASKS_FILES[lang].name}; the shape changed"
        wrong = [n for n in typed if "gw-tty" not in str(tasks[n].get("run", ""))]
        assert wrong == [], f"reads a passphrase but does not use `gw-tty`: {wrong}"
        raw = [n for n in typed if not tasks[n].get("raw")]
        assert raw == [], (
            f"needs `raw = true` so mise does not sit between the prompt and the terminal: {raw}"
        )

    @pytest.mark.parametrize("lang", LANGS)
    def it_uses_only_the_primitives_sgw_already_has(lang):
        # sgw.sh cannot be shipped in the image, so anything new there has to be patched into
        # every user's copy by hand — the failure this whole file exists to stop.
        unknown = sorted(
            {
                sub
                for body in _tasks(lang).values()
                for sub in _SGW_CALL.findall(str(body.get("run", "")))
                if sub not in SGW_PRIMITIVES
            }
        )
        assert unknown == [], (
            f"{TASKS_FILES[lang].name} calls sgw.sh subcommands outside "
            f"{sorted(SGW_PRIMITIVES)}: {unknown}. Every project's sgw.sh would have to be edited "
            "by hand for these to work."
        )

    @pytest.mark.parametrize("lang", LANGS)
    def it_is_written_as_an_included_task_file(lang):
        # mise rejects `[tasks."gw:unlock"]` in a file listed under `task_config.includes` with
        # `unknown field`. The names are top-level tables here, and only there does it load.
        sections = [
            f"{n}: {line}"
            for n, line in enumerate(TASKS_FILES[lang].read_text(encoding="utf-8").splitlines(), 1)
            if line.startswith("[tasks")
        ]
        assert sections == [], (
            'an included task file names the tasks as top-level tables (`["gw:unlock"]`); '
            f"mise refuses a `[tasks.…]` section in one: {TASKS_FILES[lang].name} {sections}"
        )
        for name, task in _tasks(lang).items():
            assert isinstance(task, dict), f"{name} is not a table"
            assert task.get("run"), f"{name} has no `run`"
            assert task.get("description"), (
                f"{name} has no description; `mise tasks` lists it blank"
            )

    @pytest.mark.parametrize("task", sorted(_tasks("en")))
    def it_names_the_gateway_tasks_consistently(task):
        assert task == "gw" or task.startswith("gw:"), (
            f"{task} is not a `gw:*` task. This file is the gateway's interface; a project's own "
            "tasks stay in the project's mise.toml, where the names do not collide."
        )

    def it_ships_the_same_task_set_in_both_languages():
        # One language gaining or losing a task is the drift this whole change is about, moved
        # inside the repository. Which file a project includes must not change what it can run.
        en, ja = _tasks("en"), _tasks("ja")
        only_en = sorted(set(en) - set(ja))
        only_ja = sorted(set(ja) - set(en))
        assert (only_en, only_ja) == ([], []), (
            f"the two task files disagree: only in {TASKS_FILES['en'].name}: {only_en}; "
            f"only in {TASKS_FILES['ja'].name}: {only_ja}. A task belongs in both, or neither."
        )

    @pytest.mark.parametrize("task", sorted(_tasks("en")))
    def it_runs_the_same_command_in_both_languages(task):
        en, ja = _tasks("en"), _tasks("ja")
        if task not in ja:
            pytest.skip("the task set itself disagrees; it_ships_the_same_task_set reports it")
        differing = {
            key: (en[task].get(key), ja[task].get(key))
            for key in SHARED_KEYS
            if en[task].get(key) != ja[task].get(key)
        }
        assert differing == {}, (
            f"{task} does more than read differently between the two files: {differing}. Only "
            "`description` may differ — everything else is the gateway's behaviour."
        )

    @pytest.mark.parametrize("task", sorted(_tasks("en")))
    def it_translates_every_description(task):
        en, ja = _tasks("en"), _tasks("ja")
        if task not in ja:
            pytest.skip("the task set itself disagrees; it_ships_the_same_task_set reports it")
        english, japanese = en[task]["description"], ja[task]["description"]
        assert english.isascii(), (
            f"{task}: the English file's description is not English: {english!r}"
        )
        assert not japanese.isascii(), (
            f"{task}: the Japanese file still carries the English description ({japanese!r}). "
            "`mise tasks` would print the listing half in each language."
        )

    def it_is_shipped_in_the_image():
        # Being in the repository is not enough: `docker exec sekimore-gw cat <path>` is how a
        # project gets the file, and sgw-devcontainer-base COPY --from's the same path.
        body = DOCKERFILE.read_text(encoding="utf-8")
        for lang, path in TASKS_FILES.items():
            line = f"COPY share/{path.name} {SHIPPED_DIR}/{path.name}"
            assert line in body, (
                f"the Dockerfile does not copy the {lang} task file to {SHIPPED_DIR}, so the "
                "image does not carry it and a project has nothing to include"
            )

    @pytest.mark.parametrize("lang", LANGS)
    def it_tells_the_project_what_it_has_to_provide(lang):
        # The file cannot set SGW (the path is the project's), and the tasks that read a
        # passphrase need a `gw-tty` that old copies of sgw.sh do not have. Both have to be said
        # in the file, because the file is all a project sees.
        path = TASKS_FILES[lang]
        head = path.read_text(encoding="utf-8").split("\n\n")[0]
        assert "SGW" in head, f"{path.name}: the header does not say the project must set SGW"
        assert "gw-tty" in head, f"{path.name}: the header does not say sgw.sh needs gw-tty"
        assert f"{SHIPPED_DIR}/{path.name}" in head, (
            f"{path.name}: the header does not say where the image keeps this file"
        )


def describe_the_unattended_unlock():
    """`gw:unlock-auto` and `gw:keychain-set` (0.2.29).

    The host reads the passphrase and pipes it in; the gateway is unchanged. Two things can go
    wrong quietly and neither shows up in a manual test: the passphrase reaching a command line
    (where `ps` has it for as long as the command runs), and one of the two task files shipping
    the feature while the other does not.
    """

    @pytest.mark.parametrize("lang", LANGS)
    def it_ships_both_new_tasks(lang):
        tasks = _tasks(lang)
        for name in ("gw:unlock-auto", "gw:keychain-set"):
            assert name in tasks, (
                f"{TASKS_FILES[lang].name} has no {name}; a project that includes this file "
                "cannot unlock without a person"
            )

    def it_keeps_the_interactive_unlock_as_it_was():
        # The piped path is an addition. Someone with no passphrase stored, or a store that has
        # never been initialised, still types it at a terminal.
        en = _tasks("en")["gw:unlock"]
        assert en["run"] == 'bash "$SGW" gw-tty sekimore-relay unlock'
        assert en.get("raw") is True

    @pytest.mark.parametrize("lang", LANGS)
    def it_moves_the_passphrase_only_down_the_pipe(lang):
        # An argument is readable in `ps` by every other user on the host for as long as the
        # command runs, and lands in shell history when it is typed. The value is allowed on one
        # line of the script, and that line is a pipe into a builtin.
        run = _tasks(lang)["gw:unlock-auto"]["run"]
        assert PASSPHRASE_SINK in run, (
            f"{TASKS_FILES[lang].name}: gw:unlock-auto no longer pipes the passphrase in the way "
            f"this test can check: expected a line {PASSPHRASE_SINK!r}"
        )
        carrying = [
            line.strip()
            for line in run.splitlines()
            if '"$pass"' in line and not line.strip().startswith("#")
        ]
        emptiness = re.compile(r'^if \[ -[nz] "\$pass" \]')
        stray = [line for line in carrying if line != PASSPHRASE_SINK and not emptiness.match(line)]
        assert stray == [], (
            f"the passphrase is used somewhere other than the pipe and the emptiness tests: {stray}"
        )
        assert "export pass" not in run, "an exported passphrase is readable in /proc/<pid>/environ"

    @pytest.mark.parametrize("lang", LANGS)
    def it_tries_the_three_host_sources_in_order(lang):
        run = _tasks(lang)["gw:unlock-auto"]["run"]
        order = [
            run.index("security find-generic-password"),
            run.index("secret-tool lookup"),
            run.index("systemd-creds decrypt"),
        ]
        assert order == sorted(order), (
            "the sources are tried out of order. The machine-bound ones come first; the plain "
            f"file is the weakest and is last: {order}"
        )

    @pytest.mark.parametrize("lang", LANGS)
    def it_prompts_for_the_new_passphrase_on_the_operators_terminal(lang):
        # Same reason as gw:unlock: mise prefixes output, so without `raw` the backend's own
        # echo-off prompt has a pipe where it expects a terminal.
        assert _tasks(lang)["gw:keychain-set"].get("raw") is True, (
            "gw:keychain-set reads a passphrase and needs `raw = true`"
        )


def describe_the_host_side_shell():
    """`gw:unlock-auto` and `gw:recreate`, run for real against stand-in backends.

    Host-side shell is the part of this feature no CI machine has the real thing for: there is no
    Keychain on Linux and no desktop Secret Service on a runner. Standing the backends in as
    scripts on PATH is enough to check the part that is ours — which source wins, that the value
    arrives on the relay's stdin and not in its arguments, and that a host with nothing stored is
    not a failure.
    """

    # Everything outside the sandbox bin is off PATH, so a runner that happens to have
    # `secret-tool` installed does not change what these tests exercise.
    real_tools = ("bash", "basename", "cat", "env")

    def _sandbox(tmp_path, **fakes):
        binn = tmp_path / "bin"
        binn.mkdir()
        for tool in real_tools:
            found = shutil.which(tool)
            assert found, f"{tool} is not on PATH; this test needs it"
            (binn / tool).symlink_to(found)
        for name, body in fakes.items():
            f = binn / name
            f.write_text(body)
            f.chmod(f.stat().st_mode | stat.S_IEXEC)
        return binn

    def _run(tmp_path, *, project="case-a", env=None, **fakes):
        """Run gw:unlock-auto with stand-in backends. Returns (result, what sgw.sh received)."""
        binn = _sandbox(tmp_path, **fakes)
        script = tmp_path / "unlock-auto.sh"
        script.write_text(_tasks("en")["gw:unlock-auto"]["run"])
        argv, stdin = tmp_path / "sgw.argv", tmp_path / "sgw.stdin"
        sgw = tmp_path / "sgw.sh"
        sgw.write_text('#!/usr/bin/env bash\nprintf "%s" "$*" > "$SGW_ARGV"\ncat > "$SGW_STDIN"\n')
        root = tmp_path / project
        root.mkdir(exist_ok=True)
        environ = {
            "PATH": str(binn),
            "SGW": str(sgw),
            "SGW_ARGV": str(argv),
            "SGW_STDIN": str(stdin),
            "SGW_PASSPHRASE_DIR": str(tmp_path / "etc"),
            "MISE_PROJECT_ROOT": str(root),
            **(env or {}),
        }
        result = subprocess.run(
            [shutil.which("bash"), str(script)],
            env=environ,
            capture_output=True,
            text=True,
            timeout=30,
        )
        got = {
            "argv": argv.read_text() if argv.exists() else None,
            "stdin": stdin.read_text() if stdin.exists() else None,
        }
        return result, got

    def _echoes(value):
        return f"#!/usr/bin/env bash\nprintf '%s\\n' {value!r}\n"

    def it_pipes_the_keychain_entry_into_unlock_stdin(tmp_path):
        r, got = _run(tmp_path, security=_echoes("correct horse"))
        assert r.returncode == 0, r.stderr
        assert got["argv"] == "gw sekimore-relay unlock --stdin"
        assert got["stdin"] == "correct horse\n"
        # the value itself is never printed, only where it came from
        assert "correct horse" not in r.stdout + r.stderr
        assert "Keychain" in r.stdout

    def it_asks_the_keychain_for_this_project_only(tmp_path):
        # Two projects on one host keep separate entries, so the lookup is by the project's name
        # and a second project must not unlock with the first one's passphrase.
        record = tmp_path / "args"
        fake = f'#!/usr/bin/env bash\nprintf "%s" "$*" > {str(record)!r}\nprintf "p\\n"\n'
        _run(tmp_path, project="case-b", security=fake)
        assert record.read_text() == ("find-generic-password -s sekimore-gw -a case-b -w")

    def it_falls_through_to_the_secret_service(tmp_path):
        # No `security` on PATH at all: the macOS branch has to be skipped, not fail the task.
        r, got = _run(tmp_path, **{"secret-tool": _echoes("from the keyring")})
        assert r.returncode == 0, r.stderr
        assert got["stdin"] == "from the keyring\n"
        assert "Secret Service" in r.stdout

    def it_prefers_the_keychain_when_both_answer(tmp_path):
        r, got = _run(
            tmp_path,
            security=_echoes("from the keychain"),
            **{"secret-tool": _echoes("from the keyring")},
        )
        assert got["stdin"] == "from the keychain\n"
        assert r.returncode == 0

    def it_ignores_a_backend_that_has_no_entry(tmp_path):
        # `security` exits 44 with nothing on stdout when the item is not there, and older
        # `secret-tool` exits 0 with nothing. Neither is a passphrase.
        r, got = _run(
            tmp_path,
            security="#!/usr/bin/env bash\nexit 44\n",
            **{"secret-tool": "#!/usr/bin/env bash\nexit 0\n"},
        )
        assert r.returncode == 0, r.stderr
        assert got["stdin"] is None, "an empty lookup was sent to the relay as a passphrase"
        assert "no passphrase stored" in r.stdout

    def it_reads_the_root_owned_file_when_there_is_no_keychain(tmp_path):
        # The server path. 0600 and root-owned in the real thing; here it is simply ours, which
        # is the branch `maybe_root` takes before it reaches for sudo.
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "case-a.passphrase").write_text("from the file\n")
        r, got = _run(tmp_path)
        assert r.returncode == 0, r.stderr
        assert got["stdin"] == "from the file\n"
        assert "case-a.passphrase" in r.stdout

    def it_prefers_the_machine_bound_credential_over_the_plain_file(tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "case-a.passphrase").write_text("the plain one\n")
        (etc / "case-a.passphrase.cred").write_text("ciphertext")
        r, got = _run(tmp_path, **{"systemd-creds": _echoes("the sealed one")})
        assert got["stdin"] == "the sealed one\n", r.stderr
        assert r.returncode == 0

    def it_says_what_to_do_and_succeeds_when_nothing_is_stored(tmp_path):
        # gw:recreate calls this unconditionally. A host that never set a passphrase up has not
        # had a failed recreate, so the exit status stays 0 and the message says how to store one.
        r, got = _run(tmp_path)
        assert r.returncode == 0, r.stderr
        assert got["argv"] is None, "the relay was called with no passphrase to give it"
        assert "mise run gw:keychain-set" in r.stdout

    def it_names_the_backend_it_asked_when_nothing_came_back(tmp_path):
        # A keyring that is installed but locked answers nothing, which looks exactly like a host
        # that has no keyring at all. Which of the two it is decides whether the operator unlocks
        # their keyring or runs gw:keychain-set, so the message says what was asked.
        # a fresh directory each, because _sandbox builds the PATH it hands the script
        installed, nothing = tmp_path / "installed", tmp_path / "nothing"
        installed.mkdir()
        nothing.mkdir()
        r, _ = _run(installed, **{"secret-tool": "#!/usr/bin/env bash\nexit 0\n"})
        assert "asked: the Secret Service" in r.stdout, r.stdout
        bare, _ = _run(nothing)
        assert "asked" not in bare.stdout, f"nothing was installed to ask: {bare.stdout}"

    def it_keeps_a_passphrase_that_has_spaces_in_it(tmp_path):
        # The relay strips exactly one trailing newline and nothing else, so what is piped has to
        # be the passphrase and a newline — not a trimmed version of it.
        r, got = _run(tmp_path, security=_echoes("  two  words  "))
        assert got["stdin"] == "  two  words  \n", r.stderr

    def it_never_hands_the_passphrase_to_the_relay_as_an_argument(tmp_path):
        # The check that matters, made against the process the task actually spawns rather than
        # against the text of the script.
        r, got = _run(tmp_path, security=_echoes("correct horse"))
        assert "correct horse" not in (got["argv"] or ""), (
            f"the passphrase is in the arguments sgw.sh was called with: {got['argv']!r}"
        )
        assert r.returncode == 0

    def it_reports_a_relay_that_refuses_the_passphrase(tmp_path):
        # A stored passphrase that no longer matches must not look like a clean recreate.
        binn = _sandbox(tmp_path, security=_echoes("stale"))
        script = tmp_path / "unlock-auto.sh"
        script.write_text(_tasks("en")["gw:unlock-auto"]["run"])
        sgw = tmp_path / "sgw.sh"
        sgw.write_text("#!/usr/bin/env bash\ncat >/dev/null\nexit 1\n")
        r = subprocess.run(
            [shutil.which("bash"), str(script)],
            env={
                "PATH": str(binn),
                "SGW": str(sgw),
                "SGW_PASSPHRASE_DIR": str(tmp_path / "etc"),
                "MISE_PROJECT_ROOT": str(tmp_path),
            },
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert r.returncode != 0, "a refused unlock was reported as a success"

    def _run_recreate(tmp_path, *, env=None, unlock_exit=0):
        """Run gw:recreate with sgw.sh and mise stood in for. Returns (result, what it called)."""
        log = tmp_path / "calls"
        binn = _sandbox(
            tmp_path,
            mise=(
                "#!/usr/bin/env bash\n"
                f'printf "mise %s\\n" "$*" >> {str(log)!r}\nexit {unlock_exit}\n'
            ),
        )
        sgw = tmp_path / "sgw.sh"
        sgw.write_text(f'#!/usr/bin/env bash\nprintf "sgw %s\\n" "$*" >> {str(log)!r}\n')
        script = tmp_path / "recreate.sh"
        script.write_text(_tasks("en")["gw:recreate"]["run"])
        result = subprocess.run(
            [shutil.which("bash"), str(script)],
            env={"PATH": str(binn), "SGW": str(sgw), **(env or {})},
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result, (log.read_text() if log.exists() else "")

    def it_unlocks_after_it_has_recreated_the_gateway(tmp_path):
        # A recreated gateway starts locked, and a locked store means no GitHub API. Without
        # this the feature is half of one: a recreate is still a recreate plus a person.
        r, calls = _run_recreate(tmp_path)
        assert r.returncode == 0, r.stderr
        assert calls.splitlines() == ["sgw recreate", "mise run gw:unlock-auto"], (
            f"gw:recreate did not recreate and then unlock, in that order: {calls!r}"
        )

    def it_leaves_the_store_locked_when_told_to(tmp_path):
        r, calls = _run_recreate(tmp_path, env={"SGW_NO_AUTO_UNLOCK": "1"})
        assert r.returncode == 0, r.stderr
        assert calls.splitlines() == ["sgw recreate"], (
            f"SGW_NO_AUTO_UNLOCK did not stop the unlock: {calls!r}"
        )
        assert "mise run gw:unlock" in r.stdout, "it did not say how to unlock by hand"

    def it_does_not_report_success_when_the_unlock_failed(tmp_path):
        # The recreate worked and the unlock did not. Reporting that as a clean run leaves the
        # gateway locked and the operator unaware until the next GitHub call fails.
        r, calls = _run_recreate(tmp_path, unlock_exit=1)
        assert r.returncode != 0, f"a failed unlock was reported as a clean recreate: {calls!r}"
        assert "mise run gw:unlock" in r.stderr
