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


def _covered(tasks: dict[str, dict]) -> dict[str, str]:
    """subcommand → the task that runs it."""
    out: dict[str, str] = {}
    for name, body in tasks.items():
        m = _RELAY_CALL.search(str(body.get("run", "")))
        if m and m.group(1):
            out.setdefault(m.group(1), name)
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
        wrong = [
            covered[s]
            for s in NEEDS_TERMINAL
            if s in covered and "gw-tty" not in str(tasks[covered[s]].get("run", ""))
        ]
        assert wrong == [], f"reads a passphrase but does not use `gw-tty`: {wrong}"
        raw = [
            covered[s] for s in NEEDS_TERMINAL if s in covered and not tasks[covered[s]].get("raw")
        ]
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
