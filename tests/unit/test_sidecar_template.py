"""The template command sidecar (examples/sidecar-template) works, and its describe passes the
gateway's checks (#331).

The template is what a third party copies, so it is run as a process on a real Unix socket. The
describe rules are a copy of `check_describe` in relay/src/forge/command.rs, kept to what a
template could get wrong; relay/tests/command_sidecar.rs runs the same template through the
gateway itself.
"""

from __future__ import annotations

import http.client
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "examples" / "sidecar-template" / "sidecar.py"
SECRET = "k-not-for-the-log"
GATEWAY_RESOURCES = {"ci", "issue", "pr", "project", "release", "repo", "search", "security"}
WORD = re.compile(r"^[a-z][a-z0-9_-]*$")


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("sidecar", timeout=10)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(self.path)


class Sidecar:
    def __init__(self, path: str, proc: subprocess.Popen):
        self.path = path
        self.proc = proc

    def request(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        conn = UnixConnection(self.path)
        try:
            raw = json.dumps(body).encode() if body is not None else b""
            conn.request(method, path, raw, {"Content-Type": "application/json"})
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read())
        finally:
            conn.close()

    def command(self, name: str, args: dict, credentials: dict | None = None) -> dict:
        status, reply = self.request(
            "POST",
            "/command",
            {
                "command": name,
                "permission": "",
                "project": "case-template",
                "args": args,
                "credentials": {"api_key": SECRET} if credentials is None else credentials,
            },
        )
        assert status == 200, reply
        return reply


@pytest.fixture
def sidecar():
    # pytest's tmp_path is too long for a Unix socket path (~108 bytes)
    tmp = tempfile.mkdtemp(prefix="sc-")
    path = f"{tmp}/notes.sock"
    proc = subprocess.Popen(
        [sys.executable, str(TEMPLATE), "--socket", path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 10
        while not Path(path).is_socket():
            assert proc.poll() is None, proc.stderr.read().decode() if proc.stderr else ""
            assert time.monotonic() < deadline, "the template did not bind its socket"
            time.sleep(0.05)
        yield Sidecar(path, proc)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        shutil.rmtree(tmp, ignore_errors=True)


def refusals(d: dict, name: str, declared: list[str]) -> list[str]:
    """What the gateway would refuse in a describe; empty when it connects."""
    out = []
    for key in ("name", "version", "resources", "guide"):
        if key not in d:
            out.append(f"no {key}")
    if d.get("name") != name:
        out.append("names itself otherwise")
    resources = d.get("resources", [])
    out += [f"claims {r}" for r in resources if r not in declared]
    out += [
        f"{r} is the gateway's" for r in resources if r in GATEWAY_RESOURCES or not WORD.match(r)
    ]
    guide = d.get("guide", "")
    if not guide.strip():
        out.append("no guide")
    for r, a in re.findall(r"\[([^\[\]:]+):([^\[\]]+)\]", guide):
        if WORD.match(r) and WORD.match(a) and r not in resources:
            out.append(f"guide names [{r}:{a}]")
    seen: list[list[str]] = []
    for c in d.get("commands", []):
        if not all(k in c for k in ("name", "about", "permission")):
            out.append(f"{c}: name, about and permission are required")
            continue
        words = c["name"].split()
        if not 1 <= len(words) <= 3 or not all(WORD.match(w) for w in words):
            out.append(f"{c['name']}: words")
        if any(s[: len(words)] == words[: len(s)] for s in seen):
            out.append(f"{c['name']}: overlaps")
        seen.append(words)
        r, _, a = c["permission"].partition(":")
        if r not in resources or not WORD.match(a):
            out.append(f"{c['name']}: permission {c['permission']}")
        names = [a["name"] for a in c.get("args", [])]
        if len(set(names)) != len(names):
            out.append(f"{c['name']}: an argument twice")
        for arg in c.get("args", []):
            if not WORD.match(arg["name"]) or arg["name"] == "help":
                out.append(f"{c['name']}: argument {arg['name']}")
            if arg.get("kind", "string") not in ("string", "int", "bool", "list"):
                out.append(f"{c['name']}: kind {arg.get('kind')}")
            if arg.get("kind") == "bool" and arg.get("required"):
                out.append(f"{c['name']}: a required flag")
    return out


def describe_the_template_sidecar():
    def it_describes_itself_in_a_way_the_gateway_connects(sidecar):
        status, d = sidecar.request("GET", "/describe")
        assert status == 200
        assert refusals(d, "notes", ["notes"]) == []
        assert {c["name"]: c["permission"] for c in d["commands"]} == {
            "note add": "notes:write",
            "note list": "notes:read",
        }

    def it_adds_a_note_and_lists_it(sidecar):
        added = sidecar.command("note add", {"text": "hi", "tag": ["a", "b"], "pin": True})
        assert "error" not in added
        assert added["data"] == {"id": 1, "text": "hi", "tags": ["a", "b"], "pinned": True}
        assert added["calls"] == []
        sidecar.command("note add", {"text": "second"})
        listed = sidecar.command("note list", {"limit": 1})
        assert [n["text"] for n in listed["data"]] == ["second"]
        assert listed["message"] == "2: second"

    def it_answers_a_failure_inside_a_200_reply(sidecar):
        reply = sidecar.command("note list", {}, credentials={})
        assert reply["error"]["status"] == 503
        assert "api_key" in reply["error"]["message"]
        assert sidecar.command("note list", {"limit": 0})["error"]["status"] == 400

    def it_never_logs_the_credential(sidecar):
        sidecar.command("note add", {"text": "hi"})
        sidecar.proc.terminate()
        _, err = sidecar.proc.communicate(timeout=10)
        assert b"POST /command" in err
        assert SECRET.encode() not in err


def describe_the_copy_of_the_gateway_rules():
    """The copy of the gateway's rules refuses what the gateway refuses."""

    def it_refuses_what_the_gateway_refuses():
        base = {
            "name": "notes",
            "version": "1",
            "resources": ["notes"],
            "guide": "[notes:write]",
            "commands": [{"name": "note add", "about": "x", "permission": "notes:write"}],
        }
        assert refusals(base, "notes", ["notes"]) == []
        for change in (
            {"guide": " "},
            {"guide": "merge with [pr:merge]"},
            {"resources": ["notes", "pr"]},
            {"commands": [{"name": "note", "about": "x", "permission": "notes:write"}] * 2},
            {"commands": [{"name": "Note", "about": "x", "permission": "notes:write"}]},
            {"commands": [{"name": "note add", "permission": "notes:write"}]},
            {"commands": [{"name": "a b c d", "about": "x", "permission": "notes:write"}]},
            {"commands": [{"name": "note add", "about": "x", "permission": "pr:merge"}]},
            {
                "commands": [
                    {
                        "name": "note add",
                        "about": "x",
                        "permission": "notes:write",
                        "args": [{"name": "pin", "kind": "bool", "required": True}],
                    }
                ]
            },
        ):
            assert refusals({**base, **change}, "notes", ["notes", "pr"]), change
