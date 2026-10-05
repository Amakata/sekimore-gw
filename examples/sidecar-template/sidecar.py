#!/usr/bin/env python3
"""A minimal command sidecar for sekimore-gw: in-memory notes.

Python 3 standard library only. The protocol is docs/sidecar-protocol.md.

    python3 sidecar.py --socket /run/sekimore-sidecars/notes.sock

The gateway has already checked the permission and the arguments of every call that reaches
POST /command. This file decides nothing, stores no credential and writes no audit.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler

NAME = "notes"  # must equal the key under relay.sidecars in config.yml
VERSION = "0.1.0"
REQUEST_CAP = 8 * 1024 * 1024  # the largest request this sidecar reads

DESCRIBE = {
    "name": NAME,
    "version": VERSION,
    "resources": ["notes"],
    "guide": (
        "## notes\n\n"
        "Short notes kept by the notes sidecar for this project.\n\n"
        "- `sgw-agent notes note add --text <text> [--tag <tag>]... [--pin]` "
        "adds a note [notes:write]\n"
        "- `sgw-agent notes note list [--limit <n>]` lists the notes, newest first [notes:read]\n"
    ),
    "commands": [
        {
            "name": "note add",
            "about": "Add a note",
            "permission": "notes:write",
            "args": [
                {"name": "text", "help": "The note", "kind": "string", "required": True},
                {"name": "tag", "help": "A tag; repeat for more", "kind": "list"},
                {"name": "pin", "help": "Pin the note", "kind": "bool"},
            ],
        },
        {
            "name": "note list",
            "about": "List the notes, newest first",
            "permission": "notes:read",
            "args": [{"name": "limit", "help": "At most this many", "kind": "int"}],
        },
    ],
}

NOTES: list[dict] = []  # lost on restart: a sidecar keeps nothing it cannot afford to lose
LOCK = threading.Lock()


def note_add(args: dict) -> dict:
    note = {"text": args["text"], "tags": args.get("tag", []), "pinned": args.get("pin", False)}
    with LOCK:
        NOTES.append(note)
        note["id"] = len(NOTES)
    return {"message": f"added note {note['id']}", "data": note}


def note_list(args: dict) -> dict:
    limit = args.get("limit")
    if limit is not None and limit < 1:
        return error(400, "note list: --limit must be 1 or more")
    with LOCK:
        notes = list(reversed(NOTES))[:limit]
    lines = [f"{n['id']}: {n['text']}" for n in notes] or ["no notes"]
    return {"message": "\n".join(lines), "data": notes}


COMMANDS = {"note add": note_add, "note list": note_list}


def error(status: int, message: str) -> dict:
    """A failure, inside a 200 reply. A non-2xx HTTP status means "the sidecar is broken"."""
    return {"error": {"status": status, "message": message}}


def command(req: dict) -> dict:
    # Read the credential where it is used, and never put it in a reply or a log line.
    # A real sidecar would send it to its service here, through the gateway's 443 passthrough.
    if not req.get("credentials", {}).get("api_key"):
        return error(
            503, "the notes sidecar was sent no api_key; set relay.sidecars.notes.credentials"
        )
    run = COMMANDS.get(req.get("command", ""))
    if run is None:
        return error(404, f"no command {req.get('command')!r}")
    reply = run(req.get("args", {}))
    # Every upstream call made for this command, for the gateway's audit:
    # {"method": "POST", "path": "/v1/notes", "status": 201}. This example makes none.
    reply["calls"] = []
    return reply


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (the name http.server calls)
        if self.path != "/describe":
            return self.send_json(404, {"error": f"no GET {self.path}"})
        self.send_json(200, DESCRIBE)

    def do_POST(self):  # noqa: N802
        if self.path != "/command":
            return self.send_json(404, {"error": f"no POST {self.path}"})
        length = int(self.headers.get("Content-Length") or 0)
        if length > REQUEST_CAP:
            return self.send_json(413, {"error": "request too large"})
        try:
            req = json.loads(self.rfile.read(length))
        except ValueError:
            return self.send_json(400, {"error": "the body is not JSON"})
        self.send_json(200, command(req))

    def send_json(self, status: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_):
        # The default reads client_address[0], which a Unix socket does not have. Log the request
        # line only: never a body, which carries the credentials.
        sys.stderr.write(f"{NAME}: {self.requestline}\n")


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def bind(path: str) -> Server:
    """Bind the socket, replacing one a previous run left behind; only the gateway connects."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
    server = Server(path, Handler)
    os.chmod(path, 0o660)
    return server


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--socket", required=True, help="where to listen (on the shared volume)")
    server = bind(p.parse_args().socket)
    print(f"{NAME} {VERSION} listening", file=sys.stderr, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
