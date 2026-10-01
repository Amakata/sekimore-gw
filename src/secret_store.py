"""Read a secret out of the relay's store, over its control socket.

The store is the relay's (see `relay/src/store/`): SQLite, AES-256-GCM per value, and the key
derived from a passphrase a person types. **Only the relay process holds that key**, so the Python
side cannot open the database — it asks, over the unix socket beside the relay's state.

That socket is the relay's operator channel, not the agent-facing API on :8420. It lives on a
volume the dev container does not mount and is 0600, so reaching it means already being inside the
gateway. Nothing here widens that: this module runs in the gateway, beside the relay.

**The store starts locked.** The gateway comes up before anyone has typed a passphrase, so a read
at start-up is expected to fail and `Locked` is a normal answer rather than an error — the caller
retries once someone unlocks. `SecretStoreError` is for the cases that will not fix themselves.
"""

from __future__ import annotations

import json
import re
import socket
from dataclasses import dataclass
from pathlib import Path

from src.constants import CONTROL_SOCK_PATH
from src.logger import ComponentType, get_logger

logger = get_logger(ComponentType.SYSTEM)

# The relay answers these as `code`, so a caller can tell them apart without reading the prose.
# Matching on the message would break the first time the message is reworded.
CODE_NOT_FOUND = "not_found"
CODE_LOCKED = "locked"

# Where the upstream proxy credential is filed. The relay writes it under the same pair
# (`PROXY_NAMESPACE` / `PROXY_NAME` in relay/src/cli/operator.rs), so changing either here is a
# breaking change across two languages.
PROXY_NAMESPACE = "proxy"
PROXY_NAME = "upstream"

# #334: per-person values (`sgw var set`) are filed under `var`, and the upstream proxy credential
# lives in two of them unless config.yml names others as `{key}`. `proxy/upstream` above is the
# record from before them; the relay moves it into these once the store is readable.
VAR_NAMESPACE = "var"
VAR_PROXY_USER = "proxy_user"
VAR_PROXY_PASSWORD = "proxy_password"
_KEY_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")


def reference(field: str | None) -> str | None:
    """The key a config field refers to when the whole field is `{key}`; otherwise None.

    The same rule as the relay's `proxy_credential::reference`: segments of `[A-Za-z0-9._-]`
    joined by `/`, none of them `.` or `..`.
    """
    if not isinstance(field, str) or not field:
        return None
    f = field.strip()
    if not (f.startswith("{") and f.endswith("}")):
        return None
    key = f[1:-1]
    segments = key.split("/")
    if not key or len(key) > 128:
        return None
    if any(s in ("", ".", "..") or not _KEY_SEGMENT.fullmatch(s) for s in segments):
        return None
    return key


def literal(field: str | None) -> str | None:
    """A config field as a literal value: None when it is empty or a `{key}` reference."""
    if not field or reference(field) is not None:
        return None
    return field


def read_proxy_credential(
    username_field: str | None,
    password_field: str | None,
    sock_path: str | Path = CONTROL_SOCK_PATH,
) -> tuple[str, tuple[str, str] | None]:
    """The upstream proxy credential in the store: `set` / `locked` / `none` / `unusable`.

    The per-person values first (the keys the config refers to, or proxy_user / proxy_password),
    then the record from before them. Raises SecretStoreError when the store cannot be reached.
    """
    ku = reference(username_field) or VAR_PROXY_USER
    kp = reference(password_field) or VAR_PROXY_PASSWORD
    user = get_secret(VAR_NAMESPACE, ku, sock_path)
    if isinstance(user, Locked):
        return "locked", None
    if isinstance(user, str) and user:
        # Squid puts the username into `cache_peer ... login=<user>:<pass>`, which has no quoting:
        # a space ends the option. `proxy-credential set` refuses one when typed (#271); a value
        # set with `sgw var set` is checked here, where it is used
        if not all(c.isascii() and c.isprintable() and not c.isspace() for c in user):
            return "unusable", None
        password = get_secret(VAR_NAMESPACE, kp, sock_path)
        return "set", (user, password if isinstance(password, str) else "")
    old = get_secret(PROXY_NAMESPACE, PROXY_NAME, sock_path)
    if isinstance(old, Locked):
        return "locked", None
    if isinstance(old, NotFound):
        return "none", None
    try:
        parsed = json.loads(old)
        username, password = parsed["username"], parsed["password"]
    except (ValueError, KeyError, TypeError):
        return "unusable", None
    if not username:
        return "none", None
    return "set", (username, password or "")


# One reply is one line of JSON. A secret is small; this is only here so a socket that never
# terminates a line cannot hang the gateway's start-up.
_MAX_REPLY = 1024 * 1024
_TIMEOUT_SECONDS = 5.0


class SecretStoreError(RuntimeError):
    """The store could not be reached or answered something unusable."""


@dataclass(frozen=True)
class Locked:
    """The store is there and sealed. Not an error: it is the state at every start-up."""


@dataclass(frozen=True)
class NotFound:
    """The store is open and holds no such secret."""


def get_secret(
    namespace: str, name: str, sock_path: str | Path = CONTROL_SOCK_PATH
) -> str | Locked | NotFound:
    """One secret, or why there is not one.

    Three outcomes rather than an exception for each, because two of them are ordinary: a locked
    store means "not yet", a missing secret means "not configured", and only a broken socket is a
    fault worth raising.
    """
    reply = _call(
        {"op": "get", "namespace": namespace, "name": name},
        sock_path,
        f"{namespace}/{name}",
    )
    if reply.get("ok"):
        value = reply.get("data")
        if isinstance(value, str):
            return value
        raise SecretStoreError(f"{namespace}/{name}: the relay answered a get with no value")
    code = reply.get("code")
    if code == CODE_NOT_FOUND:
        return NotFound()
    if code == CODE_LOCKED:
        return Locked()
    raise SecretStoreError(f"{namespace}/{name}: {reply.get('message', 'no message')}")


def is_unlocked(sock_path: str | Path = CONTROL_SOCK_PATH) -> bool:
    """Whether the store is open, without reading anything out of it.

    For deciding whether it is worth redoing work that needs a secret. A store that cannot be
    reached at all counts as not unlocked — the caller's next step is the same either way.
    """
    try:
        reply = _call({"op": "status"}, sock_path, "status")
    except SecretStoreError:
        return False
    return reply.get("ok") is True and reply.get("message") == "unlocked"


def _call(request: dict[str, object], sock_path: str | Path, what: str) -> dict:
    """Send one line, read one line."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(_TIMEOUT_SECONDS)
            s.connect(str(sock_path))
            s.sendall((json.dumps(request) + "\n").encode("utf-8"))
            # Tell the relay there is nothing more coming, so it does not wait for a close
            s.shutdown(socket.SHUT_WR)
            buf = bytearray()
            while b"\n" not in buf and len(buf) < _MAX_REPLY:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
    except OSError as e:  # TimeoutError is an OSError since 3.10
        # The usual reason is the relay not running: `config.yml` may declare no git-relay
        # handler at all, in which case there is no store and never will be.
        raise SecretStoreError(
            f"{what}: cannot reach the relay's control socket at {sock_path} ({e})"
        ) from e

    if not buf:
        raise SecretStoreError(f"{what}: the relay closed the connection without answering")
    try:
        reply = json.loads(bytes(buf).split(b"\n", 1)[0])
    except ValueError as e:
        raise SecretStoreError(f"{what}: the relay's answer is not JSON ({e})") from e
    if not isinstance(reply, dict):
        raise SecretStoreError(f"{what}: the relay's answer is not an object")
    return reply
