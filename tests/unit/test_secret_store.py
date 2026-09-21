"""Reading a secret out of the relay's store, from Python.

Only the relay holds the store's key, so this side asks over the control socket. The three
answers that matter are a value, "sealed" and "no such secret", and they are not
interchangeable: a locked store means the gateway has not been unlocked yet, which is the state
at every start-up, while a missing secret means nobody configured one. Confusing them sends an
operator to the wrong command — the mistake #83 was about, one layer up.

The tests speak to a real unix socket rather than a mock, because the thing worth checking is the
wire protocol between two languages. A mock of our own reading would agree with our own writing
and prove nothing.
"""

import json
import socket
import threading

import pytest

from src.secret_store import (
    Locked,
    NotFound,
    SecretStoreError,
    get_secret,
    is_unlocked,
)


class FakeRelay:
    """A control socket that answers with whatever the test hands it.

    Stands in for the relay, which is Rust and not startable from here. The shape of the reply is
    copied from `relay/src/store/control.rs`; `test_gateway_mise_tasks.py` does the same kind of
    thing for the task file — read the other side's contract and hold this side to it.
    """

    def __init__(self, tmp_path, reply, *, hang: bool = False, close_early: bool = False):
        self.path = tmp_path / "control.sock"
        self.reply = reply
        self.hang = hang
        self.close_early = close_early
        self.requests: list[dict] = []
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(str(self.path))
        self._sock.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        with conn:
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            if buf:
                try:
                    self.requests.append(json.loads(buf.split(b"\n", 1)[0]))
                except ValueError:
                    self.requests.append({"unparseable": buf.decode("utf-8", "replace")})
            if self.close_early:
                return
            if self.hang:
                threading.Event().wait(30)
                return
            conn.sendall(
                (self.reply if isinstance(self.reply, str) else json.dumps(self.reply)).encode()
                + b"\n"
            )

    def close(self):
        self._sock.close()


@pytest.fixture
def relay(tmp_path):
    made: list[FakeRelay] = []

    def make(reply, **kw):
        r = FakeRelay(tmp_path, reply, **kw)
        made.append(r)
        return r

    yield make
    for r in made:
        r.close()


def describe_get_secret():
    def it_returns_the_value(relay):
        r = relay({"ok": True, "message": "upstream/github.com", "data": "gho_x"})
        assert get_secret("upstream", "github.com", r.path) == "gho_x"
        assert r.requests == [{"op": "get", "namespace": "upstream", "name": "github.com"}]

    def it_reports_a_locked_store_as_locked_not_as_absent(relay):
        # The distinction the whole module exists for: "not yet" and "not configured" send an
        # operator to different commands (gw:unlock vs configuring one).
        r = relay(
            {
                "ok": False,
                "message": "the secret store is locked; ask a human to run: mise run gw:unlock",
                "code": "locked",
            }
        )
        assert isinstance(get_secret("proxy", "upstream", r.path), Locked)

    def it_reports_a_missing_secret_as_absent(relay):
        r = relay({"ok": False, "message": "no secret proxy/upstream", "code": "not_found"})
        assert isinstance(get_secret("proxy", "upstream", r.path), NotFound)

    def it_reads_the_code_not_the_message(relay):
        # Prose gets reworded; the code is the contract. A reply whose message says nothing
        # recognisable still has to be understood.
        r = relay({"ok": False, "message": "🙅", "code": "locked"})
        assert isinstance(get_secret("proxy", "upstream", r.path), Locked)

    def it_raises_on_a_failure_that_is_neither(relay):
        r = relay({"ok": False, "message": "secret store database: disk I/O error"})
        with pytest.raises(SecretStoreError, match="disk I/O error"):
            get_secret("proxy", "upstream", r.path)

    def it_raises_when_ok_carries_no_value(relay):
        # Better than handing back None and letting it turn into the string "None" in a config
        r = relay({"ok": True, "message": "proxy/upstream"})
        with pytest.raises(SecretStoreError, match="no value"):
            get_secret("proxy", "upstream", r.path)

    def it_says_the_relay_is_unreachable_rather_than_that_there_is_no_secret(tmp_path):
        # A gateway whose relay is not running must not read as a store with nothing in it:
        # the answers are "start the relay" and "configure the secret", which are not the same.
        with pytest.raises(SecretStoreError, match="control socket"):
            get_secret("proxy", "upstream", tmp_path / "absent.sock")

    def it_raises_on_an_answer_that_is_not_json(relay):
        r = relay("this is not json")
        with pytest.raises(SecretStoreError, match="not JSON"):
            get_secret("proxy", "upstream", r.path)

    def it_raises_when_the_relay_answers_nothing(relay):
        r = relay({}, close_early=True)
        with pytest.raises(SecretStoreError, match="without answering"):
            get_secret("proxy", "upstream", r.path)


def describe_is_unlocked():
    def it_is_true_only_for_unlocked(relay):
        assert is_unlocked(relay({"ok": True, "message": "unlocked"}).path) is True

    @pytest.mark.parametrize("state", ["locked", "not initialised"])
    def it_is_false_for_every_other_state(relay, state):
        assert is_unlocked(relay({"ok": True, "message": state}).path) is False

    def it_is_false_when_the_relay_cannot_be_reached(tmp_path):
        # Not an exception: the caller's next step — try again later — is the same either way.
        assert is_unlocked(tmp_path / "absent.sock") is False
