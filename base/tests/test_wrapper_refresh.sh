#!/bin/sh
# scripts/sekimore renews an expired project token by itself (sgw-devcontainer-base#37).
#
# The wrapper is the agent's only way to GitHub, so when the 12h token runs out mid-task
# it has to get a new one without a human. This drives the real wrapper against fakes:
#
#   - a fake `sekimore-relay` that rejects every token but the new one, and that has no
#     `agent bootstrap` subcommand — the shipped relay has none either, which is why the
#     old wrapper could never refresh anything
#   - a tiny HTTP server standing in for the gateway's POST /bootstrap
#   - an env file in a directory the test makes read-only: /etc/sekimore-agent belongs to
#     root while the env file belongs to the agent user, so a refresh that writes a temp
#     file beside it cannot work
#
# Three cases: the token is expired by its own timestamp, the timestamp still looks good
# but the relay rejects the token, and the disposable key is not a key the wrapper may
# put into a JSON body.
#
# Run it directly: tests/test_wrapper_refresh.sh
set -eu

unset CDPATH
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
WRAPPER="$ROOT/scripts/sekimore"

# python3 is not installed in this image (mise manages languages and none is pinned), so
# uv fetches an interpreter on demand. CI runners already have python3; use it when it is
# there rather than downloading one.
if command -v python3 >/dev/null 2>&1; then
  PY="python3"
elif command -v uv >/dev/null 2>&1; then
  PY="uv run --no-project python"
else
  echo "SKIP: neither python3 nor uv is available" >&2
  exit 0
fi

OLD_TOKEN=skm_0000000000000000000000000000000000000000000000000000000000000000
NEW_TOKEN=skm_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
NEW_EXPIRES=2099-01-01T00:00:00Z
PUB="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8ZtestkeytestkeytestkeytestkeytestkeyAB sekimore-agent@test-host"

TMP=$(mktemp -d)
SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  # the test leaves the env directory read-only between cases
  chmod u+w "$TMP/etc" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP/etc" "$TMP/bin" "$TMP/key" "$TMP/out"
REQ_LOG="$TMP/out/requests"
CALLS="$TMP/out/relay-calls"
PORT_FILE="$TMP/out/port"
ENV_FILE="$TMP/etc/env"

printf '%s\n' "$PUB" > "$TMP/key/id_ed25519.pub"
# A key file the wrapper must refuse: the wrapper builds the bootstrap body by hand, and
# a quote in the value would produce a body that means something other than intended.
printf '%s\n' 'ssh-ed25519 AAAA" sekimore-agent@test-host' > "$TMP/key/quoted.pub"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok    $*"; }

# ---- the gateway: POST /bootstrap hands out a token and records who asked ----------
cat > "$TMP/out/server.py" <<'PY'
import http.server
import json
import os

REQ_LOG = os.environ["REQ_LOG"]
NEW_TOKEN = os.environ["NEW_TOKEN"]
NEW_EXPIRES = os.environ["NEW_EXPIRES"]


def record(line):
    with open(REQ_LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            pub = json.loads(raw.decode("utf-8")).get("public_key", "<no public_key>")
        except ValueError:
            pub = "<unparseable> " + raw.decode("utf-8", "replace")
        record("POST %s %s" % (self.path, pub))
        if self.path != "/bootstrap":
            self.send_error(404)
            return
        # separators matter: the wrapper greps `"token_expires":"..."` out of the raw
        # body, and the relay (serde_json) puts no spaces around the colon either.
        body = json.dumps(
            {
                "token": NEW_TOKEN,
                "token_expires": NEW_EXPIRES,
                "repos": ["Amakata/sgw-devcontainer-base"],
                "git_domain": "github.com",
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        record("GET %s -" % self.path)
        self.send_error(405)

    def log_message(self, *args):
        pass


srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(os.environ["PORT_FILE"], "w", encoding="utf-8") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
PY

REQ_LOG="$REQ_LOG" NEW_TOKEN="$NEW_TOKEN" NEW_EXPIRES="$NEW_EXPIRES" PORT_FILE="$PORT_FILE" \
  $PY "$TMP/out/server.py" &
SERVER_PID=$!

# uv may have to fetch an interpreter the first time, so wait generously.
i=0
while [ ! -s "$PORT_FILE" ]; do
  kill -0 "$SERVER_PID" 2>/dev/null || fail "the bootstrap server exited before it bound a port"
  i=$((i + 1))
  [ "$i" -le 900 ] || fail "the bootstrap server did not write its port within 90s"
  sleep 0.1
done
PORT=$(cat "$PORT_FILE")
ok "bootstrap server listening on 127.0.0.1:$PORT"

# ---- the relay: no `agent bootstrap`, and every token but the new one is expired ----
cat > "$TMP/bin/sekimore-relay" <<'RELAY'
#!/bin/sh
[ "${1:-}" = agent ] || { echo "error: unrecognized subcommand '${1:-}'" >&2; exit 2; }
shift
if [ "${1:-}" = bootstrap ]; then
  # Word for word what the shipped relay says. The old wrapper called this to refresh.
  echo "error: unrecognized subcommand 'bootstrap'" >&2
  exit 2
fi
printf '%s\t%s\n' "${SEKIMORE_TOKEN:-<unset>}" "$*" >> "__CALLS__"
if [ "${SEKIMORE_TOKEN:-}" != "__NEW_TOKEN__" ]; then
  echo "sekimore-relay: token expired at 2026-09-21T15:07:43Z" >&2
  exit 1
fi
echo "ok: $*"
RELAY
sed -i -e "s|__CALLS__|$CALLS|" -e "s|__NEW_TOKEN__|$NEW_TOKEN|" "$TMP/bin/sekimore-relay"
chmod 755 "$TMP/bin/sekimore-relay"

# ---- fixtures ------------------------------------------------------------------------
# write_env <token> <expiry> <key file>; leaves the env directory read-only, as /etc/sekimore-agent is
write_env() {
  chmod u+w "$TMP/etc"
  cat > "$ENV_FILE" <<ENVFILE
# generated by sekimore-agent-setup.sh — re-run the setup to refresh
SEKIMORE_ENDPOINT=http://127.0.0.1:$PORT
SEKIMORE_REPO=Amakata/sgw-devcontainer-base
SEKIMORE_AGENT_KEY=$3
SEKIMORE_TOKEN=$1
SEKIMORE_TOKEN_EXPIRES=$2
ENVFILE
  chmod 600 "$ENV_FILE"
  : > "$REQ_LOG"
  : > "$CALLS"
  inode_before=$(stat -c %i "$ENV_FILE")
  # root ignores this, so the inode check is what holds when the test runs as root.
  chmod 555 "$TMP/etc"
}

# run_wrapper <args...>; sets $rc and $out. The ambient SEKIMORE_* of a real dev container
# are cleared so only the fixture env file decides what the wrapper sees.
run_wrapper() {
  set +e
  out=$(env -u SEKIMORE_TOKEN -u SEKIMORE_TOKEN_EXPIRES -u SEKIMORE_ENDPOINT \
          -u SEKIMORE_ENV_OVERRIDE -u SEKIMORE_AGENT_KEY -u SEKIMORE_REPO \
          SEKIMORE_AGENT_ENV_FILE="$ENV_FILE" \
          SEKIMORE_RELAY_BIN="$TMP/bin/sekimore-relay" \
          PATH="$TMP/bin:$PATH" \
          no_proxy=127.0.0.1,localhost NO_PROXY=127.0.0.1,localhost \
          "$WRAPPER" "$@" 2>&1)
  rc=$?
  set -e
  chmod u+w "$TMP/etc"
  echo "--- wrapper output (exit $rc) ---"
  printf '%s\n' "$out" | sed 's/^/    /'
  echo "---------------------------------"
}

lines() { wc -l < "$1" | tr -d ' '; }

# =======================================================================================
echo
echo "case 1: SEKIMORE_TOKEN_EXPIRES is in the past — refresh before the call is made"
write_env "$OLD_TOKEN" 2020-01-01T00:00:00Z "$TMP/key/id_ed25519.pub"
run_wrapper whoami

[ "$rc" -eq 0 ] || fail "the wrapper exited $rc; it should have refreshed the token and succeeded"
ok "the wrapper exited 0"

n=$(lines "$REQ_LOG")
[ "$n" -eq 1 ] || fail "the gateway saw $n requests, expected exactly 1 POST /bootstrap:
$(cat "$REQ_LOG")"
[ "$(cat "$REQ_LOG")" = "POST /bootstrap $PUB" ] || fail "the bootstrap request was not the expected one:
  got:  $(cat "$REQ_LOG")
  want: POST /bootstrap $PUB"
ok "the gateway saw exactly one POST /bootstrap carrying the public key"

grep -qx "SEKIMORE_TOKEN=$NEW_TOKEN" "$ENV_FILE" || fail "the env file does not hold the new token:
$(cat "$ENV_FILE")"
grep -qx "SEKIMORE_TOKEN_EXPIRES=$NEW_EXPIRES" "$ENV_FILE" || fail "the env file does not hold the new expiry:
$(cat "$ENV_FILE")"
if grep -q "$OLD_TOKEN" "$ENV_FILE"; then fail "the old token is still in the env file"; fi
ok "the env file holds the new token and its expiry"

grep -qx '# generated by sekimore-agent-setup.sh — re-run the setup to refresh' "$ENV_FILE" \
  || fail "the rewrite dropped the header comment"
grep -qx "SEKIMORE_REPO=Amakata/sgw-devcontainer-base" "$ENV_FILE" \
  || fail "the rewrite dropped SEKIMORE_REPO"
ok "the rest of the env file survived the rewrite"

inode_after=$(stat -c %i "$ENV_FILE")
[ "$inode_before" = "$inode_after" ] || fail "the env file was replaced (inode $inode_before -> $inode_after); it has to be written in place"
mode=$(stat -c %a "$ENV_FILE")
[ "$mode" = "600" ] || fail "the env file is mode $mode, expected 600"
ok "the env file was written in place and is still 0600"

n=$(lines "$CALLS")
[ "$n" -eq 1 ] || fail "the relay was called $n times, expected exactly once:
$(cat "$CALLS")"
[ "$(cat "$CALLS")" = "$(printf '%s\t%s' "$NEW_TOKEN" whoami)" ] || fail "the relay was not called once with the new token:
$(cat "$CALLS")"
ok "the relay ran once, with the new token"

# =======================================================================================
echo
echo "case 2: the timestamp still looks valid but the relay rejects the token — refresh and retry"
write_env "$OLD_TOKEN" "$NEW_EXPIRES" "$TMP/key/id_ed25519.pub"
run_wrapper whoami

[ "$rc" -eq 0 ] || fail "the wrapper exited $rc; the rejected token should have been replaced and the command retried"
n=$(lines "$REQ_LOG")
[ "$n" -eq 1 ] || fail "the gateway saw $n requests, expected exactly 1 POST /bootstrap:
$(cat "$REQ_LOG")"
grep -qx "SEKIMORE_TOKEN=$NEW_TOKEN" "$ENV_FILE" || fail "the env file does not hold the new token:
$(cat "$ENV_FILE")"
# rejected call, the whoami that classifies the failure, then the retry
last=$(tail -1 "$CALLS")
[ "$last" = "$(printf '%s\t%s' "$NEW_TOKEN" whoami)" ] || fail "the retry did not use the new token; relay calls were:
$(cat "$CALLS")"
[ "$(lines "$CALLS")" -ge 2 ] || fail "the command was not retried; relay calls were:
$(cat "$CALLS")"
ok "the rejected token was replaced and the command retried with the new one"

# =======================================================================================
echo
echo "case 3: the disposable key is not something that may go into a JSON body — refuse, say why"
write_env "$OLD_TOKEN" 2020-01-01T00:00:00Z "$TMP/key/quoted.pub"
run_wrapper whoami

[ "$rc" -ne 0 ] || fail "the wrapper exited 0 with a key it cannot send"
n=$(lines "$REQ_LOG")
[ "$n" -eq 0 ] || fail "the gateway was asked for a token with an unusable key; requests were:
$(cat "$REQ_LOG")"
printf '%s\n' "$out" | grep -q 'quote or a backslash' \
  || fail "the wrapper did not say why it could not refresh:
$out"
grep -qx "SEKIMORE_TOKEN=$OLD_TOKEN" "$ENV_FILE" || fail "the env file was rewritten even though no token was obtained:
$(cat "$ENV_FILE")"
ok "no bootstrap was attempted, the env file was left alone, and the reason was printed"

echo
echo "PASS  tests/test_wrapper_refresh.sh"
