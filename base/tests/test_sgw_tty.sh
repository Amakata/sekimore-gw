#!/bin/sh
# share/sgw/sgw.sh gives docker exec a terminal exactly when the person has one (#50).
#
# It asked a function inside "$(...)", where stdout is always the substitution's pipe, so it never
# added -t: `dev zsh` and `gw bash` started a shell with no terminal, which reads no rc files and
# waits on stdin — it looked hung. A fake `docker` records what it is given; script(1) supplies the
# terminal. What must not get -t: output piped on (relay:verify pipes `gw … check` into sed), and a
# stdin that is not a terminal.
#
# Run it directly: tests/test_sgw_tty.sh
set -eu

unset CDPATH
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
SGW=$ROOT/share/sgw/sgw.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

if ! script --version 2>/dev/null | grep -q util-linux; then
  echo "SKIP: needs util-linux script(1) for a terminal"
  exit 0
fi

mkdir -p "$TMP/bin"
cat > "$TMP/bin/docker" <<'D'
#!/bin/sh
case $1 in
  ps) echo cid123 ;;
  exec) shift; echo "$*" > "$LOG" ;;
esac
D
chmod +x "$TMP/bin/docker"
LOG=$TMP/exec.log
export LOG

# run <shell command>: under a terminal, with the fake docker first on PATH
run() {
  rm -f "$LOG"
  script -qec "env -u DEVCONTAINER PATH='$TMP/bin:$PATH' LOG='$LOG' SGW_COMPOSE_DIR='$TMP' $1" /dev/null >/dev/null 2>&1 || true
  cat "$LOG" 2>/dev/null || echo "(docker exec was not called)"
}

echo "== a person at a terminal gets one: dev and gw"
got=$(run "bash '$SGW' dev zsh")
case $got in "-it -u vscode cid123 zsh") ;; *) fail "dev zsh from a terminal ran: docker exec $got" ;; esac
got=$(run "bash '$SGW' gw bash")
case $got in "-it -e SEKIMORE_COLOR=always cid123 bash") ;; *) fail "gw bash from a terminal ran: docker exec $got" ;; esac

echo "== output piped on: no terminal, so no carriage returns and no colour in what is read"
# relay:verify reads this through sed. sgw.sh's stdout is the pipe, so [ -t 1 ] is false: no -t,
# and no SEKIMORE_COLOR either, leaving the output exactly as it was before #83.
got=$(run "bash '$SGW' gw sekimore-relay check | cat")
case $got in "-i cid123 sekimore-relay check") ;; *) fail "a piped gw ran: docker exec $got" ;; esac

echo "== NO_COLOR wins at a terminal, and is handed to the gateway"
got=$(run "NO_COLOR=1 bash '$SGW' gw bash")
case $got in "-it -e NO_COLOR cid123 bash") ;; *) fail "gw bash with NO_COLOR ran: docker exec $got" ;; esac

echo "== an explicit SEKIMORE_COLOR is passed through, not overridden"
got=$(run "SEKIMORE_COLOR=never bash '$SGW' gw bash")
case $got in "-it -e SEKIMORE_COLOR cid123 bash") ;; *) fail "gw bash with SEKIMORE_COLOR=never ran: docker exec $got" ;; esac
got=$(run "SEKIMORE_COLOR=always bash '$SGW' gw sekimore-relay check | cat")
case $got in "-i -e SEKIMORE_COLOR cid123 sekimore-relay check") ;; *) fail "a piped gw with SEKIMORE_COLOR=always ran: docker exec $got" ;; esac

echo "== dev is left alone: the colour is the gateway CLI's"
got=$(run "bash '$SGW' dev true </dev/null")
case $got in "-i -u vscode cid123 true") ;; *) fail "dev must carry no colour env: docker exec $got" ;; esac

echo "== stdin not a terminal: no -t, which docker would refuse anyway"
got=$(run "bash '$SGW' dev true </dev/null")
case $got in "-i -u vscode cid123 true") ;; *) fail "dev with stdin from /dev/null ran: docker exec $got" ;; esac

echo "PASS: sgw.sh terminal handling"
