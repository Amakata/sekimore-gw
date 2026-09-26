#!/usr/bin/env bash
# vscode.sh — start VS Code so that SSH_AUTH_SOCK never reaches it (mise run vscode). Run it on the host (Mac).
#
# With SSH_AUTH_SOCK in VS Code's own environment, the Dev Containers extension forwards the operator's (your) SSH key (ssh-agent)
# into the container unconditionally (no setting disables it: vscode-remote-release#11413). A plain `env -u SSH_AUTH_SOCK code …` fails on macOS:
#   1. the `code` CLI on macOS (Big Sur and later) starts the app with `open -n -a …`. open goes through LaunchServices,
#      so the app inherits launchd's environment (SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.*/Listeners), not the shell's
#   2. the app then starts a login shell and takes its environment in (shell env resolution). Exporting SSH_AUTH_SOCK
#      from ~/.zshrc and the like (1Password, say) brings it back. Only VSCODE_CLI=1 leaves that step out
#   3. when VS Code is already running, a new `code` only hands the folder to the existing instance (which has the socket)
# So this script (a) unsets launchd's SSH_AUTH_SOCK, (b) starts the app directly rather than through open, with no
# SSH_AUTH_SOCK and VSCODE_CLI=1, and (c) checks the app's environment with ps -Eww once it is up.
#
# Order with Docker Desktop: the /run/host-services/ssh-auth.sock handed to the gateway is Docker Desktop forwarding the
# SSH_AUTH_SOCK it had "at its own start-up". Start Docker Desktop first (with SSH_AUTH_SOCK). To restart Docker Desktop
# after (a), put launchd's value back with `vscode.sh --restore-agent-env` first.
#
#   vscode.sh                      launch (with the checks)
#   vscode.sh --check              report only (launchd / shell / rc files / Docker Desktop / a running VS Code)
#   vscode.sh --restore-agent-env  put SSH_AUTH_SOCK back into launchd (before restarting Docker Desktop)
#   SEKIMORE_VSCODE_APP=/path/to/Visual Studio Code.app   name the app location (when it cannot be found automatically)
#
# Distributed by sgw-devcontainer-base: `mise run upgrade:apply` replaces this file, and stops
# rather than overwrite it once it has been edited.
set -euo pipefail

ROOT=${MISE_PROJECT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
MODE=${1:-launch}
STATE_DIR=${SEKIMORE_HOST_STATE_DIR:-$HOME/.sekimore}
SAVED_SOCK_FILE=$STATE_DIR/launchd_ssh_auth_sock
os=$(uname -s)

# The relay's rule, so the gateway and these scripts agree: the first of these that names a
# language we have decides; C, POSIX, empty and languages we do not have fall through.
sgw_lang() {
  local v p
  for v in "${SEKIMORE_LANG:-}" "${LC_ALL:-}" "${LC_MESSAGES:-}" "${LANG:-}"; do
    p=$(printf '%s' "$v" | sed 's/^[[:space:]]*//; s/[^A-Za-z].*//' | tr 'A-Z' 'a-z')
    case $p in en|ja) echo "$p"; return ;; esac
  done
  echo en
}
L=$(sgw_lang)

# msg <key>: the format string for the current language. English is the fallback.
msg() {
  case "$L:$1" in
    ja:n_launchd) echo '(unset なら以後 GUI 経由で起動するアプリには渡らない)' ;;
    *:n_launchd) echo '(unset: apps started through the GUI from now on do not get it)' ;;
    ja:n_rc) echo '(あれば VS Code の shell env resolution で戻る → VSCODE_CLI=1 で起動する必要)' ;;
    *:n_rc) echo "(if any, VS Code's shell env resolution brings it back → launch with VSCODE_CLI=1)" ;;
    ja:n_dd_down) echo '(gateway の agent はこれが転送する。SSH_AUTH_SOCK ありで先に起動する)' ;;
    *:n_dd_down) echo '(this is what forwards the agent to the gateway; start it first, with SSH_AUTH_SOCK)' ;;
    ja:n_dd_ok) echo '(OK: gateway に agent が渡る)' ;;
    *:n_dd_ok) echo '(OK: the agent reaches the gateway)' ;;
    ja:n_dd_bad) echo 'gateway の agent は動かない (--restore-agent-env の後に Docker Desktop を再起動)' ;;
    *:n_dd_bad) echo "the gateway's agent will not work (restart Docker Desktop after --restore-agent-env)" ;;
    ja:n_exposed) echo 'このままだとあなたの SSH 鍵がコンテナ内の AI から使えてしまう' ;;
    *:n_exposed) echo 'as it stands, your SSH key is usable by the AI inside the container' ;;
    ja:restored) echo 'vscode.sh: launchd の SSH_AUTH_SOCK を %s に戻しました (Docker Desktop を再起動するならこの後)' ;;
    *:restored) echo 'vscode.sh: launchd SSH_AUTH_SOCK restored to %s (restart Docker Desktop after this, if you are going to)' ;;
    ja:must_quit) echo '  起動中の VS Code が SSH_AUTH_SOCK を持っています。完全終了 (Cmd+Q) が必要です。' ;;
    *:must_quit) echo '  The running VS Code has SSH_AUTH_SOCK. It has to be quit completely (Cmd+Q).' ;;
    ja:quit_now) echo '  今終了しますか? (未保存があれば VS Code が確認します) [y/N] ' ;;
    *:quit_now) echo '  Quit it now? (VS Code will ask about anything unsaved) [y/N] ' ;;
    ja:unset_launchd) echo 'vscode.sh: launchd の SSH_AUTH_SOCK を外しました (保存: %s。戻すには: mise run vscode:restore-agent-env)' ;;
    *:unset_launchd) echo "vscode.sh: unset launchd's SSH_AUTH_SOCK (saved in %s; to put it back: mise run vscode:restore-agent-env)" ;;
    ja:w_dd_down) echo 'vscode.sh: ⚠️  Docker Desktop が起動していません。gateway に agent を渡すには、vscode:restore-agent-env の後に Docker Desktop を起動してください' ;;
    *:w_dd_down) echo 'vscode.sh: ⚠️  Docker Desktop is not running. To get the agent to the gateway, start Docker Desktop after vscode:restore-agent-env' ;;
    ja:w_dd_bad) echo 'vscode.sh: ⚠️  Docker Desktop が SSH_AUTH_SOCK 無しで動いています。gateway の agent は使えません (vscode:restore-agent-env → Docker Desktop 再起動)' ;;
    *:w_dd_bad) echo "vscode.sh: ⚠️  Docker Desktop is running without SSH_AUTH_SOCK. The gateway's agent will not work (vscode:restore-agent-env → restart Docker Desktop)" ;;
    ja:e_launched) echo 'vscode.sh: ❌ 直接起動した本体 (pid %s) の環境に SSH_AUTH_SOCK があります。この出力を添えて報告してください' ;;
    *:e_launched) echo 'vscode.sh: ❌ the directly launched app (pid %s) has SSH_AUTH_SOCK in its environment. Report this with the output above' ;;
    ja:ok_launched) echo 'vscode.sh: 本体 pid %s の環境に SSH_AUTH_SOCK は無い' ;;
    *:ok_launched) echo 'vscode.sh: no SSH_AUTH_SOCK in the environment of app pid %s' ;;
    ja:e_running) echo 'vscode.sh: ❌ 起動中の VS Code の環境に SSH_AUTH_SOCK があります。この出力を添えて報告してください (mise run vscode:check でも再確認できます)' ;;
    *:e_running) echo 'vscode.sh: ❌ the running VS Code has SSH_AUTH_SOCK in its environment. Report this with the output above (mise run vscode:check re-checks it)' ;;
    ja:store_unlocked) echo 'vscode.sh: 秘密ストアは解錠済み' ;;
    *:store_unlocked) echo 'vscode.sh: the secret store is unlocked' ;;
    ja:store_unlock_now) echo 'vscode.sh: 秘密ストアが「%s」です。ここで解錠します (中断しても後から mise run gw:unlock)' ;;
    *:store_unlock_now) echo 'vscode.sh: the secret store is "%s". Unlocking it here (if you stop, run mise run gw:unlock later)' ;;
    ja:store_left_locked) echo 'vscode.sh: 解錠していません。後で mise run gw:unlock を実行してください' ;;
    *:store_left_locked) echo 'vscode.sh: not unlocked. Run mise run gw:unlock later' ;;
    ja:gw_not_up) echo 'vscode.sh: ゲートウェイはまだ起動していません。コンテナで開いた後、mise run gw:unlock で秘密ストアを解錠してください' ;;
    *:gw_not_up) echo 'vscode.sh: the gateway is not up yet. After opening the container, unlock the secret store with mise run gw:unlock' ;;
    ja:done) echo "vscode.sh: OK — 'Dev Containers: Reopen in Container' で開き、dev 内で 'ssh-add -l' が失敗することを確認 (mise run relay:verify)。" ;;
    *:done) echo "vscode.sh: OK — open it with 'Dev Containers: Reopen in Container', then check that 'ssh-add -l' fails inside dev (mise run relay:verify)." ;;
  esac
}
say() { local f; f=$(msg "$1"); shift; printf "$f\n" "$@"; }
# ---- macOS: where the VS Code app is, and the name of its executable ----
APP=""; EXE=""; APP_HOW=""
resolve_app() {
  [ "$os" = Darwin ] || return 0
  local real cand
  if [ -n "${SEKIMORE_VSCODE_APP:-}" ]; then APP=${SEKIMORE_VSCODE_APP%/}; APP_HOW="SEKIMORE_VSCODE_APP"; fi
  # 1. work back from what `code` actually resolves to (…/X.app/Contents/Resources/app/bin/code → X.app)
  if [ -z "$APP" ] && command -v code >/dev/null 2>&1; then
    real=$(perl -MCwd=realpath -e 'print realpath($ARGV[0])' "$(command -v code)" 2>/dev/null || true)
    cand=$(printf '%s' "$real" | sed -E 's|(\.app)/.*$|\1|')
    if [ -n "$cand" ] && [ "$cand" != "$real" ] && [ -d "$cand" ]; then APP=$cand; APP_HOW="command -v code → $real"; fi
  fi
  # 2. ask LaunchServices (works with Spotlight disabled)
  if [ -z "$APP" ]; then
    for id in com.microsoft.VSCode com.microsoft.VSCodeInsiders; do
      cand=$(osascript -e "POSIX path of (path to application id \"$id\")" 2>/dev/null || true)
      cand=${cand%/}
      if [ -n "$cand" ] && [ -d "$cand" ]; then APP=$cand; APP_HOW="LaunchServices ($id)"; break; fi
    done
  fi
  # 3. the well-known locations
  if [ -z "$APP" ]; then
    for cand in "/Applications/Visual Studio Code.app" "$HOME/Applications/Visual Studio Code.app" \
                "/Applications/Visual Studio Code - Insiders.app" "$HOME/Applications/Visual Studio Code - Insiders.app"; do
      if [ -d "$cand" ]; then APP=$cand; APP_HOW="well-known path"; break; fi
    done
  fi
  [ -n "$APP" ] || return 0
  EXE=$(defaults read "$APP/Contents/Info" CFBundleExecutable 2>/dev/null || true)
  [ -n "$EXE" ] || EXE=Electron
}

# "pid command" lines for VS Code itself (the main process). Helpers (renderer and the rest) are excluded
vscode_procs() {
  case "$os" in
    Darwin)
      if [ -n "$APP" ]; then
        ps -axo pid=,command= | grep -F "$APP/Contents/MacOS/$EXE" | grep -Ev 'Helper|--type=|Frameworks/| grep ' || true
      else
        ps -axo pid=,command= | grep -F '/Contents/MacOS/' | grep -Ei 'visual studio code|/code( - insiders)?\.app' | grep -Ev 'Helper|--type=|Frameworks/| grep ' || true
      fi ;;
    *) ps -axo pid=,command= | grep -E '^ *[0-9]+ +(/[^ ]*/)?code(-insiders)?( |$)' || true ;;
  esac
}
find_vscode_pids() { vscode_procs | awk '{print $1}'; }
# 0 if the given PID's environment has SSH_AUTH_SOCK (only your own processes are visible)
has_agent_env() {
  case "$os" in
    Darwin) ps -Eww -o command= -p "$1" 2>/dev/null | tr ' ' '\n' | grep -q '^SSH_AUTH_SOCK=' ;;
    *)      tr '\0' '\n' < "/proc/$1/environ" 2>/dev/null | grep -q '^SSH_AUTH_SOCK=' ;;
  esac
}
launchd_sock() { if [ "$os" = Darwin ]; then launchctl getenv SSH_AUTH_SOCK 2>/dev/null || true; fi; }
docker_backend_pid() { pgrep -f 'com.docker.backend' 2>/dev/null | head -1 || true; }

report() {  # returns 0 = VS Code is running and has SSH_AUTH_SOCK
  local pids found=0 dirty=0 ls dp rc
  if [ "$os" = Darwin ]; then
    ls=$(launchd_sock)
    echo "launchd SSH_AUTH_SOCK: ${ls:-<unset>}   $(msg n_launchd)"
    echo "shell   SSH_AUTH_SOCK: ${SSH_AUTH_SOCK:-<unset>}"
    rc=$(grep -ln 'SSH_AUTH_SOCK' "$HOME/.zshenv" "$HOME/.zprofile" "$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile" 2>/dev/null | tr '\n' ' ' || true)
    echo "rc files setting it:   ${rc:-<none>}   $(msg n_rc)"
    dp=$(docker_backend_pid)
    if [ -z "$dp" ]; then
      echo "Docker Desktop:        not running $(msg n_dd_down)"
    elif has_agent_env "$dp"; then
      echo "Docker Desktop:        running with SSH_AUTH_SOCK $(msg n_dd_ok)"
    else
      echo "Docker Desktop:        running WITHOUT SSH_AUTH_SOCK — $(msg n_dd_bad)"
    fi
    if [ -n "$APP" ]; then echo "VS Code app:           $APP (exe: $EXE; via $APP_HOW)"; else echo "VS Code app:           NOT FOUND (set SEKIMORE_VSCODE_APP)"; fi
  fi
  pids=$(find_vscode_pids)
  for p in $pids; do found=1; has_agent_env "$p" && dirty=1; done
  if [ "$found" -eq 0 ]; then echo "VS Code:               not running"; return 1; fi
  vscode_procs | cut -c1-160 | sed 's/^/  process: /'
  if [ "$dirty" -eq 1 ]; then
    echo "VS Code:               RUNNING WITH SSH_AUTH_SOCK — $(msg n_exposed)"; return 0
  fi
  echo "VS Code:               running without SSH_AUTH_SOCK (OK)"; return 1
}

restore_agent_env() {
  [ "$os" = Darwin ] || { echo "vscode.sh: --restore-agent-env is for macOS" >&2; exit 2; }
  local v
  v=$(cat "$SAVED_SOCK_FILE" 2>/dev/null || true)
  if [ -z "$v" ]; then
    # with nothing saved, look for launchd's ssh-agent socket (com.openssh.ssh-agent's Listeners)
    v=$(ls /private/tmp/com.apple.launchd.*/Listeners 2>/dev/null | head -1 || true)
  fi
  [ -n "$v" ] || { echo "vscode.sh: no saved value and no launchd agent socket found; logging out/in restores it" >&2; exit 1; }
  launchctl setenv SSH_AUTH_SOCK "$v"
  say restored "$v"
}

resolve_app
case "$MODE" in
  --check) if report; then exit 1; else exit 0; fi ;;
  --restore-agent-env) restore_agent_env; exit 0 ;;
  launch) ;;
  # the usage is the leading comment block; a fixed line range drops lines as the block grows
  *) sed -n '2,${/^#/!q;s/^# \{0,1\}//;p;}' "$0" >&2; exit 2 ;;
esac

if [ "${TERM_PROGRAM:-}" = "vscode" ]; then
  echo "vscode.sh: run this from Terminal.app / iTerm, not from a VS Code integrated terminal." >&2; exit 2
fi
if [ "${DEVCONTAINER:-}" = "true" ]; then
  echo "vscode.sh: this is the inside of the dev container; run it on the host (Mac)." >&2; exit 2
fi

# Have an already running VS Code quit (a new code only hands over to the existing instance)
if report; then
  say must_quit >&2
  if [ -t 0 ] && [ "$os" = Darwin ]; then
    printf '%s' "$(msg quit_now)"
    read -r ans
    if [ "$ans" = y ] || [ "$ans" = Y ]; then
      osascript -e 'tell application "Visual Studio Code" to quit' || true
      for _ in $(seq 1 30); do [ -z "$(find_vscode_pids)" ] && break; sleep 1; done
    fi
  fi
  [ -z "$(find_vscode_pids)" ] || { echo "vscode.sh: VS Code is still running; quit it (Cmd+Q) and run 'mise run vscode' again." >&2; exit 1; }
fi

launched_pid=""
if [ "$os" = Darwin ]; then
  [ -n "$APP" ] || { echo "vscode.sh: VS Code app not found. Run with SEKIMORE_VSCODE_APP=\"/path/to/Visual Studio Code.app\" (find it with: mdfind 'kMDItemCFBundleIdentifier == com.microsoft.VSCode')" >&2; exit 2; }
  electron="$APP/Contents/MacOS/$EXE"
  [ -x "$electron" ] || { echo "vscode.sh: executable not found: $electron" >&2; exit 2; }

  # (a) unset launchd's SSH_AUTH_SOCK (apps started through the GUI from now on do not get it; logging back in restores it)
  cur=$(launchd_sock)
  if [ -n "$cur" ]; then
    mkdir -p "$STATE_DIR"; printf '%s\n' "$cur" > "$SAVED_SOCK_FILE"
    launchctl unsetenv SSH_AUTH_SOCK
    say unset_launchd "$SAVED_SOCK_FILE"
  fi
  dp=$(docker_backend_pid)
  if [ -z "$dp" ]; then
    say w_dd_down >&2
  elif ! has_agent_env "$dp"; then
    say w_dd_bad >&2
  fi

  # (b) start the app directly instead of through open (it inherits the shell's environment = no SSH_AUTH_SOCK; VSCODE_CLI=1 leaves shell env resolution out)
  echo "vscode.sh: launching \"$electron\" without SSH_AUTH_SOCK: $ROOT"
  cd /
  env -u SSH_AUTH_SOCK VSCODE_CLI=1 nohup "$electron" "$ROOT" >/dev/null 2>&1 &
  launched_pid=$!
  disown "$launched_pid" 2>/dev/null || true
  cd "$ROOT"
else
  command -v code >/dev/null || { echo "vscode.sh: 'code' CLI not found" >&2; exit 2; }
  echo "vscode.sh: launching VS Code without SSH_AUTH_SOCK: $ROOT"
  env -u SSH_AUTH_SOCK VSCODE_CLI=1 code "$ROOT"
fi

# (c) wait for it to come up, then check the app's environment
for _ in $(seq 1 30); do [ -n "$(find_vscode_pids)" ] && break; sleep 1; done
sleep 3
if [ -n "$launched_pid" ] && kill -0 "$launched_pid" 2>/dev/null; then
  if has_agent_env "$launched_pid"; then
    say e_launched "$launched_pid" >&2; exit 1
  fi
  say ok_launched "$launched_pid"
fi
if report; then
  say e_running >&2
  exit 1
fi
# (d) the secret store. Locked, the relay cannot take the upstream credentials out of it.
#     When the gateway is already up, finish the unlock while the operator is at this terminal.
#     When it is not, that comes after "Reopen in Container", so only say what to do then.
SGW=${SGW:-$(dirname "$0")/sgw.sh}
if store_state=$(bash "$SGW" gw sekimore-relay store-status 2>/dev/null); then
  case "$store_state" in
    unlocked) say store_unlocked ;;
    *)
      say store_unlock_now "$store_state"
      bash "$SGW" gw-tty sekimore-relay unlock || say store_left_locked >&2
      ;;
  esac
else
  say gw_not_up
fi

say done
