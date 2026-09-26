#!/usr/bin/env bash
# sgw.sh — operate this devcontainer's compose stack (started by the Dev Containers extension) from the Mac.
# Called from the mise tasks. To use it directly:
#
#   sgw.sh gw   [cmd...]   run cmd in the sekimore-gw container (default: sekimore-relay check)
#   sgw.sh gw-tty cmd...   the same, always with a terminal (for commands that read a passphrase)
#   sgw.sh dev  [cmd...]   run cmd in the dev container (as the vscode user. default: zsh)
#   sgw.sh id   <service>  print the container ID
#   sgw.sh port <service> [container-port]  print the published host port (default: 8080)
#   sgw.sh project         print the compose project name (Dev Containers: "<folder name>_devcontainer")
#   sgw.sh ps              list the stack's containers
#   sgw.sh recreate        pull the latest image and recreate the gateway (docker restart keeps the old one)
#
# How it finds them: the compose labels (service name + the project's working_dir = this .devcontainer).
# The project name depends on the folder name, so look it up by label rather than by name.
#
# Distributed by sgw-devcontainer-base: `mise run upgrade:apply` replaces this file, and stops
# rather than overwrite it once it has been edited.
set -euo pipefail
# The Docker CLI's "What's next: Try Docker Debug…" hint after docker exec would land in the
# middle of relay:verify's output (#102). Every host-side docker call goes through this file.
export DOCKER_CLI_HINTS=false

ROOT=${MISE_PROJECT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
COMPOSE_DIR=${SGW_COMPOSE_DIR:-$ROOT/.devcontainer}

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
    ja:inside) echo 'sgw: ここは dev コンテナの中です。スタックを動かしている Docker Desktop のホスト (Mac) で実行してください。' ;;
    *:inside) echo "sgw: this is the inside of the dev container; run it on the host (Mac) where Docker Desktop runs the stack." ;;
    ja:none) echo "sgw: サービス '%s' のコンテナが動いていません (devcontainer は開いていますか? working_dir=%s)" ;;
    *:none) echo "sgw: no running container for service '%s' (is the devcontainer open? working_dir=%s)" ;;
    ja:several) echo "sgw: '%s' のコンテナが複数動いています。他を止めるか、MISE_PROJECT_ROOT / SGW_COMPOSE_DIR を指定してください:" ;;
    *:several) echo "sgw: several '%s' containers are running; stop the others or set MISE_PROJECT_ROOT / SGW_COMPOSE_DIR:" ;;
    ja:needs_tty) echo 'sgw.sh: %s は標準入力に端末が要ります (パイプで渡さないでください)' ;;
    *:needs_tty) echo 'sgw.sh: %s needs a terminal on stdin (do not pipe it)' ;;
    ja:no_port) echo "sgw: サービス '%s' はコンテナのポート %s をホストに公開していません" ;;
    *:no_port) echo "sgw: service '%s' publishes no host port for %s" ;;
    ja:waiting) echo 'gateway の起動を待っています' ;;
    *:waiting) echo 'waiting for the gateway' ;;
    ja:recreated) echo '完了。Web UI の Relay タブを再読み込みしてください (または mise run gw:check)' ;;
    *:recreated) echo 'done. reload the Web UI Relay tab (or run: mise run gw:check)' ;;
  esac
}
say() { local f; f=$(msg "$1"); shift; printf "$f\n" "$@"; }

if [ "${DEVCONTAINER:-}" = "true" ] && [ -z "${SGW_FORCE:-}" ]; then
  say inside >&2
  exit 2
fi
by_label() { docker ps -q --filter "label=com.docker.compose.project.working_dir=$COMPOSE_DIR" "$@"; }

find_container() {
  local svc=$1 ids n
  ids=$(by_label --filter "label=com.docker.compose.service=$svc")
  if [ -z "$ids" ]; then
    # fallback where the working_dir label does not match (path normalization differences, etc.):
    # take it when the service name alone is unique
    ids=$(docker ps -q --filter "label=com.docker.compose.service=$svc")
  fi
  n=$(printf '%s\n' "$ids" | grep -c . || true)
  if [ "$n" -eq 0 ]; then
    say none "$svc" "$COMPOSE_DIR" >&2
    docker ps -a --format '  {{.Names}}  {{.Status}}  ({{.Image}})' --filter "label=com.docker.compose.service=$svc" >&2 || true
    exit 1
  fi
  if [ "$n" -gt 1 ]; then
    say several "$svc" >&2
    docker ps --format '  {{.Names}}  {{.Label "com.docker.compose.project.working_dir"}}' --filter "label=com.docker.compose.service=$svc" >&2
    exit 1
  fi
  printf '%s' "$ids"
}

# Build compose's -f / --env-file arguments into the array FARGS. $1 = the project working_dir,
# $2 = the config_files label ("," separated), $3 = env file.
# A path can hold spaces (the Dev Containers generated file lives under
# "~/Library/Application Support/…"), so keep them in an array rather than concatenating a string.
# The config_files label is used when it is there, but a container recreated in the past without the
# overlay has no overlay left in its label either.
# On a relay setup (docker-compose.relay.yml exists) always include that file. Files that do not exist,
# and duplicates, are skipped.
compose_args() {
  local wd=$1 cfgs=$2 envfile=$3 c
  FARGS=()
  add_f() {
    local f=$1 x
    [ -f "$f" ] || return 0
    for x in "${FARGS[@]}"; do [ "$x" = "$f" ] && return 0; done
    FARGS+=(-f "$f")
  }
  if [ -n "$cfgs" ]; then
    local OLDIFS=$IFS; IFS=","
    for c in $cfgs; do
      case "$c" in /*) add_f "$c" ;; *) add_f "$wd/$c" ;; esac
    done
    IFS=$OLDIFS
  fi
  [ ${#FARGS[@]} -eq 0 ] && add_f "$wd/docker-compose.yml"
  add_f "$wd/docker-compose.relay.yml"
  [ -n "$envfile" ] && [ -f "$envfile" ] && FARGS+=(--env-file "$envfile")
  return 0
}


# -t only when both ends are the person's terminal: an interactive shell needs it, and output piped
# on (relay:verify's `| sed`) must not get the carriage returns a pty adds. Decided here, in this
# shell: asked inside "$(...)", stdout is the substitution's pipe, so the old tty_flag function
# always answered "no terminal" and interactive shells started without one, waiting on stdin (#50).
if [ -t 0 ] && [ -t 1 ]; then TTY_OPT=-it; else TTY_OPT=-i; fi

# Let the relay's CLI colour its output when a person is watching. Decided here for the same reason
# as TTY_OPT: inside "$(...)" stdout is the substitution's pipe and [ -t 1 ] is always false. So
# `mise run gw:check` at a terminal gets colour, while `$(mise run gw:check)` and relay:verify's
# `bash "$SGW" gw sekimore-relay check | sed …` stay plain — the `| sed` keeps stdout a pipe, so
# nothing is injected there and its output is unchanged.
# An explicit SEKIMORE_COLOR from the caller wins; NO_COLOR is handed through when it is set.
COLOR_ENV=()
if [ -n "${SEKIMORE_COLOR:-}" ]; then COLOR_ENV=(-e SEKIMORE_COLOR)
elif [ -t 1 ] && [ -z "${NO_COLOR+x}" ]; then COLOR_ENV=(-e SEKIMORE_COLOR=always)
fi
if [ -n "${NO_COLOR+x}" ]; then COLOR_ENV+=(-e NO_COLOR); fi

case "${1:-}" in
  gw)
    shift; cid=$(find_container sekimore-gw)
    if [ $# -eq 0 ]; then set -- sekimore-relay check; fi
    exec docker exec "$TTY_OPT" ${COLOR_ENV[@]+"${COLOR_ENV[@]}"} "$cid" "$@" ;;
  # Always -it, for a command that reads a passphrase. the plain `gw` asks for stdout as well, and a
  # task runner that prefixes output makes stdout a pipe — so the detection says "no terminal"
  # while the person is sitting at one. What matters here is stdin, and asking for a terminal we
  # do not need costs nothing: docker only refuses -t when stdin itself is not one.
  gw-tty)
    shift; cid=$(find_container sekimore-gw)
    [ -t 0 ] || { say needs_tty "$*" >&2; exit 2; }
    exec docker exec -it ${COLOR_ENV[@]+"${COLOR_ENV[@]}"} "$cid" "$@" ;;
  dev)
    shift; cid=$(find_container dev)
    if [ $# -eq 0 ]; then set -- zsh; fi
    exec docker exec "$TTY_OPT" -u vscode "$cid" "$@" ;;
  id)
    find_container "${2:?usage: sgw.sh id <service>}"; echo ;;
  # Ask the running container which host port it listens on. Not the compose file, because a
  # project moves the published port when 8090 is taken, and a number written into a task drifts
  # from it the moment that happens. The running container cannot disagree with itself.
  port)
    svc=${2:?usage: sgw.sh port <service> [container-port]}
    cport=${3:-8080}
    cid=$(find_container "$svc")
    hp=$(docker port "$cid" "$cport" 2>/dev/null | head -1)
    [ -n "$hp" ] || { say no_port "$svc" "$cport" >&2; exit 1; }
    # take the number out of "0.0.0.0:8091" or "[::]:8091"
    printf '%s\n' "${hp##*:}" ;;
  recreate)
    # Recreate the gateway on the latest image. docker restart resumes with the existing image, so it
    # does not swap.
    # Use it after bumping the image tag in compose (the Web UI's Relay tab is stale, etc.).
    # Dev Containers layers several compose files (docker-compose.yml + docker-compose.relay.yml + the
    # generated one), so pass every one of them with -f, taken from the container's config_files label.
    # Missing even one drops the relay overlay (the agent socket mount, etc.) and breaks the gateway.
    cid=$(find_container sekimore-gw)
    running=$(docker inspect -f "{{.Config.Image}}" "$cid")
    proj=$(docker inspect -f "{{index .Config.Labels \"com.docker.compose.project\"}}" "$cid")
    wd=$(docker inspect -f "{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}" "$cid")
    cfgs=$(docker inspect -f "{{index .Config.Labels \"com.docker.compose.project.config_files\"}}" "$cid")
    envfile=$(docker inspect -f "{{index .Config.Labels \"com.docker.compose.project.environment_file\"}}" "$cid")
    compose_args "$wd" "$cfgs" "$envfile"
    # What is pulled is the image compose declares (right after a tag bump it is newer than the running
    # container's image).
    # compose up does not re-pull a tag it already has, so an update to the same tag (latest, etc.) is
    # taken in here too.
    # Where compose config is unavailable, it falls back to the running container's image
    image=$(docker compose -p "$proj" --project-directory "$wd" "${FARGS[@]}" config --images sekimore-gw 2>/dev/null | head -1)
    image=${image:-$running}
    if [ "$image" != "$running" ]; then echo "gateway: $running → $image (project=$proj)"; else echo "gateway: $image (project=$proj)"; fi
    printf 'compose:'; printf ' %q' "${FARGS[@]}"; echo
    echo "before:  $(docker inspect -f "{{.Image}}" "$cid")"
    docker pull "$image"
    docker compose -p "$proj" --project-directory "$wd" "${FARGS[@]}" up -d --force-recreate sekimore-gw
    new=$(find_container sekimore-gw)
    echo "after:   $(docker inspect -f "{{.Image}}" "$new")"
    printf "%s" "$(msg waiting)"
    for _ in $(seq 1 30); do
      # the gateway has no curl, so hit it with python (always present)
      if docker exec "$new" python -c "import urllib.request,sys; urllib.request.urlopen(\"http://127.0.0.1:8080/api/config\",timeout=3)" 2>/dev/null; then echo " ok"; break; fi
      printf "."; sleep 1
    done
    say recreated ;;
  project)
    cid=$(find_container sekimore-gw)
    docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$cid" ;;
  ps)
    docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' --filter "label=com.docker.compose.project.working_dir=$COMPOSE_DIR" ;;
  *)
    # Print the leading comment block until it runs out. Cutting it at a line number drops the
    # last subcommand silently as soon as one line of usage is added (adding port nearly did).
    sed -n '2,${/^#/!q;s/^# \{0,1\}//;p;}' "$0" >&2; exit 2 ;;
esac
