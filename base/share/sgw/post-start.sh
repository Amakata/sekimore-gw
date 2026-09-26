#!/bin/sh
# post-start.sh — what devcontainer.json's postStartCommand runs, inside the dev container:
#
#   1. sekimore-agent-setup.sh as root, with every SEKIMORE_* variable this container has
#   2. docker-init.sh, which starts the Docker daemon inside dev
#   3. take out the HTTPS credential helper the Dev Containers extension plants (below)
#   4. the project's own .devcontainer/scripts/post-create.sh, when there is one
#
#   "postStartCommand": "sh /workspace/.devcontainer/sgw/post-start.sh"
#
# Why every SEKIMORE_* variable rather than a list: sudo resets the environment, so a variable
# from .env reaches agent-setup only if --preserve-env= names it, and one it does not name is set
# and then silently ignored. That list used to sit in devcontainer.json, the project's own file,
# and fell behind each time agent-setup gained an input (SEKIMORE_GUIDE_LANG). The names are taken
# from the environment at the moment this runs, so there is nothing to keep in step. It hands root
# nothing new: these are the container's own environment, which the vscode user already has.
#
# Anything else a project wants at start goes in .devcontainer/scripts/post-create.sh, which is
# the project's.
#
# Distributed with sekimore-gw (base/share/sgw/): `mise run upgrade:apply` replaces this file, and stops
# rather than overwrite it once it has been edited.
set -e

here=$(cd "$(dirname "$0")" && pwd)
# The three steps' commands, overridable only so tests can stand in for them
agent_setup=${SGW_AGENT_SETUP:-/usr/local/bin/sekimore-agent-setup.sh}
docker_init=${SGW_DOCKER_INIT:-/usr/local/bin/docker-init.sh}
post_create=${SGW_POST_CREATE:-$here/../scripts/post-create.sh}

# Names only, one per line, then joined with commas: SEKIMORE_ followed by the rest of a name
vars=$(env | sed -n 's/^\(SEKIMORE_[A-Za-z0-9_]*\)=.*/\1/p' | sort -u | paste -sd, -)
if [ -n "$vars" ]; then
  sudo --preserve-env="$vars" "$agent_setup"
else
  sudo "$agent_setup"
fi
"$docker_init"

# The VS Code Dev Containers extension writes a git credential.helper into /etc/gitconfig and
# ~/.gitconfig that hands HTTPS git the operator's GitHub credentials from the host — a way around
# the gateway, whose git goes over SSH. It writes it again on every start, so it is taken out on
# every start. Here rather than in rc.d: /etc/gitconfig needs sudo, and it has to hold for the AI's
# non-interactive commands too. (The other route, GIT_ASKPASS, is 70-sekimore.zsh's.) Each project
# used to carry this in post-create.sh, and the copies carried a bug that stopped the start (#56).
# SEKIMORE_ALLOW_CREDENTIAL_HELPER=1 keeps the helper, for tracking a problem down.
if [ "${SEKIMORE_ALLOW_CREDENTIAL_HELPER:-0}" != 1 ]; then
  removed=
  for scope in system global; do
    as=; [ "$scope" = global ] || as=sudo
    case $(git config --"$scope" --get-all credential.helper 2>/dev/null || true) in
      *vscode-remote-containers*|*vscode-server*)
        $as git config --"$scope" --unset-all credential.helper 2>/dev/null || true
        # an empty value clears any helper set before it, in a file read earlier
        $as git config --"$scope" credential.helper "" 2>/dev/null || true
        removed="$removed $scope"
        ;;
    esac
  done
  if [ -n "$removed" ]; then
    echo "[post-start] took out the VS Code HTTPS git credential helper (${removed# }); git goes over the gateway's SSH. SEKIMORE_ALLOW_CREDENTIAL_HELPER=1 keeps it"
  fi
fi
# 0.2.26 moved the credential-helper removal here, out of each project's post-create.sh. A copy
# left behind there does not just duplicate the work: its last statement is a test that is false
# once this file has already taken the helper out, so the function returns non-zero and `set -e`
# stops the start. The project then fails every time, with no output saying why (#64). Warn rather
# than edit: post-create.sh belongs to the project.
if [ -f "$post_create" ] && grep -q 'disable_vscode_credential_helper' "$post_create" 2>/dev/null; then
  echo "[post-start] WARNING: $post_create still defines disable_vscode_credential_helper." >&2
  echo "[post-start]   base 0.2.26 does this on every start, before post-create.sh runs, so the copy" >&2
  echo "[post-start]   is not needed — and it stops the start once there is no helper left to remove." >&2
  echo "[post-start]   Take the function and its call out of post-create.sh (UPGRADING: base 0.2.26)." >&2
fi
if [ -f "$post_create" ]; then
  sh "$post_create"
fi
