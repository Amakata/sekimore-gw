#!/bin/bash
set -ex

# ---------------------------------------------------------------------------
# Agent-side setup for sekimore-relay (the relay for git and the GitHub API)
#
# Superseded by `sgw-agent setup` (relay/src/agent_setup/, #257), which the base image runs from
# 0.2.51 through sgw-post-start. This script stays for the standalone compose example and older
# base images; the two do the same things.
#
# Runs only when the gateway has a relay (http://<gw>:8420/healthz answers). Otherwise it does nothing.
# postStartCommand runs on every start, so every write is idempotent (create if absent, replace instead of append, atomic env file).
#
#   - disposable auth key  <home>/.ssh/sekimore/id_ed25519       (only valid against the relay)
#   - signing key          the gateway's filtered ssh-agent when it offers one (0.2.29, #59): the
#                          public half lands in <home>/.ssh/sekimore/signing.pub and SSH_AUTH_SOCK
#                          points at the socket. The private half never enters this container.
#                          Without it, the old behaviour: <home>/.ssh/sekimore/signing_ed25519,
#                          generated here — disposable, and therefore unable to stay registered
#   - project token        SEKIMORE_TOKEN in /etc/sekimore-agent/env (from POST /bootstrap; reused while still valid)
#   - known_hosts          the relay's host key registered under <git_domain>
#   - ~/.ssh/config        Host <git_domain> pointing at the disposable key (a marked block, replaced in place)
#   - git config       gpg.format ssh / user.signingkey / commit.gpgsign / gpg.ssh.allowedSignersFile
#   - proxy env        /etc/profile.d/sekimore-proxy.sh and a marked block in /etc/environment, from
#                      GET /api/proxy-env (#212). Only when the gateway has an upstream proxy; removed again
#                      when it stops having one. Runs whether or not the gateway has a relay
#
# Optional environment variables:
#   SEKIMORE_AGENT_USER      owner of the keys and settings (default vscode, else the current user)
#   SEKIMORE_AGENT_HOME      that user's home (default: from getent)
#   SEKIMORE_KEY_DIR         where the keys live (default <home>/.ssh/sekimore; a volume keeps them across rebuilds)
#   SEKIMORE_AGENT_ENV_FILE  the env file (default /etc/sekimore-agent/env)
#   SEKIMORE_BOOTSTRAP       auto (default) | manual — manual registers no key and fetches no token; the operator does it
#   SEKIMORE_WEBUI_PORT      the gateway's Web UI port, where /api/proxy-env lives (default 8080)
#   SEKIMORE_PROXY_ENV_ROOT  prefix for the two proxy env files (default none, i.e. /etc/...). For tests
#   SEKIMORE_GIT_DOMAIN      the domain pointed at the relay (default: from the /bootstrap response, else github.com)
#   SEKIMORE_RELAY_API_PORT / SEKIMORE_RELAY_SSH_PORT  (default 8420 / 22)
#   SEKIMORE_SIGNING_KEY_COMMENT  comment on the *generated* signing key (the title shown in GitHub). Default: "sekimore-agent-signing: <SEKIMORE_PROJECT> / <git user.name> <user.email>"
#                            Unused when the gateway offers a signing key: that one is the operator's, named on the host
#   SEKIMORE_PROJECT         the project name used above (passed from compose; omitted when unset)
# ---------------------------------------------------------------------------
# Prepare the signing key. $1 = key directory, $2 = comment. Generated when absent; an old default comment is updated (the fingerprint does not change).
sekimore_ensure_signing_key() {
  local keydir=$1 comment=$2 current
  if [ ! -f "$keydir/signing_ed25519" ]; then
    ssh-keygen -q -t ed25519 -N '' -C "$comment" -f "$keydir/signing_ed25519"
    return 0
  fi
  current=$(cut -d' ' -f3- "$keydir/signing_ed25519.pub" 2>/dev/null || true)
  if [ -n "${SEKIMORE_SIGNING_KEY_COMMENT:-}" ]; then
    # A comment the operator set explicitly is applied to an existing key too (rewritten only when it differs; the key itself is untouched)
    if [ "$current" != "$comment" ]; then
      ssh-keygen -q -c -C "$comment" -P '' -f "$keydir/signing_ed25519" >/dev/null 2>&1 || true
    fi
  elif [ "${current#sekimore-agent-signing@}" != "$current" ] && [ "${comment#sekimore-agent-signing@}" = "$comment" ]; then
    # Update the old default (…@<hostname>) to the form that carries the name
    ssh-keygen -q -c -C "$comment" -P '' -f "$keydir/signing_ed25519" >/dev/null 2>&1 || true
  fi
}


# Build the signing key comment. $1 = the target user's HOME (its global git config is read)
sekimore_signing_key_comment() {
  if [ -n "${SEKIMORE_SIGNING_KEY_COMMENT:-}" ]; then printf '%s' "$SEKIMORE_SIGNING_KEY_COMMENT"; return 0; fi
  local home=$1 name email project
  name=$(HOME=$home git config --global --get user.name 2>/dev/null || true)
  email=$(HOME=$home git config --global --get user.email 2>/dev/null || true)
  project=${SEKIMORE_PROJECT:-}
  local who="" c="sekimore-agent-signing"
  if [ -n "$name" ]; then who=$name; fi
  if [ -n "$email" ]; then who="${who:+$who }<$email>"; fi
  if [ -n "$project" ] && [ -n "$who" ]; then c="$c: $project / $who"
  elif [ -n "$project" ]; then c="$c: $project"
  elif [ -n "$who" ]; then c="$c: $who"
  else c="$c@$(hostname)"
  fi
  printf '%s' "$c"
}

# Put the agent guide (sgw-agent guide) where each tool reads it automatically.
#   Claude Code: <home>/.claude/skills/sekimore-relay/SKILL.md (loaded when the work is related)
#   Codex CLI:   a marked block in <home>/.codex/AGENTS.md (always read, so it carries the essentials and points at the guide)
# For any other tool, put the output of `sgw-agent guide` wherever that tool expects it.
# SEKIMORE_AGENT_INSTRUCTIONS=claude,codex (default), or none to disable. Idempotent: a re-run replaces the block.
sekimore_agent_instructions() {
  local home=$1 own=$2 signing_mode=${3:-}
  local targets=${SEKIMORE_AGENT_INSTRUCTIONS:-claude,codex}
  if [ "$targets" = none ] || [ -z "$targets" ]; then return 0; fi
  if ! command -v sekimore-relay >/dev/null 2>&1; then
    echo "[agent] relay: sekimore-relay not found; skipping agent instructions"
    return 0
  fi
  # The guide goes to an AI agent, so it defaults to English; SEKIMORE_GUIDE_LANG overrides it.
  # --lang was added in 0.2.4, so fall back to the plain form on an older CLI.
  local guide lang=${SEKIMORE_GUIDE_LANG:-en}
  guide=$(sekimore-relay agent guide --lang "$lang" 2>/dev/null) || guide=""
  if [ -z "$guide" ]; then
    guide=$(sekimore-relay agent guide 2>/dev/null) || guide=""
  fi
  if [ -z "$guide" ]; then
    echo "[agent] relay: sekimore-relay agent guide is not available (old CLI); skipping agent instructions"
    return 0
  fi
  local version
  version=$(sekimore-relay --version 2>/dev/null | awk '{print $2}')
  # 0.2.29 (#59): the guide gets a signing section only where the relay actually refuses an
  # unsigned commit. Telling an agent about a rule that does not apply to it is how the rules
  # that do apply stop being read.
  local signing_note=""
  if [ "$signing_mode" = required ]; then
    signing_note=$(cat <<'SIGNING_EOF'

## Signing is required here

Every commit you push has to carry a signature. The relay reads the pack and refuses the push
otherwise — `pushing refs/heads/... is not allowed: commit <sha> carries no signature`.

This container is already set up to sign: plain `git commit` signs. So if a push is refused for
this, the commit was made in a way that went around that setup (`-c commit.gpgsign=false`, a
`--no-gpg-sign`, or a commit written by a tool of its own).

- Fix the tip with `git commit -S --amend --no-edit`, and older commits with `git rebase --exec 'git commit -S --amend --no-edit' <base>`.
- **Do not turn signing off.** `git config commit.gpgsign false` makes every later commit fail
  the same check, one at a time. If signing itself is broken, say so and stop; it is the
  operator's to fix, not something to work around.
SIGNING_EOF
)
  fi
  case ",$targets," in
    *,claude,*)
      local skill_dir="$home/.claude/skills/sekimore-relay"
      install -d -m 755 "$skill_dir"
      {
        echo "---"
        echo "name: sekimore-relay"
        echo "description: In this environment git push, pull requests, CI checks, issues and the GitHub API all go through sekimore-relay. Read this before pushing, opening a PR, checking CI or calling GitHub. sekimore-relay ${version:-unknown}"
        echo "---"
        echo
        printf '%s\n' "$guide"
        if [ -n "$signing_note" ]; then printf '%s\n' "$signing_note"; fi
      } > "$skill_dir/SKILL.md.tmp.$$"
      mv -f "$skill_dir/SKILL.md.tmp.$$" "$skill_dir/SKILL.md"
      chown -R "$own" "$home/.claude/skills" 2>/dev/null || true
      echo "[agent] relay: wrote Claude Code skill $skill_dir/SKILL.md"
      ;;
  esac
  case ",$targets," in
    *,codex,*)
      local codex_dir="$home/.codex" agents="$home/.codex/AGENTS.md"
      install -d -m 755 "$codex_dir"
      touch "$agents"
      local tmpa="$agents.tmp.$$"
      awk '/^<!-- >>> sekimore-relay >>> -->/{skip=1} /^<!-- <<< sekimore-relay <<< -->/{skip=0; next} !skip' "$agents" > "$tmpa"
      {
        echo "<!-- >>> sekimore-relay >>> -->"
        echo "## sekimore-relay (git and GitHub go through the relay)"
        echo
        echo "In this environment git push, pull requests, CI checks and the GitHub API all go through sekimore-relay. Run \`sgw-agent guide\` before you start working."
        echo "In short: push to \`HEAD:refs/heads/sekimore/<topic>\` (then \`sgw-agent pr create\`) or to \`HEAD:refs/for/<base>\`. Direct pushes to main, tags, deletions and HTTPS git are refused."
        echo "Check your permissions and repositories with \`sgw-agent whoami\`. Denials are printed on stderr as \`sgw-agent: …\`. The operator's credentials are not in this environment; do not try to work around the relay."
        if [ -n "$signing_note" ]; then
          echo "Every commit you push has to be signed; plain \`git commit\` signs here. If a push is refused for a missing signature, amend with \`git commit -S --amend --no-edit\` — never turn \`commit.gpgsign\` off."
        fi
        echo "<!-- <<< sekimore-relay <<< -->"
      } >> "$tmpa"
      mv -f "$tmpa" "$agents"
      chown -R "$own" "$codex_dir" 2>/dev/null || true
      echo "[agent] relay: wrote Codex instructions block in $agents"
      ;;
  esac
  return 0
}

# Git's signing settings, put where a later write to ~/.gitconfig cannot undo them (#145).
#
# The Dev Containers extension copies the host's user.name, user.email and user.signingkey into
# ~/.gitconfig after postStart, every time the container starts — over what this script wrote, so
# the AI's commits went to sign with the operator's own key, which the gateway's socket does not
# hold. git reads a config file top to bottom and the last value wins, and `git config --global`
# edits a key where it already is rather than moving it. So the settings go into a root-owned file
# that ~/.gitconfig includes as its very last lines, and the same keys are written above it too:
# the extension then rewrites those lines in place, above the include, and the include still wins.
#
# $1 = the user's home, $2 = its owner (user:group), $3 = the file to hold the settings,
# $4 = the public key to sign with, or empty when there is none (signing is then turned off)
sekimore_git_signing() {
  local home=$1 own=$2 file=$3 key=$4
  local signers="$home/.config/git/allowed_signers" tmp gpgsign=false
  [ -n "$key" ] && gpgsign=true
  tmp=$(mktemp "$file.XXXXXX")
  {
    echo "# Written by sekimore-agent-setup.sh on every start. ~/.gitconfig includes this last, so"
    echo "# these win over anything written above them later (the Dev Containers extension copies the"
    echo "# host's user.* in). Do not turn signing off: see the agent guide."
  } > "$tmp"
  git config --file "$tmp" gpg.format ssh
  git config --file "$tmp" gpg.ssh.allowedSignersFile "$signers"
  [ -z "$key" ] || git config --file "$tmp" user.signingkey "$key"
  git config --file "$tmp" commit.gpgsign "$gpgsign"
  git config --file "$tmp" tag.gpgsign "$gpgsign"
  chmod 644 "$tmp"
  # root's, so the agent cannot edit it; readable, so its git can
  if [ "$(id -u)" = 0 ]; then chown root:root "$tmp"; fi
  mv -f "$tmp" "$file"

  # The same keys in ~/.gitconfig itself, so each already has a line there for the extension to
  # rewrite in place. A key it had to add would land at the end, after the include, and win.
  HOME=$home git config --global gpg.format ssh
  HOME=$home git config --global gpg.ssh.allowedSignersFile "$signers"
  [ -z "$key" ] || HOME=$home git config --global user.signingkey "$key"
  HOME=$home git config --global commit.gpgsign "$gpgsign"
  HOME=$home git config --global tag.gpgsign "$gpgsign"

  # The include, last and once. An earlier one (from the previous start) is taken out first, so a
  # restart does not leave it in the middle of the file with the extension's writes below it.
  local re
  re=$(printf '%s' "$file" | sed 's/[][\.*^$/]/\\&/g')
  HOME=$home git config --global --unset-all include.path "^$re\$" 2>/dev/null || true
  printf '[include]\n\tpath = %s\n' "$file" >> "$home/.gitconfig"
  chown "$own" "$home/.gitconfig"
}

# ---------------------------------------------------------------------------
# Proxy environment (#212)
#
# With `proxy.upstream_proxy` set, dev's ordinary traffic used to leave the gateway directly:
# the DNS answer admitted the address into the firewall's ipset and the packet was NATed
# straight out, so it never reached Squid and never reached the upstream. Nothing told this
# container that a proxy existed. The gateway now says so at GET /api/proxy-env, and these
# functions turn that answer into HTTP_PROXY / NO_PROXY for every shell here.
#
# NO_PROXY is not optional: Squid refuses CONNECT to the relay's handler targets
# (api.github.com, registry.npmjs.org, …) on purpose, so HTTP_PROXY alone would break the
# GitHub API and npm. The gateway builds the list from `domain_handlers`, so a handler added
# later is covered without editing anything here.
#
# SEKIMORE_PROXY_ENV_ROOT prefixes both files; it exists so a test can write into a temp dir.
# ---------------------------------------------------------------------------
SEKIMORE_PROXY_MARK_BEGIN='# sekimore-proxy begin'
SEKIMORE_PROXY_MARK_END='# sekimore-proxy end'

# Ask the gateway. $1 = gateway IP. Retries for ~10 s: postStartCommand can run before the Web
# UI is listening. Prints the JSON body, or nothing when it never answered.
sekimore_proxy_env_fetch() {
  local gw=$1 port=${SEKIMORE_WEBUI_PORT:-8080} i body
  command -v curl >/dev/null 2>&1 || return 1
  for i in 1 2 3 4 5; do
    body=$(curl -fsS -m 3 "http://$gw:$port/api/proxy-env" 2>/dev/null) || body=""
    if [ -n "$body" ]; then
      printf '%s' "$body"
      return 0
    fi
    [ "$i" = 5 ] || sleep 2
  done
  return 1
}

# One JSON string or number field, without jq (the agent image may not have it).
# $1 = body, $2 = key.
sekimore_json_field() {
  printf '%s' "$1" | tr ',{}' '\n\n\n' | sed -n "s/^[[:space:]]*\"$2\"[[:space:]]*:[[:space:]]*//p" \
    | head -1 | sed 's/^"//; s/"$//; s/[[:space:]]*$//'
}

# The "no_proxy" array, joined with commas. Takes the body on $1.
sekimore_json_no_proxy() {
  printf '%s' "$1" | sed -n 's/.*"no_proxy"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p' \
    | tr -d ' "' | sed 's/^,//; s/,$//'
}

# Remove the marked block from a file, in place. $1 = path.
sekimore_proxy_block_remove() {
  local f=$1
  [ -f "$f" ] || return 0
  sed -i "/^${SEKIMORE_PROXY_MARK_BEGIN}\$/,/^${SEKIMORE_PROXY_MARK_END}\$/d" "$f"
}

# Write /etc/profile.d/sekimore-proxy.sh and the marked block in /etc/environment, or take both
# out again. $1 = the JSON body from the gateway, $2 = the gateway IP.
sekimore_proxy_env_apply() {
  local body=$1 gw=$2
  local root=${SEKIMORE_PROXY_ENV_ROOT:-}
  local profile="$root/etc/profile.d/sekimore-proxy.sh"
  local envfile="$root/etc/environment"
  local configured port no_proxy url

  configured=$(sekimore_json_field "$body" configured)
  if [ "$configured" != "true" ]; then
    # No upstream proxy (or Squid is off): leave nothing behind from a previous start, so a
    # container that had a proxy and no longer does stops sending its traffic to a dead one.
    rm -f "$profile"
    sekimore_proxy_block_remove "$envfile"
    echo "[agent] proxy: no upstream proxy configured; HTTP_PROXY not set"
    return 0
  fi

  port=$(sekimore_json_field "$body" port)
  [ -n "$port" ] || port=3128
  no_proxy=$(sekimore_json_no_proxy "$body")
  url="http://$gw:$port"

  install -d -m 755 "$root/etc/profile.d"
  cat > "$profile" <<EOF
$SEKIMORE_PROXY_MARK_BEGIN
# Written by sekimore agent-setup. Edits are lost on the next container start;
# change proxy.upstream_proxy / proxy.no_proxy in the gateway's config.yml instead.
export HTTP_PROXY="$url"
export HTTPS_PROXY="$url"
export http_proxy="$url"
export https_proxy="$url"
export NO_PROXY="$no_proxy"
export no_proxy="$no_proxy"
$SEKIMORE_PROXY_MARK_END
EOF
  chmod 644 "$profile"

  # /etc/environment is read by PAM and by anything that is not a login shell, so the same six
  # assignments go there too (no `export`; it is not a script). Replaced, never appended twice.
  touch "$envfile"
  sekimore_proxy_block_remove "$envfile"
  cat >> "$envfile" <<EOF
$SEKIMORE_PROXY_MARK_BEGIN
HTTP_PROXY="$url"
HTTPS_PROXY="$url"
http_proxy="$url"
https_proxy="$url"
NO_PROXY="$no_proxy"
no_proxy="$no_proxy"
$SEKIMORE_PROXY_MARK_END
EOF

  local egress
  egress=$(sekimore_json_field "$body" direct_egress)
  echo "[agent] proxy: HTTP_PROXY=$url, NO_PROXY=$no_proxy (direct_egress: ${egress:-allow})"
}

# Fetch and apply. A gateway without the endpoint (an older one) leaves everything as it was.
sekimore_proxy_env_setup() {
  local gw=$1 body
  if ! body=$(sekimore_proxy_env_fetch "$gw"); then
    echo "[agent] proxy: /api/proxy-env did not answer; leaving the proxy environment alone"
    return 0
  fi
  sekimore_proxy_env_apply "$body" "$gw"
}

sekimore_relay_setup() {
  local gw=$1
  local api_port=${SEKIMORE_RELAY_API_PORT:-8420}
  local ssh_port=${SEKIMORE_RELAY_SSH_PORT:-22}
  local endpoint="http://$gw:$api_port"
  local env_file=${SEKIMORE_AGENT_ENV_FILE:-/etc/sekimore-agent/env}
  local mode=${SEKIMORE_BOOTSTRAP:-auto}

  if ! command -v curl >/dev/null 2>&1; then
    echo "[agent] relay: 'curl' not found, skipping relay setup"
    return 0
  fi
  if ! curl -fsS -m 3 -o /dev/null "$endpoint/healthz" 2>/dev/null; then
    echo "[agent] relay: no relay on $gw:$api_port, skipping (gateway without git-relay)"
    return 0
  fi
  local c
  for c in ssh-keygen ssh-keyscan git; do
    if ! command -v "$c" >/dev/null 2>&1; then
      echo "[agent] relay: ERROR: '$c' not found (install openssh-client and git in the agent image)"
      return 1
    fi
  done

  # The target user
  local user=${SEKIMORE_AGENT_USER:-vscode}
  if ! getent passwd "$user" >/dev/null 2>&1; then
    echo "[agent] relay: user '$user' not found, using $(id -un)"
    user=$(id -un)
  fi
  local home=${SEKIMORE_AGENT_HOME:-$(getent passwd "$user" | cut -d: -f6)}
  local own="$user:$(id -gn "$user")"
  local keydir=${SEKIMORE_KEY_DIR:-$home/.ssh/sekimore}

  install -d -m 700 "$home/.ssh" "$keydir"
  chown "$own" "$home/.ssh" "$keydir"
  install -d -m 755 "$(dirname "$env_file")"

  # Keys (not regenerated when they already exist)
  if [ ! -f "$keydir/id_ed25519" ]; then
    ssh-keygen -q -t ed25519 -N '' -C "sekimore-agent@$(hostname)" -f "$keydir/id_ed25519"
  fi
  chown -R "$own" "$keydir"
  chmod 600 "$keydir/id_ed25519"
  chmod 644 "$keydir/id_ed25519.pub"
  # The signing key is decided after /bootstrap answers: the gateway may hold one, and generating
  # one here first would make an unregistered key on every start (#59).

  # ---- project token (kept out of the trace) ----
  local xtrace=0
  case $- in *x*) xtrace=1 ;; esac
  set +x
  local token="" token_expires="" repo="" git_domain="" git_domains="" resp=""
  local sig_sock="" sig_fp="" sig_mode=""
  if [ -r "$env_file" ]; then
    token=$(sed -n 's/^SEKIMORE_TOKEN=//p' "$env_file" | head -1)
    token_expires=$(sed -n 's/^SEKIMORE_TOKEN_EXPIRES=//p' "$env_file" | head -1)
    repo=$(sed -n 's/^SEKIMORE_REPO=//p' "$env_file" | head -1)
    git_domain=$(sed -n 's/^SEKIMORE_GIT_DOMAIN=//p' "$env_file" | head -1)
    # 0.2.0: several upstreams ("domain:port,domain:port", the first is the default). Stored so a re-run that skips bootstrap can still rebuild the Host blocks.
    git_domains=$(sed -n 's/^SEKIMORE_GIT_DOMAINS=//p' "$env_file" | head -1)
    # 0.2.29 (#59): so a run that keeps its token, and therefore never calls /bootstrap, still
    # knows where the gateway's signing socket is
    sig_sock=$(sed -n 's/^SEKIMORE_SIGNING_SOCK=//p' "$env_file" | head -1)
    sig_fp=$(sed -n 's/^SEKIMORE_SIGNING_KEY=//p' "$env_file" | head -1)
    sig_mode=$(sed -n 's/^SEKIMORE_SIGNING_MODE=//p' "$env_file" | head -1)
  fi
  if [ -n "$token" ] && curl -fsS -m 5 -o /dev/null -X POST -H "Authorization: Bearer $token" \
       -H 'Content-Type: application/json' -d '{}' "$endpoint/whoami" 2>/dev/null; then
    echo "[agent] relay: existing project token is still valid, keeping it"
  else
    token=""
    if [ "$mode" = "auto" ]; then
      local pub
      pub=$(cat "$keydir/id_ed25519.pub")
      resp=$(curl -sS -m 10 -X POST -H 'Content-Type: application/json' \
               -d "{\"public_key\":\"$pub\",\"label\":\"$(hostname)\"}" "$endpoint/bootstrap" 2>/dev/null) || resp=""
      token=$(printf '%s' "$resp" | grep -o 'skm_[0-9a-f]\{64\}' | head -1)
      token_expires=$(printf '%s' "$resp" | grep -o '"token_expires":"[^"]*"' | cut -d'"' -f4)
      if [ -n "$token" ]; then
        echo "[agent] relay: registered the disposable key and received a project token"
        if [ -z "$repo" ]; then
          repo=$(printf '%s' "$resp" | grep -o '"repos":\[[^]]*\]' | grep -o '"[^"]*"' | sed -n '2p' | tr -d '"')
        fi
        local d
        d=$(printf '%s' "$resp" | grep -o '"git_domain":"[^"]*"' | cut -d'"' -f4)
        if [ -n "$d" ]; then git_domain=$d; fi
        # 0.2.0: "git_domains":[{"domain":"github.com","ssh_port":22,...},{"domain":"ghe.example.com","ssh_port":2222,...}]
        local gd
        gd=$(printf '%s' "$resp" | grep -o '"git_domains":\[[^]]*\]' | grep -o '{[^}]*}' | while IFS= read -r obj; do
               dd=$(printf '%s' "$obj" | grep -o '"domain":"[^"]*"' | cut -d'"' -f4)
               pp=$(printf '%s' "$obj" | grep -o '"ssh_port":[0-9]*' | cut -d: -f2)
               if [ -n "$dd" ]; then printf '%s:%s,' "$dd" "${pp:-22}"; fi
             done)
        if [ -n "$gd" ]; then git_domains=${gd%,}; fi
        # 0.2.29 (#59): "signing":{"socket":"…","fingerprint":"SHA256:…","namespace":"git","public_key":"…"}
        # Its presence is how this script detects that the gateway offers a signing key. Assigned
        # unconditionally, so a gateway that stopped offering one clears the cached value instead
        # of leaving dev pointed at a socket that is no longer served.
        local sb
        sb=$(printf '%s' "$resp" | grep -o '"signing":{[^}]*}') || sb=""
        sig_sock=$(printf '%s' "$sb" | grep -o '"socket":"[^"]*"' | cut -d'"' -f4)
        sig_fp=$(printf '%s' "$sb" | grep -o '"fingerprint":"[^"]*"' | cut -d'"' -f4)
        sig_mode=$(printf '%s' "$sb" | grep -o '"mode":"[^"]*"' | cut -d'"' -f4)
      else
        echo "[agent] relay: WARNING: bootstrap did not return a token: $(printf '%s' "$resp" | head -c 300)"
        echo "[agent] relay:   the operator can register the key and issue a token on the gateway:"
        echo "[agent] relay:     sekimore-relay add-key \"$pub\" && sekimore-relay token"
      fi
    else
      echo "[agent] relay: bootstrap is manual; the operator must put SEKIMORE_TOKEN into $env_file"
    fi
  fi
  git_domain=${git_domain:-${SEKIMORE_GIT_DOMAIN:-github.com}}
  # Without a list (a 0.1.x relay, or manual setup) use the default domain alone; if the list omits it, put it first
  if [ -z "$git_domains" ]; then git_domains="$git_domain:$ssh_port"; fi
  case ",$git_domains," in
    *",$git_domain:"*) ;;
    *) git_domains="$git_domain:$ssh_port,$git_domains" ;;
  esac

  # ---- the signing key (#59) ----
  # The gateway offers a filtered ssh-agent when relay.signing_key is configured: it answers for
  # one fingerprint and signs nothing that is not a git signature, so handing dev the socket hands
  # it no authentication path and no private key. The socket's presence is confirmed before
  # anything is pointed at it, because a missing shared volume is the likely misconfiguration.
  local signing_pub="" signing_mode=none listed=""
  if [ -n "$sig_sock" ] && [ -S "$sig_sock" ]; then
    # The exit status is what decides, not the output: an empty agent prints "The agent has no
    # identities." on stdout and exits 1, and taking that as a key is how this first went wrong
    if listed=$(SSH_AUTH_SOCK="$sig_sock" ssh-add -L 2>/dev/null) && [ -n "$listed" ]; then
      signing_pub=$(printf '%s\n' "$listed" | head -1)
      signing_mode=gateway
      # Only the public half. The private one stays in the operator's agent, on the host
      printf '%s\n' "$signing_pub" > "$keydir/signing.pub"
      chmod 644 "$keydir/signing.pub"
      chown "$own" "$keydir/signing.pub"
    else
      echo "[agent] relay: WARNING: the gateway's signing socket holds no key${sig_fp:+ ($sig_fp)}."
      echo "[agent] relay:   The operator has to ssh-add it on the host. Commits will NOT be signed."
    fi
  elif [ -n "$sig_sock" ]; then
    echo "[agent] relay: WARNING: the gateway named a signing socket ($sig_sock) that is not in this container."
    echo "[agent] relay:   Mount the shared volume into the dev service (docker-compose.relay.yml). Commits will NOT be signed."
  else
    # No gateway key: generate one here, as before. It lives and dies with this volume, so it
    # cannot stay registered with the forge — which is exactly #59. The comment becomes the title
    # in GitHub; an existing key still on the old default is updated to carry the name.
    sekimore_ensure_signing_key "$keydir" "$(sekimore_signing_key_comment "$home")"
    chmod 600 "$keydir/signing_ed25519"
    chmod 644 "$keydir/signing_ed25519.pub"
    chown "$own" "$keydir/signing_ed25519" "$keydir/signing_ed25519.pub"
    signing_pub=$(cat "$keydir/signing_ed25519.pub")
    signing_mode=generated
  fi

  # The env file (atomic, 0600, owned by the target user)
  local tmp="$env_file.tmp.$$"
  {
    echo "# generated by sekimore-agent-setup.sh — re-run the setup to refresh"
    echo "SEKIMORE_IP=$gw"
    echo "SEKIMORE_ENDPOINT=$endpoint"
    echo "SEKIMORE_GIT_DOMAIN=$git_domain"
    echo "SEKIMORE_GIT_DOMAINS=$git_domains"
    if [ -n "$repo" ]; then echo "SEKIMORE_REPO=$repo"; fi
    if [ -n "$token" ]; then echo "SEKIMORE_TOKEN=$token"; fi
    # The next two let the `sekimore` wrapper renew by itself (it re-runs bootstrap once the token expires)
    if [ -n "$token_expires" ]; then echo "SEKIMORE_TOKEN_EXPIRES=$token_expires"; fi
    echo "SEKIMORE_AGENT_KEY=$keydir/id_ed25519.pub"
    if [ -n "$sig_sock" ]; then
      echo "SEKIMORE_SIGNING_SOCK=$sig_sock"
      if [ -n "$sig_fp" ]; then echo "SEKIMORE_SIGNING_KEY=$sig_fp"; fi
    fi
    if [ -n "$sig_mode" ]; then echo "SEKIMORE_SIGNING_MODE=$sig_mode"; fi
    if [ "$signing_mode" = gateway ]; then
      # git signs through the gateway's filtered agent. Exporting it is not an authentication
      # path: the socket refuses everything that is not an SSHSIG blob in namespace git, and the
      # ~/.ssh/config block below keeps IdentitiesOnly yes for the relay's hosts anyway.
      echo "SSH_AUTH_SOCK=$sig_sock"
    fi
  } > "$tmp"
  chmod 600 "$tmp"
  chown "$own" "$tmp"
  mv -f "$tmp" "$env_file"
  local token_note="(NO token)"
  if [ -n "$token" ]; then token_note="(token issued)"; fi
  unset token token_expires resp
  if [ "$xtrace" = 1 ]; then set -x; fi

  # ---- known_hosts: register the relay's host key under <git_domain> (replaced, so a new key is picked up) ----
  # 0.2.0: each upstream has its own relay-side port. keyscan each one and register it as "[domain]:port,[gw]:port"
  local kh="$home/.ssh/known_hosts"
  touch "$kh"
  ssh-keygen -q -R "$gw" -f "$kh" >/dev/null 2>&1 || true
  local entry d p scan i hostnames
  for entry in $(printf '%s' "$git_domains" | tr ',' ' '); do
    d=${entry%%:*}
    p=${entry##*:}
    if [ "$p" = "$entry" ] || [ -z "$p" ]; then p=22; fi
    ssh-keygen -q -R "$d" -f "$kh" >/dev/null 2>&1 || true
    if [ "$p" != 22 ]; then
      ssh-keygen -q -R "[$d]:$p" -f "$kh" >/dev/null 2>&1 || true
      ssh-keygen -q -R "[$gw]:$p" -f "$kh" >/dev/null 2>&1 || true
    fi
    scan=""
    for i in 1 2 3; do
      scan=$(ssh-keyscan -T 3 -p "$p" "$gw" 2>/dev/null) || scan=""
      if [ -n "$scan" ]; then break; fi
      sleep 1
    done
    if [ -z "$scan" ]; then
      echo "[agent] relay: ERROR: relay on $gw:$p (for $d) did not answer ssh-keyscan"
      return 1
    fi
    if [ "$p" = 22 ]; then hostnames="$d,$gw"; else hostnames="[$d]:$p,[$gw]:$p"; fi
    # Replace the first field of the keyscan output ("<ip>" or "[<ip>]:<port>")
    printf '%s\n' "$scan" | grep -v '^#' | awk -v h="$hostnames" '{ $1 = h; print }' >> "$kh"
  done
  rm -f "$kh.old"
  chown "$own" "$kh"
  chmod 644 "$kh"

  # ---- ~/.ssh/config: replace the marked block (one Host block per upstream, all using the same disposable key) ----
  local cfg="$home/.ssh/config"
  touch "$cfg"
  local tmpc="$cfg.tmp.$$"
  awk '/^# >>> sekimore-relay >>>/{skip=1} /^# <<< sekimore-relay <<</{skip=0; next} !skip' "$cfg" > "$tmpc"
  {
    echo "# >>> sekimore-relay >>>"
    for entry in $(printf '%s' "$git_domains" | tr ',' ' '); do
      d=${entry%%:*}
      p=${entry##*:}
      if [ "$p" = "$entry" ] || [ -z "$p" ]; then p=22; fi
      echo "Host $d"
      echo "  User git"
      echo "  Port $p"
      echo "  IdentityFile $keydir/id_ed25519"
      echo "  IdentitiesOnly yes"
    done
    echo "# <<< sekimore-relay <<<"
  } >> "$tmpc"
  mv -f "$tmpc" "$cfg"
  chmod 600 "$cfg"
  chown "$own" "$cfg"

  # ---- git: sign with the AI key (never with the operator's key) ----
  mkdir -p "$home/.config/git"
  if [ -O "$home/.config" ]; then chown "$own" "$home/.config"; fi
  chown "$own" "$home/.config/git"
  local signers="$home/.config/git/allowed_signers"
  touch "$signers"
  local signkey=""
  if [ -n "$signing_pub" ]; then
    if [ "$signing_mode" = gateway ]; then signkey="$keydir/signing.pub"; else signkey="$keydir/signing_ed25519.pub"; fi
  fi
  # No key: signing goes off. Leaving it on would make every commit fail, and signing with a key
  # nobody registered is what #59 is about.
  sekimore_git_signing "$home" "$own" "$(dirname "$env_file")/gitconfig" "$signkey"
  if [ -n "$signing_pub" ]; then
    local sigpub principal
    sigpub=$(printf '%s' "$signing_pub" | cut -d' ' -f1,2)
    principal=${GIT_COMMITTER_EMAIL:-${GIT_AUTHOR_EMAIL:-*}}
    if ! grep -qF "$sigpub" "$signers"; then
      echo "$principal namespaces=\"git\" $sigpub" >> "$signers"
    fi
  fi
  chown "$own" "$signers"
  if [ -f "$home/.gitconfig" ]; then chown "$own" "$home/.gitconfig"; fi

  # ---- put the agent guide where each tool reads it (Claude Code skill / Codex AGENTS.md) ----
  sekimore_agent_instructions "$home" "$own" "$sig_mode" || echo "[agent] relay: WARNING: could not write agent instructions"

  echo "[agent] relay: ready — git via $git_domains → $gw, API $endpoint, env $env_file $token_note"
  if [ "$sig_mode" = required ] && [ -z "$signing_pub" ]; then
    echo "[agent] relay: ERROR: this project is signing: required and there is no key to sign with."
    echo "[agent] relay:   Every push to a branch will be refused until the operator fixes the signing key above."
  fi
  case $signing_mode in
    gateway)
      # Nothing for anyone to register: the key is the operator's and was registered once.
      echo "[agent] relay: commits are signed through the gateway's filtered agent ($sig_sock)"
      echo "[agent] relay:   $signing_pub"
      ;;
    generated)
      echo "[agent] relay: commits are signed with $keydir/signing_ed25519.pub"
      echo "[agent] relay: register that public key on GitHub as a *Signing Key* (Settings → SSH and GPG keys → New SSH key → Key type: Signing Key):"
      cat "$keydir/signing_ed25519.pub"
      echo "[agent] relay: NOTE: this key is generated in this container and dies with its volume, so it has to be"
      echo "[agent] relay:   registered again every time. relay.signing_key on the gateway replaces it with one key per person (#59)."
      ;;
    *)
      echo "[agent] relay: commits are NOT signed (commit.gpgsign false); see the warning above"
      ;;
  esac
  return 0
}

# Guard so tests can source the functions alone (source it with SEKIMORE_AGENT_SETUP_SOURCE_ONLY=1)
if [ -n "${SEKIMORE_AGENT_SETUP_SOURCE_ONLY:-}" ]; then
  return 0 2>/dev/null || exit 0
fi

echo "[agent] Starting agent setup..."

# Check if required commands are available
if ! command -v ip >/dev/null 2>&1; then
  echo "[agent] ERROR: 'ip' command not found"
  echo "[agent] Please install iproute2 package in your Docker image"
  echo "[agent] Add to Dockerfile: RUN apt-get update && apt-get install -y iproute2"
  exit 1
fi

# Docker internal DNS (127.0.0.11) is disabled, so we need to find sekimore-gw by scanning
echo "[agent] Scanning subnet to find sekimore-gw..."

# Get our IP address and subnet
MY_IP=$(ip -4 addr show eth0 | grep inet | awk '{print $2}' | cut -d'/' -f1)
SUBNET_MASK=$(ip -4 addr show eth0 | grep inet | awk '{print $2}' | cut -d'/' -f2)
NETWORK=$(echo $MY_IP | cut -d'.' -f1-3)

# Validate that we got network information
if [ -z "$MY_IP" ] || [ -z "$SUBNET_MASK" ]; then
  echo "[agent] ERROR: Could not get IP address or subnet mask from eth0"
  echo "[agent] Network interface status:"
  ip -4 addr show eth0 || echo "[agent] eth0 interface not found"
  exit 1
fi

echo "[agent] My IP: $MY_IP, Subnet: $NETWORK.0/$SUBNET_MASK"

# Scan subnet to find host with DNS port (53) open
# Optimization: parallel ping → ARP table → 2-stage TCP → full scan
SEKIMORE_IP=""

# Method 0: Parallel ping to populate ARP cache quickly (standard tools only, fastest)
echo "[agent] Using parallel ping to populate ARP cache..."

# Execute parallel ping based on subnet size
if [ "$SUBNET_MASK" -ge 24 ]; then
  # /24 or smaller: Parallel ping entire subnet (max 256 IPs)
  echo "[agent] Pinging entire /$SUBNET_MASK subnet..."
  for i in {1..255}; do
    TEST_IP="${NETWORK}.${i}"

    # Skip ourselves
    if [ "$TEST_IP" = "$MY_IP" ]; then
      continue
    fi

    # Background parallel ping (1 count, 1 second timeout)
    ping -c 1 -W 1 "$TEST_IP" >/dev/null 2>&1 &
  done

  # Wait for all pings to complete (max 2 seconds)
  sleep 2

else
  # Larger than /24: Parallel ping priority IPs only
  echo "[agent] Pinging priority IPs in /$SUBNET_MASK subnet..."
  PRIORITY_IPS="1 2 254 253 3 4 5 10 20 100"

  for i in $PRIORITY_IPS; do
    TEST_IP="${NETWORK}.${i}"

    if [ "$TEST_IP" = "$MY_IP" ]; then
      continue
    fi

    ping -c 1 -W 1 "$TEST_IP" >/dev/null 2>&1 &
  done

  sleep 1
fi

# Get live hosts from ARP cache
echo "[agent] Checking ARP cache after ping sweep..."
ARP_HOSTS=$(ip neigh show dev eth0 | grep REACHABLE | awk '{print $1}')

if [ -z "$ARP_HOSTS" ]; then
  echo "[agent] No REACHABLE hosts in ARP cache, checking all entries..."
  ARP_HOSTS=$(ip neigh show dev eth0 | grep -v FAILED | grep -v INCOMPLETE | awk '{print $1}')
fi

if [ -n "$ARP_HOSTS" ]; then
  ARP_COUNT=$(echo "$ARP_HOSTS" | wc -l)
  echo "[agent] Found $ARP_COUNT host(s) in ARP cache"

  # Test DNS port (53) on found hosts
  for TEST_IP in $ARP_HOSTS; do
    if [ "$TEST_IP" = "$MY_IP" ]; then
      continue
    fi

    echo "[agent] Testing DNS on $TEST_IP (from ARP cache)..."
    if timeout 0.3 bash -c "echo > /dev/tcp/$TEST_IP/53" 2>/dev/null; then
      echo "[agent] Found DNS server at $TEST_IP (via parallel ping + ARP)"
      SEKIMORE_IP=$TEST_IP
      break
    fi
  done
else
  echo "[agent] No hosts found in ARP cache, falling back to TCP-based discovery..."
fi

# Method 1: 2-stage TCP approach (parallel TCP → ARP cache → DNS test)
if [ -z "$SEKIMORE_IP" ]; then
  echo "[agent] Using 2-stage ARP discovery approach..."

  # Phase 1: Parallel TCP scan to populate ARP cache (based on subnet size)
  if [ "$SUBNET_MASK" -ge 24 ]; then
    # /24 or smaller: Scan entire subnet (max 256 IPs)
    echo "[agent] Scanning entire /$SUBNET_MASK subnet to populate ARP cache..."
    for i in {1..255}; do
      TEST_IP="${NETWORK}.${i}"

      # Skip ourselves
      if [ "$TEST_IP" = "$MY_IP" ]; then
        continue
      fi

      # Background parallel TCP connection attempt (for ARP cache population)
      timeout 0.1 bash -c "echo > /dev/tcp/$TEST_IP/53" 2>/dev/null &
    done

    # Wait for all parallel processes to complete
    wait

  else
    # Larger than /24: Optimized scan (priority IPs in nearby /24 blocks)
    echo "[agent] Optimized scan for /$SUBNET_MASK subnet to populate ARP cache..."
    PRIORITY_IPS="1 2 254 253 3 4 5"

    for i in $PRIORITY_IPS; do
      TEST_IP="${NETWORK}.${i}"

      # Skip ourselves
      if [ "$TEST_IP" = "$MY_IP" ]; then
        continue
      fi

      # Background parallel TCP connection attempt
      timeout 0.1 bash -c "echo > /dev/tcp/$TEST_IP/53" 2>/dev/null &
    done

    # Wait for all parallel processes to complete
    wait
  fi

  # Phase 2: Get live hosts from ARP cache
  echo "[agent] Checking ARP cache for live hosts..."
  ARP_HOSTS=$(ip neigh show dev eth0 | grep -v FAILED | grep -v INCOMPLETE | awk '{print $1}')

  if [ -z "$ARP_HOSTS" ]; then
    echo "[agent] WARNING: No hosts found in ARP cache"
  else
    ARP_COUNT=$(echo "$ARP_HOSTS" | wc -l)
    echo "[agent] Found $ARP_COUNT host(s) in ARP cache"
  fi

  # Phase 3: Test DNS port (53) on hosts recorded in ARP cache
  for TEST_IP in $ARP_HOSTS; do
    # Skip ourselves
    if [ "$TEST_IP" = "$MY_IP" ]; then
      continue
    fi

    echo "[agent] Testing DNS on $TEST_IP..."
    if timeout 0.3 bash -c "echo > /dev/tcp/$TEST_IP/53" 2>/dev/null; then
      echo "[agent] Found DNS server at $TEST_IP (via 2-stage ARP approach)"
      SEKIMORE_IP=$TEST_IP
      break
    fi
  done

  # If not found, wait briefly and retry (timing issue mitigation)
  if [ -z "$SEKIMORE_IP" ]; then
    echo "[agent] DNS server not found on first attempt, waiting for services to start..."

    # Retry up to 3 times (0.5 second interval)
    for retry in 1 2 3; do
      sleep 0.5

      # Retry Phase 2 and Phase 3 (ARP cache already populated)
      echo "[agent] Retrying ARP cache check (attempt $retry/3)..."
      ARP_HOSTS=$(ip neigh show dev eth0 | grep -v FAILED | grep -v INCOMPLETE | awk '{print $1}')

      if [ -n "$ARP_HOSTS" ]; then
        ARP_COUNT=$(echo "$ARP_HOSTS" | wc -l)
        echo "[agent] Found $ARP_COUNT host(s) in ARP cache (retry $retry)"

        for TEST_IP in $ARP_HOSTS; do
          # Skip ourselves
          if [ "$TEST_IP" = "$MY_IP" ]; then
            continue
          fi

          echo "[agent] Testing DNS on $TEST_IP (retry $retry)..."
          if timeout 0.3 bash -c "echo > /dev/tcp/$TEST_IP/53" 2>/dev/null; then
            echo "[agent] Found DNS server at $TEST_IP (via 2-stage ARP approach, retry $retry)"
            SEKIMORE_IP=$TEST_IP
            break 2  # Break outer loop as well
          fi
        done
      fi
    done
  fi

  # Error message if not found even after retry
  if [ -z "$SEKIMORE_IP" ]; then
    echo "[agent] ERROR: Could not find sekimore-gw in /$SUBNET_MASK subnet (after retry)"
    if [ "$SUBNET_MASK" -lt 24 ]; then
      echo "[agent] HINT: Consider using a smaller subnet (e.g., /24 or /25) for better discovery"
    fi
    echo "[agent] HINT: Ensure sekimore-gw container is running and accessible"
  fi
fi

# Method 2: Sequential scan (fallback, reliable but slow)
if [ -z "$SEKIMORE_IP" ]; then
  SCAN_COUNT=0
  MAX_SCAN=1024  # Max scan count (timeout mitigation)

  if [ "$SUBNET_MASK" -ge 24 ]; then
    # /24 or larger: Scan within same 3rd octet (max 256 IPs)
    echo "[agent] Scanning /$SUBNET_MASK subnet..."
    for i in {6..255}; do
      TEST_IP="${NETWORK}.${i}"

      # Skip ourselves and already-checked priority IPs
      if [ "$TEST_IP" = "$MY_IP" ] || echo "$PRIORITY_IPS" | grep -qw "$i"; then
        continue
      fi

      SCAN_COUNT=$((SCAN_COUNT + 1))
      if [ $SCAN_COUNT -gt $MAX_SCAN ]; then
        echo "[agent] Max scan limit reached ($MAX_SCAN)"
        break
      fi

      # Check if port 53 (DNS) is open
      if timeout 0.3 bash -c "echo > /dev/tcp/$TEST_IP/53" 2>/dev/null; then
        echo "[agent] Found DNS server at $TEST_IP (via subnet scan)"
        SEKIMORE_IP=$TEST_IP
        break
      fi
    done

  elif [ "$SUBNET_MASK" -ge 16 ]; then
    # /16-/23: Scan changing 3rd octet (limited to 1024 IPs)
    echo "[agent] Scanning /$SUBNET_MASK subnet (limited to $MAX_SCAN IPs)..."
    BASE_NETWORK=$(echo $MY_IP | cut -d'.' -f1-2)
    MY_THIRD_OCTET=$(echo $MY_IP | cut -d'.' -f3)

    # Start from our 3rd octet and scan forward/backward
    for offset in $(seq 0 255); do
      for direction in 0 1; do
        if [ $direction -eq 0 ]; then
          third=$((MY_THIRD_OCTET + offset))
        else
          third=$((MY_THIRD_OCTET - offset))
        fi

        # Range check
        if [ $third -lt 0 ] || [ $third -gt 255 ]; then
          continue
        fi

        # Check only priority IPs within each 3rd octet (full scan takes too long)
        for fourth in 1 2 254 253; do
          TEST_IP="${BASE_NETWORK}.${third}.${fourth}"

          # Skip ourselves
          if [ "$TEST_IP" = "$MY_IP" ]; then
            continue
          fi

          SCAN_COUNT=$((SCAN_COUNT + 1))
          if [ $SCAN_COUNT -gt $MAX_SCAN ]; then
            echo "[agent] Max scan limit reached ($MAX_SCAN)"
            break 3
          fi

          # Check if port 53 (DNS) is open
          if timeout 0.3 bash -c "echo > /dev/tcp/$TEST_IP/53" 2>/dev/null; then
            echo "[agent] Found DNS server at $TEST_IP (via /16 scan)"
            SEKIMORE_IP=$TEST_IP
            break 3
          fi
        done
      done
    done
  fi
fi

if [ -z "$SEKIMORE_IP" ]; then
  echo "[agent] ERROR: could not find sekimore-gw (no DNS server found in subnet)"
  exit 1
fi

echo "[agent] sekimore-gw IP (discovered): $SEKIMORE_IP"

# Rewrite /etc/resolv.conf (remove 127.0.0.11, use sekimore-gw's DNS)
echo "nameserver $SEKIMORE_IP" > /etc/resolv.conf

echo "[agent] DNS configuration updated:"
cat /etc/resolv.conf

# Configure default route
ip route del default || true
ip route add default via $SEKIMORE_IP dev eth0 || true

echo "[agent] default via $SEKIMORE_IP set"
ip route || true

# Verification: Test if DNS resolution via sekimore-gw works
echo "[agent] Testing DNS resolution..."
if nslookup google.com $SEKIMORE_IP > /dev/null 2>&1; then
  echo "[agent] DNS resolution via sekimore-gw: OK"
else
  echo "[agent] WARNING: DNS resolution via sekimore-gw failed"
fi

# The proxy environment (#212). Asks the gateway which traffic should go through Squid and
# writes HTTP_PROXY / NO_PROXY. A gateway too old to answer, or one with no upstream proxy,
# leaves this container as it was.
sekimore_proxy_env_setup "$SEKIMORE_IP" || echo "[agent] WARNING: proxy environment setup failed"

# sekimore-relay (the relay for git and the GitHub API). Does nothing when the gateway has no relay; a failure still leaves DNS and routes in place
sekimore_relay_setup "$SEKIMORE_IP" || echo "[agent] WARNING: relay setup failed; git through the relay will not work until it is fixed"

echo "[agent] Setup complete"
