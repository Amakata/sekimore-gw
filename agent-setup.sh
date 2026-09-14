#!/bin/bash
set -ex

# ---------------------------------------------------------------------------
# sekimore-relay (git / GitHub API の中継関所) のエージェント側セットアップ
#
# gateway に relay が居る (http://<gw>:8420/healthz が応答する) ときだけ動く。居なければ何もしない。
# postStartCommand は毎起動で走るので、全ての書き込みは冪等 (生成は存在チェック、追記は置換、env は atomic)。
#
#   - 使い捨て認証鍵   <home>/.ssh/sekimore/id_ed25519        (関所にしか通用しない)
#   - AI 専用署名鍵    <home>/.ssh/sekimore/signing_ed25519   (公開鍵を GitHub に Signing Key として登録する)
#   - 案件トークン     /etc/sekimore-agent/env の SEKIMORE_TOKEN (POST /bootstrap で受け取る。既存が有効なら再利用)
#   - known_hosts      関所のホスト鍵を <git_domain> として登録
#   - ~/.ssh/config    Host <git_domain> → 使い捨て鍵 (マーカー付きブロックを置換)
#   - git config       gpg.format ssh / user.signingkey / commit.gpgsign / gpg.ssh.allowedSignersFile
#
# 環境変数 (任意):
#   SEKIMORE_AGENT_USER      鍵と設定の所有者 (既定 vscode。無ければ現在のユーザー)
#   SEKIMORE_AGENT_HOME      上記ユーザーのホーム (既定 getent)
#   SEKIMORE_KEY_DIR         鍵の置き場 (既定 <home>/.ssh/sekimore。volume にすると再ビルドでも鍵が変わらない)
#   SEKIMORE_AGENT_ENV_FILE  env ファイル (既定 /etc/sekimore-agent/env)
#   SEKIMORE_BOOTSTRAP       auto (既定) | manual  — manual なら鍵登録もトークン取得もせず、操作者に任せる
#   SEKIMORE_GIT_DOMAIN      relay に向けたドメイン (既定は /bootstrap の応答、無ければ github.com)
#   SEKIMORE_RELAY_API_PORT / SEKIMORE_RELAY_SSH_PORT  (既定 8420 / 22)
#   SEKIMORE_SIGNING_KEY_COMMENT  署名鍵のコメント (GitHub 登録時の Title)。既定は "sekimore-agent-signing: <SEKIMORE_PROJECT> / <git user.name> <user.email>"
#   SEKIMORE_PROJECT         上の案件名 (compose から渡す。無ければ省略)
# ---------------------------------------------------------------------------
# 署名鍵を用意する。$1 = 鍵ディレクトリ、$2 = コメント。無ければ生成、旧既定コメントのままなら更新 (fingerprint は変わらない)
sekimore_ensure_signing_key() {
  local keydir=$1 comment=$2
  if [ ! -f "$keydir/signing_ed25519" ]; then
    ssh-keygen -q -t ed25519 -N '' -C "$comment" -f "$keydir/signing_ed25519"
  elif grep -q ' sekimore-agent-signing@' "$keydir/signing_ed25519.pub" 2>/dev/null \
       && [ "${comment#sekimore-agent-signing@}" = "$comment" ]; then
    ssh-keygen -q -c -C "$comment" -P '' -f "$keydir/signing_ed25519" >/dev/null 2>&1 || true
  fi
}


# 署名鍵のコメントを組む。$1 = 対象ユーザーの HOME (git の global 設定を読む)
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

  # 対象ユーザー
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

  # 鍵 (存在すれば生成しない)
  if [ ! -f "$keydir/id_ed25519" ]; then
    ssh-keygen -q -t ed25519 -N '' -C "sekimore-agent@$(hostname)" -f "$keydir/id_ed25519"
  fi
  # 署名鍵のコメントは GitHub に Signing Key として登録するときの Title になるので、誰の・どの案件の AI 鍵か分かる形にする
  # (sekimore_signing_key_comment)。既存の鍵が旧既定 "sekimore-agent-signing@<hostname>" のままなら名前入りに更新する (鍵は不変)
  sekimore_ensure_signing_key "$keydir" "$(sekimore_signing_key_comment "$home")"
  chown -R "$own" "$keydir"
  chmod 600 "$keydir/id_ed25519" "$keydir/signing_ed25519"
  chmod 644 "$keydir/id_ed25519.pub" "$keydir/signing_ed25519.pub"

  # ---- 案件トークン (トレースに出さない) ----
  local xtrace=0
  case $- in *x*) xtrace=1 ;; esac
  set +x
  local token="" repo="" git_domain="" resp=""
  if [ -r "$env_file" ]; then
    token=$(sed -n 's/^SEKIMORE_TOKEN=//p' "$env_file" | head -1)
    repo=$(sed -n 's/^SEKIMORE_REPO=//p' "$env_file" | head -1)
    git_domain=$(sed -n 's/^SEKIMORE_GIT_DOMAIN=//p' "$env_file" | head -1)
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
      if [ -n "$token" ]; then
        echo "[agent] relay: registered the disposable key and received a project token"
        if [ -z "$repo" ]; then
          repo=$(printf '%s' "$resp" | grep -o '"repos":\[[^]]*\]' | grep -o '"[^"]*"' | sed -n '2p' | tr -d '"')
        fi
        local d
        d=$(printf '%s' "$resp" | grep -o '"git_domain":"[^"]*"' | cut -d'"' -f4)
        if [ -n "$d" ]; then git_domain=$d; fi
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

  # env ファイル (atomic、0600、所有者は対象ユーザー)
  local tmp="$env_file.tmp.$$"
  {
    echo "# generated by sekimore-agent-setup.sh — re-run the setup to refresh"
    echo "SEKIMORE_IP=$gw"
    echo "SEKIMORE_ENDPOINT=$endpoint"
    echo "SEKIMORE_GIT_DOMAIN=$git_domain"
    if [ -n "$repo" ]; then echo "SEKIMORE_REPO=$repo"; fi
    if [ -n "$token" ]; then echo "SEKIMORE_TOKEN=$token"; fi
  } > "$tmp"
  chmod 600 "$tmp"
  chown "$own" "$tmp"
  mv -f "$tmp" "$env_file"
  local token_note="(NO token)"
  if [ -n "$token" ]; then token_note="(token issued)"; fi
  unset token resp
  if [ "$xtrace" = 1 ]; then set -x; fi

  # ---- known_hosts: 関所のホスト鍵を <git_domain> として登録 (置換なので鍵が変わっても追従) ----
  local kh="$home/.ssh/known_hosts"
  touch "$kh"
  ssh-keygen -q -R "$git_domain" -f "$kh" >/dev/null 2>&1 || true
  ssh-keygen -q -R "$gw" -f "$kh" >/dev/null 2>&1 || true
  if [ "$ssh_port" != 22 ]; then
    ssh-keygen -q -R "[$git_domain]:$ssh_port" -f "$kh" >/dev/null 2>&1 || true
    ssh-keygen -q -R "[$gw]:$ssh_port" -f "$kh" >/dev/null 2>&1 || true
  fi
  rm -f "$kh.old"
  local scan="" i
  for i in 1 2 3; do
    scan=$(ssh-keyscan -T 3 -p "$ssh_port" "$gw" 2>/dev/null) || scan=""
    if [ -n "$scan" ]; then break; fi
    sleep 1
  done
  if [ -z "$scan" ]; then
    echo "[agent] relay: ERROR: relay on $gw:$ssh_port did not answer ssh-keyscan"
    return 1
  fi
  local hostnames
  if [ "$ssh_port" = 22 ]; then hostnames="$git_domain,$gw"; else hostnames="[$git_domain]:$ssh_port,[$gw]:$ssh_port"; fi
  # keyscan の先頭フィールド ("<ip>" または "[<ip>]:<port>") を差し替える
  printf '%s\n' "$scan" | grep -v '^#' | awk -v h="$hostnames" '{ $1 = h; print }' >> "$kh"
  chown "$own" "$kh"
  chmod 644 "$kh"

  # ---- ~/.ssh/config: マーカー付きブロックを置換 ----
  local cfg="$home/.ssh/config"
  touch "$cfg"
  local tmpc="$cfg.tmp.$$"
  awk '/^# >>> sekimore-relay >>>/{skip=1} /^# <<< sekimore-relay <<</{skip=0; next} !skip' "$cfg" > "$tmpc"
  cat >> "$tmpc" <<CFG
# >>> sekimore-relay >>>
Host $git_domain
  User git
  Port $ssh_port
  IdentityFile $keydir/id_ed25519
  IdentitiesOnly yes
# <<< sekimore-relay <<<
CFG
  mv -f "$tmpc" "$cfg"
  chmod 600 "$cfg"
  chown "$own" "$cfg"

  # ---- git: AI 専用鍵で署名 (依頼者の鍵では署名しない) ----
  mkdir -p "$home/.config/git"
  if [ -O "$home/.config" ]; then chown "$own" "$home/.config"; fi
  chown "$own" "$home/.config/git"
  local signers="$home/.config/git/allowed_signers"
  HOME=$home git config --global gpg.format ssh
  HOME=$home git config --global user.signingkey "$keydir/signing_ed25519.pub"
  HOME=$home git config --global commit.gpgsign true
  HOME=$home git config --global tag.gpgsign true
  HOME=$home git config --global gpg.ssh.allowedSignersFile "$signers"
  local sigpub principal
  sigpub=$(cut -d' ' -f1,2 "$keydir/signing_ed25519.pub")
  principal=${GIT_COMMITTER_EMAIL:-${GIT_AUTHOR_EMAIL:-*}}
  touch "$signers"
  if ! grep -qF "$sigpub" "$signers"; then
    echo "$principal namespaces=\"git\" $sigpub" >> "$signers"
  fi
  chown "$own" "$signers"
  if [ -f "$home/.gitconfig" ]; then chown "$own" "$home/.gitconfig"; fi

  echo "[agent] relay: ready — git via $git_domain → $gw:$ssh_port, API $endpoint, env $env_file $token_note"
  echo "[agent] relay: commits are signed with $keydir/signing_ed25519.pub"
  echo "[agent] relay: register that public key on GitHub as a *Signing Key* (Settings → SSH and GPG keys → New SSH key → Key type: Signing Key):"
  cat "$keydir/signing_ed25519.pub"
  return 0
}

# テストから関数だけ読み込むためのガード (SEKIMORE_AGENT_SETUP_SOURCE_ONLY=1 で source する)
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

# sekimore-relay (git / GitHub API 中継関所)。gateway に relay が居なければ何もしない。失敗しても DNS / ルートは維持する
sekimore_relay_setup "$SEKIMORE_IP" || echo "[agent] WARNING: relay setup failed; git through the relay will not work until it is fixed"

echo "[agent] Setup complete"
