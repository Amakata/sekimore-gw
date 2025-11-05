#!/bin/bash
set -ex

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

echo "[agent] Setup complete"
