#!/bin/bash
set -e

# Use iptables-legacy (to avoid compatibility issues with Docker's nf_tables)
update-alternatives --set iptables /usr/sbin/iptables-legacy
update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

# DNS configuration uses Docker's default (127.0.0.11)
# sekimore-gw itself uses 127.0.0.11 for external domain + service name resolution
# ai-agent uses sekimore-gw's DNS server (e.g., 10.100.0.2)

# Default route configuration is handled by orchestrator.py via Docker API
# No manual default route setup needed here

# Start ulogd2 (foreground → backgrounded)
echo "Starting ulogd2..."
/usr/sbin/ulogd -c /etc/ulogd.conf &

# Wait for startup
sleep 1

# Cleanup Squid PID file (if left over)
rm -f /run/squid.pid

# Initialize Squid cache directories (only if proxy is enabled)
if [ -f "/etc/squid/squid.conf" ]; then
    echo "Initializing Squid cache directories..."
    squid -z 2>/dev/null || true
fi

# Start Web UI and main application
echo "Starting applications..."
python -m src.web_ui.app &
python -m src.main
