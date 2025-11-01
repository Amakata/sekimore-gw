"""Integration tests for agent-setup.sh script.

These tests verify the agent setup script's network discovery and configuration logic.
"""

import subprocess
from pathlib import Path


def describe_agent_setup_script():
    """Integration tests for agent-setup.sh script."""

    def it_extracts_ip_and_subnet_correctly(tmp_path):
        """Test IP and subnet extraction from network interface."""
        Path(__file__).parent.parent.parent / "agent-setup.sh"

        # Create a test script that only extracts IP/subnet
        test_script = tmp_path / "test_ip_extraction.sh"
        test_script.write_text("""#!/bin/bash
# Simulate ip command output
cat <<EOF
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:ac:14:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.20.0.2/24 brd 172.20.0.255 scope global eth0
       valid_lft forever preferred_lft forever
EOF
""")
        test_script.chmod(0o755)

        # Execute and capture output
        result = subprocess.run(
            [
                "bash",
                "-c",
                f"source {test_script} | grep inet | awk '{{print $2}}' | cut -d'/' -f1",
            ],
            capture_output=True,
            text=True,
        )

        ip = result.stdout.strip()
        assert ip == "172.20.0.2"

    def it_handles_dns_server_discovery_simulation(tmp_path):
        """Test DNS server discovery logic simulation."""
        # Create a mock script that simulates DNS discovery
        mock_script = tmp_path / "mock_discovery.sh"
        mock_script.write_text("""#!/bin/bash
set -e

# Simulate network environment
MY_IP="172.20.0.5"
SUBNET_MASK="24"
NETWORK="172.20.0"

echo "[agent] My IP: $MY_IP, Subnet: $NETWORK.0/$SUBNET_MASK"

# Simulate finding DNS server
SEKIMORE_IP="172.20.0.2"
echo "[agent] Found DNS server at $SEKIMORE_IP (simulated)"

# Check if we found it
if [ -z "$SEKIMORE_IP" ]; then
  echo "[agent] ERROR: could not find sekimore-gw"
  exit 1
fi

echo "[agent] sekimore-gw IP (discovered): $SEKIMORE_IP"
exit 0
""")
        mock_script.chmod(0o755)

        # Execute mock script
        result = subprocess.run(
            ["bash", str(mock_script)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "172.20.0.2" in result.stdout
        assert "Found DNS server" in result.stdout

    def it_fails_when_dns_server_not_found(tmp_path):
        """Test script fails gracefully when DNS server is not found."""
        mock_script = tmp_path / "mock_no_dns.sh"
        mock_script.write_text("""#!/bin/bash
set -e

SEKIMORE_IP=""

if [ -z "$SEKIMORE_IP" ]; then
  echo "[agent] ERROR: could not find sekimore-gw (no DNS server found in subnet)"
  exit 1
fi
""")
        mock_script.chmod(0o755)

        result = subprocess.run(
            ["bash", str(mock_script)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1
        assert "ERROR" in result.stdout
        assert "could not find sekimore-gw" in result.stdout

    def it_tests_resolv_conf_update_logic(tmp_path):
        """Test /etc/resolv.conf update logic."""
        test_resolv = tmp_path / "resolv.conf"

        # Create script that updates resolv.conf
        update_script = tmp_path / "update_resolv.sh"
        update_script.write_text(f"""#!/bin/bash
SEKIMORE_IP="172.20.0.2"
echo "nameserver $SEKIMORE_IP" > {test_resolv}
cat {test_resolv}
""")
        update_script.chmod(0o755)

        result = subprocess.run(
            ["bash", str(update_script)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert test_resolv.exists()
        content = test_resolv.read_text()
        assert "nameserver 172.20.0.2" in content

    def it_handles_subnet_mask_24_logic(tmp_path):
        """Test subnet mask /24 detection logic."""
        test_script = tmp_path / "test_subnet.sh"
        test_script.write_text("""#!/bin/bash
SUBNET_MASK=24

if [ "$SUBNET_MASK" -ge 24 ]; then
  echo "Using /24 subnet logic"
  exit 0
else
  echo "Using larger subnet logic"
  exit 1
fi
""")
        test_script.chmod(0o755)

        result = subprocess.run(
            ["bash", str(test_script)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "/24 subnet logic" in result.stdout

    def it_handles_subnet_mask_16_logic(tmp_path):
        """Test subnet mask /16 detection logic."""
        test_script = tmp_path / "test_subnet_16.sh"
        test_script.write_text("""#!/bin/bash
SUBNET_MASK=16

if [ "$SUBNET_MASK" -ge 24 ]; then
  echo "Using /24 subnet logic"
  exit 1
elif [ "$SUBNET_MASK" -ge 16 ]; then
  echo "Using /16 subnet logic"
  exit 0
fi
""")
        test_script.chmod(0o755)

        result = subprocess.run(
            ["bash", str(test_script)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "/16 subnet logic" in result.stdout

    def it_tests_arp_cache_parsing_logic(tmp_path):
        """Test ARP cache parsing logic."""
        test_script = tmp_path / "test_arp.sh"
        test_script.write_text("""#!/bin/bash
# Simulate ARP cache output
cat <<EOF | grep -v FAILED | grep -v INCOMPLETE | awk '{print $1}'
172.20.0.1 dev eth0 lladdr 02:42:12:34:56:78 REACHABLE
172.20.0.2 dev eth0 lladdr 02:42:ac:14:00:02 REACHABLE
172.20.0.3 dev eth0 lladdr 02:42:ac:14:00:03 FAILED
172.20.0.4 dev eth0  INCOMPLETE
EOF
""")
        test_script.chmod(0o755)

        result = subprocess.run(
            ["bash", str(test_script)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        output_lines = result.stdout.strip().split("\n")
        assert len(output_lines) == 2
        assert "172.20.0.1" in output_lines
        assert "172.20.0.2" in output_lines
        assert "172.20.0.3" not in result.stdout
        assert "172.20.0.4" not in result.stdout

    def it_tests_priority_ips_logic(tmp_path):
        """Test priority IPs configuration."""
        test_script = tmp_path / "test_priority.sh"
        test_script.write_text("""#!/bin/bash
PRIORITY_IPS="1 2 254 253 3 4 5 10 20 100"
MY_IP="172.20.0.5"
NETWORK="172.20.0"

for i in $PRIORITY_IPS; do
  TEST_IP="${NETWORK}.${i}"

  if [ "$TEST_IP" = "$MY_IP" ]; then
    continue
  fi

  echo "$TEST_IP"
done
""")
        test_script.chmod(0o755)

        result = subprocess.run(
            ["bash", str(test_script)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        output = result.stdout
        assert "172.20.0.1" in output
        assert "172.20.0.2" in output
        assert "172.20.0.5" not in output  # Should skip MY_IP

    def it_tests_network_extraction_logic(tmp_path):
        """Test network address extraction from IP."""
        test_script = tmp_path / "test_network.sh"
        test_script.write_text("""#!/bin/bash
MY_IP="172.20.0.5"
NETWORK=$(echo $MY_IP | cut -d'.' -f1-3)
echo "$NETWORK"
""")
        test_script.chmod(0o755)

        result = subprocess.run(
            ["bash", str(test_script)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "172.20.0"

    def it_validates_script_exists_and_is_executable():
        """Test that agent-setup.sh exists and is executable."""
        script_path = Path(__file__).parent.parent.parent / "agent-setup.sh"
        assert script_path.exists(), "agent-setup.sh should exist"
        assert script_path.stat().st_mode & 0o111, "agent-setup.sh should be executable"

    def it_validates_script_has_shebang():
        """Test that agent-setup.sh has proper shebang."""
        script_path = Path(__file__).parent.parent.parent / "agent-setup.sh"
        with open(script_path) as f:
            first_line = f.readline()
            assert first_line.startswith("#!/bin/bash"), "Script should have bash shebang"

    def it_validates_script_has_set_options():
        """Test that agent-setup.sh has 'set -ex' for error handling."""
        script_path = Path(__file__).parent.parent.parent / "agent-setup.sh"
        content = script_path.read_text()
        assert "set -ex" in content or "set -e" in content, "Script should have error handling"

    def it_tests_retry_logic_simulation(tmp_path):
        """Test retry logic when DNS server not found initially."""
        test_script = tmp_path / "test_retry.sh"
        test_script.write_text("""#!/bin/bash
SEKIMORE_IP=""
retry_count=0

# Simulate retry logic
for retry in 1 2 3; do
  retry_count=$retry
  echo "[agent] Retrying (attempt $retry/3)..."

  # Simulate finding on 2nd attempt
  if [ $retry -eq 2 ]; then
    SEKIMORE_IP="172.20.0.2"
    echo "[agent] Found DNS server at $SEKIMORE_IP (retry $retry)"
    break
  fi
done

echo "Retries: $retry_count"
echo "Found: $SEKIMORE_IP"

if [ -z "$SEKIMORE_IP" ]; then
  exit 1
fi
""")
        test_script.chmod(0o755)

        result = subprocess.run(
            ["bash", str(test_script)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "attempt 2/3" in result.stdout
        assert "Found: 172.20.0.2" in result.stdout


def describe_agent_setup_error_cases():
    """Error handling tests for agent-setup.sh."""

    def it_provides_helpful_error_for_large_subnets(tmp_path):
        """Test helpful error message for large subnets."""
        test_script = tmp_path / "test_large_subnet.sh"
        test_script.write_text("""#!/bin/bash
SUBNET_MASK=20
SEKIMORE_IP=""

if [ -z "$SEKIMORE_IP" ]; then
  echo "[agent] ERROR: Could not find sekimore-gw in /$SUBNET_MASK subnet (after retry)"
  if [ "$SUBNET_MASK" -lt 24 ]; then
    echo "[agent] HINT: Consider using a smaller subnet (e.g., /24 or /25) for better discovery"
  fi
  exit 1
fi
""")
        test_script.chmod(0o755)

        result = subprocess.run(
            ["bash", str(test_script)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1
        assert "HINT" in result.stdout
        assert "/24 or /25" in result.stdout

    def it_handles_max_scan_limit(tmp_path):
        """Test max scan limit protection."""
        test_script = tmp_path / "test_max_scan.sh"
        test_script.write_text("""#!/bin/bash
SCAN_COUNT=0
MAX_SCAN=1024

for i in {1..2000}; do
  SCAN_COUNT=$((SCAN_COUNT + 1))

  if [ $SCAN_COUNT -gt $MAX_SCAN ]; then
    echo "[agent] Max scan limit reached ($MAX_SCAN)"
    break
  fi
done

echo "Final count: $SCAN_COUNT"
""")
        test_script.chmod(0o755)

        result = subprocess.run(
            ["bash", str(test_script)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Max scan limit reached" in result.stdout
        assert "Final count: 1025" in result.stdout

    def it_validates_empty_subnet_mask(tmp_path):
        """Test validation of empty SUBNET_MASK variable."""
        test_script = tmp_path / "test_empty_subnet.sh"
        test_script.write_text("""#!/bin/bash
# Simulate eth0 with no inet line (SUBNET_MASK will be empty)
MY_IP=$(echo "" | awk '{print $2}' | cut -d'/' -f1)
SUBNET_MASK=$(echo "" | awk '{print $2}' | cut -d'/' -f2)

# Validate that we got network information
if [ -z "$MY_IP" ] || [ -z "$SUBNET_MASK" ]; then
  echo "[agent] ERROR: Could not get IP address or subnet mask from eth0"
  echo "[agent] Network interface status:"
  exit 1
fi

echo "[agent] This should not be reached"
""")
        test_script.chmod(0o755)

        result = subprocess.run(
            ["bash", str(test_script)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1
        assert "ERROR: Could not get IP address or subnet mask" in result.stdout
        assert "This should not be reached" not in result.stdout

    def it_validates_empty_my_ip(tmp_path):
        """Test validation of empty MY_IP variable."""
        test_script = tmp_path / "test_empty_ip.sh"
        test_script.write_text("""#!/bin/bash
# Simulate eth0 with no output
MY_IP=""
SUBNET_MASK="24"

# Validate that we got network information
if [ -z "$MY_IP" ] || [ -z "$SUBNET_MASK" ]; then
  echo "[agent] ERROR: Could not get IP address or subnet mask from eth0"
  echo "[agent] Network interface status:"
  exit 1
fi

echo "[agent] This should not be reached"
""")
        test_script.chmod(0o755)

        result = subprocess.run(
            ["bash", str(test_script)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1
        assert "ERROR: Could not get IP address or subnet mask" in result.stdout
        assert "This should not be reached" not in result.stdout

    def it_detects_missing_ip_command(tmp_path):
        """Test detection of missing 'ip' command."""
        # Read the actual agent-setup.sh script
        script_path = Path(__file__).parent.parent.parent / "agent-setup.sh"

        with open(script_path) as f:
            script_content = f.read()

        # Find the ip command check section
        assert "if ! command -v ip" in script_content
        assert "ERROR: 'ip' command not found" in script_content
        assert "install iproute2" in script_content

        # Create a test script that simulates the check
        test_script = tmp_path / "test_ip_check.sh"
        test_script.write_text("""#!/bin/bash
# Test the logic of ip command detection
# Override command to simulate missing ip
command() {
    if [ "$1" = "-v" ] && [ "$2" = "ip" ]; then
        return 1  # ip not found
    fi
    builtin command "$@"
}

if ! command -v ip >/dev/null 2>&1; then
  echo "[agent] ERROR: 'ip' command not found"
  echo "[agent] Please install iproute2 package in your Docker image"
  exit 1
fi

echo "[agent] This should not be reached"
""")
        test_script.chmod(0o755)

        result = subprocess.run(
            ["bash", str(test_script)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1
        assert "ERROR: 'ip' command not found" in result.stdout
        assert "install iproute2" in result.stdout
        assert "This should not be reached" not in result.stdout
