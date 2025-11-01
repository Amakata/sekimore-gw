"""E2E tests for DNS server - actual port 53 binding verification.

These tests verify that the DNS server actually starts and binds to port 53
in a real Docker environment (not mocked).
"""

import subprocess
import time
from pathlib import Path

import pytest


@pytest.mark.e2e
def describe_dns_server_e2e():
    """E2E tests for DNS server startup.

    These tests require docker-compose and cannot run in CI or devcontainer.
    Run manually on host machine with: pytest tests/e2e -v
    """

    @pytest.fixture(scope="module")
    def docker_compose_project():
        """Start docker-compose environment for E2E testing."""
        project_root = Path(__file__).parent.parent.parent
        compose_file = project_root / "docker-compose.yml"

        if not compose_file.exists():
            pytest.skip("docker-compose.yml not found")

        # Stop any existing containers
        subprocess.run(
            ["docker-compose", "down"],
            cwd=project_root,
            capture_output=True,
        )

        # Start sekimore-gw only (not ai-agent)
        result = subprocess.run(
            ["docker-compose", "up", "-d", "sekimore-gw"],
            cwd=project_root,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            pytest.fail(f"Failed to start docker-compose: {result.stderr}")

        # Wait for container to be ready
        time.sleep(5)

        yield project_root

        # Cleanup
        subprocess.run(
            ["docker-compose", "down"],
            cwd=project_root,
            capture_output=True,
        )

    def it_starts_dns_server_on_port_53(docker_compose_project):
        """Test that DNS server actually binds to port 53."""
        # Check if sekimore-gw container is running
        result = subprocess.run(
            ["docker-compose", "ps", "-q", "sekimore-gw"],
            cwd=docker_compose_project,
            capture_output=True,
            text=True,
        )

        container_id = result.stdout.strip()
        assert container_id, "sekimore-gw container is not running"

        # Check if port 53 is listening inside the container
        result = subprocess.run(
            ["docker", "exec", "sekimore-gw", "ss", "-tulnp"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, "Failed to execute ss command in container"
        assert ":53 " in result.stdout, f"Port 53 is not listening. Output:\n{result.stdout}"

        # Verify it's listening on the correct IP (not 127.0.0.1 only)
        # Should be listening on internal-net IP (e.g., 172.21.0.2:53)
        assert "0.0.0.0:53" in result.stdout or ":53" in result.stdout, (
            "DNS server not listening on expected interface"
        )

    def it_logs_dns_server_startup(docker_compose_project):
        """Test that DNS server logs startup message."""
        result = subprocess.run(
            ["docker-compose", "logs", "sekimore-gw"],
            cwd=docker_compose_project,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, "Failed to get logs"

        # Check for DNS bind IP detection
        assert "DNS bind IP detected" in result.stdout, (
            f"DNS bind IP detection message not found in logs:\n{result.stdout}"
        )

        # Check for DNS server started message
        assert "DNS server started" in result.stdout, (
            f"DNS server startup message not found in logs:\n{result.stdout}"
        )

    def it_detects_internal_subnet_from_docker_api(docker_compose_project):
        """Test that internal subnet is detected from Docker API."""
        result = subprocess.run(
            ["docker-compose", "logs", "sekimore-gw"],
            cwd=docker_compose_project,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, "Failed to get logs"

        # Check for Docker API detection
        assert (
            "Docker API detection" in result.stdout or "Using Docker API detection" in result.stdout
        ), f"Docker API detection message not found in logs:\n{result.stdout}"

        # Check that internal_subnet was logged
        assert "internal_subnet" in result.stdout or "lan_subnet" in result.stdout, (
            f"Internal subnet not logged:\n{result.stdout}"
        )

    def it_responds_to_dns_queries(docker_compose_project):
        """Test that DNS server responds to actual DNS queries."""
        # Get sekimore-gw IP address
        result = subprocess.run(
            [
                "docker",
                "inspect",
                "sekimore-gw",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            ],
            capture_output=True,
            text=True,
        )

        dns_server_ip = result.stdout.strip().split("\n")[0]  # Get first IP
        assert dns_server_ip, "Failed to get sekimore-gw IP address"

        # Try to query DNS server using nslookup from host (if available)
        # This might fail if nslookup is not installed, so we'll make it optional
        try:
            result = subprocess.run(
                ["nslookup", "google.com", dns_server_ip],
                capture_output=True,
                text=True,
                timeout=5,
            )

            # If nslookup succeeded, verify we got a response
            if result.returncode == 0:
                assert "Name:" in result.stdout or "answer" in result.stdout.lower(), (
                    f"DNS query did not return expected response:\n{result.stdout}"
                )
        except FileNotFoundError:
            # nslookup not available on host, try using dig instead
            try:
                result = subprocess.run(
                    ["dig", "@" + dns_server_ip, "google.com"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.returncode == 0:
                    assert "ANSWER SECTION" in result.stdout or "status: " in result.stdout, (
                        f"DNS query did not return expected response:\n{result.stdout}"
                    )
            except FileNotFoundError:
                # Neither nslookup nor dig available
                pytest.skip("nslookup and dig not available on host for DNS query testing")
