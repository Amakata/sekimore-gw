"""Unit tests for the constants module.

These cover the environment variables that were silently ignored before:
the values are read at import time, so each test reloads the module with
the variable set and then checks the code that consumes it.
"""

import importlib

import pytest

from src import constants


def _restore() -> None:
    """Reload constants so the shared module object matches the real environment.

    Called from a fixture rather than inline: monkeypatch only unsets the
    variables after the test function returns, so a reload inside the test
    would re-read the patched values and leak them into the next test.
    """
    importlib.reload(constants)


@pytest.fixture(autouse=True)
def _reset_constants():
    """Restore the module before and after every test in this file."""
    _restore()
    yield
    _restore()


def describe_ulog_file_path():
    """SEKIMORE_ULOG_PATH reaches the firewall monitor."""

    def it_defaults_to_the_file_ulogd_actually_writes(monkeypatch):
        """config/ulogd.conf writes firewall.log, so that is the default."""
        monkeypatch.delenv("SEKIMORE_ULOG_PATH", raising=False)
        reloaded = importlib.reload(constants)
        assert reloaded.ULOG_FILE_PATH == "/var/log/ulog/firewall.log"

    def it_reads_the_log_path_from_the_environment(monkeypatch):
        """Setting the env var changes the constant."""
        monkeypatch.setenv("SEKIMORE_ULOG_PATH", "/tmp/custom-firewall.log")
        reloaded = importlib.reload(constants)
        assert reloaded.ULOG_FILE_PATH == "/tmp/custom-firewall.log"
