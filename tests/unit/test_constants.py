"""Unit tests for the constants module.

These cover the environment variables that were silently ignored before:
the values are read at import time, so each test reloads the module with
the variable set and then checks the code that consumes it.
"""

import importlib
import sys
from pathlib import Path
from textwrap import dedent
from types import ModuleType
from unittest.mock import Mock, patch

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


def describe_web_ui_bind():
    """SEKIMORE_WEB_HOST / SEKIMORE_WEB_PORT reach the uvicorn bind."""

    def it_defaults_to_all_interfaces_on_8080(monkeypatch):
        """Without the env vars the defaults are unchanged."""
        monkeypatch.delenv("SEKIMORE_WEB_HOST", raising=False)
        monkeypatch.delenv("SEKIMORE_WEB_PORT", raising=False)
        reloaded = importlib.reload(constants)
        assert reloaded.WEB_UI_HOST == "0.0.0.0"
        assert reloaded.WEB_UI_PORT == 8080

    def it_reads_the_host_and_port_from_the_environment(monkeypatch):
        """Setting the env vars changes the constants."""
        monkeypatch.setenv("SEKIMORE_WEB_HOST", "127.0.0.1")
        monkeypatch.setenv("SEKIMORE_WEB_PORT", "9999")
        reloaded = importlib.reload(constants)
        assert reloaded.WEB_UI_HOST == "127.0.0.1"
        assert reloaded.WEB_UI_PORT == 9999

    def it_binds_uvicorn_to_the_configured_host_and_port(monkeypatch):
        """The __main__ block of web_ui.app passes the constants to uvicorn.

        Executes just that block (entrypoint.sh runs the module with
        `python -m src.web_ui.app`) and captures the uvicorn.run arguments.
        Importing src.web_ui.app for real would start the app, so the block
        is read from the source and run against a stub uvicorn.
        """
        monkeypatch.setenv("SEKIMORE_WEB_HOST", "127.0.0.1")
        monkeypatch.setenv("SEKIMORE_WEB_PORT", "9999")
        reloaded = importlib.reload(constants)
        source = (Path(__file__).parents[2] / "src" / "web_ui" / "app.py").read_text()
        block = source.split('if __name__ == "__main__":')[1]
        body = dedent(block).strip()
        assert "uvicorn.run(" in body

        uvicorn = ModuleType("uvicorn")
        uvicorn.run = Mock()  # type: ignore[attr-defined]
        with patch.dict(sys.modules, {"uvicorn": uvicorn}):
            exec(body, {"app": object(), "constants": reloaded})  # noqa: S102

        uvicorn.run.assert_called_once()
        assert uvicorn.run.call_args.kwargs["host"] == "127.0.0.1"
        assert uvicorn.run.call_args.kwargs["port"] == 9999


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
