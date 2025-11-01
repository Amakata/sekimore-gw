"""Unit tests for main module."""

from pathlib import Path
from unittest.mock import Mock, patch


def describe_main():
    """Main function unit tests."""

    @patch("src.main.SecurityGatewayOrchestrator")
    @patch("src.main.asyncio.run")
    def it_initializes_and_starts_orchestrator(mock_asyncio_run, mock_orchestrator_class):
        """Test main function initializes and starts orchestrator."""
        from src.main import main

        mock_orchestrator = Mock()
        mock_orchestrator_class.return_value = mock_orchestrator
        mock_asyncio_run.return_value = None

        main()

        # Verify orchestrator was initialized with config path
        mock_orchestrator_class.assert_called_once()
        call_args = mock_orchestrator_class.call_args
        assert "config_path" in call_args.kwargs
        assert isinstance(call_args.kwargs["config_path"], Path)

        # Verify orchestrator.start() was called via asyncio.run
        mock_asyncio_run.assert_called_once()

    @patch("src.main.SecurityGatewayOrchestrator")
    @patch("src.main.asyncio.run")
    @patch("sys.exit")
    def it_handles_keyboard_interrupt(mock_exit, mock_asyncio_run, mock_orchestrator_class):
        """Test main function handles KeyboardInterrupt."""
        from src.main import main

        mock_orchestrator = Mock()
        mock_orchestrator_class.return_value = mock_orchestrator
        mock_asyncio_run.side_effect = KeyboardInterrupt()

        main()

        # Should exit with code 0
        mock_exit.assert_called_once_with(0)

    @patch("src.main.SecurityGatewayOrchestrator")
    @patch("src.main.asyncio.run")
    @patch("sys.exit")
    def it_handles_exceptions_and_exits(mock_exit, mock_asyncio_run, mock_orchestrator_class):
        """Test main function handles exceptions and exits with error code."""
        from src.main import main

        mock_orchestrator = Mock()
        mock_orchestrator_class.return_value = mock_orchestrator
        mock_asyncio_run.side_effect = RuntimeError("Test error")

        main()

        # Should exit with code 1
        mock_exit.assert_called_once_with(1)

    @patch("src.main.SecurityGatewayOrchestrator")
    def it_uses_default_config_path(mock_orchestrator_class):
        """Test main function uses default config path."""
        from src.main import main

        mock_orchestrator = Mock()
        mock_orchestrator_class.return_value = mock_orchestrator

        # Mock asyncio.run to prevent actual execution
        with patch("src.main.asyncio.run"):
            main()

        # Verify default path is used
        call_args = mock_orchestrator_class.call_args
        config_path = call_args.kwargs["config_path"]
        assert str(config_path) == "/etc/sekimore/config.yml"
