"""AI Security Gateway - main entry point."""

import asyncio
import sys
import traceback
from pathlib import Path

from .orchestrator import SecurityGatewayOrchestrator


def main() -> None:
    """Main entry point."""
    # Configuration file path
    config_path = Path("/etc/sekimore/config.yml")

    # Initialize the orchestrator
    orchestrator = SecurityGatewayOrchestrator(config_path=config_path)

    # Start
    try:
        asyncio.run(orchestrator.start())
    except KeyboardInterrupt:
        print("\n\nShutdown requested... exiting")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
