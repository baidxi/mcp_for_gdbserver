"""Main CLI entry point for MCP GDB Server.

Loads configuration, initializes logging, and starts the MCP SSE server.
Optionally pre-starts a GDB server process if configured via CLI or config file.

Usage:
    # Via entry point (installed):
    mcp-gdbserver [options]

    # Via module:
    python -m mcp_gdbserver [options]
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

import anyio

from .config import load_config
from .server import run_server

logger = logging.getLogger("mcp_gdbserver")


def setup_logging(level: str) -> None:
    """Configure root logger for the application.

    Args:
        level: Logging level string (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    # Quiet down noisy third-party loggers
    for name in ("httpx", "httpcore", "mcp", "starlette", "uvicorn", "uvicorn.error"):
        logging.getLogger(name).setLevel(logging.WARNING)


def main(argv: list[str] | None = None) -> int:
    """Synchronous entry point.

    Parses CLI arguments, loads merged configuration, sets up logging,
    and runs the async MCP server.

    Args:
        argv: Optional argument list (defaults to sys.argv[1:])

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    try:
        config = load_config(argv)
    except SystemExit as exc:
        # argparse --help or parse error
        return exc.code if isinstance(exc.code, int) else 1
    except Exception as exc:
        print(f"Error loading configuration: {exc}", file=sys.stderr)
        return 1

    # Setup logging
    setup_logging(config.log_level)
    logger.info("MCP GDB Server starting (log_level=%s)", config.log_level)
    logger.debug("Configuration: %s", config.model_dump_json(indent=2))

    try:
        anyio.run(_run, config)
    except KeyboardInterrupt:
        logger.info("Interrupted by user, shutting down")
    except Exception as exc:
        logger.exception("Fatal error: %s", exc)
        return 1

    return 0


async def _run(config) -> None:
    """Async entry point — starts the MCP SSE server.

    Args:
        config: Validated MCPConfig instance
    """
    logger.info(
        "Starting MCP SSE server on %s:%d (GDB: %s)",
        config.host,
        config.port,
        config.gdb_path,
    )

    if config.gdbserver.mode == "custom" and config.gdbserver.command:
        logger.info("Custom GDB server command: %s", config.gdbserver.command)
    else:
        logger.info(
            "Standard gdbserver mode (port=%d, multi=%s, once=%s)",
            config.gdbserver.port,
            config.gdbserver.multi,
            config.gdbserver.once,
        )

    await run_server(config)


if __name__ == "__main__":
    sys.exit(main())
