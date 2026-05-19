"""MCP Server setup and startup.

Creates the FastMCP application instance, configures SSE transport,
registers all Tools and Resources, and provides the server run function.
"""

from __future__ import annotations

import logging
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .config import MCPConfig
from .tools import AppContext, set_context, register_tools
from .resources import register_resources

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Monkey-patch: work around Zoo Code MCP client initialization timing issue
# ---------------------------------------------------------------------------
# Some MCP clients (e.g. Zoo Code extension) send tool call requests before
# the MCP initialization handshake completes. The standard MCP SDK rejects
# these with RuntimeError → -32602. Instead, we queue and retry them.
# ---------------------------------------------------------------------------

_original_received_request = None


def _patch_mcp_session() -> None:
    """Apply monkey-patch to MCP ServerSession for Zoo Code MCP client compatibility.

    Zoo Code's MCP client sends tools/list and tools/call requests before
    the MCP initialization handshake completes. The standard MCP SDK raises
    a RuntimeError for uninitialized requests. This patch auto-initializes
    the session when a non-initialize request arrives before initialization.
    """
    global _original_received_request

    try:
        from mcp.server.session import ServerSession, InitializationState
    except ImportError:
        logger.warning("Could not import ServerSession for monkey-patch")
        return

    if _original_received_request is not None:
        return  # Already patched

    _original_received_request = ServerSession._received_request

    async def patched_received_request(self, responder):
        """Patched version: auto-initialize session if needed."""
        import mcp.types as types

        root = getattr(responder.request, 'root', None)
        if root is not None:
            # Auto-initialize for any non-initialize, non-ping request
            if not isinstance(root, (types.InitializeRequest, types.PingRequest)):
                if self._initialization_state == InitializationState.NotInitialized:
                    logger.info(
                        "Auto-initializing session for %s request (Zoo Code compatibility)",
                        type(root).__name__,
                    )
                    self._initialization_state = InitializationState.Initialized

        # Call original handler
        await _original_received_request(self, responder)

    ServerSession._received_request = patched_received_request
    logger.info("Applied MCP session monkey-patch for Zoo Code compatibility")


def create_server(config: MCPConfig) -> FastMCP:
    """Create and configure the FastMCP server instance.

    Args:
        config: Application configuration

    Returns:
        Configured FastMCP instance (not yet running)
    """
    # Apply Zoo Code MCP client compatibility patch
    _patch_mcp_session()

    # Create the application context with config values
    ctx = AppContext()
    ctx.gdbserver_config = config.gdbserver
    ctx.gdb_path = config.gdb_path
    ctx.gdb_init_commands = list(config.gdb_init_commands)
    ctx.default_target = config.default_target
    ctx.timeout_seconds = config.timeout_seconds
    set_context(ctx)

    # Create FastMCP server
    mcp = FastMCP(
        "MCP GDB Server",
        instructions=(
            "MCP Server for GDB debugging via gdbserver. "
            "Supports both standard GNU gdbserver and custom GDB servers "
            "(ST-LINK, OpenOCD, JLink, etc.). "
            "Use start_gdb_server to launch a GDB server, start_gdb to start GDB, "
            "load_file to load an ELF, connect_target to connect, then use debugging tools."
        ),
    )

    # Register all tools and resources
    register_tools(mcp)
    register_resources(mcp)

    logger.info("MCP server configured (host=%s, port=%d)", config.host, config.port)
    return mcp


async def run_server(config: MCPConfig) -> None:
    """Run the MCP server with SSE transport.

    This starts the FastMCP server using SSE transport on the configured
    host and port.

    Args:
        config: Application configuration
    """
    mcp = create_server(config)

    logger.info("Starting MCP SSE server on %s:%d", config.host, config.port)

    # Use the SSE transport via FastMCP's built-in run method
    mcp.settings.host = config.host
    mcp.settings.port = config.port

    await mcp.run_sse_async()
