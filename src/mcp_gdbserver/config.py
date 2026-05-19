"""Configuration management for MCP GDB Server.

Supports loading configuration from:
1. CLI arguments (highest priority)
2. JSON config file
3. Environment variables
4. Default values (lowest priority)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shlex
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


class GdbServerConfig(BaseModel):
    """Configuration for the GDB remote protocol server process."""

    mode: str = Field(
        default="standard",
        description="Server mode: 'standard' (GNU gdbserver) or 'custom' (any GDB remote protocol server)",
    )
    # Standard gdbserver fields
    port: int = Field(default=50000, description="gdbserver listen port")
    multi: bool = Field(default=False, description="Enable --multi extended-remote mode")
    once: bool = Field(default=False, description="Enable --once single-session mode")
    attach_pid: Optional[int] = Field(default=None, description="Attach to existing process PID")
    args: list[str] = Field(default_factory=list, description="Arguments passed to the inferior")
    # Custom server fields
    command: Optional[str] = Field(
        default=None,
        description="Full command line for custom GDB server (e.g. ST-LINK_gdbserver, OpenOCD, JLinkGDBServer)",
    )

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        if v not in ("standard", "custom"):
            raise ValueError(f"mode must be 'standard' or 'custom', got '{v}'")
        return v

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError(f"port must be 1-65535, got {v}")
        return v


class MCPConfig(BaseModel):
    """Top-level configuration for the MCP GDB Server application."""

    # GDB settings
    gdb_path: str = Field(
        default="arm-none-eabi-gdb",
        description="Path to GDB executable",
    )

    # MCP SSE server settings
    host: str = Field(default="0.0.0.0", description="MCP SSE server bind host")
    port: int = Field(default=8765, description="MCP SSE server bind port")

    # Default remote target
    default_target: Optional[str] = Field(
        default=None,
        description="Default remote target in host:port format",
    )

    # GDB initialization commands
    gdb_init_commands: list[str] = Field(
        default_factory=lambda: ["set pagination off", "set confirm off"],
        description="GDB commands to execute on startup",
    )

    # Timeout
    timeout_seconds: float = Field(
        default=30.0,
        description="Default timeout for GDB command execution (seconds)",
    )

    # Logging
    log_level: str = Field(default="INFO", description="Logging level")

    # GDB Server configuration
    gdbserver: GdbServerConfig = Field(default_factory=GdbServerConfig)

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            raise ValueError(f"log_level must be one of {valid}, got '{v}'")
        return upper

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError(f"port must be 1-65535, got {v}")
        return v


def load_config_from_file(path: str | Path) -> dict[str, Any]:
    """Load configuration from a JSON file.

    Returns a dict (not yet validated) that can be merged with other sources.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Config file not found: {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    logger.info("Loaded config from %s", file_path)
    return data


def build_argparser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcp-gdbserver",
        description="MCP Server for GDB debugging (supports both standard gdbserver and custom GDB servers)",
    )

    # General options
    parser.add_argument(
        "--gdb-path",
        default=None,
        help="Path to GDB executable (default: arm-none-eabi-gdb)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="MCP SSE server host (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=None,
        help="MCP SSE server port (default: 8765)",
    )
    parser.add_argument(
        "--target", "-t",
        default=None,
        help="Default remote target (format: host:port)",
    )

    # Standard GNU gdbserver options
    gdbserver_group = parser.add_argument_group("standard GNU gdbserver options")
    gdbserver_group.add_argument(
        "--gdbserver-port",
        type=int,
        default=None,
        help="gdbserver listen port (default: 50000)",
    )
    gdbserver_group.add_argument(
        "--gdbserver-multi",
        action="store_true",
        default=None,
        help="Enable --multi extended-remote mode",
    )
    gdbserver_group.add_argument(
        "--gdbserver-once",
        action="store_true",
        default=None,
        help="Enable --once single-session mode",
    )
    gdbserver_group.add_argument(
        "--gdbserver-attach",
        type=int,
        default=None,
        metavar="PID",
        help="Attach to existing process PID",
    )

    # Custom GDB server options
    custom_group = parser.add_argument_group("custom GDB server options")
    custom_group.add_argument(
        "--gdb-server-cmd", "-g",
        default=None,
        help="Full command line for custom GDB server "
             "(e.g. 'ST-LINK_gdbserver -p 50000 -cp /path --swd')",
    )

    # Config file
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="Path to JSON config file",
    )

    # Verbose
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable verbose (DEBUG) logging",
    )

    return parser


def _merge_configs(
    defaults: dict[str, Any],
    file_config: dict[str, Any],
    env_config: dict[str, Any],
    cli_config: dict[str, Any],
) -> dict[str, Any]:
    """Deep-merge configs with priority: CLI > env > file > defaults.

    Only merges dict values recursively; scalar values are overridden.
    """
    import copy

    result = copy.deepcopy(defaults)

    for source in (file_config, env_config, cli_config):
        _deep_merge(result, source)

    return result


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> None:
    """Recursively merge override into base (in-place)."""
    for key, value in override.items():
        if value is None:
            continue
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def _load_env_config() -> dict[str, Any]:
    """Load configuration from environment variables.

    Environment variables use the prefix MCP_GDB_ and double-underscore nesting:
      MCP_GDB_GDB_PATH=arm-none-eabi-gdb
      MCP_GDB_PORT=8765
      MCP_GDB_GDBSERVER__PORT=50000
      MCP_GDB_GDBSERVER__MODE=custom
      MCP_GDB_GDBSERVER__COMMAND="..."
    """
    config: dict[str, Any] = {}
    prefix = "MCP_GDB_"

    env_map = {
        "MCP_GDB_GDB_PATH": ("gdb_path", str),
        "MCP_GDB_HOST": ("host", str),
        "MCP_GDB_PORT": ("port", int),
        "MCP_GDB_TARGET": ("default_target", str),
        "MCP_GDB_TIMEOUT": ("timeout_seconds", float),
        "MCP_GDB_LOG_LEVEL": ("log_level", str),
    }

    for env_var, (key, type_fn) in env_map.items():
        val = os.environ.get(env_var)
        if val is not None:
            try:
                config[key] = type_fn(val)
            except (ValueError, TypeError):
                logger.warning("Invalid env var %s=%s, skipping", env_var, val)

    # Nested gdbserver config
    gdbserver_env_map = {
        "MCP_GDB_GDBSERVER_PORT": ("port", int),
        "MCP_GDB_GDBSERVER_MULTI": ("multi", lambda v: v.lower() in ("true", "1", "yes")),
        "MCP_GDB_GDBSERVER_ONCE": ("once", lambda v: v.lower() in ("true", "1", "yes")),
        "MCP_GDB_GDBSERVER_MODE": ("mode", str),
        "MCP_GDB_GDBSERVER_COMMAND": ("command", str),
    }

    gdbserver_config: dict[str, Any] = {}
    for env_var, (key, type_fn) in gdbserver_env_map.items():
        val = os.environ.get(env_var)
        if val is not None:
            try:
                gdbserver_config[key] = type_fn(val)
            except (ValueError, TypeError):
                logger.warning("Invalid env var %s=%s, skipping", env_var, val)

    if gdbserver_config:
        config["gdbserver"] = gdbserver_config

    return config


def _find_config_file() -> str | None:
    """Auto-discover a configuration file.

    Search order:
    1. Explicit --config path (handled separately in load_config)
    2. config.json in the project directory (where this script lives)
    3. config.example.stlink.json
    4. config.example.json

    Uses the script's directory (parent of src/mcp_gdbserver/) as base,
    falling back to CWD if that can't be determined.
    """
    # Determine project root: parent of src/mcp_gdbserver/config.py
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    # __file__ is in src/mcp_gdbserver/, so project root is grandparent
    _project_root = os.path.dirname(os.path.dirname(_script_dir))

    candidates = [
        os.path.join(_project_root, "config.json"),
        os.path.join(_project_root, "config.example.stlink.json"),
        os.path.join(_project_root, "config.example.json"),
    ]
    # Also check CWD as fallback
    candidates.extend(["config.json", "config.example.stlink.json", "config.example.json"])

    seen = set()
    for path in candidates:
        abs_path = os.path.abspath(path)
        if abs_path in seen:
            continue
        seen.add(abs_path)
        if os.path.isfile(abs_path):
            logger.info("Auto-discovered config file: %s", abs_path)
            return abs_path
    return None


def load_config(args: list[str] | None = None) -> MCPConfig:
    """Load and merge configuration from all sources.

    Priority: CLI > environment variables > config file > defaults.

    Config file discovery order:
    1. --config CLI argument (explicit)
    2. Auto-discovery: config.json -> config.example.stlink.json -> config.example.json
    """
    parser = build_argparser()
    parsed = parser.parse_args(args)

    # 1. Defaults from Pydantic model
    defaults = MCPConfig().model_dump()

    # 2. Config file -- explicit CLI path or auto-discovered
    file_config: dict[str, Any] = {}
    config_path = parsed.config or _find_config_file()
    if config_path:
        try:
            file_config = load_config_from_file(config_path)
        except FileNotFoundError:
            logger.warning("Config file not found: %s, using defaults", config_path)

    # 3. Environment variables
    env_config = _load_env_config()

    # 4. CLI arguments (only non-None values)
    cli_config: dict[str, Any] = {}
    if parsed.gdb_path is not None:
        cli_config["gdb_path"] = parsed.gdb_path
    if parsed.host is not None:
        cli_config["host"] = parsed.host
    if parsed.port is not None:
        cli_config["port"] = parsed.port
    if parsed.target is not None:
        cli_config["default_target"] = parsed.target
    if parsed.verbose:
        cli_config["log_level"] = "DEBUG"

    # CLI gdbserver options
    cli_gdbserver: dict[str, Any] = {}
    if parsed.gdbserver_port is not None:
        cli_gdbserver["port"] = parsed.gdbserver_port
    if parsed.gdbserver_multi is not None and parsed.gdbserver_multi:
        cli_gdbserver["multi"] = True
    if parsed.gdbserver_once is not None and parsed.gdbserver_once:
        cli_gdbserver["once"] = True
    if parsed.gdbserver_attach is not None:
        cli_gdbserver["attach_pid"] = parsed.gdbserver_attach

    # Custom GDB server command from CLI
    if parsed.gdb_server_cmd is not None:
        cli_gdbserver["mode"] = "custom"
        cli_gdbserver["command"] = parsed.gdb_server_cmd

    if cli_gdbserver:
        cli_config["gdbserver"] = cli_gdbserver

    # Merge all sources
    merged = _merge_configs(defaults, file_config, env_config, cli_config)

    return MCPConfig(**merged)


def resolve_gdbserver_command(config: GdbServerConfig, gdbserver_path: str = "gdbserver") -> list[str]:
    """Build the command line for launching the GDB server process.

    For 'custom' mode, the command string is split using shell-like syntax.
    For 'standard' mode, the gdbserver command is assembled from individual fields.

    Returns a list of arguments suitable for subprocess.Popen.
    """
    if config.mode == "custom" and config.command:
        return shlex.split(config.command)

    # Standard GNU gdbserver mode
    cmd: list[str] = [gdbserver_path]

    if config.multi:
        cmd.append("--multi")
    if config.once:
        cmd.append("--once")
    if config.attach_pid is not None:
        cmd.extend(["--attach", str(config.attach_pid)])

    # Target specification: :port
    cmd.append(f":{config.port}")

    return cmd
