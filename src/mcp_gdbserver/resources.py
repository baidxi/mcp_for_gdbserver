"""MCP Resource definitions and implementations.

Registers GDB-related resources with the FastMCP server.
Resources provide read-only views of the current debug session state.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from .session import GDBSession, GDBState
from .tools import get_context

logger = logging.getLogger(__name__)


def _json_resource(data: dict[str, Any]) -> str:
    """Format a resource response as JSON string."""
    return json.dumps(data, indent=2, ensure_ascii=False)


def _ensure_session() -> GDBSession:
    """Get the GDB session from context, raising if not available."""
    ctx = get_context()
    if not ctx.session.is_alive:
        raise ValueError("GDB session is not started")
    return ctx.session


def register_resources(mcp: FastMCP) -> None:
    """Register all MCP resources with the FastMCP server."""

    @mcp.resource("gdb://status")
    async def gdb_status() -> str:
        """当前调试器状态。"""
        ctx = get_context()
        status = ctx.session.get_status()
        if ctx.server_mgr:
            status["gdb_server"] = ctx.server_mgr.get_status()
        return _json_resource(status)

    @mcp.resource("gdb://registers")
    async def gdb_registers() -> str:
        """当前寄存器值。"""
        session = _ensure_session()
        try:
            text = await session.send_raw_command("info registers")
            # Parse register output
            registers = []
            for line in text.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    reg_entry = {
                        "name": parts[0],
                        "value": parts[1],
                        "hex": parts[1] if parts[1].startswith("0x") else None,
                    }
                    if len(parts) >= 3 and parts[2].startswith("0x"):
                        reg_entry["hex"] = parts[2]
                    registers.append(reg_entry)
            return _json_resource({"registers": registers})
        except Exception as e:
            return _json_resource({"error": str(e), "registers": []})

    @mcp.resource("gdb://backtrace")
    async def gdb_backtrace() -> str:
        """当前调用栈。"""
        session = _ensure_session()
        try:
            output = await session.send_mi_command("-stack-list-frames")
            frames = []
            if output.result and not output.is_error:
                stack = output.result.results.get("stack", [])
                for entry in stack:
                    frame = entry.get("frame", entry) if isinstance(entry, dict) else entry
                    frames.append({
                        "frame_num": frame.get("level", "?"),
                        "func": frame.get("func", "??"),
                        "file": frame.get("file", frame.get("fullname", "??")),
                        "line": frame.get("line", "?"),
                        "addr": frame.get("addr", "??"),
                    })
            return _json_resource({"frames": frames})
        except Exception as e:
            return _json_resource({"error": str(e), "frames": []})

    @mcp.resource("gdb://breakpoints")
    async def gdb_breakpoints() -> str:
        """当前断点列表。"""
        session = _ensure_session()
        try:
            output = await session.send_mi_command("-break-list")
            breakpoints = []
            if output.result and not output.is_error:
                table = output.result.results.get("BreakpointTable", {})
                body = table.get("body", [])
                for entry in body:
                    bkpt = entry.get("bkpt", entry) if isinstance(entry, dict) else entry
                    breakpoints.append(bkpt)
            return _json_resource({"breakpoints": breakpoints})
        except Exception as e:
            return _json_resource({"error": str(e), "breakpoints": []})

    @mcp.resource("gdb://threads")
    async def gdb_threads() -> str:
        """线程列表。"""
        session = _ensure_session()
        try:
            output = await session.send_mi_command("-thread-info")
            threads = []
            current = None
            if output.result and not output.is_error:
                threads = output.result.results.get("threads", [])
                current = output.result.results.get("current-thread-id")
            return _json_resource({
                "threads": threads,
                "current_thread": current,
            })
        except Exception as e:
            return _json_resource({"error": str(e), "threads": []})

    @mcp.resource("gdb://memory/{address}/{size}")
    async def gdb_memory(address: str, size: str) -> str:
        """读取指定地址和大小的内存数据。

        Args:
            address: 起始地址 (如 "0x20000000")
            size: 读取的字节数
        """
        session = _ensure_session()
        try:
            num_bytes = int(size)
            output = await session.send_mi_command(
                f"-data-read-memory-bytes {address} {num_bytes}"
            )
            if output.result and not output.is_error:
                memory = output.result.results.get("memory", [])
                return _json_resource({"address": address, "size": num_bytes, "memory": memory})
            return _json_resource({"error": output.error_message, "address": address})
        except Exception as e:
            return _json_resource({"error": str(e), "address": address})

    @mcp.resource("gdb://locals")
    async def gdb_locals() -> str:
        """局部变量。"""
        session = _ensure_session()
        try:
            output = await session.send_mi_command("-stack-list-variables --all-values")
            variables = []
            if output.result and not output.is_error:
                variables = output.result.results.get("variables", [])
            return _json_resource({"locals": variables})
        except Exception as e:
            return _json_resource({"error": str(e), "locals": []})

    @mcp.resource("gdb://args")
    async def gdb_args() -> str:
        """函数参数。"""
        session = _ensure_session()
        try:
            output = await session.send_mi_command("-stack-list-arguments --all-values 0 0")
            args = []
            if output.result and not output.is_error:
                stack_args = output.result.results.get("stack-args", [])
                for entry in stack_args:
                    frame = entry.get("frame", {})
                    args.extend(frame.get("args", []))
            return _json_resource({"args": args})
        except Exception as e:
            return _json_resource({"error": str(e), "args": []})

    @mcp.resource("gdb://frame")
    async def gdb_frame() -> str:
        """当前帧信息。"""
        session = _ensure_session()
        try:
            output = await session.send_mi_command("-stack-info-frame")
            if output.result and not output.is_error:
                frame = output.result.results.get("frame", {})
                return _json_resource(frame)
            return _json_resource({"error": output.error_message})
        except Exception as e:
            return _json_resource({"error": str(e)})

    @mcp.resource("gdb://sections")
    async def gdb_sections() -> str:
        """目标节区信息。"""
        session = _ensure_session()
        try:
            text = await session.send_raw_command("info files")
            sections = []
            for line in text.strip().splitlines():
                line = line.strip()
                if line and not line.startswith(" ") and "0x" in line:
                    sections.append(line)
            return _json_resource({"sections": sections, "raw": text.strip()})
        except Exception as e:
            return _json_resource({"error": str(e), "sections": []})
