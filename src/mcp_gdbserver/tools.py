"""MCP Tool definitions and implementations.

Registers all GDB debugging tools with the FastMCP server.
Each tool wraps one or more GDB MI commands and returns structured results.
"""

from __future__ import annotations

import logging
import os
import struct
from typing import Annotated, Any, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .session import GDBSession, GDBState
from .gdb_server_mgr import GdbServerManager, GdbServerError
from .config import GdbServerConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Application context — holds references to shared state
# ---------------------------------------------------------------------------

class AppContext:
    """Shared application context for tools.

    Supports multiple named GDB sessions via a dictionary keyed by session_id.
    The ``active_session_id`` determines which session is used by default.
    """

    DEFAULT_SESSION = "default"

    def __init__(self) -> None:
        self._sessions: dict[str, GDBSession] = {}
        self.active_session_id: str = self.DEFAULT_SESSION
        self.server_mgr: Optional[GdbServerManager] = None
        self.gdbserver_config: Optional[GdbServerConfig] = None
        # Configuration defaults loaded from config file / CLI
        self.gdb_path: str = "arm-none-eabi-gdb"
        self.gdb_init_commands: list[str] = ["set pagination off", "set confirm off"]
        self.default_target: Optional[str] = None
        self.timeout_seconds: float = 30.0

    @property
    def sessions(self) -> dict[str, GDBSession]:
        """Read-only view of all sessions."""
        return dict(self._sessions)

    def get_session(self, session_id: str | None = None) -> GDBSession:
        """Get a session by id, creating it if it does not exist."""
        sid = session_id or self.active_session_id
        if sid not in self._sessions:
            self._sessions[sid] = GDBSession()
        return self._sessions[sid]

    def ensure_session(self, session_id: str | None = None) -> GDBSession:
        """Get an *alive* session, raising if not started."""
        session = self.get_session(session_id)
        if not session.is_alive:
            sid = session_id or self.active_session_id
            raise ValueError(
                f"GDB session '{sid}' is not started. Call start_gdb first."
            )
        return session

    def drop_session(self, session_id: str) -> bool:
        """Remove a session from tracking (does NOT quit GDB)."""
        return self._sessions.pop(session_id, None) is not None

    # Backward-compatible alias
    @property
    def session(self) -> GDBSession:
        """The currently active session (backward-compat)."""
        return self.get_session()


# Global context — will be set during server initialization
_ctx: Optional[AppContext] = None


def get_context() -> AppContext:
    """Get the global application context."""
    global _ctx
    if _ctx is None:
        _ctx = AppContext()
    return _ctx


def set_context(ctx: AppContext) -> None:
    """Set the global application context."""
    global _ctx
    _ctx = ctx


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

import re

# Regex to match ANSI escape sequences.
# MI3 mode outputs them as literal "\e[...m" strings (not raw ESC bytes),
# but we also handle raw ESC (0x1b) in case direct terminal output is mixed in.
_ANSI_ESCAPE_RE = re.compile(
    r"(?:\x1b|\\e)"                     # ESC byte OR literal \e
    r"(?:"
    r"\[[0-9;]*[a-zA-Z]|"              # CSI: colors, cursor, SGR
    r"\]8;[^\x07]*?(?:\x1b|\\e)\\\\"   # OSC 8 hyperlink
    r")"
)

def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from a string.
    
    Used to clean pwndbg output (and other colored GDB output) before
    returning to MCP clients, since JSON serialization would otherwise
    escape the raw escape bytes into unreadable sequences.
    """
    if not text:
        return text
    return _ANSI_ESCAPE_RE.sub("", text)


def _format_output(output: Any) -> str:
    """Format a MI output result as a human-readable string."""
    if hasattr(output, "console_output"):
        # It's an MIOutput
        if output.is_error:
            return f"Error: {output.error_message}"
        text = strip_ansi(output.console_output.strip())
        if text:
            return text
        # Return structured results if no console text
        if output.result and output.result.results:
            return str(output.result.results)
        return "OK"
    return str(output)


def _format_mi_results(results: dict[str, Any]) -> str:
    """Format MI result data as a human-readable text (GDB CLI style).

    Handles common MI result structures:
    - stack  → backtrace (GDB bt style)
    - threads → thread list
    - frame  → frame info
    - Anything else → pretty JSON
    """
    if not results:
        return "OK"

    # ── stack (from -stack-list-frames) ──────────────────────────────
    stack = results.get("stack")
    if stack is not None and isinstance(stack, list):
        lines = []
        for entry in stack:
            frame = entry.get("frame", entry) if isinstance(entry, dict) else entry
            if not isinstance(frame, dict):
                continue
            level = str(frame.get("level", "?"))
            func = frame.get("func", "??")
            addr = frame.get("addr", "??")
            file_ = frame.get("file", frame.get("fullname", None))
            line = frame.get("line", None)

            if level == "0":
                prefix = f"#0  "
            else:
                prefix = f"#{level}  {addr} in "

            func_part = f"{func} ()"
            loc_parts = []
            if file_:
                loc_part = file_
                if line:
                    loc_part += f":{line}"
                loc_parts.append(f"at {loc_part}")

            line_text = prefix + func_part
            if loc_parts:
                line_text += " " + " ".join(loc_parts)
            lines.append(line_text)
        if lines:
            return "\n".join(lines)

    # ── stack-args (from -stack-list-arguments) ──────────────────────
    stack_args = results.get("stack-args")
    if stack_args is not None and isinstance(stack_args, list):
        lines = []
        for entry in stack_args:
            frame = entry.get("frame", {})
            level = str(frame.get("level", "?"))
            args_list = frame.get("args", [])
            real_args = [a for a in args_list if not a.get("name", "").endswith("@entry")]
            if real_args:
                args_str = ", ".join(f"{a['name']}={a['value']}" for a in real_args)
                lines.append(f"  Frame #{level}: {args_str}")
            else:
                lines.append(f"  Frame #{level}: (no arguments)")
        if lines:
            return "\n".join(lines)

    # ── threads (from -thread-info) ──────────────────────────────────
    threads = results.get("threads")
    if threads is not None and isinstance(threads, list):
        current = results.get("current-thread-id")
        lines = []
        for t in threads:
            tid = t.get("id", "?")
            target_id = t.get("target-id", "?")
            state = t.get("state", "?")
            frame = t.get("frame", {})
            func = frame.get("func", "??") if frame else "??"
            marker = " *" if str(tid) == str(current) else ""
            lines.append(f"  Thread {tid} ({target_id}): {state} in {func}{marker}")
        if lines:
            return "\n".join(lines)

    # ── frame (from -stack-info-frame) ───────────────────────────────
    frame = results.get("frame")
    if frame is not None and isinstance(frame, dict):
        level = frame.get("level", "?")
        func = frame.get("func", "??")
        addr = frame.get("addr", "??")
        file_ = frame.get("file", frame.get("fullname", None))
        line = frame.get("line", None)
        parts = [f"Frame #{level}: {addr} in {func}"]
        if file_:
            fl = file_
            if line:
                fl += f":{line}"
            parts.append(f"at {fl}")
        return " ".join(parts)

    # ── bkpt (from -break-insert) ────────────────────────────────────
    bkpt = results.get("bkpt")
    if bkpt is not None and isinstance(bkpt, dict):
        num = bkpt.get("number", "?")
        func = bkpt.get("func", bkpt.get("original-location", "?"))
        file_ = bkpt.get("file", "??")
        line = bkpt.get("line", "?")
        return f"Breakpoint {num} at {file_}:{line}, {func}"

    # ── BreakpointTable (from -break-list) ────────────────────────────
    bptable = results.get("BreakpointTable")
    if bptable is not None and isinstance(bptable, dict):
        body = bptable.get("body", [])
        lines = []
        for entry in body:
            bkpt = entry.get("bkpt", entry) if isinstance(entry, dict) else entry
            if not isinstance(bkpt, dict):
                continue
            num = bkpt.get("number", "?")
            func = bkpt.get("func", bkpt.get("original-location", "?"))
            file_ = bkpt.get("file", "??")
            line = bkpt.get("line", "?")
            addr = bkpt.get("addr", "??")
            enabled = bkpt.get("enabled", "y") == "y"
            enb = "y" if enabled else "n"
            disp = bkpt.get("disp", "keep")
            btype = bkpt.get("type", "breakpoint")
            lines.append(f"  {num:<4} {btype:<12} {disp:<6} {enb:<3} {addr:<18} in {func} at {file_}:{line}")
        if lines:
            return "\n".join(lines)

    # ── memory (from -data-read-memory-bytes) ────────────────────────
    memory = results.get("memory")
    if memory is not None and isinstance(memory, list):
        lines = []
        for block in memory:
            addr = block.get("address", "?")
            data = block.get("contents", [])
            hex_bytes = " ".join(b.get("value", "??") for b in data) if isinstance(data, list) else str(data)
            lines.append(f"  {addr}: {hex_bytes}")
        return "\n".join(lines) if lines else "No memory data"

    # ── variables (from -stack-list-variables) ───────────────────────
    variables = results.get("variables")
    if variables is not None and isinstance(variables, list):
        lines = []
        for var in variables:
            name = var.get("name", "?")
            value = var.get("value", "?")
            lines.append(f"  {name} = {value}")
        if lines:
            return "\n".join(lines)

    # ── Fallback: pretty JSON ────────────────────────────────────────
    try:
        import json
        return json.dumps(results, indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(results)


def _result_dict(success: bool, message: str, **kwargs: Any) -> dict[str, Any]:
    """Create a standardized result dictionary."""
    result = {"success": success, "message": message}
    result.update(kwargs)
    return result


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

def register_tools(mcp: FastMCP) -> None:
    """Register all MCP tools with the FastMCP server."""

    # =======================================================================
    # 5.1 生命周期工具 (Lifecycle Tools)
    # =======================================================================

    @mcp.tool()
    async def start_gdb_server(
        command: Annotated[str | None, Field(description="完整的自定义 GDB Server 命令行 (模式B)")] = None,
        port: Annotated[int | None, Field(description="gdbserver 监听端口 (模式A)")] = None,
        executable: Annotated[str | None, Field(description="要调试的可执行文件路径 (模式A, 可选)")] = None,
        args: Annotated[list[str] | None, Field(description="传递给 inferior 的参数 (模式A)")] = None,
        multi: Annotated[bool, Field(description="启用 --multi 扩展远程模式 (模式A)")] = False,
        once: Annotated[bool, Field(description="启用 --once 单次会话模式 (模式A)")] = False,
        attach_pid: Annotated[int | None, Field(description="附加到已有进程的 PID (模式A)")] = None,
    ) -> str:
        """启动 GDB 远程协议服务器。

        【前置条件】无，这是调试流程的第一步。
        【后续步骤】启动后调用 start_gdb → load_file → connect_target。

        支持两种模式:
        - 模式A (标准 GNU gdbserver): 提供 port 参数
          - 示例: start_gdb_server(port=50000, multi=True)
          - 示例: start_gdb_server(port=50000, executable="./test.elf")
        - 模式B (自定义 GDB Server): 提供 command 参数 (如 ST-LINK_gdbserver)
          - 示例: start_gdb_server(command="ST-LINK_gdbserver -p 50000 --swd")

        如果同时提供 command 和 port, command 优先 (模式B).
        如不提供任何参数，则尝试使用配置文件中的 gdbserver 配置。

        【注意】远程调试场景必须先调用此工具启动 GDB Server，
        然后才能使用 connect_target 连接。本地调试场景不需要此工具。
        """
        ctx = get_context()

        if ctx.server_mgr and ctx.server_mgr.is_running:
            return str(_result_dict(False, "GDB server is already running"))

        # Determine mode:
        # 1. 显式参数优先
        # 2. 其次使用配置文件中的 gdbserver 配置
        # 3. 否则报错
        if command:
            mode = "custom"
            config = GdbServerConfig(mode="custom", command=command, port=port or 50000)
        elif port is not None:
            mode = "standard"
            config = GdbServerConfig(
                mode="standard",
                port=port,
                multi=multi,
                once=once,
                attach_pid=attach_pid,
                args=args or [],
            )
        elif ctx.gdbserver_config is not None:
            # 回退到配置文件中的 gdbserver 配置
            config = ctx.gdbserver_config
            mode = config.mode
            logger.info("Using config file gdbserver mode=%s", mode)
        else:
            return str(_result_dict(False, "Must provide either 'command' (custom) or 'port' (standard), or configure gdbserver in config file"))

        ctx.gdbserver_config = config
        ctx.server_mgr = GdbServerManager(config)

        try:
            await ctx.server_mgr.start_and_wait_ready(timeout=15.0)
            status = ctx.server_mgr.get_status()
            return str(_result_dict(
                True,
                f"GDB server started (mode={mode}, PID={status['pid']})",
                **status,
            ))
        except GdbServerError as e:
            ctx.server_mgr = None
            return str(_result_dict(False, f"Failed to start GDB server: {e}"))

    @mcp.tool()
    async def stop_gdb_server() -> str:
        """停止已启动的 GDB Server 进程。

        【前置条件】已调用 start_gdb_server 且 GDB Server 正在运行。
        【使用场景】调试结束后清理资源，或重启 GDB Server 时使用。
        【注意】停止 GDB Server 后，已连接的 GDB 会话将断开连接。
        建议先调用 quit 关闭 GDB，再停止 GDB Server。
        """
        ctx = get_context()

        if not ctx.server_mgr or not ctx.server_mgr.is_running:
            return str(_result_dict(False, "GDB server is not running"))

        ctx.server_mgr.stop()
        ctx.server_mgr = None
        return str(_result_dict(True, "GDB server stopped"))

    @mcp.tool()
    async def start_gdb(
        gdb_path: Annotated[str, Field(description="GDB 可执行文件路径")] = "",
        init_commands: Annotated[list[str] | None, Field(description="GDB 启动后执行的初始化命令列表")] = None,
        session_id: Annotated[str | None, Field(description="会话标识符 (默认: 'default')，可同时运行多个独立 GDB 实例")] = None,
    ) -> str:
        """启动 GDB 进程 (MI3 模式)。

        【前置条件】无，但远程调试建议先调用 start_gdb_server。
        【后续步骤】调用 load_file 加载 ELF → connect_target 连接目标。
        【核心说明】这是所有调试操作的前置条件——必须先启动 GDB 才能执行后续任何调试操作。

        如果已有同名 session 在运行，会先退出旧的。
        如不提供参数，则使用配置文件中的默认值（如 arm-none-eabi-gdb）。
        使用不同的 session_id 可以同时运行多个独立的 GDB 实例。

        【示例】
        - start_gdb()  — 使用默认配置启动
        - start_gdb(gdb_path="gdb-multiarch")  — 指定 GDB 路径
        - start_gdb(session_id="stm32")  — 创建独立命名的调试会话
        """
        ctx = get_context()
        session = ctx.get_session(session_id)

        if session.is_alive:
            await session.quit()

        # 使用传入参数，或回退到配置文件中的默认值
        effective_gdb_path = gdb_path or ctx.gdb_path
        effective_init = list(ctx.gdb_init_commands)  # 从配置文件加载的初始命令
        if init_commands:
            effective_init.extend(init_commands)

        new_session = GDBSession(
            gdb_path=effective_gdb_path,
            init_commands=effective_init,
        )
        # Replace the session in the dict
        sid = session_id or ctx.active_session_id
        ctx._sessions[sid] = new_session

        try:
            await new_session.start()
            return str(_result_dict(
                True,
                f"GDB started (PID={new_session.pid}, session='{sid}')",
                pid=new_session.pid,
                session_id=sid,
                state=new_session.state.value,
            ))
        except Exception as e:
            return str(_result_dict(False, f"Failed to start GDB: {e}"))

    @mcp.tool()
    async def connect_target(
        host: Annotated[str, Field(description="GDB server 主机地址")] = "",
        port: Annotated[int, Field(description="GDB server 端口号")] = 0,
    ) -> str:
        """连接到 GDB 远程协议服务器。

        【前置条件】需先调用 start_gdb（启动 GDB）和 start_gdb_server（启动 GDB Server）。
        【后续步骤】连接成功后，可设置断点（break_insert）并开始执行（continue_execution）。
        【使用场景】远程嵌入式调试，连接目标开发板的 GDB Server。

        如不提供 host 和 port 参数，则使用配置文件中的 default_target。

        【示例】
        - connect_target()  — 使用配置文件的默认目标
        - connect_target(host="192.168.1.100", port=50000)  — 指定远程地址

        【注意】如果不需要远程调试（如本地调试），跳过此工具直接使用
        attach 或 break_insert → run_command("run"）。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        # 使用传入参数，或回退到配置文件中的 default_target
        effective_host = host
        effective_port = port
        if (not host or port == 0) and ctx.default_target:
            # 从 default_target (host:port) 中解析
            parts = ctx.default_target.split(":")
            if len(parts) == 2:
                effective_host = effective_host or parts[0]
                effective_port = effective_port or int(parts[1])
            else:
                effective_host = effective_host or "localhost"
                effective_port = effective_port or 50000

        if not effective_host or not effective_port:
            effective_host = "localhost"
            effective_port = 50000

        try:
            output = await session.send_mi_command(
                f"-target-select remote {effective_host}:{effective_port}"
            )
            if output.is_error:
                return str(_result_dict(False, f"Connection failed: {output.error_message}"))

            ctx.session._target_address = f"{effective_host}:{effective_port}"
            ctx.session._state = GDBState.CONNECTED
            return str(_result_dict(True, f"Connected to {effective_host}:{effective_port}"))
        except Exception as e:
            return str(_result_dict(False, f"Connection error: {e}"))

    @mcp.tool()
    async def disconnect() -> str:
        """断开与 GDB Server 的连接。

        【前置条件】已调用 connect_target 且连接处于活动状态。
        【后续步骤】可再次调用 connect_target 重新连接，或调用 quit 关闭 GDB。
        断开后 GDB 进程仍然保持运行状态。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command("-target-disconnect")
            ctx.session._target_address = None
            ctx.session._state = GDBState.STARTED
            return str(_result_dict(True, "Disconnected", output=_format_output(output)))
        except Exception as e:
            return str(_result_dict(False, f"Disconnect error: {e}"))

    @mcp.tool()
    async def attach(
        pid: Annotated[int, Field(description="要附加到的目标进程 PID")],
    ) -> str:
        """附加到正在运行的进程。

        【前置条件】需先调用 start_gdb 启动 GDB，并通过 load_file 加载对应程序。
        【后续步骤】附加成功后，可设置断点（break_insert）、继续执行（continue_execution）等。

        GDB 会附加到指定 PID 的进程并暂停其执行。
        需要 GDB 有足够的权限（可能需要 sudo 或设置 ptrace_scope）。

        【示例】attach(pid=1234)

        【注意】此工具适用于本地进程调试（如调试 Linux 本地程序），
        而非嵌入式远程调试。嵌入式场景请使用 connect_target。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command(f"-target-attach {pid}")
            if output.is_error:
                return str(_result_dict(False, f"Attach failed: {output.error_message}"))

            ctx.session._state = GDBState.STOPPED
            return str(_result_dict(
                True,
                f"Attached to process {pid}",
                pid=pid,
                state=ctx.session.state.value,
                console=strip_ansi(output.console_output.strip()) if output.console_output else "",
            ))
        except Exception as e:
            return str(_result_dict(False, f"Attach error: {e}"))

    @mcp.tool()
    async def load_file(
        file_path: Annotated[str, Field(description="ELF 可执行文件的绝对路径 (服务器本地路径)")],
    ) -> str:
        """通过文件路径加载 ELF 可执行文件到 GDB。

        【前置条件】需先调用 start_gdb 启动 GDB。
        【后续步骤】加载成功后，调用 connect_target（远程）或
        break_insert → continue_execution（本地）开始调试。

        需要提供 MCP 服务器本地的 ELF 文件绝对路径。
        会自动验证: 文件是否存在、是否可读、是否为 ELF 格式。

        【示例】
        - load_file(file_path="/home/user/projects/test.elf")
        - load_file(file_path="/workspace/build/firmware.elf")

        【注意】路径是 MCP 服务器上的路径，不是 AI 所在客户端的路径。
        如果文件尚未编译，需先确保已编译生成 ELF 文件。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        # Validate file exists
        if not os.path.exists(file_path):
            return str(_result_dict(False, f"File not found: {file_path}"))
        if not os.path.isfile(file_path):
            return str(_result_dict(False, f"Not a file: {file_path}"))
        if not os.access(file_path, os.R_OK):
            return str(_result_dict(False, f"File not readable: {file_path}"))

        # Check ELF magic bytes
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                if magic != b"\x7fELF":
                    return str(_result_dict(False, f"Not an ELF file: {file_path}"))
        except OSError as e:
            return str(_result_dict(False, f"Cannot read file: {e}"))

        try:
            # Load file and symbols
            output = await session.send_mi_command(
                f'-file-exec-and-symbols {file_path}'
            )
            if output.is_error:
                return str(_result_dict(False, f"Load failed: {output.error_message}"))

            ctx.session._loaded_file = file_path
            return str(_result_dict(
                True,
                f"Loaded: {file_path}",
                file=file_path,
            ))
        except Exception as e:
            return str(_result_dict(False, f"Load error: {e}"))

    @mcp.tool()
    async def quit(
        session_id: Annotated[str | None, Field(description="会话标识符 (默认: 当前活跃 session)")] = None,
    ) -> str:
        """关闭 GDB 进程并清理资源。

        【前置条件】当前 session 的 GDB 进程处于运行状态。
        【使用场景】调试结束后清理资源。
        【后续步骤】如不再需要，可调用 stop_gdb_server 停止 GDB Server。

        关闭指定 session_id 的 GDB 进程。如不指定，关闭当前活跃 session。
        进程退出后该 session 会被自动清理。

        【注意】quit 后如需继续调试，需重新调用 start_gdb 启动 GDB。
        """
        ctx = get_context()

        try:
            session = ctx.get_session(session_id)
            await session.quit()
            sid = session_id or ctx.active_session_id
            ctx.drop_session(sid)
            return str(_result_dict(True, f"GDB session '{sid}' exited"))
        except Exception as e:
            return str(_result_dict(False, f"Quit error: {e}"))

    @mcp.tool()
    async def get_status() -> str:
        """获取当前调试器状态（包含所有 session）。

        【使用场景】在任何时候都可以调用，了解当前调试会话的整体状态。
        返回所有 session 的信息，包括: GDB 进程是否存活、当前状态、
        已加载的文件、连接的远程目标等。还包含 GDB Server 的运行状态。

        适合在调试循环开始时调用，以了解当前处于调试的哪个阶段。
        """
        ctx = get_context()

        all_sessions = {}
        for sid, s in ctx.sessions.items():
            all_sessions[sid] = s.get_status()
            all_sessions[sid]["gdb_path"] = ctx.gdb_path

        status = {
            "active_session": ctx.active_session_id,
            "sessions": all_sessions,
        }
        if ctx.server_mgr:
            status["gdb_server"] = ctx.server_mgr.get_status()

        return str(_result_dict(True, "Status retrieved", **status))

    @mcp.tool()
    async def switch_session(
        session_id: Annotated[str, Field(description="要切换到的会话标识符")],
    ) -> str:
        """切换到指定的 GDB 会话。

        【前置条件】目标 session 必须存在（需先调用 start_gdb 创建）。
        【使用场景】多会话调试时，在不同调试实例之间切换。

        后续所有工具调用（如 continue, break_insert, print 等）都将
        作用于该会话。使用 list_sessions 查看所有可用会话。

        【示例】
        - switch_session(session_id="stm32")  — 切换到名为 stm32 的会话
        - 先 list_sessions 查看所有会话，再切换

        【注意】此工具不创建新会话，仅切换当前活跃的会话。
        创建新会话请使用 start_gdb(session_id="...")。
        """
        ctx = get_context()

        if session_id not in ctx._sessions:
            available = list(ctx._sessions.keys()) or ["(none)"]
            return str(_result_dict(
                False,
                f"Session '{session_id}' not found. Available: {', '.join(available)}",
            ))

        ctx.active_session_id = session_id
        session = ctx._sessions[session_id]
        return str(_result_dict(
            True,
            f"Switched to session '{session_id}' (alive={session.is_alive})",
            session_id=session_id,
            alive=session.is_alive,
        ))

    @mcp.tool()
    async def list_sessions() -> str:
        """列出所有 GDB 会话及其状态。

        【使用场景】查看当前所有调试会话的概览信息。
        返回每个 session 的: 是否存活、PID、当前状态、已加载的文件。
        同时也显示当前活跃的 session_id。

        适合在 switch_session 之前调用，了解可用的会话列表。
        """
        ctx = get_context()

        result = {}
        for sid, s in ctx.sessions.items():
            result[sid] = {
                "alive": s.is_alive,
                "pid": s.pid,
                "state": s.state.value,
                "loaded_file": s.loaded_file,
            }

        return str(_result_dict(
            True,
            f"{len(result)} session(s)",
            active=ctx.active_session_id,
            sessions=result,
        ))

    # =======================================================================
    # 5.2 执行控制工具 (Execution Control Tools)
    # =======================================================================

    @mcp.tool()
    async def continue_execution() -> str:
        """继续执行目标程序。

        【前置条件】需先完成 start_gdb → load_file → connect_target（远程）或
        break_insert → run_command("run")（本地），且程序当前处于停止状态。
        【使用场景】程序已停在断点或单步执行后，恢复执行。
        【后续步骤】程序继续运行，直到遇到断点、收到 interrupt 或程序结束。

        常用于以下流程：break_insert → continue_execution → 等待断点触发 →
        查看变量/调用栈 → continue_execution 继续。

        【注意】如果程序已在运行状态，调用此工具不会报错但无实际效果。
        如需中断运行中的程序，请使用 interrupt。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command("-exec-continue")
            if output.is_error:
                return str(_result_dict(False, f"Continue failed: {output.error_message}"))
            ctx.session._state = GDBState.RUNNING
            return str(_result_dict(True, "Execution continued"))
        except Exception as e:
            return str(_result_dict(False, f"Continue error: {e}"))

    @mcp.tool()
    async def interrupt() -> str:
        """中断目标程序执行 (发送 Ctrl+C)。

        【前置条件】程序当前处于运行状态（已调用 continue_execution 等）。
        【使用场景】程序运行超时或需要手动停止时，中断执行以进入 GDB 交互模式。
        【后续步骤】中断后可使用 backtrace 查看停在何处、print 查看变量值、
        step/next 单步执行等。

        【注意】调用后 GDB 会发送 SIGINT 信号，程序暂停后状态变为 STOPPED。
        如果程序未运行，此工具调用不会造成影响。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            await session.interrupt()
            # Wait a moment for the stop event
            import asyncio
            await asyncio.sleep(0.3)
            return str(_result_dict(True, "Target interrupted", state=ctx.session.state.value))
        except Exception as e:
            return str(_result_dict(False, f"Interrupt error: {e}"))

    @mcp.tool()
    async def stepi(
        count: Annotated[int, Field(description="执行的指令条数 (默认: 1)")] = 1,
    ) -> str:
        """单步执行一条机器指令 (step into)。

        【前置条件】程序当前处于停止状态（停在断点、单步后或刚被 interrupt）。
        【使用场景】需要逐条汇编指令调试时使用，比 step 更细粒度。
        会进入 call 指令所调用的函数内部。
        【后续步骤】执行后可查看寄存器（info_registers）、反汇编（disassemble）、
        查看内存（examine）或继续单步。

        【示例】stepi() — 执行一条指令；stepi(count=5) — 执行 5 条指令

        【对比】step — 按源码行单步（进入函数）
              nexti — 按指令单步（跳过函数调用）
              stepi — 按指令单步（进入函数调用）
        """
        ctx = get_context()
        session = ctx.ensure_session()

        cmd = f"-exec-step-instruction {count}" if count > 1 else "-exec-step-instruction"
        try:
            output = await session.send_mi_command(cmd)
            if output.is_error:
                return str(_result_dict(False, f"Stepi failed: {output.error_message}"))
            return str(_result_dict(True, f"Stepped {count} instruction(s)"))
        except Exception as e:
            return str(_result_dict(False, f"Stepi error: {e}"))

    @mcp.tool()
    async def step(
        count: Annotated[int, Field(description="执行的源码行数 (默认: 1)")] = 1,
    ) -> str:
        """单步执行一行源码 (step into, 进入函数)。

        【前置条件】程序当前处于停止状态（停在断点、单步后或刚被 interrupt）。
        【使用场景】逐行调试源码，当遇到函数调用时会进入函数内部。
        【后续步骤】执行后可查看变量（list_locals, print）、查看调用栈
        （backtrace）或继续单步。

        【示例】step() — 执行一行源码；step(count=3) — 执行 3 行

        【对比】step — 按源码行单步（进入函数）
              next — 按源码行单步（跳过函数）
              stepi — 按指令单步（进入函数）
        """
        ctx = get_context()
        session = ctx.ensure_session()

        cmd = f"-exec-step {count}" if count > 1 else "-exec-step"
        try:
            output = await session.send_mi_command(cmd)
            if output.is_error:
                return str(_result_dict(False, f"Step failed: {output.error_message}"))
            return str(_result_dict(True, f"Stepped {count} line(s)"))
        except Exception as e:
            return str(_result_dict(False, f"Step error: {e}"))

    @mcp.tool()
    async def nexti(
        count: Annotated[int, Field(description="执行的指令条数 (默认: 1)")] = 1,
    ) -> str:
        """单步执行一条机器指令 (step over, 不进入函数)。

        【前置条件】程序当前处于停止状态。
        【使用场景】逐条汇编指令调试，跳过 call 指令（不进入被调用函数）。
        【后续步骤】执行后可查看寄存器或继续单步。

        【示例】nexti() — 跳过一条指令；nexti(count=3) — 跳过 3 条指令

        【对比】next — 按源码行单步（跳过函数）
              nexti — 按指令单步（跳过函数调用）
              stepi — 按指令单步（进入函数调用）
        """
        ctx = get_context()
        session = ctx.ensure_session()

        cmd = f"-exec-next-instruction {count}" if count > 1 else "-exec-next-instruction"
        try:
            output = await session.send_mi_command(cmd)
            if output.is_error:
                return str(_result_dict(False, f"Nexti failed: {output.error_message}"))
            return str(_result_dict(True, f"Nexted {count} instruction(s)"))
        except Exception as e:
            return str(_result_dict(False, f"Nexti error: {e}"))

    @mcp.tool()
    async def next(
        count: Annotated[int, Field(description="执行的源码行数 (默认: 1)")] = 1,
    ) -> str:
        """单步执行一行源码 (step over, 不进入函数)。

        【前置条件】程序当前处于停止状态。
        【使用场景】最常用的单步调试方式，逐行执行源码但跳过函数内部细节。
        适用于大多数调试场景。
        【后续步骤】执行后可查看变量或继续单步。

        【示例】next() — 执行一行；next(count=3) — 执行 3 行

        【对比】step — 按源码行单步（进入函数）
              next — 按源码行单步（跳过函数）
              finish — 执行到当前函数返回
        """
        ctx = get_context()
        session = ctx.ensure_session()

        cmd = f"-exec-next {count}" if count > 1 else "-exec-next"
        try:
            output = await session.send_mi_command(cmd)
            if output.is_error:
                return str(_result_dict(False, f"Next failed: {output.error_message}"))
            return str(_result_dict(True, f"Nexted {count} line(s)"))
        except Exception as e:
            return str(_result_dict(False, f"Next error: {e}"))

    @mcp.tool()
    async def finish() -> str:
        """执行到当前函数返回。

        【前置条件】程序当前处于停止状态，且当前正在某个函数内。
        【使用场景】已经 step 进入一个函数后，想快速跳出回到调用者。
        相当于一次性执行完当前函数的剩余部分，停在调用处的下一行。
        【后续步骤】返回后可使用 backtrace 确认位置，或 continue_execution 继续。

        【示例】step → 进入函数 → finish → 跳出函数回到调用处
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command("-exec-finish")
            if output.is_error:
                return str(_result_dict(False, f"Finish failed: {output.error_message}"))
            return str(_result_dict(True, "Finished current function"))
        except Exception as e:
            return str(_result_dict(False, f"Finish error: {e}"))

    @mcp.tool()
    async def until(
        location: Annotated[str, Field(description='目标位置 (如 "main", "file.c:42", "0x08000100")')],
    ) -> str:
        """执行到指定位置。

        【前置条件】程序当前处于停止状态。
        【使用场景】希望程序快速执行到某个特定位置停下，如某个函数、行号或地址。
        类似于设置一个临时断点并继续执行。

        【示例】
        - until(location="main") — 执行到 main 函数
        - until(location="file.c:42") — 执行到文件指定行
        - until(location="0x08000100") — 执行到指定地址

        【注意】如果目标位置在当前执行路径之外（如之前的代码），可能无法到达。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command(f"-exec-until {location}")
            if output.is_error:
                return str(_result_dict(False, f"Until failed: {output.error_message}"))
            return str(_result_dict(True, f"Executing until: {location}"))
        except Exception as e:
            return str(_result_dict(False, f"Until error: {e}"))

    @mcp.tool()
    async def restart() -> str:
        """重新启动目标程序。

        【前置条件】已完成调试环境设置（GDB、连接等）。
        【使用场景】调试过程中需要重新运行程序时使用。
        会尝试使用 -exec-run 重新执行，失败时尝试通过 monitor reset 复位。

        【注意】对于远程嵌入式目标，重启效果取决于 GDB Server 的实现。
        有些场景可能需要先 disconnect 再重新 connect。
        对于嵌入式场景，也可使用 reset_target 进行芯片级复位。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            # Use -exec-run to restart (works for remote targets with extended-remote)
            output = await session.send_mi_command("-exec-run")
            if output.is_error:
                # Try alternative: disconnect and reconnect
                output2 = await session.send_cli_command("monitor reset")
                return str(_result_dict(True, "Restart attempted via monitor reset"))
            return str(_result_dict(True, "Program restarted"))
        except Exception as e:
            return str(_result_dict(False, f"Restart error: {e}"))

    @mcp.tool()
    async def reset_target(
        halt: Annotated[bool, Field(description="复位后是否暂停目标 (默认: True). True=monitor reset halt, False=monitor reset")] = True,
    ) -> str:
        """复位目标芯片 (通过 monitor 命令)。

        【前置条件】已连接到目标（connect_target），且 GDB Server 支持 monitor 命令。
        【使用场景】嵌入式调试中，需要复位目标芯片（如 STM32）时使用。
        【后续步骤】复位后可使用 continue_execution 运行或 stepi 单步从复位向量执行。

        发送 ``monitor reset halt`` (halt=True) 或 ``monitor reset`` (halt=False)。
        ``monitor reset halt`` 会将芯片复位并停在复位向量处，适合调试场景。
        ``monitor reset`` 只复位不暂停，适合需要芯片完全重启的场景。

        【注意】仅嵌入式远程调试场景有效，不适用于本地进程调试。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        cmd = "monitor reset halt" if halt else "monitor reset"
        try:
            # Use send_raw_command instead of send_cli_command because
            # ST-LINK GDB server may return ^error for successful monitor
            # commands (protocol quirk with Rcmd responses).
            text = await session.send_raw_command(cmd)
            return str(_result_dict(True, f"Reset via '{cmd}'", output=text.strip() or "OK"))
        except Exception as e:
            return str(_result_dict(False, f"Reset error: {e}"))

    # =======================================================================
    # 5.3 断点工具 (Breakpoint Tools)
    # =======================================================================

    @mcp.tool()
    async def break_insert(
        location: Annotated[str, Field(description='断点位置 (如 "main", "file.c:42", "*0x08000100")')],
        condition: Annotated[str | None, Field(description="断点条件表达式 (可选)")] = None,
        temporary: Annotated[bool, Field(description="是否为临时断点 (触发后自动删除)")] = False,
    ) -> str:
        """设置断点。

        【前置条件】需先完成 start_gdb → load_file → connect_target。
        【使用场景】在希望程序暂停的位置设置断点，然后使用 continue_execution
        运行程序，执行到断点处会自动停下。
        【后续步骤】设置后可调用 continue_execution 执行到断点，到达后使用
        backtrace/print/list_locals 查看程序状态。

        支持的位置格式:
        - "main" — 按函数名
        - "file.c:42" — 按文件和行号
        - "*0x08000100" — 按地址（需要 * 前缀）
        - condition 参数设置条件断点（如 condition="x > 5"）
        - temporary=True 设置临时断点（触发一次后自动删除）

        【示例】
        - break_insert(location="main") — 在 main 函数设断点
        - break_insert(location="app.c:84", condition="counter > 10") — 条件断点
        - break_insert(location="*0x08000100", temporary=True) — 临时地址断点
        """
        ctx = get_context()
        session = ctx.ensure_session()

        cmd = "-break-insert"
        if temporary:
            cmd = "-break-insert -t"
        if condition:
            cmd += f' -c "{condition}"'
        cmd += f" {location}"

        try:
            output = await session.send_mi_command(cmd)
            if output.is_error:
                return str(_result_dict(False, f"Break insert failed: {output.error_message}"))

            bkpt = output.result.results.get("bkpt", {}) if output.result else {}
            return str(_result_dict(
                True,
                f"Breakpoint set at {location}",
                breakpoint=bkpt,
            ))
        except Exception as e:
            return str(_result_dict(False, f"Break insert error: {e}"))

    @mcp.tool()
    async def break_delete(
        breakpoint_ids: Annotated[list[int], Field(description="要删除的断点 ID 列表")],
    ) -> str:
        """删除指定断点。

        【前置条件】已设置至少一个断点（可通过 break_list 查看断点 ID）。
        【使用场景】不再需要某个断点时，将其从目标上删除。

        【示例】
        - break_delete(breakpoint_ids=[1]) — 删除 1 号断点
        - break_delete(breakpoint_ids=[1, 2, 3]) — 批量删除多个断点

        【注意】删除不可恢复，如果需要临时禁用请使用 break_disable。
        如果想清空所有断点，可先 break_list 获取所有 ID 再批量删除。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        ids_str = " ".join(str(i) for i in breakpoint_ids)
        try:
            output = await session.send_mi_command(f"-break-delete {ids_str}")
            if output.is_error:
                return str(_result_dict(False, f"Break delete failed: {output.error_message}"))
            return str(_result_dict(True, f"Deleted breakpoints: {ids_str}"))
        except Exception as e:
            return str(_result_dict(False, f"Break delete error: {e}"))

    @mcp.tool()
    async def break_disable(
        breakpoint_ids: Annotated[list[int], Field(description="要禁用的断点 ID 列表")],
    ) -> str:
        """禁用指定断点。

        【前置条件】已设置至少一个断点（可通过 break_list 查看断点 ID）。
        【使用场景】临时禁用某个断点而不删除它，之后可重新启用。
        与 break_enable 配合使用。
        【后续步骤】禁用的断点不会触发，可通过 break_enable 重新启用。

        【示例】break_disable(breakpoint_ids=[2]) — 禁用 2 号断点

        【注意】禁用后断点依然保留在断点列表中（break_list 仍可看到），
        只是不再生效。如需永久移除请使用 break_delete。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        ids_str = " ".join(str(i) for i in breakpoint_ids)
        try:
            output = await session.send_mi_command(f"-break-disable {ids_str}")
            if output.is_error:
                return str(_result_dict(False, f"Break disable failed: {output.error_message}"))
            return str(_result_dict(True, f"Disabled breakpoints: {ids_str}"))
        except Exception as e:
            return str(_result_dict(False, f"Break disable error: {e}"))

    @mcp.tool()
    async def break_enable(
        breakpoint_ids: Annotated[list[int], Field(description="要启用的断点 ID 列表")],
    ) -> str:
        """启用指定断点。

        【前置条件】目标断点已被禁用（通过 break_disable）。
        【使用场景】重新启用之前被禁用的断点。
        【后续步骤】启用后，程序运行到该位置时会再次停下。

        【示例】break_enable(breakpoint_ids=[2]) — 重新启用 2 号断点

        【注意】如果断点从未被禁用，启用操作无实际效果。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        ids_str = " ".join(str(i) for i in breakpoint_ids)
        try:
            output = await session.send_mi_command(f"-break-enable {ids_str}")
            if output.is_error:
                return str(_result_dict(False, f"Break enable failed: {output.error_message}"))
            return str(_result_dict(True, f"Enabled breakpoints: {ids_str}"))
        except Exception as e:
            return str(_result_dict(False, f"Break enable error: {e}"))

    @mcp.tool()
    async def break_list() -> str:
        """列出所有断点。

        【前置条件】GDB 已启动。
        【使用场景】查看当前已设置的所有断点，包括其编号、位置、启用状态等。
        可用于在 break_delete/break_disable/break_enable 前查询断点 ID。

        【返回信息】每个断点的编号(number)、类型(type)、启用状态(enabled)、
        地址(addr)、函数(func)、文件:行号等信息。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command("-break-list")
            if output.is_error:
                return str(_result_dict(False, f"Break list failed: {output.error_message}"))

            bkpts = output.result.results.get("BreakpointTable", {}) if output.result else {}
            return str(_result_dict(True, "Breakpoint list", breakpoints=bkpts))
        except Exception as e:
            return str(_result_dict(False, f"Break list error: {e}"))

    @mcp.tool()
    async def catch(
        event_type: Annotated[str, Field(description='捕获事件类型 (如 "throw", "catch", "syscall", "load", "unload")')],
    ) -> str:
        """设置捕获点 (catchpoint)。

        【前置条件】GDB 已启动并连接到目标。
        【使用场景】捕获特定事件，如 C++ 异常抛出、系统调用、动态库加载/卸载等。
        当目标程序触发指定事件时，GDB 会自动暂停。

        【示例】
        - catch(event_type="throw") — 捕获 C++ 异常抛出
        - catch(event_type="syscall") — 捕获系统调用
        - catch(event_type="load") — 捕获动态库加载

        【注意】C++ 异常捕获需要 GDB 运行时支持，嵌入式场景可能不可用。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command(f"-catch-{event_type}")
            if output.is_error:
                return str(_result_dict(False, f"Catch failed: {output.error_message}"))
            return str(_result_dict(True, f"Catchpoint set for: {event_type}"))
        except Exception as e:
            return str(_result_dict(False, f"Catch error: {e}"))

    # =======================================================================
    # 5.4 数据查看工具 (Data Inspection Tools)
    # =======================================================================

    @mcp.tool()
    async def print(
        expression: Annotated[str, Field(description="要计算的表达式")],
        format: Annotated[str | None, Field(description="输出格式 (x=hex, d=decimal, t=binary, o=octal, etc.)")] = None,
    ) -> str:
        """求值并打印表达式。

        【前置条件】程序当前处于停止状态（停在断点或单步后）。
        【使用场景】调试时查看变量的值、计算表达式结果。
        支持所有 GDB 能识别的表达式格式。

        【示例】
        - print(expression="counter") — 查看变量 counter 的值
        - print(expression="counter + 1") — 计算表达式
        - print(expression="*(int*)0x20000000") — 指针解引用
        - print(expression="array[5]", format="x") — 以十六进制查看数组元素

        【注意】format 参数只在 MI 命令失败时作为后备使用。
        如需更强大的内存查看功能，请使用 examine 或 memory_read。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        fmt = f"/{format}" if format else ""
        try:
            output = await session.send_mi_command(
                f"-data-evaluate-expression {expression}"
            )
            if output.is_error:
                # Fallback to CLI print
                text = await session.send_raw_command(f"print{fmt} {expression}")
                return str(_result_dict(True, text.strip() if text.strip() else "No output"))

            value = output.result.results.get("value", "") if output.result else ""
            return str(_result_dict(True, f"{expression} = {value}", value=value))
        except Exception as e:
            return str(_result_dict(False, f"Print error: {e}"))

    @mcp.tool()
    async def examine(
        address: Annotated[str, Field(description='起始地址 (如 "0x20000000" 或 "&variable")')],
        count: Annotated[int, Field(description="要显示的单元数")] = 1,
        format: Annotated[str, Field(description="显示格式 (x=hex, d=decimal, t=binary, o=octal, s=string, i=instruction)")] = "x",
        size: Annotated[str, Field(description="单元大小 (b=byte, h=halfword, w=word, g=giant)")] = "w",
    ) -> str:
        """检查内存 (GDB x 命令)。

        【前置条件】程序当前处于停止状态。
        【使用场景】查看指定地址的内存内容，支持多种格式和大小。
        相当于 GDB 的 examine (x) 命令，比 memory_read 更灵活。

        【参数说明】
        - address: 起始地址，如 "0x20000000" 或 "&variable"
        - count: 显示的单元数（默认 1）
        - format: 显示格式 (x=十六进制, d=十进制, t=二进制, s=字符串, i=指令)
        - size: 单元大小 (b=字节, h=半字, w=字, g=8字节)

        【示例】
        - examine(address="0x20000000", count=16, format="x", size="b") — 16 字节十六进制
        - examine(address="&buffer", count=4, format="d", size="w") — 4 个十进制字
        - examine(address="main", count=8, format="i") — 反汇编 8 条指令

        【注意】此工具使用 GDB CLI 命令，返回文本格式。
        如需结构化数据请使用 memory_read。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        cmd = f"x/{count}{size}{format} {address}"
        try:
            text = await session.send_raw_command(cmd)
            return str(_result_dict(True, text.strip() if text.strip() else "No output"))
        except Exception as e:
            return str(_result_dict(False, f"Examine error: {e}"))

    @mcp.tool()
    async def display(
        expression: Annotated[str, Field(description="要自动显示的表达式")],
    ) -> str:
        """设置自动显示表达式 (每次程序停止时自动显示)。

        【前置条件】程序当前处于停止状态。
        【使用场景】每次程序停止时自动显示某个表达式的值，适合持续观察变量变化。
        相当于 GDB 的 display 命令。

        【示例】display(expression="counter") — 每次停止时自动显示 counter 的值

        【注意】设置后每次程序暂停（断点、单步后）都会自动显示该表达式的值。
        过多的 display 项会影响性能。如需取消，可使用 run_command("undisplay N")。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            text = await session.send_raw_command(f"display {expression}")
            return str(_result_dict(True, text.strip() if text.strip() else "Display set"))
        except Exception as e:
            return str(_result_dict(False, f"Display error: {e}"))

    @mcp.tool()
    async def set_variable(
        name: Annotated[str, Field(description='变量名或寄存器名 (如 "var1", "$pc", "$sp")')],
        value: Annotated[str, Field(description='要设置的值 (如 "42", "0x100", \\"hello\\")')],
    ) -> str:
        """修改变量或寄存器的值。

        【前置条件】程序当前处于停止状态。
        【使用场景】调试时修改变量的值以测试不同代码路径，或修改寄存器控制硬件行为。
        适用于变量、寄存器、内存位置。

        【示例】
        - set_variable(name="counter", value="42") — 将 counter 设为 42
        - set_variable(name="$pc", value="0x08000100") — 修改程序计数器
        - set_variable(name="*0x20000000", value="0xff") — 修改内存

        【注意】修改 $pc（程序计数器）可强制跳转到指定地址执行，
        修改 $sp（栈指针）需谨慎，可能导致栈不一致。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command(
                f"-gdb-set {name} = {value}"
            )
            if output.is_error:
                return str(_result_dict(False, f"Set failed: {output.error_message}"))
            return str(_result_dict(True, f"Set {name} = {value}"))
        except Exception as e:
            return str(_result_dict(False, f"Set error: {e}"))

    @mcp.tool()
    async def memory_read(
        address: Annotated[str, Field(description='起始地址 (如 "0x20000000")')],
        size: Annotated[int, Field(description="读取的字节数")] = 4,
    ) -> str:
        """读取指定地址的内存数据。

        【前置条件】程序当前处于停止状态。
        【使用场景】读取目标板内存的原始字节数据，返回结构化数据格式。
        适合需要解析内存内容的场景。

        【示例】
        - memory_read(address="0x20000000", size=16) — 读取 16 字节
        - memory_read(address="0x08000000", size=256) — 读取 256 字节

        【注意】返回的是结构化数据（每个字节 address/value 对应）。
        如需更灵活的格式控制（如按字/半字显示），请使用 examine。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command(
                f"-data-read-memory-bytes {address} {size}"
            )
            if output.is_error:
                return str(_result_dict(False, f"Memory read failed: {output.error_message}"))

            memory = output.result.results.get("memory", []) if output.result else []
            return str(_result_dict(True, "Memory read", memory=memory))
        except Exception as e:
            return str(_result_dict(False, f"Memory read error: {e}"))

    @mcp.tool()
    async def memory_write(
        address: Annotated[str, Field(description='目标地址 (如 "0x20000000")')],
        data: Annotated[str, Field(description='要写入的数据 (十六进制字符串, 如 "deadbeef")')],
        size: Annotated[int | None, Field(description="写入的字节数 (可选, 默认为 data 长度/2)")] = None,
    ) -> str:
        """写入内存数据。

        【前置条件】程序当前处于停止状态。
        【使用场景】向目标板内存写入原始字节数据，如修改变量、打补丁、配置外设寄存器等。

        【示例】
        - memory_write(address="0x20000000", data="deadbeef") — 写入 4 字节
        - memory_write(address="0x40020000", data="01020304", size=4) — 写入指定长度

        【注意】data 为十六进制字符串，不包含 0x 前缀。
        size 默认为 data 长度的一半（每个字节两个字符）。
        写入前请确认目标地址可写（RAM），Flash 写入需要特殊操作。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        # Remove 0x prefix if present
        if data.startswith("0x") or data.startswith("0X"):
            data = data[2:]

        num_bytes = size or (len(data) // 2)

        try:
            output = await session.send_mi_command(
                f"-data-write-memory-bytes {address} {data} {num_bytes}"
            )
            if output.is_error:
                return str(_result_dict(False, f"Memory write failed: {output.error_message}"))
            return str(_result_dict(True, f"Wrote {num_bytes} bytes to {address}"))
        except Exception as e:
            return str(_result_dict(False, f"Memory write error: {e}"))

    # =======================================================================
    # 5.5 堆栈/线程工具 (Stack/Thread Tools)
    # =======================================================================

    @mcp.tool()
    async def backtrace(
        count: Annotated[int | None, Field(description="显示的栈帧数量 (可选, 默认全部)。正数显示前 N 帧，负数显示后 N 帧")] = None,
        full: Annotated[bool, Field(description="是否同时显示局部变量")] = False,
    ) -> str:
        """显示调用栈。

        【前置条件】程序当前处于停止状态（停在断点、单步后或刚被 interrupt）。
        【使用场景】程序暂停时查看调用栈，了解当前执行位置和函数调用链。
        格式化输出与 GDB ``bt`` 命令风格一致，包含函数地址、参数、文件名和行号。

        【参数说明】
        - count: 显示帧数控制。正数显示前 N 帧，负数显示后 N 帧，默认显示全部
        - full: 设置为 True 时同时显示当前帧的局部变量

        【示例】
        - backtrace() — 显示完整调用栈
        - backtrace(count=5) — 显示最近 5 帧
        - backtrace(count=-3) — 显示最后 3 帧（最顶层的调用者）
        - backtrace(full=True) — 显示调用栈+局部变量

        【后续步骤】使用 select_frame 选择特定帧，然后查看局部变量或参数。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            # 1) 获取栈帧列表
            frames_output = await session.send_mi_command("-stack-list-frames")
            if frames_output.is_error:
                return str(_result_dict(False, f"Backtrace failed: {frames_output.error_message}"))

            frames = frames_output.result.results.get("stack", []) if frames_output.result else []

            # 2) 获取函数参数
            args_output = await session.send_mi_command("-stack-list-arguments --all-values")
            args_by_level: dict[str, list[dict]] = {}
            if args_output.result and not args_output.is_error:
                stack_args = args_output.result.results.get("stack-args", [])
                for entry in stack_args:
                    frame = entry.get("frame", {})
                    level = str(frame.get("level", ""))
                    args_list = frame.get("args", [])
                    # 只显示有实际参数的帧
                    if args_list:
                        # 过滤掉 @entry 后缀的参数（GDB bt 不显示它们）
                        real_args = [a for a in args_list if not a.get("name", "").endswith("@entry")]
                        if real_args:
                            args_by_level[level] = real_args

            # 3) 构建格式化输出
            result_text = ""
            num_frames = len(frames)

            # 应用 count 限制
            start_idx = 0
            end_idx = num_frames
            if count is not None:
                if count > 0:
                    end_idx = min(count, num_frames)
                elif count < 0:
                    start_idx = max(0, num_frames + count)

            for i in range(start_idx, end_idx):
                frame_entry = frames[i]
                frame = frame_entry.get("frame", frame_entry) if isinstance(frame_entry, dict) else frame_entry
                level = str(frame.get("level", "?"))
                func = frame.get("func", "??")
                file_ = frame.get("file", frame.get("fullname", None))
                line = frame.get("line", None)
                addr = frame.get("addr", "??")

                # 获取该帧的函数参数
                frame_args = args_by_level.get(level, [])
                args_str = ", ".join(f"{a['name']}={a['value']}" for a in frame_args) if frame_args else ""

                # GDB bt 格式:
                #   #0  func (args) at file:line          (当前帧，无地址前缀)
                #   #N  0xADDR in func (args) at file:line (其他帧)
                if level == "0":
                    prefix = f"#0  "
                else:
                    prefix = f"#{level}  {addr} in "

                # 格式化: func (args)
                if args_str:
                    func_part = f"{func} ({args_str})"
                else:
                    func_part = f"{func} ()"

                # 格式化: at file:line
                loc_parts = []
                if file_:
                    loc_part = file_
                    if line:
                        loc_part += f":{line}"
                    loc_parts.append(f"at {loc_part}")

                line_text = prefix + func_part
                if loc_parts:
                    line_text += " " + " ".join(loc_parts)

                result_text += line_text + "\n"

            # 4) full 模式：显示局部变量（仅当前帧）
            if full and frames:
                try:
                    vars_output = await session.send_mi_command("-stack-list-variables --all-values")
                    if vars_output.result:
                        variables = vars_output.result.results.get("variables", [])
                        if variables:
                            result_text += "\nVariables:\n"
                            for var in variables:
                                name = var.get("name", "?")
                                value = var.get("value", "?")
                                result_text += f"  {name} = {value}\n"
                except Exception:
                    pass

            return str(_result_dict(
                True,
                result_text.strip() if result_text.strip() else "No backtrace available",
            ))
        except Exception as e:
            return str(_result_dict(False, f"Backtrace error: {e}"))

    @mcp.tool()
    async def select_frame(
        frame_num: Annotated[int, Field(description="栈帧编号 (0=当前, 1=调用者, ...)")],
    ) -> str:
        """选择当前栈帧。

        【前置条件】程序处于停止状态，且存在至少一个栈帧（backtrace 可查看）。
        【使用场景】在 backtrace 显示调用链后，选择某帧查看其局部变量和参数。
        【后续步骤】选择后可使用 list_locals 查看该帧的局部变量、list_args 查看参数。

        【示例】backtrace() → select_frame(frame_num=2) → list_locals()

        【注意】帧编号 0 为当前执行位置，数字越大越靠近程序入口（main）。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command(f"-stack-select-frame {frame_num}")
            if output.is_error:
                return str(_result_dict(False, f"Select frame failed: {output.error_message}"))
            return str(_result_dict(True, f"Selected frame {frame_num}"))
        except Exception as e:
            return str(_result_dict(False, f"Select frame error: {e}"))

    @mcp.tool()
    async def frame_info() -> str:
        """显示当前栈帧信息。

        【前置条件】程序处于停止状态。
        【使用场景】查看当前栈帧的详细信息，包括函数名、参数、地址、源文件位置等。
        适合在单步执行后确认当前执行位置。
        【后续步骤】如需查看其他帧，先使用 select_frame 切换。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command("-stack-info-frame")
            if output.is_error:
                return str(_result_dict(False, f"Frame info failed: {output.error_message}"))

            frame = output.result.results.get("frame", {}) if output.result else {}
            return str(_result_dict(True, "Frame info", frame=frame))
        except Exception as e:
            return str(_result_dict(False, f"Frame info error: {e}"))

    @mcp.tool()
    async def list_locals() -> str:
        """显示当前栈帧的局部变量。

        【前置条件】程序处于停止状态，且当前帧有局部变量。
        【使用场景】调试时查看当前函数的局部变量及其值。
        如需查看其他帧的变量，先使用 select_frame 切换。
        【后续步骤】如需计算表达式，使用 print 工具。

        【示例】break_insert("main") → continue_execution → list_locals()
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command("-stack-list-variables --all-values")
            if output.is_error:
                return str(_result_dict(False, f"List locals failed: {output.error_message}"))

            variables = output.result.results.get("variables", []) if output.result else []
            locals_text = ""
            for var in variables:
                name = var.get("name", "?")
                value = var.get("value", "?")
                locals_text += f"{name} = {value}\n"

            return str(_result_dict(
                True,
                locals_text.strip() if locals_text.strip() else "No local variables",
                variables=variables,
            ))
        except Exception as e:
            return str(_result_dict(False, f"List locals error: {e}"))

    @mcp.tool()
    async def list_args() -> str:
        """显示当前函数的参数。

        【前置条件】程序处于停止状态，且当前帧有函数参数。
        【使用场景】查看当前函数接收到的参数值，与 list_locals 互补。
        如需查看其他帧的参数，先使用 select_frame 切换。
        【后续步骤】如需修改参数值，使用 set_variable。

        【示例】break_insert("main") → continue_execution → list_args()
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command("-stack-list-arguments --all-values 0 0")
            if output.is_error:
                return str(_result_dict(False, f"List args failed: {output.error_message}"))

            stack_args = output.result.results.get("stack-args", []) if output.result else []
            args_text = ""
            for entry in stack_args:
                frame = entry.get("frame", {})
                level = frame.get("level", "?")
                args = frame.get("args", [])
                if args:
                    args_text += f"Frame #{level}:\n"
                    for arg in args:
                        name = arg.get("name", "?")
                        value = arg.get("value", "?")
                        args_text += f"  {name} = {value}\n"

            return str(_result_dict(
                True,
                args_text.strip() if args_text.strip() else "No arguments",
                args=stack_args,
            ))
        except Exception as e:
            return str(_result_dict(False, f"List args error: {e}"))

    @mcp.tool()
    async def thread_info() -> str:
        """列出所有线程信息。

        【前置条件】程序处于停止状态，且目标支持多线程。
        【使用场景】查看目标程序的所有线程及其状态，可用于定位线程问题。
        【后续步骤】使用 thread_select 切换到指定线程进行调试。

        【注意】单线程或嵌入式目标可能只显示一个线程。
        多线程调试时，切换线程后 backtrace/print 等操作将作用于新线程。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command("-thread-info")
            if output.is_error:
                return str(_result_dict(False, f"Thread info failed: {output.error_message}"))

            threads = output.result.results.get("threads", []) if output.result else []
            current = output.result.results.get("current-thread-id", None) if output.result else None

            threads_text = ""
            for t in threads:
                tid = t.get("id", "?")
                target_id = t.get("target-id", "?")
                state = t.get("state", "?")
                frame = t.get("frame", {})
                func = frame.get("func", "??") if frame else "??"
                marker = " *" if str(tid) == str(current) else ""
                threads_text += f"Thread {tid} ({target_id}): {state} in {func}{marker}\n"

            return str(_result_dict(
                True,
                threads_text.strip() if threads_text.strip() else "No threads",
                threads=threads,
                current_thread=current,
            ))
        except Exception as e:
            return str(_result_dict(False, f"Thread info error: {e}"))

    @mcp.tool()
    async def thread_select(
        thread_id: Annotated[int, Field(description="线程 ID")],
    ) -> str:
        """选择当前线程。

        【前置条件】程序处于停止状态，且存在多个线程（thread_info 可查看）。
        【使用场景】多线程调试时切换到指定线程进行调试。
        【后续步骤】切换后可使用 backtrace/print 查看该线程的状态和变量。

        【示例】thread_info() → thread_select(thread_id=2) → backtrace()

        【注意】切换线程后，后续所有调试操作（单步、断点等）都作用于该线程。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command(f"-thread-select {thread_id}")
            if output.is_error:
                return str(_result_dict(False, f"Thread select failed: {output.error_message}"))
            return str(_result_dict(True, f"Selected thread {thread_id}"))
        except Exception as e:
            return str(_result_dict(False, f"Thread select error: {e}"))

    # =======================================================================
    # 5.6 反汇编/源码工具 (Disassembly/Source Tools)
    # =======================================================================

    @mcp.tool()
    async def disassemble(
        location: Annotated[str | None, Field(description='要反汇编的位置 (如 "main", "0x08000100", 可选, 默认当前位置)')] = None,
    ) -> str:
        """反汇编当前或指定位置的代码。

        【前置条件】程序处于停止状态。
        【使用场景】查看当前执行位置或指定函数的汇编代码。
        适合分析底层行为、理解编译器优化、调试没有源码的情况。

        【示例】
        - disassemble() — 反汇编当前位置
        - disassemble(location="main") — 反汇编 main 函数
        - disassemble(location="0x08000100") — 反汇编指定地址

        【注意】反汇编输出依赖于 GDB 的反汇编风格配置。
        如需查看当前指令，也可使用 examine(format="i")。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        loc = f" {location}" if location else ""
        try:
            text = await session.send_raw_command(f"disassemble{loc}")
            return str(_result_dict(True, text.strip() if text.strip() else "No disassembly"))
        except Exception as e:
            return str(_result_dict(False, f"Disassemble error: {e}"))

    @mcp.tool()
    async def list_source(
        file: Annotated[str | None, Field(description="源文件名 (可选)")] = None,
        line: Annotated[int | None, Field(description="起始行号 (可选)")] = None,
    ) -> str:
        """列出源代码。

        【前置条件】程序已加载 ELF 文件（包含调试符号），且源码在 GDB 可访问的路径。
        【使用场景】查看当前位置或指定文件/行的源代码。
        【后续步骤】可与 break_insert(location="file.c:line") 配合设置断点。

        【示例】
        - list_source() — 列出当前位置的源码
        - list_source(file="main.c") — 列出 main.c 开头
        - list_source(file="main.c", line=42) — 从 main.c:42 开始列出

        【注意】源码文件需在 GDB 可访问的路径中。
        如果编译时使用了 -g 但不包含源码路径，可能无法显示。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        location = ""
        if file and line:
            location = f" {file}:{line}"
        elif file:
            location = f" {file}"
        elif line:
            location = f" {line}"

        try:
            text = await session.send_raw_command(f"list{location}")
            return str(_result_dict(True, text.strip() if text.strip() else "No source available"))
        except Exception as e:
            return str(_result_dict(False, f"List source error: {e}"))

    @mcp.tool()
    async def info_registers(
        registers: Annotated[list[str] | None, Field(description="要显示的寄存器名列表 (可选, 默认显示所有寄存器)")] = None,
    ) -> str:
        """显示寄存器值。

        【前置条件】程序处于停止状态。
        【使用场景】查看 CPU 寄存器的当前值，对于底层调试、异常分析和
        嵌入式开发非常重要。

        【示例】
        - info_registers() — 显示所有寄存器
        - info_registers(registers=["r0", "r1", "pc", "sp"]) — 显示指定寄存器

        【注意】显示的寄存器集合取决于目标 CPU 架构（ARM、x86、RISC-V 等）。
        使用 print(expression="$pc") 也可查看单个寄存器值。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        if registers:
            reg_str = " ".join(registers)
            cmd = f"info registers {reg_str}"
        else:
            cmd = "info registers"

        try:
            text = await session.send_raw_command(cmd)
            return str(_result_dict(True, text.strip() if text.strip() else "No register info"))
        except Exception as e:
            return str(_result_dict(False, f"Info registers error: {e}"))

    @mcp.tool()
    async def info_types(
        name: Annotated[str | None, Field(description="类型名 (可选, 默认显示所有类型)")] = None,
    ) -> str:
        """显示类型信息。

        【前置条件】程序已加载带调试符号的 ELF 文件（编译时加 -g 选项）。
        【使用场景】查看 C/C++ 结构体、枚举、类型定义等详细信息。
        对于理解复杂数据结构非常有用。

        【示例】
        - info_types() — 列出所有已知类型
        - info_types(name="GPIO_TypeDef") — 查看结构体定义
        - info_types(name="int") — 查看 int 类型信息

        【注意】需要目标文件包含完整的 DWARF 调试信息。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        cmd = f"ptype {name}" if name else "info types"
        try:
            text = await session.send_raw_command(cmd)
            return str(_result_dict(True, text.strip() if text.strip() else "No type info"))
        except Exception as e:
            return str(_result_dict(False, f"Info types error: {e}"))

    # =======================================================================
    # 5.7 通用/高级工具 (General/Advanced Tools)
    # =======================================================================

    @mcp.tool()
    async def run_command(
        command: Annotated[str, Field(description="GDB 命令字符串")],
        mi: Annotated[bool, Field(description="是否为 MI 命令 (默认为 CLI 命令)")] = False,
    ) -> str:
        """执行任意 GDB 命令 (escape hatch)。

        【前置条件】GDB 已启动。
        【使用场景】当 MCP 提供的标准工具无法满足需求时，使用此工具执行
        任意 GDB 命令作为兜底方案。支持 CLI 和 MI 两种命令模式。

        【示例 - CLI 模式】
        - run_command(command="info vector") — 查看向量表信息
        - run_command(command="monitor flash info") — 查询 Flash 信息
        - run_command(command="show architecture") — 查看目标架构

        【示例 - MI 模式】
        - run_command(command="-symbol-list-lines", mi=True)

        【注意】mi=True 时命令需符合 GDB MI 语法（以 - 开头）。
        如果 MCP 已提供标准工具，优先使用以获得更好的格式化输出。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            if mi:
                output = await session.send_mi_command(command)
                if output.is_error:
                    return str(_result_dict(False, f"Command error: {output.error_message}"))
                return str(_result_dict(
                    True,
                    output.console_output.strip() or "OK",
                    result=output.result.results if output.result else {},
                ))
            else:
                text = await session.send_raw_command(command)
                return str(_result_dict(True, text.strip() if text.strip() else "OK"))
        except Exception as e:
            return str(_result_dict(False, f"Command error: {e}"))

    @mcp.tool()
    async def define_hook(
        event: Annotated[str, Field(description='事件名称 (如 "stop", "breakpoint")')],
        command: Annotated[str, Field(description="事件触发时执行的 GDB 命令")],
    ) -> str:
        """定义事件钩子命令。

        【前置条件】GDB 已启动。
        【使用场景】设置在特定 GDB 事件发生时自动执行的命令。
        如每次程序停止时自动打印寄存器值或执行特定操作。

        【示例】
        - define_hook(event="stop", command="info registers pc sp")
          — 每次停止时自动显示 PC 和 SP 寄存器

        【注意】这是 GDB 的 hook- 高级功能。
        使用 run_command(command="show hook-stop") 查看已定义的钩子。
        """
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            text = await session.send_raw_command(
                f"define hook-{event}\n{command}\nend"
            )
            return str(_result_dict(True, f"Hook defined for event '{event}'"))
        except Exception as e:
            return str(_result_dict(False, f"Define hook error: {e}"))

    # =======================================================================
    # 额外的便利工具 (Additional Convenience Tools)
    # =======================================================================

    @mcp.tool()
    async def flash_and_run(
        file_path: Annotated[str, Field(description="ELF 可执行文件的绝对路径")],
        host: Annotated[str, Field(description="GDB server 主机地址")] = "localhost",
        port: Annotated[int, Field(description="GDB server 端口号")] = 50000,
        stop_at: Annotated[str | None, Field(description='可选断点位置 (如 "main")')] = None,
    ) -> str:
        """一站式操作: 加载 ELF → 连接 → (可选)设断点 → 运行。

        【前置条件】GDB Server 需已启动（通过 start_gdb_server）。
        【使用场景】快速完成调试的完整流程，无需手动调用多个工具。
        适合自动化调试或快速开始调试。

        自动完成以下步骤:
        1. start_gdb（如未启动）
        2. load_file（加载 ELF 文件）
        3. connect_target（连接 GDB Server）
        4. break_insert（如指定 stop_at，设置断点）
        5. -target-download（烧录到目标板）
        6. continue_execution（如设置了断点，执行到断点）

        【示例】
        - flash_and_run(file_path="/workspace/build/firmware.elf")
        - flash_and_run(file_path="/workspace/build/firmware.elf", stop_at="main")

        【注意】GDB Server 需提前启动。此工具依赖 -target-download 命令，
        部分 GDB Server 可能不支持，失败不会阻塞后续操作。
        """
        ctx = get_context()

        results: list[str] = []

        # Start GDB if not running
        if not ctx.session.is_alive:
            r = await start_gdb()
            results.append(f"[start_gdb] {r}")

        # Load file
        r = await load_file(file_path=file_path)
        results.append(f"[load_file] {r}")
        if '"success": false' in r or '"success":False' in r:
            return str(_result_dict(False, "Flash and run failed at load_file", details=results))

        # Connect
        r = await connect_target(host=host, port=port)
        results.append(f"[connect] {r}")
        if '"success": false' in r or '"success":False' in r:
            return str(_result_dict(False, "Flash and run failed at connect", details=results))

        # Set breakpoint if requested
        if stop_at:
            r = await break_insert(location=stop_at)
            results.append(f"[breakpoint] {r}")

        # Load to target
        try:
            load_output = await ctx.session.send_mi_command("-target-download")
            results.append(f"[download] {_format_output(load_output)}")
        except Exception as e:
            results.append(f"[download] Error: {e}")

        # Continue
        if stop_at:
            r = await continue_execution()
            results.append(f"[continue] {r}")

        return str(_result_dict(True, "Flash and run completed", details=results))
