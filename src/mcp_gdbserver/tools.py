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
    """Shared application context for tools."""

    def __init__(self) -> None:
        self.session = GDBSession()
        self.server_mgr: Optional[GdbServerManager] = None
        self.gdbserver_config: Optional[GdbServerConfig] = None
        # Configuration defaults loaded from config file / CLI
        self.gdb_path: str = "arm-none-eabi-gdb"
        self.gdb_init_commands: list[str] = ["set pagination off", "set confirm off"]
        self.default_target: Optional[str] = None
        self.timeout_seconds: float = 30.0

    def ensure_session(self) -> GDBSession:
        """Get the GDB session, raising an error if not started."""
        if not self.session.is_alive:
            raise ValueError("GDB session is not started. Call start_gdb / connect first.")
        return self.session


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

        支持两种模式:
        - 模式A (标准 GNU gdbserver): 提供 port 参数
        - 模式B (自定义 GDB Server): 提供 command 参数 (如 ST-LINK_gdbserver)

        如果同时提供 command 和 port, command 优先 (模式B).
        如不提供任何参数，则尝试使用配置文件中的 gdbserver 配置。
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
        """停止已启动的 GDB Server 进程。"""
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
    ) -> str:
        """启动 GDB 进程 (MI3 模式)。

        如果已有 GDB 进程在运行，会先退出旧的。
        如不提供参数，则使用配置文件中的默认值。
        """
        ctx = get_context()

        if ctx.session.is_alive:
            await ctx.session.quit()

        # 使用传入参数，或回退到配置文件中的默认值
        effective_gdb_path = gdb_path or ctx.gdb_path
        effective_init = list(ctx.gdb_init_commands)  # 从配置文件加载的初始命令
        if init_commands:
            effective_init.extend(init_commands)

        ctx.session = GDBSession(
            gdb_path=effective_gdb_path,
            init_commands=effective_init,
        )

        try:
            await ctx.session.start()
            return str(_result_dict(
                True,
                f"GDB started (PID={ctx.session.pid})",
                pid=ctx.session.pid,
                state=ctx.session.state.value,
            ))
        except Exception as e:
            return str(_result_dict(False, f"Failed to start GDB: {e}"))

    @mcp.tool()
    async def connect_target(
        host: Annotated[str, Field(description="GDB server 主机地址")] = "",
        port: Annotated[int, Field(description="GDB server 端口号")] = 0,
    ) -> str:
        """连接到 GDB 远程协议服务器。

        如不提供参数，则使用配置文件中的 default_target。
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
        """断开与 GDB Server 的连接。"""
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
    async def load_file(
        file_path: Annotated[str, Field(description="ELF 可执行文件的绝对路径 (服务器本地路径)")],
    ) -> str:
        """通过文件路径加载 ELF 可执行文件到 GDB。"""
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
    async def quit() -> str:
        """关闭 GDB 进程并清理资源。"""
        ctx = get_context()

        try:
            await ctx.session.quit()
            return str(_result_dict(True, "GDB exited"))
        except Exception as e:
            return str(_result_dict(False, f"Quit error: {e}"))

    @mcp.tool()
    async def get_status() -> str:
        """获取当前调试器状态。"""
        ctx = get_context()

        status = ctx.session.get_status()
        # Show configured GDB path (from config file) even before GDB is started
        status["gdb_path"] = ctx.gdb_path
        if ctx.server_mgr:
            status["gdb_server"] = ctx.server_mgr.get_status()

        return str(_result_dict(True, "Status retrieved", **status))

    # =======================================================================
    # 5.2 执行控制工具 (Execution Control Tools)
    # =======================================================================

    @mcp.tool()
    async def continue_execution() -> str:
        """继续执行目标程序。"""
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
        """中断目标程序执行 (发送 Ctrl+C)。"""
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
        """单步执行一条机器指令 (step into)。"""
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
        """单步执行一行源码 (step into, 进入函数)。"""
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
        """单步执行一条机器指令 (step over, 不进入函数)。"""
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
        """单步执行一行源码 (step over, 不进入函数)。"""
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
        """执行到当前函数返回。"""
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
        """执行到指定位置。"""
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
        """重新启动目标程序。"""
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

        发送 ``monitor reset halt`` (halt=True) 或 ``monitor reset`` (halt=False)。
        ``monitor reset halt`` 会将芯片复位并停在复位向量处，适合调试场景。
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
        """设置断点。"""
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
        """删除指定断点。"""
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
        """禁用指定断点。"""
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
        """启用指定断点。"""
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
        """列出所有断点。"""
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
        """设置捕获点 (catchpoint)。"""
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
        """求值并打印表达式。"""
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
        """检查内存 (GDB x 命令)。"""
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
        """设置自动显示表达式 (每次程序停止时自动显示)。"""
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
        """修改变量或寄存器的值。"""
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
        """读取指定地址的内存数据。"""
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
        """写入内存数据。"""
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
        count: Annotated[int | None, Field(description="显示的栈帧数量 (可选, 默认全部)")] = None,
        full: Annotated[bool, Field(description="是否同时显示局部变量")] = False,
    ) -> str:
        """显示调用栈。"""
        ctx = get_context()
        session = ctx.ensure_session()

        try:
            output = await session.send_mi_command("-stack-list-frames")
            if output.is_error:
                return str(_result_dict(False, f"Backtrace failed: {output.error_message}"))

            frames = output.result.results.get("stack", []) if output.result else []

            result_text = ""
            if frames:
                for frame_entry in frames:
                    frame = frame_entry.get("frame", frame_entry) if isinstance(frame_entry, dict) else frame_entry
                    level = frame.get("level", "?")
                    func = frame.get("func", "??")
                    file_ = frame.get("file", frame.get("fullname", "??"))
                    line = frame.get("line", "?")
                    addr = frame.get("addr", "??")
                    result_text += f"#{level} {func} at {file_}:{line} (addr={addr})\n"

            if full:
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
                frames=frames,
            ))
        except Exception as e:
            return str(_result_dict(False, f"Backtrace error: {e}"))

    @mcp.tool()
    async def select_frame(
        frame_num: Annotated[int, Field(description="栈帧编号 (0=当前, 1=调用者, ...)")],
    ) -> str:
        """选择当前栈帧。"""
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
        """显示当前栈帧信息。"""
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
        """显示当前栈帧的局部变量。"""
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
        """显示当前函数的参数。"""
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
        """列出所有线程信息。"""
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
        """选择当前线程。"""
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
        """反汇编当前或指定位置的代码。"""
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
        """列出源代码。"""
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
        """显示寄存器值。"""
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
        """显示类型信息。"""
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
        """执行任意 GDB 命令 (escape hatch)。"""
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
        """定义事件钩子命令。"""
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
        """一站式操作: 加载 ELF → 连接 → (可选)设断点 → 运行。"""
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
