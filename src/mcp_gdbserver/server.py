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
            "# MCP GDB Server — AI 使用指南\n"
            "\n"
            "## 概述\n"
            "这是基于 Model Context Protocol (MCP) 的 GDB 远程调试服务器，支持标准 GNU gdbserver\n"
            "和自定义 GDB Server（ST-LINK、OpenOCD、J-Link 等）。提供了 28 个 MCP 工具和 10 个\n"
            "MCP 资源，覆盖完整的 GDB 调试能力。\n"
            "\n"
            "## 典型工作流\n"
            "\n"
            "### 场景 A: 嵌入式远程调试（最常用）\n"
            "按以下顺序依次调用工具:\n"
            "1. start_gdb_server — 启动 GDB Server（标准 gdbserver 或 ST-LINK 等自定义）\n"
            "2. start_gdb — 启动 GDB 进程（MI3 模式）；这是所有调试操作的第一步\n"
            "3. load_file — 加载 ELF 可执行文件（需要文件服务器本地绝对路径）\n"
            "4. connect_target — 连接到已启动的 GDB Server\n"
            "5. break_insert — 设置断点（如 main 函数）\n"
            "6. continue_execution — 运行程序到断点处停下\n"
            "7. 执行调试操作：step/next 单步执行，print 查看变量，backtrace 查看调用栈等\n"
            "8. quit — 结束调试\n"
            "\n"
            "### 场景 B: 一站式快捷方式\n"
            "flash_and_run — 调用一次即可完成：启动 GDB → 加载 ELF → 连接目标 → 设断点 → 运行\n"
            "\n"
            "### 场景 C: 本地进程调试\n"
            "1. start_gdb — 启动 GDB\n"
            "2. load_file — 加载可执行文件\n"
            "3. attach — 附加到正在运行的进程（需提供 PID）\n"
            "4. 执行调试操作...\n"
            "\n"
            "### 场景 D: 本地运行（无需 GDB Server）\n"
            "1. start_gdb — 启动 GDB\n"
            "2. load_file — 加载可执行文件\n"
            "3. break_insert — 设置断点\n"
            "4. run_command(command='run') — 本地运行\n"
            "5. 执行调试操作...\n"
            "\n"
            "## 工具分类速查\n"
            "\n"
            "### 生命周期（设置和清理）\n"
            "- start_gdb_server / stop_gdb_server — 启动/停止 GDB 远程协议服务器\n"
            "- start_gdb — 启动 GDB 进程（必须先调用）\n"
            "- connect_target / disconnect — 连接/断开 GDB Server\n"
            "- attach — 附加到正在运行的进程\n"
            "- load_file — 加载 ELF 可执行文件\n"
            "- quit — 关闭 GDB 进程\n"
            "- get_status — 获取当前调试器状态\n"
            "- switch_session / list_sessions — 多会话管理\n"
            "\n"
            "### 执行控制\n"
            "- continue_execution — 继续执行\n"
            "- interrupt — 中断执行（Ctrl+C）\n"
            "- step / next — 单步执行源码行（step 会进入函数，next 跳过函数）\n"
            "- stepi / nexti — 单步执行机器指令\n"
            "- finish — 执行到当前函数返回\n"
            "- until — 执行到指定位置\n"
            "- restart — 重新启动目标程序\n"
            "- reset_target — 复位嵌入式目标芯片\n"
            "\n"
            "### 断点\n"
            "- break_insert — 设置断点\n"
            "- break_delete — 删除断点\n"
            "- break_disable / break_enable — 禁用/启用断点\n"
            "- break_list — 列出所有断点\n"
            "- catch — 设置捕获点\n"
            "\n"
            "### 数据查看\n"
            "- print — 求值并打印表达式\n"
            "- examine — 检查内存（GDB x 命令）\n"
            "- display — 设置自动显示表达式\n"
            "- set_variable — 修改变量或寄存器值\n"
            "- memory_read / memory_write — 读写内存\n"
            "\n"
            "### 堆栈/线程\n"
            "- backtrace — 显示调用栈\n"
            "- select_frame — 选择栈帧\n"
            "- frame_info — 显示当前帧信息\n"
            "- list_locals — 显示局部变量\n"
            "- list_args — 显示函数参数\n"
            "- thread_info — 列出所有线程\n"
            "- thread_select — 选择线程\n"
            "\n"
            "### 反汇编/源码\n"
            "- disassemble — 反汇编代码\n"
            "- list_source — 列出源码\n"
            "- info_registers — 显示寄存器值\n"
            "- info_types — 显示类型信息\n"
            "\n"
            "### 通用\n"
            "- run_command — 执行任意 GDB 命令（兜底方案）\n"
            "- define_hook — 定义事件钩子\n"
            "- flash_and_run — 一站式加载→连接→运行\n"
            "\n"
            "## MCP 资源（只读数据查询）\n"
            "- gdb://status — 当前调试器状态\n"
            "- gdb://registers — 寄存器值\n"
            "- gdb://backtrace — 调用栈\n"
            "- gdb://breakpoints — 断点列表\n"
            "- gdb://threads — 线程列表\n"
            "- gdb://memory/{address}/{size} — 内存数据\n"
            "- gdb://locals — 局部变量\n"
            "- gdb://args — 函数参数\n"
            "- gdb://frame — 当前帧信息\n"
            "- gdb://sections — 目标节区信息\n"
            "- gdb://guide — 详细使用指南\n"
            "\n"
            "## 重要注意事项\n"
            "1. start_gdb 是所有调试操作的前置条件——必须先启动 GDB\n"
            "2. 远程调试需要先 start_gdb_server，再 connect_target\n"
            "3. 地址格式使用 0x 前缀（如 0x20000000）\n"
            "4. 断点位置格式：\"main\"、\"file.c:42\"、\"*0x08000100\"\n"
            "5. 如果遇到不支持的调试场景，可使用 run_command 执行任意 GDB 命令兜底\n"
            "6. 使用 reset_target 复位嵌入式芯片（halt=True 停在复位向量）\n"
            "7. 使用 interrupt 中断正在运行的程序\n"
            "8. 多会话场景使用 switch_session/list_sessions 管理多个独立调试会话\n"
            "9. 详情可查询 gdb://guide 资源获取完整参考文档\n"
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
