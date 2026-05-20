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

    @mcp.resource("gdb://guide")
    async def gdb_guide() -> str:
        """📖 MCP GDB Server 完整使用指南 — AI 可查询的详细参考文档。

        内容包含: 工具分类说明、工作流指引、常见场景示例、故障排查指南。
        AI 助手可在需要时查询此资源获取全面的使用说明。
        """
        guide = """
# MCP GDB Server — 完整使用指南

## 概述

本服务器提供基于 MCP 协议的 GDB 远程调试能力，支持 28 个工具和 11 个资源，
覆盖嵌入式调试和本地进程调试的全流程。

## 工具分类

### 1️⃣ 生命周期（Lifecycle）
负责调试环境的搭建和清理。

| 工具 | 功能 | 前置条件 |
|------|------|---------|
| start_gdb_server | 启动 GDB Server | 无 |
| stop_gdb_server | 停止 GDB Server | GDB Server 已启动 |
| start_gdb | 启动 GDB 进程 | 无（第 1 步） |
| connect_target | 连接远程目标 | GDB + GDB Server 已启动 |
| disconnect | 断开远程连接 | 已连接 |
| attach | 附加到进程 | GDB 已启动 |
| load_file | 加载 ELF 文件 | GDB 已启动 |
| quit | 退出 GDB 会话 | GDB 运行中 |
| get_status | 查看调试状态 | 无 |
| switch_session | 切换调试会话 | 目标 session 存在 |
| list_sessions | 列出所有会话 | 无 |

### 2️⃣ 执行控制（Execution Control）
控制目标程序的执行流程。

| 工具 | 功能 | 类似 GDB 命令 |
|------|------|---------------|
| continue_execution | 继续执行 | continue/c |
| interrupt | 中断执行 | Ctrl+C |
| step | 单步至下一行（进入函数） | step/s |
| next | 单步至下一行（跳过函数） | next/n |
| stepi | 单步一条指令（进入函数） | stepi/si |
| nexti | 单步一条指令（跳过函数） | nexti/ni |
| finish | 执行到函数返回 | finish/fin |
| until | 执行到指定位置 | until/u |
| restart | 重启程序 | run |
| reset_target | 复位芯片 | monitor reset |

### 3️⃣ 断点（Breakpoint）

| 工具 | 功能 | 参数说明 |
|------|------|---------|
| break_insert | 设置断点 | location, condition, temporary |
| break_delete | 删除断点 | breakpoint_ids (list) |
| break_disable | 禁用断点 | breakpoint_ids (list) |
| break_enable | 启用断点 | breakpoint_ids (list) |
| break_list | 列出所有断点 | 无 |
| catch | 设置捕获点 | event_type |

支持的位置格式:
- 按函数名: "main", "HAL_GPIO_Toggle"
- 按文件和行: "main.c:42", "src/app.c:100"
- 按地址: "*0x08000100"（注意 * 前缀）

### 4️⃣ 数据查看（Data Inspection）

| 工具 | 功能 | 使用场景 |
|------|------|---------|
| print | 求值表达式 | 查看变量、计算表达式 |
| examine | 检查内存 (x 命令) | 灵活的内存查看 |
| display | 自动显示表达式 | 每次停止时自动显示 |
| set_variable | 修改变量/寄存器 | 调试时修改值 |
| memory_read | 读取内存（结构化） | 获取原始字节 |
| memory_write | 写入内存 | 修改内存数据 |

### 5️⃣ 堆栈/线程（Stack/Thread）

| 工具 | 功能 |
|------|------|
| backtrace | 显示调用栈 |
| select_frame | 选择栈帧 |
| frame_info | 当前帧信息 |
| list_locals | 局部变量 |
| list_args | 函数参数 |
| thread_info | 列出线程 |
| thread_select | 选择线程 |

### 6️⃣ 反汇编/源码（Disassembly/Source）

| 工具 | 功能 |
|------|------|
| disassemble | 反汇编代码 |
| list_source | 列出源码 |
| info_registers | 显示寄存器 |
| info_types | 显示类型信息 |

### 7️⃣ 通用（General）

| 工具 | 功能 |
|------|------|
| run_command | 执行任意 GDB 命令（兜底） |
| define_hook | 定义事件钩子 |
| flash_and_run | 一站式加载→连接→运行 |

## MCP 资源

| 资源 URI | 功能 |
|----------|------|
| gdb://status | 调试器状态 |
| gdb://registers | 寄存器值 |
| gdb://backtrace | 调用栈 |
| gdb://breakpoints | 断点列表 |
| gdb://threads | 线程列表 |
| gdb://memory/{address}/{size} | 内存数据 |
| gdb://locals | 局部变量 |
| gdb://args | 函数参数 |
| gdb://frame | 当前帧信息 |
| gdb://sections | 目标节区信息 |
| gdb://guide | 本使用指南 |

## 工作流速查

### 嵌入式远程调试
```
1. start_gdb_server(port=50000, multi=True)
2. start_gdb()
3. load_file(file_path="/path/to/firmware.elf")
4. connect_target(host="localhost", port=50000)
5. break_insert(location="main")
6. continue_execution()  → 程序运行到 main 停下
7. 调试: step/next/print/backtrace...
8. quit()
9. stop_gdb_server()
```

### 本地进程调试
```
1. start_gdb()
2. load_file(file_path="/path/to/program")
3. break_insert(location="main")
4. run_command(command="run")
5. 调试: step/next/print...
6. quit()
```

### 快速闪存启动
```
1. start_gdb_server(port=50000, multi=True)
2. flash_and_run(file_path="/path/to/firmware.elf", stop_at="main")
```

## 常见问题

Q: GDB 无法启动？
A: 检查 gdb_path 是否正确，确保 GDB 可执行文件已安装。

Q: 连接超时？
A: 确认 GDB Server 已启动且端口正确（默认 50000）。
   检查网络连接和目标板状态。

Q: 断点设置失败？
A: 确保程序已加载（load_file），可能需要在运行后设置。
   对于已优化的代码，部分函数/行可能无法设置断点。

Q: 无法读取内存/寄存器？
A: 确认程序处于停止状态（停在断点或单步后）。
   程序运行时无法读取。

Q: 中文路径问题？
A: 确保 ELF 文件路径使用正确的编码，推荐使用不含中文的路径。
"""
        return guide.strip()
