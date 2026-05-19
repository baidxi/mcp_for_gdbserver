# MCP GDB Server

基于 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 的 GDB 远程调试服务器。

通过 SSE/HTTP 传输协议暴露 GDB 调试能力，支持标准 GNU gdbserver 和自定义 GDB Server（ST-LINK、OpenOCD、J-Link 等）。

## 特性

- 🎯 **完整 GDB 命令覆盖** — 28 个 MCP 工具 + 10 个 MCP 资源
- 🔌 **双模式 GDB Server** — 标准 gdbserver 和自定义 GDB Server（ST-LINK 等）
- 📡 **SSE/HTTP 传输** — 兼容所有 MCP 客户端（Claude Desktop、Cursor 等）
- 📂 **ELF 文件路径加载** — 通过文件系统绝对路径加载，无需 base64 编码
- ⚙️ **灵活配置** — CLI 参数 / JSON 配置文件 / 环境变量，优先级递减
- 🐛 **GDB MI3 协议** — 使用 Machine Interface 实现结构化通信

## 系统要求

- Python 3.10+
- GDB（如 `arm-none-eabi-gdb`）已安装
- gdbserver 或自定义 GDB Server（如 ST-LINK_gdbserver）

## 安装依赖

```bash
pip install mcp>=1.0.0 anyio>=4.0 httpx>=0.27 pydantic>=2.0 starlette uvicorn
```

## 快速开始

### 直接运行（无需安装）

```bash
# 标准 gdbserver 模式
python3 run.py \
  --gdb-path arm-none-eabi-gdb \
  --gdbserver-port 50000 \
  --gdbserver-multi

# ST-LINK 模式
python3 run.py \
  --gdb-path arm-none-eabi-gdb \
  --target localhost:50000 \
  --gdb-server-cmd "/path/to/ST-LINK_gdbserver -p 50000 -cp /path --swd"

# 或赋予执行权限后直接运行
chmod +x run.py
./run.py --config config.example.json
```

### 安装后运行（可选）

```bash
# 开发模式安装
pip install -e .

# 然后可以直接使用 mcp-gdbserver 命令
mcp-gdbserver \
  --gdb-path arm-none-eabi-gdb \
  --gdbserver-port 50000 \
  --gdbserver-multi
```

### 2. ST-LINK GDB Server 模式

```bash
# 使用配置文件启动
mcp-gdbserver --config config.example.stlink.json

# 或通过命令行指定
mcp-gdbserver \
  --gdb-path arm-none-eabi-gdb \
  --target localhost:50000 \
  --gdb-server-cmd "/path/to/ST-LINK_gdbserver -p 50000 -cp /path --swd --serial-number xxx --halt --apid 1"
```

### 3. MCP 客户端配置

在 Claude Desktop 或其他 MCP 客户端的配置文件中添加：

```json
{
  "mcpServers": {
    "gdb": {
      "url": "http://localhost:8765/sse"
    }
  }
}
```

## CLI 参数

```
usage: mcp-gdbserver [-h] [--gdb-path PATH] [--host HOST] [--port PORT]
                     [--target HOST:PORT] [--gdbserver-port PORT]
                     [--gdbserver-multi] [--gdbserver-once]
                     [--gdbserver-attach PID] [--gdb-server-cmd CMD]
                     [--config FILE] [--verbose]

选项:
  --gdb-path              GDB 可执行文件路径 (默认: arm-none-eabi-gdb)
  --host                  MCP SSE 服务器绑定地址 (默认: 0.0.0.0)
  --port, -p              MCP SSE 服务器端口 (默认: 8765)
  --target, -t            默认远程目标 (格式: host:port)

标准 GNU gdbserver 参数:
  --gdbserver-port        gdbserver 监听端口 (默认: 50000)
  --gdbserver-multi       启用 --multi 扩展远程模式
  --gdbserver-once        启用 --once 单次会话模式
  --gdbserver-attach PID  附加到指定进程

自定义 GDB Server 参数:
  --gdb-server-cmd, -g    GDB Server 完整命令行

通用参数:
  --config, -c            JSON 配置文件路径
  --verbose, -v           启用 DEBUG 级别日志
```

## 环境变量

所有配置项均可通过 `MCP_GDB_` 前缀的环境变量设置：

| 环境变量 | 对应配置项 |
|---|---|
| `MCP_GDB_GDB_PATH` | `gdb_path` |
| `MCP_GDB_HOST` | `host` |
| `MCP_GDB_PORT` | `port` |
| `MCP_GDB_TARGET` | `default_target` |
| `MCP_GDB_TIMEOUT` | `timeout_seconds` |
| `MCP_GDB_LOG_LEVEL` | `log_level` |
| `MCP_GDB_GDBSERVER_PORT` | `gdbserver.port` |
| `MCP_GDB_GDBSERVER_MULTI` | `gdbserver.multi` |
| `MCP_GDB_GDBSERVER_ONCE` | `gdbserver.once` |
| `MCP_GDB_GDBSERVER_MODE` | `gdbserver.mode` |
| `MCP_GDB_GDBSERVER_COMMAND` | `gdbserver.command` |

配置优先级：**CLI 参数 > 环境变量 > 配置文件 > 默认值**

## MCP 工具列表

### 生命周期工具

| 工具 | 说明 |
|---|---|
| `start_gdb_server` | 启动 GDB Server 进程（标准/自定义模式） |
| `stop_gdb_server` | 停止 GDB Server 进程 |
| `start_gdb` | 启动 GDB 进程（MI3 模式） |
| `connect_target` | 连接到远程目标 |
| `disconnect` | 断开远程目标连接 |
| `load_file` | 加载 ELF 可执行文件（通过绝对路径） |
| `quit` | 退出 GDB 会话 |
| `get_status` | 获取当前调试器状态 |

### 执行控制工具

| 工具 | 说明 |
|---|---|
| `continue_execution` | 继续执行程序 |
| `interrupt` | 中断正在运行的程序 |
| `stepi` | 汇编级单步进入 |
| `step` | 源码级单步进入 |
| `nexti` | 汇编级单步跳过 |
| `next` | 源码级单步跳过 |
| `finish` | 执行到当前函数返回 |
| `until` | 执行到指定位置 |
| `restart` | 重新启动程序 |

### 断点工具

| 工具 | 说明 |
|---|---|
| `break_insert` | 插入断点 |
| `break_delete` | 删除断点 |
| `break_disable` | 禁用断点 |
| `break_enable` | 启用断点 |
| `break_list` | 列出所有断点 |
| `catch` | 设置捕获点（异常/系统调用等） |

### 数据查看工具

| 工具 | 说明 |
|---|---|
| `print` | 计算并打印表达式 |
| `examine` | 检查内存内容 |
| `display` | 设置每次停止时自动显示的表达式 |
| `set_variable` | 修改变量值 |
| `memory_read` | 读取内存（十六进制） |
| `memory_write` | 写入内存 |

### 堆栈/线程工具

| 工具 | 说明 |
|---|---|
| `backtrace` | 显示调用栈 |
| `select_frame` | 选择栈帧 |
| `frame_info` | 显示当前栈帧信息 |
| `list_locals` | 列出局部变量 |
| `list_args` | 列出函数参数 |
| `thread_info` | 显示线程信息 |
| `thread_select` | 选择线程 |

### 反汇编/源码工具

| 工具 | 说明 |
|---|---|
| `disassemble` | 反汇编代码 |
| `list_source` | 显示源代码 |
| `info_registers` | 显示寄存器值 |
| `info_types` | 显示类型信息 |

### 高级工具

| 工具 | 说明 |
|---|---|
| `run_command` | 执行任意 GDB CLI 命令 |
| `define_hook` | 定义 GDB 钩子命令 |
| `flash_and_run` | 烧录固件并运行（嵌入式专用） |

## MCP 资源列表

| 资源 URI | 说明 |
|---|---|
| `gdb://status` | 当前调试器完整状态 |
| `gdb://registers` | 当前寄存器值 |
| `gdb://backtrace` | 当前调用栈 |
| `gdb://breakpoints` | 当前断点列表 |
| `gdb://threads` | 线程信息 |
| `gdb://memory/{address}/{size}` | 读取指定地址和大小的内存 |
| `gdb://locals` | 当前栈帧的局部变量 |
| `gdb://args` | 当前栈帧的函数参数 |
| `gdb://frame` | 当前栈帧详细信息 |
| `gdb://sections` | 可执行文件的段信息 |

## 典型调试流程

### MCP 客户端调用顺序

```
1. start_gdb_server()        → 启动 GDB Server（或已通过 CLI 自动启动）
2. start_gdb()               → 启动 GDB 进程
3. load_file("/path/firmware.elf")  → 加载 ELF 文件
4. connect_target("localhost:50000") → 连接到远程目标
5. break_insert("main")      → 在 main 设置断点
6. continue_execution()      → 继续执行
7. print("variable")         → 查看变量
8. backtrace()               → 查看调用栈
9. step() / next()           → 单步调试
```

### 嵌入式 ST-LINK 调试示例

```bash
# 1. 启动 MCP 服务器（ST-LINK 模式）
mcp-gdbserver \
  --gdb-path arm-none-eabi-gdb \
  --target localhost:50000 \
  -g "/opt/STMicroelectronics/ST-LINK_gdbserver -p 50000 -cp /opt/STM32Cube/STM32CubeProgrammer/bin --swd"

# 2. MCP 客户端中调用工具：
#    start_gdb_server()                    # 启动 ST-LINK GDB Server
#    start_gdb()                           # 启动 arm-none-eabi-gdb
#    load_file("/project/build/firmware.elf")
#    connect_target("localhost:50000")     # 连接到 ST-LINK
#    flash_and_run()                       # 烧录并运行
#    break_insert("main")
#    continue_execution()
```

## 项目结构

```
src/mcp_gdbserver/
├── __init__.py          # 包初始化
├── __main__.py          # python -m 入口
├── main.py              # CLI 主入口
├── config.py            # 配置管理（CLI/文件/环境变量）
├── mi_parser.py         # GDB MI 输出解析器
├── gdb_server_mgr.py    # GDB Server 进程管理器
├── session.py           # GDB 会话管理器（PTY + MI3）
├── tools.py             # 28 个 MCP 工具
├── resources.py         # 10 个 MCP 资源
└── server.py            # FastMCP 服务器配置与启动
```

## 配置文件示例

参见：
- [`config.example.json`](config.example.json) — 标准 gdbserver 模式
- [`config.example.stlink.json`](config.example.stlink.json) — ST-LINK 自定义模式

## 许可证

MIT
