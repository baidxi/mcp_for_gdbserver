"""GDB session manager.

Manages a GDB subprocess running in MI3 mode, providing:
- GDB process lifecycle (start/stop)
- MI command sending with token-based request-response matching
- Async event notification (breakpoint hits, stops, etc.)
- State machine management
- Timeout handling
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import pty
import re
import select
import signal
import subprocess
from enum import Enum
from typing import Any, Callable, Optional

from .mi_parser import (
    MIOutput,
    MIRecordType,
    MIResult,
    MIResultClass,
    MIStreamParser,
    parse_mi_line,
)

logger = logging.getLogger(__name__)
cmd_logger = logging.getLogger("mcp_gdbserver.command")


def _brief_result(output: MIOutput) -> str:
    """Generate a brief human-readable summary of an MI command result.

    Used for command-echo logging so that every GDB command and its
    response are visible in the server terminal at INFO level.

    Args:
        output: Parsed MI output from a command execution.

    Returns:
        A string summary, truncated to ~500 characters for readability.
    """
    if output.is_error:
        return f"Error: {output.error_message}"
    if output.console_output:
        text = output.console_output.strip()
        # Trim to at most 500 characters to avoid flooding the terminal
        return text[:500] + ("..." if len(text) > 500 else "")
    if output.result and output.result.results:
        try:
            formatted = json.dumps(
                output.result.results, indent=2, ensure_ascii=False
            )
        except (TypeError, ValueError):
            formatted = str(output.result.results)
        return formatted[:500] + ("..." if len(formatted) > 500 else "")
    return "OK"


class GDBState(Enum):
    """GDB debug session state."""
    IDLE = "idle"              # GDB not started
    STARTED = "started"        # GDB started, not connected
    CONNECTED = "connected"    # Connected to target, target stopped
    RUNNING = "running"        # Target is running
    STOPPED = "stopped"        # Target is stopped (breakpoint, signal, etc.)
    EXITED = "exited"          # Target program exited
    ERROR = "error"            # Error state


class GDBSessionError(Exception):
    """Error raised by GDBSession."""
    pass


class GDBSession:
    """Manages a GDB subprocess in MI3 mode.

    Communication is done through a PTY (pseudo-terminal) to avoid
    pipe buffering issues and to support interactive features like
    Ctrl+C interrupts.
    """

    def __init__(
        self,
        gdb_path: str = "arm-none-eabi-gdb",
        timeout: float = 30.0,
        init_commands: list[str] | None = None,
        on_event: Callable[[MIResult], None] | None = None,
    ) -> None:
        self._gdb_path = gdb_path
        self._timeout = timeout
        self._init_commands = init_commands or []
        self._on_event = on_event

        self._process: Optional[subprocess.Popen] = None
        self._master_fd: Optional[int] = None
        self._slave_fd: Optional[int] = None
        self._token_counter = 0
        self._state = GDBState.IDLE
        self._stream_parser = MIStreamParser()

        # Pending responses: token -> Future
        self._pending: dict[int, asyncio.Future] = {}
        # Pending stream records: token -> list[MIResult]
        # Accumulates CONSOLE/TARGET/LOG stream records for each pending command.
        # These are bundled into MIOutput when the RESULT record arrives.
        self._pending_streams: dict[int, list[MIResult]] = {}
        # Async event queue for out-of-band events
        self._event_queue: list[MIResult] = []

        # Reader task
        self._reader_task: Optional[asyncio.Task] = None
        self._running = False

        # Initial prompt synchronization
        self._prompt_detected = asyncio.Event()

        # Loaded file info
        self._loaded_file: Optional[str] = None
        self._target_address: Optional[str] = None

    @property
    def state(self) -> GDBState:
        """Current GDB session state."""
        return self._state

    @property
    def is_alive(self) -> bool:
        """Whether the GDB process is running."""
        if self._process is None:
            return False
        return self._process.poll() is None

    @property
    def loaded_file(self) -> Optional[str]:
        """Currently loaded ELF file path."""
        return self._loaded_file

    @property
    def target_address(self) -> Optional[str]:
        """Current target address (host:port)."""
        return self._target_address

    @property
    def pid(self) -> Optional[int]:
        """GDB process PID."""
        if self._process is not None:
            return self._process.pid
        return None

    def _next_token(self) -> int:
        """Generate the next command token."""
        self._token_counter += 1
        return self._token_counter

    async def start(self) -> None:
        """Start the GDB process in MI3 mode.

        Creates a PTY and launches GDB with --interpreter=mi3.
        Executes init commands after startup.
        """
        if self.is_alive:
            raise GDBSessionError("GDB is already running (PID={})".format(self.pid))

        logger.info("Starting GDB: %s --interpreter=mi3", self._gdb_path)

        # Create PTY
        self._master_fd, self._slave_fd = pty.openpty()

        try:
            self._process = subprocess.Popen(
                [self._gdb_path, "--interpreter=mi3"],
                stdin=self._slave_fd,
                stdout=self._slave_fd,
                stderr=self._slave_fd,
                preexec_fn=os.setsid,
                close_fds=False,
            )
        except FileNotFoundError:
            os.close(self._master_fd)
            os.close(self._slave_fd)
            self._master_fd = None
            self._slave_fd = None
            raise GDBSessionError(f"GDB executable not found: {self._gdb_path}")
        except OSError as e:
            os.close(self._master_fd)
            os.close(self._slave_fd)
            self._master_fd = None
            self._slave_fd = None
            raise GDBSessionError(f"Failed to start GDB: {e}")

        # Close slave in parent — only GDB process needs it
        os.close(self._slave_fd)
        self._slave_fd = None

        self._running = True
        self._state = GDBState.STARTED

        # Wait for initial prompt FIRST, before starting reader loop.
        # This avoids race conditions where _reader_loop consumes the prompt
        # before _wait_for_prompt can detect it.
        try:
            await asyncio.wait_for(self._wait_for_prompt(), timeout=10.0)
        except asyncio.TimeoutError:
            self._cleanup()
            raise GDBSessionError("Timeout waiting for GDB initial prompt")

        # Prompt found — now start the async reader task for normal operations
        self._reader_task = asyncio.create_task(self._reader_loop())

        # Execute init commands
        for cmd in self._init_commands:
            logger.debug("Init command: %s", cmd)
            await self.send_cli_command(cmd)

        logger.info("GDB started (PID=%d)", self._process.pid)

    async def _wait_for_prompt(self) -> None:
        """Wait for the initial GDB prompt.

        Reads PTY directly (before _reader_loop starts) to avoid
        race conditions with the async reader task.
        """
        buffer = ""
        while self._running:
            data = self._read_available()
            if data:
                buffer += data
                # Process complete lines
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    record = parse_mi_line(line)
                    if record and record.record_type == MIRecordType.PROMPT:
                        logger.info("GDB initial prompt detected")
                        self._prompt_detected.set()
                        return
                    # Log initial output for diagnostics
                    if record and record.record_type == MIRecordType.CONSOLE_STREAM:
                        logger.debug("GDB startup: %s", (record.stream_text or "").strip())
            await asyncio.sleep(0.02)

    async def _reader_loop(self) -> None:
        """Background task that reads from the PTY and dispatches responses."""
        buffer = ""
        while self._running:
            data = self._read_available()
            if data:
                buffer += data
                # Process complete lines
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    await self._process_line(line)

            await asyncio.sleep(0.01)

    def _read_available(self) -> str:
        """Read available data from the PTY master fd (non-blocking)."""
        if self._master_fd is None:
            return ""
        try:
            if select.select([self._master_fd], [], [], 0.0)[0]:
                data = os.read(self._master_fd, 4096)
                return data.decode("utf-8", errors="replace")
        except (OSError, ValueError):
            pass
        return ""

    async def _process_line(self, line: str) -> None:
        """Process a single line of GDB MI output."""
        record = parse_mi_line(line)
        if record is None:
            return

        if record.record_type == MIRecordType.PROMPT:
            # Prompt marks end of a response — no action needed
            # The RESULT record has already resolved the pending future
            pass

        elif record.record_type == MIRecordType.RESULT and record.token is not None:
            # Token-matched result — resolve the pending future,
            # bundling any accumulated stream records.
            future = self._pending.pop(record.token, None)
            if future and not future.done():
                # Collect accumulated stream records for this token
                streams = self._pending_streams.pop(record.token, [])
                output = MIOutput(result=record, streams=streams)
                future.set_result(output)
            else:
                # Clean up orphaned streams
                self._pending_streams.pop(record.token, None)
                logger.warning("Received result for unknown token %d", record.token)

        elif record.record_type in (
            MIRecordType.EXEC_ASYNC,
            MIRecordType.NOTIFY_ASYNC,
            MIRecordType.STATUS_ASYNC,
        ):
            # Async event — update state and notify
            await self._handle_async_event(record)

        elif record.record_type in (
            MIRecordType.CONSOLE_STREAM,
            MIRecordType.TARGET_STREAM,
            MIRecordType.LOG_STREAM,
        ):
            # Stream output — accumulate for the current pending command.
            # Since MI3 processes commands sequentially, stream records
            # between send and result belong to the most recently sent command.
            if record.token is not None and record.token in self._pending:
                # Stream has explicit token matching a pending command
                self._pending_streams.setdefault(record.token, []).append(record)
            elif self._pending:
                # No token on stream — associate with the latest pending command
                latest_token = max(self._pending.keys())
                self._pending_streams.setdefault(latest_token, []).append(record)
            else:
                # No pending commands — just log it
                text = (record.stream_text or "").strip()
                if text:
                    logger.debug("Orphaned stream: %s", text[:200])

    async def _handle_async_event(self, record: MIResult) -> None:
        """Handle an async event from GDB."""
        if record.record_type == MIRecordType.EXEC_ASYNC:
            if record.async_class == "stopped":
                reason = record.results.get("reason", "unknown")
                logger.info("Target stopped: %s", reason)
                self._state = GDBState.STOPPED
            elif record.async_class == "running":
                logger.info("Target running")
                self._state = GDBState.RUNNING

        # Notify event callback
        if self._on_event:
            try:
                self._on_event(record)
            except Exception:
                logger.exception("Error in event callback")

        self._event_queue.append(record)

    async def send_mi_command(
        self,
        command: str,
        timeout: float | None = None,
        log_command: bool = True,
    ) -> MIOutput:
        """Send a GDB MI command and wait for the response.

        The command is prefixed with a unique token for response matching.

        Args:
            command: MI command (e.g. "-break-insert main")
            timeout: Response timeout in seconds (uses default if None)
            log_command: When True (default), echoes the command and result
                to the ``mcp_gdbserver.command`` logger at INFO level.

        Returns:
            MIOutput containing the parsed response, including any
            console/target/log stream output accumulated before the result.

        Raises:
            GDBSessionError: If GDB is not running or times out.
        """
        if not self.is_alive:
            raise GDBSessionError("GDB is not running")

        token = self._next_token()
        timeout = timeout or self._timeout

        # Create future for this command's response
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self._pending[token] = future

        # Send command with token prefix
        full_command = f"{token}{command}\n"
        logger.debug("Sending MI: %s", full_command.strip())

        if log_command:
            cmd_logger.info("→ GDB: %s", command)

        self._write(full_command)

        try:
            # Wait for response with timeout
            result = await self._wait_for_future(future, timeout)
            if log_command:
                cmd_logger.info("←      %s", _brief_result(result))
            return result
        except asyncio.TimeoutError:
            self._pending.pop(token, None)
            self._pending_streams.pop(token, None)
            if log_command:
                cmd_logger.info("←      Timeout")
            raise GDBSessionError(
                f"Timeout ({timeout}s) waiting for response to: {command}"
            )

    async def _wait_for_future(self, future: asyncio.Future, timeout: float) -> MIOutput:
        """Wait for a future to complete, pumping the reader loop."""
        deadline = asyncio.get_event_loop().time() + timeout
        while not future.done():
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError()
            try:
                await asyncio.wait_for(asyncio.shield(future), timeout=min(remaining, 0.1))
                break
            except asyncio.TimeoutError:
                if future.done():
                    break
                continue
        return future.result()

    async def send_cli_command(
        self,
        command: str,
        timeout: float | None = None,
    ) -> MIOutput:
        """Send a GDB CLI command via the MI interface.

        Uses the -interpreter-exec console "command" MI command.

        Args:
            command: CLI command (e.g. "info registers")
            timeout: Response timeout in seconds

        Returns:
            MIOutput containing the parsed response, with console_output
            populated from the accumulated stream records.
        """
        # Log the original CLI command before wrapping it in MI
        cmd_logger.info("→ GDB: %s", command)

        # Escape quotes in the command
        escaped = command.replace("\\", "\\\\").replace('"', '\\"')
        return await self.send_mi_command(
            f'-interpreter-exec console "{escaped}"',
            timeout=timeout,
            log_command=False,
        )

    async def send_raw_command(
        self,
        command: str,
        timeout: float | None = None,
    ) -> str:
        """Send a raw CLI command and return the console output as text.

        This is a convenience method for commands where the text output
        is more useful than the structured MI result.

        Returns the concatenated console stream output.
        """
        output = await self.send_cli_command(command, timeout=timeout)
        return output.console_output

    def _write(self, data: str) -> None:
        """Write data to the PTY master fd."""
        if self._master_fd is None:
            raise GDBSessionError("PTY not available")
        try:
            os.write(self._master_fd, data.encode("utf-8"))
        except OSError as e:
            raise GDBSessionError(f"Failed to write to GDB: {e}")

    async def interrupt(self) -> None:
        """Send Ctrl+C (SIGINT) to the GDB process to interrupt the target."""
        if not self.is_alive:
            raise GDBSessionError("GDB is not running")
        cmd_logger.info("→ GDB: <SIGINT>")
        logger.info("Sending interrupt (Ctrl+C) to GDB (PID=%d)", self.pid)
        try:
            os.kill(self._process.pid, signal.SIGINT)
        except ProcessLookupError:
            raise GDBSessionError("GDB process not found")

    async def quit(self) -> None:
        """Quit GDB gracefully."""
        if not self.is_alive:
            return

        try:
            self._write("999999-gdb-exit\n")
            await asyncio.sleep(0.5)
        except Exception:
            pass

        self._cleanup()

    def _cleanup(self) -> None:
        """Clean up resources."""
        self._running = False

        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()

        if self._process and self.is_alive:
            try:
                pgid = os.getpgid(self._process.pid)
                os.killpg(pgid, signal.SIGTERM)
            except (ProcessLookupError, OSError):
                pass
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    pgid = os.getpgid(self._process.pid)
                    os.killpg(pgid, signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass

        if self._master_fd is not None:
            try:
                os.close(self._master_fd)
            except OSError:
                pass
            self._master_fd = None

        self._process = None
        self._state = GDBState.IDLE
        self._loaded_file = None
        self._target_address = None
        self._pending.clear()
        self._pending_streams.clear()
        self._event_queue.clear()

    def get_status(self) -> dict[str, Any]:
        """Get the current session status."""
        return {
            "state": self._state.value,
            "gdb_pid": self.pid,
            "gdb_path": self._gdb_path,
            "loaded_file": self._loaded_file,
            "target_address": self._target_address,
            "alive": self.is_alive,
        }

    def __del__(self) -> None:
        """Cleanup on garbage collection."""
        try:
            self._cleanup()
        except Exception:
            pass
