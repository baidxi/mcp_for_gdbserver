"""GDB Server process manager.

Manages the lifecycle of a GDB remote protocol server process.
Supports both standard GNU gdbserver and custom servers
(ST-LINK GDB Server, OpenOCD, JLinkGDBServer, etc.).
"""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
import signal
import subprocess
from typing import Optional

from .config import GdbServerConfig, resolve_gdbserver_command

logger = logging.getLogger(__name__)


class GdbServerError(Exception):
    """Error raised by GdbServerManager."""
    pass


class GdbServerManager:
    """Manages a GDB remote protocol server process.

    This manager is responsible for:
    - Starting the GDB server process (standard or custom)
    - Monitoring the process for unexpected exits
    - Stopping the process gracefully (SIGTERM → SIGKILL)
    - Reporting process status
    """

    def __init__(
        self,
        config: GdbServerConfig,
        gdbserver_path: str = "gdbserver",
        cwd: str | None = None,
    ) -> None:
        self._config = config
        self._gdbserver_path = gdbserver_path
        self._cwd = cwd
        self._process: Optional[subprocess.Popen] = None
        self._command: list[str] = []
        self._running = False

    @property
    def is_running(self) -> bool:
        """Whether the GDB server process is currently running."""
        if self._process is None:
            return False
        return self._process.poll() is None

    @property
    def pid(self) -> Optional[int]:
        """PID of the GDB server process, or None if not running."""
        if self._process is not None:
            return self._process.pid
        return None

    @property
    def command(self) -> list[str]:
        """The command that was used to start the server."""
        return self._command

    @property
    def port(self) -> int:
        """The port the server is configured to listen on."""
        return self._config.port

    @property
    def exit_code(self) -> Optional[int]:
        """Exit code of the process, or None if still running/not started."""
        if self._process is None:
            return None
        return self._process.poll()

    def start(self) -> None:
        """Start the GDB server process.

        Raises GdbServerError if the process fails to start.
        """
        if self.is_running:
            raise GdbServerError("GDB server is already running (PID={})".format(self.pid))

        self._command = resolve_gdbserver_command(self._config, self._gdbserver_path)
        cmd_str = " ".join(shlex.quote(a) for a in self._command)
        logger.info("Starting GDB server: %s", cmd_str)

        try:
            # Use subprocess.PIPE for stdin so the process gets a valid fd
            # (some servers like ST-LINK GDB Server need stdin to be available).
            # Do NOT use preexec_fn=os.setsid as some GDB servers (ST-LINK)
            # may need process group membership for proper signal handling.
            self._process = subprocess.Popen(
                self._command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self._cwd,
            )
            self._running = True
            logger.info("GDB server started (PID=%d)", self._process.pid)
        except FileNotFoundError:
            raise GdbServerError(f"GDB server executable not found: {self._command[0]}")
        except OSError as e:
            raise GdbServerError(f"Failed to start GDB server: {e}")

    async def start_and_wait_ready(self, timeout: float = 10.0) -> None:
        """Start the GDB server and wait until it appears ready.

        Reads stderr/stdout for a short period to detect startup messages.
        For custom servers like ST-LINK, this checks for the listening message.

        Args:
            timeout: Maximum time to wait for the server to stay alive (seconds).

        Raises:
            GdbServerError: If the server exits before timeout, with
            captured stdout/stderr and exit code in the error message.
        """
        self.start()

        # Give the server a moment to start
        await asyncio.sleep(0.5)

        if not self.is_running:
            # Process already exited — collect all output for diagnostics
            stdout, stderr = self._read_all_output()
            exit_code = self.exit_code
            logger.error(
                "GDB server exited immediately (exit_code=%s).\n"
                "  Command: %s\n"
                "  stdout: %s\n"
                "  stderr: %s",
                exit_code,
                " ".join(shlex.quote(a) for a in self._command),
                stdout.strip() or "(empty)",
                stderr.strip() or "(empty)",
            )
            raise GdbServerError(
                f"GDB server exited immediately (exit_code={exit_code}). "
                f"stdout: {stdout.strip() or '(empty)'} | "
                f"stderr: {stderr.strip() or '(empty)'}"
            )

        # Read initial output for a short time to detect readiness
        elapsed = 0.0
        interval = 0.2
        while elapsed < timeout:
            if not self.is_running:
                stdout, stderr = self._read_all_output()
                exit_code = self.exit_code
                logger.error(
                    "GDB server exited during startup (exit_code=%s).\n"
                    "  Command: %s\n"
                    "  stdout: %s\n"
                    "  stderr: %s",
                    exit_code,
                    " ".join(shlex.quote(a) for a in self._command),
                    stdout.strip() or "(empty)",
                    stderr.strip() or "(empty)",
                )
                raise GdbServerError(
                    f"GDB server exited during startup (exit_code={exit_code}). "
                    f"stdout: {stdout.strip() or '(empty)'} | "
                    f"stderr: {stderr.strip() or '(empty)'}"
                )

            # Read available output for diagnostics
            out, err = self.read_output()
            if out:
                logger.debug("GDB server stdout: %s", out.strip()[:500])
            if err:
                logger.debug("GDB server stderr: %s", err.strip()[:500])
                # Check for common readiness indicators
                if "listening" in err.lower() or "waiting" in err.lower() or "accepting" in err.lower():
                    logger.info("GDB server ready (detected listening message)")
                    return

            await asyncio.sleep(interval)
            elapsed += interval

        logger.info("GDB server ready on port %d", self._config.port)

    def _read_all_output(self) -> tuple[str, str]:
        """Read ALL available stdout and stderr from the process (blocking read).

        Returns (stdout, stderr) as strings. This should only be called
        after the process has exited.
        """
        stdout = ""
        stderr = ""
        if self._process:
            try:
                if self._process.stdout:
                    stdout = self._process.stdout.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            try:
                if self._process.stderr:
                    stderr = self._process.stderr.read().decode("utf-8", errors="replace")
            except Exception:
                pass
        return stdout, stderr

    def stop(self) -> None:
        """Stop the GDB server process gracefully.

        Sends SIGTERM first, then SIGKILL after a timeout.
        Uses os.killpg to terminate the entire process group.
        """
        if self._process is None or not self.is_running:
            logger.debug("GDB server not running, nothing to stop")
            return

        pid = self._process.pid
        logger.info("Stopping GDB server (PID=%d)", pid)

        try:
            # Kill the entire process group
            pgid = os.getpgid(pid)
            os.killpg(pgid, signal.SIGTERM)
        except (ProcessLookupError, OSError):
            # If setsid wasn't used, the process may not have its own group
            try:
                os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, OSError):
                pass

        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning("GDB server did not exit after SIGTERM, sending SIGKILL")
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                logger.error("GDB server refused to die")

        self._running = False
        logger.info("GDB server stopped (PID=%d)", pid)

    def get_status(self) -> dict:
        """Get the current status of the GDB server process."""
        if self._process is None:
            return {"running": False, "pid": None, "command": None}

        exit_code = self._process.poll()
        return {
            "running": exit_code is None,
            "pid": self._process.pid,
            "exit_code": exit_code,
            "command": " ".join(shlex.quote(a) for a in self._command),
            "mode": self._config.mode,
            "port": self._config.port,
        }

    def read_output(self) -> tuple[str, str]:
        """Read available stdout and stderr from the GDB server process.

        Returns (stdout, stderr) as strings. Non-blocking.
        """
        stdout = ""
        stderr = ""

        if self._process and self._process.stdout:
            try:
                import selectors
                sel = selectors.DefaultSelector()
                sel.register(self._process.stdout, selectors.EVENT_READ)
                sel.register(self._process.stderr, selectors.EVENT_READ)
                for key, _ in sel.select(timeout=0):
                    data = key.fileobj.read1(4096) if hasattr(key.fileobj, 'read1') else b""
                    if data:
                        text = data.decode("utf-8", errors="replace")
                        if key.fileobj == self._process.stdout:
                            stdout = text
                        else:
                            stderr = text
                sel.close()
            except Exception:
                pass

        return stdout, stderr

    def __del__(self) -> None:
        """Ensure the process is cleaned up on garbage collection."""
        try:
            self.stop()
        except Exception:
            pass
