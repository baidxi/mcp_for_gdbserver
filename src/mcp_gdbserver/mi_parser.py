"""GDB Machine Interface (MI) output parser.

Parses the output from GDB when running with --interpreter=mi3.

MI output consists of several types of records:
- Result records: ^done, ^running, ^error, ^exit (with optional result data)
- Async records: *stopped, *running, =notification (out-of-band events)
- Stream records: ~"console", @"target", &"log" (text output)
- Prompt: (gdb)

Each record may be prefixed with a token (integer) for request-response matching.

Example MI output:
    1^done,bkpt={number="1",type="breakpoint",addr="0x08000100",file="main.c",line="42"}
    *stopped,reason="breakpoint-hit",bkptno="1",frame={addr="0x08000100",func="main",args=[]}
    ~"Breakpoint 1 at 0x800100: file main.c, line 42.\\n"
    (gdb)
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class MIRecordType(Enum):
    """Type of MI output record."""
    RESULT = "result"           # ^done, ^running, ^error, ^exit
    EXEC_ASYNC = "exec_async"   # *stopped, *running
    NOTIFY_ASYNC = "notify"     # =breakpoint-modified, =thread-created, etc.
    STATUS_ASYNC = "status"     # +download, etc.
    CONSOLE_STREAM = "console"  # ~"text"
    TARGET_STREAM = "target"    # @"text"
    LOG_STREAM = "log"          # &"text"
    PROMPT = "prompt"           # (gdb)


class MIResultClass(Enum):
    """MI result class (the part after ^)."""
    DONE = "done"
    RUNNING = "running"
    ERROR = "error"
    EXIT = "exit"
    CONNECTED = "connected"


@dataclass
class MIResult:
    """Parsed MI output record."""
    record_type: MIRecordType
    token: Optional[int] = None
    result_class: Optional[MIResultClass] = None
    async_class: Optional[str] = None       # e.g. "stopped", "running"
    results: dict[str, Any] = field(default_factory=dict)
    stream_text: Optional[str] = None       # For stream records
    raw: str = ""                           # Original raw line


@dataclass
class MIOutput:
    """Aggregated output from a GDB MI command response.

    Collects all records until the prompt is received.
    """
    result: Optional[MIResult] = None       # The primary result record (^done, ^error, etc.)
    streams: list[MIResult] = field(default_factory=list)  # Stream output
    async_records: list[MIResult] = field(default_factory=list)  # Async notifications
    raw_lines: list[str] = field(default_factory=list)

    @property
    def console_output(self) -> str:
        """Concatenated console stream text."""
        return "".join(
            r.stream_text for r in self.streams
            if r.record_type == MIRecordType.CONSOLE_STREAM and r.stream_text
        )

    @property
    def target_output(self) -> str:
        """Concatenated target stream text."""
        return "".join(
            r.stream_text for r in self.streams
            if r.record_type == MIRecordType.TARGET_STREAM and r.stream_text
        )

    @property
    def log_output(self) -> str:
        """Concatenated log stream text."""
        return "".join(
            r.stream_text for r in self.streams
            if r.record_type == MIRecordType.LOG_STREAM and r.stream_text
        )

    @property
    def error_message(self) -> Optional[str]:
        """Error message if the result was an error."""
        if self.result and self.result.result_class == MIResultClass.ERROR:
            msg = self.result.results.get("msg", "")
            return _unescape_string(msg)
        return None

    @property
    def is_error(self) -> bool:
        """Whether the command resulted in an error."""
        return self.result is not None and self.result.result_class == MIResultClass.ERROR

    @property
    def is_done(self) -> bool:
        """Whether the command completed successfully."""
        return self.result is not None and self.result.result_class == MIResultClass.DONE


# ---------------------------------------------------------------------------
# MI Tuple / List parsing
# ---------------------------------------------------------------------------

def _unescape_string(s: str) -> str:
    """Unescape a GDB MI quoted string (remove surrounding quotes and escapes)."""
    if not s:
        return s
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    # Handle common escape sequences
    s = s.replace("\\n", "\n")
    s = s.replace("\\t", "\t")
    s = s.replace("\\\\", "\\")
    s = s.replace('\\"', '"')
    return s


def _parse_value(s: str) -> Any:
    """Parse a MI value: string, tuple, or list."""
    s = s.strip()
    if not s:
        return None

    if s.startswith('"'):
        return _parse_c_string(s)
    elif s.startswith("{"):
        result, _ = _parse_tuple(s, 0)
        return result
    elif s.startswith("["):
        result, _ = _parse_list(s, 0)
        return result
    else:
        # Bare value (e.g. number or identifier)
        return s


def _parse_c_string(s: str) -> str:
    """Parse a C-style string, handling escape sequences."""
    if not s.startswith('"'):
        return s
    result = []
    i = 1  # skip opening quote
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            next_ch = s[i + 1]
            if next_ch == 'n':
                result.append('\n')
            elif next_ch == 't':
                result.append('\t')
            elif next_ch == '\\':
                result.append('\\')
            elif next_ch == '"':
                result.append('"')
            else:
                result.append(s[i])
                result.append(next_ch)
            i += 2
        elif s[i] == '"':
            break
        else:
            result.append(s[i])
            i += 1
    return "".join(result)


def _parse_tuple(s: str, start: int) -> tuple[dict[str, Any], int]:
    """Parse a MI tuple: {name=value,name=value,...}

    Returns (dict, end_position).
    """
    result: dict[str, Any] = {}
    i = start + 1  # skip '{'
    i = _skip_whitespace(s, i)

    while i < len(s) and s[i] != '}':
        # Parse name
        name, i = _parse_identifier(s, i)
        if not name:
            i += 1
            continue

        i = _skip_whitespace(s, i)

        # Expect '='
        if i < len(s) and s[i] == '=':
            i += 1
            i = _skip_whitespace(s, i)

            # Parse value
            value, i = _parse_value_with_end(s, i)
            result[name] = value
        else:
            # Bare name without = (some MI outputs do this)
            result[name] = True

        i = _skip_whitespace(s, i)

        # Skip comma
        if i < len(s) and s[i] == ',':
            i += 1
            i = _skip_whitespace(s, i)

    if i < len(s) and s[i] == '}':
        i += 1
    return result, i


def _parse_list(s: str, start: int) -> tuple[list[Any], int]:
    """Parse a MI list: [value,value,...] or [name=value,...]

    Returns (list, end_position).
    """
    result: list[Any] = []
    i = start + 1  # skip '['
    i = _skip_whitespace(s, i)

    while i < len(s) and s[i] != ']':
        if s[i] == '{':
            value, i = _parse_tuple(s, i)
            result.append(value)
        elif s[i] == '"':
            value = _parse_c_string_from(s, i)
            i = _skip_c_string(s, i)
            result.append(value)
        elif s[i] == '[':
            value, i = _parse_list(s, i)
            result.append(value)
        else:
            # Try to parse name=value
            name, new_i = _parse_identifier(s, i)
            if name and new_i < len(s) and s[new_i] == '=':
                i = new_i + 1
                i = _skip_whitespace(s, i)
                value, i = _parse_value_with_end(s, i)
                result.append({name: value})
            else:
                # Bare token
                token, i = _parse_identifier(s, i)
                if token:
                    result.append(token)
                else:
                    i += 1

        i = _skip_whitespace(s, i)
        if i < len(s) and s[i] == ',':
            i += 1
            i = _skip_whitespace(s, i)

    if i < len(s) and s[i] == ']':
        i += 1
    return result, i


def _parse_value_with_end(s: str, start: int) -> tuple[Any, int]:
    """Parse a value and return (value, end_position)."""
    i = _skip_whitespace(s, start)
    if i >= len(s):
        return None, i

    if s[i] == '"':
        value = _parse_c_string_from(s, i)
        end = _skip_c_string(s, i)
        return value, end
    elif s[i] == '{':
        return _parse_tuple(s, i)
    elif s[i] == '[':
        return _parse_list(s, i)
    else:
        # Bare value
        token, end = _parse_identifier(s, i)
        return token, end


def _parse_c_string_from(s: str, start: int) -> str:
    """Parse a C-style string starting at position start."""
    result = []
    i = start + 1  # skip opening quote
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            next_ch = s[i + 1]
            if next_ch == 'n':
                result.append('\n')
            elif next_ch == 't':
                result.append('\t')
            elif next_ch == '\\':
                result.append('\\')
            elif next_ch == '"':
                result.append('"')
            else:
                result.append(s[i])
                result.append(next_ch)
            i += 2
        elif s[i] == '"':
            break
        else:
            result.append(s[i])
            i += 1
    return "".join(result)


def _skip_c_string(s: str, start: int) -> int:
    """Skip past a C-style string starting at position start, return end position."""
    i = start + 1  # skip opening quote
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            i += 2
        elif s[i] == '"':
            return i + 1
        else:
            i += 1
    return i


def _parse_identifier(s: str, start: int) -> tuple[str, int]:
    """Parse an identifier (variable name) starting at position start."""
    i = start
    while i < len(s) and (s[i].isalnum() or s[i] in ('_', '-')):
        i += 1
    return s[start:i], i


def _skip_whitespace(s: str, i: int) -> int:
    """Skip whitespace characters."""
    while i < len(s) and s[i] in (' ', '\t'):
        i += 1
    return i


def _parse_mi_results(s: str) -> dict[str, Any]:
    """Parse MI result data: name=value,name=value,...

    This handles the comma-separated variable=value pairs that follow
    result records and async records.
    """
    result: dict[str, Any] = {}
    i = 0
    s = s.strip()

    while i < len(s):
        name, new_i = _parse_identifier(s, i)
        if not name:
            i = new_i + 1
            continue

        i = _skip_whitespace(s, new_i)

        if i < len(s) and s[i] == '=':
            i += 1
            i = _skip_whitespace(s, i)
            value, i = _parse_value_with_end(s, i)
            result[name] = value
        else:
            result[name] = True

        i = _skip_whitespace(s, i)
        if i < len(s) and s[i] == ',':
            i += 1
            i = _skip_whitespace(s, i)

    return result


# ---------------------------------------------------------------------------
# Line-level parsing
# ---------------------------------------------------------------------------

# Regex patterns for MI output lines
_TOKEN_RESULT_RE = re.compile(r'^(\d+)\^(done|running|error|exit|connected)(?:,(.*))?$')
_RESULT_RE = re.compile(r'^(done|running|error|exit|connected)(?:,(.*))?$')
_EXEC_ASYNC_RE = re.compile(r'^(\d+)?\*(stopped|running)(?:,(.*))?$')
_NOTIFY_ASYNC_RE = re.compile(r'^(\d+)?=(\w[\w-]*)(?:,(.*))?$')
_STATUS_ASYNC_RE = re.compile(r'^(\d+)?\+(\w+)(?:,(.*))?$')
_CONSOLE_STREAM_RE = re.compile(r'^(?:\d+)?~"(.*)"$')
_TARGET_STREAM_RE = re.compile(r'^(?:\d+)?@"(.*)"$')
_LOG_STREAM_RE = re.compile(r'^(?:\d+)?&"(.*)"$')
_PROMPT_RE = re.compile(r'^\(gdb\)\s*$')


def parse_mi_line(line: str) -> Optional[MIResult]:
    """Parse a single line of GDB MI output.

    Returns an MIResult if the line is recognized, or None for unknown lines.
    """
    line = line.rstrip('\n\r')
    if not line:
        return None

    raw = line

    # Prompt
    if _PROMPT_RE.match(line):
        return MIResult(record_type=MIRecordType.PROMPT, raw=raw)

    # Token + result record: N^done,...
    m = _TOKEN_RESULT_RE.match(line)
    if m:
        token = int(m.group(1))
        result_class = MIResultClass(m.group(2))
        results_str = m.group(3) or ""
        results = _parse_mi_results(results_str) if results_str else {}
        return MIResult(
            record_type=MIRecordType.RESULT,
            token=token,
            result_class=result_class,
            results=results,
            raw=raw,
        )

    # Result record without token: ^done,...
    m = _RESULT_RE.match(line)
    if m:
        result_class = MIResultClass(m.group(1))
        results_str = m.group(2) or ""
        results = _parse_mi_results(results_str) if results_str else {}
        return MIResult(
            record_type=MIRecordType.RESULT,
            result_class=result_class,
            results=results,
            raw=raw,
        )

    # Exec async: *stopped,...
    m = _EXEC_ASYNC_RE.match(line)
    if m:
        token = int(m.group(1)) if m.group(1) else None
        async_class = m.group(2)
        results_str = m.group(3) or ""
        results = _parse_mi_results(results_str) if results_str else {}
        return MIResult(
            record_type=MIRecordType.EXEC_ASYNC,
            token=token,
            async_class=async_class,
            results=results,
            raw=raw,
        )

    # Notify async: =breakpoint-modified,...
    m = _NOTIFY_ASYNC_RE.match(line)
    if m:
        token = int(m.group(1)) if m.group(1) else None
        async_class = m.group(2)
        results_str = m.group(3) or ""
        results = _parse_mi_results(results_str) if results_str else {}
        return MIResult(
            record_type=MIRecordType.NOTIFY_ASYNC,
            token=token,
            async_class=async_class,
            results=results,
            raw=raw,
        )

    # Status async: +download,...
    m = _STATUS_ASYNC_RE.match(line)
    if m:
        return MIResult(
            record_type=MIRecordType.STATUS_ASYNC,
            token=int(m.group(1)) if m.group(1) else None,
            async_class=m.group(2),
            results=_parse_mi_results(m.group(3) or ""),
            raw=raw,
        )

    # Console stream: ~"text"
    m = _CONSOLE_STREAM_RE.match(line)
    if m:
        return MIResult(
            record_type=MIRecordType.CONSOLE_STREAM,
            stream_text=_unescape_string(m.group(1)),
            raw=raw,
        )

    # Target stream: @"text"
    m = _TARGET_STREAM_RE.match(line)
    if m:
        return MIResult(
            record_type=MIRecordType.TARGET_STREAM,
            stream_text=_unescape_string(m.group(1)),
            raw=raw,
        )

    # Log stream: &"text"
    m = _LOG_STREAM_RE.match(line)
    if m:
        return MIResult(
            record_type=MIRecordType.LOG_STREAM,
            stream_text=_unescape_string(m.group(1)),
            raw=raw,
        )

    # Unknown line — treat as console output if it's not a known pattern
    logger.debug("Unrecognized MI line: %s", line)
    return None


class MIStreamParser:
    """Stream parser for GDB MI output.

    Accumulates lines until a prompt is received, then produces a complete
    MIOutput representing the full response to a command.
    """

    def __init__(self) -> None:
        self._lines: list[str] = []
        self._records: list[MIResult] = []

    def reset(self) -> None:
        """Reset parser state for a new command response."""
        self._lines.clear()
        self._records.clear()

    def feed_line(self, line: str) -> Optional[MIOutput]:
        """Feed a line of GDB MI output.

        Returns a complete MIOutput when the prompt is received,
        or None if more lines are expected.
        """
        self._lines.append(line)
        record = parse_mi_line(line)

        if record is None:
            # Unrecognized line — store as raw
            return None

        if record.record_type == MIRecordType.PROMPT:
            # End of response — assemble MIOutput
            output = self._assemble_output()
            self.reset()
            return output

        self._records.append(record)
        return None

    def feed_all(self, text: str) -> list[MIOutput]:
        """Feed multiple lines of text and return all complete outputs.

        Text may contain multiple complete responses separated by prompts.
        """
        outputs: list[MIOutput] = []
        for line in text.splitlines():
            output = self.feed_line(line)
            if output is not None:
                outputs.append(output)
        return outputs

    def _assemble_output(self) -> MIOutput:
        """Assemble accumulated records into an MIOutput."""
        output = MIOutput(raw_lines=list(self._lines))

        for record in self._records:
            if record.record_type == MIRecordType.RESULT:
                output.result = record
            elif record.record_type in (
                MIRecordType.CONSOLE_STREAM,
                MIRecordType.TARGET_STREAM,
                MIRecordType.LOG_STREAM,
            ):
                output.streams.append(record)
            elif record.record_type in (
                MIRecordType.EXEC_ASYNC,
                MIRecordType.NOTIFY_ASYNC,
                MIRecordType.STATUS_ASYNC,
            ):
                output.async_records.append(record)

        return output
