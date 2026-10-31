"""Terminal helpers: colours, safe display of file names, progress line."""

from __future__ import annotations

import os
import re
import shutil
import sys
import unicodedata

from .units import format_count, format_size


class Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled and text else text

    def bold(self, t: str) -> str:
        return self._wrap("1", t)

    def dim(self, t: str) -> str:
        return self._wrap("2", t)

    def red(self, t: str) -> str:
        return self._wrap("31", t)

    def green(self, t: str) -> str:
        return self._wrap("32", t)

    def yellow(self, t: str) -> str:
        return self._wrap("33", t)

    def cyan(self, t: str) -> str:
        return self._wrap("36", t)

    def safety(self, level: str, text: str | None = None) -> str:
        text = text if text is not None else level
        return {
            "safe": self.green,
            "regenerable": self.cyan,
            "review": self.yellow,
            "caution": self.red,
        }.get(level, lambda t: t)(text)


def color_enabled(mode: str, stream=None) -> bool:
    stream = stream or sys.stdout
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty() and os.environ.get("TERM") != "dumb"


def width(default: int = 100) -> int:
    return max(60, min(160, shutil.get_terminal_size((default, 24)).columns))


def show(text: str) -> str:
    """Make a file name safe to print: undecodable bytes and control
    characters become escapes, so odd names cannot garble the terminal."""
    raw = text.encode("utf-8", "surrogateescape")
    out = raw.decode("utf-8", "backslashreplace")
    if out.isprintable():
        return out
    return "".join(ch if ch.isprintable() or ch == " " else ch.encode("unicode_escape").decode("ascii") for ch in out)


def display_width(text: str) -> int:
    w = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        w += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return w


def _cut(text: str, cols: int, from_end: bool = False) -> str:
    """The longest start (or end) of `text` that fits in `cols` columns."""
    out, w = [], 0
    for ch in reversed(text) if from_end else text:
        cw = 0 if unicodedata.combining(ch) else 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if w + cw > cols:
            break
        out.append(ch)
        w += cw
    return "".join(reversed(out)) if from_end else "".join(out)


def clip(text: str, limit: int) -> str:
    """Cut text to `limit` columns, ending with … when it was cut."""
    if display_width(text) <= limit:
        return text
    return _cut(text, max(0, limit - 1)) + "…"


def shorten_middle(text: str, limit: int) -> str:
    if display_width(text) <= limit or limit < 8:
        return text
    head = (limit - 1) // 3
    return _cut(text, head) + "…" + _cut(text, limit - 1 - head, from_end=True)


_HEX_RUN = re.compile(r"[0-9a-f]{20,}|[0-9A-F]{20,}")


def shorten_path(path: str, limit: int) -> str:
    """Shorten a path to `limit` columns. Long hex ids (content hashes,
    container and machine ids) are cut to their start first. Then folders are
    left out of the middle, keeping the first two, the last part whole, and
    as many of the folders just above it as fit:
    /home/alex/…/models--Qwen--Qwen2.5-3B/blobs/6b86b273…"""
    if display_width(path) <= limit or limit < 8:
        return path
    path = _HEX_RUN.sub(lambda m: m.group(0)[:8] + "…", path)
    if display_width(path) <= limit:
        return path
    lead = "/" if path.startswith("/") else ""
    parts = [x for x in path.split("/") if x]
    if len(parts) < 2 or display_width(parts[-1]) + 4 > limit:
        return shorten_middle(path, limit)
    head, tail = parts[: min(2, len(parts) - 1)], parts[-1:]
    rest = parts[len(head) : -1]  # folders that may be left out

    def fits(h: list, t: list) -> bool:
        return display_width(lead + "/".join(h)) + 3 + display_width("/".join(t)) <= limit

    while head and not fits(head, tail):
        rest.insert(0, head.pop())
    i, j = len(rest), 0  # rest[j:i] is left out
    while i > j and fits(head, rest[i - 1 : i] + tail):
        i -= 1
        tail.insert(0, rest[i])
    while j < i and fits(head + rest[j : j + 1], tail):
        head.append(rest[j])
        j += 1
    if j >= i:
        return lead + "/".join(head + tail)
    return (lead + "/".join(head) + "/…/" if head else lead + "…/") + "/".join(tail)


def home_short(path: str) -> str:
    home = os.path.expanduser("~")
    if home not in ("/", "") and (path == home or path.startswith(home + "/")):
        return "~" + path[len(home) :]
    return path


class ProgressLine:
    """One updating status line on stderr while scanning."""

    def __init__(self, stream=None, enabled: bool | None = None):
        self.stream = stream or sys.stderr
        self.enabled = enabled if enabled is not None else (hasattr(self.stream, "isatty") and self.stream.isatty())
        self._last_len = 0

    def __call__(self, info: dict) -> None:
        if not self.enabled:
            return
        if "message" in info:
            self._write(info["message"] + "…")
            return
        parts = [
            f"{format_count(info['files'])} files",
            f"{format_count(info['dirs'])} folders",
            format_size(info["alloc"]),
        ]
        if info.get("used"):
            parts[-1] += f" ({min(100.0, 100.0 * info['alloc'] / info['used']):.0f}% of used space)"
        if info.get("errors"):
            parts.append(f"{format_count(info['errors'])} unreadable")
        elapsed = info.get("elapsed", 0.0)
        tail = f"{elapsed:.0f} s"
        if info.get("budget"):
            tail += f" of {info['budget']:.0f} s"
        if info.get("stopping"):
            tail += ", stopping"
        self._write("Scanning: " + ", ".join(parts) + f" [{tail}]")

    def _write(self, line: str) -> None:
        line = line[: width() - 1]
        pad = max(0, self._last_len - len(line))
        self.stream.write("\r" + line + " " * pad)
        self.stream.flush()
        self._last_len = len(line)

    def clear(self) -> None:
        if self.enabled and self._last_len:
            self.stream.write("\r" + " " * self._last_len + "\r")
            self.stream.flush()
            self._last_len = 0
