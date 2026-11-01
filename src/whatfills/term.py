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


def shorten_path(path: str, limit: int, keep: int = 0) -> str:
    """Shorten a path to `limit` columns. Long hex ids (content hashes,
    container and machine ids) are cut to their start first. Then folders are
    left out, each run of them shown as "…", and the last part stays whole
    (if it alone is too long, the middle of the path is cut instead).

    The start of the path ("/" or "~") is kept when there is room, so a
    shortened path still shows where it starts. Then folders are kept in this
    order, as far as they fit: the ones just above the last part, then the
    first part and those after it. With `keep`, the folder made of the first
    `keep` parts (the folder that explains a file, say) comes first, and the
    folders just above it come before the first part:
    /…/huggingface/…/models--Qwen--Qwen2.5-3B/blobs/6b86b273…"""
    if display_width(path) <= limit or limit < 8:
        return path
    path = _HEX_RUN.sub(lambda m: m.group(0)[:8] + "…", path)
    if display_width(path) <= limit:
        return path
    lead = "/" if path.startswith("/") else ""
    parts = [x for x in path.split("/") if x]
    n = len(parts)
    if n < 2 or display_width(parts[-1]) + 2 > limit:
        return shorten_middle(path, limit)
    shown = [False] * n
    shown[-1] = True
    root = False  # show the leading "/" even when the first part is left out: /…/name

    def render() -> str:
        out, gap = [], False
        for part, s in zip(parts, shown):
            if s:
                out += ["…", part] if gap else [part]
                gap = False
            else:
                gap = True
        return (lead if shown[0] or root else "") + "/".join(out)

    def add(i: int) -> bool:
        if shown[i]:
            return True
        shown[i] = True
        if display_width(render()) <= limit:
            return True
        shown[i] = False
        return False

    if lead:
        root = display_width(lead + "…/" + parts[-1]) <= limit
    elif parts[0] == "~":
        add(0)
    anchor = keep - 1 if 0 < keep < n - 1 else -1
    runs = [range(n - 2, anchor, -1)]  # the folders just above the last part
    if anchor >= 0 and add(anchor):
        runs.append(range(anchor - 1, -1, -1))  # the folders just above the kept one
    runs.append(range(n - 1))  # the first part and those after it
    for run in runs:
        for i in run:
            if not add(i):
                break
    return render()


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
