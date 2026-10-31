"""Parsing and formatting of sizes, durations and ages."""

from __future__ import annotations

import re

_SIZE_RE = re.compile(r"^\s*([0-9]*\.?[0-9]+)\s*([a-zA-Z]*)\s*$")

# Bare K/M/G/T are powers of 1024, like du and ls. KB/MB/GB/TB are powers of 1000.
_SIZE_UNITS = {
    "": 1,
    "b": 1,
    "k": 1024,
    "kib": 1024,
    "m": 1024**2,
    "mib": 1024**2,
    "g": 1024**3,
    "gib": 1024**3,
    "t": 1024**4,
    "tib": 1024**4,
    "p": 1024**5,
    "pib": 1024**5,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "tb": 1000**4,
    "pb": 1000**5,
}


def parse_size(text: str | int) -> int:
    """Parse "500M", "2G", "1.5TiB", "10GB" or a plain byte count."""
    if isinstance(text, bool):
        raise ValueError(f"invalid size {text!r}")
    if isinstance(text, int):
        if text < 0:
            raise ValueError(f"size cannot be negative: {text}")
        return text
    m = _SIZE_RE.match(str(text))
    unit = m.group(2).lower() if m else None
    if not m or unit not in _SIZE_UNITS:
        raise ValueError(f"invalid size {text!r}: use a number with an optional unit, such as 500M, 2G or 1.5TiB")
    return int(float(m.group(1)) * _SIZE_UNITS[unit])


def format_size(n: int | float) -> str:
    """Human-readable size with binary units: 512 B, 1.2 KiB, 3.4 GiB."""
    n = float(n)
    sign = "-" if n < 0 else ""
    n = abs(n)
    if n < 1024:
        return f"{sign}{int(n)} B"
    for unit in ("KiB", "MiB", "GiB", "TiB", "PiB"):
        n /= 1024
        if n < 1024 or unit == "PiB":
            return f"{sign}{n:.1f} {unit}"
    raise AssertionError("unreachable")


_DUR_FULL = re.compile(r"^\s*(?:\d+(?:\.\d+)?\s*(?:ms|s|m|h|d)?\s*)+$", re.IGNORECASE)
_DUR_PART = re.compile(r"(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?", re.IGNORECASE)
_DUR_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "": 1}


def parse_duration(text: str | int | float) -> float:
    """Parse "30s", "5m", "1h30m" or a number of seconds. 0 means no limit."""
    if isinstance(text, bool):
        raise ValueError(f"invalid duration {text!r}")
    if isinstance(text, (int, float)):
        if text < 0:
            raise ValueError(f"duration cannot be negative: {text}")
        return float(text)
    s = str(text)
    if not _DUR_FULL.match(s):
        raise ValueError(f"invalid duration {text!r}: use a number of seconds or values like 30s, 5m, 1h30m")
    return sum(float(num) * _DUR_UNITS[unit.lower()] for num, unit in _DUR_PART.findall(s))


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    m, s = divmod(int(round(seconds)), 60)
    if m < 60:
        return f"{m} min {s} s"
    h, m = divmod(m, 60)
    return f"{h} h {m} min"


def format_count(n: int) -> str:
    """1234 -> 1,234; 1234567 -> 1.23M."""
    if n < 100_000:
        return f"{n:,}"
    if n < 1_000_000:
        return f"{n / 1000:.0f}k"
    if n < 1_000_000_000:
        return f"{n / 1_000_000:.2f}M"
    return f"{n / 1_000_000_000:.2f}B"


# Age buckets reported by the scanner, oldest last.
AGE_LABELS = ("under 1 day", "1–7 days", "7–30 days", "30–90 days", "90 days–1 year", "1–3 years", "over 3 years")
AGE_LIMITS_DAYS = (1, 7, 30, 90, 365, 3 * 365, None)


def _n(value: float, unit: str) -> str:
    v = round(value)
    return f"{v} {unit}" + ("" if v == 1 else "s")


def format_age(seconds: float) -> str:
    days = seconds / 86400
    if days < 1:
        hours = seconds / 3600
        return "under an hour" if hours < 1 else _n(hours, "hour")
    if days < 60:
        return _n(days, "day")
    if days < 730:
        return _n(days / 30.4, "month")
    return f"{days / 365:.1f} years"
