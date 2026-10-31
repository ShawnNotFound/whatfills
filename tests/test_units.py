"""Parsing and formatting of sizes, durations and ages."""

import pytest

from whatfills.units import format_age, format_count, format_duration, format_size, parse_duration, parse_size


def test_parse_size():
    assert parse_size("500M") == 500 * 1024**2
    assert parse_size("1.5TiB") == int(1.5 * 1024**4)
    assert parse_size("10GB") == 10 * 1000**3
    assert parse_size("64k") == 64 * 1024
    assert parse_size(4096) == 4096
    with pytest.raises(ValueError, match="such as 500M"):
        parse_size("12X")
    with pytest.raises(ValueError, match="negative"):
        parse_size(-1)
    with pytest.raises(ValueError):
        parse_size(True)


def test_parse_duration():
    assert parse_duration("1h30m") == 5400
    assert parse_duration("45") == 45
    assert parse_duration("2m 10s") == 130
    assert parse_duration("250ms") == 0.25
    assert parse_duration(0) == 0
    with pytest.raises(ValueError, match="like 30s"):
        parse_duration("soon")
    with pytest.raises(ValueError, match="like 30s"):
        parse_duration("5 minutes")


def test_formatting():
    assert format_size(1536) == "1.5 KiB"
    assert format_size(10) == "10 B"
    assert format_size(-2048) == "-2.0 KiB"
    assert format_size(3 * 1024**5 * 2000).endswith("PiB")
    assert format_count(1234) == "1,234"
    assert format_count(1_234_567) == "1.23M"
    assert format_duration(0.25) == "250 ms"
    assert format_duration(75) == "1 min 15 s"
    assert format_age(3 * 86400) == "3 days"
    assert format_age(400 * 86400) == "13 months"
    assert format_age(1.2 * 86400) == "1 day" and format_age(2 * 3600) == "2 hours"
