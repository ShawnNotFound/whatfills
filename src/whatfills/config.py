"""Settings: built-in defaults, then config files, then command-line flags.

Config files (all optional, later ones win; list settings are combined):
  /etc/whatfills/config.toml
  $XDG_CONFIG_HOME/whatfills/config.toml   (usually ~/.config/whatfills/config.toml)
When run with sudo, the invoking user's config is read as well, so personal
exclusions still apply.
"""

from __future__ import annotations

import difflib
import os
import pwd
import sys
from dataclasses import dataclass, field

from .units import parse_duration, parse_size

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

EFFORTS = ("quick", "normal", "deep")
IO_PRIORITIES = ("normal", "low", "idle")
COLOR_MODES = ("auto", "always", "never")

# Scanner settings behind each effort level. "quick" gives an answer within
# about 30 seconds even on huge disks (the report then says how much of the
# used space it covered); "deep" keeps more detail for drilling down.
EFFORT_PRESETS = {
    "quick": {
        "time_budget": 30.0,
        "keep_dir_min": parse_size("16M"),
        "big_file_min": parse_size("256M"),
        "top_files": 50,
        "matches_per_rule": 50,
        "files_per_rule": 10,
        "max_links": 2 << 20,  # hard-linked files tracked so each is counted once (about 70 bytes each)
        "collect_ext": False,
        "dont_sync": True,
    },
    "normal": {
        "time_budget": 0.0,
        "keep_dir_min": parse_size("1M"),
        "big_file_min": parse_size("64M"),
        "top_files": 200,
        "matches_per_rule": 100,
        "files_per_rule": 20,
        "max_links": 8 << 20,
        "collect_ext": True,
        "dont_sync": False,
    },
    "deep": {
        "time_budget": 0.0,
        "keep_dir_min": parse_size("64K"),
        "big_file_min": parse_size("16M"),
        "top_files": 1000,
        "matches_per_rule": 500,
        "files_per_rule": 100,
        "max_links": 32 << 20,
        "collect_ext": True,
        "dont_sync": False,
    },
}

_SCHEMA = {
    "scan": {
        "effort": "str",
        "threads": "int",
        "one_file_system": "bool",
        "cross_subvolumes": "bool",
        "time_budget": "duration",
        "io_priority": "str",
        "apparent_size": "bool",
    },
    "exclude": {"paths": "list", "names": "list", "globs": "list", "fstypes": "list"},
    "report": {"top": "int", "color": "str"},
    "rules": {"disable": "list", "files": "list", "builtin": "bool"},
}

CONFIG_TEMPLATE = """\
# whatfills settings. Every key is optional; remove the leading '#' to use one.
# Command-line flags override these, and list settings add up.

[scan]
# effort = "normal"          # quick (answer in ~30 s), normal, or deep (more detail)
# threads = 0                # 0 = pick from the storage type (SSD, HDD, network)
# one_file_system = true     # stay on the filesystem you scan, like du -x
# cross_subvolumes = false   # also count btrfs subvolumes (snapshots can double count)
# time_budget = "0"          # stop after this long and report what was found, e.g. "2m"
# io_priority = "normal"     # normal, low, or idle (gentler on busy servers)
# apparent_size = false      # report file sizes instead of disk usage

[exclude]
# Never opened or measured.
# paths = ["/data/private"]          # absolute folders or files
# names = [".snapshots", "*.vmdk"]  # file or folder names, * and ? allowed
# globs = ["/srv/**/raw"]            # full-path patterns, ** crosses folders
# fstypes = ["nfs", "cifs"]          # filesystem types, when crossing filesystems

[report]
# top = 10            # rows per section
# color = "auto"      # auto, always, never (NO_COLOR is respected)

[rules]
# disable = ["var-log"]                    # rule ids, see `whatfills rules list`
# files = ["~/my-rules.toml"]              # extra rules files
"""


class ConfigError(ValueError):
    """A setting is invalid. The message names the file and the key."""


@dataclass
class Settings:
    effort: str = "normal"
    threads: int = 0
    one_file_system: bool = True
    cross_subvolumes: bool = False
    time_budget: float | None = None  # None: use the effort preset
    io_priority: str = "normal"
    apparent_size: bool = False
    exclude_paths: list = field(default_factory=list)
    exclude_names: list = field(default_factory=list)
    exclude_globs: list = field(default_factory=list)
    exclude_fstypes: list = field(default_factory=list)
    top: int = 10
    color: str = "auto"
    rules_disable: list = field(default_factory=list)
    rules_files: list = field(default_factory=list)
    builtin_rules: bool = True
    sources: list = field(default_factory=list)  # config files that were read
    warnings: list = field(default_factory=list)  # config files that exist but could not be read

    def preset(self) -> dict:
        p = dict(EFFORT_PRESETS[self.effort])
        if self.time_budget is not None:
            p["time_budget"] = self.time_budget
        return p


def _user_config_dir(home: str | None = None, xdg: str | None = None) -> str:
    if xdg and os.path.isabs(xdg):
        return os.path.join(xdg, "whatfills")
    return os.path.join(home or os.path.expanduser("~"), ".config", "whatfills")


def config_dirs() -> list[str]:
    """Config folders, lowest priority first."""
    dirs = ["/etc/whatfills", _user_config_dir(xdg=os.environ.get("XDG_CONFIG_HOME"))]
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and sudo_user:
        try:
            d = _user_config_dir(home=pwd.getpwnam(sudo_user).pw_dir)
            if d not in dirs:
                dirs.append(d)
        except KeyError:
            pass
    return dirs


def user_config_path() -> str:
    return os.path.join(_user_config_dir(xdg=os.environ.get("XDG_CONFIG_HOME")), "config.toml")


def _check(value, kind: str, where: str):
    if kind == "str":
        if not isinstance(value, str):
            raise ConfigError(f"{where} must be a string")
        return value
    if kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{where} must be a whole number")
        return value
    if kind == "bool":
        if not isinstance(value, bool):
            raise ConfigError(f"{where} must be true or false")
        return value
    if kind == "list":
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{where} must be a list of strings")
        return value
    if kind == "duration":
        try:
            return parse_duration(value)
        except ValueError as e:
            raise ConfigError(f"{where}: {e}") from None
    raise AssertionError(kind)


def _suggest(word: str, options) -> str:
    close = difflib.get_close_matches(word, sorted(options), n=1)
    return f" (did you mean {close[0]!r}?)" if close else ""


def parse_config_text(text: str, source: str) -> dict:
    """Validate a config file and return {"section.key": value}."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{source}: not valid TOML: {e}") from None
    out = {}
    for section, table in data.items():
        if section not in _SCHEMA:
            raise ConfigError(f"{source}: unknown section [{section}]{_suggest(section, _SCHEMA)}")
        if not isinstance(table, dict):
            raise ConfigError(f"{source}: [{section}] must be a table")
        for key, value in table.items():
            kinds = _SCHEMA[section]
            if key not in kinds:
                raise ConfigError(f"{source}: unknown key {key!r} in [{section}]{_suggest(key, kinds)}")
            out[f"{section}.{key}"] = _check(value, kinds[key], f"{source}: {section}.{key}")
    return out


def _expand_user_paths(values: list, base_dir: str) -> list:
    out = []
    for v in values:
        v = os.path.expanduser(v)
        if not os.path.isabs(v):
            v = os.path.join(base_dir, v)
        out.append(os.path.normpath(v))
    return out


_LIST_KEYS = {"exclude.paths", "exclude.names", "exclude.globs", "exclude.fstypes", "rules.disable", "rules.files"}


def apply(settings: Settings, values: dict, base_dir: str = "") -> None:
    """Apply validated values ("section.key" -> value) to settings."""
    base_dir = base_dir or os.getcwd()
    for key, value in values.items():
        if key in _LIST_KEYS and any(not v.strip() for v in value):
            raise ConfigError(f"{key} has an empty entry; remove it (an empty path would mean the current folder)")
        if key == "scan.effort":
            if value not in EFFORTS:
                raise ConfigError(f"effort must be one of {', '.join(EFFORTS)}, not {value!r}")
            settings.effort = value
        elif key == "scan.threads":
            if not 0 <= value <= 256:
                raise ConfigError(f"threads must be between 0 (automatic) and 256, not {value}")
            settings.threads = value
        elif key == "scan.one_file_system":
            settings.one_file_system = value
        elif key == "scan.cross_subvolumes":
            settings.cross_subvolumes = value
        elif key == "scan.time_budget":
            settings.time_budget = value
        elif key == "scan.io_priority":
            if value not in IO_PRIORITIES:
                raise ConfigError(f"io_priority must be one of {', '.join(IO_PRIORITIES)}, not {value!r}")
            settings.io_priority = value
        elif key == "scan.apparent_size":
            settings.apparent_size = value
        elif key == "exclude.paths":
            settings.exclude_paths += _expand_user_paths(value, base_dir)
        elif key == "exclude.names":
            for v in value:
                if "/" in v:
                    raise ConfigError(f"exclude name {v!r} contains '/'; names match a single file or folder name, "
                                      "use exclude globs or paths for paths")  # fmt: skip
            settings.exclude_names += value
        elif key == "exclude.globs":
            settings.exclude_globs += value
        elif key == "exclude.fstypes":
            settings.exclude_fstypes += value
        elif key == "report.top":
            if not 1 <= value <= 10000:
                raise ConfigError(f"top must be between 1 and 10000, not {value}")
            settings.top = value
        elif key == "report.color":
            if value not in COLOR_MODES:
                raise ConfigError(f"color must be one of {', '.join(COLOR_MODES)}, not {value!r}")
            settings.color = value
        elif key == "rules.disable":
            settings.rules_disable += value
        elif key == "rules.files":
            settings.rules_files += _expand_user_paths(value, base_dir)
        elif key == "rules.builtin":
            settings.builtin_rules = value
        else:  # pragma: no cover - guarded by _SCHEMA
            raise ConfigError(f"unknown setting {key}")


def load(extra_file: str | None = None, read_default_files: bool = True) -> Settings:
    settings = Settings()
    paths = [os.path.join(d, "config.toml") for d in config_dirs()] if read_default_files else []
    if extra_file:
        paths.append(extra_file)
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except FileNotFoundError:
            if path == extra_file:
                raise ConfigError(f"config file not found: {path}") from None
            continue
        except UnicodeDecodeError as e:
            raise ConfigError(f"{path}: not UTF-8 text (bad byte at position {e.start})") from None
        except OSError as e:
            if path == extra_file:
                raise ConfigError(f"cannot read config file {path}: {e.strerror}") from None
            settings.warnings.append(f"skipped config file {path}: {e.strerror}")
            continue
        values = parse_config_text(text, path)
        try:
            apply(settings, values, base_dir=os.path.dirname(os.path.abspath(path)))
        except ConfigError as e:
            raise ConfigError(f"{path}: {e}") from None
        settings.sources.append(path)
    return settings
