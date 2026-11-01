"""Rules describe what a folder or file is, why it can get big, and how to
free the space. Built-in rules ship with whatfills; users can add or override
rules with their own TOML files.

A rule matches either folders or files:

    [[rule]]
    id = "pip-cache"                 # lowercase letters, digits and dashes
    name = "pip download cache"
    category = "caches"
    safety = "safe"                  # safe | regenerable | review | caution
    dirs = [".cache/pip"]            # folder whose path ends with these components
    paths = ["/var/cache/pip"]       # folder at exactly this path ("~/x" = in any home folder)
    explain = "..."
    fix = [{ label = "Clear it", run = "pip cache purge" }]
    tips = ["..."]

File rules use `files = ["*.iso"]` plus optional `min_size`, `within` (ids of
folder rules the file must be inside), `outside` (ids of folder rules it must
not be inside) and `in_dirs` (folders it must be directly in). Patterns of the
form "*.ext" ignore case.
"""

from __future__ import annotations

import dataclasses
import difflib
import glob as _glob
import os
import pwd
import re
import sys
from dataclasses import dataclass, field

from .units import parse_size

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

SAFETY = {
    "safe": "Safe to delete. It is a cache or a leftover, and nothing you need is lost.",
    "regenerable": "Safe to delete. It is rebuilt or downloaded again when needed, which takes time.",
    "review": "Check before deleting. It may hold things you want to keep.",
    "caution": "Do not delete by hand. Use the suggested command or the program that owns it.",
}

CATEGORIES = {
    "logs": "Logs",
    "packages": "System packages",
    "containers": "Containers and VMs",
    "caches": "Caches",
    "dev": "Development",
    "ml": "Machine learning",
    "system": "System",
    "personal": "Personal files",
    "media": "Media",
    "trash": "Trash",
    "backups": "Backups and snapshots",
    "databases": "Databases",
    "other": "Other",
}

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_RULE_KEYS = {
    "id", "name", "category", "safety", "explain", "paths", "dirs", "files", "min_size",
    "within", "outside", "in_dirs", "require_child", "require_sibling", "opaque", "fix", "tips",
}  # fmt: skip
_FIX_KEYS = {"label", "run", "root", "note"}


class RuleError(ValueError):
    """A rules file could not be loaded. The message says where and why."""


@dataclass
class Fix:
    label: str
    run: str = ""
    root: bool = False
    note: str = ""


@dataclass
class Rule:
    id: str
    name: str
    category: str = "other"
    safety: str = "review"
    explain: str = ""
    paths: list = field(default_factory=list)
    dirs: list = field(default_factory=list)
    files: list = field(default_factory=list)
    min_size: int = 0
    within: list = field(default_factory=list)
    outside: list = field(default_factory=list)
    in_dirs: list = field(default_factory=list)
    require_child: list = field(default_factory=list)
    require_sibling: list = field(default_factory=list)
    opaque: bool = False  # no other folder rule matches inside its folders
    fixes: list = field(default_factory=list)
    tips: list = field(default_factory=list)
    source: str = ""
    num: int = 0  # numeric id used by the scanner, assigned by RuleSet

    @property
    def kind(self) -> str:
        return "files" if self.files else "folders"


UNCLASSIFIED = Rule(
    id="unclassified",
    name="Not matched by any rule",
    category="other",
    safety="review",
    explain="Space that no rule recognised. Look at the largest folders and files below.",
)


def _suggest(word: str, options) -> str:
    close = difflib.get_close_matches(word, sorted(options), n=1)
    return f" (did you mean {close[0]!r}?)" if close else ""


def _str_list(value, where: str, key: str) -> list:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise RuleError(f"{where}: '{key}' must be a string or a list of strings")
    return list(value)


def _parse_rule(raw: dict, where: str, source: str) -> Rule:
    if not isinstance(raw, dict):
        raise RuleError(f"{where}: each [[rule]] must be a table")
    for key in raw:
        if key not in _RULE_KEYS:
            raise RuleError(f"{where}: unknown key {key!r}{_suggest(key, _RULE_KEYS)}")
    rid = raw.get("id")
    if not isinstance(rid, str) or not _ID_RE.match(rid):
        raise RuleError(f"{where}: 'id' is required and must use lowercase letters, digits and dashes, e.g. \"pip-cache\"")
    where = f"{where} ({rid})"
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise RuleError(f"{where}: 'name' is required, e.g. name = \"pip download cache\"")
    category = raw.get("category", "other")
    if category not in CATEGORIES:
        raise RuleError(f"{where}: unknown category {category!r}{_suggest(str(category), CATEGORIES)}; "
                        f"choose one of {', '.join(CATEGORIES)}")  # fmt: skip
    safety = raw.get("safety", "review")
    if safety not in SAFETY:
        raise RuleError(f"{where}: unknown safety {safety!r}{_suggest(str(safety), SAFETY)}; choose one of {', '.join(SAFETY)}")
    explain = raw.get("explain", "")
    if not isinstance(explain, str):
        raise RuleError(f"{where}: 'explain' must be a string")

    paths = _str_list(raw.get("paths", []), where, "paths")
    dirs = _str_list(raw.get("dirs", []), where, "dirs")
    files = _str_list(raw.get("files", []), where, "files")
    if not (paths or dirs or files):
        raise RuleError(f"{where}: a rule needs at least one of 'paths', 'dirs' or 'files' to match something")
    if files and (paths or dirs):
        raise RuleError(f"{where}: a rule matches either folders ('paths', 'dirs') or files ('files'), not both; "
                        "split it into two rules")  # fmt: skip
    for p in paths:
        if not (p.startswith("/") or p.startswith("~/") or p.startswith("$")):
            raise RuleError(f"{where}: path {p!r} must be absolute, start with ~/ (any home folder) or with $VARIABLE")
    for d in dirs:
        if d.startswith("/"):
            raise RuleError(f"{where}: 'dirs' entries match the end of a path, so {d!r} must not start with '/'; "
                            "use 'paths' for absolute paths")  # fmt: skip
    for pat in paths + dirs:
        comps = [c for c in pat.split("/") if c not in ("", "~") and not c.startswith("$")]
        if any(c in (".", "..") for c in comps):
            raise RuleError(f"{where}: pattern {pat!r} must not contain '.' or '..' components")
    for f in files:
        if "/" in f:
            raise RuleError(f"{where}: file pattern {f!r} must be a file name pattern without '/'; "
                            "use 'in_dirs' or 'within' to limit where it applies")  # fmt: skip

    min_size = 0
    if "min_size" in raw:
        if not files:
            raise RuleError(f"{where}: 'min_size' only applies to file rules")
        try:
            min_size = parse_size(raw["min_size"])
        except ValueError as e:
            raise RuleError(f"{where}: {e}") from None
    within = _str_list(raw.get("within", []), where, "within")
    outside = _str_list(raw.get("outside", []), where, "outside")
    in_dirs = _str_list(raw.get("in_dirs", []), where, "in_dirs")
    if (within or outside or in_dirs) and not files:
        raise RuleError(f"{where}: 'within', 'outside' and 'in_dirs' only apply to file rules")
    for d in in_dirs:
        if not d.startswith("/"):
            raise RuleError(f"{where}: in_dirs entry {d!r} must be an absolute path")
    req_child = _str_list(raw.get("require_child", []), where, "require_child")
    req_sib = _str_list(raw.get("require_sibling", []), where, "require_sibling")
    if (req_child or req_sib) and files:
        raise RuleError(f"{where}: 'require_child' and 'require_sibling' only apply to folder rules")
    for key, names, place, example in (("require_child", req_child, "inside the folder", "pyvenv.cfg"),
                                       ("require_sibling", req_sib, "next to the folder", "Cargo.toml")):
        for n in names:
            if not n.strip("/") or n.startswith("/") or any(p in (".", "..") for p in n.split("/")):
                raise RuleError(f"{where}: '{key}' entry {n!r} must be a name {place}, like \"{example}\", "
                                "not empty, absolute or with '.' or '..' parts")
    if "*" in dirs and not req_child:
        raise RuleError(f"{where}: dirs entry '*' matches every folder; add 'require_child' to say what must be "
                        "inside it, for example require_child = [\"pyvenv.cfg\"]")  # fmt: skip
    opaque = raw.get("opaque", False)
    if not isinstance(opaque, bool):
        raise RuleError(f"{where}: 'opaque' must be true or false")
    if opaque and files:
        raise RuleError(f"{where}: 'opaque' only applies to folder rules")

    fixes = []
    raw_fix = raw.get("fix", [])
    if isinstance(raw_fix, dict):
        raw_fix = [raw_fix]
    if not isinstance(raw_fix, list):
        raise RuleError(f"{where}: 'fix' must be a table or a list of tables")
    for i, fx in enumerate(raw_fix, 1):
        if not isinstance(fx, dict):
            raise RuleError(f"{where}: fix {i} must be a table like {{ label = \"...\", run = \"...\" }}")
        for key in fx:
            if key not in _FIX_KEYS:
                raise RuleError(f"{where}: fix {i}: unknown key {key!r}{_suggest(key, _FIX_KEYS)}")
        if not isinstance(fx.get("label"), str) or not fx["label"].strip():
            raise RuleError(f"{where}: fix {i} needs a 'label'")
        for key in ("run", "note"):
            if key in fx and not isinstance(fx[key], str):
                raise RuleError(f"{where}: fix {i}: '{key}' must be a string")
        if "root" in fx and not isinstance(fx["root"], bool):
            raise RuleError(f"{where}: fix {i}: 'root' must be true or false")
        fixes.append(Fix(label=fx["label"], run=fx.get("run", ""), root=fx.get("root", False), note=fx.get("note", "")))
    tips = _str_list(raw.get("tips", []), where, "tips")

    return Rule(
        id=rid, name=name.strip(), category=category, safety=safety, explain=explain.strip(),
        paths=paths, dirs=dirs, files=files, min_size=min_size, within=within, outside=outside, in_dirs=in_dirs,
        require_child=req_child, require_sibling=req_sib, opaque=opaque, fixes=fixes, tips=tips, source=source,
    )  # fmt: skip


def parse_rules_text(text: str, source: str) -> list[Rule]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise RuleError(f"{source}: not valid TOML: {e}") from None
    unknown = set(data) - {"rule", "version"}
    if unknown:
        key = sorted(unknown)[0]
        raise RuleError(f"{source}: unknown top-level key {key!r}{_suggest(key, {'rule', 'version'})}; "
                        "rules go in [[rule]] tables")  # fmt: skip
    raw_rules = data.get("rule", [])
    if not isinstance(raw_rules, list):
        raise RuleError(f"{source}: use [[rule]] (double brackets) for each rule")
    rules = []
    ids = set()
    for i, raw in enumerate(raw_rules, 1):
        rule = _parse_rule(raw, f"{source}: rule {i}", source)
        if rule.id in ids:
            raise RuleError(f"{source}: rule id {rule.id!r} is defined twice in this file")
        ids.add(rule.id)
        rules.append(rule)
    return rules


def load_rules_file(path: str) -> list[Rule]:
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except UnicodeDecodeError as e:
        raise RuleError(f"{path}: not UTF-8 text (bad byte at position {e.start})") from None
    except OSError as e:
        raise RuleError(f"cannot read rules file {path}: {e.strerror}") from None
    return parse_rules_text(text, path)


def builtin_rules() -> list[Rule]:
    from importlib import resources

    rules = []
    base = resources.files("whatfills") / "data" / "rules"
    for entry in sorted(base.iterdir(), key=lambda p: p.name):
        if entry.name.endswith(".toml"):
            rules.extend(parse_rules_text(entry.read_text(encoding="utf-8"), f"built-in {entry.name}"))
    return rules


_NOT_HOMES = ("/nonexistent", "/var/empty", "/dev/null", "/proc", "/sys", "/dev", "/run", "/var/run", "/tmp", "/bin",
              "/sbin", "/usr")  # fmt: skip


def home_bases(entries=None) -> list[str]:
    """Folders that `~/` in a rule path stands for: every user's home folder.
    Homes directly in /home are covered by /home/*; when three or more homes
    share another parent folder (/users/a, /users/b, ...), that folder's
    children are covered with one pattern."""
    bases = {"/home/*", "/root"}
    candidates = [os.path.expanduser("~")]
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            candidates.append(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    if entries is None:
        try:
            entries = pwd.getpwall()
        except Exception:  # pragma: no cover - NSS problems
            entries = []
    if len(entries) < 5000:
        candidates += [e.pw_dir for e in entries if e.pw_uid >= 1000 and e.pw_uid != 65534]
    by_parent: dict[str, set] = {}
    for c in candidates:
        c = os.path.normpath(c) if c else ""
        if not c.startswith("/") or c == "/" or any(c == x or c.startswith(x + "/") for x in _NOT_HOMES):
            continue
        parent = os.path.dirname(c)
        if parent == "/home":
            continue  # covered by /home/*
        by_parent.setdefault(parent, set()).add(c)
    for parent, homes in by_parent.items():
        if len(homes) >= 3 and parent != "/":
            bases.add(parent + "/*")
        else:
            bases.update(homes)
    return sorted(bases)


def expand_path_pattern(pat: str, homes: list[str]) -> list[str]:
    """Absolute patterns for a rule path: ~/ becomes every home folder, $VAR
    is replaced when set (and the pattern is dropped when it is not)."""
    if pat.startswith("~/"):
        rest = pat[2:]
        return [f"{h.rstrip('/')}/{rest}" for h in homes]
    if pat.startswith("$"):
        m = re.match(r"^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?(.*)$", pat)
        if not m:
            return []
        value = os.environ.get(m.group(1))
        if not value or not value.startswith("/"):
            return []
        return [os.path.normpath(value + m.group(2))]
    return [pat]


def _comps(pat: str) -> list[str]:
    return [c for c in pat.split("/") if c]


class RuleSet:
    """The active rules, in priority order, plus their compiled scanner form."""

    def __init__(self, rules: list[Rule], homes: list[str] | None = None):
        self.rules = rules
        self.homes = homes if homes is not None else home_bases()
        self.by_id = {r.id: r for r in rules}
        for i, r in enumerate(rules, 1):
            r.num = i
        self.by_num = {0: UNCLASSIFIED, **{r.num: r for r in rules}}
        for r in rules:
            for key in ("within", "outside"):
                for w in getattr(r, key):
                    target = self.by_id.get(w)
                    if target is None:
                        raise RuleError(f"{r.source}: rule {r.id!r}: '{key}' refers to unknown rule {w!r}"
                                        f"{_suggest(w, self.by_id)}")  # fmt: skip
                    if target.kind != "folders":
                        raise RuleError(f"{r.source}: rule {r.id!r}: '{key}' must name folder rules, "
                                        f"but {w!r} matches files")  # fmt: skip

    @classmethod
    def load(cls, extra_files=(), disable=(), builtin: bool = True, homes=None) -> RuleSet:
        """Built-in rules, then system and user rules.d folders, then extra files.
        A later rule with the same id replaces an earlier one and takes priority."""
        layers: list[list[Rule]] = []
        if builtin:
            layers.append(builtin_rules())
        for d in rules_dirs():
            for path in sorted(_glob.glob(os.path.join(_glob.escape(d), "*.toml"))):
                layers.append(load_rules_file(path))
        for path in extra_files:
            layers.append(load_rules_file(path))
        merged: dict[str, Rule] = {}
        layer_of: dict[str, int] = {}
        for li, layer in enumerate(layers):
            for r in layer:
                merged.pop(r.id, None)
                merged[r.id] = r
                layer_of[r.id] = li
        disable = set(disable)
        unknown = disable - set(merged)
        if unknown:
            d = sorted(unknown)[0]
            raise RuleError(f"cannot disable unknown rule {d!r}{_suggest(d, merged)}; see `whatfills rules list`")
        active = []
        for r in merged.values():
            if r.id in disable:
                continue
            if any(w in disable for w in r.within + r.outside):
                # A turned-off folder rule matches nothing, so 'outside' it is
                # everywhere and 'within' it is nowhere.
                within = [w for w in r.within if w not in disable]
                if r.within and not within:
                    continue
                r = dataclasses.replace(r, within=within, outside=[w for w in r.outside if w not in disable])
            active.append(r)
        # Later layers first (user overrides win), file order within a layer.
        ordered = sorted(active, key=lambda r: -layer_of[r.id])
        return cls(ordered, homes=homes)

    def get(self, num: int) -> Rule:
        return self.by_num.get(num, UNCLASSIFIED)

    def compile(self) -> dict:
        """Scanner options for the rules (names and paths as bytes)."""
        enc = os.fsencode
        patterns = []  # (priority, specificity, rule, anchored, comps)
        for prio, r in enumerate(self.rules):
            if r.kind != "folders":
                continue
            for p in r.paths:
                for ap in expand_path_pattern(p, self.homes):
                    comps = _comps(ap)
                    if comps:
                        patterns.append((prio, 0, -len(comps), r, True, comps))
            for d in r.dirs:
                comps = _comps(d)
                if comps:
                    patterns.append((prio, 1, -len(comps), r, False, comps))
        patterns.sort(key=lambda t: t[:3])
        dir_rules = []
        for order, (_, _, _, r, anchored, comps) in enumerate(patterns):
            dir_rules.append(
                {
                    "id": r.num,
                    "order": order,
                    "anchored": anchored,
                    "comps": [enc(c) for c in comps],
                    "require_child": [enc(c) for c in r.require_child],
                    "require_sibling": [enc(c) for c in r.require_sibling],
                }
            )
        file_rules = []
        for prio, r in enumerate(self.rules):
            if r.kind != "files":
                continue
            file_rules.append(
                {
                    "id": r.num,
                    "order": prio,
                    "globs": [enc(g) for g in r.files],
                    "min_size": r.min_size,
                    "within": [self.by_id[w].num for w in r.within],
                    "not_within": [self.by_id[w].num for w in r.outside],
                    "in_dirs": [enc(os.path.normpath(d)) for d in r.in_dirs],
                }
            )
        opaque = [r.num for r in self.rules if r.opaque and r.kind == "folders"]
        return {
            "dir_rules": dir_rules,
            "file_rules": file_rules,
            "opaque_rules": opaque,
            "max_rule_id": len(self.rules),
        }


def rules_dirs() -> list[str]:
    """Folders searched for extra *.toml rule files, lowest priority first."""
    from .config import config_dirs

    return [os.path.join(d, "rules.d") for d in config_dirs()]
