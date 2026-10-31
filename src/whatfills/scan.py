"""Run a scan and hold its results."""

from __future__ import annotations

import os
import socket
import stat
import time
from dataclasses import dataclass, field

from . import fsinfo
from .config import Settings
from .probes import DeletedReport, HiddenReport, deleted_open_files, hidden_under_mounts
from .rules import Rule, RuleSet

try:
    from . import _core
except ImportError as _e:  # pragma: no cover - depends on the install
    _core = None
    _CORE_ERROR = str(_e)

IO_CLASS = {"normal": 0, "low": 2, "idle": 3}

F_UNREADABLE = 1 << 0
F_PARTIAL = 1 << 1
F_INCOMPLETE = 1 << 2
F_PRUNED = 1 << 3
F_MATCH = 1 << 4
F_CHANGED = 1 << 5
PROBLEM_FLAGS = F_UNREADABLE | F_PARTIAL | F_INCOMPLETE | F_CHANGED


class ScanError(RuntimeError):
    """The scan could not run. The message says what to do."""


def _dec(b: bytes) -> str:
    return os.fsdecode(b)


class Folder:
    """A folder in the scanned tree. Folders below the size kept by the
    effort level have no children listed (their totals are still exact)."""

    __slots__ = (
        "name", "parent", "alloc", "apparent", "files", "dirs", "mtime", "flags", "sub_flags", "err",
        "rule", "match_rule", "children", "big_files",
    )  # fmt: skip

    def __init__(self, name, parent, alloc, apparent, files, dirs, mtime, flags, sub_flags, err, rule, match_rule):
        self.name = name
        self.parent = parent
        self.alloc = alloc
        self.apparent = apparent
        self.files = files
        self.dirs = dirs
        self.mtime = mtime
        self.flags = flags
        self.sub_flags = sub_flags
        self.err = err
        self.rule = rule  # rule number that the folder's own space belongs to
        self.match_rule = match_rule  # rule number that matched exactly here, or 0
        self.children = []
        self.big_files = []

    @property
    def path(self) -> str:
        parts = []
        x = self
        while x.parent is not None:
            parts.append(x.name)
            x = x.parent
        base = x.name
        if not parts:
            return base
        return base.rstrip("/") + "/" + "/".join(reversed(parts))

    @property
    def problems(self) -> int:
        return (self.flags | self.sub_flags) & PROBLEM_FLAGS

    @property
    def pruned(self) -> bool:
        return bool(self.flags & F_PRUNED)

    def walk(self):
        stack = [self]
        while stack:
            f = stack.pop()
            yield f
            stack.extend(f.children)

    def __repr__(self) -> str:
        return f"Folder({self.path!r}, alloc={self.alloc})"


@dataclass
class FileHit:
    path: str
    alloc: int
    apparent: int
    mtime: int
    atime: int
    uid: int
    rule: int


@dataclass
class Match:
    rule: int
    outer: int
    path: str
    alloc: int
    apparent: int
    files: int
    mtime: int
    flags: int


@dataclass
class RuleTotal:
    rule: Rule
    alloc: int
    apparent: int
    files: int
    matches: int  # number of matching folders (folder rules)
    age_mtime: list
    age_atime: list
    locations: list = field(default_factory=list)  # biggest matching folders (Match)
    top_files: list = field(default_factory=list)  # biggest matching files (FileHit), file rules
    shared: int = 0  # bytes in hard-linked files also linked from elsewhere: deleting this cause would not free them


@dataclass
class ScanResult:
    root: str
    requested: str
    hostname: str
    started_at: float
    elapsed: float
    threads: int
    statx: bool
    settings: Settings
    rules: RuleSet
    mount: fsinfo.Mount | None
    space: fsinfo.Space | None
    storage: fsinfo.Storage
    tree: Folder
    totals: list  # RuleTotal for every rule with space, biggest first (unclassified included)
    top_files: list
    uids: dict
    exts: dict
    errors: list  # (path, errno, op)
    errnos: dict
    n_errors: int
    skips: list  # (path, reason, dev)
    n_skips: int
    excluded_names: int
    hardlink_dupes: int
    vanished: int
    budget_hit: bool = False
    cancelled: bool = False
    deleted: DeletedReport | None = None
    hidden: HiddenReport | None = None  # files under mount points (whole-filesystem scans)
    folders_kept: int = 0
    links: dict = field(default_factory=dict)  # files with several hard links (see the scanner's link summary)

    @property
    def whole_fs(self) -> bool:
        return self.mount is not None and self.mount.mount_point == self.root

    @property
    def partial(self) -> bool:
        return self.budget_hit or self.cancelled

    @property
    def total_alloc(self) -> int:
        return self.tree.alloc

    @property
    def total_apparent(self) -> int:
        return self.tree.apparent

    def size(self, obj) -> int:
        """Size of a folder, file or rule total in the unit the user asked for."""
        return obj.apparent if self.settings.apparent_size else obj.alloc

    @property
    def coverage(self) -> float | None:
        """Share of the filesystem's used space that the scan found, when the
        whole filesystem was scanned."""
        if not self.whole_fs or not self.space or self.space.used <= 0:
            return None
        return min(1.0, self.total_alloc / self.space.used)


def _bind_source(m: fsinfo.Mount, s: fsinfo.Mount) -> str | None:
    """Where the content of mount `m` is also reachable through mount `s` of
    the same filesystem (m is then a bind mount), or None."""
    if m.dev != s.dev:
        return None
    if not (s.root == "/" or m.root == s.root or m.root.startswith(s.root.rstrip("/") + "/")):
        return None
    rel = os.path.relpath(m.root, s.root)
    return os.path.normpath(os.path.join(s.mount_point, rel))


def _counted_elsewhere(m: fsinfo.Mount, traversed: list, root: str, mounts: list) -> str | None:
    """The path where a bind mount's content is already counted by this scan, if any."""
    for s in traversed:
        src = _bind_source(m, s)
        if src is None or not fsinfo.is_under(src, root):
            continue  # not visible elsewhere in the scanned folder: count it here
        if fsinfo.is_under(src, m.mount_point):
            continue  # hidden by this very mount, e.g. a folder bound onto itself
        if fsinfo.mount_for(src, mounts) is not s:
            continue  # hidden under another mount
        return src
    return None


def _plan_mounts(root: str, root_mount, mounts, settings: Settings):
    """Mount points under root (so the scanner can tell mounts from btrfs
    subvolumes) and which of them to skip and why: bind mounts whose content
    is counted at its other location and, when crossing filesystems, pseudo
    and memory filesystems."""
    under = fsinfo.mounts_under(root, mounts)
    mount_points = [m.mount_point for m in under]
    auto_skip: dict[str, str] = {}
    skip_types = fsinfo.PSEUDO_FSTYPES | fsinfo.DEFAULT_CROSS_SKIP_FSTYPES | set(settings.exclude_fstypes)
    traversed = [root_mount] if root_mount is not None else []
    for m in sorted(under, key=lambda m: m.mount_point.count("/")):
        if any(fsinfo.is_under(m.mount_point, p) for p in auto_skip):
            continue  # inside a mount we already skip
        if settings.one_file_system and (root_mount is None or m.dev != root_mount.dev):
            continue  # another filesystem: the scanner does not enter it
        if not settings.one_file_system and m.fstype in skip_types:
            auto_skip[m.mount_point] = f"{m.fstype} filesystem"
            continue
        if not settings.one_file_system and m.is_network:
            # Walking a big network share by accident can take hours and load
            # the server; scanning it directly is a deliberate choice.
            auto_skip[m.mount_point] = f"{m.fstype} network filesystem"
            continue
        src = _counted_elsewhere(m, traversed, root, mounts)
        if src is not None:
            auto_skip[m.mount_point] = f"bind mount of {src}, counted there"
            continue
        traversed.append(m)
    return mount_points, auto_skip


def _resolve_exclude(path: str) -> list:
    """An exclude path as the scanner will see it: symlinks in the folders
    leading to it are resolved (the scan walks real paths), the last part is
    kept as is, so excluding a symlink does not exclude what it points to."""
    path = os.path.normpath(path)
    if path == "/":
        return [path]
    real = os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path))
    return [path] if real == path else [path, real]


def exclude_paths(settings: Settings) -> list:
    out: list = []
    for p in settings.exclude_paths:
        for x in _resolve_exclude(p):
            if x not in out:
                out.append(x)
    return out


def build_options(root: str, settings: Settings, rules: RuleSet, threads: int, mount_points, auto_skip) -> dict:
    p = settings.preset()
    enc = os.fsencode
    opts = {
        "root": enc(root),
        "threads": threads,
        "one_file_system": settings.one_file_system,
        "cross_subvolumes": settings.cross_subvolumes,
        "dont_sync": p["dont_sync"],
        "collect_ext": p["collect_ext"],
        "by_apparent": settings.apparent_size,
        "io_class": IO_CLASS[settings.io_priority],
        "nice": 10 if settings.io_priority != "normal" else 0,
        "keep_dir_min": p["keep_dir_min"],
        "big_file_min": max(p["big_file_min"], p["keep_dir_min"]),
        "top_files": max(p["top_files"], settings.top),
        "matches_per_rule": p["matches_per_rule"],
        "files_per_rule": p["files_per_rule"],
        "max_links": p["max_links"],
        "now": int(time.time()),
        "exclude_paths": [enc(x) for x in exclude_paths(settings) + list(auto_skip)],
        "exclude_names": [enc(x) for x in settings.exclude_names],
        "exclude_globs": [enc(x) for x in settings.exclude_globs],
        "mount_points": [enc(x) for x in mount_points],
    }
    opts.update(rules.compile())
    return opts


def run_scan(target: str, settings: Settings, rules: RuleSet, on_progress=None, interval: float = 0.1) -> ScanResult:
    """Scan `target` and return the results. `on_progress(info)` is called
    about every `interval` seconds while scanning. Ctrl-C stops the scan and
    returns what was found so far (result.cancelled is then True)."""
    if _core is None:
        raise ScanError(
            "whatfills's compiled scanner (whatfills._core) could not be loaded: "
            f"{_CORE_ERROR}. Reinstall with `pip install --force-reinstall whatfills`; "
            "installing from source needs a C++17 compiler."
        )
    requested = target
    target = os.path.expanduser(target)
    root = _check_target(target, requested)
    for p in exclude_paths(settings):
        if fsinfo.is_under(root, p):
            raise ScanError(f"{root} is excluded by your settings (exclude path {p}); remove it from the exclusions to scan it")

    mounts = fsinfo.read_mounts()
    root_mount = fsinfo.mount_for(root, mounts)
    space = fsinfo.space(root)
    storage = fsinfo.storage_kind(root_mount)
    threads = settings.threads or fsinfo.default_threads(storage)
    mount_points, auto_skip = _plan_mounts(root, root_mount, mounts, settings)
    opts = build_options(root, settings, rules, threads, mount_points, auto_skip)
    budget = settings.preset()["time_budget"]

    scanner = _core.Scanner(opts)
    started_at = time.time()
    t0 = time.monotonic()
    try:
        scanner.start()
    except RuntimeError as e:
        msg = str(e)
        if "Permission denied" in msg:
            msg += ". Try running it with sudo."
        raise ScanError(msg) from None

    budget_hit = cancelled = False
    used = space.used if space and root_mount and root_mount.mount_point == root else None
    while True:
        try:
            done = scanner.wait(interval)
        except KeyboardInterrupt:
            scanner.cancel()
            cancelled = True
            continue
        if done:
            break
        elapsed = time.monotonic() - t0
        if budget and elapsed >= budget and not budget_hit and not cancelled:
            scanner.cancel()
            budget_hit = True
        if on_progress is not None:
            info = scanner.progress()
            info.update(elapsed=elapsed, budget=budget, used=used, stopping=budget_hit or cancelled)
            try:
                on_progress(info)
            except KeyboardInterrupt:
                scanner.cancel()
                cancelled = True

    raw = scanner.result()
    mount_types = {m.mount_point: m.fstype for m in fsinfo.mounts_under(root, mounts)}
    result = _build_result(raw, root, requested, settings, rules, root_mount, space, storage, started_at, auto_skip,
                           mount_types)  # fmt: skip
    result.budget_hit = budget_hit
    result.cancelled = cancelled
    if root_mount is not None and result.whole_fs:
        try:
            result.deleted = deleted_open_files(os.stat(root).st_dev)
        except OSError:
            result.deleted = None
        if not result.partial and space is not None and space.used - result.total_alloc > (256 << 20):
            if on_progress is not None:
                on_progress({"message": "Checking for files hidden under mount points"})
            result.hidden = hidden_under_mounts(root_mount, mounts)
    return result


def _check_target(target: str, requested: str) -> str:
    """The real path of the folder to scan, or a ScanError that says what is wrong."""
    try:
        os.lstat(target)
    except FileNotFoundError:
        raise ScanError(f"{requested}: no such file or folder") from None
    except PermissionError:
        raise ScanError(f"{requested}: permission denied on a folder leading to it. Try running it with sudo.") from None
    except OSError as e:
        raise ScanError(f"{requested}: {e.strerror}") from None
    root = os.path.realpath(target)
    try:
        st = os.stat(root)
    except FileNotFoundError:
        raise ScanError(f"{requested} is a link to {root}, which does not exist") from None
    except PermissionError:
        raise ScanError(f"{requested}: permission denied. Try running it with sudo.") from None
    except OSError as e:
        raise ScanError(f"{requested}: {e.strerror}") from None
    if stat.S_ISREG(st.st_mode):
        raise ScanError(f"{requested} is a file, not a folder. whatfills scans folders; try its parent folder.")
    if not stat.S_ISDIR(st.st_mode):
        raise ScanError(f"{requested} is not a folder")
    return root


def _skip_reason(path: str, reason: str, auto_skip: dict, mount_types: dict) -> str:
    """Say why a path was skipped in the words the report uses."""
    if reason == "excluded" and path in auto_skip:
        return auto_skip[path]
    if reason == "mount":
        fstype = mount_types.get(path, "")
        if fstype in fsinfo.NETWORK_FSTYPES:
            return f"{fstype} network filesystem"
        if fstype in fsinfo.PSEUDO_FSTYPES or fstype in fsinfo.DEFAULT_CROSS_SKIP_FSTYPES:
            return f"{fstype} filesystem"  # kernel, memory or image filesystems: not on this disk
    return reason


def _build_result(raw, root, requested, settings, rules, mount, space, storage, started_at, auto_skip,
                  mount_types=None) -> ScanResult:  # fmt: skip
    nodes = raw["nodes"]
    folders = []
    for parent, name, alloc, apparent, files, dirs, mtime, flags, sub_flags, err, eff, match in nodes:
        f = Folder(_dec(name), folders[parent] if parent >= 0 else None, alloc, apparent, files, dirs, mtime, flags,
                   sub_flags, err, eff, match)  # fmt: skip
        if parent >= 0:
            folders[parent].children.append(f)
        folders.append(f)
    key = (lambda c: c.apparent) if settings.apparent_size else (lambda c: c.alloc)
    for f in folders:
        f.children.sort(key=key, reverse=True)
    for idx, name, alloc, apparent, mtime, atime, uid, rule in raw["big_files"]:
        owner = folders[idx]
        owner.big_files.append(FileHit(owner.path.rstrip("/") + "/" + _dec(name), alloc, apparent, mtime, atime, uid, rule))

    totals = []
    locations: dict[int, list] = {}
    for rule, outer, path, alloc, apparent, files, mtime, flags in raw["matches"]:
        locations.setdefault(rule, []).append(Match(rule, outer, _dec(path), alloc, apparent, files, mtime, flags))
    rule_files: dict[int, list] = {}
    for rule, path, alloc, apparent, mtime, atime, uid in raw["rule_files"]:
        rule_files.setdefault(rule, []).append(FileHit(_dec(path), alloc, apparent, mtime, atime, uid, rule))
    for num, (alloc, apparent, files, matches, age_m, age_a, shared) in enumerate(raw["rules"]):
        if alloc == 0 and apparent == 0 and files == 0:
            continue
        totals.append(
            RuleTotal(rules.get(num), alloc, apparent, files, matches, list(age_m), list(age_a),
                      locations.get(num, []), rule_files.get(num, []), shared)  # fmt: skip
        )
    key = (lambda t: t.apparent) if settings.apparent_size else (lambda t: t.alloc)
    totals.sort(key=key, reverse=True)

    skips = []
    for path, reason, dev in raw["skips"]:
        p = _dec(path)
        skips.append((p, _skip_reason(p, reason, auto_skip, mount_types or {}), dev))

    stats = raw["stats"]
    return ScanResult(
        root=root,
        requested=requested,
        hostname=socket.gethostname(),
        started_at=started_at,
        elapsed=stats["elapsed"],
        threads=stats["threads"],
        statx=stats["statx"],
        settings=settings,
        rules=rules,
        mount=mount,
        space=space,
        storage=storage,
        tree=folders[0],
        totals=totals,
        top_files=[FileHit(_dec(p), a, ap, m, at, u, r) for p, a, ap, m, at, u, r in raw["top_files"]],
        uids=dict(raw["uids"]),
        exts={_dec(k): v for k, v in raw["exts"].items()},
        errors=[(_dec(p), e, op) for p, e, op in raw["errors"]],
        errnos=dict(raw["errnos"]),
        n_errors=stats["errors"],
        skips=skips,
        n_skips=stats["skips"],
        excluded_names=stats["excluded_names"],
        hardlink_dupes=stats["hardlink_dupes"],
        vanished=stats["vanished"],
        folders_kept=len(folders),
        links=dict(raw["links"]),
    )
