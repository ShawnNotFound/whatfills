"""Saved scans and comparisons between them ("what grew since last time")."""

from __future__ import annotations

import datetime
import gzip
import hashlib
import json
import os
import tempfile

from .report import SCHEMA_VERSION, to_dict
from .term import Style, display_width, shorten_path, show
from .units import format_size

KIND = "whatfills-snapshot"


class SnapshotError(ValueError):
    pass


def state_dir() -> str:
    base = os.environ.get("XDG_STATE_HOME")
    if not base or not os.path.isabs(base):
        base = os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "whatfills")


def snapshot_dir(root: str) -> str:
    slug = root.strip("/").replace("/", "_") or "root"
    slug = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in slug)[:60]
    digest = hashlib.sha1(os.fsencode(root)).hexdigest()[:8]
    return os.path.join(state_dir(), "snapshots", f"{slug}-{digest}")


def save(result, path: str | None = None) -> str:
    """Write a compressed snapshot of a scan. Returns the file path."""
    data = to_dict(result, top=1000, all_folders=True)
    data["kind"] = KIND
    if not path:
        # Names sort in time order; milliseconds keep two quick scans apart.
        d = snapshot_dir(result.root)
        t = datetime.datetime.fromtimestamp(result.started_at)
        ms = t.microsecond // 1000
        while True:
            path = os.path.join(d, f"{t.strftime('%Y%m%d-%H%M%S')}-{ms:03d}.json.gz")
            if not os.path.exists(path) or ms >= 999:
                break
            ms += 1
    path = os.path.abspath(os.path.expanduser(path))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".whatfills-", suffix=".tmp", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb") as gz:
            gz.write(json.dumps(data, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def load(path: str) -> dict:
    try:
        with open(path, "rb") as f:
            head = f.read(2)
            f.seek(0)
            raw = gzip.decompress(f.read()) if head == b"\x1f\x8b" else f.read()
        data = json.loads(raw)
    except FileNotFoundError:
        raise SnapshotError(f"snapshot not found: {path}") from None
    except (OSError, ValueError, EOFError) as e:
        raise SnapshotError(f"{path} is not a readable whatfills snapshot: {e}") from None
    if not isinstance(data, dict) or data.get("kind") != KIND:
        raise SnapshotError(f"{path} is not a whatfills snapshot (save one with `whatfills --save`)")
    if data.get("schema", 0) > SCHEMA_VERSION:
        raise SnapshotError(f"{path} was written by a newer whatfills (schema {data.get('schema')}); please upgrade")
    return data


def list_snapshots(root: str) -> list[str]:
    d = snapshot_dir(root)
    try:
        names = sorted(n for n in os.listdir(d) if n.endswith(".json.gz"))
    except FileNotFoundError:
        return []
    return [os.path.join(d, n) for n in names]


def all_roots() -> list[str]:
    """Folders that have saved snapshots, most recently saved first."""
    base = os.path.join(state_dir(), "snapshots")
    try:
        dirs = [os.path.join(base, d) for d in os.listdir(base)]
    except FileNotFoundError:
        return []
    found = []
    for d in dirs:
        try:
            names = sorted(n for n in os.listdir(d) if n.endswith(".json.gz"))
        except OSError:
            continue
        if not names:
            continue
        newest = os.path.join(d, names[-1])
        try:
            root = load(newest).get("root")
        except SnapshotError:
            continue
        if isinstance(root, str) and snapshot_dir(root) == d:
            found.append((os.path.getmtime(newest), root))
    return [root for _, root in sorted(found, reverse=True)]


def latest_root() -> str | None:
    """The folder whose snapshot was saved most recently."""
    roots = all_roots()
    return roots[0] if roots else None


def _parent(path: str) -> str:
    p = os.path.dirname(path.rstrip("/")) or "/"
    return p


def diff(old: dict, new: dict, top: int = 15, min_change: int | None = None) -> dict:
    """Compare two snapshots of the same folder."""
    of = {f["path"]: f for f in old.get("folders", [])}
    nf = {f["path"]: f for f in new.get("folders", [])}
    deltas = {}
    for path in set(of) | set(nf):
        a, b = of.get(path), nf.get(path)
        if a is None:
            parent = of.get(_parent(path))
            if parent is None or not parent.get("children_kept", True):
                continue  # not comparable: the old scan did not keep this level
            old_bytes = 0
        else:
            old_bytes = a["bytes"]
        if b is None:
            parent = nf.get(_parent(path))
            if parent is None or not parent.get("children_kept", True):
                continue
            new_bytes = 0
        else:
            new_bytes = b["bytes"]
        if new_bytes != old_bytes:
            deltas[path] = (old_bytes, new_bytes)

    total_change = abs(new["scanned"]["bytes"] - old["scanned"]["bytes"])
    if min_change is None:
        min_change = max(64 << 20, total_change // 100)
    cands = {p: v for p, v in deltas.items() if abs(v[1] - v[0]) >= min_change}

    def is_under(p: str, q: str) -> bool:
        return p != q and (q == "/" or p.startswith(q.rstrip("/") + "/"))

    # Keep the most specific folders: drop a folder when one folder inside it
    # explains most (80%) of its change in the same direction.
    keep = []
    for p, (a, b) in cands.items():
        d = b - a
        explained = any(
            is_under(q, p) and (qb - qa) * d > 0 and abs(qb - qa) >= 0.8 * abs(d) for q, (qa, qb) in cands.items()
        )
        if not explained:
            keep.append({"path": p, "old": a, "new": b, "change": d})
    keep.sort(key=lambda x: abs(x["change"]), reverse=True)

    oc = {c["id"]: c for c in old.get("causes", [])}
    nc = {c["id"]: c for c in new.get("causes", [])}
    causes = []
    for cid in set(oc) | set(nc):
        a = oc.get(cid, {}).get("bytes", 0)
        b = nc.get(cid, {}).get("bytes", 0)
        if a != b:
            name = (nc.get(cid) or oc.get(cid))["name"]
            causes.append({"id": cid, "name": name, "old": a, "new": b, "change": b - a})
    causes.sort(key=lambda x: abs(x["change"]), reverse=True)

    def fs_used(d):
        fs = d.get("filesystem") or {}
        return fs.get("used")

    return {
        "root": new.get("root"),
        "old_time": old.get("started_at"),
        "new_time": new.get("started_at"),
        "scanned_old": old["scanned"]["bytes"],
        "scanned_new": new["scanned"]["bytes"],
        "used_old": fs_used(old),
        "used_new": fs_used(new),
        "folders": keep[:top],
        "causes": [c for c in causes if abs(c["change"]) >= min(min_change, 1 << 20)][:top],
        "min_change": min_change,
        "partial": bool(old.get("partial") or new.get("partial")),
    }


def _signed(n: int) -> str:
    return ("+" if n > 0 else "-" if n < 0 else "±") + format_size(abs(n))


def render_diff(d: dict, style: Style, cols: int = 100) -> str:
    s = style
    out = [s.bold(f"Changes in {show(d['root'] or '?')}") + f"  {d['old_time']} → {d['new_time']}"]
    out.append(
        f"Scanned total: {format_size(d['scanned_old'])} → {format_size(d['scanned_new'])} "
        f"({_signed(d['scanned_new'] - d['scanned_old'])})"
    )
    if d["used_old"] is not None and d["used_new"] is not None:
        out.append(f"Filesystem used: {format_size(d['used_old'])} → {format_size(d['used_new'])} "
                   f"({_signed(d['used_new'] - d['used_old'])})")  # fmt: skip
    if d["partial"]:
        out.append(s.yellow("One of the scans was partial, so some changes may be missing or overstated."))
    out.append("")
    if d["causes"]:
        out.append(s.bold("By cause"))
        for c in d["causes"]:
            ch = _signed(c["change"])
            ch = s.red(f"{ch:>12}") if c["change"] > 0 else s.green(f"{ch:>12}")
            out.append(f"  {ch}  {c['name']}  ({format_size(c['old'])} → {format_size(c['new'])})")
        out.append("")
    if d["folders"]:
        out.append(s.bold("Where it changed"))
        for f in d["folders"]:
            ch = _signed(f["change"])
            ch = s.red(f"{ch:>12}") if f["change"] > 0 else s.green(f"{ch:>12}")
            prefix = f"  {ch}  "
            room = max(10, cols - display_width(prefix) - 30)
            out.append(prefix + shorten_path(show(f["path"]), room)
                       + s.dim(f"  ({format_size(f['old'])} → {format_size(f['new'])})"))  # fmt: skip
        out.append("")
    if not d["causes"] and not d["folders"]:
        out.append(f"No folder changed by more than {format_size(d['min_change'])}.")
    return "\n".join(out).rstrip() + "\n"
