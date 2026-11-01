"""Text and JSON reports for a scan."""

from __future__ import annotations

import datetime
import errno as errno_mod
import os
import pwd
import shlex
import textwrap

from . import __version__, fsinfo
from .rules import CATEGORIES, SAFETY, UNCLASSIFIED
from .scan import F_CHANGED, F_INCOMPLETE, F_PARTIAL, F_UNREADABLE, Folder, ScanResult
from .term import Style, clip, display_width, home_short, shorten_middle, shorten_path, show
from .units import format_age, format_count, format_duration, format_size

SCHEMA_VERSION = 1
_OLD_BUCKETS = slice(4, None)  # 90 days and older


_names: dict = {}


def user_name(uid: int) -> str:
    if uid not in _names:
        try:
            _names[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _names[uid] = str(uid)
    return _names[uid]


def _errno_name(e: int) -> str:
    return errno_mod.errorcode.get(e, str(e))


def _use_atime(r: ScanResult) -> bool:
    return r.mount is None or r.mount.atime_mode != "noatime"


def old_share(r: ScanResult, total) -> float:
    """Share of a rule's bytes not used (or, on noatime mounts, not changed) for 90+ days."""
    ages = total.age_atime if _use_atime(r) else total.age_mtime
    s = sum(ages)
    return sum(ages[_OLD_BUCKETS]) / s if s else 0.0


def _pct(part: float, whole: float) -> str:
    if whole <= 0:
        return "  -  "
    p = 100.0 * part / whole
    return f"{p:4.1f}%" if p < 99.95 else " 100%"


def _sudo(cmd: str, root: bool) -> str:
    """Prefix sudo for commands that need root, unless the user is really
    root. Under sudo the commands are still shown with it, since they are
    usually pasted into the user's own shell."""
    as_root = os.geteuid() == 0 and not os.environ.get("SUDO_USER")
    return f"sudo {cmd}" if root and not as_root and not cmd.startswith("sudo ") else cmd


def _where(r: ScanResult, t) -> tuple:
    """(count, path) describing where a cause's space is: how many folders or
    files it is in (empty when there is one) and the biggest of them."""
    if t.rule is UNCLASSIFIED or t.rule.num == 0:
        return "see the largest folders below", ""
    if t.rule.kind == "files":
        if not t.top_files:
            return f"{format_count(t.files)} files", ""
        biggest = home_short(show(t.top_files[0].path))
        return ("", biggest) if t.files == 1 else (f"{format_count(t.files)} files", biggest)
    if not t.locations:
        return "", ""
    biggest = home_short(show(t.locations[0].path))
    return ("", biggest) if t.matches <= 1 else (f"{format_count(t.matches)} folders", biggest)


def _where_text(r: ScanResult, t, room: int = 10_000, strict: bool = False) -> str | None:
    """_where as text of at most `room` columns; the path is shortened to fit,
    or left out when only the count fits. With `strict`, None instead when the
    path would be left out or lose its start ("~" or "/")."""
    count, path = _where(r, t)
    if not path:
        return count
    lead = f"{count}, biggest " if count else ""
    if lead and display_width(lead) + 12 > room:
        return None if strict else count
    short = shorten_path(path, room - display_width(lead))
    if strict and path[0] in "~/" and short[0] not in "~/":
        return None
    return lead + short


def _has_own_name(rule, folder: str) -> bool:
    """Whether a folder that a rule matched has a name of its own rather than
    the fixed name in the rule: a virtual environment called .venv-tvm
    (dirs = ["*"]) has one, a node_modules folder does not."""
    name = folder.rstrip("/").rsplit("/", 1)[-1]
    lasts = [p.rstrip("/").rsplit("/", 1)[-1] for p in rule.dirs + rule.paths]
    return name not in lasts and any(any(c in x for c in "*?[") for x in lasts)


def _cause_folders(r: ScanResult) -> dict:
    """Rule number -> the folders it matched that have names of their own,
    deepest first."""
    out = {}
    for t in r.totals:
        own = [m.path for m in t.locations if _has_own_name(t.rule, m.path)]
        if own:
            out[t.rule.num] = sorted(own, key=len, reverse=True)
    return out


def _short_file_path(path: str, room: int, folders: list) -> str:
    """A file's path for display. When it is inside one of `folders` (a
    virtual environment or conda environment, found by what it holds), that
    folder is kept in view if there is room."""
    shown = home_short(show(path))
    for d in folders:
        if path.startswith(d.rstrip("/") + "/"):
            return shorten_path(shown, room, keep=len([x for x in home_short(show(d)).split("/") if x]))
    return shorten_path(shown, room)


def _wrap(text: str, w: int, **kw) -> list:
    """textwrap.wrap that never splits a word, a path or a key like max-file."""
    return textwrap.wrap(text, width=max(20, w), break_long_words=False, break_on_hyphens=False, **kw)


def _para(text: str, w: int, indent: str = "  ", hang: str | None = None, style=None) -> list:
    """Wrap prose to the terminal width (long paths are not broken)."""
    lines = _wrap(text, max(30, w), initial_indent=indent,
                  subsequent_indent=indent if hang is None else hang) or [indent.rstrip()]  # fmt: skip
    return [style(x) for x in lines] if style else lines


def _bar(frac: float, length: int) -> str:
    filled = round(min(1.0, max(0.0, frac)) * length)
    return "█" * filled + "░" * (length - filled)


def hidden_checkable(r: ScanResult) -> bool:
    """Whether other filesystems are mounted inside the scanned one (so files could hide under them)."""
    return any(_skip_kind(why) in ("mount", "subvolume", "special", "network", "bind") for _, why, _ in r.skips)


def _plural(n: int, noun: str) -> str:
    return f"{format_count(n)} {noun}" + ("" if n == 1 else "s")


def _skip_kind(why: str) -> str:
    if why.startswith("bind mount of "):
        return "bind"
    if why.endswith(" network filesystem"):
        return "network"
    if why.endswith(" filesystem"):
        fstype = why[: -len(" filesystem")]
        # kernel, memory and image filesystems hold nothing on this disk
        special = fstype in fsinfo.PSEUDO_FSTYPES or fstype in fsinfo.DEFAULT_CROSS_SKIP_FSTYPES
        return "special" if special else "mount"
    return why


def _shared_matters(t) -> bool:
    """Worth saying that deleting this cause frees less than its size."""
    return t.rule.num != 0 and t.shared >= max(64 << 20, 0.05 * t.alloc)


def _flags_note(flags: int) -> str:
    notes = []
    if flags & F_UNREADABLE:
        notes.append("some folders unreadable")
    elif flags & F_PARTIAL:
        notes.append("some entries unreadable")
    if flags & F_INCOMPLETE:
        notes.append("not finished")
    if flags & F_CHANGED:
        notes.append("changed during scan")
    return ", ".join(notes)


def _chain(f: Folder, size) -> tuple:
    """Follow single dominant children so 'var' -> 'var/lib/docker' when one
    child holds 90% or more of its parent."""
    names = [f.name]
    while f.children:
        c = f.children[0]
        if size(f) <= 0 or size(c) < 0.9 * size(f):
            break
        names.append(c.name)
        f = c
    return "/".join(names), f


def render_text(r: ScanResult, style: Style, top: int = 10, cols: int = 100) -> str:
    out: list[str] = []
    size = r.size
    total = size(r.tree)
    s = style
    w = cols

    # Header
    fs_desc = ""
    if r.mount is not None:
        kind = {"ssd": "SSD", "hdd": "HDD", "virtual": "virtual disk", "network": "network", "memory": "memory"}.get(
            r.storage.kind, "")  # fmt: skip
        src = r.mount.source if r.mount.source not in ("none", "") else r.mount.fstype
        fs_desc = f" on {r.mount.fstype} ({show(src)}{', ' + kind if kind else ''})"
    out.append(s.bold(f"whatfills {__version__}") + f"  {show(r.root)}{fs_desc}")
    mode = "file sizes" if r.settings.apparent_size else "disk usage"
    # Whole numbers here, so the two counts read alike (151,203 files in 17,044 folders).
    out += _para(f"Scanned {r.tree.files:,} files in {r.tree.dirs + 1:,} folders "
                 f"in {format_duration(r.elapsed)} ({r.settings.effort} effort, {r.threads} threads, {mode}).", w, "")  # fmt: skip
    if r.partial:
        why = "the time budget ran out" if r.budget_hit else "you pressed Ctrl-C"
        cov = f", about {100 * r.coverage:.0f}% of the used space" if r.coverage is not None else ""
        if not r.budget_hit:
            hint = "Run it again and let it finish for the full picture."
        elif r.settings.effort == "quick":
            hint = "Run with --effort normal (or a longer --budget) for the full picture."
        else:
            hint = "Use a longer --budget, or none, for the full picture."
        out += _para(f"Partial results: the scan stopped because {why}. Found {format_size(total)}{cov}. {hint}", w, "",
                     style=s.yellow)  # fmt: skip
    out.append("")

    # Disk and what the scan could not see
    if r.space is not None and r.whole_fs:
        sp = r.space
        frac = sp.used_fraction
        colour = s.red if frac >= 0.95 else s.yellow if frac >= 0.85 else s.green
        out.append(s.bold("Disk"))
        summary = f"  {format_size(sp.total)} total, {format_size(sp.used)} used, {format_size(sp.avail)} free for normal users"
        bar_len = min(40, w - len(summary) - 7)
        if bar_len >= 10:
            out.append(summary + "  " + colour(_bar(frac, bar_len)) + f" {sp.used_percent}%")
        else:
            out.append("  " + colour(_bar(frac, max(10, min(40, w - 9)))) + f" {sp.used_percent}%")
            out += _para(summary.strip(), w)
        if sp.reserved > 0:
            if r.mount and r.mount.fstype in ("ext2", "ext3", "ext4"):
                out += _para(f"{format_size(sp.reserved)} more is reserved for root (only root can write there).", w)
            else:
                out += _para(f"{format_size(sp.reserved)} more is counted as free, but the filesystem keeps it in "
                             "reserve, so normal users cannot use it.", w)  # fmt: skip
        if sp.inodes_total and sp.inodes_fraction >= 0.9:
            out += _para(f"{100 * sp.inodes_fraction:.0f}% of inodes (file slots) are used. New files can fail with "
                         "'No space left on device' even when bytes are free; folders with the most files are listed "
                         "below.", w, style=s.red)  # fmt: skip
        found = r.total_alloc
        gap = sp.used - found
        out += _para(f"The scan found {format_size(found)} in files and folders ({_pct(found, sp.used).strip()} of used).", w)
        if not r.partial and gap > max(256 << 20, 0.01 * sp.used):
            out.append(f"  Not found by the scan: {format_size(gap)}. Likely reasons:")
            explained = 0
            reasons = []
            if r.deleted and r.deleted.total_alloc:
                reasons.append((format_size(r.deleted.total_alloc), "deleted files that running programs still hold open (see below)"))
                explained += r.deleted.total_alloc
            hidden = r.hidden
            if hidden is not None and not hidden.error and hidden.total_alloc:
                reasons.append((format_size(hidden.total_alloc),
                                f"files hidden under {_plural(len(hidden.found), 'mount point')} (see below)"))  # fmt: skip
                explained += hidden.total_alloc
            if r.n_errors:
                reasons.append(("", f"{format_count(r.n_errors)} entries could not be read"
                                + ("" if os.geteuid() == 0 else "; run with sudo to include them")))  # fmt: skip
            subvols = [p for p, why, _ in r.skips if why == "subvolume"]
            if subvols:
                reasons.append(("", f"{_plural(len(subvols), 'btrfs subvolume')} not entered (--cross-subvolumes)"))
            if r.mount and r.mount.fstype in ("btrfs", "zfs", "bcachefs"):
                reasons.append(("", f"snapshots and filesystem metadata ({r.mount.fstype} does not show them as files)"))
            if gap - explained > 0 and (hidden is None or hidden.error) and hidden_checkable(r):
                why = "run with sudo to check" if os.geteuid() != 0 else f"could not check: {hidden.error}" if hidden else ""
                reasons.append(("", "possibly files hidden under a mount point (written there before something was "
                                    "mounted on top)" + (f"; {why}" if why else "")))  # fmt: skip
            for amount, text in reasons:
                out += _para(text, w, f"    {amount:>10}  ", " " * 16)
        elif gap < -max(256 << 20, 0.01 * sp.used):
            out += _para("The files add up to more than the filesystem reports as used, which happens with "
                         "compression or shared (reflinked or deduplicated) data.", w)  # fmt: skip
        out.append("")
    elif r.space is not None:
        sp = r.space
        mp = show(r.mount.mount_point) if r.mount else "?"
        out += _para(f"This folder holds {format_size(total)}. Its filesystem ({mp}) has {format_size(sp.total)} total, "
                     f"{format_size(sp.used)} used ({sp.used_percent}%), {format_size(sp.avail)} free.", w, "")  # fmt: skip
        out.append("")

    # Causes
    out.append(s.bold("Why it's full: space by cause"))
    rows = []
    safe_bytes = 0
    for t in r.totals:
        if t.rule.safety in ("safe", "regenerable") and t.rule.num != 0:
            safe_bytes += size(t)
    for t in r.totals:
        if len(rows) >= top + 2:
            break
        if size(t) <= 0:
            continue
        if t.rule.num != 0 and total and size(t) < 0.001 * total and len(rows) >= 3:
            continue
        rows.append(t)
    name_w = min(44, max([display_width(t.rule.name) for t in rows] + [10]))
    for t in rows:
        name = t.rule.name
        name = clip(name, name_w)
        safety = t.rule.safety if t.rule.num != 0 else ""
        old = old_share(r, t)
        extra = ""
        if t.rule.num != 0 and t.rule.safety != "caution" and old >= 0.5 and size(t) >= (1 << 30):
            verb = "used" if _use_atime(r) else "changed"
            extra = f" ({100 * old:.0f}% not {verb} in 90+ days)"
        prefix = f"  {format_size(size(t)):>10}  {_pct(size(t), total)}  "
        indent = " " * display_width(prefix)
        line = prefix + name + " " * (name_w - display_width(name)) + "  " + s.safety(safety, safety.ljust(11)) + "  "
        room = w - display_width(prefix) - name_w - 15 - len(extra)
        where = _where_text(r, t, room, strict=True) if room >= 32 else None
        if where is not None:
            out.append(line + s.dim(where + extra))
        else:
            # Where the space is goes under the name, and the note after it
            # if both fit, else on a line of its own.
            out.append(line.rstrip())
            room = w - len(indent)
            if room - len(extra) >= 32:
                out.append(indent + s.dim(_where_text(r, t, room - len(extra)) + extra))
            else:
                out.append(indent + s.dim(_where_text(r, t, room)))
                if extra:
                    out.append(indent + s.dim(extra.strip()))
        if _shared_matters(t):
            note = f"{format_size(t.shared)} of it is hard-linked from elsewhere, so deleting it frees less"
            out += [indent + s.dim(x) for x in _wrap(note, w - len(indent))]
    if not rows:
        out.append("  Nothing found.")
    if safe_bytes and total:
        amount = f"{format_size(safe_bytes)} ({_pct(safe_bytes, total).strip()})"
        lines = _para(f"{amount} is caches or files that can be rebuilt or downloaded again.", w)
        lines[0] = lines[0].replace(amount, s.green(amount), 1)
        out += lines
    out.append("")

    # Largest folders
    if r.tree.children:
        out.append(s.bold("Largest folders"))
        out.append(f"  {format_size(total):>10}  {_pct(total, total)}  {show(r.root)}")
        limits = [top, max(3, top // 2), 3]

        locs = [m for t in r.totals for m in t.locations]
        loc_at = {m.path: m for m in locs}

        def cause_of(c: Folder, end: Folder) -> str:
            """The cause to show next to a folder (c, or the chain c/.../end):
            the rule that matched there if it holds most of the space, else
            the cause that does, if one does."""
            matched = []
            x = end
            while x is not None:
                if x.match_rule:
                    matched.append(x)  # deepest first
                if x is c:
                    break
                x = x.parent
            if not matched:
                return ""
            here = size(c)
            for n in matched:
                m = loc_at.get(n.path)
                if m is None or size(m) >= 0.5 * here:
                    return r.rules.get(n.match_rule).name
            base = c.path.rstrip("/") + "/"
            by_rule: dict = {}
            for m in locs:
                if m.path == c.path or m.path.startswith(base):
                    by_rule[m.rule] = by_rule.get(m.rule, 0) + size(m)
            rule, held = max(by_rule.items(), key=lambda kv: kv[1], default=(0, 0))
            return "mostly " + r.rules.get(rule).name if rule and held >= 0.5 * here else ""

        def add(f: Folder, depth: int, indent: str) -> None:
            if depth >= len(limits):
                return
            kids = [c for c in f.children if size(c) >= max(1, (0.01 if depth == 0 else 0.02) * total)]
            for i, c in enumerate(kids[: limits[depth]]):
                label, end = _chain(c, size)
                cause = cause_of(c, end)
                tag = "  " + s.dim(f"[{cause}]") if cause else ""
                note = _flags_note(end.problems)
                if note:
                    tag += "  " + s.yellow(f"({note})")
                branch = "└─ " if i == len(kids[: limits[depth]]) - 1 else "├─ "
                prefix = f"  {format_size(size(c)):>10}  {_pct(size(c), total)}  {indent}{branch}"
                room = max(10, w - display_width(prefix) - 2)
                out.append(prefix + shorten_middle(show(label), room) + tag)
                add(end, depth + 1, indent + ("   " if branch == "└─ " else "│  "))

        add(r.tree, 0, "")
        out.append("")

    # Largest files
    if r.top_files:
        owners = {f.uid for f in r.top_files[:top]}
        out.append(s.bold("Largest files"))
        now = r.started_at
        ages = [format_age(max(0, now - f.mtime)) for f in r.top_files[:top]]
        age_w = max(len(a) for a in ages)
        who_w = max(len(user_name(f.uid)) for f in r.top_files[:top])
        cause_folders = _cause_folders(r)
        for f, age in zip(r.top_files[:top], ages):
            who = f"  {user_name(f.uid):<{who_w}}" if len(owners) > 1 else ""
            prefix = f"  {format_size(size(f)):>10}  {age:>{age_w}}{who}  "
            room = max(10, w - display_width(prefix))
            out.append(prefix + _short_file_path(f.path, room, cause_folders.get(f.rule, [])))
        out.append(s.dim("  (age = time since the file was last changed)"))
        out.append("")

    # Inode pressure: where the files are
    if r.space is not None and r.whole_fs and r.space.inodes_total and r.space.inodes_fraction >= 0.9:
        out.append(s.bold("Folders with the most files"))
        cands = sorted((f for f in r.tree.walk() if f.parent is not None), key=lambda f: f.files, reverse=True)
        listed = []
        for f in cands:
            if len(listed) >= top:
                break
            if any(f.path.startswith(x.path.rstrip("/") + "/") and f.files >= 0.8 * x.files for x in listed):
                continue
            listed = [x for x in listed if not (x.path.startswith(f.path.rstrip("/") + "/"))]
            listed.append(f)
        for f in listed:
            out.append(f"  {format_count(f.files):>10} files  {shorten_path(show(f.path), w - 22)}")
        out.append("")

    # Owners
    if r.uids and total:
        sig = sorted(r.uids.items(), key=lambda kv: kv[1][0], reverse=True)
        if len(sig) > 1 and sig[1][1][0] >= 0.02 * total:
            out.append(s.bold("By owner"))
            for uid, (alloc, files) in sig[:top]:
                if alloc < 0.005 * total:
                    break
                out.append(f"  {format_size(alloc):>10}  {_pct(alloc, total)}  {user_name(uid):<16} {format_count(files)} files")
            out.append("")

    # File types (deep effort)
    if r.exts and r.settings.effort == "deep":
        out.append(s.bold("By file type"))
        for ext, (alloc, files) in sorted(r.exts.items(), key=lambda kv: kv[1][0], reverse=True)[:top]:
            label = f".{show(ext)}" if ext else "(no extension)"
            out.append(f"  {format_size(alloc):>10}  {_pct(alloc, total)}  {label:<16} {format_count(files)} files")
        out.append("")

    # Hidden under mount points
    if r.hidden is not None and r.hidden.found:
        out.append(s.bold("Files hidden under mount points"))
        out += _para("These files were written into a folder before another filesystem was mounted on top of it. "
                     "They still use space here, but nothing can reach them until that filesystem is unmounted.", w)  # fmt: skip
        for h in r.hidden.found[:top]:
            note = "" if h.complete else ", check stopped early"
            out.append(f"  {format_size(h.alloc):>10}  {show(h.mount_point)}  ({_plural(h.files, 'file')}{note})")
        fs = r.mount.mount_point if r.mount else "/"
        rel = os.path.relpath(r.hidden.found[0].mount_point, fs)
        out += _para("To reach them without unmounting anything, mount this filesystem a second time somewhere else. "
                     "That second view shows what is under the mount points, and deleting or moving files there frees "
                     "the space:", w)  # fmt: skip
        view = shlex.quote(f"/mnt/fsview/{show(rel)}")
        for cmd in (_sudo("mkdir -p /mnt/fsview", True) + " && " + _sudo(f"mount --bind {shlex.quote(show(fs))} /mnt/fsview", True),
                    f"ls -la {view}", _sudo("umount /mnt/fsview", True) + "    # when done"):
            out.append("       " + s.cyan("$ " + cmd))
        out.append("")

    # Deleted but still open
    if r.deleted and r.deleted.files:
        out.append(s.bold("Deleted files still using space"))
        out += _para("These files were deleted, but a running program still has them open, so their space is not "
                     "freed until that program closes them or restarts.", w)  # fmt: skip
        for d in r.deleted.files[:top]:
            procs = ", ".join(f"{name} (pid {pid})" for pid, name in d.pids[:3])
            more = f" and {len(d.pids) - 3} more" if len(d.pids) > 3 else ""
            out += _para(f"{shorten_path(show(d.path), max(20, w - 40))}  held by {procs}{more}", w,
                         f"  {format_size(d.alloc):>10}  ", " " * 14)  # fmt: skip
        if not r.deleted.complete:
            out.append(s.dim("  Only your own programs were checked. Run with sudo to check all of them."))
        out.append("")

    # What to do
    actions = [t for t in r.totals if t.rule.num != 0 and size(t) > 0 and (t.rule.fixes or t.rule.tips or t.rule.explain)]
    floor = max(min(64 << 20, 0.02 * total), 0.005 * total)  # small scans still get advice
    actions = [t for t in actions if size(t) >= floor][: max(3, min(top, 6))]
    if actions:
        out.append(s.bold("What you can do"))
        for i, t in enumerate(actions, 1):
            # The location may wrap onto the next line; it is only shortened
            # when it would not fit on a line of its own.
            where = _where_text(r, t, w - 8)
            lines = _para(f"{t.rule.name}: {format_size(size(t))}" + (f" in {where}" if where else ""), w,
                          f"  {i}. ", "     ")  # fmt: skip
            lines[0] = lines[0].replace(t.rule.name, s.bold(t.rule.name), 1)
            out += lines
            body_w = max(40, w - 5)
            out += _para(SAFETY[t.rule.safety], body_w + 5, "     ", style=lambda x, lv=t.rule.safety: s.safety(lv, x))
            if _shared_matters(t):
                out.extend("     " + s.yellow(line) for line in _wrap(
                    f"Deleting it frees less than this: {format_size(t.shared)} of it is in files that are also "
                    "hard-linked from other folders, and that space stays in use until every link is gone.", body_w))
            for line in _wrap(t.rule.explain, body_w):
                out.append("     " + line)
            for fx in t.rule.fixes:
                label = fx.label + (f". {fx.note}" if fx.note else "")
                if fx.run:
                    out.append("       " + s.cyan("$ " + _sudo(fx.run, fx.root)))  # never wrapped: it gets copied
                    out += _para(label, w, " " * 9)
                else:
                    out += _para(label, w, " " * 7)
            for tip in t.rule.tips:
                for line in _wrap("Tip: " + tip, body_w):
                    out.append("     " + s.dim(line))
        out.append("")

    # Notes
    notes = []
    if r.n_errors:
        by = ", ".join(f"{format_count(n)} {_errno_name(e)}" for e, n in sorted(r.errnos.items(), key=lambda kv: -kv[1]))
        hint = " Run with sudo to include them." if os.geteuid() != 0 and errno_mod.EACCES in r.errnos else ""
        notes.append(f"{format_count(r.n_errors)} entries could not be read ({by}).{hint}")
        for path, e, op in r.errors[:3]:
            notes.append(f"  e.g. {show(path)}: {os.strerror(e)}")
    by_kind: dict = {}
    for path, why, _ in r.skips:
        by_kind.setdefault(_skip_kind(why), []).append((path, why))
    for kind, items in by_kind.items():
        paths = sorted(p for p, _ in items)
        sample = ", ".join(show(p) for p in paths[:4]) + (", …" if len(paths) > 4 else "")
        n = len(paths)
        if kind == "mount":
            typed = sorted((p, why[: -len(" filesystem")] if why.endswith(" filesystem") else "") for p, why in items)
            sample = ", ".join(show(p) + (f" ({t})" if t else "") for p, t in typed[:4]) + (", …" if n > 4 else "")
            notes.append(f"Did not enter {_plural(n, 'other mounted filesystem')}: {sample}. "
                         f"Use --cross-mounts to include {'it' if n == 1 else 'them'}.")  # fmt: skip
        elif kind == "subvolume":
            notes.append(f"Did not enter {_plural(n, 'btrfs subvolume')}: {sample}. Use --cross-subvolumes to include "
                         f"{'it' if n == 1 else 'them'} (snapshots share data, so their sizes add up to more than they "
                         "really use).")  # fmt: skip
        elif kind == "excluded":
            notes.append(f"Excluded by your settings: {sample}.")
        elif kind == "bind":
            first = sorted(items)[0]
            notes.append(f"Did not count {_plural(n, 'bind mount')} again, because the folders they show are counted "
                         f"where they really are ({show(first[0])} is a {first[1]}).")  # fmt: skip
        elif kind == "network":
            notes.append(f"Did not enter {_plural(n, 'network filesystem')}: {sample}. Scan one directly to include "
                         "it, for example: whatfills " + show(paths[0]))  # fmt: skip
        elif kind == "special":
            pass  # /proc, /sys, tmpfs, snap images and the like hold nothing on this disk; JSON still lists them
        else:
            notes.append(f"Skipped ({kind}): {sample}.")
    if r.n_skips > len(r.skips):
        notes.append(f"({format_count(r.n_skips - len(r.skips))} more skipped paths not listed.)")
    if r.excluded_names:
        notes.append(f"Skipped {format_count(r.excluded_names)} entries whose names are excluded by your settings.")
    links = r.links or {}
    if r.hardlink_dupes:
        text = f"{format_count(r.hardlink_dupes)} extra hard links to files already counted were not counted again."
        if links.get("linked_inside_bytes", 0) >= (64 << 20):
            text += (f" Those files hold {format_size(links['linked_inside_bytes'])}. Each one is counted once, in the "
                     "folder where the scan reached it first, so folders that share them can show less than du gives "
                     "for each folder on its own, and the split between them can change from one scan to the next.")
        notes.append(text)
    if links.get("cross_cause_bytes", 0) >= (64 << 20):
        notes.append(
            f"{format_size(links['cross_cause_bytes'])} is in files hard-linked from places that match different "
            "causes (for example a package cache and the environments made from it), so the split between those "
            "causes can change from one scan to the next too."
        )
    if links.get("untracked"):
        notes.append(
            f"{format_count(links['untracked'])} hard links were found after the hard-link table was full "
            f"({format_count(links.get('table_limit', 0))} files), so some files may be counted more than once. "
            "Use --effort deep for a larger table."
        )
    if r.vanished:
        notes.append(f"{format_count(r.vanished)} entries changed or disappeared during the scan.")
    if notes:
        out.append(s.bold("Notes"))
        for n in notes:
            out.extend("  " + line for line in _wrap(n, w - 4, subsequent_indent="  ") or [""])
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def _iso(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat(timespec="seconds")


def to_dict(r: ScanResult, top: int = 50, all_folders: bool = False) -> dict:
    """A JSON-ready summary. With all_folders=True every kept folder is listed
    (used for snapshots); otherwise the `top` largest."""
    total = r.total_alloc
    fs = None
    if r.mount is not None:
        fs = {"mount_point": r.mount.mount_point, "fstype": r.mount.fstype, "source": r.mount.source,
              "storage": r.storage.kind}  # fmt: skip
        if r.space is not None:
            sp = r.space
            fs.update(total=sp.total, used=sp.used, free=sp.free, avail=sp.avail, reserved=sp.reserved,
                      inodes_total=sp.inodes_total, inodes_used=sp.inodes_used)  # fmt: skip

    causes = []
    for t in r.totals:
        rule = t.rule
        causes.append(
            {
                "id": rule.id,
                "name": rule.name,
                "category": rule.category,
                "category_name": CATEGORIES.get(rule.category, rule.category),
                "safety": rule.safety,
                "kind": rule.kind,
                "bytes": t.alloc,
                "apparent_bytes": t.apparent,
                "files": t.files,
                "folders": t.matches,
                "shared_bytes": t.shared,
                "share": (t.alloc / total) if total else 0.0,
                "bytes_by_age": {"modified": t.age_mtime, "accessed": t.age_atime},
                "locations": [{"path": m.path, "bytes": m.alloc, "apparent_bytes": m.apparent, "files": m.files}
                              for m in t.locations[:top]],  # fmt: skip
                "files_top": [{"path": f.path, "bytes": f.alloc, "apparent_bytes": f.apparent, "mtime": f.mtime}
                              for f in t.top_files[:top]],  # fmt: skip
                "explain": rule.explain,
                "fixes": [{"label": f.label, "run": f.run, "root": f.root, "note": f.note} for f in rule.fixes],
                "tips": rule.tips,
            }
        )

    folders = [f for f in r.tree.walk()]
    if not all_folders:
        folders = sorted(folders, key=r.size, reverse=True)[:top]
    folder_list = [
        {"path": f.path, "bytes": f.alloc, "apparent_bytes": f.apparent, "files": f.files, "folders": f.dirs,
         "mtime": f.mtime, "rule": r.rules.get(f.rule).id, "problems": _flags_note(f.problems) or None,
         "children_kept": not f.pruned}  # fmt: skip
        for f in folders
    ]

    deleted = None
    if r.deleted is not None:
        deleted = {
            "bytes": r.deleted.total_alloc,
            "complete": r.deleted.complete,
            "files": [{"path": d.path, "bytes": d.alloc, "processes": [{"pid": p, "name": n} for p, n in d.pids]}
                      for d in r.deleted.files[:top]],  # fmt: skip
        }

    return {
        "whatfills": __version__,
        "schema": SCHEMA_VERSION,
        "root": r.root,
        "host": r.hostname,
        "started_at": _iso(r.started_at),
        "elapsed_seconds": round(r.elapsed, 3),
        "partial": r.partial,
        "stopped_because": "time budget" if r.budget_hit else "cancelled" if r.cancelled else None,
        "effort": r.settings.effort,
        "threads": r.threads,
        "size_mode": "apparent" if r.settings.apparent_size else "disk usage",
        "filesystem": fs,
        "scanned": {"bytes": r.total_alloc, "apparent_bytes": r.total_apparent, "files": r.tree.files,
                    "folders": r.tree.dirs + 1, "coverage": r.coverage},  # fmt: skip
        "causes": causes,
        "folders": folder_list,
        "largest_files": [{"path": f.path, "bytes": f.alloc, "apparent_bytes": f.apparent, "mtime": f.mtime,
                           "owner": user_name(f.uid), "rule": r.rules.get(f.rule).id}
                          for f in r.top_files[:top]],  # fmt: skip
        "owners": [{"uid": uid, "user": user_name(uid), "bytes": a, "files": n}
                   for uid, (a, n) in sorted(r.uids.items(), key=lambda kv: -kv[1][0])],  # fmt: skip
        "types": [{"extension": ext, "bytes": a, "files": n}
                  for ext, (a, n) in sorted(r.exts.items(), key=lambda kv: -kv[1][0])[:top]],  # fmt: skip
        "deleted_open_files": deleted,
        "hidden_under_mounts": None if r.hidden is None else {
            "checked": r.hidden.checked, "bytes": r.hidden.total_alloc, "error": r.hidden.error or None,
            "mounts": [{"mount_point": h.mount_point, "bytes": h.alloc, "files": h.files, "complete": h.complete}
                       for h in r.hidden.found],
        },  # fmt: skip
        "problems": {
            "unreadable": r.n_errors,
            "by_error": {_errno_name(e): n for e, n in r.errnos.items()},
            "examples": [{"path": p, "error": os.strerror(e), "during": op} for p, e, op in r.errors[:top]],
            "changed_during_scan": r.vanished,
        },
        "skipped": [{"path": p, "reason": why} for p, why, _ in r.skips],
        "excluded_by_name": r.excluded_names,
        "hardlink_duplicates": r.hardlink_dupes,
        "hard_links": {k: (r.links or {}).get(k, 0) for k in ("files", "bytes", "shared_files", "shared_bytes",
                                                              "cross_cause_bytes", "linked_inside_bytes",
                                                              "untracked")},  # fmt: skip
    }
