"""Checks for space that a folder scan cannot see."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field


@dataclass
class OpenDeleted:
    """A file that was deleted while a program still had it open. Its space
    is only freed when the program closes it or exits."""

    path: str
    alloc: int
    apparent: int
    pids: list = field(default_factory=list)  # (pid, command name)


@dataclass
class DeletedReport:
    files: list
    total_alloc: int
    complete: bool  # False when other users' processes could not be inspected
    unreadable_processes: int


def _comm(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return "?"


def deleted_open_files(dev: int, proc: str = "/proc") -> DeletedReport:
    """Find deleted files on device `dev` that running processes still hold open."""
    found: dict = {}
    unreadable = 0
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        return DeletedReport([], 0, False, 0)
    me = os.getpid()
    for pid in pids:
        if int(pid) == me:
            continue
        fd_dir = f"{proc}/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except PermissionError:
            unreadable += 1
            continue
        except OSError:
            continue  # process exited
        for fd in fds:
            link = f"{fd_dir}/{fd}"
            try:
                target = os.readlink(link)
            except OSError:
                continue
            if not target.endswith(" (deleted)"):
                continue
            try:
                st = os.stat(link)  # follows the link to the open file itself
            except OSError:
                continue
            if st.st_dev != dev or not stat.S_ISREG(st.st_mode) or st.st_nlink != 0:
                continue
            key = (st.st_dev, st.st_ino)
            entry = found.get(key)
            if entry is None:
                entry = found[key] = OpenDeleted(target[: -len(" (deleted)")], st.st_blocks * 512, st.st_size)
            if all(p != int(pid) for p, _ in entry.pids):
                entry.pids.append((int(pid), _comm(pid)))
    files = sorted(found.values(), key=lambda e: e.alloc, reverse=True)
    complete = os.geteuid() == 0 or unreadable == 0
    return DeletedReport(files, sum(f.alloc for f in files), complete, unreadable)


@dataclass
class HiddenData:
    """Files in a folder that another filesystem is mounted on top of."""

    mount_point: str
    alloc: int
    files: int
    complete: bool = True


@dataclass
class HiddenReport:
    found: list  # HiddenData with at least 1 MiB, biggest first
    total_alloc: int
    checked: int  # mount points looked under
    error: str = ""  # why the check could not run; empty when it ran


# Runs inside a private mount namespace: bind-mount the filesystem without its
# submounts, so the folders under mount points show what is really in them.
_HIDDEN_CHILD = r"""
import json, os, subprocess, sys, time
src, view, budget = sys.argv[1], sys.argv[2], float(sys.argv[3])
rels = sys.argv[4:]
r = subprocess.run(["mount", "--bind", src, view], capture_output=True, text=True)
if r.returncode != 0:
    print(json.dumps({"error": (r.stderr or r.stdout).strip() or "mount --bind failed"}))
    sys.exit(0)
from whatfills import _core
deadline = time.monotonic() + budget
out = []
for rel in rels:
    d = os.path.join(view, rel)
    try:
        if not os.listdir(d):
            continue
    except OSError:
        continue
    s = _core.Scanner({"root": os.fsencode(d), "threads": 4, "now": int(time.time()), "keep_dir_min": 1 << 62,
                       "big_file_min": 1 << 62, "top_files": 0, "matches_per_rule": 0, "files_per_rule": 0,
                       "collect_ext": False, "max_errors": 0, "max_skips": 0})
    s.start()
    done = s.wait(max(0.1, deadline - time.monotonic()))
    if not done:
        s.cancel()
        s.wait()
    root = s.result()["nodes"][0]
    out.append([rel, root[2], root[4], bool(done)])
print(json.dumps({"found": out}))
"""


def _scratch_dir() -> str | None:
    """An empty folder for the bind mount, preferably in memory (the disk may be full)."""
    for base in ("/run", "/dev/shm", tempfile.gettempdir()):
        try:
            return tempfile.mkdtemp(prefix="whatfills-view-", dir=base)
        except OSError:
            continue
    return None


def hidden_under_mounts(fs_mount, mounts: list, budget: float = 15.0) -> HiddenReport:
    """Measure files hidden under the mount points of the filesystem mounted
    at `fs_mount`. They use space on it, but no path leads to them, so a
    folder scan cannot see them. Needs root (to make a private bind mount);
    nothing outside a private mount namespace is changed."""
    covered = sorted({m.mount_point for m in mounts if m.parent_id == fs_mount.mount_id and m is not fs_mount
                      and m.mount_point != fs_mount.mount_point})  # fmt: skip
    if not covered:
        return HiddenReport([], 0, 0)
    if os.geteuid() != 0:
        return HiddenReport([], 0, 0, "needs root")
    if not shutil.which("unshare") or not shutil.which("mount"):
        return HiddenReport([], 0, 0, "needs the unshare and mount commands")
    view = _scratch_dir()
    if view is None:
        return HiddenReport([], 0, 0, "could not create a temporary folder")
    rels = [os.path.relpath(p, fs_mount.mount_point) for p in covered]
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    cmd = ["unshare", "-m", "--propagation", "private", sys.executable, "-c", _HIDDEN_CHILD,
           fs_mount.mount_point, view, str(budget), *rels]  # fmt: skip
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=budget + 30)
        data = json.loads(r.stdout or "{}") if r.returncode == 0 else {"error": r.stderr.strip()[-200:]}
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        data = {"error": str(e)}
    finally:
        try:
            os.rmdir(view)
        except OSError:
            pass
    if "found" not in data:
        return HiddenReport([], 0, len(covered), data.get("error") or "the check failed")
    base = fs_mount.mount_point.rstrip("/")
    found = [HiddenData(f"{base}/{rel}", alloc, files, done) for rel, alloc, files, done in data["found"] if alloc >= 1 << 20]
    found.sort(key=lambda h: h.alloc, reverse=True)
    return HiddenReport(found, sum(h.alloc for h in found), len(covered))
