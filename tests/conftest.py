import os
import shutil
import stat
import subprocess
import sys
import time

import pytest

from whatfills import _core


@pytest.fixture(autouse=True)
def isolated_config(tmp_path_factory, monkeypatch):
    """Keep the user's real config, rules and snapshots out of the tests."""
    base = tmp_path_factory.mktemp("xdg")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(base / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(base / "state"))
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    yield


def write(path, size=0, data=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        if data is not None:
            f.write(data)
        elif size:
            f.write(os.urandom(min(size, 1 << 16)) * (size // (1 << 16)) + os.urandom(size % (1 << 16)))
    return path


def core_scan(root, **opts):
    """Run the C++ scanner directly and return its raw result."""
    o = {"root": os.fsencode(str(root)), "threads": 4, "now": int(time.time()), "keep_dir_min": 0}
    o.update(opts)
    s = _core.Scanner(o)
    s.start()
    assert s.wait(60)
    return s.result()


def nodes_by_path(raw):
    """{path: node tuple} for a raw result."""
    nodes = raw["nodes"]
    paths = []
    out = {}
    for parent, name, *rest in nodes:
        name = os.fsdecode(name)
        p = name if parent < 0 else (paths[parent].rstrip("/") + "/" + name)
        paths.append(p)
        out[p] = (parent, name, *rest)
    return out


def oracle(root, one_fs=True):
    """Reference implementation in plain Python: per-folder (alloc, apparent,
    files, dirs) with hard links counted once in sorted depth-first order."""
    seen = set()
    result = {}
    root_dev = os.lstat(root).st_dev

    def walk(path):
        st = os.lstat(path)
        alloc, apparent, files, dirs = st.st_blocks * 512, 0, 0, 0
        for name in sorted(os.listdir(path)):
            p = os.path.join(path, name)
            s = os.lstat(p)
            if stat.S_ISDIR(s.st_mode):
                if one_fs and s.st_dev != root_dev:
                    continue
                a, ap, f, d = walk(p)
                alloc += a
                apparent += ap
                files += f
                dirs += d + 1
            else:
                if s.st_nlink > 1:
                    key = (s.st_dev, s.st_ino)
                    if key in seen:
                        continue
                    seen.add(key)
                alloc += s.st_blocks * 512
                apparent += s.st_size
                files += 1
        result[path] = (alloc, apparent, files, dirs)
        return result[path]

    walk(str(root))
    return result


def du(root, apparent=False):
    du_bin = shutil.which("du")
    if du_bin is None:
        return None
    args = [du_bin, "-sxB1"] + (["--apparent-size"] if apparent else []) + [str(root)]
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    return int(out.split()[0])


IS_ROOT = os.geteuid() == 0
PY = sys.executable
