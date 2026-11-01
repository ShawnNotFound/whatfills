"""The C++ scanner against a plain-Python oracle and GNU du."""

import os
import random
import shutil
import subprocess
import sys
import tempfile
import time

import pytest
from conftest import IS_ROOT, core_scan, du, nodes_by_path, oracle, write

from whatfills import _core
from whatfills.rules import RuleSet, parse_rules_text


def make_tree(root, seed=1, dirs=40, files=400, max_size=200_000):
    rnd = random.Random(seed)
    folders = [str(root)]
    for i in range(dirs):
        parent = rnd.choice(folders)
        p = os.path.join(parent, f"d{i}")
        os.mkdir(p)
        folders.append(p)
    for i in range(files):
        write(os.path.join(rnd.choice(folders), f"f{i}.bin"), size=rnd.randrange(0, max_size))
    return folders


@pytest.mark.parametrize("threads", [1, 2, 8])
def test_matches_oracle_per_folder(tmp_path, threads):
    make_tree(tmp_path)
    raw = core_scan(tmp_path, threads=threads)
    got = nodes_by_path(raw)
    want = oracle(tmp_path)
    assert set(got) == set(want)
    for path, (alloc, apparent, files, dirs) in want.items():
        node = got[path]
        assert node[2:6] == (alloc, apparent, files, dirs), path


def test_matches_du(tmp_path):
    make_tree(tmp_path, seed=7, dirs=60, files=600)
    raw = core_scan(tmp_path)
    root = raw["nodes"][0]
    if du(tmp_path) is None:
        pytest.skip("du not available")
    assert root[2] == du(tmp_path)
    assert root[3] == du(tmp_path, apparent=True)


def test_hard_links_counted_once(tmp_path):
    a = write(tmp_path / "a" / "big.bin", size=300_000)
    os.makedirs(tmp_path / "b")
    os.link(a, tmp_path / "b" / "same.bin")
    os.link(a, tmp_path / "b" / "again.bin")
    raw = core_scan(tmp_path)
    root = raw["nodes"][0]
    assert root[4] == 1  # one file
    assert raw["stats"]["hardlink_dupes"] == 2
    assert root[2] == oracle(tmp_path)[str(tmp_path)][0]


def test_sparse_file(tmp_path):
    p = tmp_path / "sparse.img"
    with open(p, "wb") as f:
        f.truncate(1 << 30)
    raw = core_scan(tmp_path)
    root = raw["nodes"][0]
    assert root[3] == 1 << 30  # apparent
    assert root[2] < 1 << 20  # almost nothing allocated


def test_symlinks_not_followed_and_loops_ok(tmp_path):
    write(tmp_path / "real" / "x.bin", size=100_000)
    os.symlink(tmp_path / "real", tmp_path / "link_to_dir")
    os.symlink(tmp_path, tmp_path / "real" / "loop")
    os.symlink("/nonexistent/target", tmp_path / "dangling")
    raw = core_scan(tmp_path)
    got = nodes_by_path(raw)
    assert str(tmp_path / "link_to_dir") not in got
    assert got[str(tmp_path)][4] == 4  # x.bin plus three symlinks
    assert oracle(tmp_path)[str(tmp_path)][:3] == got[str(tmp_path)][2:5]


def test_deeper_than_path_max(tmp_path):
    name = "d" * 200
    fd = os.open(tmp_path, os.O_RDONLY)
    depth = 30  # 30 * 201 bytes > PATH_MAX (4096)
    try:
        for _ in range(depth):
            os.mkdir(name, dir_fd=fd)
            nfd = os.open(name, os.O_RDONLY, dir_fd=fd)
            os.close(fd)
            fd = nfd
        leaf = os.open("leaf.bin", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd)
        os.write(leaf, b"x" * 50_000)
        os.close(leaf)
    finally:
        os.close(fd)
    raw = core_scan(tmp_path)
    root = raw["nodes"][0]
    assert root[4] == 1
    assert root[5] == depth
    assert raw["stats"]["errors"] == 0
    # clean up with fd-relative removal (rmtree copes with long paths)
    shutil.rmtree(tmp_path / name)


def test_non_utf8_names_round_trip(tmp_path):
    raw_name = b"caf\xe9-\xff.bin"
    p = os.path.join(os.fsencode(str(tmp_path)), raw_name)
    with open(p, "wb") as f:
        f.write(b"y" * 10_000)
    raw = core_scan(tmp_path, top_files=5)
    paths = [t[0] for t in raw["top_files"]]
    assert p in paths


def test_many_files_in_one_folder(tmp_path):
    n = 20_000
    d = tmp_path / "flat"
    d.mkdir()
    for i in range(n):
        (d / f"{i}.txt").write_bytes(b"z")
    raw = core_scan(tmp_path, threads=8)
    assert raw["nodes"][0][4] == n


def test_exclusions(tmp_path):
    write(tmp_path / "keep" / "a.bin", size=10_000)
    write(tmp_path / "secret" / "b.bin", size=20_000)
    write(tmp_path / "keep" / ".git" / "c.bin", size=30_000)
    write(tmp_path / "keep" / "x.tmp", size=40_000)
    write(tmp_path / "data" / "raw" / "d.bin", size=50_000)
    write(tmp_path / "data" / "raw2" / "e.bin", size=60_000)
    raw = core_scan(
        tmp_path,
        exclude_paths=[os.fsencode(str(tmp_path / "secret"))],
        exclude_names=[b".git", b"*.tmp"],
        exclude_globs=[os.fsencode(str(tmp_path) + "/**/raw")],
    )
    got = nodes_by_path(raw)
    assert str(tmp_path / "secret") not in got
    assert str(tmp_path / "keep" / ".git") not in got
    assert str(tmp_path / "data" / "raw") not in got
    assert str(tmp_path / "data" / "raw2") in got
    assert got[str(tmp_path)][4] == 2  # a.bin and e.bin
    assert raw["stats"]["excluded_names"] == 2
    reasons = {os.fsdecode(p): why for p, why, _ in raw["skips"]}
    assert reasons[str(tmp_path / "secret")] == "excluded"
    assert reasons[str(tmp_path / "data" / "raw")] == "excluded"


def test_pruning_keeps_totals(tmp_path):
    make_tree(tmp_path, seed=3, dirs=80, files=500, max_size=20_000)
    full = core_scan(tmp_path, keep_dir_min=0)
    pruned = core_scan(tmp_path, keep_dir_min=1 << 30)
    assert pruned["nodes"][0][2:6] == full["nodes"][0][2:6]
    assert len(pruned["nodes"]) < len(full["nodes"])
    # the root's children are kept (one level), deeper levels are dropped
    assert all(parent <= 0 for parent, *_ in pruned["nodes"])


def test_cancel_returns_partial(tmp_path):
    for i in range(200):
        d = tmp_path / f"d{i}"
        d.mkdir()
        for j in range(50):
            (d / f"{j}").write_bytes(b"")
    s = _core.Scanner({"root": os.fsencode(str(tmp_path)), "threads": 2, "now": int(time.time())})
    s.start()
    s.cancel()
    assert s.wait(30)
    raw = s.result()
    assert raw["stats"]["stopped"]
    assert raw["nodes"][0][4] <= 200 * 50


def test_progress_reports_counts(tmp_path):
    make_tree(tmp_path, dirs=10, files=100)
    s = _core.Scanner({"root": os.fsencode(str(tmp_path)), "threads": 2, "now": int(time.time())})
    s.start()
    s.wait(30)
    p = s.progress()
    assert p["done"] and p["files"] == 100 and p["dirs"] == 11


def test_root_must_be_a_folder(tmp_path):
    f = write(tmp_path / "file.bin", size=10)
    s = _core.Scanner({"root": os.fsencode(str(f))})
    with pytest.raises(RuntimeError, match="not a folder"):
        s.start()
    s2 = _core.Scanner({"root": os.fsencode(str(tmp_path / "missing"))})
    with pytest.raises(RuntimeError, match="No such file"):
        s2.start()


def test_unknown_option_is_rejected():
    with pytest.raises(ValueError, match="unknown scanner option"):
        _core.Scanner({"root": b"/", "thread": 2})


def _unshare_works():
    if not shutil.which("unshare"):
        return False
    r = subprocess.run(["unshare", "-rm", "true"], capture_output=True)
    return r.returncode == 0


@pytest.mark.skipif(not _unshare_works(), reason="needs unprivileged user and mount namespaces")
def test_one_file_system_and_mount_list(tmp_path):
    """Mount a tmpfs inside the tree (in a private mount namespace) and check
    that it is skipped by default and counted when crossing is allowed."""
    write(tmp_path / "local" / "a.bin", size=100_000)
    (tmp_path / "mnt").mkdir()
    script = f"""
import os, subprocess, sys, time, json
sys.path[:0] = {sys.path!r}
subprocess.run(["mount", "-t", "tmpfs", "none", {str(tmp_path / 'mnt')!r}], check=True)
with open({str(tmp_path / 'mnt' / 'b.bin')!r}, "wb") as f:
    f.write(os.urandom(200_000))
from whatfills import _core
out = {{}}
for one_fs in (True, False):
    s = _core.Scanner({{"root": os.fsencode({str(tmp_path)!r}), "one_file_system": one_fs, "now": int(time.time()),
                        "mount_points": [os.fsencode({str(tmp_path / 'mnt')!r})]}})
    s.start(); s.wait(30); r = s.result()
    out[str(one_fs)] = [r["nodes"][0][4], [x[1] for x in r["skips"]]]
print(json.dumps(out))
"""
    r = subprocess.run(["unshare", "-rm", sys.executable, "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    import json

    out = json.loads(r.stdout)
    assert out["True"] == [1, ["mount"]]
    assert out["False"][0] == 2


def test_unreadable_folder_reported(tmp_path):
    base = tempfile.mkdtemp(prefix="whatfills-perm-")
    try:
        os.chmod(base, 0o755)
        write(os.path.join(base, "ok", "a.bin"), size=1000)
        write(os.path.join(base, "locked", "b.bin"), size=1000)
        os.chmod(os.path.join(base, "ok"), 0o755)
        os.chmod(os.path.join(base, "ok", "a.bin"), 0o644)
        os.chmod(os.path.join(base, "locked"), 0o000)
        code = (
            "import os,sys,time\n"
            f"sys.path[:0]={sys.path!r}\n"
            "from whatfills import _core\n"
            f"s=_core.Scanner({{'root':os.fsencode({base!r}),'now':int(time.time())}})\n"
            "s.start(); s.wait(30); r=s.result()\n"
            "print(r['stats']['errors'], r['nodes'][0][4], sorted(r['errnos']))\n"
        )
        if IS_ROOT:
            if not shutil.which("setpriv"):
                pytest.skip("needs setpriv to drop root")
            drop = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"]
            probe = f"import sys\nsys.path[:0]={sys.path!r}\nfrom whatfills import _core\n"
            if subprocess.run(drop + [sys.executable, "-c", probe], capture_output=True).returncode != 0:
                pytest.skip("Python or whatfills is installed where an unprivileged user cannot read it")
            cmd = drop + [sys.executable, "-c", code]
        else:
            cmd = [sys.executable, "-c", code]
        r = subprocess.run(cmd, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        errors, files, errnos = r.stdout.split(" ", 2)
        assert int(errors) == 1
        assert int(files) == 1
        assert "13" in errnos  # EACCES
    finally:
        os.chmod(os.path.join(base, "locked"), 0o755)
        shutil.rmtree(base)


def test_glob_matching():
    m = _core.glob_match_name
    assert m(b"*.py", b"a.py")
    assert not m(b"*.py", b"a.pyc")
    assert m(b"core.[0-9]*", b"core.1234")
    assert not m(b"core.[0-9]*", b"core.x")
    assert m(b"[!.]*", b"abc") and not m(b"[!.]*", b".abc")
    assert m(b"a\\*b", b"a*b") and not m(b"a\\*b", b"axb")
    assert m(b"[a-c]x", b"bx") and not m(b"[a-c]x", b"dx")
    assert m(b"[unclosed", b"[unclosed")
    p = _core.glob_match_path
    assert p(b"/data/**/raw", b"/data/raw")
    assert p(b"/data/**/raw", b"/data/a/b/raw")
    assert not p(b"/data/*/raw", b"/data/a/b/raw")
    assert p(b"/data/*/raw", b"/data/a/raw")
    assert p(b"node_modules", b"/x/y/node_modules")
    assert not p(b"node_modules", b"/x/y/node_modules2")
    assert p(b"/srv/**", b"/srv/a/b")
    assert not p(b"/srv/?", b"/srv/ab")


GLOB_CASES = [b"*/cache/*", b"**/tmp/*.o", b"data/**/raw", b"*.tar.gz", b"[ab]*/c*", b"x\\*y", b"/no/such/**", b"*", b"d?/e"]


@pytest.mark.parametrize("pattern", GLOB_CASES)
def test_exclude_globs_agree_with_the_matcher(tmp_path, pattern):
    """The scanner checks cheap literal parts of a pattern first; the folders
    it skips must be exactly those the full matcher accepts."""
    names = ["cache", "tmp", "data", "raw", "a1", "bz", "c", "cx", "x*y", "d1", "e", "f.tar.gz", "g.o", "h.txt"]
    rnd = random.Random(5)
    for i in range(300):
        parts = [rnd.choice(names) for _ in range(rnd.randrange(1, 5))]
        write(os.path.join(tmp_path, *parts, f"{i}.bin"), size=10)
    raw = core_scan(tmp_path, exclude_globs=[pattern])
    skipped = {os.fsdecode(p) for p, why, _ in raw["skips"]}
    expected = set()
    for dirpath, dirnames, filenames in os.walk(tmp_path):
        for name in sorted(dirnames) + filenames:
            full = os.path.join(dirpath, name)
            if _core.glob_match_path(pattern, os.fsencode(full)):
                expected.add(full)
        dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d) not in expected]
    assert skipped == expected


def test_hard_link_summary(tmp_path):
    a = write(tmp_path / "a" / "big.bin", size=300_000)
    os.makedirs(tmp_path / "b")
    os.link(a, tmp_path / "b" / "same.bin")
    c = write(tmp_path / "c.bin", size=100_000)
    os.link(c, tmp_path.parent / f"{tmp_path.name}-outside.bin")  # a link the scan cannot see
    try:
        raw = core_scan(tmp_path)
    finally:
        os.unlink(tmp_path.parent / f"{tmp_path.name}-outside.bin")
    links = raw["links"]
    assert links["files"] == 2 and links["shared_files"] == 1  # big.bin's links are all inside
    assert links["shared_bytes"] == os.stat(c).st_blocks * 512
    assert links["cross_cause_bytes"] == 0 and links["untracked"] == 0
    assert raw["rules"][0][6] == links["shared_bytes"]  # no rules: everything is unclassified


def test_hard_link_table_limit(tmp_path):
    for n in "abc":
        p = write(tmp_path / f"{n}1", size=10_000)
        os.link(p, tmp_path / f"{n}2")
    raw = core_scan(tmp_path, max_links=1, threads=1)
    # one file is tracked and counted once; the other two are counted at each link
    assert raw["nodes"][0][4] == 5
    assert raw["links"]["untracked"] == 4 and raw["stats"]["hardlink_dupes"] == 1


@pytest.mark.parametrize("buffer", [600, 4096, 128 * 1024])
def test_marker_found_in_long_listings(tmp_path, buffer):
    # A folder whose listing takes several reads is still recognised by a name
    # inside it, wherever that name comes in the listing, and every entry is
    # counted once.
    env = tmp_path / "env"
    for i in range(400):
        write(env / f"f{i:03d}.py", size=1)
    write(env / "pyvenv.cfg", size=10)
    write(tmp_path / "other" / "x.bin", size=5000)
    text = '[[rule]]\nid = "venv"\nname = "venv"\ndirs = ["*"]\nrequire_child = ["pyvenv.cfg"]\n'
    rules = RuleSet(parse_rules_text(text, "t.toml"), homes=[])
    raw = core_scan(tmp_path, dents_buffer=buffer, **rules.compile())
    venv = rules.by_id["venv"].num
    matches = [m for m in raw["matches"] if m[0] == venv]
    assert [os.fsdecode(m[2]) for m in matches] == [str(env)]
    assert matches[0][3] == oracle(tmp_path)[str(env)][0]
    assert matches[0][5] == 401
    assert raw["nodes"][0][4] == 402
