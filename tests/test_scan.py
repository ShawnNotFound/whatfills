"""Running a scan: which mounts to enter, target checks, exclusions, hard links."""

import json
import os
import shutil
import subprocess
import sys

import pytest
from conftest import IS_ROOT, write

from whatfills import fsinfo
from whatfills.config import Settings
from whatfills.rules import RuleSet, parse_rules_text
from whatfills.scan import ScanError, _plan_mounts, run_scan

NO_RULES = RuleSet([], homes=[])

MOUNTINFO = """\
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
23 22 0:21 / /proc rw,nosuid shared:12 - proc proc rw
40 22 259:3 / /home rw,noatime shared:30 - ext4 /dev/nvme0n1p3 rw
41 22 259:3 /shared /srv/shared rw,relatime shared:30 - ext4 /dev/nvme0n1p3 rw
42 22 0:50 / /mnt/my\\040disk rw - fuse.sshfs host:/x rw
44 22 259:6 / /data rw shared:32 - xfs /dev/sdc1 rw
45 22 0:60 / /run rw - tmpfs tmpfs rw
"""


def test_plan_mounts_when_crossing():
    mounts = fsinfo.parse_mountinfo(MOUNTINFO)
    root_mount = fsinfo.mount_for("/", mounts)
    points, skip = _plan_mounts("/", root_mount, mounts, Settings(one_file_system=False))
    assert skip["/proc"] == "proc filesystem"
    assert skip["/run"] == "tmpfs filesystem"
    assert skip["/srv/shared"] == "bind mount of /home/shared, counted there"
    assert skip["/mnt/my disk"] == "fuse.sshfs network filesystem"
    assert "/home" not in skip and "/data" not in skip
    assert set(points) == {"/proc", "/home", "/srv/shared", "/mnt/my disk", "/data", "/run"}
    # a type left out in the settings is listed as excluded, not as a kernel filesystem
    _, skip = _plan_mounts("/", root_mount, mounts, Settings(one_file_system=False, exclude_fstypes=["xfs"]))
    assert skip["/data"] == "excluded" and skip["/proc"] == "proc filesystem"


def test_plan_mounts_one_filesystem_leaves_other_filesystems_to_the_scanner():
    mounts = fsinfo.parse_mountinfo(MOUNTINFO)
    points, skip = _plan_mounts("/", fsinfo.mount_for("/", mounts), mounts, Settings())
    assert skip == {} and "/home" in points


BINDS = """\
22 1 259:2 / / rw - ext4 /dev/sda2 rw
30 22 259:2 /var/lib/vols/y /pods/v rw - ext4 /dev/sda2 rw
31 22 259:2 /srv /srv rw - ext4 /dev/sda2 rw
32 22 259:7 / /data rw - xfs /dev/sdb1 rw
33 22 259:2 /data/z /x rw - ext4 /dev/sda2 rw
34 22 259:2 / /mnt/rootview rw - ext4 /dev/sda2 rw
"""


def test_plan_mounts_same_filesystem_binds():
    mounts = fsinfo.parse_mountinfo(BINDS)
    points, skip = _plan_mounts("/", fsinfo.mount_for("/", mounts), mounts, Settings())
    assert skip == {
        "/pods/v": "bind mount of /var/lib/vols/y, counted there",
        "/mnt/rootview": "bind mount of /, counted there",
    }
    # /srv is bound onto itself, and /x shows a folder hidden under the /data mount:
    # both are only visible here, so they are counted here.
    # Scanning /pods alone: the bind's source is outside the scan, so it counts.
    points, skip = _plan_mounts("/pods", fsinfo.mount_for("/pods", mounts), mounts, Settings())
    assert skip == {}


def _unshare_works():
    if not shutil.which("unshare"):
        return False
    return subprocess.run(["unshare", "-rm", "true"], capture_output=True).returncode == 0


@pytest.mark.skipif(not _unshare_works(), reason="needs unprivileged user and mount namespaces")
def test_bind_mount_is_counted_once(tmp_path):
    write(tmp_path / "real" / "data.bin", size=200_000)
    (tmp_path / "view").mkdir()
    # The bind mount only exists inside a private mount namespace, so the scan
    # runs in a child process there and prints what it found.
    script = (
        "import json, sys\n"
        "from whatfills.config import Settings\n"
        "from whatfills.rules import RuleSet\n"
        "from whatfills.scan import run_scan\n"
        "r = run_scan(sys.argv[1], Settings(), RuleSet([], homes=[]))\n"
        "print(json.dumps({'files': r.tree.files, 'skips': [[p, why] for p, why, _ in r.skips]}))\n"
    )
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    cmd = 'mount --bind "$1" "$2" && exec "$3" -c "$4" "$5"'
    args = [str(tmp_path / "real"), str(tmp_path / "view"), sys.executable, script, str(tmp_path)]
    r = subprocess.run(["unshare", "-rm", "sh", "-c", cmd, "sh", *args], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["files"] == 1
    assert data["skips"] == [[str(tmp_path / "view"), f"bind mount of {tmp_path / 'real'}, counted there"]]


def test_target_errors(tmp_path):
    s = Settings()
    with pytest.raises(ScanError, match="no such file or folder"):
        run_scan(str(tmp_path / "missing"), s, NO_RULES)
    os.symlink(tmp_path / "nowhere", tmp_path / "dangling")
    with pytest.raises(ScanError, match="is a link to .*nowhere, which does not exist"):
        run_scan(str(tmp_path / "dangling"), s, NO_RULES)
    write(tmp_path / "f.txt", size=1)
    with pytest.raises(ScanError, match="is a file, not a folder"):
        run_scan(str(tmp_path / "f.txt"), s, NO_RULES)
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(ScanError, match="is not a folder"):
        run_scan(str(tmp_path / "pipe"), s, NO_RULES)


@pytest.mark.skipif(IS_ROOT, reason="root can enter any folder")
def test_target_behind_a_locked_folder(tmp_path):
    (tmp_path / "locked" / "inner").mkdir(parents=True)
    os.chmod(tmp_path / "locked", 0)
    try:
        with pytest.raises(ScanError, match="permission denied.*sudo"):
            run_scan(str(tmp_path / "locked" / "inner"), Settings(), NO_RULES)
    finally:
        os.chmod(tmp_path / "locked", 0o755)


def test_exclude_paths_and_symlinks(tmp_path):
    real = tmp_path / "real"
    write(real / "keep" / "a.bin", size=10_000)
    write(real / "secret" / "b.bin", size=20_000)
    os.symlink(real, tmp_path / "alias")
    # the scan walks real paths, so an exclusion written through a symlinked folder still applies
    r = run_scan(str(real), Settings(exclude_paths=[str(tmp_path / "alias" / "secret")]), NO_RULES)
    assert r.tree.files == 1
    # excluding a symlink itself skips the link, not the folder it points to
    os.symlink(real / "keep", real / "keep-link")
    r = run_scan(str(real), Settings(exclude_paths=[str(real / "keep-link")]), NO_RULES)
    assert r.tree.files == 2
    assert [p for p, why, _ in r.skips] == [str(real / "keep-link")]
    with pytest.raises(ScanError, match="excluded by your settings"):
        run_scan(str(tmp_path / "alias" / "secret"), Settings(exclude_paths=[str(real / "secret")]), NO_RULES)


LINK_RULES = """
[[rule]]
id = "pkgs"
name = "package cache"
dirs = ["pkgs"]

[[rule]]
id = "envs"
name = "environments"
dirs = ["envs"]
"""


def test_hard_links_shared_between_causes(tmp_path):
    root = tmp_path / "scan"
    lib = write(root / "pkgs" / "lib.so", size=300_000)
    os.makedirs(root / "envs" / "e1")
    os.link(lib, root / "envs" / "e1" / "lib.so")
    write(root / "pkgs" / "only.so", size=100_000)
    write(root / "envs" / "e1" / "own.py", size=50_000)
    outside = write(tmp_path / "elsewhere" / "x.bin", size=200_000)
    os.link(outside, root / "pkgs" / "x.bin")  # its other link is outside the scanned folder

    rules = RuleSet(parse_rules_text(LINK_RULES, "t.toml"), homes=[])
    r = run_scan(str(root), Settings(), rules)
    t = {x.rule.id: x for x in r.totals}
    lib_alloc = os.stat(lib).st_blocks * 512
    x_alloc = os.stat(outside).st_blocks * 512
    assert r.links["files"] == 2 and r.links["shared_files"] == 2
    assert r.links["cross_cause_bytes"] == lib_alloc
    assert r.links["shared_bytes"] == lib_alloc + x_alloc
    assert sum(x.shared for x in r.totals) == r.links["shared_bytes"]
    assert t["pkgs"].shared in (x_alloc, x_alloc + lib_alloc)  # lib.so is credited to whichever link came first
    assert r.hardlink_dupes == 1
    assert sum(x.alloc for x in r.totals) == r.total_alloc


def test_skip_reasons_use_the_filesystem_type():
    from whatfills.scan import _skip_reason

    types = {"/proc": "proc", "/run": "tmpfs", "/snap/core/1": "squashfs", "/mnt/nas": "nfs4", "/home": "ext4"}
    assert _skip_reason("/proc", "mount", {}, types) == "proc filesystem"
    assert _skip_reason("/snap/core/1", "mount", {}, types) == "squashfs filesystem"
    assert _skip_reason("/mnt/nas", "mount", {}, types) == "nfs4 network filesystem"
    assert _skip_reason("/home", "mount", {}, types) == "ext4 filesystem"
    assert _skip_reason("/media/usb", "mount", {}, types) == "mount"  # mounted after the scan began
    assert _skip_reason("/x", "excluded", {"/x": "bind mount of /y, counted there"}, types).startswith("bind mount")
