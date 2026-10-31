"""Mount parsing, free space, storage type and the deleted-but-open probe."""

import os
import subprocess
import sys

import pytest

from whatfills import fsinfo, probes

MOUNTINFO = """\
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
23 22 0:21 / /proc rw,nosuid shared:12 - proc proc rw
40 22 259:3 / /home rw,noatime shared:30 - ext4 /dev/nvme0n1p3 rw
41 22 259:3 /shared /srv/shared rw,relatime shared:30 - ext4 /dev/nvme0n1p3 rw
42 22 0:50 / /mnt/my\\040disk rw - fuse.sshfs host:/x rw
43 22 259:5 / /data rw shared:31 - xfs /dev/sdb1 rw
44 22 259:6 / /data rw shared:32 - xfs /dev/sdc1 rw
"""


def test_mountinfo_parsing():
    mounts = fsinfo.parse_mountinfo(MOUNTINFO + "garbage line\n\n")
    assert len(mounts) == 7
    m = {x.mount_point: x for x in mounts}
    assert "/mnt/my disk" in m and m["/mnt/my disk"].is_network
    assert m["/proc"].is_pseudo
    assert m["/home"].atime_mode == "noatime"
    assert m["/"].atime_mode == "relatime"
    assert m["/srv/shared"].root == "/shared"
    assert fsinfo.mount_for("/home/x/y", mounts).mount_point == "/home"
    assert fsinfo.mount_for("/homework", mounts).mount_point == "/"
    assert fsinfo.mount_for("/data/z", mounts).source == "/dev/sdc1"  # a later mount hides the earlier one
    under = {x.mount_point: x for x in fsinfo.mounts_under("/", mounts)}
    assert under["/data"].source == "/dev/sdc1"
    assert "/" not in under


def test_is_under():
    assert fsinfo.is_under("/a/b", "/a")
    assert fsinfo.is_under("/a", "/a")
    assert not fsinfo.is_under("/ab", "/a")
    assert fsinfo.is_under("/anything", "/")


def test_space_and_threads(tmp_path):
    sp = fsinfo.space(str(tmp_path))
    assert sp is not None and sp.total > 0 and 0 <= sp.used_fraction <= 1
    assert sp.reserved >= 0 and sp.inodes_used <= sp.inodes_total
    assert fsinfo.space(str(tmp_path / "missing")) is None
    assert fsinfo.default_threads(fsinfo.Storage("network")) == 32
    assert fsinfo.default_threads(fsinfo.Storage("hdd"), cpus=16) == 8
    assert fsinfo.default_threads(fsinfo.Storage("ssd"), cpus=1) == 8
    assert fsinfo.default_threads(fsinfo.Storage("ssd"), cpus=4) == 16
    assert fsinfo.default_threads(fsinfo.Storage("virtual"), cpus=4) == 16
    assert fsinfo.default_threads(fsinfo.Storage("ssd"), cpus=64) == 32


def test_storage_kind_of_real_mount(tmp_path):
    m = fsinfo.mount_for(os.path.realpath(tmp_path), fsinfo.read_mounts())
    assert fsinfo.storage_kind(m).kind in ("ssd", "hdd", "virtual", "network", "memory", "unknown")
    assert fsinfo.storage_kind(None).kind == "unknown"


def test_deleted_open_file_is_found(tmp_path):
    p = tmp_path / "held.log"
    p.write_bytes(os.urandom(300_000))
    child = subprocess.Popen(
        [sys.executable, "-c", f"import time; f = open({str(p)!r}, 'rb'); print('ready', flush=True); time.sleep(30)"],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout.readline().strip() == "ready"
        os.unlink(p)
        rep = probes.deleted_open_files(os.stat(tmp_path).st_dev)
        hits = [f for f in rep.files if f.path == str(p)]
        assert hits, rep
        assert hits[0].alloc >= 300_000 // 2
        assert any(pid == child.pid for pid, _ in hits[0].pids)
        assert rep.total_alloc >= hits[0].alloc
    finally:
        child.kill()
        child.wait()


def _private_mounts_work():
    import shutil

    if os.geteuid() != 0 or not shutil.which("unshare"):
        return False
    return subprocess.run(["unshare", "-m", "--propagation", "private", "true"], capture_output=True).returncode == 0


@pytest.mark.skipif(not _private_mounts_work(), reason="needs root and mount namespaces")
def test_files_hidden_under_a_mount_point(tmp_path):
    """Write files into a folder, mount a tmpfs on top (in a private mount
    namespace) and check that the probe finds them."""
    (tmp_path / "backup").mkdir()
    (tmp_path / "backup" / "old.tar").write_bytes(os.urandom(3 << 20))
    code = f"""
import json, os, subprocess, sys
sys.path[:0] = {sys.path!r}
subprocess.run(["mount", "-t", "tmpfs", "none", {str(tmp_path / 'backup')!r}], check=True)
from whatfills import fsinfo, probes
mounts = fsinfo.read_mounts()
fs = fsinfo.mount_for({str(tmp_path)!r}, mounts)
covering = fsinfo.mount_for({str(tmp_path / 'backup')!r}, mounts)
rep = probes.hidden_under_mounts(fs, mounts)
print(json.dumps([rep.error, [(h.mount_point, h.alloc, h.files) for h in rep.found], os.listdir({str(tmp_path / 'backup')!r})]))
"""
    r = subprocess.run(["unshare", "-m", "--propagation", "private", sys.executable, "-c", code],
                       capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stderr
    import json

    error, found, visible = json.loads(r.stdout)
    assert visible == []  # the tmpfs hides the file
    assert error == ""
    assert [f[0] for f in found] == [str(tmp_path / "backup")]
    assert found[0][1] >= 3 << 20 and found[0][2] == 1


def test_used_percent_matches_df():
    from whatfills.fsinfo import Space

    # df: Use% = ceil(used / (used + avail)); 95.0001% shows as 96%
    sp = Space(total=1000, used=950_001, free=100, avail=49_999, inodes_total=0, inodes_free=0)
    assert sp.used_percent == 96
    assert Space(total=10, used=5, free=5, avail=5, inodes_total=0, inodes_free=0).used_percent == 50
    assert Space(total=0, used=0, free=0, avail=0, inodes_total=0, inodes_free=0).used_percent == 0


def test_virtual_disk_detection(tmp_path):
    # /sys/block/<disk>/queue, with the disk's vendor next to it
    disk = tmp_path / "devices" / "pci0000:00" / "block" / "sda"
    (disk / "queue").mkdir(parents=True)
    (disk / "device").mkdir()
    assert not fsinfo._is_virtual_disk(str(disk / "queue"))
    (disk / "device" / "vendor").write_text("QEMU    \n")
    assert fsinfo._is_virtual_disk(str(disk / "queue"))
    vd = tmp_path / "devices" / "pci0000:00" / "virtio1" / "block" / "vda"
    (vd / "queue").mkdir(parents=True)
    assert fsinfo._is_virtual_disk(str(vd / "queue"))
