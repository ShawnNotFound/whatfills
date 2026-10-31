"""Filesystem facts: mounts, free space, storage type."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# Kernel and virtual filesystems that never hold user data on a disk.
PSEUDO_FSTYPES = frozenset(
    {
        "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "pstore", "bpf", "tracefs",
        "debugfs", "securityfs", "configfs", "fusectl", "mqueue", "hugetlbfs", "autofs",
        "binfmt_misc", "efivarfs", "nsfs", "rpc_pipefs", "selinuxfs", "ramfs", "nfsd", "fuse.gvfsd-fuse",
        "fuse.portal", "fuse.lxcfs",
    }
)  # fmt: skip

# Skipped by default when crossing into other filesystems: memory-backed or
# read-only images whose bytes live somewhere else (snap squashfs images are
# already counted as .snap files under /var/lib/snapd).
DEFAULT_CROSS_SKIP_FSTYPES = frozenset({"tmpfs", "squashfs", "overlay", "iso9660", "udf"})

NETWORK_FSTYPES = frozenset(
    {
        "nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "glusterfs", "fuse.glusterfs", "lustre", "gpfs",
        "beegfs", "fuse.sshfs", "sshfs", "fuse.rclone", "9p", "afs", "fuse.s3fs", "fuse.cephfs", "orangefs",
        "fuse.juicefs", "wekafs", "panfs",
    }
)  # fmt: skip


@dataclass
class Mount:
    mount_id: int
    parent_id: int
    dev: int  # same encoding as os.stat().st_dev
    root: str  # path inside the filesystem that is mounted here ("/" unless a bind mount)
    mount_point: str
    options: str
    fstype: str
    source: str
    super_options: str = ""

    @property
    def is_pseudo(self) -> bool:
        return self.fstype in PSEUDO_FSTYPES

    @property
    def is_network(self) -> bool:
        return self.fstype in NETWORK_FSTYPES

    @property
    def readonly(self) -> bool:
        return "ro" in self.options.split(",")

    @property
    def atime_mode(self) -> str:
        """How access times are kept: "noatime" means they are not updated at all."""
        opts = set(self.options.split(","))
        if "noatime" in opts:
            return "noatime"
        if "strictatime" in opts:
            return "strictatime"
        return "relatime"  # kernel default since 2.6.30


_ESCAPE_RE = re.compile(r"\\([0-7]{3})")


def _unescape(s: str) -> str:
    """mountinfo escapes space, tab, newline and backslash as \\ooo."""
    return _ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 8)), s)


def parse_mountinfo(text: str) -> list[Mount]:
    mounts = []
    for line in text.splitlines():
        if not line.strip():
            continue
        left, sep, right = line.partition(" - ")
        if not sep:
            continue
        a = left.split()
        b = right.split()
        if len(a) < 6 or len(b) < 2:
            continue
        try:
            major, minor = (int(x) for x in a[2].split(":"))
        except ValueError:
            continue
        mounts.append(
            Mount(
                mount_id=int(a[0]),
                parent_id=int(a[1]),
                dev=os.makedev(major, minor),
                root=_unescape(a[3]),
                mount_point=_unescape(a[4]),
                options=a[5],
                fstype=b[0],
                source=_unescape(b[1]),
                super_options=b[2] if len(b) > 2 else "",
            )
        )
    return mounts


def read_mounts(path: str = "/proc/self/mountinfo") -> list[Mount]:
    try:
        with open(path, encoding="utf-8", errors="surrogateescape") as f:
            return parse_mountinfo(f.read())
    except OSError:
        return []


def is_under(path: str, top: str) -> bool:
    """True if `path` is `top` or inside it (both normalised absolute paths)."""
    if top == "/":
        return path.startswith("/")
    return path == top or path.startswith(top + "/")


def mount_for(path: str, mounts: list[Mount]) -> Mount | None:
    """The mount that holds `path`: the last-mounted entry with the longest
    mount point that is a prefix of the path (later mounts hide earlier ones)."""
    best = None
    for m in mounts:
        if is_under(path, m.mount_point):
            if best is None or len(m.mount_point) >= len(best.mount_point):
                best = m
    return best


def mounts_under(root: str, mounts: list[Mount]) -> list[Mount]:
    """Mounts strictly below `root`, without the ones hidden by later mounts on the same point."""
    seen: dict[str, Mount] = {}
    for m in mounts:
        if m.mount_point != root and is_under(m.mount_point, root):
            seen[m.mount_point] = m  # a later mount on the same point wins
    return list(seen.values())


@dataclass
class Space:
    total: int
    used: int  # total - free; includes blocks reserved for root that are in use
    free: int  # free blocks, including the reserved ones
    avail: int  # free blocks that normal users can use
    inodes_total: int
    inodes_free: int

    @property
    def reserved(self) -> int:
        return max(0, self.free - self.avail)

    @property
    def used_fraction(self) -> float:
        # Same formula as df: used / (used + avail).
        denom = self.used + self.avail
        return self.used / denom if denom else 0.0

    @property
    def used_percent(self) -> int:
        """Use% as df prints it: rounded up, so a nearly full disk never shows a lower number."""
        denom = self.used + self.avail
        return -(-self.used * 100 // denom) if denom else 0

    @property
    def inodes_used(self) -> int:
        return max(0, self.inodes_total - self.inodes_free)

    @property
    def inodes_fraction(self) -> float:
        return self.inodes_used / self.inodes_total if self.inodes_total else 0.0


def space(path: str) -> Space | None:
    try:
        s = os.statvfs(path)
    except OSError:
        return None
    total = s.f_blocks * s.f_frsize
    free = s.f_bfree * s.f_frsize
    return Space(
        total=total,
        used=total - free,
        free=free,
        avail=s.f_bavail * s.f_frsize,
        inodes_total=s.f_files,
        inodes_free=s.f_ffree,
    )


@dataclass
class Storage:
    kind: str  # "ssd", "hdd", "virtual", "network", "memory" or "unknown"
    device: str = ""
    details: dict = field(default_factory=dict)


def _block_queue_dir(major: int, minor: int) -> str | None:
    base = f"/sys/dev/block/{major}:{minor}"
    try:
        real = os.path.realpath(base)
    except OSError:
        return None
    if os.path.exists(os.path.join(real, "partition")):
        real = os.path.dirname(real)
    q = os.path.join(real, "queue")
    return q if os.path.isdir(q) else None


# Virtual machine disks often report themselves as rotating even when the
# host stores them on SSDs or network block storage, where many requests in
# flight help a lot (a cold scan here ran 1.4x faster with 16 threads than 4).
_VIRTUAL_BUSES = ("/virtio", "/vmbus", "/xen")
_VIRTUAL_VENDORS = ("QEMU", "VMWARE", "MSFT", "VBOX", "XEN", "AMAZON", "GOOGLE")


def _is_virtual_disk(queue_dir: str) -> bool:
    disk = os.path.dirname(queue_dir)
    if any(bus in os.path.realpath(disk).lower() for bus in _VIRTUAL_BUSES):
        return True
    for name in ("device/vendor", "device/model"):
        try:
            with open(os.path.join(disk, name)) as f:
                value = f.read().strip().upper()
        except OSError:
            continue
        if value.startswith(_VIRTUAL_VENDORS):
            return True
    return False


def storage_kind(m: Mount | None) -> Storage:
    if m is None:
        return Storage("unknown")
    if m.is_network:
        return Storage("network", m.source)
    if m.fstype in ("tmpfs", "ramfs"):
        return Storage("memory", m.source)
    dev = None
    if m.source.startswith("/dev/"):
        try:
            dev = os.stat(m.source).st_rdev
        except OSError:
            dev = None
    if dev is None or os.major(dev) == 0:
        dev = m.dev
    if os.major(dev) == 0:
        return Storage("unknown", m.source)
    q = _block_queue_dir(os.major(dev), os.minor(dev))
    if q is None:
        return Storage("unknown", m.source)
    try:
        with open(os.path.join(q, "rotational")) as f:
            rot = f.read().strip() == "1"
    except OSError:
        return Storage("unknown", m.source)
    if rot and _is_virtual_disk(q):
        return Storage("virtual", m.source)
    return Storage("hdd" if rot else "ssd", m.source)


def default_threads(storage: Storage, cpus: int | None = None) -> int:
    """Worker threads for a scan. Directory walking is mostly waiting on the
    kernel or the disk, so more threads than cores helps on fast storage and a
    lot more helps on network filesystems, where each request has latency."""
    cpus = cpus or os.cpu_count() or 4
    if storage.kind == "network":
        return 32
    if storage.kind == "hdd":
        return min(8, max(2, cpus))
    return min(32, max(8, cpus * 4))
