# How whatfills works

This note describes the parts that are not obvious from the README: how the
scanner walks a tree quickly with bounded memory, how space is attributed to
causes, and how the report explains the gap between `df` and the scan.

The code is split in two:

- `csrc/` is the scanner, in C++17, exposed to Python as `whatfills._core`
  with nanobind. It does all per-file work: reading folders, `statx`, rule
  matching, totals, hard links and the largest files.
- `src/whatfills/` is Python: settings and rules, mount planning, the probes
  (deleted-but-open files, files hidden under mount points), the report, the
  JSON output and snapshots.

Python only sees totals and the folders worth showing, so the boundary is
crossed once per scan rather than once per file.

## The scanner

### Walking the tree

Every folder is a task. Each worker thread keeps its own stack of folders to
read and works depth first: that keeps the working set small and the
filesystem's caches warm. When a worker sees that another one is idle, it
moves the oldest half of its stack (the folders nearest the root, which
usually hold the most work) to a shared queue, and idle workers take from
there. On a deep tree almost all work stays local, and on a wide one the
work spreads out quickly.

A folder is read with `getdents64` into a large buffer and each entry is
looked up with `statx`, asking only for the fields that are used (type, mode,
link count, owner, times, inode, size and blocks). `AT_NO_AUTOMOUNT` keeps
autofs mounts from being triggered. The quick effort level adds
`AT_STATX_DONT_SYNC`, which lets network filesystems answer from cached
attributes instead of a round trip per file. Kernels or sandboxes without
`statx` fall back to `fstatat`. Folders are opened with `O_NOATIME` when allowed, so a scan does
not change access times, and paths longer than `PATH_MAX` are opened one
component at a time with `openat`.

The default thread count depends on the storage, read from
`/sys/dev/block/*/queue/rotational`: one per core (2 to 8) on a rotating
disk, four per core (8 to 32) on an SSD, and 32 on network filesystems, where
each request mostly waits on latency. Virtual machine disks (virtio, Xen,
Hyper-V, VMware) usually claim to be rotating even when the host keeps them
on SSDs or network storage, so they are treated like SSDs. On a 4-core VM a
cold scan of a million files took 11.5 s with 4 threads and 8.1 s with 16.
`--io low` and `--io idle` set the I/O priority of every worker with
`ioprio_set`.

### Totals without locks

Each folder counts its children that are not finished yet. When the last one
finishes, it adds its totals (blocks, apparent size, files, folders, newest
change) to its parent with atomic adds, and the parent may then finish in
turn. Nothing is locked, and a folder's totals are final as soon as it is
finished.

### Bounded memory

A finished folder smaller than the effort level's threshold (1 MiB by
default) drops its sub-folders: its totals already include them. A kept
folder lists its sub-folders above the threshold plus its 20 largest smaller
ones, so small scans still show some structure. The tree held in memory is
therefore proportional to the number of folders that matter, not to the
number of files. Everything that needs per-file detail (the largest files,
per-cause file lists, owners, file types) is collected into fixed-size
per-thread tables while the scan runs.

### Stopping early

A time budget (`--budget`, or 30 seconds with `--effort quick`) or Ctrl-C
stops the workers. Unfinished folders are marked incomplete, totals are
folded up as far as they got, and the report says it is partial and how much
of the used space it covered.

### Filesystem boundaries

A folder on a different device than its parent is either a mount point or a
btrfs subvolume. Python reads `/proc/self/mountinfo` before the scan and
passes the mount points to the scanner, so the two can be told apart. Mount
points are skipped when staying on one filesystem, and subvolumes unless
`--cross-subvolumes` is given. Both are listed in the report.

When crossing mounts, Python plans which ones to enter, shallowest first:

- pseudo, memory and image filesystems (`proc`, `sysfs`, `tmpfs`, `squashfs`
  for snaps and so on) are never entered;
- network filesystems are skipped, since a slow server would stall the scan;
  scanning one directly works;
- a bind mount whose source is inside the scanned tree on the same
  filesystem is skipped, because those files are already counted where they
  really are. A mount that binds a folder onto itself is kept.

## Rules and causes

A rule says what a folder or file is. Folder rules match by an exact path
(`/var/log/journal`, or `~/.cache/pip` in every home folder), by the end of a
path (`node_modules`, `.cache/huggingface`), and optionally by a file that
must exist inside (`pyvenv.cfg` for virtual environments) or next to the
folder (`Cargo.toml` for Rust `target` folders). File rules match names
(`*.iso`, `*-json.log`) with an optional minimum size and conditions on the
folder rules they must be inside or outside.

Rules are compiled once into tables the scanner checks inline:

- when a folder is created, the folder rules are tried against its path.
  If several match, the first in priority order wins: your own rules before
  the built-in ones, then the order of the rules files, and within one rule
  exact paths before path endings;
- a folder without a match inherits its parent's cause, so a deeper match
  takes over below it: `~/.cache` is "Other app caches", but
  `~/.cache/pip` inside it is "pip download cache";
- a rule marked `opaque` owns everything below its folders: no other folder
  rule is tried inside, so a `.git` folder inside `node_modules`, or a
  virtual environment inside a Docker image layer, stays with the folder
  that holds it;
- each file belongs to the first matching file rule, or else to its folder's
  cause.

The bytes of each file are added to exactly one cause, which is why the
causes always add up to the scanned total. Each match also records the bytes
that belong to its rule (not counting the parts that more specific rules
took), which is how the report can label `.cache` as "mostly Hugging Face
models" rather than "app caches" when that is where its space really is.

Exclusions are checked before anything is opened: exact paths with a hash
lookup, names with a small glob matcher, and full-path globs with a cheap
literal check first, so that a pattern like `/srv/**/raw` costs little on
paths that cannot match.

## Hard links

A file with more than one link is looked up in a sharded table keyed by
device and inode. The first path to reach it counts its blocks; later ones
only add to its link count. The table also remembers the cause that counted
the file, so the report can say:

- how much of a cause is in files that are also linked from outside the
  scan, or from another cause, so deleting that cause frees less than its
  size;
- how many files were linked from places with different causes (a package
  cache and the environments installed from it, for example).

The table is capped by the effort level (8 million files by default). Links
found after that are counted again, and the report says how many there were.

## Explaining `df`

For a whole-filesystem scan the report compares the filesystem's own numbers
(`statvfs`) with the scan and explains the difference:

- **Reserved blocks:** free space only root can use (`free - avail`), which
  is why `df` can show 100% while root can still write.
- **Deleted but open files:** Python reads `/proc/*/fd`, keeps the links that
  end in `(deleted)` and point at the scanned device, and sums the blocks of
  each such file once, listing the processes that hold it. Without root only
  your own processes can be read, and the report says so.
- **Files hidden under mount points:** files written into a folder before a
  filesystem was mounted on top of it still use space, but no path leads to
  them. As root, whatfills starts a child process with `unshare -m
  --propagation private`, which bind-mounts the filesystem (without its
  submounts) on a scratch folder in `/run` or `/dev/shm` inside that private
  namespace, and scans the folders under each mount point there. Nothing
  changes outside that namespace, and the bind mount goes away when the
  child exits. The check runs only when the scan found at least 256 MiB less
  than the filesystem reports as used, and it stops after 15 seconds.
- **Unreadable folders, btrfs subvolumes and snapshots**, and filesystem
  metadata on btrfs, ZFS and bcachefs are named as possible reasons when they
  apply.

## Snapshots

`--save` writes the JSON report, with every kept folder, gzip-compressed to
`~/.local/state/whatfills/snapshots/<folder>-<hash>/`. File names are
timestamps with milliseconds, so they sort in time order and two quick saves
do not collide. `whatfills diff` compares folder sizes and cause totals
between two snapshots. A folder missing from one snapshot counts as new (or
gone) only if that snapshot listed its parent's sub-folders; otherwise it was
just too small to keep and is not compared. A folder is left out of the list
when one folder inside it explains most of its change, so the diff points at
the most specific places that grew.

## JSON

`--json` writes the report as one JSON object. `schema` is the format
version; it changes only when fields are renamed or removed, and new fields
may be added at any time. Sizes are in bytes. `started_at` is an ISO 8601
time, and file and folder times (`mtime`) are Unix timestamps. The main
keys are `filesystem`, `scanned`, `causes` (with `locations`, `files_top`,
`bytes_by_age`, `fixes` and `tips`), `folders`, `largest_files`, `owners`,
`types`, `deleted_open_files`, `hidden_under_mounts`, `hard_links`,
`problems` and `skipped`.

## Testing

`tests/` covers each part on its own: the scanner against `du` and against
pruning, exclusions, hard links, the rule matcher, configuration errors, mount
planning (including real bind mounts in user namespaces), the report text at
several widths, snapshots and the CLI. Tests that need root, such as the
hidden-files check, are skipped for normal users, and a few that only make
sense without root are skipped for root.
