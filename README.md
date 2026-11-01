# whatfills

Find out why a Linux disk is full, and what you can safely do about it.

`whatfills` scans a filesystem quickly and explains the space by cause:
Docker, the systemd journal, package caches, old kernels, Hugging Face
models, virtual environments and about 80 other things that commonly fill
disks. It also accounts for space that `du` cannot see, such as deleted files
that a running program still holds open and files hidden under a mount point.
For each cause it says how safe it is to delete and prints the command that
frees it. It never deletes anything itself.

```
$ sudo whatfills /
whatfills 0.1.0.dev0  / on ext4 (/dev/loop0, SSD)
Scanned 82,229 files in 10,799 folders in 554 ms (normal effort, 16 threads, disk usage).

Disk
  54.8 GiB total, 49.4 GiB used, 2.6 GiB free for normal users  █████████████████████████████░░ 96%
  2.8 GiB more is reserved for root (only root can write there).
  The scan found 45.2 GiB in files and folders (91.4% of used).
  Not found by the scan: 4.3 GiB. Likely reasons:
       2.4 GiB  deleted files that running programs still hold open (see below)
       1.9 GiB  files hidden under 2 mount points (see below)

Why it's full: space by cause
     8.3 GiB  18.3%  Docker images, containers and build cache  caution
                     /var/lib/docker
     6.2 GiB  13.7%  Hugging Face models and datasets           regenerable
                     /home/alex/.cache/huggingface (100% not used in 90+ days)
     4.0 GiB   8.8%  systemd journal (system logs)              safe
                     /var/log/journal (88% not used in 90+ days)
     3.3 GiB   7.3%  Docker container logs                      review
                     2 files, biggest /var/lib/docker/containers/14c2529e…/14c2529e…-json.log
     2.6 GiB   5.8%  Disk images (ISO)                          review
                     /…/Downloads/ubuntu-24.04.1-live-server-amd64.iso (100% not used in 90+ days)
  ...
  17.9 GiB (39.7%) is caches or files that can be rebuilt or downloaded again.

Files hidden under mount points
  These files were written into a folder before another filesystem was mounted on top of it. They
  still use space here, but nothing can reach them until that filesystem is unmounted.
     1.6 GiB  /mnt/backup  (1 file)
   259.8 MiB  /tmp  (300 files)
  ...

Deleted files still using space
  These files were deleted, but a running program still has them open, so their space is not freed
  until that program closes them or restarts.
     2.4 GiB  /var/log/app/worker.log  held by worker (pid 18347)

What you can do
  ...
  3. systemd journal (system logs): 4.0 GiB in /var/log/journal
     Safe to delete. It is a cache or a leftover, and nothing you need is lost.
     Logs collected by systemd-journald. Unless a limit is set, the journal may use up to 10% of the
     filesystem, capped at 4 GiB. Shrinking it removes the oldest entries first.
       $ sudo journalctl --vacuum-size=500M
         Shrink the journal to 500 MB
       $ sudo journalctl --disk-usage
         Show how much the journal uses
     Tip: To cap it for good, set SystemMaxUse=500M in /etc/systemd/journald.conf (or in a file
     under /etc/systemd/journald.conf.d/), then run: sudo systemctl restart systemd-journald
```

This is real output, shortened, from a 56 GB test disk set up to look like a
small web server that ran out of space. The [full output](docs/example-output.txt)
also has the largest folders and files, space by owner and the advice for
every cause.

## Why use it

Tools like ncdu, gdu, dua and dust are good at showing where the bytes are.
When a server has just run out of space, the next questions are usually what
the bytes are, whether they are safe to delete, and why `df` says the disk is
full when `du` finds less. That is what whatfills is for.

- **Causes, not just folders.** 85 built-in rules recognise system logs,
  package manager caches, snap revisions, Docker and other container storage,
  crash dumps, old kernels, databases, language and build caches, ML model
  caches and personal folders. Every byte is counted under exactly one cause,
  and the most specific rule wins, so a pip cache inside `~/.cache` counts as
  the pip cache, not as a generic cache.
- **Safety rating and the official fix.** Each cause is rated `safe`,
  `regenerable`, `review` or `caution`, with the command its own tool provides
  (`journalctl --vacuum-size`, `docker system prune`, `apt-get clean`,
  `huggingface-cli delete-cache` and so on) rather than `rm -rf`.
- **It explains the whole `df` number.** It compares what the scan found with
  what the filesystem reports as used. It measures deleted files that are
  still held open (and names the process holding them), files hidden under
  mount points and the space reserved for root, and it names the other likely
  reasons, such as btrfs or ZFS snapshots and folders it could not read.
- **Fast, with bounded memory.** The scanner is written in C++ and walks
  folders in parallel with `getdents64` and `statx`. It keeps totals for
  every folder but details only for the bigger ones, so memory stays small on
  huge trees. On a benchmark of a million files it was the fastest of the six
  tools tried, with a warm or a cold cache, and used 35 MiB (see
  [Benchmark](#benchmark)).
- **Polite on busy machines.** It stays on one filesystem by default, never
  enters pseudo filesystems such as `/proc`, leaves network filesystems alone
  unless you scan one directly, can run at idle I/O priority (`--io idle`),
  and can stop after a time limit and report what it found (`--budget 5m`, or
  `--effort quick` for an answer within about 30 seconds).
- **Shared space is handled.** Hard-linked files are counted once, and the
  report says when deleting a cause would free less than its size because
  some of its files are also linked from elsewhere. Bind mounts are not
  counted twice.
- **What grew since last time.** Save a snapshot with `--save`, and later
  `whatfills diff /` shows which causes and folders grew.
- **Scriptable.** `--json` writes the whole report as JSON with a versioned
  schema.
- **Read-only and offline.** It never deletes, moves or changes files. It
  makes no network connections of its own and collects no telemetry.

## Install

whatfills is not on PyPI yet. It needs Linux, Python 3.9 or newer and a C++17
compiler (GCC 8 or newer, or Clang 7 or newer). The build fetches its own
build tools.

```sh
# Debian or Ubuntu: a compiler and the Python headers
sudo apt install g++ python3-dev python3-venv pipx

pipx install git+https://github.com/ShawnNotFound/whatfills
```

Or from a checkout:

```sh
git clone https://github.com/ShawnNotFound/whatfills
cd whatfills
pip install .
```

If the disk is already too full to install anything, install into memory
instead (about 15 MB); nothing is written to the full disk:

```sh
python3 -m venv /dev/shm/whatfills
TMPDIR=/dev/shm /dev/shm/whatfills/bin/pip install --no-cache-dir git+https://github.com/ShawnNotFound/whatfills
sudo /dev/shm/whatfills/bin/whatfills /
```

## Usage

```sh
whatfills                       # the filesystem that holds the current folder
sudo whatfills /                # the root filesystem, including other users' files
whatfills ~ --effort quick      # an answer within about 30 seconds
whatfills /data --exclude /data/private --exclude-name '.snapshot*'
whatfills / --save              # keep a snapshot; later `whatfills diff /` shows what grew
whatfills / --json report.json  # the full report as JSON (--json alone prints it)
```

Running it as root (with `sudo`) lets it read every folder, find deleted files
held open by other users' programs, and measure files hidden under mount
points. When you run it with `sudo`, the commands it suggests still start with
`sudo`, because you will usually paste them into your own shell.

Run `whatfills scan --help` for every option.

### Effort levels

|                           | `quick`            | `normal` (default) | `deep`             |
|---------------------------|--------------------|--------------------|--------------------|
| Time limit                | 30 s, then reports what it found and how much of the used space that covers | none | none |
| Folders listed in detail  | 16 MiB and bigger  | 1 MiB and bigger   | 64 KiB and bigger  |
| Largest files tracked     | 50                 | 200                | 1,000              |
| Space by file type        | no                 | in the JSON report | yes                |

Every effort level visits every file (unless the time limit stops it), so
the totals are exact; higher effort only keeps more detail. `--budget` sets a
time limit for any effort level.

### Leaving things out

Excluded paths are never opened or measured.

```sh
whatfills / --exclude /srv/backups              # a folder or file
whatfills / --exclude-name '.snapshot*'         # a name anywhere, * and ? allowed
whatfills / --exclude-glob '/home/*/mnt/**'     # a full-path pattern, ** crosses folders
whatfills / --cross-mounts --exclude-fstype nfs4
```

### Config file

`whatfills config init` writes a commented config file to
`~/.config/whatfills/config.toml`. A system-wide one can go in
`/etc/whatfills/config.toml`. Under `sudo`, your own config is read as well
as root's. Command-line flags win over config files, and list settings (such
as exclusions) add up.

```toml
[scan]
effort = "normal"
io_priority = "low"

[exclude]
paths = ["/data/private"]
names = [".snapshots", "*.vmdk"]

[rules]
disable = ["personal-folders"]
```

`whatfills config show` prints the settings in effect and the config files
that were read.

### Rules

```sh
whatfills rules list           # every active rule
whatfills rules show journald  # what a rule matches and what it suggests
whatfills rules check my.toml  # check a rules file for mistakes
```

You can add rules, or replace built-in ones by reusing their `id`, with TOML
files in `~/.config/whatfills/rules.d/` or `/etc/whatfills/rules.d/`, or with
`--rules FILE`:

```toml
[[rule]]
id = "render-cache"
name = "Render farm cache"
category = "caches"
safety = "safe"
paths = ["/srv/render/cache"]   # an exact folder; "~/x" means x in every home folder
dirs = [".render-cache"]        # or: any folder whose path ends with these parts
explain = "Intermediate frames. The farm recreates them when a job is resubmitted."
fix = [{ label = "Clear frames older than a week", run = "find /srv/render/cache -mtime +7 -delete", root = true }]
```

Folder rules can also require a name inside the folder
(`require_child = ["HEAD"]`) or next to it (`require_sibling = ["Cargo.toml"]`).
With `dirs = ["*"]` and `require_child`, a rule matches any folder that holds
that name, whatever the folder is called. That is how virtual environments
(`pyvenv.cfg`) and conda environments (`conda-meta`) are found. With
`opaque = true` everything inside belongs to the rule: no other folder rule
matches below it, so a `.git` or `build` folder inside `node_modules` counts
as `node_modules`.

File rules use `files = ["*.iso"]` instead of `paths` or `dirs`, and can add
`min_size`, `within` or `outside` (ids of folder rules). They also apply
inside opaque folders. Mistakes are reported with the file, the rule and a
suggestion, for example `unknown key 'dirz' (did you mean 'dirs'?)`. The
built-in rules are in [`src/whatfills/data/rules`](src/whatfills/data/rules).

| Safety        | Meaning |
|---------------|---------|
| `safe`        | A cache or a leftover. Nothing you need is lost. |
| `regenerable` | Rebuilt or downloaded again when needed, which takes time. |
| `review`      | May hold things you want to keep. Look before deleting. |
| `caution`     | Do not delete by hand. Use the suggested command or the program that owns it. |

### Snapshots

`--save` stores a compressed snapshot of the scan in
`~/.local/state/whatfills/snapshots/`. Later:

```sh
whatfills diff /               # compare the last two snapshots of /
whatfills diff old.json.gz new.json.gz
whatfills snapshots            # list them
whatfills / --save --compare   # scan, save, and show what changed since the last one
```

The diff lists the causes and the most specific folders that grew or shrank.

## How it counts

- **Disk usage**, like `du`: the blocks a file really uses, so sparse files
  and compression count as they are stored. `--apparent-size` reports file
  sizes instead. On ext4 the result matches `du -sxB1` to the byte.
- **One filesystem** by default, like `du -x`. Other filesystems mounted inside
  are listed at the end of the report; `--cross-mounts` includes them.
  Pseudo filesystems such as `/proc` and `tmpfs` are never entered, and
  network filesystems (NFS, CIFS, SSHFS, Lustre and others) only when you
  point whatfills at one directly. Btrfs subvolumes are skipped unless
  you pass `--cross-subvolumes`, because snapshots share data and would add
  up to more than they use.
- **Bind mounts** of folders that the scan already covers are not counted
  again.
- **Hard links:** each file is counted once, under the first path the scan
  reaches.
- **Deleted but open files** are found in `/proc/*/fd`. Without root, only
  your own processes can be checked.
- **Files hidden under mount points:** as root, whatfills makes a private
  bind mount of the filesystem inside its own mount namespace (nothing changes
  for the rest of the system, and it disappears when whatfills exits) and
  measures what is under each mount point. This needs `unshare` and `mount`
  from util-linux, and takes at most about 15 seconds.

[docs/design.md](docs/design.md) describes the scanner, the rules and these
checks in more detail.

## Benchmark

A synthetic tree of 1,000,000 files in 274,603 folders (1.1 GB, made with
`bench/make_tree.py`), on ext4 on the virtio disk of a 4-vCPU cloud VM (Intel
Xeon at 2.1 GHz, 15 GiB of RAM, Linux 6.18). Warm cache is the best of 3 runs;
cold cache drops the page cache before each run and takes the best of 2.
Peak memory is the largest resident set size.

| Command                     | Version    | Warm cache | Cold cache | Peak memory |
|-----------------------------|------------|-----------:|-----------:|------------:|
| `whatfills`                 | 0.1.0.dev0 |     1.39 s |     7.87 s |      35 MiB |
| `dust -x -n 1`              | 1.2.6      |     2.58 s |    11.69 s |     380 MiB |
| `gdu -n -x -p`              | 5.25.0     |     3.22 s |    12.89 s |     1.3 GiB |
| `ncdu -x -0 -o /dev/null`   | 1.19       |     4.20 s |    33.86 s |     2.4 MiB |
| `du -sxB1`                  | 9.4        |     4.35 s |    35.57 s |     3.4 MiB |
| `dua -f bytes`              | 2.46.0     |     6.14 s |    14.03 s |      25 MiB |

Notes for reading it fairly:

- whatfills chose 16 threads by itself; the others used their own defaults.
  Its time includes starting Python and building the whole report.
- gdu and dust keep the whole tree in memory so you can browse it, which is
  most of their memory use. whatfills keeps detail only for folders of 1 MiB
  or more, and `ncdu -o` and `du` write totals out as they go.
- gdu 5.25 is the Ubuntu 24.04 package; newer releases may do better.
- Cold-cache times on this VM varied by up to about 20% from one run to the
  next.

To reproduce (the cold-cache runs need root):

```sh
python bench/make_tree.py /tmp/wf-bench --files 1000000
python bench/bench.py /tmp/wf-bench
sudo python bench/bench.py /tmp/wf-bench --drop-caches --runs 2
```

The exact command for each tool is in [`bench/bench.py`](bench/bench.py).

## Limitations

- Linux only for now.
- No interactive browsing yet. To explore folder by folder, ncdu, gdu and dua
  are better today.
- It does not delete anything. Some will see that as a missing feature: gdu,
  dua and ncdu let you delete from inside the tool.
- Building needs a compiler and Python, and there is no prebuilt package yet.
- Blocks shared through reflinks (btrfs, XFS) are not detected, so copies made
  with `cp --reflink` are counted at full size each.
- The rules are informed guesses about what a folder is. Check the path before
  you delete anything, especially for `review` and `caution` causes.

## Roadmap

- Wheels on PyPI (`pipx install whatfills`) and distribution packages.
- A single-file build that runs from `/dev/shm` on a full disk.
- Guided cleanup: pick causes, see a dry run, then run the suggested commands,
  with a log.
- An interactive view for drilling into folders.
- "Freed if removed" sizes that account for reflinks and snapshots.
- Export to and import from the ncdu JSON format.
- macOS support.

## Contributing

Bug reports with the output of `whatfills --version` and the command you ran
are very welcome. New rules are the easiest way to help: add one to the right
file in `src/whatfills/data/rules`, check it with `whatfills rules check`, and
say in the pull request where the folder comes from and why the safety rating
fits.

To work on the code:

```sh
git clone https://github.com/ShawnNotFound/whatfills
cd whatfills
python3 -m venv .venv && . .venv/bin/activate
pip install -e . pytest
pytest
```

A few tests only run as root (they use mount namespaces) and a few only as a
normal user; pytest skips the ones that do not apply and says why.

## License

Apache License 2.0. See [LICENSE](LICENSE).
