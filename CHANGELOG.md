# Changelog

## 0.1.0 (unreleased)

First version.

- Parallel scanner in C++ (`getdents64` and `statx`) with bounded memory:
  totals for every folder, detail only for the ones that matter.
- 84 built-in rules that explain space by cause, each with a safety rating
  and the cleanup command of the tool that owns the data.
- Explains the difference between `df` and the scan: reserved blocks,
  deleted files still held open, files hidden under mount points (as root),
  unreadable folders and snapshots.
- Effort levels (`quick`, `normal`, `deep`), a time budget, and idle I/O
  priority for busy machines.
- Exclusions by path, name, full-path glob and filesystem type, from the
  command line or a config file.
- Stays on one filesystem by default; skips pseudo and network filesystems
  and does not count bind mounts twice.
- Hard-linked files counted once, with a warning when deleting a cause would
  free less than its size.
- Your own rules in TOML, checked with clear error messages.
- Snapshots and `whatfills diff` to see what grew.
- JSON output with a versioned schema.
