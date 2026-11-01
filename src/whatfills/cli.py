"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, config, fsinfo, report, snapshot
from .config import ConfigError, Settings
from .rules import SAFETY, RuleError, RuleSet, load_rules_file
from .scan import ScanError, run_scan
from .term import ProgressLine, Style, color_enabled, show, width
from .units import format_size, parse_duration

COMMANDS = ("scan", "diff", "snapshots", "rules", "config")

EPILOG = """\
examples:
  whatfills                      why is the disk holding the current folder full?
  sudo whatfills /               the root filesystem, including other users' files
  whatfills ~ --effort quick     an answer in about 30 seconds
  whatfills /data --exclude /data/private --exclude-name '.snapshot*'
  whatfills / --save             keep a snapshot; later `whatfills diff /` shows what grew
  whatfills / --json report.json
"""


class UsageError(Exception):
    pass


def _scan_parser(sub) -> argparse.ArgumentParser:
    p = sub.add_parser(
        "scan",
        help="scan a folder and explain what uses the space (the default command)",
        description="Scan a folder or filesystem and explain what is using the space.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("path", nargs="?", help="folder to scan (default: the filesystem holding the current folder)")
    g = p.add_argument_group("how to scan")
    g.add_argument("-e", "--effort", choices=config.EFFORTS, help="quick (about 30 s), normal (default) or deep (more detail)")
    g.add_argument("-j", "--threads", type=int, help="worker threads (default: picked from the storage type)")
    g.add_argument("-b", "--budget", metavar="TIME", help="stop after this long and report what was found, e.g. 45s or 5m")
    g.add_argument("--cross-mounts", action="store_true", help="also scan other filesystems mounted inside the folder")
    g.add_argument("--cross-subvolumes", action="store_true", help="also scan btrfs subvolumes")
    g.add_argument("--io", choices=config.IO_PRIORITIES, help="disk priority: low or idle are gentler on busy machines")
    g.add_argument("--apparent-size", action="store_true", help="report file sizes instead of the disk space they use")
    x = p.add_argument_group("what to skip (never opened or measured)")
    x.add_argument("--exclude", action="append", default=[], metavar="PATH", help="a folder or file (repeatable)")
    x.add_argument("--exclude-name", action="append", default=[], metavar="NAME", help="a file or folder name, * and ? allowed")
    x.add_argument("--exclude-glob", action="append", default=[], metavar="GLOB", help="a full-path pattern, ** crosses folders")
    x.add_argument("--exclude-fstype", action="append", default=[], metavar="TYPE", help="a filesystem type, with --cross-mounts")
    o = p.add_argument_group("output")
    o.add_argument("-n", "--top", type=int, help="rows per section (default 10)")
    o.add_argument("--json", nargs="?", const="-", metavar="FILE", help="write a JSON report to FILE (or stdout)")
    o.add_argument("--save", nargs="?", const="", metavar="FILE", help="save a snapshot for `whatfills diff` later")
    o.add_argument("--compare", action="store_true", help="after scanning, show what changed since the last saved snapshot")
    o.add_argument("--color", choices=config.COLOR_MODES, help="colour output (default auto)")
    o.add_argument("--no-color", action="store_const", const="never", dest="color", help="same as --color never")
    o.add_argument("-q", "--quiet", action="store_true", help="no progress line")
    c = p.add_argument_group("settings and rules")
    c.add_argument("--config", metavar="FILE", help="read this config file as well")
    c.add_argument("--no-config", action="store_true", help="ignore the usual config files")
    c.add_argument("--rules", action="append", default=[], metavar="FILE", help="extra rules file (repeatable)")
    c.add_argument("--disable-rule", action="append", default=[], metavar="ID", help="turn off a built-in rule")
    c.add_argument("--no-builtin-rules", action="store_true", help="use only your own rules")
    return p


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="whatfills",
        description="Find out why a disk is full: a fast scan that explains what is using the space and how to free it.",
        epilog=EPILOG + "\nRun `whatfills scan --help` for all scan options.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"whatfills {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    _scan_parser(sub)

    d = sub.add_parser("diff", help="show what changed between two saved snapshots")
    d.add_argument("old", nargs="?", help="older snapshot file, or a folder to compare its last two snapshots")
    d.add_argument("new", nargs="?", help="newer snapshot file (default: the latest one for the same folder)")
    d.add_argument("-n", "--top", type=int, default=15, help="rows per section")
    d.add_argument("--json", action="store_true", help="print JSON")
    d.add_argument("--color", choices=config.COLOR_MODES, default="auto")

    s = sub.add_parser("snapshots", help="list saved snapshots")
    s.add_argument("path", nargs="?", help="the scanned folder (default: all folders with snapshots)")

    r = sub.add_parser("rules", help="list, show or check rules")
    rs = r.add_subparsers(dest="rules_cmd", metavar="ACTION")
    rs.add_parser("list", help="list the active rules")
    show_p = rs.add_parser("show", help="show one rule")
    show_p.add_argument("id")
    chk = rs.add_parser("check", help="check a rules file for mistakes")
    chk.add_argument("file")

    cfg = sub.add_parser("config", help="show or create the config file")
    cs = cfg.add_subparsers(dest="config_cmd", metavar="ACTION")
    cs.add_parser("show", help="show the settings in effect and where they come from")
    cs.add_parser("init", help="write a commented config file to fill in")
    cs.add_parser("path", help="print the config files that are read")
    return parser


def _settings_from_args(args) -> Settings:
    settings = config.load(extra_file=args.config, read_default_files=not args.no_config)
    values = {}
    if args.effort:
        values["scan.effort"] = args.effort
    if args.threads is not None:
        values["scan.threads"] = args.threads
    if args.budget is not None:
        try:
            values["scan.time_budget"] = parse_duration(args.budget)
        except ValueError as e:
            raise UsageError(f"--budget: {e}") from None
    if args.cross_mounts:
        values["scan.one_file_system"] = False
    if args.cross_subvolumes:
        values["scan.cross_subvolumes"] = True
    if args.io:
        values["scan.io_priority"] = args.io
    if args.apparent_size:
        values["scan.apparent_size"] = True
    if args.top is not None:
        values["report.top"] = args.top
    if args.color:
        values["report.color"] = args.color
    for key, attr in (("exclude.paths", "exclude"), ("exclude.names", "exclude_name"),
                      ("exclude.globs", "exclude_glob"), ("exclude.fstypes", "exclude_fstype"),
                      ("rules.files", "rules"), ("rules.disable", "disable_rule")):  # fmt: skip
        if getattr(args, attr):
            values[key] = list(getattr(args, attr))
    if args.no_builtin_rules:
        values["rules.builtin"] = False
    config.apply(settings, values, base_dir=os.getcwd())
    return settings


def _default_target() -> tuple[str, str]:
    cwd = os.getcwd()
    m = fsinfo.mount_for(os.path.realpath(cwd), fsinfo.read_mounts())
    if m is None:
        return cwd, ""
    return m.mount_point, f"No folder given, so scanning the filesystem that holds the current folder: {show(m.mount_point)}"


def _check_output_path(path: str, flag: str) -> None:
    """Fail before a long scan, not after it, when an output file cannot be written."""
    full = os.path.abspath(os.path.expanduser(path))
    folder = os.path.dirname(full)
    if os.path.isdir(full):
        raise UsageError(f"{flag}: {path} is a folder; give a file name")
    if not os.path.isdir(folder):
        raise UsageError(f"{flag}: the folder {folder} does not exist")
    # Really try it: permissions are not the only reason a write fails
    # (read-only or special filesystems such as /proc, a full disk, quotas).
    existed = os.path.lexists(full)
    try:
        with open(full, "ab"):
            pass
    except OSError as e:
        raise UsageError(f"{flag}: cannot write {path}: {e.strerror or e}") from None
    if not existed:
        try:
            os.unlink(full)
        except OSError:
            pass


def _active_rules(settings: Settings) -> RuleSet:
    return RuleSet.load(extra_files=settings.rules_files, disable=settings.rules_disable,
                        builtin=settings.builtin_rules)  # fmt: skip


def cmd_scan(args) -> int:
    settings = _settings_from_args(args)
    for w in settings.warnings:
        print(f"whatfills: warning: {w}", file=sys.stderr)
    if args.json not in (None, "-"):
        _check_output_path(args.json, "--json")
    if args.save:
        _check_output_path(args.save, "--save")
    rules = _active_rules(settings)
    target = args.path
    if target is None:
        target, msg = _default_target()
        if msg and not args.quiet:
            print(msg, file=sys.stderr)
    json_to_stdout = args.json == "-"
    progress = ProgressLine(enabled=None if not args.quiet else False)
    try:
        result = run_scan(target, settings, rules, on_progress=progress)
    finally:
        progress.clear()

    style = Style(color_enabled(settings.color))
    if not json_to_stdout:
        sys.stdout.write(report.render_text(result, style, top=settings.top, cols=width()))
        sys.stdout.flush()
    if args.json is not None:
        data = report.to_dict(result, top=max(50, settings.top))
        text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        if json_to_stdout:
            sys.stdout.write(text.encode("utf-8", "surrogateescape").decode("utf-8", "replace"))
        else:
            with open(os.path.expanduser(args.json), "w", encoding="utf-8", errors="surrogateescape") as f:
                f.write(text)
            print(f"JSON report written to {args.json}")

    previous = snapshot.list_snapshots(result.root) if args.compare else []
    if args.save is not None:
        if result.partial:
            print("Note: this snapshot is partial, so comparisons with it can be misleading.", file=sys.stderr)
        path = snapshot.save(result, args.save or None)
        if not json_to_stdout:
            print(f"Snapshot saved to {path}")
    if args.compare:
        if not previous:
            print("No earlier snapshot of this folder to compare with; use --save to keep one.", file=sys.stderr)
        else:
            old = snapshot.load(previous[-1])
            new = report.to_dict(result, top=1000, all_folders=True)
            out = sys.stderr if json_to_stdout else sys.stdout
            out.write("\n" + snapshot.render_diff(snapshot.diff(old, new, top=settings.top), style, width()))
    return 130 if result.cancelled else 0


def cmd_diff(args) -> int:
    style = Style(color_enabled(args.color))
    if args.old and os.path.isdir(args.old):
        snaps = snapshot.list_snapshots(os.path.realpath(args.old))
        if len(snaps) < 2:
            raise UsageError(f"need two saved snapshots of {args.old} to compare, found {len(snaps)}; "
                             f"save one with `whatfills {args.old} --save`")  # fmt: skip
        old_path, new_path = snaps[-2], snaps[-1]
    elif args.old and args.new:
        old_path, new_path = args.old, args.new
    elif args.old:
        old = snapshot.load(args.old)
        snaps = [p for p in snapshot.list_snapshots(old["root"]) if os.path.abspath(p) != os.path.abspath(args.old)]
        if not snaps:
            raise UsageError(f"no newer snapshot of {old['root']} to compare with")
        old_path, new_path = args.old, snaps[-1]
    else:
        latest = snapshot.latest_root()
        snaps = snapshot.list_snapshots(latest) if latest else []
        if len(snaps) < 2:
            raise UsageError("give two snapshot files, or a folder that has two saved snapshots (see `whatfills snapshots`)")
        old_path, new_path = snaps[-2], snaps[-1]
    old, new = snapshot.load(old_path), snapshot.load(new_path)
    if old.get("root") != new.get("root"):
        print(f"Warning: the snapshots are of different folders ({old.get('root')} and {new.get('root')}).", file=sys.stderr)
    d = snapshot.diff(old, new, top=args.top)
    if args.json:
        print(json.dumps(d, indent=2))
    else:
        sys.stdout.write(snapshot.render_diff(d, style, width()))
    return 0


def cmd_snapshots(args) -> int:
    if args.path is None:
        roots = snapshot.all_roots()
        if not roots:
            print(f"No snapshots saved yet (they go in {snapshot.state_dir()}). Save one with: whatfills FOLDER --save")
            return 0
    else:
        roots = [os.path.realpath(os.path.expanduser(args.path))]
    for i, root in enumerate(roots):
        snaps = snapshot.list_snapshots(root)
        if not snaps:
            print(f"No snapshots of {root} yet. Save one with: whatfills {root} --save")
            continue
        if i:
            print()
        print(f"{root}:")
        for p in snaps:
            try:
                data = snapshot.load(p)
                print(f"  {data['started_at']}  {format_size(data['scanned']['bytes']):>10}  {p}")
            except snapshot.SnapshotError as e:
                print(f"  (unreadable) {p}: {e}")
    return 0


def cmd_rules(args) -> int:
    settings = config.load()
    if args.rules_cmd == "check":
        rules = load_rules_file(args.file)
        RuleSet(_active_rules(settings).rules + rules)  # cross-references such as 'within' must resolve
        print(f"{args.file}: OK, {len(rules)} rule{'' if len(rules) == 1 else 's'}")
        return 0
    rules = _active_rules(settings)
    if args.rules_cmd == "show":
        r = rules.by_id.get(args.id)
        if r is None:
            raise UsageError(f"no rule with id {args.id!r}; see `whatfills rules list`")
        print(f"{r.id}: {r.name}")
        print(f"  category: {r.category}    safety: {r.safety} ({SAFETY[r.safety]})")
        print(f"  from: {r.source}")
        for key in ("paths", "dirs", "files", "within", "outside", "in_dirs", "require_child", "require_sibling"):
            if getattr(r, key):
                print(f"  {key}: {', '.join(getattr(r, key))}")
        if r.opaque:
            print("  opaque: everything inside counts here; other folder rules do not match inside")
        if r.min_size:
            print(f"  min_size: {format_size(r.min_size)}")
        if r.explain:
            print(f"  {r.explain}")
        for fx in r.fixes:
            print(f"  fix: {fx.label}" + (f": {fx.run}" if fx.run else "") + (" (as root)" if fx.root else ""))
        for t in r.tips:
            print(f"  tip: {t}")
        return 0
    for r in rules.rules:
        print(f"{r.id:<22} {r.category:<11} {r.safety:<12} {r.name}")
    return 0


def cmd_config(args) -> int:
    if args.config_cmd == "init":
        path = config.user_config_path()
        if os.path.exists(path):
            print(f"{path} already exists; edit it directly.")
            return 0
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "x", encoding="utf-8") as f:
            f.write(config.CONFIG_TEMPLATE)
        print(f"Wrote {path}")
        return 0
    if args.config_cmd == "path":
        for d in config.config_dirs():
            p = os.path.join(d, "config.toml")
            print(f"{p}{'' if os.path.exists(p) else '  (not present)'}")
        return 0
    s = config.load()
    print("Config files read: " + (", ".join(s.sources) if s.sources else "none"))
    for key in ("effort", "threads", "one_file_system", "cross_subvolumes", "time_budget", "io_priority",
                "apparent_size", "exclude_paths", "exclude_names", "exclude_globs", "exclude_fstypes", "top",
                "color", "rules_disable", "rules_files", "builtin_rules"):  # fmt: skip
        print(f"  {key} = {getattr(s, key)!r}")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "scan")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            if args.threads is not None and not 0 <= args.threads <= 256:
                raise UsageError("--threads must be between 0 (automatic) and 256")
            if args.top is not None and args.top < 1:
                raise UsageError("--top must be at least 1")
            return cmd_scan(args)
        if args.command == "diff":
            return cmd_diff(args)
        if args.command == "snapshots":
            return cmd_snapshots(args)
        if args.command == "rules":
            return cmd_rules(args)
        if args.command == "config":
            return cmd_config(args)
        parser.print_help()
        return 2
    except (UsageError, ConfigError, RuleError) as e:
        print(f"whatfills: {e}", file=sys.stderr)
        return 2
    except (ScanError, snapshot.SnapshotError) as e:
        print(f"whatfills: {e}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print("\nwhatfills: interrupted", file=sys.stderr)
        return 130
    except OSError as e:
        where = f"{e.filename}: " if e.filename else ""
        print(f"whatfills: {where}{e.strerror or e}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
