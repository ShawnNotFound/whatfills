"""The text report and the JSON summary."""

import json

import pytest
from conftest import write

from whatfills import report
from whatfills.config import Settings
from whatfills.rules import RuleSet, builtin_rules, parse_rules_text
from whatfills.scan import run_scan
from whatfills.term import Style

RULES = """
[[rule]]
id = "pkgs"
name = "package cache"
safety = "safe"
dirs = ["pkgs"]
explain = "Downloaded packages."
fix = [{ label = "Clean it", run = "pkg clean" }]
"""


@pytest.fixture
def result(tmp_path):
    write(tmp_path / "pkgs" / "a.tar", size=300_000)
    write(tmp_path / "misc" / "notes.txt", size=20_000)
    return run_scan(str(tmp_path), Settings(), RuleSet(parse_rules_text(RULES, "t.toml"), homes=[]))


def text(r, **kw):
    return report.render_text(r, Style(False), cols=kw.pop("cols", 100), **kw)


def test_sections(result):
    out = text(result)
    assert "Why it's full: space by cause" in out
    assert "package cache" in out and "safe" in out
    assert "Largest folders" in out and "Largest files" in out
    assert "What you can do" in out and "$ pkg clean" in out


def test_narrow_terminal_still_renders(result):
    out = text(result, cols=60)
    assert "package cache" in out
    long = [line for line in out.splitlines() if len(line) > 60 and result.root not in line]
    assert long == []


def test_hard_link_sharing_is_explained(result):
    t = next(x for x in result.totals if x.rule.id == "pkgs")
    t.alloc = 500 << 20
    t.shared = 200 << 20
    result.links = {"cross_cause_bytes": 200 << 20, "untracked": 3, "table_limit": 100}
    out = " ".join(text(result).split())  # undo line wrapping
    assert "200.0 MiB hard-linked elsewhere too" in out
    assert "Deleting it frees less than this" in out
    assert "counted once, under the first place the scan reached" in out
    assert "3 hard links were found after the hard-link table was full" in out


def test_skip_notes_are_grouped(result):
    result.skips = [
        ("/srv/a", "bind mount of /x/a, counted there", 0),
        ("/srv/b", "bind mount of /x/b, counted there", 0),
        ("/mnt/nfs", "nfs4 network filesystem", 0),
        ("/proc", "proc filesystem", 0),
        ("/run", "tmpfs filesystem", 0),
        ("/home", "mount", 7),
    ]
    out = " ".join(text(result).split())  # undo line wrapping
    assert "Did not count 2 bind mounts again" in out and "/srv/a is a bind mount of /x/a, counted there" in out
    assert "Did not enter 1 network filesystem: /mnt/nfs" in out
    assert "/proc" not in out and "/run" not in out  # kernel and memory filesystems are not worth a note
    assert "Did not enter 1 other mounted filesystem: /home." in out


def test_json_summary(result):
    data = json.loads(json.dumps(report.to_dict(result)))
    assert data["schema"] == report.SCHEMA_VERSION
    assert data["scanned"]["files"] == 2
    causes = {c["id"]: c for c in data["causes"]}
    assert causes["pkgs"]["shared_bytes"] == 0
    assert causes["pkgs"]["fixes"][0]["run"] == "pkg clean"
    assert sum(c["bytes"] for c in data["causes"]) == data["scanned"]["bytes"]
    assert set(data["hard_links"]) == {"files", "bytes", "shared_files", "shared_bytes", "cross_cause_bytes", "untracked"}
    assert data["folders"][0]["path"] == result.root


def test_empty_folder(tmp_path):
    r = run_scan(str(tmp_path), Settings(), RuleSet(builtin_rules(), homes=[]))
    out = text(r)
    assert "Why it's full" in out


def test_odd_file_names_are_escaped(tmp_path):
    write(tmp_path / "evil\x1b[31mname.bin", size=50_000)
    r = run_scan(str(tmp_path), Settings(), RuleSet([], homes=[]))
    out = text(r)
    assert "\x1b" not in out and "\\x1b" in out


def test_shorten_path_keeps_the_file_name():
    from whatfills.term import shorten_path

    p = "/home/alex/Downloads/ubuntu-24.04.1-live-server-amd64.iso"
    assert shorten_path(p, 100) == p
    # the folders right above the file come first, then the start of the path
    assert shorten_path(p, 50) == "…/Downloads/ubuntu-24.04.1-live-server-amd64.iso"
    assert shorten_path(p, 56) == "…/alex/Downloads/ubuntu-24.04.1-live-server-amd64.iso"
    assert shorten_path("/a/" + "x" * 80, 40).count("…") == 1  # a name too long to keep whole is cut in the middle


def test_shorten_path_drops_folders_from_the_middle():
    from whatfills.term import display_width, shorten_path

    blob = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"
    hf = "/home/alex/.cache/huggingface/hub/models--Qwen--Qwen2.5-3B-Instruct/blobs/" + blob
    # hashes are cut to their start, and the folders right above the file are kept
    assert shorten_path(hf, 65) == "/home/…/hub/models--Qwen--Qwen2.5-3B-Instruct/blobs/6b86b273…"
    log = f"/var/lib/docker/containers/{blob}/{blob}-json.log"
    assert shorten_path(log, 60) == "/var/lib/docker/containers/6b86b273…/6b86b273…-json.log"
    assert shorten_path(log, 200) == log  # nothing changes when it fits
    wide = "/srv/数据/训练集/很长的文件夹名字/模型权重文件.bin"
    assert display_width(shorten_path(wide, 30)) <= 30
    assert shorten_path("rel/a/b/c/d/e/file.txt", 18) == "…/b/c/d/e/file.txt"
    deep = "/" + "/".join(["d"] * 3000) + "/f.bin"
    assert display_width(shorten_path(deep, 60)) <= 60


def test_shorten_path_keeps_a_chosen_folder():
    from whatfills.term import shorten_path

    blob = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"
    hf = "/home/alex/.cache/huggingface/hub/models--Qwen--Qwen2.5-3B-Instruct/blobs/" + blob
    assert shorten_path(hf, 65, keep=4) == "…/huggingface/…/models--Qwen--Qwen2.5-3B-Instruct/blobs/6b86b273…"
    lib = "~/GitHub/contrib/.venv-tvm-relax/lib/python3.13/site-packages/torch/lib/libtorch_cpu.so"
    plain = shorten_path(lib, 60)
    assert ".venv-tvm-relax" not in plain
    assert shorten_path(lib, 60, keep=4) == "…/.venv-tvm-relax/…/site-packages/torch/lib/libtorch_cpu.so"
    # the file's own folder, the file itself or past the end: nothing to add
    for keep in (-1, 0, 9, 10, 99):
        assert shorten_path(lib, 60, keep=keep) == plain
    assert shorten_path(lib, 30, keep=4) == "~/…/torch/lib/libtorch_cpu.so"  # no room for it


def test_largest_files_show_the_environment_they_are_in(tmp_path):
    env = tmp_path / "work" / "projects" / "contrib" / ".venv-tvm-relax"
    write(env / "pyvenv.cfg", size=100)
    write(env / "lib" / "python3.13" / "site-packages" / "torch" / "lib" / "libtorch_cpu.so", size=400_000)
    write(tmp_path / "work" / "notes" / "a" / "b" / "c" / "d" / "e" / "f" / "g" / "notes.txt", size=200_000)
    r = run_scan(str(tmp_path), Settings(), RuleSet(builtin_rules(), homes=[]))
    lines = text(r, cols=80).splitlines()
    files = lines[lines.index("Largest files") + 1 :]
    torch = next(x for x in files if x.endswith("libtorch_cpu.so"))
    assert "/.venv-tvm-relax/…/" in torch and len(torch) <= 80
    assert next(x for x in files if x.endswith("notes.txt")).count("…") == 1


def test_tree_names_the_cause_that_holds_the_space(tmp_path):
    rules = """
[[rule]]
id = "cache"
name = "app caches"
dirs = [".cache"]

[[rule]]
id = "models"
name = "model downloads"
dirs = [".cache/models"]

[[rule]]
id = "db"
name = "database"
dirs = ["db"]
"""
    mib = 1 << 20
    write(tmp_path / "u" / ".cache" / "models" / "m.bin", size=8 * mib)
    write(tmp_path / "u" / ".cache" / "x.dat", size=1 * mib)
    write(tmp_path / "u" / "notes.txt", size=3 * mib)
    write(tmp_path / "srv" / "db" / "16" / "main" / "t1", size=6 * mib)
    r = run_scan(str(tmp_path), Settings(), RuleSet(parse_rules_text(rules, "t.toml"), homes=[]))
    lines = text(r).splitlines()
    tree = lines[lines.index("Largest folders") :]
    row = {line.split("─ ")[1].split("  ")[0]: line for line in tree if "─ " in line}
    assert row["srv/db/16/main"].endswith("[database]")  # the match is at the start of the chain
    assert row[".cache"].endswith("[mostly model downloads]")  # 'app caches' itself holds little of it
    assert row["models"].endswith("[model downloads]")
    assert "[" not in row["u"]


def test_hidden_files_section(result, monkeypatch):
    from whatfills.probes import HiddenData, HiddenReport

    result.hidden = HiddenReport([HiddenData("/mnt/back up", 1 << 30, 1)], 1 << 30, 3)
    monkeypatch.setattr(report.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "alex")
    out = text(result)
    assert "1.0 GiB  /mnt/back up  (1 file)" in out
    fs = result.mount.mount_point if result.mount else "/"
    assert f"$ sudo mkdir -p /mnt/fsview && sudo mount --bind {fs} /mnt/fsview" in out
    assert "$ ls -la '/mnt/fsview/" in out and "back up'" in out  # quoted for the shell


def test_sudo_prefix(monkeypatch):
    monkeypatch.setattr(report.os, "geteuid", lambda: 1000)
    assert report._sudo("journalctl --vacuum-size=500M", True) == "sudo journalctl --vacuum-size=500M"
    assert report._sudo("docker system df", False) == "docker system df"
    monkeypatch.setattr(report.os, "geteuid", lambda: 0)
    assert report._sudo("apt-get clean", True) == "apt-get clean"  # a real root shell
    monkeypatch.setenv("SUDO_USER", "alex")
    assert report._sudo("apt-get clean", True) == "sudo apt-get clean"  # ran under sudo: commands go to alex's shell


def test_wrapping_keeps_words_whole():
    lines = report._wrap('Limit container logs: "log-opts": {"max-size": "50m", "max-file": "3"}.', 30)
    assert not any(line.endswith("-") for line in lines)
    assert any('"max-file":' in line for line in lines)


def test_reserved_space_wording(result):
    import dataclasses

    from whatfills.fsinfo import Space

    result.space = Space(total=100 << 30, used=90 << 30, free=10 << 30, avail=5 << 30, inodes_total=0, inodes_free=0)
    result.mount = dataclasses.replace(result.mount, fstype="ext4", mount_point=result.root)  # a whole-filesystem scan
    out = " ".join(text(result).split())
    assert "5.0 GiB more is reserved for root" in out and "95%" in out
    result.mount = dataclasses.replace(result.mount, fstype="btrfs")
    out = " ".join(text(result).split())
    assert "5.0 GiB more is counted as free, but the filesystem keeps it in reserve" in out


def test_partial_results_hint(result):
    result.cancelled = True
    assert "let it finish" in " ".join(text(result).split())
    result.cancelled, result.budget_hit = False, True
    result.settings.effort = "quick"
    assert "Run with --effort normal" in " ".join(text(result).split())
    result.settings.effort = "normal"
    assert "Use a longer --budget, or none" in " ".join(text(result).split())
