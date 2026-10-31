"""End-to-end runs of the command line."""

import json
import os

import pytest
from conftest import write

from whatfills import snapshot
from whatfills.cli import main


def run(capsys, *args):
    code = main(list(args))
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "t"
    write(root / "proj" / "node_modules" / "lib.js", size=300_000)
    write(root / "home" / ".cache" / "pip" / "w.whl", size=200_000)
    write(root / "videos" / "big.mkv", size=150_000)
    write(root / "misc" / "notes.txt", size=5_000)
    return root


def test_text_report(capsys, tree):
    code, out, err = run(capsys, str(tree), "--no-config", "-q")
    assert code == 0, err
    assert "Why it's full: space by cause" in out
    assert "node_modules folders" in out
    assert "pip download cache" in out
    assert "Largest folders" in out
    assert "What you can do" in out
    assert "$ pip cache purge" in out


def test_json_report(capsys, tree):
    code, out, err = run(capsys, str(tree), "--no-config", "--json")
    assert code == 0, err
    data = json.loads(out)
    assert data["root"] == str(tree)
    assert data["scanned"]["files"] == 4
    ids = {c["id"] for c in data["causes"]}
    assert {"node-modules", "pip-cache"} <= ids
    assert sum(c["bytes"] for c in data["causes"]) == data["scanned"]["bytes"]
    assert data["largest_files"][0]["path"].endswith("lib.js")


def test_json_to_file(capsys, tree, tmp_path):
    out_file = tmp_path / "r.json"
    code, out, err = run(capsys, str(tree), "--no-config", "-q", "--json", str(out_file))
    assert code == 0
    assert json.loads(out_file.read_text())["scanned"]["files"] == 4
    assert f"JSON report written to {out_file}" in out


def test_exclude_flags(capsys, tree):
    code, out, err = run(capsys, str(tree), "--no-config", "--json", "--exclude", str(tree / "proj"),
                         "--exclude-name", "*.mkv")  # fmt: skip
    data = json.loads(out)
    assert data["scanned"]["files"] == 2
    assert data["excluded_by_name"] == 1
    assert data["skipped"] == [{"path": str(tree / "proj"), "reason": "excluded"}]


def test_errors_are_clear(capsys, tmp_path):
    code, out, err = run(capsys, str(tmp_path / "missing"), "--no-config")
    assert code == 1 and "no such file or folder" in err
    f = write(tmp_path / "file.txt", size=10)
    code, out, err = run(capsys, str(f), "--no-config")
    assert code == 1 and "is a file, not a folder" in err
    code, out, err = run(capsys, str(tmp_path), "--no-config", "--budget", "soon")
    assert code == 2 and "--budget" in err
    code, out, err = run(capsys, str(tmp_path), "--no-config", "--disable-rule", "nope-rule")
    assert code == 2 and "cannot disable unknown rule" in err
    code, out, err = run(capsys, str(tmp_path), "--no-config", "--exclude", str(tmp_path))
    assert code == 1 and "excluded by your settings" in err


def test_save_and_diff(capsys, tree):
    code, out, err = run(capsys, str(tree), "--no-config", "-q", "--save")
    assert code == 0 and "Snapshot saved to" in out
    write(tree / "proj" / "node_modules" / "more" / "x.js", size=5_000_000)
    code, out, err = run(capsys, str(tree), "--no-config", "-q", "--save", "--compare")
    assert code == 0
    assert "Changes in" in out
    assert len(snapshot.list_snapshots(str(tree))) == 2  # two scans within a second get separate files
    code, out, err = run(capsys, "diff", str(tree))
    assert code == 0
    assert "node_modules" in out


def test_rules_and_config_commands(capsys, tmp_path):
    code, out, err = run(capsys, "rules", "list")
    assert code == 0 and "node-modules" in out
    code, out, err = run(capsys, "rules", "show", "journald")
    assert code == 0 and "journalctl --vacuum-size=500M" in out
    bad = tmp_path / "bad.toml"
    bad.write_text('[[rule]]\nid = "x"\nname = "X"\ndirz = ["a"]\n')
    code, out, err = run(capsys, "rules", "check", str(bad))
    assert code == 2 and "did you mean 'dirs'" in err
    good = tmp_path / "good.toml"
    good.write_text('[[rule]]\nid = "x"\nname = "X"\ndirs = ["a"]\n')
    code, out, err = run(capsys, "rules", "check", str(good))
    assert code == 0 and "OK, 1 rule" in out
    code, out, err = run(capsys, "config", "init")
    assert code == 0 and "Wrote" in out
    path = os.path.join(os.environ["XDG_CONFIG_HOME"], "whatfills", "config.toml")
    assert os.path.exists(path)
    code, out, err = run(capsys, "config", "show")
    assert code == 0 and path in out  # the template parses: every line is commented out


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert "whatfills" in capsys.readouterr().out


def test_bad_output_path_fails_before_scanning(capsys, tree, tmp_path):
    code, out, err = run(capsys, str(tree), "--no-config", "-q", "--json", str(tmp_path / "no" / "such" / "r.json"))
    assert code == 2 and "does not exist" in err and out == ""
    code, out, err = run(capsys, str(tree), "--no-config", "-q", "--save", str(tmp_path))
    assert code == 2 and "is a folder" in err
    # /proc accepts no new files, even from root
    code, out, err = run(capsys, str(tree), "--no-config", "-q", "--json", "/proc/whatfills-test.json")
    assert code == 2 and "cannot write /proc/whatfills-test.json" in err and out == ""
    # a normal output file still works after the check
    target = tmp_path / "r.json"
    code, out, err = run(capsys, str(tree), "--no-config", "-q", "--json", str(target))
    assert code == 0 and json.loads(target.read_text())["schema"] >= 1


def test_rules_list_follows_config(capsys):
    d = os.path.join(os.environ["XDG_CONFIG_HOME"], "whatfills")
    os.makedirs(d)
    with open(os.path.join(d, "config.toml"), "w") as f:
        f.write("[rules]\ndisable = ['journald']\n")
    code, out, err = run(capsys, "rules", "list")
    assert code == 0 and "var-log" in out and "journald" not in out


def test_snapshots_and_diff_without_arguments(capsys, tree):
    code, out, err = run(capsys, "snapshots")
    assert code == 0 and "No snapshots saved yet" in out
    run(capsys, str(tree), "--no-config", "-q", "--save")
    write(tree / "videos" / "more.mkv", size=2_000_000)
    run(capsys, str(tree), "--no-config", "-q", "--save")
    code, out, err = run(capsys, "snapshots")
    assert code == 0 and f"{tree}:" in out
    code, out, err = run(capsys, "diff")
    assert code == 0, err
    assert f"Changes in {tree}" in out


def test_warns_about_unreadable_config_but_scans(capsys, tree, monkeypatch):
    from whatfills import config

    real_load = config.load

    def load(**kw):
        s = real_load(**kw)
        s.warnings.append("skipped config file /etc/whatfills/config.toml: Permission denied")
        return s

    monkeypatch.setattr(config, "load", load)
    code, out, err = run(capsys, str(tree), "-q")
    assert code == 0 and "warning: skipped config file" in err
