"""Saved snapshots and the comparison between two of them."""

import os

import pytest
from conftest import write

from whatfills import snapshot
from whatfills.config import Settings
from whatfills.rules import RuleSet
from whatfills.scan import run_scan


def test_diff_keeps_the_most_specific_folder():
    old = {"root": "/", "started_at": "a", "scanned": {"bytes": 1000}, "filesystem": {"used": 2000},
           "folders": [{"path": "/", "bytes": 1000, "children_kept": True},
                       {"path": "/var", "bytes": 600, "children_kept": True},
                       {"path": "/var/log", "bytes": 500, "children_kept": True},
                       {"path": "/home", "bytes": 300, "children_kept": True}],
           "causes": [{"id": "logs", "name": "Logs", "bytes": 500}]}  # fmt: skip
    new = {"root": "/", "started_at": "b", "scanned": {"bytes": 1900}, "filesystem": {"used": 2900},
           "folders": [{"path": "/", "bytes": 1900, "children_kept": True},
                       {"path": "/var", "bytes": 1500, "children_kept": True},
                       {"path": "/var/log", "bytes": 1400, "children_kept": True},
                       {"path": "/home", "bytes": 300, "children_kept": True}],
           "causes": [{"id": "logs", "name": "Logs", "bytes": 1400}]}  # fmt: skip
    d = snapshot.diff(old, new, min_change=100)
    assert [f["path"] for f in d["folders"]] == ["/var/log"]
    assert d["causes"][0]["change"] == 900
    assert d["used_new"] - d["used_old"] == 900


def test_diff_ignores_levels_the_old_scan_did_not_keep():
    old = {"root": "/", "scanned": {"bytes": 100}, "causes": [],
           "folders": [{"path": "/", "bytes": 100, "children_kept": True},
                       {"path": "/a", "bytes": 100, "children_kept": False}]}  # fmt: skip
    new = {"root": "/", "scanned": {"bytes": 900}, "causes": [],
           "folders": [{"path": "/", "bytes": 900, "children_kept": True},
                       {"path": "/a", "bytes": 900, "children_kept": True},
                       {"path": "/a/b", "bytes": 800, "children_kept": True}]}  # fmt: skip
    d = snapshot.diff(old, new, min_change=100)
    assert [f["path"] for f in d["folders"]] == ["/a"]  # /a/b is new only because the old scan pruned /a


def test_snapshot_load_errors(tmp_path):
    p = tmp_path / "x.json"
    p.write_text("{}")
    with pytest.raises(snapshot.SnapshotError, match="not a whatfills snapshot"):
        snapshot.load(str(p))
    with pytest.raises(snapshot.SnapshotError, match="snapshot not found"):
        snapshot.load(str(tmp_path / "none.json.gz"))
    (tmp_path / "broken.json.gz").write_bytes(b"\x1f\x8b not really gzip")
    with pytest.raises(snapshot.SnapshotError, match="not a readable whatfills snapshot"):
        snapshot.load(str(tmp_path / "broken.json.gz"))


def test_save_list_and_latest(tmp_path):
    rules = RuleSet([], homes=[])
    for name in ("a", "b"):
        write(tmp_path / name / "f.bin", size=10_000)
    ra = run_scan(str(tmp_path / "a"), Settings(), rules)
    pa = snapshot.save(ra)
    rb = run_scan(str(tmp_path / "b"), Settings(), rules)
    pb = snapshot.save(rb)
    os.utime(pa, (1, 1))  # make a's snapshot clearly older
    assert snapshot.list_snapshots(str(tmp_path / "a")) == [pa]
    assert snapshot.all_roots() == [str(tmp_path / "b"), str(tmp_path / "a")]
    assert snapshot.latest_root() == str(tmp_path / "b")
    data = snapshot.load(pb)
    assert data["kind"] == snapshot.KIND and data["root"] == str(tmp_path / "b")
    assert not [n for n in os.listdir(os.path.dirname(pb)) if n.endswith(".tmp")]  # written atomically
