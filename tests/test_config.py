"""Config files: layering, validation and error messages."""

import os

import pytest

from whatfills import config
from whatfills.config import ConfigError, Settings


def test_config_file(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text(
        '[scan]\neffort = "deep"\ntime_budget = "2m"\n'
        '[exclude]\npaths = ["~/private", "rel"]\nnames = [".snapshot"]\n'
        '[report]\ntop = 5\n'
    )
    s = config.load(extra_file=str(p), read_default_files=False)
    assert s.effort == "deep"
    assert s.time_budget == 120
    assert s.exclude_paths == [os.path.expanduser("~/private"), str(tmp_path / "rel")]
    assert s.exclude_names == [".snapshot"]
    assert s.top == 5
    assert s.sources == [str(p)]


@pytest.mark.parametrize(
    "text, message",
    [
        ("[scan]\neffrot = 'deep'", "unknown key 'effrot' in [scan] (did you mean 'effort'?)"),
        ("[scna]\neffort = 'deep'", "unknown section [scna] (did you mean 'scan'?)"),
        ("[scan]\neffort = 'max'", "effort must be one of quick, normal, deep"),
        ("[scan]\nthreads = 'many'", "scan.threads must be a whole number"),
        ("[scan]\nthreads = 999", "threads must be between 0 (automatic) and 256"),
        ("[scan]\ntime_budget = 'later'", "invalid duration"),
        ("[exclude]\nnames = ['a/b']", "contains '/'"),
        ("[exclude]\npaths = ['']", "empty entry"),
        ("[report]\ncolor = 'blue'", "color must be one of auto, always, never"),
        ("[scan\neffort = 1", "not valid TOML"),
    ],
)
def test_config_errors_name_the_file(tmp_path, text, message):
    p = tmp_path / "bad.toml"
    p.write_text(text)
    with pytest.raises(ConfigError) as e:
        config.load(extra_file=str(p), read_default_files=False)
    assert message in str(e.value)
    assert str(e.value).startswith(str(p))


def test_config_not_utf8(tmp_path):
    p = tmp_path / "latin1.toml"
    p.write_bytes(b"[exclude]\nnames = ['caf\xe9']\n")
    with pytest.raises(ConfigError, match="not UTF-8 text"):
        config.load(extra_file=str(p), read_default_files=False)


def test_config_missing_file_is_clear(tmp_path):
    with pytest.raises(ConfigError, match="config file not found"):
        config.load(extra_file=str(tmp_path / "nope.toml"), read_default_files=False)


def test_user_config_is_read():
    d = os.path.join(os.environ["XDG_CONFIG_HOME"], "whatfills")
    os.makedirs(d)
    with open(os.path.join(d, "config.toml"), "w") as f:
        f.write("[exclude]\nnames = ['.cache']\n")
    s = config.load()
    assert s.exclude_names == [".cache"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read any file")
def test_unreadable_default_config_is_a_warning():
    d = os.path.join(os.environ["XDG_CONFIG_HOME"], "whatfills")
    os.makedirs(d)
    p = os.path.join(d, "config.toml")
    with open(p, "w") as f:
        f.write("[report]\ntop = 3\n")
    os.chmod(p, 0)
    try:
        s = config.load()
    finally:
        os.chmod(p, 0o644)
    assert s.top == 10 and any(p in w for w in s.warnings)


def test_lists_add_up_and_scalars_override(tmp_path):
    a = tmp_path / "a.toml"
    a.write_text("[exclude]\nnames = ['x']\n[report]\ntop = 3\n")
    s = config.load(extra_file=str(a), read_default_files=False)
    config.apply(s, {"exclude.names": ["y"], "report.top": 7})
    assert s.exclude_names == ["x", "y"] and s.top == 7


def test_effort_presets():
    s = Settings(effort="quick")
    assert s.preset()["time_budget"] == 30
    s.time_budget = 0
    assert s.preset()["time_budget"] == 0
    for name, p in config.EFFORT_PRESETS.items():
        assert p["big_file_min"] >= p["keep_dir_min"], name  # big files never sit in pruned folders


def test_template_is_valid():
    assert config.parse_config_text(config.CONFIG_TEMPLATE, "template") == {}
