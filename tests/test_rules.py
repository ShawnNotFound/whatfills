"""Rule files, validation messages, and how space is attributed to rules."""

import os

import pytest
from conftest import oracle, write

from whatfills.config import Settings
from whatfills.rules import (
    Rule,
    RuleError,
    RuleSet,
    builtin_rules,
    expand_path_pattern,
    home_bases,
    load_rules_file,
    parse_rules_text,
)
from whatfills.scan import run_scan


def scan(root, rules_toml, **settings):
    rules = RuleSet(parse_rules_text(rules_toml, "test.toml"), homes=["/home/*"])
    s = Settings(**settings)
    return run_scan(str(root), s, rules)


def totals(result):
    return {t.rule.id: t for t in result.totals}


def test_builtin_rules_load_and_compile():
    rules = builtin_rules()
    assert len(rules) > 60
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
    compiled = RuleSet(rules).compile()
    assert compiled["dir_rules"] and compiled["file_rules"]
    assert compiled["opaque_rules"]


@pytest.mark.parametrize(
    "toml, message",
    [
        ('[[rule]]\nid = "x"\nname = "X"\ndirz = ["a"]', "unknown key 'dirz' (did you mean 'dirs'?)"),
        ('[[rule]]\nid = "Bad Id"\nname = "X"\ndirs = ["a"]', "'id' is required and must use lowercase"),
        ('[[rule]]\nid = "x"\nname = "X"', "needs at least one of 'paths', 'dirs' or 'files'"),
        ('[[rule]]\nid = "x"\nname = "X"\ndirs = ["a"]\nfiles = ["*.a"]', "not both"),
        ('[[rule]]\nid = "x"\nname = "X"\npaths = ["relative/path"]', "must be absolute"),
        ('[[rule]]\nid = "x"\nname = "X"\ndirs = ["/abs"]', "must not start with '/'"),
        ('[[rule]]\nid = "x"\nname = "X"\ndirs = ["a"]\nsafety = "maybe"', "unknown safety 'maybe'"),
        ('[[rule]]\nid = "x"\nname = "X"\nfiles = ["*.a"]\nmin_size = "lots"', "invalid size 'lots'"),
        ('[[rule]]\nid = "x"\nname = "X"\ndirs = ["a"]\nmin_size = "1M"', "only applies to file rules"),
        ('[[rule]]\nid = "x"\nname = "X"\ndirs = ["a"]\nfix = [{ lable = "y" }]', "unknown key 'lable' (did you mean 'label'?)"),
        ('[rule]\nid = "x"', "use [[rule]]"),
        ("this is = not toml", "not valid TOML"),
        ('[[rules]]\nid = "x"', "unknown top-level key 'rules' (did you mean 'rule'?)"),
        ('[[rule]]\nid = "x"\nname = "X"\ndirs = ["a"]\nopaque = "yes"', "'opaque' must be true or false"),
        ('[[rule]]\nid = "x"\nname = "X"\nfiles = ["*.a"]\nopaque = true', "'opaque' only applies to folder rules"),
    ],
)
def test_validation_messages(toml, message):
    with pytest.raises(RuleError) as e:
        parse_rules_text(toml, "my.toml")
    assert message in str(e.value)
    assert str(e.value).startswith("my.toml")


def test_within_must_name_a_folder_rule():
    rules = parse_rules_text('[[rule]]\nid = "f"\nname = "F"\nfiles = ["*.x"]\nwithin = ["nope"]', "t.toml")
    with pytest.raises(RuleError, match="unknown rule 'nope'"):
        RuleSet(rules)


def test_path_expansion(monkeypatch):
    assert expand_path_pattern("~/Downloads", ["/home/*", "/root"]) == ["/home/*/Downloads", "/root/Downloads"]
    monkeypatch.setenv("HF_HOME", "/data/hf")
    assert expand_path_pattern("$HF_HOME/hub", []) == ["/data/hf/hub"]
    monkeypatch.delenv("HF_HOME")
    assert expand_path_pattern("$HF_HOME", []) == []


RULES = """
[[rule]]
id = "nm"
name = "node_modules"
dirs = ["node_modules"]
safety = "regenerable"

[[rule]]
id = "pip"
name = "pip cache"
dirs = [".cache/pip"]

[[rule]]
id = "cache"
name = "generic cache"
dirs = [".cache"]

[[rule]]
id = "venv"
name = "venv"
dirs = ["venv", ".venv"]
require_child = ["pyvenv.cfg"]

[[rule]]
id = "target"
name = "rust target"
dirs = ["target"]
require_sibling = ["Cargo.toml"]

[[rule]]
id = "iso"
name = "iso"
files = ["*.iso"]
min_size = "100K"

[[rule]]
id = "logs"
name = "logs"
dirs = ["logs"]

[[rule]]
id = "oldlog"
name = "old logs"
files = ["*.gz"]
within = ["logs"]

[[rule]]
id = "notincache"
name = "big bins outside caches"
files = ["*.bin"]
outside = ["cache", "pip"]
"""


def test_attribution(tmp_path):
    write(tmp_path / "proj" / "node_modules" / "a.js", size=100_000)
    write(tmp_path / "proj" / "node_modules" / "dep" / "node_modules" / "b.js", size=50_000)
    write(tmp_path / "home" / ".cache" / "pip" / "wheel.whl", size=70_000)
    write(tmp_path / "home" / ".cache" / "other" / "x.dat", size=30_000)
    write(tmp_path / "home" / ".cache" / "blob.bin", size=11_000)
    write(tmp_path / "py" / "venv" / "pyvenv.cfg", size=100)
    write(tmp_path / "py" / "venv" / "lib.so", size=40_000)
    write(tmp_path / "notvenv" / "venv" / "data.txt", size=40_000)
    write(tmp_path / "rs" / "Cargo.toml", size=10)
    write(tmp_path / "rs" / "target" / "app", size=60_000)
    write(tmp_path / "java" / "target" / "app.jar", size=60_000)
    write(tmp_path / "dl" / "ubuntu.iso", size=200_000)
    write(tmp_path / "dl" / "tiny.iso", size=1_000)
    write(tmp_path / "logs" / "a.log.1.gz", size=20_000)
    write(tmp_path / "other" / "b.gz", size=20_000)
    write(tmp_path / "other" / "c.bin", size=12_000)

    r = scan(tmp_path, RULES)
    t = totals(r)
    # every byte belongs to exactly one rule
    assert sum(x.alloc for x in r.totals) == r.total_alloc
    assert t["nm"].matches == 1  # nested node_modules merge into the outer one
    assert t["nm"].files == 2
    assert t["pip"].files == 1
    assert t["cache"].files == 2  # other/x.dat and blob.bin, not the pip wheel
    assert "notincache" in t and t["notincache"].files == 1  # c.bin only; blob.bin is inside the cache
    assert t["venv"].matches == 1 and t["venv"].files == 2  # notvenv/venv has no pyvenv.cfg
    assert t["target"].matches == 1  # java/target has no Cargo.toml next to it
    assert t["iso"].files == 1  # tiny.iso is below min_size
    assert t["oldlog"].files == 1  # other/b.gz is not inside logs
    assert {os.path.basename(m.path) for m in t["nm"].locations} == {"node_modules"}


def test_root_itself_can_match(tmp_path):
    root = tmp_path / "node_modules"
    write(root / "a.js", size=10_000)
    r = scan(root, RULES)
    assert r.totals[0].rule.id == "nm"
    assert r.totals[0].alloc == r.total_alloc


def test_anchored_paths(tmp_path):
    write(tmp_path / "var" / "log" / "journal" / "x.journal", size=40_000)
    write(tmp_path / "var" / "log" / "syslog", size=20_000)
    rules = f"""
[[rule]]
id = "journal"
name = "journal"
paths = ["{tmp_path}/var/log/journal"]

[[rule]]
id = "varlog"
name = "var log"
paths = ["{tmp_path}/var/log"]
"""
    t = totals(scan(tmp_path, rules))
    assert t["journal"].files == 1
    assert t["varlog"].files == 1


def test_user_rule_overrides_builtin(tmp_path, monkeypatch):
    rules_dir = os.path.join(os.environ["XDG_CONFIG_HOME"], "whatfills", "rules.d")
    os.makedirs(rules_dir)
    with open(os.path.join(rules_dir, "mine.toml"), "w") as f:
        f.write('[[rule]]\nid = "node-modules"\nname = "My JS deps"\ndirs = ["node_modules"]\nsafety = "safe"\n')
    rs = RuleSet.load()
    assert rs.by_id["node-modules"].name == "My JS deps"
    assert rs.rules[0].id == "node-modules"  # user rules come first


def test_disable_unknown_rule_is_clear():
    with pytest.raises(RuleError, match="cannot disable unknown rule 'node-modulez' \\(did you mean 'node-modules'\\?\\)"):
        RuleSet.load(disable=["node-modulez"])


def test_rule_kind():
    assert Rule(id="a", name="A", files=["*.x"]).kind == "files"
    assert Rule(id="a", name="A", dirs=["x"]).kind == "folders"


def test_disabling_a_rule_that_others_depend_on():
    # 'installers' only applies within 'downloads': turning that off drops it instead of failing
    rs = RuleSet.load(disable=["downloads"])
    assert "downloads" not in rs.by_id and "installers" not in rs.by_id
    # 'model-files' applies outside the model caches: turning one off keeps the rule
    rs = RuleSet.load(disable=["hf-cache"])
    assert rs.by_id["model-files"].outside == ["torch-hub", "ollama", "lmstudio"]
    assert "hf-cache" in RuleSet.load().by_id["model-files"].outside  # the built-in rule itself is unchanged


def test_home_bases():
    class E:
        def __init__(self, uid, home):
            self.pw_uid, self.pw_dir = uid, home

    entries = [E(1000, "/home/ann"), E(1001, "/users/bo"), E(1002, "/users/cy"), E(1003, "/users/di"),
               E(250000, "/data/lab/eve"), E(65534, "/nonexistent"), E(1004, "/var/empty"), E(5, "/usr/games")]  # fmt: skip
    bases = home_bases(entries)
    assert {"/home/*", "/root", "/users/*", "/data/lab/eve"} <= set(bases)
    assert not {"/home/ann", "/users/bo", "/nonexistent", "/var/empty", "/usr/games"} & set(bases)


def test_rules_file_not_utf8(tmp_path):
    p = tmp_path / "r.toml"
    p.write_bytes(b'[[rule]]\nid = "x"\nname = "caf\xe9"\ndirs = ["a"]\n')
    with pytest.raises(RuleError, match="not UTF-8 text"):
        load_rules_file(str(p))


OPAQUE_RULES = """
[[rule]]
id = "nm"
name = "node_modules"
dirs = ["node_modules"]
opaque = true

[[rule]]
id = "git"
name = "git"
dirs = [".git"]
require_child = ["HEAD"]

[[rule]]
id = "pycache"
name = "bytecode"
dirs = ["__pycache__"]

[[rule]]
id = "iso"
name = "iso"
files = ["*.iso"]
min_size = "100K"
"""


def test_opaque_rule_owns_everything_inside(tmp_path):
    nm = tmp_path / "proj" / "node_modules"
    write(nm / "a.js", size=30_000)
    write(nm / "pkg" / ".git" / "HEAD", size=20)
    write(nm / "pkg" / ".git" / "objects" / "pack.pack", size=40_000)
    write(nm / "pkg" / "__pycache__" / "x.pyc", size=10_000)
    write(nm / "pkg" / "disk.iso", size=200_000)
    write(tmp_path / "proj" / ".git" / "HEAD", size=20)
    write(tmp_path / "proj" / "__pycache__" / "y.pyc", size=10_000)

    r = scan(tmp_path, OPAQUE_RULES)
    t = totals(r)
    sizes = oracle(tmp_path)
    assert sum(x.alloc for x in r.totals) == r.total_alloc
    # Folder rules do not match inside node_modules, so its .git and
    # __pycache__ count as node_modules; file rules still apply there.
    assert [m.path for m in t["git"].locations] == [str(tmp_path / "proj" / ".git")]
    assert [m.path for m in t["pycache"].locations] == [str(tmp_path / "proj" / "__pycache__")]
    assert t["iso"].files == 1
    (loc,) = t["nm"].locations
    assert loc.alloc == sizes[str(nm)][0] - os.stat(nm / "pkg" / "disk.iso").st_blocks * 512

