"""Tests for config-file loading and flag assembly."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from tungtungarmor.config import (  # noqa: E402
    assemble_pyi_flags,
    find_default_config,
    load_config,
)


def test_assemble_pyi_flags_full():
    pyi = {
        "hidden_imports": ["api_server", "fastapi"],
        "collect_data": ["pandas"],
        "collect_submodules": ["uvicorn"],
        "copy_metadata": ["numpy"],
        "add_data": ["assets:assets"],
        "icon": "app.ico",
        "noupx": True,
        "pyi_options": "-w --name 'My App'",
        "extra_args": ["--clean"],
    }
    flags = assemble_pyi_flags(pyi)
    assert flags[:4] == ["--hidden-import", "api_server", "--hidden-import", "fastapi"]
    assert "--collect-data" in flags and "pandas" in flags
    assert "--collect-submodules" in flags and "uvicorn" in flags
    assert "--copy-metadata" in flags and "numpy" in flags
    assert "--add-data" in flags and "assets:assets" in flags
    assert flags[flags.index("-i") + 1] == "app.ico"
    assert "--noupx" in flags
    # raw pyi_options is shlex-split, preserving the quoted name
    assert "-w" in flags
    assert "My App" in flags
    assert "--clean" in flags


def test_assemble_empty():
    assert assemble_pyi_flags({}) == []


def test_load_json(tmp_path):
    cfg = {"output": "out", "pyinstaller": {"name": "x", "hidden_imports": ["a"]}}
    p = tmp_path / "tungtungarmor.json"
    p.write_text(json.dumps(cfg))
    loaded = load_config(p)
    assert loaded["output"] == "out"
    assert loaded["pyinstaller"]["hidden_imports"] == ["a"]


def test_find_default_config(tmp_path):
    assert find_default_config(tmp_path) is None
    (tmp_path / "tungtungarmor.json").write_text("{}")
    found = find_default_config(tmp_path)
    assert found is not None and found.name == "tungtungarmor.json"


def test_load_example_toml():
    """The shipped example config must parse (TOML, needs 3.11+/tomli)."""
    import tungtungarmor.config as c
    example = ROOT / "examples" / "tungtungarmor.toml"
    if c._toml is None:  # interpreter without TOML support
        return
    cfg = load_config(example)
    assert cfg["pyinstaller"]["name"] == "TungTung Poster"
    assert "api_server" in cfg["pyinstaller"]["hidden_imports"]
