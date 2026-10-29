"""Tests for the Nuitka integration helpers."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from tungtungarmor.nuitka_integration import _split_data  # noqa: E402


def test_split_data_equals():
    assert _split_data("assets=assets") == ("assets", "assets")
    assert _split_data("a/b/c=dest/here") == ("a/b/c", "dest/here")


def test_split_data_semicolon_and_colon():
    assert _split_data("assets;assets") == ("assets", "assets")
    # last separator wins so a trailing dest is split off
    src, dest = _split_data("templates:tpl")
    assert (src, dest) == ("templates", "tpl")


def test_split_data_bare():
    src, dest = _split_data("assets")
    assert src == "assets" and dest == "assets"
