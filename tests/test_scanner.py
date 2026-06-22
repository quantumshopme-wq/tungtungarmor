"""Tests for the import-following dependency scanner."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from tungtungarmor import ObfuscateOptions, pack  # noqa: E402
from tungtungarmor.scanner import discover  # noqa: E402


def _make_project(tmp_path):
    root = tmp_path / "proj"
    (root / "pkg" / "sub").mkdir(parents=True)
    (root / "debug_app").mkdir()
    (root / ".venv").mkdir()

    (root / "main.py").write_text(
        "import os\n"                       # stdlib -> ignored
        "import helper\n"                   # local module
        "from pkg import thing\n"           # local package + submodule
        "from pkg.sub import deep\n"        # nested
        "print('app')\n"
    )
    (root / "helper.py").write_text("VALUE = 1\n")
    (root / "pkg" / "__init__.py").write_text("from . import thing\n")
    (root / "pkg" / "thing.py").write_text("import helper\nX = 2\n")
    (root / "pkg" / "sub" / "__init__.py").write_text("")
    (root / "pkg" / "sub" / "deep.py").write_text("Y = 3\n")

    # Unrelated / broken files that must NOT be touched.
    (root / "debug_app" / "broken.py").write_text("with open( # never closed\n")
    (root / ".venv" / "junk.py").write_text("import nonsense_$$\n")
    (root / "scratch.py").write_text("import not_imported_anywhere\n")
    return root


def test_discover_follows_only_local_imports(tmp_path):
    root = _make_project(tmp_path)
    files, modules = discover(root / "main.py", root)
    rel = {f.relative_to(root).as_posix() for f in files}

    assert rel == {
        "main.py",
        "helper.py",
        "pkg/__init__.py",
        "pkg/thing.py",
        "pkg/sub/__init__.py",
        "pkg/sub/deep.py",
    }
    assert "scratch.py" not in rel
    assert "debug_app/broken.py" not in rel
    assert ".venv/junk.py" not in rel

    assert "helper" in modules
    assert "pkg" in modules
    assert "pkg.sub.deep" in modules


def test_pack_only_files_runs(tmp_path):
    root = _make_project(tmp_path)
    files, _ = discover(root / "main.py", root)
    out = tmp_path / "out"
    pack(root, out, ObfuscateOptions(), only_files=sorted(files))

    # broken/unrelated files were never obfuscated
    assert not (out / "scratch.py").exists()
    assert not (out / "debug_app").exists()
    assert not (out / ".venv").exists()

    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(out)}
    proc = subprocess.run([sys.executable, str(out / "main.py")],
                          capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    assert "app" in proc.stdout


def test_follow_imports_is_default_for_file_target(tmp_path):
    """obfuscate <entry.py> with no flags must follow imports and ignore the
    broken/unrelated sibling files."""
    root = _make_project(tmp_path)
    out = tmp_path / "out"
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src")}
    proc = subprocess.run(
        [sys.executable, "-m", "tungtungarmor", "obfuscate",
         str(root / "main.py"), "-o", str(out)],
        capture_output=True, text=True, env=env,
    )
    assert proc.returncode == 0, proc.stderr
    assert "scanned imports" in proc.stdout
    assert not (out / "scratch.py").exists()
    assert not (out / "debug_app").exists()


def test_no_follow_imports_processes_tree(tmp_path):
    """--no-follow-imports falls back to whole-tree and hits the broken file."""
    root = _make_project(tmp_path)
    out = tmp_path / "out2"
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src")}
    proc = subprocess.run(
        [sys.executable, "-m", "tungtungarmor", "obfuscate",
         str(root), "--no-follow-imports", "-o", str(out)],
        capture_output=True, text=True, env=env,
    )
    assert proc.returncode != 0  # the broken debug file is a SyntaxError


def test_include_forces_dynamic_module(tmp_path):
    root = _make_project(tmp_path)
    # scratch.py is not imported; force it in via include
    files, _ = discover(root / "main.py", root, include=["scratch"])
    rel = {f.relative_to(root).as_posix() for f in files}
    assert "scratch.py" in rel
