"""Tests for the import-following dependency scanner."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from tungtungarmor import ObfuscateOptions, pack  # noqa: E402
from tungtungarmor.scanner import (  # noqa: E402
    ScanResult,
    discover,
    select_hidden_imports,
)


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


def test_external_thirdparty_imports_collected(tmp_path):
    root = tmp_path / "proj2"
    root.mkdir()
    (root / "main.py").write_text(
        "import os\n"                                  # stdlib -> filtered
        "import sys, json\n"                           # stdlib -> filtered
        "import requests\n"                            # third-party
        "from moviepy.editor import VideoFileClip\n"   # third-party submodule
        "from . import nothing_local\n"                # relative -> not external
        "import helper2\n"                             # local
    )
    (root / "helper2.py").write_text("import numpy\n")  # third-party in a dep

    scan = discover(root / "main.py", root)
    assert "requests" in scan.external_modules
    assert "moviepy.editor" in scan.external_modules
    assert "numpy" in scan.external_modules
    # stdlib and relative imports must not leak in
    assert "os" not in scan.external_modules
    assert "json" not in scan.external_modules
    assert not any(m.startswith("nothing_local") for m in scan.external_modules)
    assert "helper2" in scan.local_modules


def test_selenium_style_submodule_added_as_hidden_import(tmp_path):
    """from X.Y import Z where Z is a submodule must be recorded so it can be
    passed to PyInstaller as a precise hidden import."""
    root = tmp_path / "proj3"
    root.mkdir()
    (root / "main.py").write_text(
        "from selenium.webdriver.support import expected_conditions as EC\n"
        "import requests\n"
        "print('ok')\n"
    )
    scan = discover(root / "main.py", root)
    assert "selenium.webdriver.support" in scan.external_modules
    assert "selenium.webdriver.support.expected_conditions" in scan.external_modules


def test_select_hidden_imports_filters_junk():
    scan = ScanResult(
        files=set(),
        local_modules={"core", "core.engine", "utils.helpers"},
        external_modules={
            # real installed modules / submodules -> kept
            "urllib3",
            "urllib3.util.retry",
            # class/attribute names -> dropped (not modules)
            "urllib3.HTTPConnectionPool",
            "json.nonexistent_attr",
            # local attribute leak (top-level is a local package) -> dropped
            "core.engine.Engine",
            "utils.helpers.do_thing",
            # entry/dunder/runtime -> dropped
            "__main__",
            "__main__._",
        },
    )
    hidden = select_hidden_imports(scan, entry_module="main",
                                   runtime_pkg="tungtungarmor_runtime")
    # local modules kept
    assert "core" in hidden and "core.engine" in hidden and "utils.helpers" in hidden
    # real third-party module + submodule kept
    assert "urllib3" in hidden
    assert "urllib3.util.retry" in hidden
    # junk dropped
    assert "urllib3.HTTPConnectionPool" not in hidden
    assert "json.nonexistent_attr" not in hidden
    assert "core.engine.Engine" not in hidden
    assert "utils.helpers.do_thing" not in hidden
    assert not any(m.startswith("__main__") for m in hidden)
