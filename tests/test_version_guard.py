"""The bootstrap must refuse to run on a mismatched Python version."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from tungtungarmor import ObfuscateOptions, pack  # noqa: E402


def _run(out):
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(out)}
    return subprocess.run([sys.executable, str(out / "mod.py")],
                          capture_output=True, text=True, env=env)


def test_bootstrap_bakes_current_version(tmp_path):
    src = tmp_path / "mod.py"
    src.write_text("print('V-OK')\n")
    out = tmp_path / "out"
    pack(src, out, ObfuscateOptions())
    text = (out / "mod.py").read_text()
    assert f"({sys.version_info[0]}, {sys.version_info[1]})" in text
    assert _run(out).returncode == 0


def test_version_mismatch_aborts(tmp_path):
    src = tmp_path / "mod.py"
    src.write_text("print('SHOULD-NOT-RUN')\n")
    out = tmp_path / "out"
    pack(src, out, ObfuscateOptions())
    prot = out / "mod.py"
    text = prot.read_text()
    good = f"({sys.version_info[0]}, {sys.version_info[1]})"
    # Simulate a build for a different minor version.
    prot.write_text(text.replace(good, f"({sys.version_info[0]}, {sys.version_info[1] + 1})"))
    proc = _run(out)
    assert proc.returncode != 0
    assert "built for Python" in proc.stderr
    assert "SHOULD-NOT-RUN" not in proc.stdout
