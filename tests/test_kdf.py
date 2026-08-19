"""Tests for the key-derivation mode (key is not shipped)."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from tungtungarmor import ObfuscateOptions, pack  # noqa: E402

SRC = "MSG = 'derived-key-ok'\nprint(MSG)\n"
ITERS = 10_000  # keep tests fast


def _run(out, env_extra=None):
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(out)}
    if env_extra:
        env.update(env_extra)
    return subprocess.run([sys.executable, str(out / "mod.py")],
                          capture_output=True, text=True, env=env)


def _build(tmp_path, **kw):
    src = tmp_path / "mod.py"
    src.write_text(SRC)
    out = tmp_path / "out"
    pack(src, out, ObfuscateOptions(kdf="pbkdf2", kdf_secret="s3cr3t",
                                    kdf_iters=ITERS, **kw))
    return out


def test_key_not_shipped(tmp_path):
    out = _build(tmp_path)
    key_src = (out / "tungtungarmor_runtime" / "_key.py").read_text()
    assert "pbkdf2" in key_src
    assert "b85decode" not in key_src  # no raw key present


def test_runs_with_correct_secret(tmp_path):
    out = _build(tmp_path)
    proc = _run(out, {"TTA_SECRET": "s3cr3t"})
    assert proc.returncode == 0 and "derived-key-ok" in proc.stdout, proc.stderr


def test_fails_without_secret(tmp_path):
    out = _build(tmp_path)
    proc = _run(out)
    assert proc.returncode != 0
    assert "secret" in proc.stderr.lower()
    assert "derived-key-ok" not in proc.stdout


def test_fails_with_wrong_secret(tmp_path):
    out = _build(tmp_path)
    proc = _run(out, {"TTA_SECRET": "not-the-secret"})
    assert proc.returncode != 0
    assert "derived-key-ok" not in proc.stdout


def test_custom_secret_env_name(tmp_path):
    out = _build(tmp_path, kdf_secret_env="MY_APP_KEY")
    key_src = (out / "tungtungarmor_runtime" / "_key.py").read_text()
    assert "MY_APP_KEY" in key_src
    proc = _run(out, {"MY_APP_KEY": "s3cr3t"})
    assert proc.returncode == 0 and "derived-key-ok" in proc.stdout, proc.stderr
