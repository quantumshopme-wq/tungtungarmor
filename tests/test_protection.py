"""Tests for runtime protection: expiry, machine binding, anti-debug, license."""

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from tungtungarmor import ObfuscateOptions, pack  # noqa: E402
from tungtungarmor.protection import (  # noqa: E402
    ProtectionOptions,
    machine_id,
    read_key_from_runtime,
    sign_license,
)

SRC = "print('PROTECTED-OK')\n"


def _build(tmp_path, protection):
    src = tmp_path / "mod.py"
    src.write_text(SRC)
    out = tmp_path / "out"
    pack(src, out, ObfuscateOptions(), protection=protection)
    return out


def _run(out, env_extra=None):
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(out)}
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(out / "mod.py")],
        capture_output=True, text=True, env=env,
    )


def test_no_protection_runs(tmp_path):
    out = _build(tmp_path, ProtectionOptions())
    proc = _run(out)
    assert proc.returncode == 0 and "PROTECTED-OK" in proc.stdout


def test_expire_future_ok(tmp_path):
    out = _build(tmp_path, ProtectionOptions(expire=time.time() + 3600))
    proc = _run(out)
    assert proc.returncode == 0 and "PROTECTED-OK" in proc.stdout


def test_expire_past_blocks(tmp_path):
    out = _build(tmp_path, ProtectionOptions(expire=time.time() - 3600))
    proc = _run(out)
    assert proc.returncode != 0
    assert "expired" in proc.stderr
    assert "PROTECTED-OK" not in proc.stdout


def test_machine_bind_self_ok(tmp_path):
    out = _build(tmp_path, ProtectionOptions(machines=[machine_id()]))
    proc = _run(out)
    assert proc.returncode == 0 and "PROTECTED-OK" in proc.stdout


def test_machine_bind_other_blocks(tmp_path):
    out = _build(tmp_path, ProtectionOptions(machines=["deadbeef" * 4]))
    proc = _run(out)
    assert proc.returncode != 0
    assert "machine" in proc.stderr


def test_anti_debug_clean_run_ok(tmp_path):
    out = _build(tmp_path, ProtectionOptions(anti_debug=True))
    proc = _run(out)
    assert proc.returncode == 0 and "PROTECTED-OK" in proc.stdout


def test_anti_debug_detects_tracer(tmp_path):
    out = _build(tmp_path, ProtectionOptions(anti_debug=True))
    # Run under an active trace function -> guard must abort.
    code = (
        "import sys, runpy;"
        "sys.settrace(lambda *a: None);"
        f"runpy.run_path({str(out / 'mod.py')!r}, run_name='__main__')"
    )
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(out)}
    proc = subprocess.run([sys.executable, "-c", code],
                          capture_output=True, text=True, env=env)
    assert proc.returncode != 0
    assert "debug" in proc.stderr.lower() or "trac" in proc.stderr.lower()


def test_require_license(tmp_path):
    out = _build(tmp_path, ProtectionOptions(require_license=True))
    key = read_key_from_runtime(out / "tungtungarmor_runtime")

    # No license -> blocked.
    proc = _run(out)
    assert proc.returncode != 0 and "license" in proc.stderr

    # Valid license (future expiry, bound to this machine) -> runs.
    lic = sign_license(key, expire=time.time() + 3600, machines=[machine_id()])
    lic_file = tmp_path / "my.lic"
    lic_file.write_text(lic)
    proc = _run(out, {"TTA_LICENSE": str(lic_file)})
    assert proc.returncode == 0, proc.stderr
    assert "PROTECTED-OK" in proc.stdout

    # Tampered license -> rejected.
    bad = tmp_path / "bad.lic"
    bad.write_text(lic[:-3] + "AAA")
    proc = _run(out, {"TTA_LICENSE": str(bad)})
    assert proc.returncode != 0


def test_license_expired_blocks(tmp_path):
    out = _build(tmp_path, ProtectionOptions(require_license=True))
    key = read_key_from_runtime(out / "tungtungarmor_runtime")
    lic = sign_license(key, expire=time.time() - 10)
    lic_file = tmp_path / "expired.lic"
    lic_file.write_text(lic)
    proc = _run(out, {"TTA_LICENSE": str(lic_file)})
    assert proc.returncode != 0 and "expired" in proc.stderr
