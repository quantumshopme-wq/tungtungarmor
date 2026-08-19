"""Tests for the round-trip deobfuscator (own-format recovery)."""

import importlib.util
import subprocess
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from tungtungarmor import ObfuscateOptions, new_key, obfuscate_source  # noqa: E402
from tungtungarmor import deobfuscator as D  # noqa: E402
from tungtungarmor.crypto import decrypt  # noqa: E402


def _helpers(key):
    return {
        "__armor_s__": lambda b: decrypt(b, key).decode("utf-8"),
        "__armor_b__": lambda b: decrypt(b, key),
        "__armor_fmt__": lambda v, c, s: format(
            {"s": str, "r": repr, "a": ascii}.get(c, lambda z: z)(v), s
        ),
    }


def test_recover_behaviourally_equivalent():
    key = new_key()
    src = "A = 'alpha'\ndef f(x):\n    return f'{A}:{x*2}'\nRESULT = f(9)\n"
    protected = obfuscate_source(src, key, ObfuscateOptions())
    code = D.recover_code(protected, key)
    assert isinstance(code, types.CodeType)
    ns = _helpers(key)
    exec(code, ns)
    assert ns["RESULT"] == "alpha:18"


def test_pyc_has_valid_magic():
    key = new_key()
    protected = obfuscate_source("X = 1\n", key, ObfuscateOptions())
    code = D.recover_code(protected, key)
    pyc = D.code_to_pyc(code)
    assert pyc[:4] == importlib.util.MAGIC_NUMBER


def test_disassembly_nonempty():
    key = new_key()
    protected = obfuscate_source("print('hi')\n", key, ObfuscateOptions())
    code = D.recover_code(protected, key)
    text = D.disassemble(code)
    assert "LOAD" in text


def test_wrong_key_raises():
    key = new_key()
    protected = obfuscate_source("Y = 2\n", key, ObfuscateOptions())
    with pytest.raises(D.DeobfuscateError):
        D.recover_code(protected, new_key())


def test_not_protected_raises():
    with pytest.raises(D.DeobfuscateError):
        D.extract_blob("print('just a normal file')\n")


def test_cli_deobfuscate_roundtrip(tmp_path):
    src = tmp_path / "mod.py"
    src.write_text("Z = 'zeta'\nprint(Z)\n")
    out = tmp_path / "out"
    from tungtungarmor import pack
    pack(src, out, ObfuscateOptions())

    rec = tmp_path / "rec.pyc"
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src")}
    proc = subprocess.run(
        [sys.executable, "-m", "tungtungarmor", "deobfuscate",
         str(out / "mod.py"), "--runtime", str(out / "tungtungarmor_runtime"),
         "-o", str(rec)],
        capture_output=True, text=True, env=env,
    )
    assert proc.returncode == 0, proc.stderr
    assert rec.exists()
    assert rec.read_bytes()[:4] == importlib.util.MAGIC_NUMBER
