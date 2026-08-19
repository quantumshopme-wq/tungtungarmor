"""Tests for the hardening passes: bytecode strip, integrity, f-strings,
global renaming and string-length tuning."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from tungtungarmor import ObfuscateOptions, new_key, pack  # noqa: E402
from tungtungarmor.packer import STRIPPED_FILENAME, obfuscate_source, strip_debug_info  # noqa: E402


def _run(out, entry="mod.py", env_extra=None):
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(out)}
    if env_extra:
        env.update(env_extra)
    return subprocess.run([sys.executable, str(out / entry)],
                          capture_output=True, text=True, env=env)


def test_strip_bytecode_removes_source_path(tmp_path):
    src = tmp_path / "mod.py"
    src.write_text("V = 'ok'\nprint('OUT', V)\n")
    out = tmp_path / "out"
    pack(src, out, ObfuscateOptions(strip_bytecode=True))
    proc = _run(out)
    assert proc.returncode == 0 and "OUT ok" in proc.stdout, proc.stderr
    # The developer's absolute source path must not be embedded anywhere.
    assert str(src).encode() not in (out / "mod.py").read_bytes()


def test_strip_debug_info_sets_opaque_filename():
    code = compile("def f():\n return 1\n", "/secret/abs/path.py", "exec")
    stripped = strip_debug_info(code)
    assert stripped.co_filename == STRIPPED_FILENAME
    nested = [c for c in stripped.co_consts if hasattr(c, "co_filename")]
    assert nested and all(c.co_filename == STRIPPED_FILENAME for c in nested)


def test_integrity_detects_tampered_cipher(tmp_path):
    src = tmp_path / "mod.py"
    src.write_text("print('SAFE')\n")
    out = tmp_path / "out"
    pack(src, out, ObfuscateOptions())
    cipher = out / "tungtungarmor_runtime" / "_cipher.py"
    cipher.write_text(cipher.read_text() + "\nLEAK = 1\n")
    proc = _run(out)
    assert proc.returncode != 0
    assert "integrity" in proc.stderr.lower()
    assert "SAFE" not in proc.stdout


def test_fstring_fragments_hidden_and_correct(tmp_path):
    src = tmp_path / "mod.py"
    src.write_text(
        "name = 'Wanderer'\n"
        "n = 42\n"
        "w = 6\n"
        "print(f'greeting-fragment {name!r} n={n:>{w}}')\n"
    )
    out = tmp_path / "out"
    pack(src, out, ObfuscateOptions(min_string_length=1))
    proc = _run(out)
    assert proc.returncode == 0, proc.stderr
    assert "greeting-fragment 'Wanderer' n=    42" in proc.stdout
    # The literal fragment must not survive in the shipped bytecode.
    assert b"greeting-fragment" not in (out / "mod.py").read_bytes()


def test_rename_globals_runs_and_hides_private_names(tmp_path):
    src = tmp_path / "mod.py"
    src.write_text(
        "_base = 10\n"
        "def _boost(x):\n"
        "    return x + _base\n"
        "print('R', _boost(5))\n"
    )
    out = tmp_path / "out"
    key = new_key()
    # behaviour is preserved end to end
    pack(src, out, ObfuscateOptions(rename_globals=True), key=key)
    proc = _run(out)
    assert proc.returncode == 0 and "R 15" in proc.stdout, proc.stderr
    # the private names must not appear in the pre-compile transform
    protected = obfuscate_source(src.read_text(), key,
                                 ObfuscateOptions(rename_globals=True,
                                                  encrypt_strings=False))
    assert "_boost" not in protected and "_base" not in protected


def test_rename_globals_bails_on_dynamic_namespace(tmp_path):
    # A module using globals() must be left correct (renamer bails).
    src = tmp_path / "mod.py"
    src.write_text(
        "_val = 7\n"
        "def get():\n"
        "    return globals()['_val']\n"
        "print('G', get())\n"
    )
    out = tmp_path / "out"
    pack(src, out, ObfuscateOptions(rename_globals=True))
    proc = _run(out)
    assert proc.returncode == 0 and "G 7" in proc.stdout, proc.stderr


def test_short_strings_below_min_length_not_encrypted(tmp_path):
    # With default min length (2), 1-char strings stay plain but code still runs.
    src = tmp_path / "mod.py"
    src.write_text("sep = '-'\nprint(sep.join(['a', 'b', 'c']))\n")
    out = tmp_path / "out"
    pack(src, out, ObfuscateOptions())
    proc = _run(out)
    assert proc.returncode == 0 and "a-b-c" in proc.stdout, proc.stderr
