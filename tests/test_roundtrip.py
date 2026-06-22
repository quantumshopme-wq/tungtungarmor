"""Round-trip tests: obfuscated code must behave like the original."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from tungtungarmor import ObfuscateOptions, new_key  # noqa: E402
from tungtungarmor.crypto import decrypt, encrypt  # noqa: E402
from tungtungarmor.packer import obfuscate_source, pack  # noqa: E402


def test_crypto_roundtrip():
    key = new_key()
    data = b"some binary \x00\x01\x02 payload" * 100
    assert decrypt(encrypt(data, key), key) == data


def test_crypto_wrong_key_fails():
    blob = encrypt(b"hello", new_key())
    with pytest.raises(ValueError):
        decrypt(blob, new_key())


def _run_protected(source, key, options, runtime_dir, tmp_path):
    """Write protected source + runtime and run it in a fresh interpreter."""
    protected = obfuscate_source(source, key, options)
    script = tmp_path / "prog.py"
    script.write_text(protected)
    env = {"PYTHONPATH": str(tmp_path), "PATH": "/usr/bin:/bin"}
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env,
    )
    return proc


def test_pack_and_execute(tmp_path):
    source = (
        "import sys\n"
        "GREETING = 'hello from protected code'\n"
        "def f(x):\n"
        "    msg = 'value is %d' % x\n"
        "    return msg\n"
        "print(GREETING)\n"
        "print(f(7))\n"
        "print('argv ok' if isinstance(sys.argv, list) else 'bad')\n"
    )
    src_file = tmp_path / "mod.py"
    src_file.write_text(source)
    out = tmp_path / "out"
    options = ObfuscateOptions(encrypt_strings=True, rename_locals=True)
    pack(src_file, out, options)

    env = {"PYTHONPATH": str(out), "PATH": "/usr/bin:/bin"}
    proc = subprocess.run(
        [sys.executable, str(out / "mod.py")],
        capture_output=True, text=True, env=env,
    )
    assert proc.returncode == 0, proc.stderr
    assert "hello from protected code" in proc.stdout
    assert "value is 7" in proc.stdout
    assert "argv ok" in proc.stdout


def test_no_plaintext_string_leaks(tmp_path):
    source = "TOKEN = 'super-secret-token-value'\nprint(TOKEN)\n"
    key = new_key()
    options = ObfuscateOptions(encrypt_strings=True)
    protected = obfuscate_source(source, key, options)
    assert "super-secret-token-value" not in protected


def test_excludes_venv_and_custom(tmp_path):
    proj = tmp_path / "proj"
    (proj / ".venv" / "lib").mkdir(parents=True)
    (proj / "vendored").mkdir()
    (proj / "main.py").write_text("print('main')\n")
    (proj / ".venv" / "lib" / "thing.py").write_text("print('venv')\n")
    (proj / "vendored" / "skip.py").write_text("print('vendored')\n")

    out = tmp_path / "out"
    result = pack(proj, out, ObfuscateOptions(), exclude=["vendored"])

    names = {p.name for p in result.obfuscated_files}
    assert "main.py" in names
    # .venv (default) and vendored (custom) must NOT be obfuscated or copied
    assert not (out / ".venv").exists()
    assert not (out / "vendored").exists()
    assert "thing.py" not in names
    assert "skip.py" not in names


def test_package_tree(tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("from .util import shout\n")
    (pkg / "util.py").write_text(
        "def shout(s):\n    return s.upper() + '!!!'\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "import mypkg\n"
        "print(mypkg.shout('protected package'))\n"
    )
    out = tmp_path / "out"
    pack(tmp_path, out, ObfuscateOptions())

    env = {"PYTHONPATH": str(out), "PATH": "/usr/bin:/bin"}
    proc = subprocess.run(
        [sys.executable, str(out / "main.py")],
        capture_output=True, text=True, env=env,
    )
    assert proc.returncode == 0, proc.stderr
    assert "PROTECTED PACKAGE!!!" in proc.stdout
