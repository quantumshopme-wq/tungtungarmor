"""Round-trip deobfuscator for tungtungarmor's *own* output.

This reverses the tungtungarmor packaging format so you can inspect or debug
code **you protected yourself**: it extracts the embedded blob, decrypts it
with the build key and recovers the original code object.  From there it can

* write a standard ``.pyc`` you can run or feed to any decompiler, and
* print a bytecode disassembly (``dis``).

It is **not** a generic Python decompiler and it cannot break another tool's
obfuscation -- it only undoes tungtungarmor's transform when you hold the key
(or, in KDF mode, the runtime secret).  Compilation is lossy, so the exact
original source (comments, formatting, encrypted string literals as literals)
is not reconstructed; the recovered code object is behaviourally equivalent.
"""

from __future__ import annotations

import ast
import base64
import dis
import importlib.util
import io
import marshal
import struct
import types
from pathlib import Path
from typing import Optional

from .crypto import decrypt


class DeobfuscateError(Exception):
    pass


def extract_blob(protected_source: str) -> bytes:
    """Return the encrypted blob embedded in a protected ``.py`` file."""
    try:
        tree = ast.parse(protected_source)
    except SyntaxError as exc:  # pragma: no cover - malformed input
        raise DeobfuscateError(f"not parseable Python: {exc}") from exc

    payload = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__armor_data__" for t in node.targets
        ):
            try:
                payload = ast.literal_eval(node.value)
            except Exception as exc:
                raise DeobfuscateError("could not read __armor_data__") from exc
            break
    if payload is None:
        raise DeobfuscateError(
            "no __armor_data__ found -- is this a tungtungarmor-protected file?"
        )
    if isinstance(payload, str):
        payload = payload.encode("ascii")
    return base64.b85decode(payload)


def recover_code(protected_source: str, key: bytes) -> types.CodeType:
    """Recover the original code object from a protected ``.py`` file."""
    blob = extract_blob(protected_source)
    try:
        raw = decrypt(blob, key)
    except ValueError as exc:
        raise DeobfuscateError(
            "decryption failed -- wrong key/secret, or the file was tampered with"
        ) from exc
    try:
        code = marshal.loads(raw)
    except Exception as exc:  # pragma: no cover - corrupt marshal
        raise DeobfuscateError(f"could not unmarshal code object: {exc}") from exc
    if not isinstance(code, types.CodeType):
        raise DeobfuscateError("recovered object is not a code object")
    return code


def recover_code_file(path: Path, key: bytes) -> types.CodeType:
    return recover_code(Path(path).read_text(encoding="utf-8"), key)


def code_to_pyc(code: types.CodeType) -> bytes:
    """Serialize *code* as a standard ``.pyc`` (importable / decompiler-ready)."""
    header = importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, 0, 0)
    return header + marshal.dumps(code)


def disassemble(code: types.CodeType) -> str:
    """Return a full recursive disassembly of *code* as text."""
    buf = io.StringIO()
    dis.dis(code, file=buf)
    return buf.getvalue()


def write_pyc(code: types.CodeType, out_path: Path) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(code_to_pyc(code))
    return out_path


def try_decompile(pyc_path: Path) -> Optional[str]:
    """Best-effort source recovery via an installed decompiler, if any.

    Returns the decompiled source, or ``None`` when no decompiler
    (``decompyle3`` / ``uncompyle6``) is available.
    """
    for modname in ("decompyle3", "uncompyle6"):
        try:
            mod = __import__(modname)
        except ImportError:
            continue
        buf = io.StringIO()
        try:
            mod.decompile_file(str(pyc_path), buf)  # type: ignore[attr-defined]
            return buf.getvalue()
        except Exception:  # pragma: no cover - depends on external tool
            continue
    return None
