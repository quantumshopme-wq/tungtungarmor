"""Source templates for the self-contained runtime package that ships with
obfuscated programs.

The generated package (default name ``tungtungarmor_runtime``) has no
dependency on tungtungarmor itself, so the protected program runs anywhere
the right Python version is available -- including inside a PyInstaller
bundle, where it is picked up automatically as a normal import.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# _cipher.py -- decryption + literal helpers (mirror of crypto.py, no deps)
# ---------------------------------------------------------------------------
CIPHER_SRC = '''\
import hashlib, hmac, struct

NONCE_SIZE = 16
TAG_SIZE = 32


def _keystream(key, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(key + nonce + struct.pack(">Q", counter)).digest())
        counter += 1
    return bytes(out[:length])


def decrypt(blob, key):
    nonce = blob[:NONCE_SIZE]
    tag = blob[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = blob[NONCE_SIZE + TAG_SIZE:]
    expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("tungtungarmor: integrity check failed")
    keystream = _keystream(key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, keystream))
'''

# ---------------------------------------------------------------------------
# _key.py -- per-build random key (filled in by the packer)
# ---------------------------------------------------------------------------
KEY_SRC = '''\
import base64
KEY = base64.b85decode({key!r})
'''

# ---------------------------------------------------------------------------
# __init__.py -- public entry point used by every obfuscated module
# ---------------------------------------------------------------------------
INIT_SRC = '''\
"""tungtungarmor runtime -- decrypts and executes protected modules."""
import marshal
import sys

from ._cipher import decrypt
from ._key import KEY

from ._guard import check as __armor_check__

__all__ = ["__armor_exec__"]

_GUARD_DONE = [False]


def __armor_s__(blob):
    """Decrypt a protected str literal."""
    return decrypt(blob, KEY).decode("utf-8")


def __armor_b__(blob):
    """Decrypt a protected bytes literal."""
    return decrypt(blob, KEY)


def __armor_exec__(blob, name, module_globals=None):
    """Decrypt *blob* into a code object and execute it.

    *module_globals* should be the calling module's ``globals()`` so the
    original module-level code runs in the right namespace.
    """
    if not _GUARD_DONE[0]:
        __armor_check__()
        _GUARD_DONE[0] = True
    code = marshal.loads(decrypt(blob, KEY))
    if module_globals is None:
        module_globals = sys._getframe(1).f_globals
    # Make the literal-decryption helpers available to the protected code.
    module_globals.setdefault("__armor_s__", __armor_s__)
    module_globals.setdefault("__armor_b__", __armor_b__)
    exec(code, module_globals)
'''

# ---------------------------------------------------------------------------
# _guard.py -- runtime protection: anti-debug / expiry / machine binding /
# signed external license files. The per-build constraints are written as a
# generated header; the enforcement logic below is static.
# ---------------------------------------------------------------------------
GUARD_BODY = '''\
import base64
import hashlib
import hmac
import json
import os
import platform
import sys
import time
import uuid

from ._key import KEY


def _fail(reason):
    sys.stderr.write("tungtungarmor: " + reason + "\\n")
    os._exit(1)


def _machine_id():
    parts = [platform.system(), platform.node(), str(uuid.getnode())]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]


def _check_anti_debug():
    if sys.gettrace() is not None:
        _fail("debugging/tracing is not allowed")
    for mod in ("pydevd", "_pydevd_bundle", "pdb"):
        if mod in sys.modules:
            _fail("debugger detected")


def _check_expire(expire):
    if expire and time.time() > float(expire):
        _fail("license has expired")


def _check_machines(machines):
    if machines and _machine_id() not in machines:
        _fail("not licensed for this machine")


def _find_license():
    candidates = []
    env = os.environ.get("TTA_LICENSE")
    if env:
        candidates.append(env)
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        try:
            base = os.path.dirname(os.path.abspath(sys.argv[0]))
        except Exception:
            base = os.getcwd()
    candidates.append(os.path.join(base, LICENSE_NAME))
    candidates.append(os.path.join(os.getcwd(), LICENSE_NAME))
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def _verify_license(text):
    try:
        raw_b85, sig_b85 = text.strip().split(".")
        raw = base64.b85decode(raw_b85)
        sig = base64.b85decode(sig_b85)
    except Exception:
        _fail("malformed license file")
    expected = hmac.new(KEY, raw, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        _fail("invalid license signature")
    return json.loads(raw.decode("utf-8"))


def check():
    if ANTI_DEBUG:
        _check_anti_debug()
    _check_expire(EXPIRE)
    _check_machines(MACHINES)
    if REQUIRE_LICENSE:
        path = _find_license()
        if not path:
            _fail("license file '" + LICENSE_NAME + "' not found")
        with open(path, "r") as fh:
            data = _verify_license(fh.read())
        _check_expire(data.get("expire"))
        _check_machines(data.get("machines"))
'''


def _py_value(value):
    """Render a Python literal for the guard header."""
    if value is None:
        return "None"
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        return repr(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_py_value(v) for v in value) + "]"
    raise TypeError(f"unsupported guard value: {value!r}")


def render_guard(protection=None) -> str:
    """Render ``_guard.py`` with the build's protection constraints baked in."""
    from .protection import DEFAULT_LICENSE_NAME, ProtectionOptions

    p = protection or ProtectionOptions()
    header = (
        "# Generated protection constraints for this build.\n"
        f"EXPIRE = {_py_value(p.expire)}\n"
        f"MACHINES = {_py_value(p.machines)}\n"
        f"ANTI_DEBUG = {_py_value(bool(p.anti_debug))}\n"
        f"REQUIRE_LICENSE = {_py_value(bool(p.require_license))}\n"
        f"LICENSE_NAME = {_py_value(p.license_name or DEFAULT_LICENSE_NAME)}\n\n"
    )
    return header + GUARD_BODY


def render_runtime(key_bytes: bytes, protection=None) -> dict:
    """Return ``{filename: source}`` for the runtime package, given the key."""
    import base64

    key_b85 = base64.b85encode(key_bytes)
    return {
        "__init__.py": INIT_SRC,
        "_cipher.py": CIPHER_SRC,
        "_key.py": KEY_SRC.format(key=key_b85),
        "_guard.py": render_guard(protection),
    }
