"""Source templates for the self-contained runtime package that ships with
obfuscated programs.

The generated package (default name ``tungtungarmor_runtime``) has no
dependency on tungtungarmor itself, so the protected program runs anywhere
the right Python version is available -- including inside a PyInstaller
bundle, where it is picked up automatically as a normal import.
"""

from __future__ import annotations

import hashlib
import hmac

# ---------------------------------------------------------------------------
# _cipher.py -- decryption + literal helpers (mirror of crypto.py, no deps)
# ---------------------------------------------------------------------------
CIPHER_SRC = '''\
import hashlib, hmac, struct

NONCE_SIZE = 16
TAG_SIZE = 32

_HKDF_SALT = b"tungtungarmor-hkdf-v1"


def _hkdf(key, info, length=32):
    prk = hmac.new(_HKDF_SALT, key, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def _subkeys(key):
    return _hkdf(key, b"tta-enc"), _hkdf(key, b"tta-mac")


def _keystream(enc_key, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(enc_key + nonce + struct.pack(">Q", counter)).digest())
        counter += 1
    return bytes(out[:length])


def decrypt(blob, key):
    enc_key, mac_key = _subkeys(key)
    nonce = blob[:NONCE_SIZE]
    tag = blob[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = blob[NONCE_SIZE + TAG_SIZE:]
    expected = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("tungtungarmor: integrity check failed")
    keystream = _keystream(enc_key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, keystream))
'''

# ---------------------------------------------------------------------------
# _key.py (default) -- per-build random key, shipped with the program
# ---------------------------------------------------------------------------
KEY_SRC = '''\
import base64
KEY = base64.b85decode({key!r})
'''

# ---------------------------------------------------------------------------
# _key.py (KDF mode) -- key is NOT shipped; derived at runtime from a secret
# supplied through the environment.  Only salt + iterations are stored.
# ---------------------------------------------------------------------------
KEY_KDF_SRC = '''\
import hashlib, os, sys

_SECRET_ENV = {env!r}
_SALT = bytes.fromhex("{salt_hex}")
_ITERS = {iters}

_secret = os.environ.get(_SECRET_ENV)
if not _secret:
    sys.stderr.write(
        "tungtungarmor: secret not provided; set the " + _SECRET_ENV
        + " environment variable to run this program\\n"
    )
    raise SystemExit(1)

KEY = hashlib.pbkdf2_hmac("sha256", _secret.encode("utf-8"), _SALT, _ITERS, dklen=32)
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

from ._guard import check as __armor_check__, tick as __armor_tick__

__all__ = ["__armor_exec__"]

_GUARD_DONE = [False]
_STR_CACHE = {}
_BYTES_CACHE = {}


def __armor_s__(blob):
    """Decrypt a protected str literal (memoised per literal)."""
    cached = _STR_CACHE.get(blob)
    if cached is None:
        cached = decrypt(blob, KEY).decode("utf-8")
        _STR_CACHE[blob] = cached
    return cached


def __armor_b__(blob):
    """Decrypt a protected bytes literal (memoised per literal)."""
    cached = _BYTES_CACHE.get(blob)
    if cached is None:
        cached = decrypt(blob, KEY)
        _BYTES_CACHE[blob] = cached
    return cached


def __armor_fmt__(value, conv, spec):
    """f-string helper: apply !s/!r/!a then format(), immune to shadowing."""
    if conv == "s":
        value = str(value)
    elif conv == "r":
        value = repr(value)
    elif conv == "a":
        value = ascii(value)
    return format(value, spec)


def __armor_exec__(blob, name, module_globals=None):
    """Decrypt *blob* into a code object and execute it.

    *module_globals* should be the calling module's ``globals()`` so the
    original module-level code runs in the right namespace.
    """
    if not _GUARD_DONE[0]:
        __armor_check__()          # once: expire / machine / license / integrity
        _GUARD_DONE[0] = True
    __armor_tick__()               # every module: cheap anti-debug re-check
    code = marshal.loads(decrypt(blob, KEY))
    if module_globals is None:
        module_globals = sys._getframe(1).f_globals
    # Make the literal-decryption / formatting helpers available to the code.
    module_globals.setdefault("__armor_s__", __armor_s__)
    module_globals.setdefault("__armor_b__", __armor_b__)
    module_globals.setdefault("__armor_fmt__", __armor_fmt__)
    exec(code, module_globals)
'''

# ---------------------------------------------------------------------------
# _guard.py -- runtime protection: anti-debug / expiry / machine binding /
# signed external license files / self-integrity.  The per-build constraints
# are written as a generated header; the enforcement logic below is static.
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


def _traced_by_os():
    """Linux: detect an attached ptrace tracer via /proc/self/status."""
    try:
        with open("/proc/self/status", "r") as fh:
            for line in fh:
                if line.startswith("TracerPid:"):
                    return int(line.split(":", 1)[1].strip()) != 0
    except Exception:
        return False
    return False


def _check_anti_debug():
    if sys.gettrace() is not None:
        _fail("debugging/tracing is not allowed")
    for mod in ("pydevd", "_pydevd_bundle", "pdb", "bdb"):
        if mod in sys.modules:
            _fail("debugger detected")
    if _traced_by_os():
        _fail("debugger detected")


def _check_expire(expire):
    if expire and time.time() > float(expire):
        _fail("license has expired")


def _check_machines(machines):
    if machines and _machine_id() not in machines:
        _fail("not licensed for this machine")


def _check_integrity():
    """Best-effort: verify the runtime's crypto/loader weren't patched.

    Skipped silently when the sources aren't readable (e.g. inside a frozen
    PyInstaller bundle); enforced when running from the shipped .py folder.
    """
    if not INTEGRITY:
        return
    here = os.path.dirname(os.path.abspath(__file__))
    for name, expected in INTEGRITY.items():
        path = os.path.join(here, name)
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            continue  # source not on disk (frozen) -> can't check
        data = data.replace(b"\\r\\n", b"\\n").replace(b"\\r", b"\\n")
        got = hmac.new(KEY, data, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(got, expected):
            _fail("runtime integrity check failed")


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


def tick():
    """Cheap check run on every protected module load."""
    if ANTI_DEBUG:
        _check_anti_debug()


def check():
    """Full check run once, before the first protected module executes."""
    if ANTI_DEBUG:
        _check_anti_debug()
    _check_integrity()
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
    if isinstance(value, dict):
        return "{" + ", ".join(
            f"{_py_value(k)}: {_py_value(v)}" for k, v in value.items()
        ) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_py_value(v) for v in value) + "]"
    raise TypeError(f"unsupported guard value: {value!r}")


def _integrity_hex(key: bytes, content: str) -> str:
    data = content.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def render_guard(protection=None, integrity=None) -> str:
    """Render ``_guard.py`` with the build's protection constraints baked in."""
    from .protection import DEFAULT_LICENSE_NAME, ProtectionOptions

    p = protection or ProtectionOptions()
    header = (
        "# Generated protection constraints for this build.\n"
        f"EXPIRE = {_py_value(p.expire)}\n"
        f"MACHINES = {_py_value(p.machines)}\n"
        f"ANTI_DEBUG = {_py_value(bool(p.anti_debug))}\n"
        f"REQUIRE_LICENSE = {_py_value(bool(p.require_license))}\n"
        f"LICENSE_NAME = {_py_value(p.license_name or DEFAULT_LICENSE_NAME)}\n"
        f"INTEGRITY = {_py_value(integrity or {})}\n\n"
    )
    return header + GUARD_BODY


def _render_key(material) -> str:
    """Render ``_key.py`` for either the shipped-key or KDF mode."""
    import base64

    if getattr(material, "kdf", None) == "pbkdf2":
        return KEY_KDF_SRC.format(
            env=material.secret_env,
            salt_hex=material.salt.hex(),
            iters=material.iters,
        )
    key_b85 = base64.b85encode(material.key)
    return KEY_SRC.format(key=key_b85)


def render_runtime(material, protection=None) -> dict:
    """Return ``{filename: source}`` for the runtime package.

    *material* is a :class:`~tungtungarmor.packer.KeyMaterial` describing the
    key and how it is stored.  For backwards compatibility a raw ``bytes`` key
    is also accepted (treated as the default shipped-key mode).
    """
    if isinstance(material, (bytes, bytearray)):
        from .packer import KeyMaterial
        material = KeyMaterial(key=bytes(material))

    files = {
        "__init__.py": INIT_SRC,
        "_cipher.py": CIPHER_SRC,
        "_key.py": _render_key(material),
    }
    integrity = {
        "_cipher.py": _integrity_hex(material.key, files["_cipher.py"]),
        "__init__.py": _integrity_hex(material.key, files["__init__.py"]),
    }
    files["_guard.py"] = render_guard(protection, integrity)
    return files
