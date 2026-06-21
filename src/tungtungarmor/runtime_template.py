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

__all__ = ["__armor_exec__"]


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
    code = marshal.loads(decrypt(blob, KEY))
    if module_globals is None:
        module_globals = sys._getframe(1).f_globals
    # Make the literal-decryption helpers available to the protected code.
    module_globals.setdefault("__armor_s__", __armor_s__)
    module_globals.setdefault("__armor_b__", __armor_b__)
    exec(code, module_globals)
'''


def render_runtime(key_bytes: bytes) -> dict:
    """Return ``{filename: source}`` for the runtime package, given the key."""
    import base64

    key_b85 = base64.b85encode(key_bytes)
    return {
        "__init__.py": INIT_SRC,
        "_cipher.py": CIPHER_SRC,
        "_key.py": KEY_SRC.format(key=key_b85),
    }
