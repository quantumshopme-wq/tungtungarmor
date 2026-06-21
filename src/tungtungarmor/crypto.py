"""Symmetric encryption used by tungtungarmor.

Dependency-free authenticated stream cipher built on SHA-256:

    * Keystream is generated CTR-style: SHA256(key || nonce || counter).
    * Ciphertext = plaintext XOR keystream.
    * Integrity is protected with HMAC-SHA256 over (nonce || ciphertext).

This is *not* meant to be military-grade DRM -- like every pure-Python
obfuscator the key ultimately ships with the program, so a determined
attacker can recover it.  The goal is to raise the bar well above
"open the .py in a text editor": the distributed artifact contains only
encrypted, marshalled bytecode.

The exact same primitive is re-implemented (self-contained, no imports
from this package) inside the generated runtime so the protected program
can decrypt itself without depending on tungtungarmor being installed.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

NONCE_SIZE = 16
TAG_SIZE = 32


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(key + nonce + struct.pack(">Q", counter)).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def encrypt(data: bytes, key: bytes) -> bytes:
    """Return ``nonce || tag || ciphertext``."""
    nonce = os.urandom(NONCE_SIZE)
    keystream = _keystream(key, nonce, len(data))
    ciphertext = bytes(a ^ b for a, b in zip(data, keystream))
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + tag + ciphertext


def decrypt(blob: bytes, key: bytes) -> bytes:
    nonce = blob[:NONCE_SIZE]
    tag = blob[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = blob[NONCE_SIZE + TAG_SIZE:]
    expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("tungtungarmor: integrity check failed (wrong key or tampering)")
    keystream = _keystream(key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, keystream))


def new_key(size: int = 32) -> bytes:
    return os.urandom(size)
