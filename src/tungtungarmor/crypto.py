"""Symmetric encryption used by tungtungarmor.

Dependency-free authenticated stream cipher built on SHA-256:

    * Two independent sub-keys are derived from the master key with
      HKDF-SHA256 (one for the keystream, one for the MAC) so the same
      secret is never used for two purposes.
    * Keystream is generated CTR-style: SHA256(enc_key || nonce || counter).
    * Ciphertext = plaintext XOR keystream.
    * Integrity is protected with HMAC-SHA256(mac_key, nonce || ciphertext).

This is *not* meant to be military-grade DRM -- in the default mode the key
ultimately ships with the program (in ``_key.py``), so a determined attacker
can recover it.  The goal is to raise the bar well above "open the .py in a
text editor": the distributed artifact contains only encrypted, marshalled
bytecode.

For a genuinely stronger guarantee, tungtungarmor also offers a *key
derivation* mode (see :func:`derive_key_from_secret`) where the key is **not**
shipped at all but derived at runtime from a secret supplied through the
environment -- turning obfuscation into real encryption for the
server-side / password-gated use case.

The exact same primitives are re-implemented (self-contained, no imports from
this package) inside the generated runtime so the protected program can
decrypt itself without depending on tungtungarmor being installed.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

NONCE_SIZE = 16
TAG_SIZE = 32

# HKDF context labels (kept identical in the generated runtime).
_HKDF_SALT = b"tungtungarmor-hkdf-v1"
_INFO_ENC = b"tta-enc"
_INFO_MAC = b"tta-mac"

# PBKDF2 default work factor for the key-derivation mode.
DEFAULT_KDF_ITERS = 200_000


def _hkdf(key: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869) with a fixed extract salt."""
    prk = hmac.new(_HKDF_SALT, key, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def _subkeys(key: bytes):
    """Return ``(enc_key, mac_key)`` derived from *key*."""
    return _hkdf(key, _INFO_ENC), _hkdf(key, _INFO_MAC)


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(enc_key + nonce + struct.pack(">Q", counter)).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def encrypt(data: bytes, key: bytes) -> bytes:
    """Return ``nonce || tag || ciphertext``."""
    enc_key, mac_key = _subkeys(key)
    nonce = os.urandom(NONCE_SIZE)
    keystream = _keystream(enc_key, nonce, len(data))
    ciphertext = bytes(a ^ b for a, b in zip(data, keystream))
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + tag + ciphertext


def decrypt(blob: bytes, key: bytes) -> bytes:
    enc_key, mac_key = _subkeys(key)
    nonce = blob[:NONCE_SIZE]
    tag = blob[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = blob[NONCE_SIZE + TAG_SIZE:]
    expected = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("tungtungarmor: integrity check failed (wrong key or tampering)")
    keystream = _keystream(enc_key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, keystream))


def new_key(size: int = 32) -> bytes:
    return os.urandom(size)


def derive_key_from_secret(secret, salt: bytes, iters: int = DEFAULT_KDF_ITERS,
                           dklen: int = 32) -> bytes:
    """Derive a 32-byte key from *secret* with PBKDF2-HMAC-SHA256.

    Used by the key-derivation mode: the resulting key is never stored in the
    shipped artifact -- only *salt* and *iters* are, so the program can only be
    run by someone who supplies the same secret at runtime.  The identical
    computation is emitted into the runtime's ``_key.py``.
    """
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", secret, salt, iters, dklen=dklen)
