"""tungtungarmor -- a lightweight, pure-Python source obfuscator with
PyInstaller integration.

Public API
----------
>>> from tungtungarmor import pack, ObfuscateOptions
>>> pack("myproject", "dist_protected", ObfuscateOptions(rename_locals=True))
"""

from .crypto import decrypt, derive_key_from_secret, encrypt, new_key
from .deobfuscator import (
    DeobfuscateError,
    code_to_pyc,
    disassemble,
    recover_code,
    recover_code_file,
)
from .packer import (
    DEFAULT_RUNTIME_PKG,
    KeyMaterial,
    ObfuscateOptions,
    PackResult,
    obfuscate_file,
    obfuscate_source,
    pack,
    strip_debug_info,
    write_runtime,
)
from .protection import (
    DEFAULT_LICENSE_NAME,
    ProtectionOptions,
    machine_id,
    parse_expire,
    sign_license,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "ObfuscateOptions",
    "KeyMaterial",
    "PackResult",
    "DEFAULT_RUNTIME_PKG",
    "pack",
    "obfuscate_file",
    "obfuscate_source",
    "write_runtime",
    "strip_debug_info",
    "encrypt",
    "decrypt",
    "new_key",
    "derive_key_from_secret",
    "recover_code",
    "recover_code_file",
    "code_to_pyc",
    "disassemble",
    "DeobfuscateError",
    "ProtectionOptions",
    "DEFAULT_LICENSE_NAME",
    "machine_id",
    "parse_expire",
    "sign_license",
]
