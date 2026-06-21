"""tungtungarmor -- a lightweight, pure-Python source obfuscator with
PyInstaller integration.

Public API
----------
>>> from tungtungarmor import pack, ObfuscateOptions
>>> pack("myproject", "dist_protected", ObfuscateOptions(rename_locals=True))
"""

from .crypto import decrypt, encrypt, new_key
from .packer import (
    DEFAULT_RUNTIME_PKG,
    ObfuscateOptions,
    PackResult,
    obfuscate_file,
    obfuscate_source,
    pack,
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
    "PackResult",
    "DEFAULT_RUNTIME_PKG",
    "pack",
    "obfuscate_file",
    "obfuscate_source",
    "write_runtime",
    "encrypt",
    "decrypt",
    "new_key",
    "ProtectionOptions",
    "DEFAULT_LICENSE_NAME",
    "machine_id",
    "parse_expire",
    "sign_license",
]
