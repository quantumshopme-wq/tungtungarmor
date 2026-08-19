"""Runtime-protection features (build side): expiry, machine binding,
anti-debug and signed external license files -- PyArmor-style.

The matching enforcement code is emitted into the generated runtime's
``_guard.py`` (see :mod:`tungtungarmor.runtime_template`).  This module owns
the build-time helpers: computing a machine id, parsing dates and issuing
license files signed with the per-build key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import platform
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

DEFAULT_LICENSE_NAME = "tungtungarmor.lic"


def machine_id() -> str:
    """A stable-ish identifier for the current machine.

    Combines OS, hostname and the primary MAC address.  The identical
    function is emitted into the runtime guard so build-time and run-time
    agree on the value.
    """
    parts = [platform.system(), platform.node(), str(uuid.getnode())]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]


def parse_expire(date_str: str) -> float:
    """Parse ``YYYY-MM-DD`` into an epoch timestamp at end of that day."""
    dt = datetime.strptime(date_str, "%Y-%m-%d")
    # expire at 23:59:59 local time on the given date
    return dt.timestamp() + 86399.0


@dataclass
class ProtectionOptions:
    expire: Optional[float] = None            # epoch seconds, or None
    machines: Optional[List[str]] = None      # allowed machine ids (None = any)
    anti_debug: bool = False
    require_license: bool = False
    license_name: str = DEFAULT_LICENSE_NAME

    @property
    def active(self) -> bool:
        return bool(
            self.expire or self.machines or self.anti_debug or self.require_license
        )


# --------------------------------------------------------------------------
# License files (signed with the per-build key)
# --------------------------------------------------------------------------

def sign_license(
    key: bytes,
    *,
    expire: Optional[float] = None,
    machines: Optional[List[str]] = None,
    note: str = "",
) -> str:
    """Return a signed, single-line license string.

    Format: ``base85(payload) "." base85(hmac_sha256(key, payload))``.
    """
    payload = {
        "expire": expire,
        "machines": machines,
        "note": note,
        "issued": time.time(),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(key, raw, hashlib.sha256).digest()
    return base64.b85encode(raw).decode("ascii") + "." + base64.b85encode(sig).decode("ascii")


def read_key_from_runtime(runtime_dir: Path) -> bytes:
    """Recover the build key from a generated runtime package's ``_key.py``."""
    key_file = Path(runtime_dir) / "_key.py"
    if not key_file.exists():
        raise FileNotFoundError(f"no _key.py under {runtime_dir}")
    namespace: dict = {}
    exec(key_file.read_text(encoding="utf-8"), namespace)  # our own generated file
    key = namespace.get("KEY")
    if not isinstance(key, (bytes, bytearray)):
        raise ValueError(f"could not read KEY from {key_file}")
    return bytes(key)
