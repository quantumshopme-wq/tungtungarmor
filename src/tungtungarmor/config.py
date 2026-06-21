"""Config-file support for tungtungarmor.

Lets you keep long PyInstaller option lists (hidden imports, data files,
metadata, ...) in a structured file instead of one giant command line.

Supported formats
-----------------
* ``*.toml`` -- needs Python 3.11+ (``tomllib``) or the ``tomli`` package.
* ``*.json`` -- always available.

If ``--config`` is not given, a ``tungtungarmor.toml`` (or ``.json``) in the
current directory is loaded automatically when present.

Schema (TOML example)
---------------------
.. code-block:: toml

    # obfuscation options (top level)
    output = "dist_protected"
    encrypt_strings = true
    rename_locals = false
    optimize = 2
    runtime_pkg = "tungtungarmor_runtime"

    [pyinstaller]
    entry = "main.py"
    project_root = "."
    name = "TungTung Poster"
    onedir = true            # false (default) => one-file
    windowed = true          # true => no console window
    icon = "assets/icons/app.ico"
    noupx = true
    hidden_imports = ["api_server", "adbutils", "fastapi", "uvicorn"]
    collect_data = ["pandas", "uiautomator2"]
    collect_submodules = ["uvicorn"]
    collect_all = []
    copy_metadata = ["numpy", "fastapi", "uvicorn"]
    add_data = ["assets;assets", "templates;templates"]
    add_binary = []
    pyi_options = "--noconfirm"   # any extra raw flags, PyArmor-style
    extra_args = []               # already-tokenised extra flags
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # Python 3.11+
    import tomllib as _toml  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - depends on interpreter
    try:
        import tomli as _toml  # type: ignore
    except ModuleNotFoundError:
        _toml = None  # type: ignore

DEFAULT_CONFIG_NAMES = ("tungtungarmor.toml", "tungtungarmor.json")

# (config key, PyInstaller flag) for list-valued options.
_LIST_FLAGS = [
    ("hidden_imports", "--hidden-import"),
    ("collect_data", "--collect-data"),
    ("collect_submodules", "--collect-submodules"),
    ("collect_all", "--collect-all"),
    ("copy_metadata", "--copy-metadata"),
    ("add_data", "--add-data"),
    ("add_binary", "--add-binary"),
]


def find_default_config(cwd: Optional[Path] = None) -> Optional[Path]:
    cwd = cwd or Path.cwd()
    for name in DEFAULT_CONFIG_NAMES:
        candidate = cwd / name
        if candidate.exists():
            return candidate
    return None


def load_config(path: Path) -> Dict[str, Any]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"config file not found: {path}")
    if path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    # default to TOML
    if _toml is None:
        raise RuntimeError(
            f"cannot read {path}: TOML support requires Python 3.11+ or the "
            "'tomli' package (pip install tomli). Alternatively use a .json config."
        )
    with open(path, "rb") as fh:
        return _toml.load(fh)


def assemble_pyi_flags(pyi: Dict[str, Any]) -> List[str]:
    """Turn the structured ``[pyinstaller]`` section into PyInstaller flags."""
    flags: List[str] = []
    for key, flag in _LIST_FLAGS:
        for value in pyi.get(key, []) or []:
            flags.extend([flag, str(value)])
    icon = pyi.get("icon")
    if icon:
        flags.extend(["-i", str(icon)])
    if pyi.get("noupx"):
        flags.append("--noupx")
    # Raw PyArmor-style option string, then already-tokenised extras.
    raw = pyi.get("pyi_options")
    if raw:
        flags.extend(shlex.split(raw))
    for tok in pyi.get("extra_args", []) or []:
        flags.append(str(tok))
    return flags
