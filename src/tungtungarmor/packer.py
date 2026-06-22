"""Turn ordinary ``.py`` files into protected (obfuscated) ones."""

from __future__ import annotations

import base64
import fnmatch
import marshal
import os
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .crypto import encrypt, new_key
from .runtime_template import render_runtime
from .transformer import transform_source

DEFAULT_RUNTIME_PKG = "tungtungarmor_runtime"

BOOTSTRAP_TEMPLATE = '''\
# -*- coding: utf-8 -*-
# This file was protected by tungtungarmor (https://github.com/quantumshopme-wq/tungtungarmor)
# Do not edit -- the original source has been compiled, encrypted and embedded below.
import base64 as __b64
from {runtime_pkg} import __armor_exec__

__armor_data__ = (
{chunks}
)
__armor_exec__(__b64.b85decode(__armor_data__), __name__, globals())
'''


@dataclass
class ObfuscateOptions:
    encrypt_strings: bool = True
    rename_locals: bool = False
    min_string_length: int = 1
    optimize: int = 0  # passed to compile(): 0/1/2
    runtime_pkg: str = DEFAULT_RUNTIME_PKG


@dataclass
class PackResult:
    output_dir: Path
    obfuscated_files: List[Path] = field(default_factory=list)
    runtime_dir: Optional[Path] = None
    key: bytes = b""


def _wrap_b85(blob: bytes, width: int = 72) -> str:
    text = base64.b85encode(blob).decode("ascii")
    lines = textwrap.wrap(text, width)
    return "\n".join('    b"%s"' % line for line in lines)


def obfuscate_source(
    source: str,
    key: bytes,
    options: ObfuscateOptions,
    *,
    filename: str = "<tungtungarmor>",
) -> str:
    """Return the protected Python source for *source*."""
    tree = transform_source(
        source,
        key,
        encrypt_strings=options.encrypt_strings,
        rename_locals=options.rename_locals,
        min_string_length=options.min_string_length,
        filename=filename,
    )
    code = compile(tree, filename, "exec", optimize=options.optimize)
    blob = encrypt(marshal.dumps(code), key)
    return BOOTSTRAP_TEMPLATE.format(
        runtime_pkg=options.runtime_pkg,
        chunks=_wrap_b85(blob),
    )


def obfuscate_file(
    src: Path,
    dst: Path,
    key: bytes,
    options: ObfuscateOptions,
) -> Path:
    source = src.read_text(encoding="utf-8")
    protected = obfuscate_source(source, key, options, filename=str(src))
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(protected, encoding="utf-8")
    return dst


def write_runtime(output_dir: Path, key: bytes, options: ObfuscateOptions,
                  protection=None) -> Path:
    runtime_dir = output_dir / options.runtime_pkg
    runtime_dir.mkdir(parents=True, exist_ok=True)
    for name, content in render_runtime(key, protection).items():
        (runtime_dir / name).write_text(content, encoding="utf-8")
    return runtime_dir


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


# Directory names that are never obfuscated/copied unless explicitly included.
DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "build", "dist", "dist_protected", ".pyarmor", ".tox",
    "node_modules", ".idea", ".vscode",
}


def _excluded(rel: Path, extra_patterns) -> bool:
    parts = rel.parts
    for part in parts:
        if part in DEFAULT_EXCLUDE_DIRS or part.endswith(".egg-info"):
            return True
    rel_posix = rel.as_posix()
    for pattern in extra_patterns:
        pat = pattern.replace("\\", "/").rstrip("/")
        if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(rel_posix, pat + "/*"):
            return True
        if pat in parts:  # bare directory name
            return True
    return False


def _iter_py_files(root: Path, skip: Path, exclude):
    for path in root.rglob("*.py"):
        # Never re-obfuscate a previously generated runtime.
        if DEFAULT_RUNTIME_PKG in path.parts:
            continue
        # Never descend into the output directory (it may be nested in root).
        if _is_within(path, skip):
            continue
        if _excluded(path.relative_to(root), exclude):
            continue
        yield path


def pack(
    target: Path,
    output_dir: Path,
    options: Optional[ObfuscateOptions] = None,
    key: Optional[bytes] = None,
    protection=None,
    exclude: Optional[List[str]] = None,
    only_files: Optional[List[Path]] = None,
) -> PackResult:
    """Obfuscate a file or directory tree into *output_dir*.

    The output directory mirrors the input layout and additionally contains
    the generated runtime package. Common junk dirs (.venv, build, dist, .git,
    __pycache__, ...) are skipped automatically; pass *exclude* to add more
    (directory names or glob patterns relative to *target*).

    If *only_files* is given (an explicit list of ``.py`` files under *target*,
    e.g. from the import scanner), exactly those are obfuscated and the tree is
    not walked -- no data files are copied.
    """
    options = options or ObfuscateOptions()
    key = key or new_key()
    exclude = exclude or []
    target = Path(target).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    result = PackResult(output_dir=output_dir, key=key)

    if only_files is not None:
        for src in only_files:
            src = Path(src).resolve()
            rel = src.relative_to(target)
            dst = output_dir / rel
            result.obfuscated_files.append(obfuscate_file(src, dst, key, options))
    elif target.is_file():
        dst = output_dir / target.name
        result.obfuscated_files.append(obfuscate_file(target, dst, key, options))
    else:
        for src in _iter_py_files(target, output_dir, exclude):
            rel = src.relative_to(target)
            dst = output_dir / rel
            result.obfuscated_files.append(obfuscate_file(src, dst, key, options))
        # copy non-python files so the package still works
        for src in target.rglob("*"):
            if src.is_dir() or src.suffix == ".py":
                continue
            if DEFAULT_RUNTIME_PKG in src.parts:
                continue
            if _is_within(src, output_dir):
                continue
            rel = src.relative_to(target)
            if _excluded(rel, exclude):
                continue
            dst = output_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(src.read_bytes())

    result.runtime_dir = write_runtime(output_dir, key, options, protection)
    return result
