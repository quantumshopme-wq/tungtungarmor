"""Turn ordinary ``.py`` files into protected (obfuscated) ones."""

from __future__ import annotations

import base64
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


def write_runtime(output_dir: Path, key: bytes, options: ObfuscateOptions) -> Path:
    runtime_dir = output_dir / options.runtime_pkg
    runtime_dir.mkdir(parents=True, exist_ok=True)
    for name, content in render_runtime(key).items():
        (runtime_dir / name).write_text(content, encoding="utf-8")
    return runtime_dir


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _iter_py_files(root: Path, skip: Path):
    for path in root.rglob("*.py"):
        # Never re-obfuscate a previously generated runtime.
        if DEFAULT_RUNTIME_PKG in path.parts:
            continue
        # Never descend into the output directory (it may be nested in root).
        if _is_within(path, skip):
            continue
        yield path


def pack(
    target: Path,
    output_dir: Path,
    options: Optional[ObfuscateOptions] = None,
    key: Optional[bytes] = None,
) -> PackResult:
    """Obfuscate a file or directory tree into *output_dir*.

    The output directory mirrors the input layout and additionally contains
    the generated runtime package.
    """
    options = options or ObfuscateOptions()
    key = key or new_key()
    target = Path(target).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    result = PackResult(output_dir=output_dir, key=key)

    if target.is_file():
        dst = output_dir / target.name
        result.obfuscated_files.append(obfuscate_file(target, dst, key, options))
    else:
        for src in _iter_py_files(target, output_dir):
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
            dst = output_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(src.read_bytes())

    result.runtime_dir = write_runtime(output_dir, key, options)
    return result
