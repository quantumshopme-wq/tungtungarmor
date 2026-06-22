"""Dependency scanner: discover only the project's own modules by following
imports from an entry script -- like PyArmor's "search inputs / find extra
resources" step.

This lets tungtungarmor obfuscate just the files that belong to the project
(reachable from the entry point) instead of every ``.py`` in the directory
tree, so unrelated files (debug scripts, vendored copies, broken scratch
files, ...) are left alone without needing a long exclude list.

Only modules that resolve to a file *under the project root* are followed;
standard-library and third-party (site-packages) imports are ignored.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Set, Tuple


def _containing_package(f: Path, root: Path) -> str:
    """Dotted package used to resolve relative imports inside *f*."""
    rel = f.relative_to(root)
    parts = list(rel.parts)[:-1]  # drop the file name (and for __init__.py its dir)
    return ".".join(parts)


def _file_to_module(f: Path, root: Path) -> str:
    rel = f.relative_to(root)
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = parts[-1][:-3]  # strip ".py"
    return ".".join(parts)


def _module_to_files(dotted: str, root: Path) -> List[Path]:
    """Local files a dotted module maps to (module, package, parent inits)."""
    if not dotted:
        return []
    parts = dotted.split(".")
    files: List[Path] = []
    # parent package __init__.py files
    for i in range(1, len(parts)):
        init = root.joinpath(*parts[:i]) / "__init__.py"
        if init.is_file():
            files.append(init)
    cand_mod = root.joinpath(*parts).with_suffix(".py")
    cand_pkg = root.joinpath(*parts) / "__init__.py"
    if cand_mod.is_file():
        files.append(cand_mod)
    if cand_pkg.is_file():
        files.append(cand_pkg)
    return files


def _resolve_importfrom(node: ast.ImportFrom, current_pkg: str) -> List[str]:
    """Dotted module targets referenced by a ``from ... import ...``."""
    if node.level and node.level > 0:
        pkg_parts = current_pkg.split(".") if current_pkg else []
        up = node.level - 1
        base_parts = pkg_parts[: len(pkg_parts) - up] if up <= len(pkg_parts) else []
        if node.module:
            base_parts = base_parts + node.module.split(".")
        base = ".".join(base_parts)
    else:
        base = node.module or ""
    if not base:
        return []
    targets = [base]
    # imported names might themselves be submodules (from pkg import sub)
    for alias in node.names:
        if alias.name != "*":
            targets.append(base + "." + alias.name)
    return targets


def _seed_include(inc: str, root: Path) -> List[Path]:
    if any(ch in inc for ch in "/\\*?") or inc.endswith(".py"):
        return [p for p in root.glob(inc) if p.is_file() and p.suffix == ".py"]
    return _module_to_files(inc, root)


def discover(
    entry: Path,
    root: Path,
    include: Optional[Iterable[str]] = None,
    on_warn: Optional[Callable[[str], None]] = None,
) -> Tuple[Set[Path], Set[str]]:
    """Return ``(files, module_names)`` reachable from *entry* under *root*.

    *include* lets you force extra modules/globs in for imports that can't be
    found statically (dynamic ``importlib`` use, plugins, etc.).
    """
    root = Path(root).resolve()
    entry = Path(entry).resolve()

    files: Set[Path] = set()
    queue: List[Path] = [entry]
    for inc in include or []:
        queue.extend(_seed_include(inc, root))

    while queue:
        f = queue.pop()
        try:
            f = f.resolve()
        except OSError:
            continue
        if f in files or not f.is_file():
            continue
        try:
            f.relative_to(root)  # must live inside the project
        except ValueError:
            continue
        files.add(f)
        try:
            tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        except (SyntaxError, UnicodeDecodeError) as exc:
            if on_warn:
                on_warn(f"skipping imports of {f} ({exc.__class__.__name__})")
            continue
        pkg = _containing_package(f, root)
        targets: List[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                targets.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                targets.extend(_resolve_importfrom(node, pkg))
        for dotted in targets:
            for cand in _module_to_files(dotted, root):
                if cand not in files:
                    queue.append(cand)

    module_names = {_file_to_module(f, root) for f in files}
    module_names.discard("")
    return files, module_names
