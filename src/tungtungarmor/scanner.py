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
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Set, Tuple

_STDLIB = frozenset(getattr(sys, "stdlib_module_names", ()))


@dataclass
class ScanResult:
    files: Set[Path] = field(default_factory=set)
    local_modules: Set[str] = field(default_factory=set)
    external_modules: Set[str] = field(default_factory=set)

    # Backwards-compatible unpacking: ``files, modules = discover(...)``
    def __iter__(self):
        return iter((self.files, self.local_modules))


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


def _importfrom_targets(node: ast.ImportFrom, current_pkg: str):
    """Return ``(base, is_relative, expanded)`` for a ``from ... import ...``.

    *base* is the module the names are imported from; *expanded* are the
    ``base.name`` candidates (a name may itself be a submodule).
    """
    if node.level and node.level > 0:
        pkg_parts = current_pkg.split(".") if current_pkg else []
        up = node.level - 1
        base_parts = pkg_parts[: len(pkg_parts) - up] if up <= len(pkg_parts) else []
        if node.module:
            base_parts = base_parts + node.module.split(".")
        base = ".".join(base_parts)
        is_relative = True
    else:
        base = node.module or ""
        is_relative = False
    expanded = []
    if base:
        for alias in node.names:
            if alias.name != "*":
                expanded.append(base + "." + alias.name)
    return base, is_relative, expanded


def _seed_include(inc: str, root: Path) -> List[Path]:
    if any(ch in inc for ch in "/\\*?") or inc.endswith(".py"):
        return [p for p in root.glob(inc) if p.is_file() and p.suffix == ".py"]
    return _module_to_files(inc, root)


def discover(
    entry: Path,
    root: Path,
    include: Optional[Iterable[str]] = None,
    on_warn: Optional[Callable[[str], None]] = None,
) -> "ScanResult":
    """Discover project files reachable from *entry* under *root*.

    Returns a :class:`ScanResult` with the local ``files``, their
    ``local_modules`` (dotted names), and the third-party ``external_modules``
    imported by the source (stdlib filtered out). The result also unpacks as
    ``files, local_modules`` for convenience.

    *include* lets you force extra modules/globs in for imports that can't be
    found statically (dynamic ``importlib`` use, plugins, etc.).
    """
    root = Path(root).resolve()
    entry = Path(entry).resolve()

    files: Set[Path] = set()
    external: Set[str] = set()
    queue: List[Path] = [entry]
    for inc in include or []:
        queue.extend(_seed_include(inc, root))

    def _consider(dotted: str, *, allow_external: bool):
        """Enqueue local files for *dotted*; record external otherwise."""
        local = _module_to_files(dotted, root)
        if local:
            for cand in local:
                if cand not in files:
                    queue.append(cand)
            return True
        if allow_external and dotted:
            # Skip only bare top-level stdlib modules (os, json, ...): those are
            # always available. But KEEP stdlib *submodules* (tkinter.colorchooser,
            # logging.handlers, xml.etree.ElementTree, ...): the obfuscated source
            # hides the import, so PyInstaller won't bundle them unless we say so.
            if "." not in dotted and dotted in _STDLIB:
                return False
            external.add(dotted)
        return False

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
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    _consider(alias.name, allow_external=True)
            elif isinstance(node, ast.ImportFrom):
                base, is_relative, expanded = _importfrom_targets(node, pkg)
                if base:
                    # relative imports are always local; don't mark external
                    _consider(base, allow_external=not is_relative)
                # imported names may themselves be submodules -- follow if local,
                # and record as external too so e.g.
                # "from selenium.webdriver.support import expected_conditions"
                # adds the submodule as a hidden import.
                for sub in expanded:
                    _consider(sub, allow_external=not is_relative)

    local_modules = {_file_to_module(f, root) for f in files}
    local_modules.discard("")
    return ScanResult(files=files, local_modules=local_modules, external_modules=external)


def select_hidden_imports(scan, *, entry_module=None, runtime_pkg=None):
    """Pick the modules to pass to PyInstaller as ``--hidden-import``.

    The encrypted source is invisible to PyInstaller, so we feed it every
    module the code imports. But a ``from pkg import Thing`` records
    ``pkg.Thing`` too, and ``Thing`` is usually a class/function, not a module
    -- passing those just produces noisy "hidden import not found" lines. So:

    * local project modules (known to be modules from their files) are kept;
    * a third-party top-level name is kept as-is (cheap, and it triggers hooks);
    * a dotted third-party name is kept only if it really resolves to a module
      (verified with :func:`importlib.util.find_spec`), which keeps real
      submodules like ``selenium.webdriver.support.expected_conditions`` but
      drops class/attribute names like ``fastapi.FastAPI``;
    * names under a local package, ``__main__`` and the runtime package are
      never emitted.
    """
    import importlib.util

    local_modules = set(scan.local_modules)
    local_tops = {m.split(".")[0] for m in local_modules}

    def _resolvable(name):
        try:
            # None means "definitely not a module" (e.g. a class/attribute name
            # like fastapi.FastAPI) -> drop it.
            return importlib.util.find_spec(name) is not None
        except BaseException:
            # Parent couldn't be imported at build time (headless GUI libs,
            # native panics, optional deps). We can't prove it's not a module,
            # so keep it -- dropping a real submodule would break the exe, and
            # PyInstaller will just warn if it truly isn't there.
            return True

    hidden = set(local_modules)
    for ext in scan.external_modules:
        top = ext.split(".")[0]
        if not top or top in local_tops:
            continue  # local attribute leak (e.g. core.mod.SomeClass)
        if "." not in ext:
            hidden.add(ext)          # top-level third-party package
        elif _resolvable(ext):
            hidden.add(ext)          # real submodule

    for junk in ("", "__main__", entry_module, runtime_pkg):
        hidden.discard(junk)
    return sorted(m for m in hidden if m and not m.startswith("__main__"))
