"""Glue between tungtungarmor and Nuitka.

Same idea as the PyInstaller integration: obfuscate the project into a work
directory (following imports), then run Nuitka against the *obfuscated* entry.

Why this is useful with Nuitka specifically
-------------------------------------------
Nuitka, like PyInstaller, decides what to bundle by *following imports*. But
tungtungarmor's obfuscated modules hide their imports inside encrypted blobs,
so Nuitka can't see them -- which is exactly why "obfuscate then Nuitka"
normally drops half your dependencies. tungtungarmor already discovered every
import while scanning, so here we translate that into explicit Nuitka
``--include-module`` / ``--include-package`` flags. Nothing is invisible.

Important caveat
----------------
Your own modules run as encrypted bytecode through the runtime's ``exec`` --
Nuitka does **not** compile them to C (they stay protected by tungtungarmor's
encryption). Nuitka compiles the bootstrap, the runtime and the *dependencies*
you include. For big scientific stacks (numpy/pandas/scipy/...) compiling those
dependencies can be very slow; for such apps PyInstaller is usually the
pragmatic choice.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from .packer import DEFAULT_RUNTIME_PKG, ObfuscateOptions, pack


def _nuitka_available() -> bool:
    try:
        import nuitka  # noqa: F401
        return True
    except Exception:
        return False


def _split_data(spec: str):
    """Accept ``src=dest``, ``src;dest`` or ``src:dest`` (last sep wins)."""
    for sep in ("=", os.pathsep, ";", ":"):
        if sep and sep in spec:
            src, dest = spec.rsplit(sep, 1)
            return src, dest
    return spec, os.path.basename(spec.rstrip("/\\")) or spec


def build(
    entry: Path,
    *,
    project_root: Optional[Path] = None,
    work_dir: Path = Path("build/tungtungarmor_obf"),
    output_dir: Path = Path("dist"),
    name: Optional[str] = None,
    onefile: bool = False,
    console: bool = True,
    options: Optional[ObfuscateOptions] = None,
    protection=None,
    include: Optional[List[str]] = None,
    data_dirs: Optional[List[str]] = None,
    data_files: Optional[List[str]] = None,
    plugins: Optional[List[str]] = None,
    include_packages: Optional[List[str]] = None,
    extra_args: Optional[List[str]] = None,
) -> int:
    """Obfuscate *entry* (following imports) then compile it with Nuitka."""
    if not _nuitka_available():
        raise RuntimeError(
            "Nuitka is not installed. Install it with:\n    pip install nuitka"
        )

    from .scanner import discover

    entry = Path(entry).resolve()
    project_root = Path(project_root).resolve() if project_root else entry.parent
    options = options or ObfuscateOptions()
    name = name or entry.stem
    work_dir = Path(work_dir).resolve()
    output_dir = Path(output_dir).resolve()

    # 1. Obfuscate only the reachable project files.
    scan = discover(entry, project_root, include,
                    on_warn=lambda m: print("tungtungarmor: warn:", m))
    pack(project_root, work_dir, options, protection=protection,
         only_files=sorted(scan.files))

    rel_entry = entry.relative_to(project_root)
    obf_entry = work_dir / rel_entry
    if not obf_entry.exists():
        raise RuntimeError(f"obfuscated entry not found: {obf_entry}")

    # 2. Translate the scan into explicit Nuitka include flags.
    local_tops = {m.split(".")[0] for m in scan.local_modules}
    entry_module = None
    try:
        entry_module = rel_entry.with_suffix("").as_posix().replace("/", ".")
    except ValueError:
        pass

    includes: List[str] = []
    # Local project modules: include each obfuscated module by name.
    for mod in sorted(scan.local_modules):
        if mod and mod != entry_module:
            includes += [f"--include-module={mod}"]
    # Third-party top-level packages: include the whole package (all submodules)
    # so nothing the (now-invisible) source imports gets dropped.
    third_party_tops = sorted({
        e.split(".")[0] for e in scan.external_modules
        if e and e.split(".")[0] not in local_tops
    })
    for top in third_party_tops:
        includes += [f"--include-package={top}"]
    for pkg in include_packages or []:
        includes += [f"--include-package={pkg}"]
    # The runtime must always be present.
    includes += [f"--include-package={options.runtime_pkg}"]

    print(f"tungtungarmor: scanned imports from {entry.name} -> "
          f"{len(scan.files)} project file(s), "
          f"{len(third_party_tops)} third-party package(s)")

    # 3. Auto-enable the tk-inter plugin when a Tk GUI is in play.
    plugin_set = set(plugins or [])
    if {"tkinter", "customtkinter", "tkcalendar"} & (set(scan.external_modules) |
                                                     {t for t in third_party_tops}):
        plugin_set.add("tk-inter")

    # 4. Assemble the Nuitka command.
    cmd = [sys.executable, "-m", "nuitka", "--standalone",
           "--assume-yes-for-downloads", f"--output-dir={output_dir}",
           f"--output-filename={name}"]
    if onefile:
        cmd.append("--onefile")
    if not console:
        # Nuitka >=1.7 uses --windows-console-mode; keep the older flag too.
        cmd.append("--windows-console-mode=disable")
    for plug in sorted(plugin_set):
        cmd.append(f"--enable-plugin={plug}")
    cmd += includes
    # Data paths must be absolute: Nuitka runs from the work dir (see below).
    for spec in data_dirs or []:
        src, dest = _split_data(spec)
        src_abs = src if os.path.isabs(src) else str((project_root / src).resolve())
        cmd.append(f"--include-data-dir={src_abs}={dest}")
    for spec in data_files or []:
        src, dest = _split_data(spec)
        src_abs = src if os.path.isabs(src) else str((project_root / src).resolve())
        cmd.append(f"--include-data-files={src_abs}={dest}")
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(str(obf_entry))

    # CRITICAL: run Nuitka from the work dir so it resolves the local modules
    # from their OBFUSCATED copies, never from the original sources in the
    # project root (Nuitka's --include-module lookup would otherwise pick up the
    # current working directory and silently compile the un-obfuscated code).
    env = dict(os.environ)
    env["PYTHONPATH"] = str(work_dir)

    print("tungtungarmor: running", " ".join(shlex.quote(c) for c in cmd))
    proc = subprocess.run(cmd, env=env, cwd=str(work_dir))
    return proc.returncode
