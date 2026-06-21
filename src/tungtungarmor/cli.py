"""Command-line interface for tungtungarmor."""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path

from . import __version__
from .config import assemble_pyi_flags, find_default_config, load_config
from .packer import DEFAULT_RUNTIME_PKG, ObfuscateOptions, pack

# Sentinel default: optional args are absent from the namespace unless the user
# actually passed them, so we can layer  defaults < config < explicit CLI.
SUPPRESS = argparse.SUPPRESS


def _load_cfg(args):
    path = getattr(args, "config", None)
    if path:
        return load_config(Path(path))
    auto = find_default_config()
    if auto:
        print(f"tungtungarmor: using config {auto}")
        return load_config(auto)
    return {}


def _resolve(args, attr, cfg, cfg_key, default):
    """explicit CLI flag  >  config value  >  hard default."""
    if hasattr(args, attr):
        return getattr(args, attr)
    if cfg_key in cfg:
        return cfg[cfg_key]
    return default


def _build_options(args, cfg) -> ObfuscateOptions:
    if hasattr(args, "no_encrypt_strings"):
        encrypt_strings = not getattr(args, "no_encrypt_strings")
    else:
        encrypt_strings = cfg.get("encrypt_strings", True)
    return ObfuscateOptions(
        encrypt_strings=encrypt_strings,
        rename_locals=_resolve(args, "rename_locals", cfg, "rename_locals", False),
        min_string_length=_resolve(args, "min_string_length", cfg, "min_string_length", 1),
        optimize=_resolve(args, "optimize", cfg, "optimize", 0),
        runtime_pkg=_resolve(args, "runtime_pkg", cfg, "runtime_pkg", DEFAULT_RUNTIME_PKG),
    )


def _cmd_obfuscate(args) -> int:
    cfg = _load_cfg(args)
    target = getattr(args, "target", None) or cfg.get("target") or cfg.get("source")
    if not target:
        print("error: no target given (pass one on the CLI or set 'target' in the config)",
              file=sys.stderr)
        return 2
    target = Path(target)
    if not target.exists():
        print(f"error: target not found: {target}", file=sys.stderr)
        return 2
    output = _resolve(args, "output", cfg, "output", "dist_protected")
    options = _build_options(args, cfg)
    result = pack(target, Path(output), options)
    print(f"tungtungarmor: protected {len(result.obfuscated_files)} file(s)")
    print(f"  output:  {result.output_dir}")
    print(f"  runtime: {result.runtime_dir}")
    if getattr(args, "show_key", False):
        import base64
        print(f"  key(b85): {base64.b85encode(result.key).decode()}")
    return 0


def _cmd_pyinstaller(args) -> int:
    from .pyinstaller_integration import build, generate_spec

    cfg = _load_cfg(args)
    pyi = cfg.get("pyinstaller", {})

    entry = getattr(args, "entry", None) or pyi.get("entry")
    if not entry:
        print("error: no entry script given (pass one on the CLI or set "
              "[pyinstaller] entry in the config)", file=sys.stderr)
        return 2
    entry = Path(entry)
    if not entry.exists():
        print(f"error: entry not found: {entry}", file=sys.stderr)
        return 2

    options = _build_options(args, cfg)
    name = _resolve(args, "name", pyi, "name", None)
    onedir = _resolve(args, "onedir", pyi, "onedir", False)
    windowed = _resolve(args, "windowed", pyi, "windowed", False)
    project_root = _resolve(args, "project_root", pyi, "project_root", None)

    if getattr(args, "spec_only", False):
        out = generate_spec(
            entry=entry,
            pathex=entry.parent,
            name=name or entry.stem,
            runtime_pkg=options.runtime_pkg,
            console=not windowed,
            onefile=not onedir,
        )
        print(f"tungtungarmor: wrote spec -> {out}")
        return 0

    # Merge PyInstaller flags: structured config  +  --pyi-options  +  REMAINDER.
    extra = assemble_pyi_flags(pyi)
    cli_pyi_options = getattr(args, "pyi_options", None)
    if cli_pyi_options:
        extra.extend(shlex.split(cli_pyi_options))
    if getattr(args, "pyinstaller_args", None):
        extra.extend(args.pyinstaller_args)

    build_kwargs = {}
    if "dist" in pyi:
        build_kwargs["dist_dir"] = Path(pyi["dist"])

    try:
        rc = build(
            entry,
            project_root=Path(project_root) if project_root else None,
            name=name,
            onefile=not onedir,
            console=not windowed,
            options=options,
            extra_args=extra or None,
            **build_kwargs,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if rc == 0:
        print("tungtungarmor: build finished -> see dist/")
    return rc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tungtungarmor",
        description="Obfuscate Python scripts (PyArmor-style) with PyInstaller integration.",
    )
    parser.add_argument("--version", action="version", version=f"tungtungarmor {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p):
        p.add_argument("--config", default=SUPPRESS,
                       help="path to a tungtungarmor.toml/.json config "
                            "(auto-detected in the current dir if omitted)")
        p.add_argument("--no-encrypt-strings", action="store_true", default=SUPPRESS,
                       help="disable string-literal encryption")
        p.add_argument("--rename-locals", action="store_true", default=SUPPRESS,
                       help="rename function-local variables (experimental)")
        p.add_argument("--min-string-length", type=int, default=SUPPRESS,
                       help="only encrypt string literals of at least this length")
        p.add_argument("--optimize", type=int, choices=(0, 1, 2), default=SUPPRESS,
                       help="compile() optimization level (strips asserts/docstrings)")
        p.add_argument("--runtime-pkg", default=SUPPRESS,
                       help="name of the generated runtime package")

    # obfuscate
    p_obf = sub.add_parser("obfuscate", help="obfuscate a file or directory")
    p_obf.add_argument("target", nargs="?", default=SUPPRESS,
                       help="source .py file or project directory")
    p_obf.add_argument("-o", "--output", default=SUPPRESS,
                       help="output directory (default: dist_protected)")
    p_obf.add_argument("--show-key", action="store_true", default=SUPPRESS,
                       help="print the generated encryption key")
    add_common(p_obf)
    p_obf.set_defaults(func=_cmd_obfuscate)

    # pyinstaller
    p_pyi = sub.add_parser("pyinstaller", help="obfuscate then build with PyInstaller")
    p_pyi.add_argument("entry", nargs="?", default=SUPPRESS, help="entry-point .py script")
    p_pyi.add_argument("--project-root", default=SUPPRESS,
                       help="project root to obfuscate (default: entry's dir)")
    p_pyi.add_argument("--name", default=SUPPRESS,
                       help="output executable name (default: entry stem)")
    p_pyi.add_argument("--onedir", action="store_true", default=SUPPRESS,
                       help="build a one-folder bundle (default: onefile)")
    p_pyi.add_argument("--windowed", action="store_true", default=SUPPRESS,
                       help="GUI app, no console window")
    p_pyi.add_argument("--spec-only", action="store_true", default=SUPPRESS,
                       help="only write a .spec file, don't build")
    p_pyi.add_argument("--pyi-options", default=SUPPRESS,
                       help="single quoted string of PyInstaller flags, PyArmor "
                            "pyi_options style, e.g. \"-w -i app.ico --add-data assets;assets\"")
    p_pyi.add_argument("--pyinstaller-args", nargs=argparse.REMAINDER, default=SUPPRESS,
                       help="pass remaining args straight to PyInstaller")
    add_common(p_pyi)
    p_pyi.set_defaults(func=_cmd_pyinstaller)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
