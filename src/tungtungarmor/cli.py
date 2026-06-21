"""Command-line interface for tungtungarmor."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .packer import DEFAULT_RUNTIME_PKG, ObfuscateOptions, pack


def _build_options(args) -> ObfuscateOptions:
    return ObfuscateOptions(
        encrypt_strings=not args.no_encrypt_strings,
        rename_locals=args.rename_locals,
        min_string_length=args.min_string_length,
        optimize=args.optimize,
        runtime_pkg=args.runtime_pkg,
    )


def _cmd_obfuscate(args) -> int:
    target = Path(args.target)
    if not target.exists():
        print(f"error: target not found: {target}", file=sys.stderr)
        return 2
    options = _build_options(args)
    result = pack(target, Path(args.output), options)
    print(f"tungtungarmor: protected {len(result.obfuscated_files)} file(s)")
    print(f"  output:  {result.output_dir}")
    print(f"  runtime: {result.runtime_dir}")
    if args.show_key:
        import base64
        print(f"  key(b85): {base64.b85encode(result.key).decode()}")
    return 0


def _cmd_pyinstaller(args) -> int:
    from .pyinstaller_integration import build, generate_spec

    entry = Path(args.entry)
    if not entry.exists():
        print(f"error: entry not found: {entry}", file=sys.stderr)
        return 2
    options = _build_options(args)

    if args.spec_only:
        out = generate_spec(
            entry=entry,
            pathex=entry.parent,
            name=args.name or entry.stem,
            runtime_pkg=args.runtime_pkg,
            console=not args.windowed,
            onefile=not args.onedir,
        )
        print(f"tungtungarmor: wrote spec -> {out}")
        return 0

    try:
        rc = build(
            entry,
            project_root=Path(args.project_root) if args.project_root else None,
            name=args.name,
            onefile=not args.onedir,
            console=not args.windowed,
            options=options,
            pyi_options=args.pyi_options,
            extra_args=args.pyinstaller_args or None,
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
        p.add_argument("--no-encrypt-strings", action="store_true",
                       help="disable string-literal encryption")
        p.add_argument("--rename-locals", action="store_true",
                       help="rename function-local variables (experimental)")
        p.add_argument("--min-string-length", type=int, default=1,
                       help="only encrypt string literals of at least this length")
        p.add_argument("--optimize", type=int, choices=(0, 1, 2), default=0,
                       help="compile() optimization level (strips asserts/docstrings)")
        p.add_argument("--runtime-pkg", default=DEFAULT_RUNTIME_PKG,
                       help="name of the generated runtime package")

    # obfuscate
    p_obf = sub.add_parser("obfuscate", help="obfuscate a file or directory")
    p_obf.add_argument("target", help="source .py file or project directory")
    p_obf.add_argument("-o", "--output", default="dist_protected",
                       help="output directory (default: dist_protected)")
    p_obf.add_argument("--show-key", action="store_true",
                       help="print the generated encryption key")
    add_common(p_obf)
    p_obf.set_defaults(func=_cmd_obfuscate)

    # pyinstaller
    p_pyi = sub.add_parser("pyinstaller", help="obfuscate then build with PyInstaller")
    p_pyi.add_argument("entry", help="entry-point .py script")
    p_pyi.add_argument("--project-root", help="project root to obfuscate (default: entry's dir)")
    p_pyi.add_argument("--name", help="output executable name (default: entry stem)")
    p_pyi.add_argument("--onedir", action="store_true", help="build a one-folder bundle (default: onefile)")
    p_pyi.add_argument("--windowed", action="store_true", help="GUI app, no console window")
    p_pyi.add_argument("--spec-only", action="store_true", help="only write a .spec file, don't build")
    p_pyi.add_argument("--pyi-options", default=None,
                       help="single quoted string of PyInstaller flags, PyArmor "
                            "pyi_options style, e.g. \"-w -i app.ico --add-data assets;assets\"")
    p_pyi.add_argument("--pyinstaller-args", nargs=argparse.REMAINDER,
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
