"""Command-line interface for tungtungarmor."""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path

from . import __version__
from .config import assemble_pyi_flags, find_default_config, load_config
from .packer import DEFAULT_RUNTIME_PKG, ObfuscateOptions, pack
from .protection import (
    DEFAULT_LICENSE_NAME,
    ProtectionOptions,
    machine_id,
    parse_expire,
    read_key_from_runtime,
    sign_license,
)

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


def _parse_expire_value(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    if not s:
        return None
    return parse_expire(s)


def _exclude_list(args, cfg):
    excludes = list(cfg.get("exclude", []) or [])
    if getattr(args, "exclude", None):
        excludes.extend(args.exclude)
    return excludes or None


def _build_protection(args, cfg) -> ProtectionOptions:
    sec = cfg.get("protection", {})
    expire = _parse_expire_value(_resolve(args, "expire", sec, "expire", None))

    machines = list(sec.get("machines", []) or [])
    if getattr(args, "allow_machine", None):
        machines.extend(args.allow_machine)
    if _resolve(args, "bind_machine", sec, "bind_machine", False):
        machines.append(machine_id())
    machines = sorted(set(machines)) or None

    return ProtectionOptions(
        expire=expire,
        machines=machines,
        anti_debug=_resolve(args, "anti_debug", sec, "anti_debug", False),
        require_license=_resolve(args, "require_license", sec, "require_license", False),
        license_name=_resolve(args, "license_name", sec, "license_name", DEFAULT_LICENSE_NAME),
    )


def _report_protection(p: ProtectionOptions) -> None:
    if not p.active:
        return
    bits = []
    if p.anti_debug:
        bits.append("anti-debug")
    if p.expire:
        from datetime import datetime
        bits.append("expires " + datetime.fromtimestamp(p.expire).strftime("%Y-%m-%d"))
    if p.machines:
        bits.append(f"{len(p.machines)} machine(s)")
    if p.require_license:
        bits.append(f"requires license '{p.license_name}'")
    print("  protection: " + ", ".join(bits))


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
    protection = _build_protection(args, cfg)
    exclude = _exclude_list(args, cfg)
    result = pack(target, Path(output), options, protection=protection, exclude=exclude)
    print(f"tungtungarmor: protected {len(result.obfuscated_files)} file(s)")
    print(f"  output:  {result.output_dir}")
    print(f"  runtime: {result.runtime_dir}")
    _report_protection(protection)
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
    protection = _build_protection(args, cfg)
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
            protection=protection,
            exclude=_exclude_list(args, cfg),
            extra_args=extra or None,
            **build_kwargs,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if rc == 0:
        print("tungtungarmor: build finished -> see dist/")
        _report_protection(protection)
    return rc


def _cmd_machine_id(args) -> int:
    print(machine_id())
    return 0


def _cmd_license(args) -> int:
    import base64

    if getattr(args, "key", None):
        key = base64.b85decode(args.key)
    elif getattr(args, "runtime", None):
        key = read_key_from_runtime(Path(args.runtime))
    else:
        print("error: provide --runtime <runtime_dir> or --key <b85>", file=sys.stderr)
        return 2

    expire = _parse_expire_value(getattr(args, "expire", None))
    machines = list(getattr(args, "allow_machine", None) or [])
    if getattr(args, "bind_machine", False):
        machines.append(machine_id())
    machines = sorted(set(machines)) or None

    text = sign_license(key, expire=expire, machines=machines,
                        note=getattr(args, "note", "") or "")
    out = Path(getattr(args, "output", None) or DEFAULT_LICENSE_NAME)
    out.write_text(text, encoding="utf-8")
    print(f"tungtungarmor: wrote license -> {out}")
    if expire:
        from datetime import datetime
        print(f"  expires:  {datetime.fromtimestamp(expire).strftime('%Y-%m-%d')}")
    if machines:
        print(f"  machines: {', '.join(machines)}")
    return 0


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
        p.add_argument("--exclude", action="append", default=SUPPRESS, metavar="PATTERN",
                       help="extra dir name / glob to skip when obfuscating a tree "
                            "(repeatable; .venv, build, dist, .git, __pycache__ are "
                            "always skipped)")
        # --- runtime protection (PyArmor-style) ---
        g = p.add_argument_group("protection")
        g.add_argument("--expire", default=SUPPRESS, metavar="YYYY-MM-DD",
                       help="refuse to run after this date")
        g.add_argument("--anti-debug", action="store_true", default=SUPPRESS,
                       help="abort if a debugger/tracer is detected")
        g.add_argument("--bind-machine", action="store_true", default=SUPPRESS,
                       help="bind to THIS machine's id")
        g.add_argument("--allow-machine", action="append", default=SUPPRESS,
                       metavar="ID", help="allow a specific machine id (repeatable)")
        g.add_argument("--require-license", action="store_true", default=SUPPRESS,
                       help="require a valid signed license file at runtime")
        g.add_argument("--license-name", default=SUPPRESS,
                       help=f"license filename to look for (default: {DEFAULT_LICENSE_NAME})")

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

    # machine-id
    p_mid = sub.add_parser("machine-id", help="print this machine's binding id")
    p_mid.set_defaults(func=_cmd_machine_id)

    # license
    p_lic = sub.add_parser("license", help="issue a signed license file")
    src = p_lic.add_mutually_exclusive_group(required=True)
    src.add_argument("--runtime", help="path to a generated runtime package (reads its key)")
    src.add_argument("--key", help="build key as a base85 string")
    p_lic.add_argument("--expire", metavar="YYYY-MM-DD", help="license expiry date")
    p_lic.add_argument("--bind-machine", action="store_true",
                       help="bind the license to THIS machine")
    p_lic.add_argument("--allow-machine", action="append", metavar="ID",
                       help="allow a specific machine id (repeatable)")
    p_lic.add_argument("--note", default="", help="free-text note stored in the license")
    p_lic.add_argument("-o", "--output", help=f"output file (default: {DEFAULT_LICENSE_NAME})")
    p_lic.set_defaults(func=_cmd_license)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
