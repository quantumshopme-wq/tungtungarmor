"""Command-line interface for tungtungarmor."""

from __future__ import annotations

import argparse
import os
import shlex
import sys
from pathlib import Path

from . import __version__
from .config import assemble_pyi_flags, find_default_config, load_config
from .crypto import DEFAULT_KDF_ITERS
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

    if hasattr(args, "no_strip_bytecode"):
        strip_bytecode = not getattr(args, "no_strip_bytecode")
    else:
        strip_bytecode = bool(cfg.get("strip_bytecode", True))

    kdf = _resolve(args, "kdf", cfg, "kdf", None) or None
    secret_env = _resolve(args, "secret_env", cfg, "kdf_secret_env", "TTA_SECRET")
    kdf_secret = None
    if kdf:
        if kdf not in ("pbkdf2",):
            print(f"error: unknown --kdf mode: {kdf!r} (supported: pbkdf2)", file=sys.stderr)
            raise SystemExit(2)
        if getattr(args, "password", False):
            import getpass
            kdf_secret = getpass.getpass("tungtungarmor build secret: ")
        else:
            kdf_secret = os.environ.get(secret_env)
        if not kdf_secret:
            print(f"error: --kdf needs a build secret; set ${secret_env} "
                  f"(or pass --password to be prompted)", file=sys.stderr)
            raise SystemExit(2)

    return ObfuscateOptions(
        encrypt_strings=encrypt_strings,
        rename_locals=_resolve(args, "rename_locals", cfg, "rename_locals", False),
        rename_globals=_resolve(args, "rename_globals", cfg, "rename_globals", False),
        min_string_length=_resolve(args, "min_string_length", cfg, "min_string_length", 2),
        optimize=_resolve(args, "optimize", cfg, "optimize", 0),
        strip_bytecode=strip_bytecode,
        runtime_pkg=_resolve(args, "runtime_pkg", cfg, "runtime_pkg", DEFAULT_RUNTIME_PKG),
        kdf=kdf,
        kdf_secret=kdf_secret,
        kdf_secret_env=secret_env,
        kdf_iters=int(_resolve(args, "kdf_iters", cfg, "kdf_iters", DEFAULT_KDF_ITERS)),
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


def _include_list(args, cfg):
    includes = list(cfg.get("include", []) or [])
    if getattr(args, "include", None):
        includes.extend(args.include)
    return includes or None


def _follow_enabled(args, cfg, default):
    """Effective follow-imports setting: --no-follow-imports > --follow-imports
    > config > *default*."""
    if getattr(args, "no_follow_imports", False):
        return False
    if getattr(args, "follow_imports", False):
        return True
    if "follow_imports" in cfg:
        return bool(cfg["follow_imports"])
    return default


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

    only_files = None
    pack_target = target
    # Default to follow-imports when the target is a single entry script.
    if _follow_enabled(args, cfg, default=target.is_file()):
        if not target.is_file():
            print("error: follow-imports needs an entry script as target "
                  "(point it at e.g. main.py, or pass --no-follow-imports)",
                  file=sys.stderr)
            return 2
        from .scanner import discover
        root = Path(cfg.get("project_root") or target.parent).resolve()
        files, _ = discover(target.resolve(), root, _include_list(args, cfg),
                            on_warn=lambda m: print("tungtungarmor: warn:", m))
        print(f"tungtungarmor: scanned imports from {target.name} -> {len(files)} file(s)")
        only_files = sorted(files)
        pack_target = root

    result = pack(pack_target, Path(output), options, protection=protection,
                  exclude=exclude, only_files=only_files)
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
            follow_imports=_follow_enabled(args, cfg, default=True),
            include=_include_list(args, cfg),
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


def _cmd_nuitka(args) -> int:
    from .nuitka_integration import build as nuitka_build

    cfg = _load_cfg(args)
    nk = cfg.get("nuitka", {})

    entry = getattr(args, "entry", None) or nk.get("entry") or cfg.get("pyinstaller", {}).get("entry")
    if not entry:
        print("error: no entry script given (pass one on the CLI or set "
              "[nuitka] entry in the config)", file=sys.stderr)
        return 2
    entry = Path(entry)
    if not entry.exists():
        print(f"error: entry not found: {entry}", file=sys.stderr)
        return 2

    options = _build_options(args, cfg)
    protection = _build_protection(args, cfg)
    name = _resolve(args, "name", nk, "name", None)
    onefile = _resolve(args, "onefile", nk, "onefile", False)
    windowed = _resolve(args, "windowed", nk, "windowed", False)
    project_root = _resolve(args, "project_root", nk, "project_root", None)

    extra = list(nk.get("extra_args", []) or [])
    icon = nk.get("icon")
    if icon:
        extra.append(f"--windows-icon-from-ico={icon}")
    if getattr(args, "nuitka_args", None):
        extra.extend(args.nuitka_args)

    try:
        rc = nuitka_build(
            entry,
            project_root=Path(project_root) if project_root else None,
            output_dir=Path(nk.get("output_dir", "dist")),
            name=name,
            onefile=onefile,
            console=not windowed,
            options=options,
            protection=protection,
            include=_include_list(args, cfg),
            data_dirs=list(nk.get("data_dirs", []) or []),
            data_files=list(nk.get("data_files", []) or []),
            plugins=list(nk.get("plugins", []) or []),
            include_packages=list(nk.get("include_packages", []) or []),
            extra_args=extra or None,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if rc == 0:
        print("tungtungarmor: nuitka build finished -> see dist/")
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


def _cmd_deobfuscate(args) -> int:
    import base64

    from .deobfuscator import (
        DeobfuscateError,
        disassemble,
        recover_code,
        try_decompile,
        write_pyc,
    )

    target = Path(args.target)
    if not target.is_file():
        print(f"error: not a file: {target}", file=sys.stderr)
        return 2

    if getattr(args, "key", None):
        key = base64.b85decode(args.key)
    else:
        # Reading the key from a KDF-mode runtime needs the secret in the env.
        try:
            key = read_key_from_runtime(Path(args.runtime))
        except SystemExit:
            print("error: this runtime derives its key from a secret; set the "
                  "secret's environment variable and retry", file=sys.stderr)
            return 2
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    try:
        code = recover_code(target.read_text(encoding="utf-8"), key)
    except DeobfuscateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    out = Path(getattr(args, "output", None) or target.with_suffix(".pyc").name)
    write_pyc(code, out)
    print(f"tungtungarmor: recovered code object -> {out}")
    print("  (for inspection/disassembly/decompilation; string literals remain "
          "as __armor_s__(...) calls -- decrypt them with the same key)")

    if getattr(args, "decompile", False):
        source = try_decompile(out)
        if source is None:
            print("  (no decompiler found; install 'decompyle3' for source recovery)")
        else:
            src_out = out.with_suffix(".py")
            src_out.write_text(source, encoding="utf-8")
            print(f"  decompiled source -> {src_out}")

    if getattr(args, "dis", False):
        print(disassemble(code))
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
        p.add_argument("--rename-globals", action="store_true", default=SUPPRESS,
                       help="rename private module-level names, e.g. _helper "
                            "(experimental, single-module scope)")
        p.add_argument("--no-strip-bytecode", action="store_true", default=SUPPRESS,
                       help="keep the original source path in the bytecode "
                            "(by default it is stripped)")
        p.add_argument("--min-string-length", type=int, default=SUPPRESS,
                       help="only encrypt string literals of at least this length")
        # --- key-derivation mode (key is NOT shipped) ---
        k = p.add_argument_group("key derivation")
        k.add_argument("--kdf", default=SUPPRESS, metavar="MODE", choices=("pbkdf2",),
                       help="derive the key at runtime from a secret instead of "
                            "shipping it (mode: pbkdf2)")
        k.add_argument("--secret-env", default=SUPPRESS, metavar="NAME",
                       help="env var holding the build secret and read at runtime "
                            "(default: TTA_SECRET)")
        k.add_argument("--password", action="store_true", default=SUPPRESS,
                       help="prompt for the build secret instead of reading it from "
                            "the environment")
        k.add_argument("--kdf-iters", type=int, default=SUPPRESS, metavar="N",
                       help=f"PBKDF2 iterations (default: {DEFAULT_KDF_ITERS})")
        p.add_argument("--optimize", type=int, choices=(0, 1, 2), default=SUPPRESS,
                       help="compile() optimization level (strips asserts/docstrings)")
        p.add_argument("--runtime-pkg", default=SUPPRESS,
                       help="name of the generated runtime package")
        p.add_argument("--exclude", action="append", default=SUPPRESS, metavar="PATTERN",
                       help="extra dir name / glob to skip when obfuscating a tree "
                            "(repeatable; .venv, build, dist, .git, __pycache__ are "
                            "always skipped)")
        p.add_argument("--follow-imports", action="store_true", default=SUPPRESS,
                       help="(default) obfuscate only modules reachable from the "
                            "entry by following imports, PyArmor-style")
        p.add_argument("--no-follow-imports", action="store_true", default=SUPPRESS,
                       help="disable import-following; obfuscate the whole tree "
                            "(honours --exclude)")
        p.add_argument("--include", action="append", default=SUPPRESS, metavar="MODULE",
                       help="force-include a module/glob the scanner can't see, e.g. "
                            "dynamic imports (repeatable)")
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

    # deobfuscate (round-trip your own protected files, for debugging)
    p_deob = sub.add_parser(
        "deobfuscate",
        help="recover the code object from YOUR OWN protected file (debug/round-trip)",
    )
    p_deob.add_argument("target", help="a tungtungarmor-protected .py file")
    dsrc = p_deob.add_mutually_exclusive_group(required=True)
    dsrc.add_argument("--runtime", help="path to the generated runtime package (reads its key)")
    dsrc.add_argument("--key", help="build key as a base85 string")
    p_deob.add_argument("-o", "--output", help="write the recovered .pyc here "
                                               "(default: <target>.pyc)")
    p_deob.add_argument("--dis", action="store_true", help="print a bytecode disassembly")
    p_deob.add_argument("--decompile", action="store_true",
                        help="attempt source recovery via decompyle3/uncompyle6 if installed")
    p_deob.set_defaults(func=_cmd_deobfuscate)

    # nuitka
    p_nk = sub.add_parser("nuitka", help="obfuscate then compile with Nuitka")
    p_nk.add_argument("entry", nargs="?", default=SUPPRESS, help="entry-point .py script")
    p_nk.add_argument("--project-root", default=SUPPRESS,
                      help="project root to obfuscate (default: entry's dir)")
    p_nk.add_argument("--name", default=SUPPRESS, help="output binary name (default: entry stem)")
    p_nk.add_argument("--onefile", action="store_true", default=SUPPRESS,
                      help="produce a single-file binary (default: standalone folder)")
    p_nk.add_argument("--windowed", action="store_true", default=SUPPRESS,
                      help="GUI app, no console window")
    p_nk.add_argument("--nuitka-args", nargs=argparse.REMAINDER, default=SUPPRESS,
                      help="pass remaining args straight to Nuitka")
    add_common(p_nk)
    p_nk.set_defaults(func=_cmd_nuitka)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
