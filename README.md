# tungtungarmor

A lightweight, **pure-Python source obfuscator** for Python scripts — a small,
open-source, dependency-free alternative to [PyArmor](https://github.com/dashingsoft/pyarmor),
with first-class **PyInstaller** integration.

It compiles your code to bytecode, encrypts it, and ships it with a tiny
self-contained runtime that decrypts and runs it on the fly. The distributed
files contain **no readable source and no plaintext string literals** — just an
encrypted, marshalled blob.

```text
your .py  ──►  AST transforms  ──►  compile to bytecode  ──►  marshal
          ──►  encrypt (SHA-256 CTR + HMAC)  ──►  bootstrap loader + runtime
```

## Features

- 🔒 **Encrypted bytecode** — source is compiled, marshalled and encrypted with
  an authenticated stream cipher (SHA-256 keystream + HMAC-SHA256).
- 🧵 **String-literal encryption** — every `str`/`bytes` literal is encrypted and
  decrypted lazily at runtime (and **memoised**), so secrets/tokens don't survive
  even in a decompiled view of the bytecode. **f-string** constant fragments are
  encrypted too.
- 🔑 **Key-derivation mode** (optional) — instead of shipping the key, derive it
  at runtime from a secret supplied through the environment (PBKDF2). The key
  **never** lands in the artifact, turning obfuscation into real encryption for
  server-side / password-gated code.
- 🧽 **Stripped bytecode** — the developer's absolute source paths are removed
  from every code object (`co_filename`), and separate HKDF sub-keys are used for
  the cipher and the MAC.
- 🩹 **Self-integrity check** — the runtime verifies its own crypto/loader files
  weren't patched (best-effort; strongest in key-derivation mode).
- 🔁 **Round-trip deobfuscator** — recover the code object from *your own*
  protected files for debugging (`tungtungarmor deobfuscate`).
- 🪪 **Local & global renaming** (optional, experimental) — rename function
  parameters/locals, and private module-level names (`_helper`), to opaque
  names; skips unsafe functions/modules
  (`eval`/`exec`/`locals()`/`globals()`/`global`/`nonlocal`) to stay correct.
- 📦 **Whole-project packing** — obfuscate a single file or an entire package
  tree, preserving layout and copying data files.
- 🏗️ **PyInstaller integration** — obfuscate *and* build a standalone executable
  in one command. The runtime is bundled automatically.
- 🛡️ **Runtime protection** — expiry dates, machine binding, anti-debug checks
  and signed external **license files** you can re-issue without rebuilding.
- 🐍 **Pure Python, zero runtime dependencies** — the generated runtime only uses
  the standard library, so protected programs run anywhere.

## Install

```bash
pip install -e .            # from this repo
# optional, for the build command:
pip install pyinstaller
```

This installs two console commands: `tungtungarmor` and the short alias `tta`.

## Usage

### Obfuscate a single file

```bash
tungtungarmor obfuscate myscript.py -o dist_protected
python dist_protected/myscript.py        # runs exactly like the original
```

### Obfuscate a whole project

```bash
tungtungarmor obfuscate ./myproject -o dist_protected
```

The output mirrors your project layout and adds a `tungtungarmor_runtime/`
package. Ship the whole `dist_protected/` folder.

### Build a standalone executable (PyInstaller)

```bash
tungtungarmor pyinstaller app.py --name myapp
./dist/myapp                              # single self-contained binary
```

Useful flags:

```bash
tungtungarmor pyinstaller app.py \
    --project-root ./src \      # obfuscate this whole tree, entry = app.py
    --name myapp \
    --onedir \                  # one-folder bundle (default is one-file)
    --windowed \                # GUI app, no console window
    --spec-only \               # just write a .spec, don't build
    --pyinstaller-args --add-data assets:assets --icon app.ico
```

### Passing PyInstaller options (PyArmor `pyi_options` style)

If you're migrating from PyArmor's
`pyarmor cfg pack:pyi_options="..."`, use `--pyi-options` with the **same single
quoted string** — every flag is forwarded verbatim to PyInstaller:

```bash
tungtungarmor pyinstaller main.py --onedir \
  --pyi-options "-w -i assets/icons/app.ico --name \"My App\" \
    --hidden-import api_server --collect-data pandas \
    --add-data assets;assets --add-data templates;templates \
    --copy-metadata numpy --copy-metadata fastapi --noupx"
```

This covers `--hidden-import`, `--add-data`, `--collect-data`, `--copy-metadata`,
`-w`/`-i`/`--name`, `--noupx`, etc. — anything PyInstaller accepts.

You can also append flags as a raw token list after `--pyinstaller-args`
(must come last). Both sources are merged.

**No duplicate flags:** tungtungarmor injects its own `--name`,
`--onefile`/`--onedir` and `--console`/`--windowed` defaults *only if you didn't
supply them*. Whatever you pass wins, and the runtime hidden-import is always
added for you — so you don't need PyArmor's `--hidden-import pyarmor_runtime_xxx`
line.

> Note: data separators differ per OS — `assets;assets` on Windows,
> `assets:assets` on Linux/macOS (same as PyInstaller itself).

### Follow imports (obfuscate only your project, like PyArmor)

**This is the default.** Whenever an entry script is known (the `pyinstaller`
command, or `obfuscate` pointed at a file), tungtungarmor starts at the entry
and follows imports, obfuscating **only modules that belong to your project** —
standard-library and third-party packages are ignored. No config needed.

```bash
tungtungarmor pyinstaller app.py          # follows imports automatically
tungtungarmor obfuscate main.py -o out    # ditto

# Opt out and obfuscate the whole tree instead (honours --exclude):
tungtungarmor obfuscate ./proj --no-follow-imports -o out
```

> `obfuscate` on a **directory** still defaults to whole-tree mode (there's no
> single entry to follow). Point it at the entry file to get import-following.

Benefits:

- No need to exclude `.venv`, `debug/`, vendored copies, etc. — they're simply
  never reached.
- **Auto hidden-imports.** Because the obfuscated source is encrypted,
  PyInstaller can't see any `import` inside it. tungtungarmor therefore feeds
  PyInstaller the **exact** modules your source imports — your own modules
  **and** the specific third-party modules/submodules it finds, e.g.
  `moviepy.editor` or `selenium.webdriver.support.expected_conditions`.
  Standard-library imports are filtered out. This is precise (only what the
  code imports), so it won't drag in a package's broken optional submodules the
  way a blanket `--collect-submodules` can.
- You may see PyInstaller log `hidden import "x.y" not found` for a
  `from pkg import SomeClass` line (it's a class, not a module) — that's
  harmless.
- You only need to list, in `hidden_imports`, third-party modules imported
  *dynamically inside the library itself* (e.g. `uvicorn.loops.auto`), since
  those never appear in your source. For libraries that need their whole
  subtree (data + all submodules), use `collect_all = ["pkg"]` /
  `collect_submodules = ["pkg"]` in the config.
- For imports the scanner can't see statically (dynamic `importlib`, plugins),
  force them in with `--include modulename` / `--include "plugins/*.py"` (or
  `include = [...]` in the config).

### Config file (recommended for big projects)

Long `--hidden-import` / `--add-data` / `--copy-metadata` lists belong in a
config file, not on one giant command line. Drop a `tungtungarmor.toml` (or
`tungtungarmor.json`) in your project — it's auto-detected — then just run:

```bash
tungtungarmor pyinstaller        # entry, options, everything read from config
```

```toml
# tungtungarmor.toml
output = "dist_protected"
optimize = 2

[pyinstaller]
entry = "main.py"
project_root = "."
name = "TungTung Poster"
onedir = true            # false => one-file
windowed = true          # true  => no console window
icon = "assets/icons/app.ico"
noupx = true
hidden_imports = ["api_server", "adbutils", "fastapi", "uvicorn"]
collect_data = ["pandas", "uiautomator2"]
collect_submodules = ["uvicorn"]
copy_metadata = ["numpy", "fastapi", "uvicorn"]
add_data = ["assets;assets", "templates;templates"]   # use ':' on Linux/macOS
pyi_options = ""         # any extra raw flags, PyArmor style
extra_args = []          # already-tokenised extra flags
```

A full annotated example is in [`examples/tungtungarmor.toml`](examples/tungtungarmor.toml).

Precedence is **explicit CLI flag > config value > built-in default**, so you
can keep a config and still override per-run, e.g.:

```bash
tungtungarmor pyinstaller --config build/prod.toml --name "Prod Build"
```

> TOML needs Python 3.11+ (or `pip install tomli`). A `.json` config works on
> any version.

### Obfuscation options (both commands)

| Flag | Meaning |
|------|---------|
| `--no-encrypt-strings` | Disable string-literal encryption |
| `--rename-locals` | Rename local variables (experimental) |
| `--rename-globals` | Rename private module-level names, e.g. `_helper` (experimental) |
| `--no-strip-bytecode` | Keep the original source path in the bytecode (stripped by default) |
| `--min-string-length N` | Only encrypt strings of length ≥ N (default 2) |
| `--optimize {0,1,2}` | `compile()` level (2 strips asserts + docstrings) |
| `--runtime-pkg NAME` | Rename the generated runtime package |
| `--kdf pbkdf2` | Derive the key at runtime from a secret instead of shipping it |
| `--secret-env NAME` | Env var holding the build secret / read at runtime (default `TTA_SECRET`) |
| `--password` | Prompt for the build secret instead of reading it from the environment |
| `--kdf-iters N` | PBKDF2 iterations (default 200000) |
| `--follow-imports` | (default w/ an entry) obfuscate only modules reachable from the entry |
| `--no-follow-imports` | Obfuscate the whole tree instead (honours `--exclude`) |
| `--include MODULE` | Force-include a module/glob the scanner can't see (dynamic imports) |
| `--exclude PATTERN` | Extra dir/glob to skip (`.venv`, `build`, `dist`, `.git`, `__pycache__` already skipped) |
| `--config FILE` | Load options from a TOML/JSON config file |
| `--show-key` | (`obfuscate`) print the generated key |

## Compile with Nuitka instead of PyInstaller

```bash
tungtungarmor nuitka app.py --name myapp            # standalone folder
tungtungarmor nuitka app.py --onefile --windowed    # single-file GUI binary
tungtungarmor nuitka                                 # all options from config
```

The usual problem with "obfuscate then Nuitka" is that Nuitka follows imports to
decide what to compile, but the obfuscated source hides its imports inside
encrypted blobs — so most dependencies get dropped. tungtungarmor already
discovered every import while scanning, so it passes Nuitka explicit
`--include-module` (your modules) and `--include-package` (third-party
packages) flags. Nothing is invisible, and `--collect`/hidden-import guesswork
isn't needed.

Config lives in a `[nuitka]` section (see the example file): `entry`,
`project_root`, `name`, `onefile`, `windowed`, `icon`, `output_dir`,
`data_dirs`, `data_files`, `plugins`, `include_packages`, `extra_args`. The
`tk-inter` plugin is auto-enabled when a Tk GUI is detected.

> **Important caveats.** Your own modules run as encrypted bytecode through the
> runtime's `exec` — Nuitka does **not** compile them to C (they stay protected
> by tungtungarmor's encryption); Nuitka compiles the bootstrap, the runtime and
> the *dependencies*. For heavy scientific stacks (numpy/pandas/scipy/...)
> compiling those dependencies can be very slow or hit library-specific issues —
> for such apps PyInstaller is usually the pragmatic choice. tungtungarmor makes
> the build *correct*; it can't make Nuitka fast on a huge dependency tree.

## Runtime protection (PyArmor-style)

Add license-style guards that run *before* your code does. They work with both
`obfuscate` and `pyinstaller`, and can also be set in the config `[protection]`
section.

| Flag | Effect |
|------|--------|
| `--expire YYYY-MM-DD` | Refuse to run after this date |
| `--anti-debug` | Abort if a debugger/tracer is detected (`sys.gettrace`, `pydevd`/`pdb`/`bdb`, Linux `TracerPid`); re-checked on every module load |
| `--bind-machine` | Bind to the **build** machine's id |
| `--allow-machine ID` | Allow a specific machine id (repeatable) |
| `--require-license` | Require a valid signed license file at runtime |
| `--license-name NAME` | License filename to look for (default `tungtungarmor.lic`) |

```bash
# Expire + machine lock baked into the build:
tungtungarmor obfuscate app.py -o dist_protected \
    --expire 2026-12-31 --anti-debug --allow-machine <id>
```

### Machine ids

On the *target* machine, get its id:

```bash
tungtungarmor machine-id        # -> 7f5d3e16f5cf0e296c3185a759bd8f02
```

Then bind the build to it with `--allow-machine <id>` (repeat for several
machines). The id is derived from OS + hostname + MAC address.

### Floating licenses (issue without rebuilding)

With `--require-license`, the program loads a **signed license file** at startup
instead of having limits baked in — so you can issue new licenses (extend
expiry, add machines) **without rebuilding**:

```bash
# 1) build once, requiring a license
tungtungarmor pyinstaller app.py --name myapp --require-license

# 2) issue a license signed with that build's key (read from the runtime)
tungtungarmor license --runtime build/tungtungarmor_obf/tungtungarmor_runtime \
    --expire 2026-12-31 --bind-machine -o tungtungarmor.lic
```

At runtime the license is looked up via the `TTA_LICENSE` env var, then next to
the executable, then the current directory. Licenses are HMAC-SHA256 signed with
the per-build key, so they can't be forged or edited without it.

## Key-derivation mode (don't ship the key)

By default the per-build key ships inside `_key.py` — the honest ceiling of any
pure-Python obfuscator. In **key-derivation mode** the key is **not** stored at
all; only a salt + iteration count are. At runtime the key is re-derived with
PBKDF2 from a secret you supply through the environment, so the program only
runs for someone who knows that secret:

```bash
# build: read the secret from $TTA_SECRET (never written to the artifact)
TTA_SECRET='correct horse battery staple' \
  tungtungarmor obfuscate app.py -o dist_protected --kdf pbkdf2

# run: the same secret must be present in the environment
TTA_SECRET='correct horse battery staple' python dist_protected/app.py
# without it:  "tungtungarmor: secret not provided; set the TTA_SECRET ..."
```

Use `--secret-env NAME` to read/inject a different variable name, `--password`
to be prompted at build time instead of using the environment, and
`--kdf-iters N` to tune the PBKDF2 work factor. This is the mode to reach for
when you need *real* encryption (server-side code, password-gated tools), not
just deterrence.

## Deobfuscate your own files (round-trip / debugging)

You can reverse tungtungarmor's own format on code **you** protected — handy for
debugging or verifying a build. It recovers the code object and writes a
standard `.pyc` you can disassemble or feed to a decompiler:

```bash
tungtungarmor deobfuscate dist_protected/app.py \
    --runtime dist_protected/tungtungarmor_runtime \
    -o app.pyc --dis                 # also print a bytecode disassembly

# or provide the key directly, and try a decompiler if one is installed:
tungtungarmor deobfuscate app.py --key <b85> --decompile
```

For a key-derivation-mode build, set the secret's environment variable so the
runtime key can be reproduced. String literals in the recovered code object
remain as `__armor_s__(...)` calls — decrypt them with the same key. This tool
only undoes *your* obfuscation; it is not a generic decompiler.

## Python API

```python
from tungtungarmor import (
    pack, ObfuscateOptions, ProtectionOptions, parse_expire,
    recover_code_file, new_key,
)

pack(
    "myproject",
    "dist_protected",
    ObfuscateOptions(
        encrypt_strings=True,
        rename_locals=True,
        rename_globals=True,     # experimental
        strip_bytecode=True,     # default: strip source paths from bytecode
        optimize=2,
        # key-derivation mode (key not shipped):
        kdf="pbkdf2", kdf_secret="…from your env…",
    ),
    protection=ProtectionOptions(
        expire=parse_expire("2026-12-31"),
        anti_debug=True,
    ),
)
```

## How it works

1. **AST passes** (`transformer.py`) rewrite string literals (including f-string
   fragments) into runtime decryption calls and optionally rename locals/globals.
2. The transformed AST is **compiled** to a code object, **stripped** of embedded
   source paths, and **marshalled**.
3. The bytes are **encrypted** (`crypto.py`) with a per-build key (random, or —
   in key-derivation mode — derived from an environment secret via PBKDF2), using
   HKDF-separated sub-keys for the cipher and the MAC.
4. Each source file is replaced by a small **bootstrap** that checks the Python
   version, base85-decodes the blob and hands it to the runtime's
   `__armor_exec__`, which decrypts, unmarshals and `exec`s it into the module's
   namespace.
5. The **runtime package** (`runtime_template.py`) is generated alongside,
   carrying a self-contained decryptor, the guard (anti-debug / expiry /
   machine / license / self-integrity) and either the key or its derivation
   parameters — no dependency on tungtungarmor at run time.

## Limitations & honest disclaimer

- In the **default** mode — like **every** pure-Python obfuscator (PyArmor's
  pure-python mode included) — the decryption key ultimately ships inside the
  program, and the loader is pure Python, so a determined, skilled attacker can
  recover the bytecode. The goal is to **raise the bar substantially**, not to
  provide unbreakable DRM.
- **Key-derivation mode** (`--kdf pbkdf2`) removes the shipped key: the artifact
  can't be decrypted without the runtime secret, and the self-integrity check
  meaningfully resists loader patching there. This is the strongest mode
  available today. A **compiled (C-extension) runtime** — which would also hide
  the *decryptor* itself, PyArmor-style — is a planned follow-up; it needs a
  build toolchain and per-platform artifacts, so it is intentionally **not**
  bundled yet.
- The runtime guards (anti-debug, expiry, machine/license checks) are strong
  **deterrents**. In default mode a skilled attacker can patch them out; in
  key-derivation mode they are meaningfully harder to bypass. They stop casual
  sharing and enforce honest licensing, not a motivated cracker.
- Machine ids are derived from OS + hostname + MAC; they can change (new NIC,
  VM cloning) — keep a way to re-issue licenses.
- Marshalled bytecode is tied to the Python **minor version** used to obfuscate;
  the bootstrap now **enforces** this and refuses to run on a mismatched
  interpreter. Build with the same Python version you ship/run with.
- `--rename-locals` / `--rename-globals` are conservative but experimental; test
  your app after enabling them. Global renaming only touches *private*
  module-level names and bails on dynamic namespace use, but code that reaches a
  private name by string (e.g. `getattr`) across modules can still break.
- This is a defensive IP-protection / anti-casual-copying tool. Use it only on
  code you own or are authorized to protect.

## Development

```bash
pip install pytest
python -m pytest tests/ -q
```

## License

MIT — see [LICENSE](LICENSE).
