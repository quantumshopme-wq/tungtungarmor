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
  decrypted lazily at runtime, so secrets/tokens don't survive even in a
  decompiled view of the bytecode.
- 🪪 **Local-variable renaming** (optional, experimental) — renames function
  parameters and locals to opaque names; skips unsafe functions
  (`eval`/`exec`/`locals()`/`global`/`nonlocal`) to stay correct.
- 📦 **Whole-project packing** — obfuscate a single file or an entire package
  tree, preserving layout and copying data files.
- 🏗️ **PyInstaller integration** — obfuscate *and* build a standalone executable
  in one command. The runtime is bundled automatically.
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

Anything after `--pyinstaller-args` is forwarded verbatim to PyInstaller.

### Obfuscation options (both commands)

| Flag | Meaning |
|------|---------|
| `--no-encrypt-strings` | Disable string-literal encryption |
| `--rename-locals` | Rename local variables (experimental) |
| `--min-string-length N` | Only encrypt strings of length ≥ N |
| `--optimize {0,1,2}` | `compile()` level (2 strips asserts + docstrings) |
| `--runtime-pkg NAME` | Rename the generated runtime package |
| `--show-key` | (`obfuscate`) print the generated key |

## Python API

```python
from tungtungarmor import pack, ObfuscateOptions

pack(
    "myproject",
    "dist_protected",
    ObfuscateOptions(encrypt_strings=True, rename_locals=True, optimize=2),
)
```

## How it works

1. **AST passes** (`transformer.py`) rewrite string literals into runtime
   decryption calls and optionally rename locals.
2. The transformed AST is **compiled** to a code object and **marshalled**.
3. The bytes are **encrypted** (`crypto.py`) with a per-build random key.
4. Each source file is replaced by a small **bootstrap** that base85-decodes the
   blob and hands it to the runtime's `__armor_exec__`, which decrypts,
   unmarshals and `exec`s it into the module's namespace.
5. The **runtime package** (`runtime_template.py`) is generated alongside,
   carrying the key and a self-contained decryptor — no dependency on
   tungtungarmor at run time.

## Limitations & honest disclaimer

- Like **every** pure-Python obfuscator (PyArmor's pure-python mode included),
  the decryption key ultimately ships inside the program. A determined,
  skilled attacker with the runtime can recover the bytecode. The goal is to
  **raise the bar substantially**, not to provide unbreakable DRM.
- Marshalled bytecode is tied to the Python **minor version** used to obfuscate.
  Build with the same Python version you ship/run with.
- `--rename-locals` is conservative but experimental; test your app after
  enabling it.
- This is a defensive IP-protection / anti-casual-copying tool. Use it only on
  code you own or are authorized to protect.

## Development

```bash
pip install pytest
python -m pytest tests/ -q
```

## License

MIT — see [LICENSE](LICENSE).
