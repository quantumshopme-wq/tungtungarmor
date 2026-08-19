"""Source-level AST obfuscation passes.

These run *before* the code is compiled to bytecode and encrypted.  They
make any eventual decompilation of the marshalled bytecode much harder to
read, even though the encrypted blob is already the primary protection.

Passes
------
* ``StringEncryptor``  -- replaces ``str``/``bytes`` literals with calls to
  a runtime helper (``__armor_s__`` / ``__armor_b__``) that decrypts them on
  demand, so no readable literal survives in the bytecode constants.  Constant
  fragments of **f-strings** are encrypted too (the f-string is rebuilt from
  encrypted parts + a shadow-proof ``__armor_fmt__`` helper).
* ``GlobalRenamer``    -- renames *private* module-level names (functions,
  classes, assignments starting with a single underscore) to opaque names.
  Conservative: skips whole modules that touch ``globals()``/``eval``/... or a
  non-literal ``__all__``.  Off by default (experimental, single-module scope).
* ``LocalRenamer``     -- renames function-local variables / parameters to
  opaque names (conservative; skips functions that touch ``locals()``,
  ``eval``/``exec``, ``global``/``nonlocal`` to stay safe).  Off by default.
"""

from __future__ import annotations

import ast
from typing import Dict, Set

from .crypto import encrypt


def _name(id_: str) -> ast.Name:
    return ast.Name(id=id_, ctx=ast.Load())


def _call(func: str, args) -> ast.Call:
    return ast.Call(func=_name(func), args=list(args), keywords=[])


class _FStringUnsupported(Exception):
    """Raised to bail out of f-string transformation and leave it untouched."""


class StringEncryptor(ast.NodeTransformer):
    """Encrypt ``str`` and ``bytes`` constants in place, including f-strings."""

    def __init__(self, key: bytes, min_length: int = 1):
        self.key = key
        self.min_length = min_length
        self.count = 0

    def _make_call(self, helper: str, raw: bytes) -> ast.Call:
        blob = encrypt(raw, self.key)
        self.count += 1
        return ast.Call(
            func=_name(helper),
            args=[ast.Constant(value=blob)],
            keywords=[],
        )

    def _enc_str_expr(self, s: str) -> ast.expr:
        """Expression that yields *s* (encrypted when long enough)."""
        if len(s) >= self.min_length:
            return self._make_call("__armor_s__", s.encode("utf-8"))
        return ast.Constant(value=s)

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        value = node.value
        if isinstance(value, str) and len(value) >= self.min_length:
            call = self._make_call("__armor_s__", value.encode("utf-8"))
            return ast.copy_location(call, node)
        if isinstance(value, (bytes, bytearray)) and len(value) >= self.min_length:
            call = self._make_call("__armor_b__", bytes(value))
            return ast.copy_location(call, node)
        return node

    # -- f-strings ---------------------------------------------------------
    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        try:
            expr = self._fstring_to_expr(node)
        except _FStringUnsupported:
            # Leave the f-string exactly as-is (still correct, just not hidden).
            return node
        ast.copy_location(expr, node)
        ast.fix_missing_locations(expr)
        return expr

    def _fstring_to_expr(self, node: ast.JoinedStr) -> ast.expr:
        """Rebuild an f-string as ``''.join([...])`` with encrypted literals."""
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(self._enc_str_expr(v.value))
            elif isinstance(v, ast.FormattedValue):
                parts.append(self._formatted_value_expr(v))
            else:  # pragma: no cover - unexpected node kind
                raise _FStringUnsupported()
        return ast.Call(
            func=ast.Attribute(value=ast.Constant(value=""), attr="join",
                               ctx=ast.Load()),
            args=[ast.List(elts=parts, ctx=ast.Load())],
            keywords=[],
        )

    def _formatted_value_expr(self, fv: ast.FormattedValue) -> ast.expr:
        # Recurse into the interpolated expression so nested literals are hidden.
        value = self.visit(fv.value)
        conv = {115: "s", 114: "r", 97: "a"}.get(fv.conversion)
        if fv.format_spec is None:
            spec: ast.expr = ast.Constant(value="")
        else:
            spec = self._fstring_to_expr(fv.format_spec)
        # __armor_fmt__(value, conv, spec) -- applies !s/!r/!a then format(),
        # using builtins internally so it can't be broken by shadowing.
        return _call("__armor_fmt__", [value, ast.Constant(value=conv), spec])


# ---------------------------------------------------------------------------
# Global (module-level) renaming -- opt-in, conservative, single-module scope.
# ---------------------------------------------------------------------------
_UNSAFE_CALLS = {"locals", "vars", "eval", "exec", "globals", "compile"}


class _ModuleSafety(ast.NodeVisitor):
    def __init__(self):
        self.safe = True

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in _UNSAFE_CALLS:
            self.safe = False
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if any(a.name == "*" for a in node.names):
            self.safe = False


def _literal_all(node: ast.Module):
    """Return the set of names in a literal ``__all__`` list/tuple, or None.

    Returns ``False`` (sentinel) if ``__all__`` exists but is *not* a simple
    literal of strings -- meaning we can't reason about exports and must bail.
    """
    found = None
    for stmt in node.body:
        if isinstance(stmt, ast.Assign):
            targets = stmt.targets
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            targets = [stmt.target]
        else:
            continue
        if not any(isinstance(t, ast.Name) and t.id == "__all__" for t in targets):
            continue
        value = stmt.value
        if isinstance(value, (ast.List, ast.Tuple)) and all(
            isinstance(e, ast.Constant) and isinstance(e.value, str)
            for e in value.elts
        ):
            found = {e.value for e in value.elts}
        else:
            return False
    return found


class GlobalRenamer(ast.NodeTransformer):
    """Rename private module-level names within a single module."""

    def __init__(self):
        self.counter = 0

    def _new_name(self) -> str:
        self.counter += 1
        return "_G0o%X" % self.counter

    @staticmethod
    def _is_private(name: str) -> bool:
        return name.startswith("_") and not name.startswith("__")

    def visit_Module(self, node: ast.Module) -> ast.AST:
        safety = _ModuleSafety()
        safety.visit(node)
        if not safety.safe:
            return node
        exported = _literal_all(node)
        if exported is False:  # non-literal __all__ -> don't touch anything
            return node
        exported = exported or set()

        targets: Set[str] = set()
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if self._is_private(stmt.name):
                    targets.add(stmt.name)
            elif isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    if isinstance(t, ast.Name) and self._is_private(t.id):
                        targets.add(t.id)
            elif isinstance(stmt, ast.AnnAssign):
                if isinstance(stmt.target, ast.Name) and self._is_private(stmt.target.id):
                    targets.add(stmt.target.id)
        targets -= exported
        if not targets:
            return node

        mapping: Dict[str, str] = {n: self._new_name() for n in sorted(targets)}
        _RenameApplier(mapping).visit(node)
        ast.fix_missing_locations(node)
        return node


class _RenameApplier(ast.NodeVisitor):
    """Apply a name mapping across an entire tree (all scopes)."""

    def __init__(self, mapping: Dict[str, str]):
        self.mapping = mapping

    def visit_Name(self, node):
        if node.id in self.mapping:
            node.id = self.mapping[node.id]

    def _rename_def(self, node):
        if node.name in self.mapping:
            node.name = self.mapping[node.name]
        self.generic_visit(node)

    visit_FunctionDef = _rename_def
    visit_AsyncFunctionDef = _rename_def
    visit_ClassDef = _rename_def

    def visit_Global(self, node):
        node.names = [self.mapping.get(n, n) for n in node.names]


# ---------------------------------------------------------------------------
# Local (function-scope) renaming -- opt-in, conservative.
# ---------------------------------------------------------------------------
class _FunctionSafetyChecker(ast.NodeVisitor):
    """Decide whether a function body is safe to rename locals in."""

    def __init__(self):
        self.safe = True

    def visit_Global(self, node):
        self.safe = False

    def visit_Nonlocal(self, node):
        self.safe = False

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in _UNSAFE_CALLS:
            self.safe = False
        self.generic_visit(node)


class LocalRenamer(ast.NodeTransformer):
    """Rename parameters and locally-assigned names inside safe functions."""

    def __init__(self):
        self.counter = 0

    def _new_name(self) -> str:
        self.counter += 1
        return "_O0o%X" % self.counter

    def _is_safe(self, node) -> bool:
        checker = _FunctionSafetyChecker()
        for child in node.body:
            checker.visit(child)
        return checker.safe

    def _collect_locals(self, node) -> Set[str]:
        names: Set[str] = set()
        # parameters
        a = node.args
        for arg in [*a.posonlyargs, *a.args, *a.kwonlyargs]:
            names.add(arg.arg)
        if a.vararg:
            names.add(a.vararg.arg)
        if a.kwarg:
            names.add(a.kwarg.arg)

        class _Assigned(ast.NodeVisitor):
            def __init__(self, outer):
                self.outer = outer

            def visit_FunctionDef(self, n):
                pass  # don't descend into nested scopes

            visit_AsyncFunctionDef = visit_FunctionDef
            visit_ClassDef = visit_FunctionDef
            visit_Lambda = visit_FunctionDef

            def visit_Name(self, n):
                if isinstance(n.ctx, ast.Store):
                    self.outer.add(n.id)

        collector = _Assigned(names)
        for child in node.body:
            collector.visit(child)
        # never rename dunder / private-by-convention names
        return {n for n in names if not (n.startswith("__") and n.endswith("__"))}

    def _process_function(self, node):
        self.generic_visit(node)  # handle nested functions first
        if not self._is_safe(node):
            return node
        locals_ = self._collect_locals(node)
        if not locals_:
            return node
        mapping = {name: self._new_name() for name in locals_}

        class _Apply(ast.NodeTransformer):
            def visit_FunctionDef(self, n):
                return n  # nested scope already processed independently

            visit_AsyncFunctionDef = visit_FunctionDef
            visit_Lambda = visit_FunctionDef

            def visit_Name(self, n):
                if n.id in mapping:
                    n.id = mapping[n.id]
                return n

            def visit_arg(self, n):
                if n.arg in mapping:
                    n.arg = mapping[n.arg]
                return n

        a = node.args
        for arg in [*a.posonlyargs, *a.args, *a.kwonlyargs]:
            if arg.arg in mapping:
                arg.arg = mapping[arg.arg]
        if a.vararg and a.vararg.arg in mapping:
            a.vararg.arg = mapping[a.vararg.arg]
        if a.kwarg and a.kwarg.arg in mapping:
            a.kwarg.arg = mapping[a.kwarg.arg]
        applier = _Apply()
        node.body = [applier.visit(stmt) for stmt in node.body]
        return node

    def visit_FunctionDef(self, node):
        return self._process_function(node)

    def visit_AsyncFunctionDef(self, node):
        return self._process_function(node)


def transform_source(
    source: str,
    key: bytes,
    *,
    encrypt_strings: bool = True,
    rename_locals: bool = False,
    rename_globals: bool = False,
    min_string_length: int = 1,
    filename: str = "<tungtungarmor>",
) -> ast.Module:
    """Parse *source* and apply the enabled passes; return an AST module."""
    tree = ast.parse(source, filename=filename)
    if rename_globals:
        tree = GlobalRenamer().visit(tree)
    if rename_locals:
        tree = LocalRenamer().visit(tree)
    if encrypt_strings:
        tree = StringEncryptor(key, min_length=min_string_length).visit(tree)
    ast.fix_missing_locations(tree)
    return tree
