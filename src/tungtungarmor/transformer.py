"""Source-level AST obfuscation passes.

These run *before* the code is compiled to bytecode and encrypted.  They
make any eventual decompilation of the marshalled bytecode much harder to
read, even though the encrypted blob is already the primary protection.

Passes
------
* ``StringEncryptor``  -- replaces ``str``/``bytes`` literals with calls to
  a runtime helper (``__armor_s__`` / __armor_b__``) that decrypts them on
  demand, so no readable literal survives in the bytecode constants.
* ``LocalRenamer``     -- renames function-local variables / parameters to
  opaque names (conservative; skips functions that touch ``locals()``,
  ``eval``/``exec``, ``global``/``nonlocal`` to stay safe).  Off by default.
"""

from __future__ import annotations

import ast
import base64
from typing import Set

from .crypto import encrypt


class StringEncryptor(ast.NodeTransformer):
    """Encrypt ``str`` and ``bytes`` constants in place."""

    def __init__(self, key: bytes, min_length: int = 1):
        self.key = key
        self.min_length = min_length
        self.count = 0
        # Track nodes we must not touch (f-string internals).
        self._skip: Set[int] = set()

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        # f-strings: leave the whole tree alone, transforming the constant
        # fragments inside would change semantics.
        return node

    def _make_call(self, helper: str, raw: bytes) -> ast.Call:
        blob = encrypt(raw, self.key)
        self.count += 1
        return ast.Call(
            func=ast.Name(id=helper, ctx=ast.Load()),
            args=[ast.Constant(value=blob)],
            keywords=[],
        )

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        value = node.value
        if isinstance(value, str) and len(value) >= self.min_length:
            call = self._make_call("__armor_s__", value.encode("utf-8"))
            return ast.copy_location(call, node)
        if isinstance(value, (bytes, bytearray)) and len(value) >= self.min_length:
            call = self._make_call("__armor_b__", bytes(value))
            return ast.copy_location(call, node)
        return node


_UNSAFE_CALLS = {"locals", "vars", "eval", "exec", "globals", "compile"}


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
    min_string_length: int = 1,
    filename: str = "<tungtungarmor>",
) -> ast.Module:
    """Parse *source* and apply the enabled passes; return an AST module."""
    tree = ast.parse(source, filename=filename)
    if rename_locals:
        tree = LocalRenamer().visit(tree)
    if encrypt_strings:
        tree = StringEncryptor(key, min_length=min_string_length).visit(tree)
    ast.fix_missing_locations(tree)
    return tree
