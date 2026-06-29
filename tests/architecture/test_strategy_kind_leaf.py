"""The strategy→reversibility classification lives in a leaf module that
depends on neither ``specs.registry`` nor ``pure.replacer``.

Both modules import it TOP-LEVEL — the old lazy-import workaround that papered
over a registry ↔ replacer import cycle for the classification edge is gone.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

_SRC = Path(__file__).parents[2] / "src"
_LEAF = _SRC / "argus_redact" / "pure" / "_strategy_kind.py"
_REGISTRY = _SRC / "argus_redact" / "specs" / "registry.py"
_REPLACER = _SRC / "argus_redact" / "pure" / "replacer.py"


def _function_local_import_targets(py_path: Path) -> set[str]:
    """Module names imported INSIDE a function/method body (lazy imports)."""
    tree = ast.parse(py_path.read_text(encoding="utf-8"))
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.ImportFrom) and sub.module:
                for n in sub.names:
                    out.add(f"{sub.module}.{n.name}")
            elif isinstance(sub, ast.Import):
                for n in sub.names:
                    out.add(n.name)
    return out


def test_leaf_module_exists():
    assert _LEAF.exists(), f"expected strategy-kind leaf at {_LEAF}"


def test_leaf_imports_neither_registry_nor_replacer():
    tree = ast.parse(_LEAF.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(n.name for n in node.names)
    assert "argus_redact.specs.registry" not in imported
    assert "argus_redact.pure.replacer" not in imported


def test_leaf_has_no_argus_imports():
    """The leaf is dependency-free within the package (only stdlib /
    __future__). This is what lets both registry and replacer import it
    top-level without re-introducing the cycle."""
    tree = ast.parse(_LEAF.read_text(encoding="utf-8"))
    argus_imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.startswith("argus_redact"):
                argus_imports.add(node.module)
        elif isinstance(node, ast.Import):
            argus_imports.update(n.name for n in node.names if n.name.startswith("argus_redact"))
    assert not argus_imports, f"leaf must have no argus imports, found {argus_imports}"


def test_registry_and_replacer_import_cleanly_top_level():
    # Real cycle symptom would be an ImportError when a fresh interpreter
    # imports BOTH modules top-level in either order. Both orders must succeed.
    for first, second in (
        ("argus_redact.specs.registry", "argus_redact.pure.replacer"),
        ("argus_redact.pure.replacer", "argus_redact.specs.registry"),
    ):
        code = (
            f"import importlib; "
            f"a = importlib.import_module('{first}'); "
            f"b = importlib.import_module('{second}'); "
            f"assert a.is_strategy_reversible('pseudonym') is True; "
            f"assert b.is_strategy_reversible('pseudonym') is True; "
            f"assert a.is_strategy_reversible is b.is_strategy_reversible; "
            f"print('ok')"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"{first} then {second}:\n{proc.stderr}"
        assert "ok" in proc.stdout


def test_registry_has_no_lazy_strategy_reversible_import():
    lazy = _function_local_import_targets(_REGISTRY)
    assert "argus_redact.pure.replacer.is_strategy_reversible" not in lazy, (
        "registry must import is_strategy_reversible top-level from the leaf, "
        "not lazily from pure.replacer"
    )


def test_replacer_classification_comes_from_leaf_top_level():
    tree = ast.parse(_REPLACER.read_text(encoding="utf-8"))
    top_level: set[str] = set()
    for node in tree.body:  # module-level statements only
        if isinstance(node, ast.ImportFrom) and node.module:
            for n in node.names:
                top_level.add(f"{node.module}.{n.name}")
    assert "argus_redact.pure._strategy_kind.is_strategy_reversible" in top_level
