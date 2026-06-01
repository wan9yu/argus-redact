"""Architectural guard: src/argus_redact/pure/ must not import I/O or higher layers.

This is the codified contract from docs/architecture-layers.md §Layer 1:
the primitive is **pure** — deterministic transforms only, no network, no
filesystem, no LLM calls, no glue/impure layer imports. The Layer 1 frozen-
at-1.0 promise depends on this.

Mechanism: AST-walk every .py under pure/, collect import targets, fail if
any matches the forbidden set below.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

_PURE_DIR = Path(__file__).parents[2] / "src" / "argus_redact" / "pure"

_FORBIDDEN = frozenset({
    # Higher layers in argus-redact's own taxonomy
    "argus_redact.glue",
    "argus_redact.impure",
    "argus_redact.integrations",
    # Network I/O
    "httpx",
    "requests",
    "urllib.request",
    "urllib3",
    "http.client",
    "socket",
    # Process / subprocess
    "subprocess",
    # LLM clients
    "ollama",
    "anthropic",
    "openai",
})


def _imported_modules(tree: ast.AST) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                out.add(n.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                out.add(node.module)
    return out


def _violations(modules: set[str]) -> set[str]:
    bad: set[str] = set()
    for m in modules:
        for f in _FORBIDDEN:
            if m == f or m.startswith(f + "."):
                bad.add(m)
    return bad


@pytest.mark.parametrize(
    "py_path",
    sorted(_PURE_DIR.rglob("*.py")),
    ids=lambda p: str(p.relative_to(_PURE_DIR)),
)
def test_pure_file_has_no_forbidden_imports(py_path: Path):
    tree = ast.parse(py_path.read_text(encoding="utf-8"))
    bad = _violations(_imported_modules(tree))
    assert not bad, (
        f"\n{py_path.relative_to(_PURE_DIR)} imports forbidden modules:\n  "
        + "\n  ".join(sorted(bad))
        + "\n\nLayer 1 (primitive) must stay free of network / subprocess / "
        "higher-layer imports. See docs/architecture-layers.md §Layer 1."
    )


def test_pure_dir_actually_has_python_files():
    """Meta guard against silent zero-collection."""
    files = list(_PURE_DIR.rglob("*.py"))
    assert len(files) >= 5, f"Expected ≥5 .py files in pure/, found {len(files)}"
