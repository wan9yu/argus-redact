"""Architectural guard: src/argus_redact/pure/ must not import I/O or higher layers.

This is the codified contract from docs/architecture.md's Purity Architecture
section: "pure" means no filesystem, network, subprocess, or higher-layer
(glue/impure/integrations) access, and output depending only on arguments —
not the absence of all effects. Two effects are explicitly permitted because
they are the primitive's documented advisory contract and mutate no external
state: (1) diagnostic emission via ``warnings.warn`` and the ``logging``
module (PII-free, reason-codes only); (2) syscall-free stdlib introspection
to attribute those diagnostics — ``os.path`` string helpers (``dirname``/
``normpath``/``sep``, which never touch the filesystem) and ``sys._getframe``.
Filesystem-touching os calls (``realpath``/``abspath``/``stat``/``getcwd``/
``open``/``listdir``/…), ``os.environ``/``os.getenv``, pathlib filesystem
methods, ``io``/``socket``/``subprocess``, and all network clients remain
forbidden. The Layer 1 frozen-at-1.0 promise depends on this.

Mechanism: AST-walk every .py under pure/, collect import targets, fail if
any matches the forbidden set below; separately, AST-walk every ``ast.Call``
and flag fully-qualified call targets in the forbidden call-target set (this
catches filesystem/env syscalls even when ``import os`` is legitimately
present for syscall-free string ops like ``os.path.dirname``).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_PURE_DIR = Path(__file__).parents[2] / "src" / "argus_redact" / "pure"

_FORBIDDEN = frozenset(
    {
        # Higher layers in argus-redact's own taxonomy
        "argus_redact.glue",
        "argus_redact.impure",
        "argus_redact.integrations",
        # Filesystem I/O — the pure layer takes in-memory data only; any
        # path → bytes/text load belongs in glue. _safe_io is the project's
        # filesystem helper, so importing it from pure/ is itself a violation.
        "argus_redact._safe_io",
        "pathlib",
        "io",
        "tempfile",
        "shutil",
        "glob",
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
    }
)

# Fully-qualified call targets that perform filesystem/env syscalls. These are
# banned even when `import os` is legitimately present in a pure/ file for
# syscall-free string ops (os.path.dirname, os.path.normpath, os.sep) — the
# import denylist above can't catch a forbidden *call* through an allowed
# import, so this is a separate, complementary check.
_FORBIDDEN_CALL_TARGETS = frozenset(
    {
        "open",
        "os.stat",
        "os.lstat",
        "os.getcwd",
        "os.listdir",
        "os.scandir",
        "os.walk",
        "os.remove",
        "os.unlink",
        "os.mkdir",
        "os.makedirs",
        "os.rmdir",
        "os.rename",
        "os.replace",
        "os.symlink",
        "os.link",
        "os.readlink",
        "os.chmod",
        "os.chown",
        "os.getenv",
        "os.putenv",
        "os.system",
        "os.popen",
        "os.path.realpath",
        "os.path.abspath",
        "os.path.exists",
        "os.path.isfile",
        "os.path.isdir",
        "os.path.getsize",
        "os.path.getmtime",
    }
)


def _dotted_name(node: ast.expr) -> str | None:
    """Resolve an ``ast.Attribute``/``ast.Name`` chain to a dotted string.

    Returns ``None`` for anything that isn't a plain dotted-name expression
    (e.g. a call result or subscript in the middle of the chain) — such
    expressions can't match a fully-qualified target in
    ``_FORBIDDEN_CALL_TARGETS`` anyway.
    """
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    else:
        return None
    return ".".join(reversed(parts))


def _forbidden_calls(tree: ast.AST) -> set[str]:
    bad: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target = _dotted_name(node.func)
            if target in _FORBIDDEN_CALL_TARGETS:
                bad.add(target)
        elif isinstance(node, ast.Attribute):
            # os.environ is accessed as an attribute (e.g. os.environ["X"]
            # or os.environ.get(...)), not called directly — a call-target
            # check alone would miss it.
            dotted = _dotted_name(node)
            if dotted == "os.environ":
                bad.add(dotted)
    return bad


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
def test_pure_file_should_have_no_forbidden_imports(py_path: Path):
    tree = ast.parse(py_path.read_text(encoding="utf-8"))
    bad = _violations(_imported_modules(tree))
    assert not bad, (
        f"\n{py_path.relative_to(_PURE_DIR)} imports forbidden modules:\n  "
        + "\n  ".join(sorted(bad))
        + "\n\nLayer 1 (primitive) must stay free of network / subprocess / "
        "higher-layer imports. See docs/architecture-layers.md §Layer 1."
    )


@pytest.mark.parametrize(
    "py_path",
    sorted(_PURE_DIR.rglob("*.py")),
    ids=lambda p: str(p.relative_to(_PURE_DIR)),
)
def test_pure_file_should_have_no_forbidden_calls(py_path: Path):
    tree = ast.parse(py_path.read_text(encoding="utf-8"))
    bad = _forbidden_calls(tree)

    assert not bad, (
        f"\n{py_path.relative_to(_PURE_DIR)} calls forbidden filesystem/env "
        "targets:\n  "
        + "\n  ".join(sorted(bad))
        + "\n\nLayer 1 (primitive) may use os.path string helpers (dirname/"
        "normpath/sep) but must never touch the filesystem or environment. "
        "See docs/architecture.md's Purity Architecture section."
    )


def test_pure_dir_should_have_python_files():
    """Meta guard against silent zero-collection."""
    files = list(_PURE_DIR.rglob("*.py"))
    assert len(files) >= 5, f"Expected ≥5 .py files in pure/, found {len(files)}"
