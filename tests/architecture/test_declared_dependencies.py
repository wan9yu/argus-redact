"""Every third-party package imported in src/ must be declared in pyproject, or
allowlisted as stdlib / extra-guarded. Prevents the class of clean-install
ImportError bugs (pyyaml, requests) from recurring silently."""
from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

_REPO = Path(__file__).parents[2]
_SRC = _REPO / "src" / "argus_redact"

# Imports that must NOT be in base dependencies: stdlib + extra-guarded optionals
# (each guarded by try/except ImportError or a named extra) + first-party.
_ALLOWLIST = {
    "argus_redact",              # first-party
    "spacy", "hanlp",            # NER extras (zh/en/…)
    "llama_cpp",                 # (removed) full-extra example only
    "presidio_analyzer", "presidio_anonymizer",  # presidio extra (analyzer needs anonymizer)
    "mcp",                       # mcp extra
    "uvicorn", "starlette", "httpx",  # serve extra
    "faker",                     # optional realistic substitution
}


def _top_level_imports(root: Path) -> set[str]:
    mods: set[str] = set()
    for py in root.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods.add(node.module.split(".")[0])
    return mods


def _declared() -> set[str]:
    data = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))
    deps = data.get("project", {}).get("dependencies", [])
    out: set[str] = set()
    for spec in deps:
        name = spec.split(";")[0].split("[")[0]
        for sep in ("<=", ">=", "==", "~=", "!=", "<", ">", " "):
            name = name.split(sep)[0]
        # pyproject name -> import name (pyyaml imports as `yaml`)
        out.add({"pyyaml": "yaml"}.get(name.strip().lower(), name.strip().lower().replace("-", "_")))
    return out


def test_every_runtime_import_is_declared_or_allowlisted():
    imported = _top_level_imports(_SRC)
    third_party = {
        m for m in imported
        if m not in sys.stdlib_module_names and m not in _ALLOWLIST
    }
    undeclared = third_party - _declared()
    assert not undeclared, (
        f"Undeclared runtime third-party imports (clean-install ImportError risk): "
        f"{sorted(undeclared)}. Declare them in pyproject [project.dependencies] or "
        f"allowlist as extra-guarded."
    )
