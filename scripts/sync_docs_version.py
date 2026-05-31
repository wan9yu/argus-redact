"""Sync version strings from pyproject.toml into doc surfaces.

Run: `make sync-docs-version`
CI check: `make sync-docs-version-check` (exit 1 if any drift)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import tomllib

_REPO = Path(__file__).parent.parent

_TARGETS = [
    # (path, regex pattern, replacement template — single {v} placeholder)
    (
        _REPO / "src/argus_redact/__init__.py",
        r'^__version__ = "([0-9.]+)"',
        '__version__ = "{v}"',
    ),
    (
        _REPO / "README.md",
        r"Current \(v([0-9.]+)\)",
        "Current (v{v})",
    ),
    (
        _REPO / "docs/cli-reference.md",
        r"argus-redact v([0-9.]+)",
        "argus-redact v{v}",
    ),
    (
        _REPO / "docs/benchmark-report.md",
        r"argus-redact v([0-9.]+) on",
        "argus-redact v{v} on",
    ),
]


def _read_version() -> str:
    with (_REPO / "pyproject.toml").open("rb") as f:
        return tomllib.load(f)["project"]["version"]


def _sync(check_only: bool) -> int:
    version = _read_version()
    drift: list[str] = []
    for path, pattern, replacement in _TARGETS:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        new = re.sub(pattern, replacement.format(v=version), text, flags=re.MULTILINE)
        if new != text:
            if check_only:
                drift.append(str(path.relative_to(_REPO)))
            else:
                path.write_text(new, encoding="utf-8")
    if check_only and drift:
        print("Version drift detected:", file=sys.stderr)
        for p in drift:
            print(f"  - {p}", file=sys.stderr)
        print("\nRun `make sync-docs-version` to fix.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_sync(check_only="--check" in sys.argv))
