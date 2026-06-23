"""Sync version strings from pyproject.toml into doc surfaces.

Run: `make sync-docs-version`
CI check: `make sync-docs-version-check` (exit 1 if any drift)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

_REPO = Path(__file__).parent.parent

# Authoritative PII-type count. SSOT is `argus_redact.specs.list_types()` /
# `make catalog` (the catalog header reports "Total: N types"). Hardcoded here
# (not imported) so this docs-sync script stays free of the native `_core`
# import. Bump this when `make catalog` reports a different total; the README
# count targets below are then re-asserted by `make sync-docs-version-check`.
_PII_TYPE_COUNT = 63

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
    # README.zh.md hardcoded milestone version ("当前 (vX.Y.Z)") — keep in
    # lockstep with pyproject; the crates badge below is synced separately.
    (
        _REPO / "README.zh.md",
        r"当前 \(v([0-9.]+)\)",
        "当前 (v{v})",
    ),
    # README.zh.md PII-type count ("N 类 PII"). Replacement carries no {v}
    # placeholder, so `.format(v=...)` leaves the SSOT count untouched; the
    # regex re-asserts both occurrences (intro bullet + North Star table).
    (
        _REPO / "README.zh.md",
        r"[0-9]+ 类 PII",
        f"{_PII_TYPE_COUNT} 类 PII",
    ),
    # Static crates.io version badge (shields' dynamic crates/v endpoint is
    # intermittently "invalid"; a static badge is reliable, bumped here).
    (
        _REPO / "README.md",
        r"crates\.io-v([0-9.]+)-orange",
        "crates.io-v{v}-orange",
    ),
    (
        _REPO / "README.zh.md",
        r"crates\.io-v([0-9.]+)-orange",
        "crates.io-v{v}-orange",
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

_PYPROJECT_VERSION = re.compile(r'^version = "([0-9.]+)"', re.MULTILINE)


def _read_version() -> str:
    text = (_REPO / "pyproject.toml").read_text(encoding="utf-8")
    m = _PYPROJECT_VERSION.search(text)
    if m is None:
        raise RuntimeError('Could not find version = "X.Y.Z" in pyproject.toml')
    return m.group(1)


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
