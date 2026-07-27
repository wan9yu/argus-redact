"""Sync version strings from pyproject.toml into doc surfaces.

pyproject.toml's `version` is the single source of truth. This propagates it to
every other place a version literal lives — including the Cargo **workspace**
manifest (`Cargo.toml` `[workspace.package] version`), which the three crates
inherit via `version.workspace = true`. Keeping Cargo in lockstep here is what
stops the PyPI/crates.io split that broke the v0.7.12 crate publish (pyproject
bumped, Cargo left behind → `cargo publish` hit "version already exists").

Run: `make sync-docs-version`
CI check: `make sync-docs-version-check` (exit 1 if any drift)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_REPO = Path(__file__).parent.parent

# Authoritative PII-type count. SSOT is `argus_redact.specs.list_types()` /
# `make catalog` (the catalog header reports "Total: N types"). Parsed at run
# time from the generated `docs/pii-types.md` header (not imported from
# `argus_redact` so this docs-sync script stays free of the native `_core`
# import) so it can never drift from the catalog again.
_PII_TYPE_COUNT_RE = re.compile(r"^Total:\s*(\d+)\s*types", re.MULTILINE)


def _read_pii_type_count() -> int:
    path = _REPO / "docs/pii-types.md"
    text = path.read_text(encoding="utf-8")
    m = _PII_TYPE_COUNT_RE.search(text)
    if m is None:
        raise RuntimeError(
            f"Could not find a 'Total: N types' line in {path.relative_to(_REPO)}. "
            "Run `make catalog` to regenerate it, or fix the header format this "
            "script parses."
        )
    return int(m.group(1))


def _targets() -> list[tuple[Path, str, str]]:
    """Build the rewrite table. Called at run time, never at import.

    The PII-type count is read from disk here rather than at module scope so
    that importing this module stays side-effect free — an import must not
    depend on `docs/pii-types.md` existing.
    """
    count = _read_pii_type_count()
    return [
        # (path, regex pattern, replacement template — single {v} placeholder)
        (
            _REPO / "src/argus_redact/__init__.py",
            r'^__version__ = "([0-9.]+)"',
            '__version__ = "{v}"',
        ),
        # Cargo workspace version (the three crates inherit it via
        # `version.workspace = true`). `^version` anchors to the
        # `[workspace.package]` line only — dependency `version = ` lives after
        # a crate name and `rust-version`/`edition` start with other words.
        # `\g<1>` preserves the column alignment so re-sync is idempotent.
        (
            _REPO / "Cargo.toml",
            r'^version(\s+)= "([0-9.]+)"',
            r'version\g<1>= "{v}"',
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
        # PII-type count, in every surface that states one. Replacements carry
        # no {v} placeholder, so `.format(v=...)` leaves the SSOT count
        # untouched; each regex re-asserts every occurrence in its file.
        (
            _REPO / "README.zh.md",
            r"[0-9]+ 类 PII",
            f"{count} 类 PII",
        ),
        (
            _REPO / "README.md",
            r"[0-9]+ PII types",
            f"{count} PII types",
        ),
        # Demo hero badge. `\+?` also matches the older soft "60+" phrasing so
        # a rounded claim gets pulled back onto the exact catalog count.
        (
            _REPO / "demo/js/strings.js",
            r"[0-9]+\+? 类隐私信息",
            f"{count} 类隐私信息",
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
    for path, pattern, replacement in _targets():
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
