"""Version parity guard — pyproject.toml, Cargo.toml [workspace.package], and
argus_redact.__version__ must all agree.

A half-bumped release (e.g. pyproject updated, Cargo.toml not yet) is caught
here in the pytest-visible CI lane, not only in the make sync-docs-version-check
gate.
"""
from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).parents[2]


def _pyproject_version() -> str:
    text = (_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert m, "version line not found in pyproject.toml"
    return m.group(1)


def _cargo_version() -> str:
    """Read version from [workspace.package] in root Cargo.toml."""
    text = (_REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert m, "version line not found in Cargo.toml [workspace.package]"
    return m.group(1)


def test_pyproject_cargo_and_package_version_agree():
    import argus_redact

    py_ver = _pyproject_version()
    cargo_ver = _cargo_version()
    pkg_ver = argus_redact.__version__

    assert py_ver == cargo_ver == pkg_ver, (
        f"Version mismatch detected:\n"
        f"  pyproject.toml   = {py_ver!r}\n"
        f"  Cargo.toml       = {cargo_ver!r}\n"
        f"  __version__      = {pkg_ver!r}\n"
        "All three must agree before a release."
    )
