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


def test_py_crate_pins_the_current_core_version():
    """`crates/argus-redact-py/Cargo.toml` pins argus-redact-core by literal
    version, because a path dependency alone is not publishable. A stale pin
    fails at `cargo publish` — or publishes a py-crate pinning a core version
    that does not exist yet.

    `make sync-docs-version` rewrites this pin, so this test is a backstop
    against a broken generator rather than against a forgotten hand-edit. Both
    are worth having: the generator is a regex over a brace-bearing TOML table,
    and a regex that silently stops matching would otherwise leave the pin stale
    with `sync-docs-version-check` still reporting clean.

    The wasm crate needs no equivalent check: its dependency is a bare
    `{ path = "../argus-redact-core" }` with no version literal.
    """
    text = (_REPO_ROOT / "crates" / "argus-redact-py" / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'argus-redact-core\s*=\s*\{[^}]*version\s*=\s*"([0-9.]+)"', text)
    assert match, "argus-redact-core dependency pin not found in argus-redact-py/Cargo.toml"
    assert match.group(1) == _pyproject_version(), (
        f"argus-redact-py pins argus-redact-core {match.group(1)} but pyproject "
        f"declares {_pyproject_version()}. Run `make sync-docs-version` — it "
        f"rewrites this pin along with every other version literal. Do not edit "
        f"it by hand: that would leave the other targets stale."
    )
