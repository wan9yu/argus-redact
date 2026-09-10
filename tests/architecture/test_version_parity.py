"""Version parity guard — pyproject.toml, Cargo.toml [workspace.package], and
argus_redact.__version__ must all agree.

A half-bumped release (e.g. pyproject updated, Cargo.toml not yet) is caught
here in the pytest-visible CI lane, not only in the make sync-docs-version-check
gate.

Also guards the built `_core` extension: it is stamped at build time with
`__build__`, a `"{version}+{sha256_hex}"` string covering the Rust source and
data it was compiled from, so a stale or unrebuilt extension fails loudly
instead of silently running old detection logic.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

import pytest

import argus_redact
from argus_redact._core_loader import _core, parse_build_stamp

_REPO_ROOT = Path(__file__).resolve().parents[2]

# File set + repo-root derivation shared byte-for-byte with the Rust recipe in
# crates/argus-redact-py/build_hash.rs — see _source_hash below.
SOURCE_DIRS = [
    "crates/argus-redact-core/src",
    "crates/argus-redact-core/data",
    "crates/argus-redact-py/src",
]
EXTRA_FILES = [
    "Cargo.lock",
    "Cargo.toml",
    "crates/argus-redact-core/Cargo.toml",
    "crates/argus-redact-py/Cargo.toml",
]


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


def _hash_of_files(files: list[tuple[str, bytes]]) -> str:
    """The single canonical digest recipe: sort (relpath, content) pairs bytewise
    on the UTF-8 relpath, then feed ``relpath \\0 content`` for each into one
    sha256. Mirrors crates/argus-redact-py/build_hash.rs::hash_keyed."""
    h = hashlib.sha256()
    for relpath, content in sorted(files, key=lambda kv: kv[0].encode("utf-8")):
        h.update(relpath.encode("utf-8") + b"\0")
        h.update(content)
    return h.hexdigest()


def _source_hash() -> str:
    """Hash of the current checkout's Rust source + data tree, keyed and
    ordered identically to the recipe crates/argus-redact-py/build_hash.rs
    uses to bake `_core.__build__` at build time.
    """
    paths: list[Path] = []
    for d in SOURCE_DIRS:
        for root, _dirs, names in os.walk(_REPO_ROOT / d, followlinks=False):
            for n in names:
                if n.endswith((".rs", ".ron")):
                    p = Path(root) / n
                    if not p.is_symlink():
                        paths.append(p)
    for f in EXTRA_FILES:
        p = _REPO_ROOT / f
        if p.exists() and not p.is_symlink():
            paths.append(p)
    pairs = [(str(p.relative_to(_REPO_ROOT)).replace(os.sep, "/"), p.read_bytes()) for p in paths]
    return _hash_of_files(pairs)


def test_pyproject_cargo_and_package_versions_should_agree():
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


def test_py_crate_should_pin_the_current_core_version():
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


def test_core_extension_should_have_a_build_stamp():
    assert hasattr(_core, "__build__"), (
        "_core built without __build__ stamp (rebuild: maturin develop --release)"
    )


def test_build_stamp_version_should_match_package_version():
    version, _hash = parse_build_stamp(_core.__build__)
    assert version == argus_redact.__version__


@pytest.mark.skipif(
    not (_REPO_ROOT / SOURCE_DIRS[0]).exists(), reason="source tree absent (sdist/wheel)"
)
def test_build_stamp_hash_should_match_checkout_source():
    _version, baked = parse_build_stamp(_core.__build__)
    assert baked == _source_hash(), (
        "baked source hash != current checkout — _core is stale; rebuild: maturin develop --release"
    )


# Fixed tiny tree with known bytes, hashed by the same recipe as _source_hash
# above. crates/argus-redact-py/build_hash.rs asserts the SAME hex constant
# against its own Rust implementation of this hasher at build time — proving
# the two independent implementations agree, independent of the live checkout.
_VECTOR_FILES = [("a.rs", b"alpha"), ("b/c.ron", b"beta"), ("z.rs", b"gamma")]
_VECTOR_EXPECTED = "b5a7a18b4257178108b7b7f17030063393be16e8e8106a6d405634a344a896e4"


def test_hash_of_files_should_match_shared_vector():
    assert _hash_of_files(_VECTOR_FILES) == _VECTOR_EXPECTED
