"""Tests for the version-sync script.

Verifies the script can detect drift and bring drift back to pyproject.toml's version.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).parent / "sync_docs_version.py"
_REPO = Path(__file__).parent.parent


def _run_script(*args, cwd: Path) -> subprocess.CompletedProcess:
    # Use the copied script from within the fake repo so that _REPO resolves correctly
    script_in_fake_repo = cwd / "scripts" / "sync_docs_version.py"
    return subprocess.run(
        [sys.executable, str(script_in_fake_repo), *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    """Create a minimal repo skeleton with a known pyproject version and a drifted README."""
    (tmp_path / "src" / "argus_redact").mkdir(parents=True)
    (tmp_path / "docs").mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "argus-redact"\nversion = "9.9.9"\n', encoding="utf-8"
    )
    (tmp_path / "src" / "argus_redact" / "__init__.py").write_text(
        '__version__ = "0.0.0"\n', encoding="utf-8"
    )
    (tmp_path / "README.md").write_text(
        "Current (v0.0.0) something\n\n3 PII types across 3 layers\n", encoding="utf-8"
    )
    (tmp_path / "docs" / "cli-reference.md").write_text(
        "argus-redact v0.0.0 (info)\n", encoding="utf-8"
    )
    (tmp_path / "docs" / "benchmark-report.md").write_text(
        "argus-redact v0.0.0 on Apple M1\n", encoding="utf-8"
    )
    # The generated catalog header is the PII-type-count SSOT the script parses.
    (tmp_path / "docs" / "pii-types.md").write_text(
        "# PII Type Catalog\n\nTotal: 7 types\n", encoding="utf-8"
    )
    (tmp_path / "README.zh.md").write_text("当前 (v0.0.0)，3 类 PII\n", encoding="utf-8")
    (tmp_path / "demo").mkdir()
    (tmp_path / "demo" / "js").mkdir()
    (tmp_path / "demo" / "js" / "strings.js").write_text(
        "badges: ['60+ 类隐私信息'],\n", encoding="utf-8"
    )
    # Cargo workspace manifest — version line plus a dependency `version` and a
    # `rust-version` that must NOT be rewritten (anchor specificity guard).
    (tmp_path / "Cargo.toml").write_text(
        "[workspace.package]\n"
        'version      = "0.0.0"\n'
        'rust-version = "1.85"\n\n'
        "[workspace.dependencies]\n"
        'pyo3 = { version = "0.28" }\n',
        encoding="utf-8",
    )
    # The py-crate manifest pins argus-redact-core by literal version. It is the
    # only brace-bearing target, rewritten by a regex whose `\g<1>` swallows the
    # opening brace so the replacement stays brace-free (`_sync` runs
    # `.format(v=...)` over it, and a literal `{` there would raise). The
    # `=`-aligned neighbours are the guard that the pattern's own `\s*` is not
    # over-greedy, and `pyo3.workspace` must NOT be rewritten.
    (tmp_path / "crates" / "argus-redact-py").mkdir(parents=True)
    (tmp_path / "crates" / "argus-redact-py" / "Cargo.toml").write_text(
        "[package]\n"
        'name                   = "argus-redact-py"\n'
        "version.workspace      = true\n\n"
        "[dependencies]\n"
        "pyo3.workspace         = true\n"
        'argus-redact-core = { path = "../argus-redact-core", version = "0.0.0" }\n',
        encoding="utf-8",
    )
    # Copy the script into the fake repo's scripts/ dir
    (tmp_path / "scripts").mkdir()
    shutil.copy(_SCRIPT, tmp_path / "scripts" / "sync_docs_version.py")
    return tmp_path


def test_check_detects_drift(fake_repo: Path):
    """--check exits 1 when docs are out of sync with pyproject."""
    result = _run_script("--check", cwd=fake_repo)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "drift" in result.stderr.lower()


def test_sync_writes_pyproject_version_to_all_targets(fake_repo: Path):
    result = _run_script(cwd=fake_repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '"9.9.9"' in (fake_repo / "src/argus_redact/__init__.py").read_text(encoding="utf-8")
    assert "v9.9.9" in (fake_repo / "README.md").read_text(encoding="utf-8")
    assert "v9.9.9" in (fake_repo / "docs/cli-reference.md").read_text(encoding="utf-8")
    assert "v9.9.9 on" in (fake_repo / "docs/benchmark-report.md").read_text(encoding="utf-8")
    cargo = (fake_repo / "Cargo.toml").read_text(encoding="utf-8")
    assert 'version      = "9.9.9"' in cargo, "workspace version not synced (alignment preserved)"
    assert 'rust-version = "1.85"' in cargo, "rust-version must not be rewritten"
    assert 'pyo3 = { version = "0.28" }' in cargo, "dependency version must not be rewritten"
    py_crate = (fake_repo / "crates/argus-redact-py/Cargo.toml").read_text(encoding="utf-8")
    assert 'version = "9.9.9" }' in py_crate, "py-crate core pin not synced"
    assert "pyo3.workspace         = true" in py_crate, "workspace dep must not be rewritten"


def test_sync_rewrites_the_py_crate_pin_when_the_manifest_is_realigned(fake_repo: Path):
    """The pin survives TOML realignment.

    This manifest is `=`-aligned, so adding a dependency with a longer name
    shifts the pin's spacing. A pattern hardcoding single spaces would silently
    stop matching and `--check` would report clean while the pin stayed stale —
    the exact failure this target was added to prevent.
    """
    manifest = fake_repo / "crates/argus-redact-py/Cargo.toml"
    manifest.write_text(
        "[dependencies]\n"
        "a-much-longer-dependency-name = true\n"
        'argus-redact-core             = { path = "../argus-redact-core", version = "0.0.0" }\n',
        encoding="utf-8",
    )
    result = _run_script(cwd=fake_repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'version = "9.9.9" }' in manifest.read_text(encoding="utf-8")


def test_check_reports_drift_on_the_py_crate_pin(fake_repo: Path):
    """A stale pin must be named by --check, not silently skipped.

    `_sync` skips any target whose path does not exist, so a mis-specified path
    would make this target vanish without a word.

    Separators are normalised before the comparison: `_sync` reports
    `path.relative_to(_REPO)`, which renders with backslashes on Windows, and
    the CI matrix runs this on windows-latest.
    """
    result = _run_script("--check", cwd=fake_repo)
    assert result.returncode == 1
    assert "crates/argus-redact-py/Cargo.toml" in result.stderr.replace("\\", "/")


def test_sync_writes_catalog_pii_type_count_to_every_surface(fake_repo: Path):
    """The `Total: N types` catalog header owns every count claim, not a human."""
    result = _run_script(cwd=fake_repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "7 PII types" in (fake_repo / "README.md").read_text(encoding="utf-8")
    assert "7 类 PII" in (fake_repo / "README.zh.md").read_text(encoding="utf-8")
    assert "7 类隐私信息" in (fake_repo / "demo/js/strings.js").read_text(encoding="utf-8")


def test_missing_catalog_header_fails_loudly(fake_repo: Path):
    """A catalog without the parsed header must abort, not silently skip counts."""
    (fake_repo / "docs" / "pii-types.md").write_text(
        "# PII Type Catalog\n\nno header here\n", encoding="utf-8"
    )
    result = _run_script(cwd=fake_repo)
    assert result.returncode != 0
    assert "Total: N types" in result.stderr


def test_import_does_no_filesystem_reads(tmp_path: Path):
    """Importing the module must not depend on any repo file existing.

    Guards the module-scope-read regression: a target table built at import
    time made the module unimportable wherever `docs/pii-types.md` was absent.
    """
    import importlib.util

    (tmp_path / "scripts").mkdir()
    copied = tmp_path / "scripts" / "sync_docs_version.py"
    shutil.copy(_SCRIPT, copied)
    spec = importlib.util.spec_from_file_location("sync_docs_version_isolated", copied)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # tmp_path holds no docs/pii-types.md
    assert mod._REPO == tmp_path
    assert callable(mod._targets)


def test_check_passes_after_sync(fake_repo: Path):
    _run_script(cwd=fake_repo)
    result = _run_script("--check", cwd=fake_repo)
    assert result.returncode == 0, result.stdout + result.stderr


def test_script_imports_under_python_3_10():
    """Regression guard for v0.6.6 CI failure (tomllib was 3.11+).

    The script must import successfully on Python >= 3.10 without depending
    on any version-conditional stdlib module.
    """
    import importlib.util

    assert sys.version_info >= (3, 10), "argus-redact requires Python 3.10+"
    spec = importlib.util.spec_from_file_location("sync_docs_version", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # must not raise ModuleNotFoundError
