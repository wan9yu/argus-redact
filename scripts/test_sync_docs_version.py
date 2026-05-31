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
        '[project]\nname = "argus-redact"\nversion = "9.9.9"\n'
    )
    (tmp_path / "src" / "argus_redact" / "__init__.py").write_text('__version__ = "0.0.0"\n')
    (tmp_path / "README.md").write_text("Current (v0.0.0) something\n")
    (tmp_path / "docs" / "cli-reference.md").write_text("argus-redact v0.0.0 (info)\n")
    (tmp_path / "docs" / "benchmark-report.md").write_text("argus-redact v0.0.0 on Apple M1\n")
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
    assert '"9.9.9"' in (fake_repo / "src/argus_redact/__init__.py").read_text()
    assert "v9.9.9" in (fake_repo / "README.md").read_text()
    assert "v9.9.9" in (fake_repo / "docs/cli-reference.md").read_text()
    assert "v9.9.9 on" in (fake_repo / "docs/benchmark-report.md").read_text()


def test_check_passes_after_sync(fake_repo: Path):
    _run_script(cwd=fake_repo)
    result = _run_script("--check", cwd=fake_repo)
    assert result.returncode == 0, result.stdout + result.stderr
