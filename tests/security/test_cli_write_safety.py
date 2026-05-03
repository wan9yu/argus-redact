"""CLI file writes refuse to follow symlinks (audit H8) + key files 0600 (L2).

Pre-fix, ``Path.write_text`` followed symlinks by default — a privileged
daemon (root container) writing redacted output to a user-supplied path
could overwrite ``/etc/cron.d/payload`` if an attacker pre-planted a
symlink. v0.6.2+ uses ``O_NOFOLLOW`` on POSIX (Windows: ``is_symlink``
pre-check) and writes key files mode 0600 (was 0644).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only attack surface")
def test_safe_write_text_refuses_symlink_target(tmp_path):
    from argus_redact.cli.main import _safe_write_text

    target = tmp_path / "real.txt"
    target.write_text("preexisting", encoding="utf-8")
    link = tmp_path / "out.txt"
    link.symlink_to(target)

    with pytest.raises(OSError):
        _safe_write_text(str(link), "redacted output")
    # Original target untouched
    assert target.read_text(encoding="utf-8") == "preexisting"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only attack surface")
def test_safe_write_key_refuses_symlink_target(tmp_path):
    from argus_redact.cli.main import _safe_write_key

    target = tmp_path / "real_key.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "key.json"
    link.symlink_to(target)

    with pytest.raises(OSError):
        _safe_write_key(str(link), {"P-001": "Alice"})
    assert target.read_text(encoding="utf-8") == "{}"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission semantics")
def test_safe_write_key_uses_mode_0600(tmp_path):
    from argus_redact.cli.main import _safe_write_key

    key_path = tmp_path / "key.json"
    _safe_write_key(str(key_path), {"P-001": "Alice"})

    mode = key_path.stat().st_mode & 0o777
    assert mode == 0o600, f"key file mode {oct(mode)} != 0600"
    # Content readable by us
    assert json.loads(key_path.read_text(encoding="utf-8")) == {"P-001": "Alice"}


def test_safe_write_text_writes_content(tmp_path):
    from argus_redact.cli.main import _safe_write_text

    target = tmp_path / "out.txt"
    _safe_write_text(str(target), "hello world")
    assert target.read_text(encoding="utf-8") == "hello world"


def test_safe_write_key_writes_json(tmp_path):
    from argus_redact.cli.main import _safe_write_key

    target = tmp_path / "k.json"
    _safe_write_key(str(target), {"P-1": "Alice", "P-2": "Bob"})
    assert json.loads(target.read_text(encoding="utf-8")) == {"P-1": "Alice", "P-2": "Bob"}


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only attack surface")
def test_safe_write_text_overwrites_existing_regular_file(tmp_path):
    """Overwriting a non-symlink regular file is fine — only symlinks are blocked."""
    from argus_redact.cli.main import _safe_write_text

    target = tmp_path / "out.txt"
    target.write_text("old", encoding="utf-8")
    _safe_write_text(str(target), "new")
    assert target.read_text(encoding="utf-8") == "new"
