"""File permission hardening (v0.8.2 security fix).

Three defects fixed together:

1. ``safe_write_text`` used ``os.fchmod(fd, mode)`` unconditionally, which
   WIDENS a caller-hardened pre-existing file down to the (weaker) default
   mode ``0o644`` whenever a write with the default mode lands on a file
   that was previously locked to ``0o600``.
2. The CLI's ``cmd_restore`` wrote deanonymized (plaintext PII) output at
   the ``_write_output`` default mode ``0o644`` — world/group readable,
   even though the restored text is at least as sensitive as the key file
   (which is correctly written at ``0o600``).
3. The CLI's ``cmd_assess`` wrote its ``--output`` report at the same
   world-readable ``0o644`` default. The report's ``entities[].original``
   field carries the plaintext PII span verbatim (see
   ``glue/redact.py``'s ``entity_details`` construction), so it is exactly
   as sensitive as the restore output above.

All three are POSIX-only (mode bits); skipped on Windows.
"""

from __future__ import annotations

import json
import os
import stat
import sys

import pytest

from tests.cli.conftest import run_cli

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX mode bits; Windows has no chmod semantics"
)


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_safe_write_text_does_not_widen_hardened_existing_file(tmp_path):
    from argus_redact._safe_io import safe_write_text

    target = tmp_path / "hardened.txt"
    target.write_text("secret", encoding="utf-8")
    os.chmod(target, 0o600)

    # Default mode (0o644) must not widen a file that was already locked to 0o600.
    safe_write_text(str(target), "new content")

    assert _mode(target) == 0o600
    assert target.read_text(encoding="utf-8") == "new content"


def test_safe_write_text_new_file_gets_requested_mode(tmp_path):
    from argus_redact._safe_io import safe_write_text

    target = tmp_path / "new.txt"
    safe_write_text(str(target), "x", mode=0o600)

    assert _mode(target) == 0o600


def test_safe_write_key_still_narrows_existing_world_readable_file(tmp_path):
    from argus_redact._safe_io import safe_write_key

    target = tmp_path / "key.json"
    target.write_text("{}", encoding="utf-8")
    os.chmod(target, 0o644)

    safe_write_key(str(target), {"P-001": "Alice"})

    assert _mode(target) == 0o600
    assert json.loads(target.read_text(encoding="utf-8")) == {"P-001": "Alice"}


def test_cli_restore_output_file_is_mode_0600(tmp_path):
    key_file = tmp_path / "key.json"
    output_file = tmp_path / "restored.txt"

    redact_code, redacted_stdout, _ = run_cli(
        "redact",
        "-k",
        str(key_file),
        "-m",
        "fast",
        "-s",
        "42",
        stdin="电话13812345678",
    )
    assert redact_code == 0

    code, _, stderr = run_cli(
        "restore",
        "-k",
        str(key_file),
        "-o",
        str(output_file),
        stdin=redacted_stdout,
    )

    assert code == 0, stderr
    assert output_file.exists()
    assert _mode(output_file) == 0o600
    assert "13812345678" in output_file.read_text(encoding="utf-8")


def test_cli_assess_output_file_is_mode_0600(tmp_path):
    output_file = tmp_path / "report.json"

    code, _, stderr = run_cli(
        "assess",
        "-o",
        str(output_file),
        stdin="电话13812345678",
    )

    assert code == 0, stderr
    assert output_file.exists()
    assert _mode(output_file) == 0o600

    # Confirm the report is in fact PII-bearing (the whole point of the
    # hardening) — entities[].original carries the plaintext span verbatim.
    report = json.loads(output_file.read_text(encoding="utf-8"))
    originals = [e["original"] for e in report["entities"]]
    assert "13812345678" in originals
