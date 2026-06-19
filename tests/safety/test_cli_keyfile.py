"""CLI key-file hardening."""

import os
import stat

import pytest

from argus_redact.cli import main as cli


def test_read_input_refuses_symlink(tmp_path):
    target = tmp_path / "secret.txt"
    target.write_text("13800138000", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    with pytest.raises(OSError):
        cli._read_input(str(link))


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_write_output_key_mode_0600(tmp_path):
    out = tmp_path / "out.json"
    cli._write_output('{"key": "x"}', str(out), mode=0o600)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_write_output_0600_enforced_over_existing_world_readable(tmp_path):
    # A pre-existing world-readable target must be locked down to 0o600 when a
    # key-bearing payload is written into it (os.open mode applies only on create).
    out = tmp_path / "out.json"
    out.write_text("{}", encoding="utf-8")
    os.chmod(out, 0o644)
    cli._write_output('{"key": "x"}', str(out), mode=0o600)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
