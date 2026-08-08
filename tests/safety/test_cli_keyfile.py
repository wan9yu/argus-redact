"""CLI key-file hardening."""

import os
import stat

import pytest

from argus_redact.cli import main as cli


def test_safe_read_text_refuses_symlink(tmp_path):
    """The refusal itself, at its birth site — O_NOFOLLOW raises OSError."""
    from argus_redact._safe_io import safe_read_text

    target = tmp_path / "secret.txt"
    target.write_text("13800138000", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    with pytest.raises(OSError):
        safe_read_text(str(link))


def test_read_input_refuses_symlink(tmp_path, capsys):
    """The CLI still refuses, but reports it rather than emitting a traceback.

    Previously ``_read_input`` let the ``OSError`` escape, so an operator who
    pointed the CLI at a symlink got a raw traceback — the same shape as the
    directory-as-input case. It now exits nonzero with a clear message; the
    file contents are still never read.
    """
    target = tmp_path / "secret.txt"
    target.write_text("13800138000", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    with pytest.raises(SystemExit) as exc:
        cli._read_input(str(link))

    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "Error:" in err
    assert "13800138000" not in err


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
