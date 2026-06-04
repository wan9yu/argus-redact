"""v0.6.10: symmetric safe_read_text — POSIX O_NOFOLLOW for key-file reads."""
import sys
from pathlib import Path
import pytest


def test_safe_read_text_reads_regular_file(tmp_path):
    from argus_redact._safe_io import safe_read_text
    p = tmp_path / "normal.txt"
    p.write_text("hello\n", encoding="utf-8")
    assert safe_read_text(p) == "hello\n"


def test_safe_read_text_handles_string_paths(tmp_path):
    from argus_redact._safe_io import safe_read_text
    p = tmp_path / "normal.txt"
    p.write_text("hello", encoding="utf-8")
    assert safe_read_text(str(p)) == "hello"


def test_safe_read_refuses_symlink_posix(tmp_path):
    if sys.platform == "win32":
        pytest.skip("POSIX-only attack surface")
    real = tmp_path / "real.txt"
    real.write_text("safe content", encoding="utf-8")
    link = tmp_path / "evil.txt"
    link.symlink_to(real)
    from argus_redact._safe_io import safe_read_text
    with pytest.raises(OSError):
        safe_read_text(link)


def test_safe_read_refuses_symlink_windows(tmp_path):
    if sys.platform != "win32":
        pytest.skip("Windows-only branch")
    real = tmp_path / "real.txt"
    real.write_text("safe content", encoding="utf-8")
    link = tmp_path / "evil.txt"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation requires admin on Windows")
    from argus_redact._safe_io import safe_read_text
    with pytest.raises(OSError, match="symbolic link|symlink"):
        safe_read_text(link)
