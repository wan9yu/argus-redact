"""``os.write`` is a raw syscall and may write FEWER bytes than requested.

POSIX permits a short write on a regular file whenever the write cannot be
completed in full — ENOSPC, a disk quota, or an ``RLIMIT_FSIZE`` ceiling.
``_safe_io`` discarded the return value, so a short write silently produced a
truncated file. For a key file that is a permanent, unreported loss of
restorability: the redacted text survives and the key to reverse it does not.

These tests force the short write rather than waiting for a full disk, and
assert the only two acceptable outcomes: the whole buffer lands, or the caller
gets an exception.
"""

from __future__ import annotations

import json
import os
import sys
from unittest import mock

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX os.write path; Windows uses Path.write_text"
)

_REAL_WRITE = os.write


def _halving_write(fd, data):
    """Write at most half the buffer (minimum one byte) — a short write."""
    payload = bytes(data)
    n = max(1, len(payload) // 2)
    return _REAL_WRITE(fd, payload[:n])


def _stalled_write(fd, data):
    """Accept the call and report zero progress — the pathological case a
    naive retry loop would spin on forever."""
    return 0


def test_safe_write_text_completes_under_short_write(tmp_path):
    from argus_redact._safe_io import safe_write_text

    target = tmp_path / "out.txt"
    content = "联系 13800138000 " * 200  # multi-byte, comfortably over one halving

    with mock.patch("os.write", side_effect=_halving_write):
        safe_write_text(str(target), content)

    assert target.read_text(encoding="utf-8") == content


def test_safe_write_key_completes_under_short_write(tmp_path):
    """The one that matters: a truncated key file is unrecoverable PII loss."""
    from argus_redact._safe_io import safe_write_key

    target = tmp_path / "key.json"
    key = {f"138****{i:04d}": f"1380013{i:04d}" for i in range(60)}

    with mock.patch("os.write", side_effect=_halving_write):
        safe_write_key(str(target), key)

    assert json.loads(target.read_text(encoding="utf-8")) == key


def test_safe_atomic_write_text_completes_under_short_write(tmp_path):
    from argus_redact._safe_io import safe_atomic_write_text

    target = tmp_path / "atomic.txt"
    content = "x" * 4096

    with mock.patch("os.write", side_effect=_halving_write):
        safe_atomic_write_text(str(target), content)

    assert target.read_text(encoding="utf-8") == content


def test_safe_write_text_raises_when_write_makes_no_progress(tmp_path):
    """A writer that cannot make progress must raise, not spin and not
    silently return having written nothing."""
    from argus_redact._safe_io import safe_write_text

    target = tmp_path / "stalled.txt"

    with mock.patch("os.write", side_effect=_stalled_write), pytest.raises(OSError):
        safe_write_text(str(target), "some content that never lands")


def test_safe_write_key_never_silently_truncates(tmp_path):
    """The contract in one assertion: whatever the syscall does, the caller
    either gets the complete file or an exception — never a short one."""
    from argus_redact._safe_io import safe_write_key

    target = tmp_path / "k.json"
    key = {f"P-{i}": f"Name{i}" for i in range(200)}
    expected = json.dumps(key, ensure_ascii=False, indent=2)

    def _one_byte_write(fd, data):
        return _REAL_WRITE(fd, bytes(data)[:1])

    try:
        with mock.patch("os.write", side_effect=_one_byte_write):
            safe_write_key(str(target), key)
    except OSError:
        return  # raising is an acceptable outcome
    assert target.read_text(encoding="utf-8") == expected


def test_empty_content_still_creates_the_file(tmp_path):
    """Regression guard for the loop's termination condition: a zero-length
    buffer must not enter the retry loop at all."""
    from argus_redact._safe_io import safe_write_text

    target = tmp_path / "empty.txt"
    safe_write_text(str(target), "")
    assert target.read_text(encoding="utf-8") == ""
