"""Safe filesystem write helpers shared by CLI and glue layer.

Refuses to follow symlinks (POSIX: ``O_NOFOLLOW``; Windows: ``is_symlink``
pre-check) and writes key files mode 0600 (PII-bearing). Defends against
the pre-existing-symlink attack class — privileged process coaxed into
overwriting ``/etc/cron.d/payload`` via a planted ``out.txt``.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path

_IS_WIN = sys.platform == "win32"


@contextlib.contextmanager
def _open_nofollow(path: str, mode: int) -> Iterator[int]:
    """Open ``path`` for writing with ``O_NOFOLLOW`` (POSIX). Yields fd."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(path, flags, mode)
    try:
        yield fd
    finally:
        os.close(fd)


def safe_write_text(path: str, content: str, *, mode: int = 0o644) -> None:
    """Write text to ``path`` refusing to follow symlinks.

    Windows fallback uses ``Path.is_symlink()`` pre-check (best-effort —
    NTFS reparse points / junctions are not classified as symlinks by
    Python's stat semantics; comprehensive Windows hardening would need
    ``GetFileAttributesW`` + ``FILE_ATTRIBUTE_REPARSE_POINT`` checks).
    """
    if _IS_WIN:
        if Path(path).is_symlink():
            raise OSError(f"refusing to write to symbolic link: {path}")
        Path(path).write_text(content, encoding="utf-8")
        return
    with _open_nofollow(path, mode) as fd:
        os.write(fd, content.encode("utf-8"))


def safe_write_key(path: str, key: dict) -> None:
    """Persist a key dict (sensitive: contains plaintext originals) at mode
    0600 on POSIX, refusing to follow symlinks. Windows falls back to 0644
    + the ``is_symlink`` pre-check (NTFS ACLs are out of scope)."""
    safe_write_text(path, json.dumps(key, ensure_ascii=False, indent=2), mode=0o600)


def safe_read_text(path: str | Path) -> str:
    """Read a text file, refusing to follow symlinks on POSIX.

    Symmetric to ``safe_write_text`` / ``safe_write_key``. Use for paths read
    from untrusted sources (CLI args, server inputs) where a malicious symlink
    could redirect to ``/etc/passwd``, ``~/.ssh/id_rsa``, etc.

    POSIX: uses ``O_NOFOLLOW`` — read fails with ``OSError`` if the path itself
    is a symlink. (Symlinked path components above the target are still
    followed by the kernel; ``O_NOFOLLOW`` guards only the final component.)

    Windows: best-effort ``Path.is_symlink()`` check before reading. NTFS
    junctions and reparse points are not detected.
    """
    p = Path(path)
    if not _IS_WIN:
        flags = os.O_RDONLY | os.O_NOFOLLOW
        fd = os.open(str(p), flags)
        try:
            with os.fdopen(fd, "r", encoding="utf-8", closefd=True) as f:
                return f.read()
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
    else:
        if p.is_symlink():
            raise OSError(f"refusing to read symbolic link: {p}")
        return p.read_text(encoding="utf-8")


def safe_atomic_write_text(target: str, content: str, *, mode: int = 0o644) -> None:
    """Write atomically via ``<target>.tmp`` + rename. Both tmp and target
    are protected against symlink follows. Used by callers that need to
    avoid leaving a partially-written file on crash (e.g. key persistence)."""
    target_path = Path(target)
    tmp = str(target_path.with_suffix(target_path.suffix + ".tmp"))
    safe_write_text(tmp, content, mode=mode)
    if not _IS_WIN and Path(target).is_symlink():
        os.unlink(tmp)
        raise OSError(f"refusing to replace symbolic link: {target}")
    os.replace(tmp, target)
