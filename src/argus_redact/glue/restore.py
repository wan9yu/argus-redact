"""restore(text, key) — glue wrapper that resolves a key-file path to an
in-memory mapping, then delegates to the pure ``pure.restore.restore``.

The filesystem load lives here (glue) so the pure layer stays I/O-free: the
``argus_redact.restore(...)`` public entry point still accepts a ``str`` path
for backward compatibility, but the load happens at the glue boundary.
"""

from __future__ import annotations

from argus_redact.pure.restore import restore as _pure_restore


def _load_key_file(path: str) -> dict[str, str]:
    """Read a JSON key file from ``path`` (symlink-refusing) into a dict."""
    import json

    from argus_redact._safe_io import safe_read_text

    return json.loads(safe_read_text(path))


def restore(
    text: str,
    key: dict[str, str] | str,
    *,
    aliases: dict[str, tuple[str, ...]] | None = None,
    display_marker: str | None = None,
) -> str:
    """Replace pseudonyms with originals using ``key``.

    ``key`` may be an in-memory mapping or a ``str`` path to a JSON key file.
    A path is loaded here (glue boundary) and the resulting mapping is handed
    to the pure substitution function. See ``pure.restore.restore`` for the
    full ``aliases`` / ``display_marker`` semantics.

    The ``dict[str, str] | str`` annotation matches the frozen Layer-1 public
    contract; any Mapping is accepted at runtime (delegated to the pure layer).
    """
    if isinstance(key, str):
        key = _load_key_file(key)
    return _pure_restore(
        text,
        key,
        aliases=aliases,
        display_marker=display_marker,
    )
