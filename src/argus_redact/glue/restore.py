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
    guard: bool | None = True,
    anchor: object | None = None,
    strict: bool = False,
    detailed: bool = False,
) -> "str | tuple[str, dict]":
    """Replace pseudonyms with originals using ``key``.

    ``key`` may be an in-memory mapping or a ``str`` path to a JSON key file.
    A path is loaded here (glue boundary) and the resulting mapping is handed
    to the pure substitution function. See ``pure.restore.restore`` for the
    full ``aliases`` / ``display_marker`` / guard semantics.

    The ``dict[str, str] | str`` annotation matches the frozen Layer-1 public
    contract; any Mapping is accepted at runtime (delegated to the pure layer).

    Guard parameters (added v0.7.18; the default flipped to guard=True in v0.8.0):
        guard: when True (default, v0.8.0+), enables deterministic provenance (P) +
               scope (S) checks; a bare restore with no anchor FAILS CLOSED.
               when None, emits DeprecationWarning and runs legacy restore (plus a
               SecurityWarning if it substituted — see pure.restore.restore).
               when False, runs legacy restore (guard off) with NO warning — the
               explicit opt-out for callers that want a plain, unchecked restore.
        anchor: Anchor instance produced by make_anchor(); carries nonce + scope.
        strict: when True and guard=True, raises RestoreGuardError on any security event.
        detailed: when True, returns (result_text, {"security_events": [...]}) tuple.
    """
    if isinstance(key, str):
        key = _load_key_file(key)
    return _pure_restore(
        text,
        key,
        aliases=aliases,
        display_marker=display_marker,
        guard=guard,
        anchor=anchor,
        strict=strict,
        detailed=detailed,
    )
