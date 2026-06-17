"""Single-regex scanner for reserved-range PII values.

Used by the pseudonym-llm profile to detect "polluted" input — text that
already contains realistic-redaction output. Re-redacting such input would
silently corrupt the key dict mapping.

Implementation note: ``scan_for_pollution`` and the canonical pattern list
are implemented in Rust (``argus-redact-core``) and exposed via the ``_core``
extension module. Call ``dict(_core.reserved_range_patterns())`` to obtain the
``{name: regex}`` mapping (Rust is the SSOT).
"""

from __future__ import annotations


def scan_for_pollution(
    text: str,
    *,
    reserved_names: dict[str, tuple[str, ...]] | None = None,
) -> list[tuple[int, int, str]]:
    """Return ``[(start, end, type_name)]`` for every reserved-range match in text.

    ``reserved_names`` overrides the canonical fake-name tables per type. Pass
    ``{"person_zh": ()}`` to disable that type entirely (useful when input may
    legitimately contain names like 张三 / John Doe that match the defaults).
    The default singleton regex is bypassed only when this argument is provided.
    """
    from argus_redact._core import scan_for_pollution as _rust_scan

    # Convert tuple values to lists for Rust (Vec<String>).
    overrides: dict[str, list[str]] | None = None
    if reserved_names is not None:
        overrides = {k: list(v) for k, v in reserved_names.items()}

    return _rust_scan(text, overrides)
