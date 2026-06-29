"""Structured data redaction — JSON dicts/lists and CSV strings."""

from __future__ import annotations

import csv
import io
import warnings
from typing import Any

from argus_redact import redact, restore
from argus_redact.pure.replacer import SecurityWarning


def _parse_paths(paths: list[str]) -> list[list[str]]:
    """Parse dot-notation paths into segments.

    Example: ``'messages[*].content'`` → ``['messages', '*', 'content']``.
    """
    parsed = []
    for path in paths:
        segments = []
        for part in path.replace("[*]", ".*").split("."):
            segments.append(part)
        parsed.append(segments)
    return parsed


def _path_matches(current_path: list[str], target_paths: list[list[str]]) -> bool:
    """Check if current_path is at or below any target path (subtree match).

    A target matches when it is a *prefix* of current_path, so scoping to
    ``messages[*].content`` redacts every string leaf in that subtree —
    including the block form ``content=[{"type":"text","text": ...}]`` where the
    leaf sits deeper than the path. An exact-depth match would silently skip the
    block form and leak its text.
    """
    for target in target_paths:
        if len(current_path) < len(target):
            continue
        if all(t == "*" or c == t for c, t in zip(current_path, target)):
            return True
    return False


def redact_json(
    data: dict | list,
    *,
    mode: str = "fast",
    lang: str | list[str] = "zh",
    salt: int | bytes | None = None,
    config: dict | None = None,
    key: dict | None = None,
    paths: list[str] | None = None,
    with_types: bool = False,
) -> tuple[dict | list, dict] | tuple[dict | list, dict, dict]:
    """Redact PII in string values of a JSON-like structure.

    Args:
        paths: If specified, only redact strings at these paths.
        with_types: If True, return 3-tuple (data, key, types) where
                    types maps replacement → PII type across all fields.

    Returns:
        (redacted_data, key) or (redacted_data, key, type_map) if with_types=True.
    """
    combined_key = dict(key) if key else {}
    combined_types: dict[str, str] = {}
    parsed_paths = _parse_paths(paths) if paths else None

    def _walk(obj: Any, current_path: list[str] | None = None) -> Any:
        nonlocal combined_key, combined_types
        if current_path is None:
            current_path = []

        if isinstance(obj, str):
            if parsed_paths is not None and not _path_matches(current_path, parsed_paths):
                return obj
            result = redact(
                obj,
                mode=mode,
                lang=lang,
                salt=salt,
                config=config,
                key=combined_key if combined_key else None,
                with_types=with_types,
            )
            if with_types:
                redacted_text, combined_key, type_map = result
                combined_types.update(type_map)
            else:
                redacted_text, combined_key = result
            return redacted_text
        if isinstance(obj, dict):
            return {k: _walk(v, current_path + [k]) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(item, current_path + ["*"]) for item in obj]
        return obj

    result = _walk(data)
    if with_types:
        return result, combined_key, combined_types
    return result, combined_key


def restore_json(data: dict | list, key: dict) -> dict | list:
    """Restore PII in all string values of a JSON-like structure."""

    def _walk(obj: Any) -> Any:
        if isinstance(obj, str):
            return restore(obj, key)
        if isinstance(obj, dict):
            return {k: _walk(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(item) for item in obj]
        return obj

    return _walk(data)


def _row_has_pii(
    row: list[str],
    *,
    mode: str,
    lang: str | list[str],
    salt: int | bytes | None,
    config: dict | None,
) -> bool:
    """True if any cell in the row changes under redaction (i.e. carries PII)."""
    for cell in row:
        redacted, _ = redact(cell, mode=mode, lang=lang, salt=salt, config=config)
        if redacted != cell:
            return True
    return False


def redact_csv(
    csv_text: str,
    *,
    mode: str = "fast",
    lang: str | list[str] = "zh",
    salt: int | bytes | None = None,
    config: dict | None = None,
    has_header: bool = True,
) -> tuple[str, dict]:
    """Redact PII in a CSV string.

    Args:
        has_header: When True (default) the first row is treated as a header and
            preserved verbatim. Pass ``has_header=False`` for a headerless CSV so
            the first row is redacted too — otherwise its data leaks. When the
            preserved header row itself carries detectable PII (a sign the CSV is
            actually headerless), a ``SecurityWarning`` is emitted.

    Returns:
        (redacted_csv, key).
    """
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)

    if not rows:
        return csv_text, {}

    combined_key: dict = {}
    output_rows: list[list[str]] = []
    data_rows = rows

    if has_header:
        output_rows.append(rows[0])  # preserve header verbatim
        data_rows = rows[1:]
        if _row_has_pii(rows[0], mode=mode, lang=lang, salt=salt, config=config):
            warnings.warn(
                "redact_csv: the preserved header row (row 0) contains detectable "
                "PII and was NOT redacted. If this CSV has no header row, pass "
                "has_header=False so the first row is redacted too.",
                SecurityWarning,
                stacklevel=2,
            )

    for row in data_rows:
        redacted_row = []
        for cell in row:
            redacted_cell, combined_key = redact(
                cell,
                mode=mode,
                lang=lang,
                salt=salt,
                config=config,
                key=combined_key if combined_key else None,
            )
            redacted_row.append(redacted_cell)
        output_rows.append(redacted_row)

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerows(output_rows)
    return out.getvalue().strip(), combined_key


def restore_csv(csv_text: str, key: dict) -> str:
    """Restore PII in a CSV string."""
    return restore(csv_text, key)
