"""Structured data redaction — JSON dicts/lists and CSV strings."""

from __future__ import annotations

import csv
import io
from typing import Any

from argus_redact import redact, restore


def redact_json(
    data: dict | list,
    *,
    mode: str = "fast",
    lang: str | list[str] = "zh",
    seed: int | None = None,
    config: dict | None = None,
    key: dict | None = None,
) -> tuple[dict | list, dict]:
    """Redact PII in all string values of a JSON-like structure.

    Recursively walks dicts and lists, redacting string values.
    Non-string values (int, float, bool, None) are left unchanged.
    """
    combined_key = dict(key) if key else {}

    def _walk(obj: Any) -> Any:
        nonlocal combined_key
        if isinstance(obj, str):
            redacted_text, combined_key = redact(
                obj,
                mode=mode,
                lang=lang,
                seed=seed,
                config=config,
                key=combined_key if combined_key else None,
            )
            return redacted_text
        if isinstance(obj, dict):
            return {k: _walk(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(item) for item in obj]
        return obj

    result = _walk(data)
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


def redact_csv(
    csv_text: str,
    *,
    mode: str = "fast",
    lang: str | list[str] = "zh",
    seed: int | None = None,
    config: dict | None = None,
) -> tuple[str, dict]:
    """Redact PII in a CSV string. Header row preserved, each cell redacted."""
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)

    if not rows:
        return csv_text, {}

    combined_key: dict = {}
    output_rows = [rows[0]]  # preserve header

    for row in rows[1:]:
        redacted_row = []
        for cell in row:
            redacted_cell, combined_key = redact(
                cell,
                mode=mode,
                lang=lang,
                seed=seed,
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
