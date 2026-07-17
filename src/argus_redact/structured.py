"""Structured data redaction — JSON dicts/lists and CSV strings."""

from __future__ import annotations

import csv
import io
import warnings
from typing import Any

from argus_redact import redact, restore
from argus_redact.exceptions import SecurityWarning
from argus_redact.glue.redact import _build_type_map, _detect
from argus_redact.pure.lang_detect import detect_languages
from argus_redact.pure.replacer import (
    make_structured_session,
    replace_into_session,
    warn_mask_collisions,
)


def _warn_low_entropy_salt(salt: int | bytes | None) -> None:
    """Emit the same low-entropy salt SecurityWarning ``redact()`` does — once per
    structured document (the stateless per-cell path emitted it per cell)."""
    if salt is not None and (
        isinstance(salt, int) or (isinstance(salt, (bytes, bytearray)) and len(salt) < 16)
    ):
        warnings.warn(
            "low-entropy salt: an integer or short salt is grid-searchable on small "
            "PII domains; prefer salt=os.urandom(32) for the forward-secure mapping claim.",
            SecurityWarning,
            stacklevel=3,
        )


def _redact_cell(
    session,
    text: str,
    *,
    mode: str,
    lang: str | list[str],
    config: dict | None,
) -> tuple[str, list]:
    """Detect PII in one cell/leaf and redact it through the shared session.

    Returns ``(redacted_text, entities)``. Detection reuses the SAME pipeline
    ``redact()`` runs (glue ``_detect``); only the replace step is routed through
    the stateful session so the accumulation key + pseudonym generators stay in
    Rust across cells (O(N) over the document instead of O(N²)).
    """
    cell_lang = detect_languages(text) if lang == "auto" else lang
    entities, langs, _timing, _stats = _detect(
        text,
        lang=cell_lang,
        mode=mode,
        names=None,
        types=None,
        types_exclude=None,
    )
    redacted = replace_into_session(session, text, entities, config=config, langs=langs)
    return redacted, entities


def _parse_paths(paths: list[str]) -> list[list[str]]:
    """Parse dot-notation paths into segments.

    Example: ``'messages[*].content'`` → ``['messages', '*', 'content']``.
    """
    parsed = []
    for path in paths:
        segments = []
        for part in path.replace("[*]", ".*").split("."):
            # A leading (or doubled) "[*]" turns into an empty segment once split
            # on ".": "[*].phone" -> ".*.phone" -> ['', '*', 'phone']. A top-level
            # list leaf's walk-path never carries that empty prefix, so the path
            # would never match and the leaf silently goes unredacted. Drop empty
            # segments so "[*].phone" behaves the same as "*.phone".
            if part:
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
    if isinstance(paths, str):
        raise TypeError("paths must be a list of path strings, not a str")
    _warn_low_entropy_salt(salt)
    session = make_structured_session(salt=salt, key=key, config=config)
    parsed_paths = _parse_paths(paths) if paths else None
    # Entities accumulate across leaves ONLY to build the with_types map at the
    # end (fake → PII type). The key itself lives in the Rust session.
    all_entities: list = []

    def _walk(obj: Any, current_path: list[str] | None = None) -> Any:
        if current_path is None:
            current_path = []

        if isinstance(obj, str):
            if parsed_paths is not None and not _path_matches(current_path, parsed_paths):
                return obj
            redacted_text, entities = _redact_cell(
                session, obj, mode=mode, lang=lang, config=config
            )
            if with_types:
                all_entities.extend(entities)
            return redacted_text
        if isinstance(obj, dict):
            return {k: _walk(v, current_path + [k]) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(item, current_path + ["*"]) for item in obj]
        return obj

    result = _walk(data)
    # Mirrors the one-shot `replace()` path: warn once, over the
    # WHOLE document's cumulative collisions, before the key is read out — a
    # column of similarly-masked values (e.g. phone numbers) is exactly the
    # highest collision-risk shape this path exists to redact.
    warn_mask_collisions(list(session.mask_collisions))
    combined_key = session.into_key()
    if with_types:
        # Same fake → type map as redact(with_types=True), built once over all
        # leaves' entities against the final key (a repeated original reuses its
        # fake, so per-leaf vs whole-document assembly are identical).
        return result, combined_key, _build_type_map(combined_key, all_entities)
    return result, combined_key


def restore_json(data: dict | list, key: dict) -> dict | list:
    """Restore PII in all string values of a JSON-like structure."""

    def _walk(obj: Any) -> Any:
        if isinstance(obj, str):
            # guard=False: structured restore reverses a stored key file, with no
            # per-call anchor to verify — the explicit unguarded opt-out.
            return restore(obj, key, guard=False)
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


def _parse_csv_rows(csv_text: str) -> list[list[str]]:
    """Parse CSV text into rows. Shared by redact_csv/restore_csv so the two
    stay symmetric (same dialect) and a comma inside a restored value can't
    reshape the columns."""
    return list(csv.reader(io.StringIO(csv_text)))


def _serialize_csv_rows(rows: list[list[str]]) -> str:
    """Serialize rows back to CSV text. rstrip only the writer's trailing line
    terminator — .strip() would also delete non-PII leading whitespace from the
    first cell (silent corruption)."""
    out = io.StringIO()
    csv.writer(out).writerows(rows)
    return out.getvalue().rstrip("\r\n")


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
    rows = _parse_csv_rows(csv_text)

    if not rows:
        return csv_text, {}

    _warn_low_entropy_salt(salt)
    session = make_structured_session(salt=salt, config=config)
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
            redacted_cell, _entities = _redact_cell(
                session, cell, mode=mode, lang=lang, config=config
            )
            redacted_row.append(redacted_cell)
        output_rows.append(redacted_row)

    # Mirrors the one-shot `replace()` path: warn once, over the
    # WHOLE document's cumulative collisions, before the key is read out — a
    # column of similarly-masked values (e.g. phone numbers) is exactly the
    # highest collision-risk shape this path exists to redact.
    warn_mask_collisions(list(session.mask_collisions))
    return _serialize_csv_rows(output_rows), session.into_key()


def restore_csv(csv_text: str, key: dict) -> str:
    """Restore PII in a CSV string.

    Mirrors ``redact_csv``'s parse/reserialize shape instead of doing a blind
    whole-string substring restore: a restored original value that itself
    contains a comma (e.g. ``"Smith, John"``) would otherwise splice an
    unescaped comma into the flat CSV text, splitting one cell into two
    columns and corrupting the row structure on re-parse.
    """
    output_rows: list[list[str]] = []
    for row in _parse_csv_rows(csv_text):
        # guard=False: structured restore reverses a stored key file, with no
        # per-call anchor to verify — the explicit unguarded opt-out (same as
        # restore_json / redact_csv's forward path).
        output_rows.append([restore(cell, key, guard=False) for cell in row])

    return _serialize_csv_rows(output_rows)
