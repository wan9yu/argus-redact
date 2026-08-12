"""Structured data redaction — JSON dicts/lists and CSV strings."""

from __future__ import annotations

import csv
import io
import sys
import warnings
from typing import Any

from argus_redact.exceptions import SecurityWarning
from argus_redact.glue.redact import _build_type_map, _detect
from argus_redact.pure.lang_detect import detect_languages
from argus_redact.pure.replacer import (
    make_structured_session,
    replace_into_session,
    warn_coverage_restored,
    warn_mask_collisions,
)
from argus_redact.pure.restore import make_structured_restorer

__all__ = [
    "redact_json",
    "restore_json",
    "redact_csv",
    "restore_csv",
]

# Cap the recursion depth of the JSON walks so an adversarially (or accidentally)
# deep document fails with a clean, PII-free ``ValueError`` instead of an uncaught
# ``RecursionError``. Each walk level costs ~2 interpreter frames, so this sits
# well under CPython's default 1000-frame recursion limit with margin for the
# caller's own stack; it is far deeper than any real LLM/CSV payload nests. The
# SAME limit is enforced symmetrically on both the redact and restore walks.
_MAX_STRUCTURED_DEPTH = 128


def _cell_has_pii(text: str, *, mode: str, lang: str | list[str]) -> bool:
    """Detect-only PII probe: True if ``text`` carries any detectable entity.

    Runs the SAME detection pipeline ``_redact_cell`` uses (glue ``_detect``) but
    stops BEFORE the replace step — no salt, no pseudonym generation, no key
    mutation, and none of the per-cell ``SecurityWarning``s the replace path
    emits (e.g. the low-entropy-salt one). Shared by the CSV header probe and the
    JSON dict-key / numeric-leaf leak checks so none of them re-run a full
    ``redact()`` (which re-warned per cell and minted a pseudonym it discarded).
    """
    cell_lang = detect_languages(text) if lang == "auto" else lang
    entities, _langs, _timing, _stats = _detect(
        text,
        lang=cell_lang,
        mode=mode,
        names=None,
        types=None,
        types_exclude=None,
    )
    return bool(entities)


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
    restored_types: list[str] | None = None,
) -> tuple[str, list]:
    """Detect PII in one cell/leaf and redact it through the shared session.

    Returns ``(redacted_text, entities)``. Detection reuses the SAME pipeline
    ``redact()`` runs (glue ``_detect``); only the replace step is routed through
    the stateful session so the accumulation key + pseudonym generators stay in
    Rust across cells (O(N) over the document instead of O(N²)).

    ``restored_types``, if given, is MUTATED in place (extended, not
    replaced) with the PII-free type names of any entity the post-merge
    coverage invariant had to re-admit for THIS cell — same out-param idiom
    as ``_detect``. Callers accumulate across cells and warn once per
    document, mirroring ``session.mask_collisions``.
    """
    cell_lang = detect_languages(text) if lang == "auto" else lang
    entities, langs, _timing, _stats = _detect(
        text,
        lang=cell_lang,
        mode=mode,
        names=None,
        types=None,
        types_exclude=None,
        restored_types=restored_types,
    )
    redacted = replace_into_session(session, text, entities, config=config, langs=langs)
    return redacted, entities


def _parse_paths(paths: list[str | list[str]]) -> list[list[str]]:
    """Parse path selectors into segments.

    Each entry is either dot-notation (``'messages[*].content'`` →
    ``['messages', '*', 'content']``) or an already-split list of segments,
    taken verbatim with no ``.``/``[*]`` parsing — the escape hatch for a key
    that literally contains a dot or bracket (``[["a.b"]]`` targets the single
    top-level key ``"a.b"``, which no dot-notation string could reach).
    """
    parsed = []
    for path in paths:
        if isinstance(path, list):
            parsed.append(list(path))
            continue
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


def _seg_matches(current_seg: str, target_seg: str) -> bool:
    """Whether one walk path segment satisfies one target selector segment.

    A ``"*"`` selector matches any segment; otherwise segments must be equal.
    The walk labels EVERY list position ``"*"`` (it does not carry the concrete
    index), so an all-digit selector segment (``users.0.ssn``) is also accepted
    against that ``"*"`` — otherwise a numeric-index path would never match and
    the targeted leaf would silently go unredacted. The consequence, documented
    on ``redact_json``, is that a numeric index behaves as a wildcard: it cannot
    single out one list element (``users.0.ssn`` scopes every ``users[*].ssn``).
    """
    return (
        target_seg == "*"
        or current_seg == target_seg
        or (current_seg == "*" and target_seg.isdigit())
    )


def _matching_targets(current_path: list[str], target_paths: list[list[str]]) -> list[int]:
    """Indices of the target paths that are a *prefix* of ``current_path``.

    A target matches when it is a prefix of current_path, so scoping to
    ``messages[*].content`` redacts every string leaf in that subtree —
    including the block form ``content=[{"type":"text","text": ...}]`` where the
    leaf sits deeper than the path. An exact-depth match would silently skip the
    block form and leak its text. Returns indices (not just a bool) so the caller
    can tell WHICH selectors matched and warn about any that matched nothing.
    """
    hits: list[int] = []
    for i, target in enumerate(target_paths):
        if len(current_path) < len(target):
            continue
        if all(_seg_matches(c, t) for c, t in zip(current_path, target)):
            hits.append(i)
    return hits


def redact_json(
    data: dict | list,
    *,
    mode: str = "fast",
    lang: str | list[str] = "zh",
    salt: int | bytes | None = None,
    config: dict | None = None,
    key: dict | None = None,
    paths: list[str | list[str]] | None = None,
    with_types: bool = False,
    with_aliases: bool = False,
) -> (
    tuple[dict | list, dict] | tuple[dict | list, dict, dict] | tuple[dict | list, dict, dict, dict]
):
    """Redact PII in string and numeric leaf VALUES of a JSON-like structure.

    Scope: string and numeric (int/float) leaves are redacted; dict KEYS are
    preserved verbatim — they are structural identifiers (like a CSV header),
    and rewriting them would reshape the document and break the restore
    mapping. A numeric leaf (e.g. a national-ID or phone stored as a JSON
    ``number``, not a string) is coerced to ``str`` for DETECTION only: a leaf
    with no detectable PII passes through completely unchanged (its original
    ``int``/``float`` type and exact value, including arbitrary-precision
    ints, survive byte-for-byte); a leaf that DOES carry PII is redacted into
    a placeholder string, same as a string leaf — a redacted leaf legitimately
    changes type, since the placeholder is text. A PII-carrying dict KEY is
    not similarly redactable (rewriting it would reshape the document) and
    instead emits a (PII-free, count-only) ``SecurityWarning`` — move the
    value into a leaf to have it redacted.

    Args:
        paths: If specified, only redact leaves in these subtrees (string or
            numeric). Each entry is either dot-notation (``'messages[*].content'``)
            or a pre-split list of segments (``["a.b"]``) for a key that
            literally contains ``.``/``[*]`` and is unreachable by dot-notation.
            A numeric list-index segment (``users.0.ssn``) behaves as a
            wildcard — it scopes EVERY element of that list (``users[*].ssn``),
            because the walk does not carry concrete indices; it cannot single
            out one element. A selector that matches no leaf in a non-empty
            document emits a ``SecurityWarning`` (a likely typo silently
            redacting nothing).
        with_types: If True, append a ``types`` map (replacement → PII type).
        with_aliases: If True, append an ``aliases`` map (fake →
            alternate-transliteration tuple) so a realistic-strategy round-trip
            can restore an LLM that rewrote a fake into one of its aliases —
            pass it to ``restore_json(..., aliases=...)``. Mirrors the batch
            ``redact()``/``restore()`` and streaming alias contract.

    Returns:
        ``(data, key)``; with ``with_types`` a ``types`` element is appended;
        with ``with_aliases`` an ``aliases`` element is appended AFTER ``types``.
        So the widest shape is ``(data, key, types, aliases)``. The default
        2-tuple is unchanged, so existing 2-/3-tuple callers keep working.

    Raises:
        ValueError: if the document nests deeper than ``_MAX_STRUCTURED_DEPTH``.
    """
    if isinstance(paths, str):
        raise TypeError("paths must be a list of path strings, not a str")
    _warn_low_entropy_salt(salt)
    session = make_structured_session(salt=salt, key=key, config=config)
    parsed_paths = _parse_paths(paths) if paths else None
    # Entities accumulate across leaves ONLY to build the with_types map at the
    # end (fake → PII type). The key itself lives in the Rust session.
    all_entities: list = []
    # Same accumulate-then-warn-once shape as mask_collisions below — the
    # post-merge coverage invariant is evaluated per cell (_redact_cell), so
    # this collects every cell's restored types for one document-level warning.
    restored_types: list[str] = []
    # Mutation-only accumulators (no `nonlocal` needed): the recursive `_walk`
    # only ever appends/updates these, and the outer body reads them once after
    # the walk to warn a SINGLE time per document — the same shape as
    # mask_collisions. Counts (not values) keep the warnings PII-free.
    pii_key_hits: list[int] = []
    matched_targets: set[int] = set()
    leaf_seen: list[bool] = []
    # `mode`/`lang` are constant for the whole walk, so `_cell_has_pii(k, ...)`
    # is a pure function of the key string — cache it so a key repeated across
    # array elements (a common JSON shape) is detected once, not once per
    # occurrence. Does not change `pii_key_hits`: the same key always maps to
    # the same bool, so the warning's count is identical either way.
    _key_pii_cache: dict[str, bool] = {}

    def _redact_leaf(obj: Any, probe: str, current_path: list[str]) -> Any:
        """Redact one string or numeric leaf. ``probe`` is the text detection runs
        over: the string itself for a string leaf, ``str(obj)`` for a numeric one.

        Returns the redacted placeholder text, or the ORIGINAL ``obj`` when the
        leaf is outside ``paths=`` scope or carries no detectable PII. Returning
        ``obj`` (not the ``probe``) keeps a no-PII numeric leaf byte-for-byte —
        exact type (int vs float) and arbitrary-precision int value — and is a
        no-op for a string leaf (a no-PII redact leaves the text unchanged).
        """
        leaf_seen.append(True)
        if parsed_paths is not None:
            hits = _matching_targets(current_path, parsed_paths)
            if not hits:
                return obj
            matched_targets.update(hits)
        redacted_text, entities = _redact_cell(
            session, probe, mode=mode, lang=lang, config=config, restored_types=restored_types
        )
        if not entities:
            return obj
        if with_types:
            all_entities.extend(entities)
        return redacted_text

    def _walk(obj: Any, current_path: list[str] | None = None, depth: int = 0) -> Any:
        if current_path is None:
            current_path = []
        if depth > _MAX_STRUCTURED_DEPTH:
            raise ValueError(
                f"structured JSON exceeds the maximum nesting depth "
                f"({_MAX_STRUCTURED_DEPTH}); refusing to recurse further"
            )

        if isinstance(obj, str):
            return _redact_leaf(obj, obj, current_path)
        # bool is a subclass of int — check it FIRST so True/False are never
        # scanned as a numeric PII leaf.
        if isinstance(obj, bool):
            return obj
        if isinstance(obj, (int, float)):
            # Coerce-and-scan (v0.8.10): probe/redact the str(obj) form the same
            # way a string leaf is (shared `_redact_leaf`), so a numeric
            # national-ID/phone leaf is no longer a silent leak. A leaf outside
            # `paths=` scope or with no detectable PII is left completely
            # untouched — `_redact_leaf` returns the ORIGINAL object, preserving
            # exact type (int vs float) and precision (arbitrary-size Python ints
            # round-trip byte-for-byte).
            return _redact_leaf(obj, str(obj), current_path)
        if isinstance(obj, dict):
            # Keys recurse only over VALUES (keys are preserved), so a PII key
            # would leak verbatim. Detect (detect-only, no redaction) and count
            # for the one document-level warning below.
            for k in obj:
                if not isinstance(k, str):
                    continue
                if k not in _key_pii_cache:
                    _key_pii_cache[k] = _cell_has_pii(k, mode=mode, lang=lang)
                if _key_pii_cache[k]:
                    pii_key_hits.append(1)
            return {k: _walk(v, current_path + [k], depth + 1) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(item, current_path + ["*"], depth + 1) for item in obj]
        return obj

    result = _walk(data)
    # Mirrors the one-shot `replace()` path: warn once, over the
    # WHOLE document's cumulative collisions, before the key is read out — a
    # column of similarly-masked values (e.g. phone numbers) is exactly the
    # highest collision-risk shape this path exists to redact.
    warn_mask_collisions(list(session.mask_collisions))
    warn_coverage_restored(restored_types)
    _warn_structured_leaks(
        pii_key_hits=len(pii_key_hits),
        paths=paths,
        parsed_paths=parsed_paths,
        matched_targets=matched_targets,
        saw_leaf=bool(leaf_seen),
    )
    combined_key = session.into_key()
    extras: list = []
    if with_types:
        # Same fake → type map as redact(with_types=True), built once over all
        # leaves' entities against the final key (a repeated original reuses its
        # fake, so per-leaf vs whole-document assembly are identical).
        extras.append(_build_type_map(combined_key, all_entities))
    if with_aliases:
        extras.append(_session_aliases(session))
    return (result, combined_key, *extras)


def _warn_structured_leaks(
    *,
    pii_key_hits: int,
    paths: list[str | list[str]] | None,
    parsed_paths: list[list[str]] | None,
    matched_targets: set[int],
    saw_leaf: bool,
) -> None:
    """Emit the document-level leak-visibility warnings for ``redact_json``.

    One warning per class, PII-free (counts, or the caller's own selector
    strings — never a PII value). Kept out of ``redact_json``'s body so the walk
    reads as one thing and the warning policy as another. Numeric leaves are no
    longer a separate warning class here — since v0.8.10 they are coerced and
    scanned like string leaves (see the ``(int, float)`` branch of ``_walk``),
    so a numeric leaf carrying PII is redacted rather than merely flagged.
    """
    if pii_key_hits:
        warnings.warn(
            f"redact_json: {pii_key_hits} dict key(s) carry detectable PII and were "
            f"NOT redacted — keys are preserved verbatim as structural identifiers. "
            f"Move the value into a string leaf to redact it.",
            SecurityWarning,
            stacklevel=3,
        )
    if parsed_paths is not None and saw_leaf and paths is not None:
        unmatched = [paths[i] for i in range(len(parsed_paths)) if i not in matched_targets]
        if unmatched:
            warnings.warn(
                f"redact_json: path selector(s) matched no leaf in a non-empty "
                f"document (nothing redacted for them): {unmatched}",
                SecurityWarning,
                stacklevel=3,
            )


def _session_aliases(session) -> dict[str, tuple[str, ...]]:
    """Read the structured session's accumulated ``{fake: aliases}`` map in the
    tuple-valued shape ``restore(..., aliases=...)`` / ``make_structured_restorer``
    expect — the same shape the batch ``redact()`` and streaming faces return."""
    return {k: tuple(v) for k, v in session.aliases.items()}


def restore_json(
    data: dict | list, key: dict, *, aliases: dict[str, tuple[str, ...]] | None = None
) -> dict | list:
    """Restore PII in all string values of a JSON-like structure.

    ``aliases`` mirrors ``restore(text, key, aliases=...)`` and ``StreamingRestorer``:
    the ``{fake: alternate-transliterations}`` map ``redact_json(..., with_aliases=True)``
    returns, so an LLM that rewrote a realistic fake into one of its aliases still
    round-trips. Without it those alias forms would silently stay unrestored.

    UNGUARDED by design: unlike ``restore()`` / ``restore_guarded()`` (guarded by
    default since v0.8.0), ``restore_json`` has no per-call anchor to check — it is
    a stored key file substituted mechanically over a document, with no provenance
    or scope check. This is a deliberate scope decision, not an oversight: adding a
    guard here would need a per-anchor scope threaded through every leaf, which is
    a cross-layer redesign (see ``docs/stability-contract.md``), not a parameter
    add. If a leaf came from an LLM reply you don't fully trust, buffer it and call
    ``guarded_restore()`` on the plain text yourself instead.

    Known limitation: a benign string leaf that happens to COINCIDENTALLY equal one
    of ``key``'s pseudonym codes (or a mask/category label) is indistinguishable
    from a real placeholder and IS restored to that entity's original — there is no
    per-leaf marker recording which spans this function itself produced. This is
    inherent to any placeholder-substitution scheme, not specific to JSON.

    Raises:
        ValueError: if the document nests deeper than ``_MAX_STRUCTURED_DEPTH``
            (the SAME symmetric limit ``redact_json`` enforces).
    """
    # The session restores unguarded — a stored key file, no per-call anchor to
    # verify — the same explicit unguarded opt-out `restore(..., guard=False)`
    # documents, but merges the key + compiles the pattern ONCE for the whole
    # document instead of on every leaf.
    session = make_structured_restorer(key, aliases=aliases)

    def _walk(obj: Any, depth: int = 0) -> Any:
        if depth > _MAX_STRUCTURED_DEPTH:
            raise ValueError(
                f"structured JSON exceeds the maximum nesting depth "
                f"({_MAX_STRUCTURED_DEPTH}); refusing to recurse further"
            )
        if isinstance(obj, str):
            return session.restore_cell(obj)
        if isinstance(obj, dict):
            return {k: _walk(v, depth + 1) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(item, depth + 1) for item in obj]
        return obj

    return _walk(data)


def _row_has_pii(row: list[str], *, mode: str, lang: str | list[str]) -> bool:
    """True if any cell in the row carries detectable PII.

    Uses the detect-only ``_cell_has_pii`` probe rather than a full ``redact()``:
    the header probe only needs a yes/no signal, so running the whole replace
    pipeline per header cell (which re-emitted the low-entropy-salt warning once
    per cell and minted a pseudonym it immediately discarded) was pure waste.
    """
    return any(_cell_has_pii(cell, mode=mode, lang=lang) for cell in row)


def _parse_csv_rows(csv_text: str) -> list[list[str]]:
    """Parse CSV text into rows. Shared by redact_csv/restore_csv so the two
    stay symmetric (same dialect) and a comma inside a restored value can't
    reshape the columns.

    ``csv.field_size_limit`` (default 128 KiB) is raised to ``sys.maxsize`` for
    the parse and restored afterwards: a single cell over that limit otherwise
    raises an uncaught ``_csv.Error`` (naming the byte count — PII-adjacent).
    Bumping it here fixes BOTH faces at once and with the IDENTICAL limit, since
    ``redact_csv`` and ``restore_csv`` share this one parser. The limit is a
    process-global, so the previous value is restored in ``finally`` and a
    concurrent parse can never observe it unbounded past this call."""
    old_limit = csv.field_size_limit()
    try:
        # 2**31-1, not sys.maxsize: a C long is 32-bit on Windows (LLP64), so
        # csv.field_size_limit(sys.maxsize) raises OverflowError there. 2 GB per
        # field is still far past any real cell, and safe on every platform.
        csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
        return list(csv.reader(io.StringIO(csv_text)))
    finally:
        csv.field_size_limit(old_limit)


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
    with_aliases: bool = False,
) -> tuple[str, dict] | tuple[str, dict, dict]:
    """Redact PII in a CSV string.

    Args:
        has_header: When True (default) the first row is treated as a header and
            preserved verbatim. Pass ``has_header=False`` for a headerless CSV so
            the first row is redacted too — otherwise its data leaks. When the
            preserved header row itself carries detectable PII (a sign the CSV is
            actually headerless), a ``SecurityWarning`` is emitted.
        with_aliases: If True, append an ``aliases`` map (fake →
            alternate-transliteration tuple) — pass it to
            ``restore_csv(..., aliases=...)`` so a realistic-strategy round-trip
            restores an LLM that rewrote a fake into one of its aliases. Mirrors
            ``redact_json(with_aliases=...)``. The default 2-tuple is unchanged.

    Returns:
        ``(redacted_csv, key)``; with ``with_aliases`` an ``aliases`` element is
        appended → ``(redacted_csv, key, aliases)``.
    """
    rows = _parse_csv_rows(csv_text)

    if not rows:
        return (csv_text, {}, {}) if with_aliases else (csv_text, {})

    _warn_low_entropy_salt(salt)
    session = make_structured_session(salt=salt, config=config)
    output_rows: list[list[str]] = []
    data_rows = rows
    # Same accumulate-then-warn-once shape as mask_collisions below.
    restored_types: list[str] = []

    if has_header:
        output_rows.append(rows[0])  # preserve header verbatim
        data_rows = rows[1:]
        if _row_has_pii(rows[0], mode=mode, lang=lang):
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
                session, cell, mode=mode, lang=lang, config=config, restored_types=restored_types
            )
            redacted_row.append(redacted_cell)
        output_rows.append(redacted_row)

    # Mirrors the one-shot `replace()` path: warn once, over the
    # WHOLE document's cumulative collisions, before the key is read out — a
    # column of similarly-masked values (e.g. phone numbers) is exactly the
    # highest collision-risk shape this path exists to redact.
    warn_mask_collisions(list(session.mask_collisions))
    warn_coverage_restored(restored_types)
    redacted_csv = _serialize_csv_rows(output_rows)
    if with_aliases:
        return redacted_csv, session.into_key(), _session_aliases(session)
    return redacted_csv, session.into_key()


def restore_csv(
    csv_text: str, key: dict, *, aliases: dict[str, tuple[str, ...]] | None = None
) -> str:
    """Restore PII in a CSV string.

    Mirrors ``redact_csv``'s parse/reserialize shape instead of doing a blind
    whole-string substring restore: a restored original value that itself
    contains a comma (e.g. ``"Smith, John"``) would otherwise splice an
    unescaped comma into the flat CSV text, splitting one cell into two
    columns and corrupting the row structure on re-parse.

    ``aliases`` mirrors ``restore_json(..., aliases=...)`` / ``StreamingRestorer``:
    the ``{fake: alternate-transliterations}`` map ``redact_csv(..., with_aliases=True)``
    returns, so an LLM that rewrote a realistic fake into one of its aliases still
    round-trips (without it those alias forms stay unrestored).

    UNGUARDED by design: unlike ``restore()`` / ``restore_guarded()`` (guarded by
    default since v0.8.0), ``restore_csv`` has no per-call anchor to check — see
    ``restore_json``'s docstring for the same scope decision and its rationale.

    Known limitation: a benign cell that happens to COINCIDENTALLY equal one of
    ``key``'s pseudonym codes (or a mask/category label) is indistinguishable from
    a real placeholder and IS restored to that entity's original — see
    ``restore_json``'s docstring; the same inherent hazard applies here.

    Line-terminator note: for a NON-EMPTY ``key`` this reserializes through
    Python's ``csv`` module, which writes its own line terminator (``\\r\\n``)
    regardless of what ``csv_text`` used, and the result never carries a
    trailing terminator (see ``_serialize_csv_rows``) — a restore can therefore
    change line endings even when no cell changed. An EMPTY ``key`` restores
    nothing, so that round trip is skipped entirely: the input is returned
    completely unchanged, byte-for-byte, terminator included.
    """
    if not key:
        # Fast path: nothing to restore (an empty key can never substitute
        # anything — see `merge_aliases`, which also requires a `key` entry
        # for any `aliases` to attach to), so skip the csv parse/reserialize
        # round trip entirely rather than pay its terminator-normalizing cost
        # for a no-op. Mirrors `redact_csv`'s own no-op-input short circuit.
        return csv_text

    # The session restores unguarded — a stored key file, no per-call anchor to
    # verify — the same explicit unguarded opt-out `restore(..., guard=False)`
    # documents (same as restore_json / redact_csv's forward path), but merges
    # the key + compiles the pattern ONCE for the whole document instead of on
    # every cell.
    session = make_structured_restorer(key, aliases=aliases)
    output_rows: list[list[str]] = []
    for row in _parse_csv_rows(csv_text):
        output_rows.append([session.restore_cell(cell) for cell in row])

    return _serialize_csv_rows(output_rows)
