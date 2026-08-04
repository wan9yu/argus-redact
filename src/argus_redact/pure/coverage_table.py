"""What each configuration CANNOT find — the denominator that makes an empty
result readable.

This table answers "what could this call not have found", never "what survived
this document". It is derived from (lang, mode) alone and does not inspect the
text. That distinction is why the object it feeds is called `CoverageAdvisory`
and not `ResidualAdvisory`.

The table is HAND-AUTHORED, and the reason is stronger than "generated tables
drift". A table generated from the spec registry would be wrong in BOTH
directions before a single detector changed: `lookup('location')` and
`lookup('gender')` both return `[]`, yet both types are detected AND removed by
default, because `pure/replacer.py:94` falls back to `"remove"` for unknown
types. A registry-derived table would print a false "no detector" for a type
that is fully handled. Machine generation would not have prevented that bug —
the generator would have been pointed at the wrong source of truth. What makes
a table honest is being pinned to a live detection, which is what
`tests/architecture/test_coverage_table_honesty.py` does.

`mode="auto"` deliberately has no column of its own: it is `ner` plus a
best-effort Ollama pass that contributes nothing when no model is served, while
still reporting `layer_3_status="ok"`. Giving it a column would claim Layer-3
coverage a deployment may not have, so it reads the `ner` row.
"""

from __future__ import annotations

# The 9 standard inference attributes, spelled as the project's own re-id
# fixtures spell them (tests/benchmark/fixtures/reid_profiles.json). Note the
# taxonomy word is `sex`; argus's internal type name for it is `gender`.
CATEGORIES: tuple[str, ...] = (
    "age",
    "sex",
    "location",
    "occupation",
    "education",
    "relationship_status",
    "income",
    "place_of_birth",
    "medical_condition",
)

_HAVE = "have"
_NARROW = "narrow"
_NONE = "none"

# (lang, mode-row) -> {category: classification}. `auto` reads the `ner` row.
_TABLE: dict[tuple[str, str], dict[str, str]] = {
    ("zh", "fast"): {
        "age": _HAVE,
        "sex": _HAVE,
        "location": _HAVE,
        "occupation": _HAVE,
        "education": _NONE,
        "relationship_status": _NONE,
        "income": _NARROW,
        "place_of_birth": _NARROW,
        "medical_condition": _NARROW,
    },
    ("en", "fast"): {
        "age": _HAVE,
        "sex": _NARROW,
        "location": _NONE,
        "occupation": _NONE,
        "education": _NONE,
        "relationship_status": _NONE,
        "income": _NONE,
        "place_of_birth": _NONE,
        "medical_condition": _NARROW,
    },
}
# zh gains nothing at ner: every zh detector above is L1/L1b.
_TABLE[("zh", "ner")] = dict(_TABLE[("zh", "fast")])
# en gains exactly one cell at ner: spaCy supplies `location`.
_TABLE[("en", "ner")] = {**_TABLE[("en", "fast")], "location": _HAVE}


def coverage_for(lang: str, mode: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return ``(uncovered, narrow)`` for this configuration, both sorted.

    An unknown language returns every category as uncovered — the honest answer
    for a language pack this table has not been measured against. `auto` reads
    the `ner` row; see the module docstring for why it gets no column.
    """
    row_mode = "ner" if mode in ("ner", "auto") else "fast"
    row = _TABLE.get((lang, row_mode))
    if row is None:
        return CATEGORIES, ()
    uncovered = tuple(sorted(c for c, v in row.items() if v == _NONE))
    narrow = tuple(sorted(c for c, v in row.items() if v == _NARROW))
    return uncovered, narrow
