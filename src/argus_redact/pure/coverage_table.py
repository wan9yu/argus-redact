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

The `ner` rows are measured independently at `mode="ner"`, not copied from the
`fast` rows with an override — a first draft of this table did exactly that
copy and was wrong: `place_of_birth` was carried over as `narrow` (zh) / `none`
(en) on the theory that ner only adds spaCy's English `location`. Live probes
at ner showed otherwise: a generic layer-2 location entity fires on any
recognized place name (city, province, state) with no birth-specific cue
needed at all — `籍贯江苏。` and `Born in Ohio.`, both misses at fast, both
fire at ner (`type="location", layer=2, confidence=0.85`). That erases the
fast-mode narrow/none distinction in both languages, so `place_of_birth` is
`have` at ner for zh and en alike. See
`tests/architecture/test_coverage_table_honesty.py` for the pinning probes,
including the one that caught this (the fast-mode NARROW miss-probe, reused as
the ner HAVE probe).
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
    # Each ner row below is its own live measurement at mode="ner", not the
    # fast row with an override — see the module docstring for why that
    # distinction matters. Every cell that matches its fast-row counterpart
    # was re-probed, not assumed to carry over.
    ("zh", "ner"): {
        "age": _HAVE,
        "sex": _HAVE,
        "location": _HAVE,
        "occupation": _HAVE,
        "education": _NONE,
        "relationship_status": _NONE,
        "income": _NARROW,
        # Changed from `narrow` at fast: the layer-2 location entity fires on
        # a bare province name with no admin suffix and no `籍贯`-style cue.
        "place_of_birth": _HAVE,
        "medical_condition": _NARROW,
    },
    ("en", "ner"): {
        "age": _HAVE,
        "sex": _NARROW,
        # spaCy's NER supplies `location`, absent at fast.
        "location": _HAVE,
        "occupation": _NONE,
        "education": _NONE,
        "relationship_status": _NONE,
        "income": _NONE,
        # Changed from `none` at fast: the same layer-2 location entity fires
        # on "Born in Ohio." with no birth-specific detector involved.
        "place_of_birth": _HAVE,
        "medical_condition": _NARROW,
    },
}


def coverage_for(lang: str, mode: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return ``(uncovered, narrow)`` for this configuration, both sorted.

    An unknown language returns every category as uncovered — the honest answer
    for a language pack this table has not been measured against. `auto` reads
    the `ner` row; see the module docstring for why it gets no column.
    """
    row_mode = "ner" if mode in ("ner", "auto") else "fast"
    row = _TABLE.get((lang, row_mode))
    if row is None:
        # CATEGORIES is spelled in taxonomy order, not alphabetical — sort it
        # here so an unmeasured language still honors the "both sorted"
        # contract this docstring promises.
        return tuple(sorted(CATEGORIES)), ()
    uncovered = tuple(sorted(c for c, v in row.items() if v == _NONE))
    narrow = tuple(sorted(c for c, v in row.items() if v == _NARROW))
    return uncovered, narrow
