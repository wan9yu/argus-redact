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

Three cell values, and what each one actually claims:

- `none` (feeds `CoverageAdvisory.uncovered`): no probe pinned for this cell
  fires under any phrasing this table has tried.
- `narrow` (feeds `CoverageAdvisory.narrow`): the table pins BOTH a hit probe
  that fires and a miss probe that doesn't, so the boundary between the two is
  documented, not merely suspected.
- `have`: absent from both tuples above. Read that absence literally — it
  means the ONE probe pinned for this cell in
  `tests/architecture/test_coverage_table_honesty.py` fires under its exact
  probed phrasing. It is a statement about that probe, not a guarantee that
  every phrasing of the category is caught: a `have` cell can still leave a
  realistic input untouched if no test here happens to probe that phrasing.
  `have` is not "fully covered"; it is "narrow" for which no miss has been
  pinned yet. Find a reproducible miss for a `have` cell, and the honest move
  is to add the miss probe and reclassify to `narrow` — not to leave `have`
  standing next to a known counter-example.

That last point is not a hedge added after the fact — it is why `age` is
`narrow`, not `have`, in every row measured (zh and en, fast and ner). A
labelled or reformatted age (`"Age: 42"` in English; a Chinese-numeral or
`周岁`-suffixed age in Chinese) is left untouched at every measured
configuration, the same shape of gap that already made `sex` `narrow`: one
phrasing fires, a same-category phrasing right next to it does not. An earlier
draft of this table called that combination `have` for `age` while calling the
mirror-image combination `narrow` for `sex` — the same shape of evidence
producing two different verdicts. See `_NARROW_FAST` / `_NARROW_NER` in the
test module for the exact hit/miss probes.

`mode="auto"` deliberately has no column of its own: it is `ner` plus a
best-effort Ollama pass that contributes nothing when no model is served.
Giving it a column would claim Layer-3 coverage a deployment may not have, so
it reads the `ner` row. (An unreachable Layer-3 model now reports
`layer_3_status="error"` rather than the `"ok"` an earlier version of this
docstring described, but the table still reads the `ner` row: a served model
that simply finds nothing is indistinguishable from one with no coverage for
the category, and this table is about capability, not about one call.)

The `ner` rows are measured independently at `mode="ner"`, not copied from the
`fast` rows with an override — a first draft of this table did exactly that
copy and was wrong: `place_of_birth` was carried over as `narrow` (zh) / `none`
(en) on the theory that ner only adds spaCy's English `location`. Live probes
at ner showed a real change instead: a generic layer-2 location entity fires
on many recognized place names with no birth-specific cue needed at all —
`籍贯江苏。` and `Born in Ohio.`, both misses at fast, both fire at ner
(`type="location", layer=2, confidence=0.85`). That is NOT "fires on any
recognized place name", though an earlier draft of this docstring claimed
exactly that: `湖南籍。` and `他是湖南籍。` — the same bare `X籍` construction
this project's own re-identification fixtures use to spell `place_of_birth`
(`tests/benchmark/fixtures/reid_profiles.json` has `江苏籍`, `湖南籍`) — pass
through UNTOUCHED at ner. The entity fires when a separator follows the place
name (`籍贯江苏。`, `湖南籍，28岁。`) and misses the bare `X籍` construction
with no separator after it. English `place_of_birth` has no such documented
miss, so it stays `have` at ner; Chinese `place_of_birth` is `narrow` at ner
for exactly this reason — the fixtures' own preferred phrasing is the miss
probe. See `tests/architecture/test_coverage_table_honesty.py` for the pinning
probes, including the one that caught the original ner/fast divergence (the
fast-mode NARROW miss-probe, reused as the ner hit probe).
"""

from __future__ import annotations

from argus_redact._types import CoverageAdvisory

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
        # `narrow`, not `have`: fires on the digit+cue form pinned as the
        # `_NARROW_FAST` hit probe, misses a Chinese-numeral or `了`-suffixed
        # age — see the module docstring for why this is no longer `have`.
        "age": _NARROW,
        "sex": _HAVE,
        "location": _HAVE,
        "occupation": _HAVE,
        # `none` measures the education TAXONOMY attribute the way the re-id
        # fixtures spell it — degree level (`硕士学历。` passes through
        # untouched). It does not mean education-adjacent text is invisible:
        # `毕业于清华大学` ("graduated from Tsinghua University") fires, but as
        # `type="school", layer=1` — a different, adjacent detector, not an
        # education one. Read "no detector at all" as scoped to the taxonomy
        # attribute, not to every string a human would call education-related.
        "education": _NONE,
        "relationship_status": _NONE,
        "income": _NARROW,
        "place_of_birth": _NARROW,
        "medical_condition": _NARROW,
    },
    ("en", "fast"): {
        # `narrow`, not `have`: fires on full prose ("... years old"), misses
        # the labelled form ("Age: 42") — the mirror image of `sex` below, and
        # the pair the module docstring uses to explain why `have` changed
        # meaning.
        "age": _NARROW,
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
        "age": _NARROW,  # same hit/miss asymmetry as fast, re-probed at ner.
        "sex": _HAVE,
        "location": _HAVE,
        "occupation": _HAVE,
        "education": _NONE,  # same scoped "none" as the fast row above.
        "relationship_status": _NONE,
        "income": _NARROW,
        # `narrow`, not `have`: the layer-2 location entity fires when a
        # separator follows the place name (`籍贯江苏。`) but misses the bare
        # `X籍` construction (`湖南籍。`) this project's own re-id fixtures use
        # to spell place_of_birth — see the module docstring.
        "place_of_birth": _NARROW,
        "medical_condition": _NARROW,
    },
    ("en", "ner"): {
        "age": _NARROW,  # same hit/miss asymmetry as fast, re-probed at ner.
        "sex": _NARROW,
        # spaCy's NER supplies `location`, absent at fast.
        "location": _HAVE,
        "occupation": _NONE,
        "education": _NONE,
        "relationship_status": _NONE,
        "income": _NONE,
        # Changed from `none` at fast: the same layer-2 location entity fires
        # on "Born in Ohio." with no birth-specific detector involved. No
        # documented miss for English (unlike zh, above), so this stays `have`.
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


def coverage_for_langs(lang: str | list[str], mode: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Combine per-language coverage across every active language pack.

    ``redact(lang=["zh", "en"], ...)`` runs BOTH packs. A category is `have`
    in the combined result only if it is `have` in EVERY active pack; if any
    active pack has it as `none`, the combine reports `none` regardless of
    what another pack found; otherwise it is `narrow`. This is elementwise
    and pessimistic on purpose: crediting coverage from one active pack while
    staying silent about another active pack having no detector at all for
    the same category is exactly the "silence read as safety" failure
    `CoverageAdvisory` exists to close, reintroduced at the multi-language
    seam. Concretely, `occupation` is `have` for zh (cue-anchored to Chinese
    words) and `none` for en — a `lang=["zh", "en"]` call must report
    `occupation` as not covered, because the English half of that call has
    no detector for it, no matter what the Chinese half found.

    Accepts the same ``str | list[str]`` shape ``redact()``'s own ``lang``
    parameter does, so a caller can pass either directly. ``coverage_for`` is
    an O(1) dict lookup, so combining N active packs costs nothing that
    matters.
    """
    langs = [lang] if isinstance(lang, str) else list(lang)
    if not langs:
        langs = ["zh"]
    uncovered: set[str] = set()
    narrow: set[str] = set()
    for one_lang in langs:
        pack_uncovered, pack_narrow = coverage_for(one_lang, mode)
        uncovered.update(pack_uncovered)
        narrow.update(pack_narrow)
    narrow -= uncovered  # `none` in one pack outranks `narrow` in another
    return tuple(sorted(uncovered)), tuple(sorted(narrow))


def coverage_advisory(
    lang: str | list[str], mode: str, *, ran_detection: bool
) -> CoverageAdvisory | None:
    """Build the ``RedactReport.coverage`` field for one ``redact()`` call.

    ``ran_detection=False`` returns ``None``. That is the ``_pre_detected``
    path: the caller supplied its own entities and argus ran no detection at
    all, so a (lang, mode) capability claim would assert that this
    configuration looked for — and didn't find — every category the table
    lists as uncovered/narrow, when in truth argus never looked. Only build
    the advisory when detection actually ran through this configuration.
    """
    if not ran_detection:
        return None
    uncovered, narrow = coverage_for_langs(lang, mode)
    return CoverageAdvisory(uncovered=uncovered, narrow=narrow)


def layers_used(entities) -> tuple[int, ...]:
    """The sorted, deduped set of layers that produced the surviving entities.

    Derived from each entity's own ``.layer``, not from ``layer_stats``: the
    ``_pre_detected`` branch of ``redact()`` hardcodes ``layer_stats`` to
    all-zero/skipped even when entities were really detected, while
    ``.layer`` is correct on every path (see ``glue/redact.py``).

    Layer 0 is KEPT, not filtered out. A caller-supplied entity that never
    set ``layer`` (the Presidio bridge builds ``PatternMatch`` without it)
    lands at 0, and dropping those would report ``()`` — indistinguishable
    from "nothing was found", which is precisely the ambiguity this field
    exists to remove. ``(0,)`` says "entities came from a source that did not
    tag its layer"; ``()`` says "there were none".
    """
    return tuple(sorted({e.layer for e in entities}))
