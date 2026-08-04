"""The capability table must never claim a detector it does not have.

The table is what makes an empty redaction result readable: a caller who sees
no findings needs to know whether that means "clean" or "we cannot look for
that here". A cell that claims HAVE while the detector is gone turns the
advisory into false reassurance, which is worse than having no advisory.

Every fast-mode cell is therefore pinned to a live `redact()` probe rather than
to a reading of detector source. That choice is not stylistic: four separate
readings of the detector code were contradicted by the probes when this table
was first derived.

`mode="ner"` cells need models CI does not install, so they carry
`@pytest.mark.ner` and are deselected there. Every ner cell is pinned by its
own live probe below — a first draft of this file pinned only two of the
eighteen ner cells and copied the rest from the fast rows in the table module;
that copy was wrong (see `coverage_table.py`'s module docstring for what the
ner-only probes caught). `coverage_for` itself is a pure lookup with no model
dependency, so tests that only call it (not `_redacted(..., mode="ner")`) need
no `ner` marker even when they pass the string `"ner"` as an argument.
"""

import pytest

from argus_redact import redact
from argus_redact.pure.coverage_table import CATEGORIES, coverage_for

# (category, lang, probe_text) — the probe MUST be redacted at fast mode.
# `age` is NOT here — see `_NARROW_FAST`: it hits this exact digit+cue form but
# misses a Chinese-numeral or `了`-suffixed age, so it is pinned as NARROW
# (both edges), not HAVE (one edge only). Coverage_table.py's module docstring
# explains why a `have` cell with a known, reproducible miss is a bug, not a
# nuance.
_HAVE_FAST = [
    ("sex", "zh", "性别：男。"),
    ("location", "zh", "现居上海市浦东新区。"),
    ("occupation", "zh", "职业是后端工程师。"),
]

# (category, lang, probe_text) — the probe MUST come back unchanged at fast mode.
_NONE_FAST = [
    ("education", "zh", "硕士学历。"),
    ("education", "en", "Holds a master's degree."),
    ("relationship_status", "zh", "婚姻状况：已婚。"),
    ("relationship_status", "en", "Is divorced."),
    ("location", "en", "Lives in Chicago, Illinois."),
    ("occupation", "en", "Works as a software engineer."),
    ("income", "en", "My salary is 120000 USD."),
    ("place_of_birth", "en", "Born in Ohio."),
]

# (category, lang, hit_probe, miss_probe) — NARROW means BOTH must hold.
_NARROW_FAST = [
    ("age", "zh", "受访者今年28岁。", "我今年三十五岁了。"),
    ("age", "en", "The subject is 28 years old.", "Age: 42."),
    ("sex", "en", "Gender: female.", "She is a woman."),
    ("income", "zh", "月薪2万元。", "月入三四万。"),
    ("place_of_birth", "zh", "籍贯江苏省。", "籍贯江苏。"),
    ("medical_condition", "zh", "对花生过敏。", "腰椎间盘突出。"),
    ("medical_condition", "en", "Has asthma.", "Has migraines."),
]

# (category, lang, probe_text) — the probe MUST be redacted at ner mode.
# `age` is NOT here for the same reason as `_HAVE_FAST` above (see
# `_NARROW_NER`). `occupation`/en is NONE at ner (see `_NONE_NER`). `medical_condition`/en is
# NARROW at ner (see `_NARROW_NER`). Both are absent from this list and covered by the dedicated
# structural test below, which asserts the fast-vs-ner contrast directly.
# `location`/zh IS one of the cells measured here, not absent from this list.
_HAVE_NER = [
    ("sex", "zh", "性别：男。"),
    ("location", "zh", "现居上海市浦东新区。"),
    ("occupation", "zh", "职业是后端工程师。"),
]

# (category, lang, probe_text) — the probe MUST come back unchanged at ner mode.
# `education`/en is NOT the same text as `_NONE_FAST`: "Holds a master's
# degree." is contaminated at ner — spaCy tags the sentence-initial "Holds" as
# an `organization` entity (confidence 0.85), unrelated to education. That is
# a probe artifact, not education coverage, so a differently-phrased probe is
# used here instead of asserting through the false positive.
_NONE_NER = [
    ("education", "zh", "硕士学历。"),
    ("education", "en", "She holds a master's degree."),
    ("relationship_status", "zh", "婚姻状况：已婚。"),
    ("relationship_status", "en", "Is divorced."),
    ("occupation", "en", "Works as a software engineer."),
    ("income", "en", "My salary is 120000 USD."),
]

# (category, lang, hit_probe, miss_probe) — NARROW means BOTH must hold, at ner.
_NARROW_NER = [
    ("age", "zh", "受访者今年28岁。", "我今年三十五岁了。"),
    ("age", "en", "The subject is 28 years old.", "Age: 42."),
    ("income", "zh", "月薪2万元。", "月入三四万。"),
    ("sex", "en", "Gender: female.", "She is a woman."),
    ("medical_condition", "zh", "对花生过敏。", "腰椎间盘突出。"),
    ("medical_condition", "en", "Has asthma.", "Has migraines."),
    # `place_of_birth`/zh is NOT `have` at ner despite the location entity
    # firing here: it fires when a separator follows the place name but
    # misses the bare `X籍` construction this project's own re-id fixtures use
    # to spell place_of_birth (`江苏籍`, `湖南籍`) — see
    # `test_place_of_birth_is_covered_only_at_ner` and coverage_table.py's
    # module docstring.
    ("place_of_birth", "zh", "籍贯江苏。", "湖南籍。"),
]


def _redacted(text: str, lang: str, mode: str = "fast") -> str:
    out, _key = redact(text, lang=lang, mode=mode, salt=42)
    return out


@pytest.mark.parametrize(("category", "lang", "probe"), _HAVE_FAST)
def test_have_cells_actually_detect(category, lang, probe):
    """A HAVE cell must change the text. Note this asserts CHANGE, not an exact
    output: zh `occupation` over-captures its cue word (`职业是后端工程师。` ->
    `职TITLE-…。`, entity text `业是后端工程师`), a real defect recorded in
    docs/known-issues.md. Asserting an exact string here would lock that defect
    in as expected behaviour."""
    assert category in CATEGORIES
    assert _redacted(probe, lang) != probe, (
        f"table says {category}/{lang}/fast is HAVE, but the probe came back "
        f"unchanged — the detector is gone and the table now lies"
    )


@pytest.mark.parametrize(("category", "lang", "probe"), _NONE_FAST)
def test_none_cells_really_detect_nothing(category, lang, probe):
    assert _redacted(probe, lang) == probe, (
        f"table says {category}/{lang}/fast is NONE, but the probe WAS "
        f"redacted — coverage improved and the table now understates it"
    )
    uncovered, _narrow = coverage_for(lang, "fast")
    assert category in uncovered


@pytest.mark.parametrize(("category", "lang", "hit", "miss"), _NARROW_FAST)
def test_narrow_cells_hit_one_form_and_miss_another(category, lang, hit, miss):
    """NARROW is the easiest classification to rot, because it decays silently
    in both directions. Pin both edges."""
    assert _redacted(hit, lang) != hit, (
        f"{category}/{lang}/fast is NARROW but its hit-probe no longer fires — it has become NONE"
    )
    assert _redacted(miss, lang) == miss, (
        f"{category}/{lang}/fast is NARROW but its miss-probe now fires — "
        f"coverage widened and the cell may be HAVE"
    )
    _uncovered, narrow = coverage_for(lang, "fast")
    assert category in narrow


@pytest.mark.ner
@pytest.mark.parametrize(("category", "lang", "probe"), _HAVE_NER)
def test_have_cells_actually_detect_at_ner(category, lang, probe):
    """The ner counterpart of `test_have_cells_actually_detect`. A cell that
    is HAVE at fast is not guaranteed to stay HAVE at ner by construction —
    it is re-probed here rather than assumed."""
    assert _redacted(probe, lang, mode="ner") != probe, (
        f"table says {category}/{lang}/ner is HAVE, but the probe came back "
        f"unchanged — the detector is gone and the table now lies"
    )


@pytest.mark.ner
@pytest.mark.parametrize(("category", "lang", "probe"), _NONE_NER)
def test_none_cells_really_detect_nothing_at_ner(category, lang, probe):
    assert _redacted(probe, lang, mode="ner") == probe, (
        f"table says {category}/{lang}/ner is NONE, but the probe WAS "
        f"redacted — coverage improved and the table now understates it"
    )
    uncovered, _narrow = coverage_for(lang, "ner")
    assert category in uncovered


@pytest.mark.ner
@pytest.mark.parametrize(("category", "lang", "hit", "miss"), _NARROW_NER)
def test_narrow_cells_hit_one_form_and_miss_another_at_ner(category, lang, hit, miss):
    """NARROW is the easiest classification to rot, because it decays silently
    in both directions. Pin both edges — at ner as well as at fast."""
    assert _redacted(hit, lang, mode="ner") != hit, (
        f"{category}/{lang}/ner is NARROW but its hit-probe no longer fires — it has become NONE"
    )
    assert _redacted(miss, lang, mode="ner") == miss, (
        f"{category}/{lang}/ner is NARROW but its miss-probe now fires — "
        f"coverage widened and the cell may be HAVE"
    )
    _uncovered, narrow = coverage_for(lang, "ner")
    assert category in narrow


def test_the_probes_are_not_vacuous():
    """Negative control: the second assertion below must be capable of
    failing. If `_redacted` were a constant mutator that changed any input
    regardless of content, every `!=`-based HAVE assertion above would pass
    for the wrong reason, proving nothing about real detection — the second
    assertion (a clean probe must come back unchanged) is what would catch
    that.

    The first assertion is a sanity companion, not the guard: an `_redacted`
    reduced to the identity function would already fail every `!=` assertion
    above outright, including this one, so it needs no dedicated canary. Do
    not "clean up" the second assertion on the theory that the first one
    already covers vacuity — it does not."""
    assert _redacted("现居上海市浦东新区。", "zh") != "现居上海市浦东新区。"
    assert _redacted("no pii here at all", "en") == "no pii here at all"


def test_english_gets_nothing_from_the_zh_evidence_detectors():
    """Structural pin for the one ner cell that needs no model: occupation
    detection is zh-gated by construction (the only detector is
    `detect_occupation_zh`, and `crates/argus-redact-core/data/occupations/`
    contains only `zh.ron`), so the English occupation cell cannot improve
    without a deliberate new detector.

    `medical_condition` is NOT gated the same way, despite an earlier version
    of this docstring claiming otherwise: English medical detection is an
    independent regex path (`crates/argus-redact-core/data/en.ron`, the
    `medical` type patterns covering asthma/diabetes/cancer/etc.), unrelated
    to `detect_conditions_zh`. That is exactly why `medical_condition` is
    NARROW rather than NONE for English — see `_NARROW_FAST`/`_NARROW_NER`.
    This test's assertion only ever checked `occupation`, so nothing here
    changes; only the claim in the prose was wrong."""
    for mode in ("fast", "ner"):
        uncovered, _narrow = coverage_for("en", mode)
        assert "occupation" in uncovered


@pytest.mark.ner
def test_english_location_is_covered_only_at_ner():
    """The first cell that genuinely flips by mode. Marked `ner` because CI has
    no spaCy model."""
    probe = "Lives in Chicago, Illinois."
    assert _redacted(probe, "en", mode="fast") == probe
    assert _redacted(probe, "en", mode="ner") != probe
    uncovered_fast, _ = coverage_for("en", "fast")
    uncovered_ner, _ = coverage_for("en", "ner")
    assert "location" in uncovered_fast
    assert "location" not in uncovered_ner


@pytest.mark.ner
def test_place_of_birth_is_covered_only_at_ner():
    """The second cell that flips by mode, in both languages, but NOT to the
    same classification. At fast, coverage is asymmetric and cue-shaped (zh
    needs the full administrative name; en has no signal at all). At ner a
    generic layer-2 location entity fires when a separator follows the place
    name, which is enough to fully cover English (no documented miss) but
    only enough to make zh `narrow`: the same entity misses the bare `X籍`
    construction (pinned as the miss probe in `_NARROW_NER`) that this
    project's own re-id fixtures use to spell place_of_birth. The zh probe
    here is exactly the fast-mode MISS probe, reused to demonstrate the flip
    from `narrow`-at-fast to `narrow`-at-ner-for-a-different-reason; the en
    probe flips from `none` to `have`."""
    zh_probe = "籍贯江苏。"
    en_probe = "Born in Ohio."
    assert _redacted(zh_probe, "zh", mode="fast") == zh_probe
    assert _redacted(zh_probe, "zh", mode="ner") != zh_probe
    assert _redacted(en_probe, "en", mode="fast") == en_probe
    assert _redacted(en_probe, "en", mode="ner") != en_probe

    uncovered_fast_zh, narrow_fast_zh = coverage_for("zh", "fast")
    uncovered_fast_en, _narrow_fast_en = coverage_for("en", "fast")
    uncovered_ner_zh, narrow_ner_zh = coverage_for("zh", "ner")
    uncovered_ner_en, narrow_ner_en = coverage_for("en", "ner")

    assert "place_of_birth" in narrow_fast_zh
    assert "place_of_birth" in uncovered_fast_en
    assert "place_of_birth" not in uncovered_ner_zh
    assert "place_of_birth" in narrow_ner_zh  # narrow at ner too — see _NARROW_NER
    assert "place_of_birth" not in uncovered_ner_en
    assert "place_of_birth" not in narrow_ner_en  # fully `have` at ner for en


def test_coverage_for_unknown_language_returns_everything_sorted():
    """An unknown language is the exact case the fallback branch exists for —
    it must honor the same "both sorted" contract the docstring promises for
    every other row, not fall back to `CATEGORIES`' taxonomy order."""
    uncovered, narrow = coverage_for("fr", "fast")
    assert uncovered == tuple(sorted(CATEGORIES))
    assert narrow == ()


@pytest.mark.parametrize(
    ("lang", "mode"),
    [
        ("zh", "fast"),
        ("zh", "ner"),
        ("en", "fast"),
        ("en", "ner"),
        ("fr", "fast"),
        ("fr", "ner"),
    ],
)
def test_coverage_for_is_always_sorted(lang, mode):
    """No existing test checked sortedness for a known language — only the
    unknown-language branch was broken, but nothing pinned the promise for
    the measured rows either. `coverage_for` takes no model, so this needs no
    `ner` marker even for the `"ner"` mode string."""
    uncovered, narrow = coverage_for(lang, mode)
    assert uncovered == tuple(sorted(uncovered))
    assert narrow == tuple(sorted(narrow))


def test_auto_mode_reads_the_ner_row():
    """`auto` is documented (module docstring) to read the `ner` row, because
    it is ner plus a best-effort LLM pass that contributes nothing when no
    model is served. Pin the equivalence directly: if `"auto"` were ever
    dropped from the `row_mode` check, `auto` would silently read the more
    optimistic `fast` row instead, overstating coverage — the dangerous
    direction. `coverage_for` takes no model, so this needs no `ner` marker."""
    for lang in ("zh", "en", "fr"):
        assert coverage_for(lang, "auto") == coverage_for(lang, "ner")
