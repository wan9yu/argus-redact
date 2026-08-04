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
`@pytest.mark.ner` and are deselected there. The English ner cells that the zh
evidence detectors gate are pinned structurally instead, which needs no model.
"""

import pytest

from argus_redact import redact
from argus_redact.pure.coverage_table import CATEGORIES, coverage_for

# (category, lang, probe_text) — the probe MUST be redacted at fast mode.
_HAVE_FAST = [
    ("age", "zh", "受访者今年28岁。"),
    ("age", "en", "The subject is 28 years old."),
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
    ("sex", "en", "Gender: female.", "She is a woman."),
    ("income", "zh", "月薪2万元。", "月入三四万。"),
    ("place_of_birth", "zh", "籍贯江苏省。", "籍贯江苏。"),
    ("medical_condition", "zh", "对花生过敏。", "腰椎间盘突出。"),
    ("medical_condition", "en", "Has asthma.", "Has migraines."),
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


def test_the_probes_are_not_vacuous():
    """Positive control: the HAVE assertion must be capable of failing. If
    `_redacted` silently returned its input, every HAVE test above would pass
    while proving nothing."""
    assert _redacted("现居上海市浦东新区。", "zh") != "现居上海市浦东新区。"
    assert _redacted("no pii here at all", "en") == "no pii here at all"


def test_english_gets_nothing_from_the_zh_evidence_detectors():
    """Structural pin for the ner cells that need no model: occupation and
    medical-condition detection are zh-gated by construction (the only
    detectors are `detect_occupation_zh` and `detect_conditions_zh`, and
    `crates/argus-redact-core/data/occupations/` contains only `zh.ron`), so
    the English cells cannot improve without a deliberate new detector."""
    for mode in ("fast", "ner"):
        uncovered, _narrow = coverage_for("en", mode)
        assert "occupation" in uncovered


@pytest.mark.ner
def test_english_location_is_covered_only_at_ner():
    """The one cell that genuinely flips by mode. Marked `ner` because CI has
    no spaCy model."""
    probe = "Lives in Chicago, Illinois."
    assert _redacted(probe, "en", mode="fast") == probe
    assert _redacted(probe, "en", mode="ner") != probe
    uncovered_fast, _ = coverage_for("en", "fast")
    uncovered_ner, _ = coverage_for("en", "ner")
    assert "location" in uncovered_fast
    assert "location" not in uncovered_ner
