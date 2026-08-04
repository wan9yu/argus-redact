"""`redact(report=True)` must say what this configuration could not have found.

An empty result is ambiguous on its own — "we looked and found nothing" and
"we cannot look for that here" are different claims, and only one of them is
reassuring. The advisory is what separates them.
"""

import json

import pytest

from argus_redact import CoverageAdvisory, redact


def test_report_carries_a_coverage_advisory():
    report = redact("现居上海市浦东新区。", lang="zh", mode="fast", salt=42, report=True)
    assert isinstance(report.coverage, CoverageAdvisory)


def test_exhaustive_is_always_false():
    """A field, not a doc sentence — consumers read fields. It is permanently
    False because the taxonomy is not exhaustive of what can re-identify a
    person, and nothing measured in this project supports claiming otherwise."""
    for lang, mode in (("zh", "fast"), ("en", "fast")):
        report = redact("nothing here", lang=lang, mode=mode, salt=42, report=True)
        assert report.coverage.exhaustive is False


def test_uncovered_and_narrow_are_disjoint():
    report = redact("nothing here", lang="en", mode="fast", salt=42, report=True)
    assert not set(report.coverage.uncovered) & set(report.coverage.narrow)


def test_english_fast_reports_the_categories_it_cannot_see():
    report = redact("Nothing identifying here.", lang="en", mode="fast", salt=42, report=True)
    for expected in ("education", "occupation", "location", "relationship_status"):
        assert expected in report.coverage.uncovered


def test_an_empty_result_still_carries_the_advisory():
    """The whole point: the advisory must be present precisely when nothing was
    found, because that is when a caller is most likely to read silence as
    safety."""
    report = redact("nothing identifying here", lang="en", mode="fast", salt=42, report=True)
    assert report.key == {}
    assert report.layers_used == ()
    assert report.coverage.uncovered


def test_layers_used_reports_the_layers_that_contributed():
    report = redact("现居上海市浦东新区。", lang="zh", mode="fast", salt=42, report=True)
    assert report.layers_used == (1,)


def test_layers_used_is_honest_on_the_pre_detected_path():
    """`layer_stats` is hardcoded to all-zero/skipped on this path
    (glue/redact.py:827-838) even when entities were really detected. Deriving
    `layers_used` from the surviving entities' `.layer` is what keeps it true —
    this test is the one that would have caught the trap."""
    from argus_redact._types import PatternMatch
    from argus_redact.layers import LAYER_NER, LAYER_REGEX

    pre = [
        PatternMatch(
            text="13800138000", type="phone", start=15, end=26, confidence=1.0, layer=LAYER_REGEX
        ),
        PatternMatch(text="张三", type="person", start=0, end=2, confidence=0.9, layer=LAYER_NER),
    ]
    report = redact(
        "张三的手机是13800138000", lang="zh", mode="fast", salt=42, report=True, _pre_detected=pre
    )
    assert report.stats["layer_1"] == 0  # the lie this path tells
    assert report.layers_used == (1, 2)  # the truth, from the entities


def test_coverage_is_none_on_the_pre_detected_path():
    """`coverage` is built from `(lang, mode)` alone — a claim about what an
    argus *detection pass* over this configuration could not have found. On
    the `_pre_detected` path argus runs no detection at all: the caller
    supplied its own entities. Before this test, `coverage_for(lang, mode)`
    ran unconditionally here, so a caller passing `_pre_detected=` got back a
    populated `uncovered`/`narrow` — implicitly asserting that categories like
    age/sex/location/occupation were looked for and missed, when in truth
    nothing was looked for. `None` is the honest value: 'no
    configuration-derived claim applies, because this call's detection did
    not come from argus'."""
    from argus_redact._types import PatternMatch

    pre = [PatternMatch(text="13800138000", type="phone", start=3, end=14, confidence=1.0)]
    report = redact(
        "手机是13800138000", lang="zh", mode="fast", salt=42, report=True, _pre_detected=pre
    )
    assert report.coverage is None


def test_layers_used_keeps_layer_zero_for_an_untagged_pre_detected_entity():
    """`integrations/presidio.py:106-112` builds `PatternMatch` WITHOUT
    `layer=`, so a caller feeding Presidio-bridged entities through
    `_pre_detected` produces entities left at the dataclass default
    `layer=0` — this is the live production case, not a hypothetical. If
    `layers_used` filtered `layer == 0` out (e.g. `{e.layer for e in
    entities if e.layer}`), that caller would get `layers_used == ()`,
    indistinguishable from "nothing was found" — exactly the ambiguity this
    field exists to remove. This test fails under that filtered mutation and
    passes only when layer 0 is kept."""
    from argus_redact._types import PatternMatch

    pre = [PatternMatch(text="13800138000", type="phone", start=3, end=14, confidence=1.0)]
    report = redact(
        "手机是13800138000", lang="zh", mode="fast", salt=42, report=True, _pre_detected=pre
    )
    assert 0 in report.layers_used
    assert report.layers_used == (0,)


def test_stats_stays_json_serialisable():
    """`argus-redact assess` runs json.dumps over report.stats
    (cli/main.py:227-246). A dataclass or enum in there raises TypeError, so the
    advisory and layers_used live on the report, never inside stats."""
    report = redact("现居上海市浦东新区。", lang="zh", mode="fast", salt=42, report=True)
    json.dumps(report.stats)


@pytest.mark.parametrize(
    ("text", "lang"),
    [
        ("客户王建华先生来电，手机号13867251934。", "zh"),
        ("现居上海市浦东新区，今年28岁。", "zh"),
        ("Contact 555-0142 about the invoice.", "en"),
    ],
)
def test_the_advisory_changes_no_redaction_output(text, lang):
    """Neutrality: the advisory is derived from configuration and never touches
    the entity set, so redacted text must be byte-identical to what the plain
    2-tuple call produces. An advisory that could alter output would be a new
    failure surface rather than a disclosure."""
    plain, plain_key = redact(text, lang=lang, mode="fast", salt=42)
    report = redact(text, lang=lang, mode="fast", salt=42, report=True)
    assert report.redacted_text == plain
    assert report.key == plain_key
