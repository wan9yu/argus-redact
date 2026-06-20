"""`_core.detect_person_names_zh` / `_core.detect_person_names_en` bindings.

These PyO3 functions wrap the Rust core person detectors. Until T8 routes the
Python shims through `_core`, the pure-Python detectors (`lang.zh.person`,
`lang.en.person`) are the reference: every expected value below is captured by
running the SAME input through the Python detector, and the binding output must
match it field-for-field (confidence compared with exact `==`, no rounding).
"""

import argus_redact._core as _core
from argus_redact.lang.en.person import detect_person_names as py_en
from argus_redact.lang.zh.person import detect_person_names as py_zh


def _tuples(matches):
    """(text, type, start, end, confidence, layer) for each match, order-preserving."""
    return [(m.text, m.type, m.start, m.end, m.confidence, m.layer) for m in matches]


def _pm(text, type_, start, end, confidence=1.0, layer=1):
    """Build a `_core.PatternMatch` for the pii_entities arg (positional ctor)."""
    return _core.PatternMatch(text, type_, start, end, confidence, layer)


# ── zh: proximity signal fires when a structural PII sits nearby ──────────────


def test_zh_proximity_pii_boosts_confidence():
    text = "张明的电话是13800138000"
    pii = [_pm("13800138000", "phone", 6, 17)]
    out = _core.detect_person_names_zh(text, pii)
    assert isinstance(out, list)
    assert all(isinstance(m, _core.PatternMatch) for m in out)
    # Phone PII adjacent to the name pushes the score to 1.0 (vs 0.8 baseline).
    assert _tuples(out) == [("张明", "person", 0, 2, 1.0, 0)]
    # Must equal the Python detector's output on the same input.
    from argus_redact._types import PatternMatch as PyPM

    py = py_zh(text, pii_entities=[PyPM("13800138000", "phone", 6, 17, 1.0, 1)])
    assert _tuples(out) == _tuples(py)


def test_zh_baseline_without_pii():
    text = "张明的电话是13800138000"
    out = _core.detect_person_names_zh(text)
    assert _tuples(out) == [("张明", "person", 0, 2, 0.8, 0)]
    assert _tuples(out) == _tuples(py_zh(text))


# ── zh: known_names get confidence 1.0, bypassing scoring ─────────────────────


def test_zh_known_names_confidence_one():
    text = "请联系王芳"
    out = _core.detect_person_names_zh(text, None, ["王芳"])
    assert _tuples(out) == [("王芳", "person", 3, 5, 1.0, 0)]
    assert _tuples(out) == _tuples(py_zh(text, known_names=["王芳"]))


# ── zh: a self_reference entity in pii_entities is filtered (no boost) ────────


def test_zh_self_reference_in_pii_is_filtered():
    text = "张明的电话是13800138000"
    # The orchestrator strips type=="self_reference" before proximity scoring,
    # so this entity must NOT boost the name — result equals the 0.8 baseline.
    sr = [_pm("我", "self_reference", 0, 1)]
    out = _core.detect_person_names_zh(text, sr)
    assert _tuples(out) == [("张明", "person", 0, 2, 0.8, 0)]
    # Same as no-pii baseline (proves the self_reference was filtered, and that
    # `type` survived the Python→Rust conversion so the filter could fire).
    assert _tuples(out) == _tuples(_core.detect_person_names_zh(text))

    from argus_redact._types import PatternMatch as PyPM

    py = py_zh(text, pii_entities=[PyPM("我", "self_reference", 0, 1, 1.0, 1)])
    assert _tuples(out) == _tuples(py)


# ── en: known_names get confidence 1.0 ────────────────────────────────────────


def test_en_known_names_confidence_one():
    text = "Contact Alice Johnson today"
    out = _core.detect_person_names_en(text, known_names=["Alice Johnson"])
    assert isinstance(out, list)
    assert all(isinstance(m, _core.PatternMatch) for m in out)
    assert _tuples(out) == [("Alice Johnson", "person", 8, 21, 1.0, 0)]
    assert _tuples(out) == _tuples(py_en(text, known_names=["Alice Johnson"]))


# ── en: surname + given name assembled from the data pools ────────────────────


def test_en_surname_plus_given():
    text = "Please call James Smith now"
    out = _core.detect_person_names_en(text)
    assert _tuples(out) == [("James Smith", "person", 12, 23, 1.0, 0)]
    assert _tuples(out) == _tuples(py_en(text))


# ── defaults: omitting optional args behaves like the Python detector ─────────


def test_zh_defaults_match_python():
    # Omitting pii/known/threshold => empty slices + threshold 0.8.
    text = "张明的电话是13800138000"
    assert _tuples(_core.detect_person_names_zh(text)) == _tuples(py_zh(text))


def test_zh_threshold_default_is_score_threshold():
    # Explicit threshold=0.8 must match the omitted-threshold default.
    text = "张明的电话是13800138000"
    omitted = _core.detect_person_names_zh(text)
    explicit = _core.detect_person_names_zh(text, None, None, 0.8)
    assert _tuples(omitted) == _tuples(explicit)


def test_en_defaults_match_python():
    text = "Please call James Smith now"
    assert _tuples(_core.detect_person_names_en(text)) == _tuples(py_en(text))


def test_empty_text_returns_empty():
    assert _core.detect_person_names_zh("") == []
    assert _core.detect_person_names_en("") == []


# ── Pathological known_names must not crash the process (Python parity) ────────
#
# fancy_regex (regex-automata) caps compiled size at ~10MB, so a multi-MB single
# name (or a large alternation) makes Regex::new return Err. The pre-port Python
# `re` never errors here — it compiles a huge literal and simply finds no match.
# The core used to `panic!` on Err, which surfaces as a PyO3 `PanicException` — a
# `BaseException` that escapes `except Exception`. These tests pin the parity fix:
# the uncompilable name is skipped, normal names still match, and nothing crashes.


def test_en_pathological_known_name_does_not_crash():
    huge = "A" * 500_000
    out = _core.detect_person_names_en("Email Alice please", known_names=[huge, "Alice"])
    assert _tuples(out) == [("Alice", "person", 6, 11, 1.0, 0)]


def test_zh_pathological_known_name_does_not_crash():
    huge = "张" * 500_000
    out = _core.detect_person_names_zh("联系李雷", None, [huge, "李雷"])
    assert _tuples(out) == [("李雷", "person", 2, 4, 1.0, 0)]


def test_redact_pathological_name_does_not_raise_panic():
    """Top-level redact() must not surface a PyO3 PanicException for a huge name."""
    import argus_redact

    huge = "A" * 500_000
    redacted, _key = argus_redact.redact(
        "Email Alice please", lang="en", names=[huge, "Alice"]
    )
    # No crash; the normal name is redacted (replacement differs from the input).
    assert "Alice" not in redacted
