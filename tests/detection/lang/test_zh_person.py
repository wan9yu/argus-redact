"""Tests for Chinese person name detection — public ``detect_person_names``.

Candidate generation + evidence scoring (surname + 1-2 CJK minus the negative
dict; PII proximity / context-prefix / honorific-suffix / name-length signals;
2-char vs 3-char variant resolution + swallow detection; the ±20 context window
and 50 / 150 PII-proximity tiers) now live in the Rust ``person_zh`` detector.
Their unit coverage moved to ``crates/argus-redact-core/.../person_zh.rs``
``#[cfg(test)]`` (and the bit-identity is locked by
``test_person_golden_v076.py``); the former Python unit-test classes
(``TestCandidateGeneration`` / ``TestNegativeDict`` / ``TestEvidenceScoring`` /
``TestScoringWindowConstants``) tested removed module internals
(``generate_candidates`` / ``score_candidate`` / ``NameCandidate``) and were
dropped when ``lang/zh/person.py`` became a thin ``_core`` shim. What remains
here is the end-to-end behavior through the public API.
"""


# ── Integration: detect_person_names (full pipeline) ──


class TestDetectPersonNames:
    """End-to-end: text + existing PII → confirmed person entities."""

    def test_name_with_phone(self):
        from argus_redact._types import PatternMatch
        from argus_redact.lang.zh.person import detect_person_names

        text = "张明的手机号是13812345678"
        pii = [PatternMatch(text="13812345678", type="phone", start=7, end=18)]
        names = detect_person_names(text, pii_entities=pii)
        assert any(n.text == "张明" for n in names)

    def test_name_with_id_number(self):
        from argus_redact._types import PatternMatch
        from argus_redact.lang.zh.person import detect_person_names

        text = "何秀珍，身份证110101199003071234"
        pii = [PatternMatch(text="110101199003071234", type="id_number", start=4, end=22)]
        names = detect_person_names(text, pii_entities=pii)
        assert any(n.text == "何秀珍" for n in names)

    def test_name_from_names_param(self):
        from argus_redact.lang.zh.person import detect_person_names

        text = "下午和高明开会讨论方案"
        # "高明" would be in negative dict (means "clever"), but user says it's a name
        names = detect_person_names(text, pii_entities=[], known_names=["高明"])
        assert any(n.text == "高明" for n in names)

    def test_no_false_positives_on_common_words(self):
        from argus_redact.lang.zh.person import detect_person_names

        text = "这个王国的黄金储备很高"
        names = detect_person_names(text, pii_entities=[])
        detected = [n.text for n in names]
        assert "王国" not in detected
        assert "黄金" not in detected

    def test_chat_intro_pattern(self):
        from argus_redact.lang.zh.person import detect_person_names

        text = "你好我是刘伟，我的电话是13512345678"
        from argus_redact._types import PatternMatch

        pii = [PatternMatch(text="13512345678", type="phone", start=12, end=23)]
        names = detect_person_names(text, pii_entities=pii)
        assert any(n.text == "刘伟" for n in names)

    def test_multiple_persons_near_pii(self):
        from argus_redact._types import PatternMatch
        from argus_redact.lang.zh.person import detect_person_names

        text = "赵宇轩（18262174596）和萧伟（18158657809）是本次活动负责人"
        pii = [
            PatternMatch(text="18262174596", type="phone", start=4, end=15),
            PatternMatch(text="18158657809", type="phone", start=19, end=30),
        ]
        names = detect_person_names(text, pii_entities=pii)
        detected = [n.text for n in names]
        assert "赵宇轩" in detected
        assert "萧伟" in detected

    def test_returns_pattern_match_type(self):
        from argus_redact._types import PatternMatch
        from argus_redact.lang.zh.person import detect_person_names

        text = "客户张明已完成登记"
        names = detect_person_names(text, pii_entities=[])
        assert len(names) > 0
        assert all(isinstance(n, PatternMatch) for n in names)
        assert all(n.type == "person" for n in names)
