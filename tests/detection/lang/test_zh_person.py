"""Tests for Chinese person name detection — candidate generation + evidence scoring.

The new approach replaces hard-coded context patterns with:
  Step 1: structural PII detection (existing)
  Step 2: name candidate generation (surname + 1-2 CJK, minus negative dict)
  Step 3: evidence scoring (PII proximity, context words, position, name length)
"""


# ── Candidate generation ──


class TestCandidateGeneration:
    """surname + 1-2 CJK chars → raw candidates."""

    def test_three_char_name(self):
        from argus_redact.lang.zh.person import generate_candidates

        candidates = generate_candidates("何秀珍的手机号是13812345678")
        names = [c.text for c in candidates]
        assert "何秀珍" in names

    def test_two_char_name(self):
        from argus_redact.lang.zh.person import generate_candidates

        candidates = generate_candidates("张明的身份证号是110101199003071234")
        names = [c.text for c in candidates]
        assert "张明" in names

    def test_compound_surname(self):
        from argus_redact.lang.zh.person import generate_candidates

        candidates = generate_candidates("欧阳明的电话是13912345678")
        names = [c.text for c in candidates]
        assert "欧阳明" in names

    def test_multiple_names(self):
        from argus_redact.lang.zh.person import generate_candidates

        candidates = generate_candidates("张三和李四是同事")
        names = [c.text for c in candidates]
        assert "张三" in names
        assert "李四" in names

    def test_no_candidates_in_plain_text(self):
        from argus_redact.lang.zh.person import generate_candidates

        candidates = generate_candidates("今天天气很好")
        assert len(candidates) == 0

    def test_returns_start_end_offsets(self):
        from argus_redact.lang.zh.person import generate_candidates

        text = "联系张明了解详情"
        candidates = generate_candidates(text)
        zhang = [c for c in candidates if c.text == "张明"][0]
        assert text[zhang.start : zhang.end] == "张明"


# ── Negative dictionary ──


class TestNegativeDict:
    """Common words that look like names should be filtered out."""

    def test_common_words_excluded(self):
        from argus_redact.lang.zh.person import generate_candidates

        # These are common words, not names
        for word in ["王国", "张开", "高中", "陈述", "黄金", "周围"]:
            text = f"这个{word}很大"
            candidates = generate_candidates(text)
            names = [c.text for c in candidates]
            assert word not in names, f"{word} should be filtered by negative dict"

    def test_negative_dict_does_not_block_real_names(self):
        from argus_redact.lang.zh.person import generate_candidates

        # These start with surnames but are clearly names (3-char, unlikely to be words)
        candidates = generate_candidates("何秀珍和陈志远在开会")
        names = [c.text for c in candidates]
        assert "何秀珍" in names
        assert "陈志远" in names


# ── Evidence scoring ──


class TestEvidenceScoring:
    """Candidates near PII or with context signals should score higher."""

    def test_name_near_phone_scores_high(self):
        from argus_redact._types import PatternMatch
        from argus_redact.lang.zh.person import generate_candidates, score_candidate

        text = "张明的手机号是13812345678"
        candidates = generate_candidates(text)
        pii = [PatternMatch(text="13812345678", type="phone", start=7, end=18)]

        zhang = [c for c in candidates if c.text == "张明"][0]
        score = score_candidate(zhang, text, pii_entities=pii)
        assert score >= 0.8

    def test_name_with_context_prefix_scores_high(self):
        from argus_redact.lang.zh.person import generate_candidates, score_candidate

        text = "客户张明已完成登记"
        candidates = generate_candidates(text)
        zhang = [c for c in candidates if c.text == "张明"][0]
        score = score_candidate(zhang, text, pii_entities=[])
        assert score >= 0.8

    def test_name_with_intro_phrase_scores_high(self):
        from argus_redact.lang.zh.person import generate_candidates, score_candidate

        text = "你好我是张明"
        candidates = generate_candidates(text)
        zhang = [c for c in candidates if c.text == "张明"][0]
        score = score_candidate(zhang, text, pii_entities=[])
        assert score >= 0.8

    def test_name_with_honorific_suffix_scores_high(self):
        from argus_redact.lang.zh.person import generate_candidates, score_candidate

        text = "请联系张明先生"
        candidates = generate_candidates(text)
        zhang = [c for c in candidates if c.text == "张明"][0]
        score = score_candidate(zhang, text, pii_entities=[])
        assert score >= 0.8

    def test_three_char_name_baseline_higher_than_two_char(self):
        from argus_redact._types import PatternMatch
        from argus_redact.lang.zh.person import generate_candidates, score_candidate

        # With equal evidence (same PII proximity), 3-char should score higher than 2-char
        text = "客户何秀珍和张明来了，电话13812345678"
        candidates = generate_candidates(text)
        he = [c for c in candidates if c.text == "何秀珍"][0]
        zhang = [c for c in candidates if c.text == "张明"][0]
        pii = [PatternMatch(text="13812345678", type="phone", start=22, end=33)]

        score_he = score_candidate(he, text, pii_entities=pii)
        score_zhang = score_candidate(zhang, text, pii_entities=pii)
        assert score_he > score_zhang, f"3-char {score_he} should > 2-char {score_zhang}"

    def test_isolated_two_char_without_signals_scores_low(self):
        from argus_redact.lang.zh.person import generate_candidates, score_candidate

        # No PII, no context words, just a bare two-char candidate
        text = "张明来了"
        candidates = generate_candidates(text)
        zhang = [c for c in candidates if c.text == "张明"][0]
        score = score_candidate(zhang, text, pii_entities=[])
        assert score < 0.8


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
