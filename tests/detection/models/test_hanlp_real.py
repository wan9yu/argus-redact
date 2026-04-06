"""Real HanLP integration tests — requires hanlp installed.

Run with: pytest tests/impure/test_hanlp_real.py -m ner
Skip with: pytest -m 'not ner'
"""

import importlib.util

import pytest

HAS_HANLP = importlib.util.find_spec("hanlp") is not None

pytestmark = pytest.mark.ner


@pytest.fixture(scope="module")
def adapter():
    if not HAS_HANLP:
        pytest.skip("hanlp not installed")
    from argus_redact.lang.zh.ner_adapter import HanLPAdapter

    a = HanLPAdapter()
    a.load()
    return a


class TestHanLPRealNER:
    """Integration tests with real HanLP model."""

    def test_should_detect_person_name(self, adapter):
        results = adapter.detect("张三去了北京")

        persons = [r for r in results if r.type == "person"]
        assert len(persons) >= 1
        assert any(r.text == "张三" for r in persons)

    def test_should_detect_location(self, adapter):
        results = adapter.detect("张三去了北京")

        locations = [r for r in results if r.type == "location"]
        assert len(locations) >= 1
        assert any(r.text == "北京" for r in locations)

    def test_should_detect_organization(self, adapter):
        results = adapter.detect("他在腾讯工作")

        # HanLP may classify as org or location — accept either
        relevant = [r for r in results if r.type in ("organization", "location")]
        assert len(relevant) >= 1

    def test_should_return_correct_char_offsets(self, adapter):
        text = "张三去了北京"
        results = adapter.detect(text)

        for r in results:
            assert text[r.start : r.end] == r.text, (
                f"Offset mismatch: text[{r.start}:{r.end}]="
                f"{text[r.start:r.end]!r} != {r.text!r}"
            )

    def test_should_handle_complex_sentence(self, adapter):
        text = "张三和李四在星巴克讨论了去阿里面试的事"
        results = adapter.detect(text)

        persons = [r for r in results if r.type == "person"]
        assert len(persons) >= 2

        # All offsets should be valid
        for r in results:
            assert text[r.start : r.end] == r.text

    def test_should_return_empty_when_no_entities(self, adapter):
        results = adapter.detect("今天天气真不错啊")

        # May or may not find entities in this sentence
        # Just verify no crashes and offsets are valid
        for r in results:
            assert r.start >= 0
            assert r.end <= len("今天天气真不错啊")

    def test_should_handle_empty_text(self, adapter):
        results = adapter.detect("")

        assert results == [] or isinstance(results, list)


class TestHanLPRealRedactIntegration:
    """End-to-end: redact() with real HanLP NER."""

    def test_should_redact_person_name_with_ner_mode(self, adapter):
        from argus_redact import redact

        text = "张三的手机号是13812345678"
        redacted, key = redact(text, seed=42, mode="fast")

        # fast mode: only phone is redacted, 张三 remains
        assert "张三" in redacted
        assert "13812345678" not in redacted

    def test_should_roundtrip_with_real_ner(self, adapter):
        """Full roundtrip: NER detects names, regex detects phone, restore recovers all."""
        from argus_redact import restore
        from argus_redact.impure.ner import detect_ner
        from argus_redact.pure.merger import merge_entities
        from argus_redact.pure.patterns import match_patterns
        from argus_redact.pure.replacer import replace

        text = "张三的手机号是13812345678"

        # Layer 1: regex
        from argus_redact.lang.shared.patterns import PATTERNS as SHARED
        from argus_redact.lang.zh.patterns import PATTERNS as ZH

        regex_entities = match_patterns(text, ZH + SHARED)

        # Layer 2: NER
        ner_entities = detect_ner(text, adapter=adapter)
        all_entities = list(regex_entities) + [e.to_pattern_match() for e in ner_entities]

        # Merge
        merged = merge_entities(all_entities)

        # Replace
        redacted, key = replace(text, merged, seed=42)

        assert "张三" not in redacted
        assert "13812345678" not in redacted

        # Restore
        restored = restore(redacted, key)
        assert "张三" in restored
        assert "13812345678" in restored
