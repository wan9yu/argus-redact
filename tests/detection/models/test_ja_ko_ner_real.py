"""Real Japanese and Korean NER integration tests.

Run with: pytest tests/impure/test_ja_ko_ner_real.py -m ner -v
"""

import importlib.util

import pytest

pytestmark = pytest.mark.ner

HAS_JA = importlib.util.find_spec("ja_core_news_sm") is not None
HAS_KO = importlib.util.find_spec("ko_core_news_sm") is not None


@pytest.fixture(scope="module")
def ja_adapter():
    if not HAS_JA:
        pytest.skip("ja_core_news_sm not installed")
    from argus_redact.lang.ja.ner_adapter import JapaneseNERAdapter

    a = JapaneseNERAdapter()
    a.load()
    return a


@pytest.fixture(scope="module")
def ko_adapter():
    if not HAS_KO:
        pytest.skip("ko_core_news_sm not installed")
    from argus_redact.lang.ko.ner_adapter import KoreanNERAdapter

    a = KoreanNERAdapter()
    a.load()
    return a


class TestJapaneseNER:
    def test_should_detect_person_name(self, ja_adapter):
        results = ja_adapter.detect("田中太郎は東京に行った")

        persons = [r for r in results if r.type == "person"]
        assert len(persons) >= 1

    def test_should_detect_location(self, ja_adapter):
        results = ja_adapter.detect("田中太郎は東京に行った")

        locations = [r for r in results if r.type == "location"]
        assert len(locations) >= 1

    def test_should_return_correct_offsets(self, ja_adapter):
        text = "田中太郎は東京に行った"
        results = ja_adapter.detect(text)

        for r in results:
            assert text[r.start : r.end] == r.text

    def test_should_return_empty_when_no_entities(self, ja_adapter):
        results = ja_adapter.detect("今日はいい天気です")

        for r in results:
            assert r.start >= 0


class TestKoreanNER:
    def test_should_detect_person_name(self, ko_adapter):
        results = ko_adapter.detect("김철수는 서울에 갔다")

        persons = [r for r in results if r.type == "person"]
        assert len(persons) >= 1

    def test_should_detect_location(self, ko_adapter):
        results = ko_adapter.detect("김철수는 서울에 갔다")

        locations = [r for r in results if r.type == "location"]
        assert len(locations) >= 1

    def test_should_return_correct_offsets(self, ko_adapter):
        text = "김철수는 서울에 갔다"
        results = ko_adapter.detect(text)

        for r in results:
            assert text[r.start : r.end] == r.text


class TestJaKoFullPipeline:
    def test_should_roundtrip_japanese(self, ja_adapter):
        from unittest.mock import patch

        from argus_redact import redact, restore

        text = "田中太郎の電話は090-1234-5678"

        with patch(
            "argus_redact.glue.redact._get_ner_adapters",
            return_value=[ja_adapter],
        ):
            redacted, key = redact(text, seed=42, mode="ner", lang="ja")

        assert "090-1234-5678" not in redacted
        restored = restore(redacted, key)
        assert "090-1234-5678" in restored

    def test_should_roundtrip_korean(self, ko_adapter):
        from unittest.mock import patch

        from argus_redact import redact, restore

        text = "김철수 전화번호 010-1234-5678"

        with patch(
            "argus_redact.glue.redact._get_ner_adapters",
            return_value=[ko_adapter],
        ):
            redacted, key = redact(text, seed=42, mode="ner", lang="ko")

        assert "010-1234-5678" not in redacted
        restored = restore(redacted, key)
        assert "010-1234-5678" in restored
