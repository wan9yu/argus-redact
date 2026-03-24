"""Real spaCy English NER integration tests.

Run with: pytest tests/impure/test_spacy_real.py -m ner -v
"""

import importlib.util

import pytest
from argus_redact import redact, restore

HAS_SPACY = importlib.util.find_spec("spacy") is not None

pytestmark = pytest.mark.ner


@pytest.fixture(scope="module")
def adapter():
    if not HAS_SPACY:
        pytest.skip("spacy not installed")
    from argus_redact.lang.en.ner_adapter import SpaCyAdapter

    a = SpaCyAdapter()
    a.load()
    return a


class TestSpaCyRealNER:
    def test_should_detect_person_name(self, adapter):
        results = adapter.detect("John Smith went to the store")

        persons = [r for r in results if r.type == "person"]
        assert len(persons) >= 1
        assert any("John" in r.text for r in persons)

    def test_should_detect_location(self, adapter):
        results = adapter.detect("She traveled to New York last week")

        locations = [r for r in results if r.type == "location"]
        assert len(locations) >= 1

    def test_should_detect_organization(self, adapter):
        results = adapter.detect("He works at Google in California")

        orgs = [r for r in results if r.type == "organization"]
        assert len(orgs) >= 1

    def test_should_return_correct_char_offsets(self, adapter):
        text = "John went to New York"
        results = adapter.detect(text)

        for r in results:
            assert text[r.start : r.end] == r.text, (
                f"Offset mismatch: text[{r.start}:{r.end}]="
                f"{text[r.start:r.end]!r} != {r.text!r}"
            )

    def test_should_handle_complex_sentence(self, adapter):
        text = "John and Mary visited Google headquarters in Mountain View"
        results = adapter.detect(text)

        persons = [r for r in results if r.type == "person"]
        assert len(persons) >= 2

        for r in results:
            assert text[r.start : r.end] == r.text


class TestSpaCyFullPipeline:
    def test_should_redact_english_person_with_phone(self, adapter):
        from unittest.mock import patch

        text = "Call John at (555) 123-4567"

        with patch("argus_redact.glue.redact._get_ner_adapter", return_value=adapter):
            redacted_text, key = redact(text, seed=42, mode="ner", lang="en")

        assert "(555) 123-4567" not in redacted_text
        restored = restore(redacted_text, key)
        assert "(555) 123-4567" in restored

    def test_should_roundtrip_english_names_and_ssn(self, adapter):
        from unittest.mock import patch

        text = "John Smith, SSN 123-45-6789, works at Google"

        with patch("argus_redact.glue.redact._get_ner_adapter", return_value=adapter):
            redacted_text, key = redact(text, seed=42, mode="ner", lang="en")

        assert "123-45-6789" not in redacted_text
        restored = restore(redacted_text, key)
        assert "123-45-6789" in restored
