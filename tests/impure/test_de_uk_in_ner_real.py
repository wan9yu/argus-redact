"""Real German, UK, Indian NER integration tests.

Run with: pytest tests/impure/test_de_uk_in_ner_real.py -m ner -v
"""

import importlib.util

import pytest

pytestmark = pytest.mark.ner

HAS_DE = importlib.util.find_spec("de_core_news_sm") is not None
HAS_XX = importlib.util.find_spec("xx_ent_wiki_sm") is not None


class TestGermanNER:
    @pytest.fixture(scope="class")
    def adapter(self):
        if not HAS_DE:
            pytest.skip("de_core_news_sm not installed")
        from argus_redact.lang.de.ner_adapter import GermanNERAdapter

        a = GermanNERAdapter()
        a.load()
        return a

    def test_should_detect_person(self, adapter):
        results = adapter.detect("Hans Müller wohnt in Berlin")
        persons = [r for r in results if r.type == "person"]
        assert len(persons) >= 1

    def test_should_detect_location(self, adapter):
        results = adapter.detect("Hans Müller wohnt in Berlin")
        locations = [r for r in results if r.type == "location"]
        assert len(locations) >= 1

    def test_should_detect_organization(self, adapter):
        results = adapter.detect("Er arbeitet bei Siemens in München")
        orgs = [r for r in results if r.type == "organization"]
        assert len(orgs) >= 1

    def test_should_return_correct_offsets(self, adapter):
        text = "Hans Müller wohnt in Berlin"
        for r in adapter.detect(text):
            assert text[r.start : r.end] == r.text


class TestUKNER:
    @pytest.fixture(scope="class")
    def adapter(self):
        from argus_redact.lang.uk.ner_adapter import UKNERAdapter

        a = UKNERAdapter()
        a.load()
        return a

    def test_should_detect_person(self, adapter):
        results = adapter.detect("James Wilson lives in London")
        persons = [r for r in results if r.type == "person"]
        assert len(persons) >= 1

    def test_should_detect_location(self, adapter):
        results = adapter.detect("James Wilson lives in London")
        locations = [r for r in results if r.type == "location"]
        assert len(locations) >= 1


class TestIndianNER:
    @pytest.fixture(scope="class")
    def adapter(self):
        if not HAS_XX:
            pytest.skip("xx_ent_wiki_sm not installed")
        from argus_redact.lang.in_.ner_adapter import IndianNERAdapter

        a = IndianNERAdapter()
        a.load()
        return a

    def test_should_detect_person(self, adapter):
        results = adapter.detect("Raj Patel lives in Mumbai")
        persons = [r for r in results if r.type == "person"]
        assert len(persons) >= 1

    def test_should_detect_location(self, adapter):
        results = adapter.detect("Raj Patel lives in Mumbai")
        locations = [r for r in results if r.type == "location"]
        assert len(locations) >= 1

    def test_should_return_correct_offsets(self, adapter):
        text = "Raj Patel works at Tata in Mumbai"
        for r in adapter.detect(text):
            assert text[r.start : r.end] == r.text
