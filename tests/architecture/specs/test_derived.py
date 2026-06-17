"""Tests for spec-derived generators and fixtures."""

from argus_redact.specs import get, list_types
from argus_redact.specs import zh as _zh  # noqa: F401


class TestToFixtures:
    def test_should_generate_fixture_entries(self):
        phone = get("zh", "phone")
        fixtures = phone.to_fixtures()
        assert len(fixtures) > 0

    def test_fixture_format_should_have_required_keys(self):
        phone = get("zh", "phone")
        for f in phone.to_fixtures():
            assert "id" in f
            assert "input" in f
            assert "should_match" in f
            assert "type" in f
            assert "description" in f

    def test_examples_should_be_positive_fixtures(self):
        phone = get("zh", "phone")
        fixtures = phone.to_fixtures()
        positives = [f for f in fixtures if f["should_match"]]
        assert len(positives) == len(phone.examples)

    def test_counterexamples_should_be_negative_fixtures(self):
        phone = get("zh", "phone")
        fixtures = phone.to_fixtures()
        negatives = [f for f in fixtures if not f["should_match"]]
        assert len(negatives) == len(phone.counterexamples)

    def test_all_zh_types_should_generate_fixtures(self):
        for typedef in list_types("zh"):
            fixtures = typedef.to_fixtures()
            assert len(fixtures) >= 1, f"{typedef.name} produced no fixtures"

