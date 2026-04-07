"""Tests for spec-derived generators and fixtures."""

import random

from argus_redact.pure.patterns import match_patterns
from argus_redact.lang.zh.patterns import PATTERNS as ZH_PATTERNS
from argus_redact.lang.shared.patterns import PATTERNS as SHARED
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


class TestFaker:
    def test_every_zh_type_with_faker_should_produce_value(self):
        rng = random.Random(42)
        for typedef in list_types("zh"):
            if typedef.faker is None:
                continue
            value = typedef.faker(rng)
            assert isinstance(value, str)
            assert len(value) > 0

    def test_faker_output_should_match_own_patterns(self):
        """Generated fake values should be detected by our patterns."""
        rng = random.Random(42)
        all_patterns = ZH_PATTERNS + SHARED
        # phone_landline pattern emits type "phone"
        TYPE_ALIASES = {"phone_landline": "phone"}

        for typedef in list_types("zh"):
            if typedef.faker is None:
                continue
            # Person names are detected by person.py, not by PATTERNS regex
            if typedef.name == "person":
                continue
            expected_type = TYPE_ALIASES.get(typedef.name, typedef.name)
            # Generate 10 values, check they all match
            for _ in range(10):
                value = typedef.faker(rng)
                results, _ = match_patterns(value, all_patterns)
                matched_types = {r.type for r in results}
                assert expected_type in matched_types, (
                    f"Faker output '{value}' for {typedef.name} "
                    f"not matched by patterns. Got: {matched_types}"
                )

    def test_faker_should_be_deterministic_with_seed(self):
        for typedef in list_types("zh"):
            if typedef.faker is None:
                continue
            v1 = typedef.faker(random.Random(42))
            v2 = typedef.faker(random.Random(42))
            assert v1 == v2, f"{typedef.name} faker not deterministic"

    def test_id_number_faker_should_pass_checksum(self):
        from argus_redact.lang.zh.patterns import _validate_id_number
        rng = random.Random(42)
        id_def = get("zh", "id_number")
        for _ in range(20):
            value = id_def.faker(rng)
            assert _validate_id_number(value), f"Invalid ID: {value}"

    def test_bank_card_faker_should_pass_validation(self):
        from argus_redact.lang.zh.patterns import _validate_bank_card
        rng = random.Random(42)
        card_def = get("zh", "bank_card")
        for _ in range(20):
            value = card_def.faker(rng)
            assert _validate_bank_card(value), f"Invalid card: {value}"
