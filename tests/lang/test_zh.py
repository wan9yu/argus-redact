"""Tests for Chinese regex patterns — data-driven from JSON fixtures."""

from argus_redact.pure.patterns import match_patterns

from tests.conftest import parametrize_examples


class TestChinesePhone:
    @parametrize_examples("zh_phone.json")
    def test_should_match_or_reject_when_phone_input(self, zh_patterns, example):
        results = match_patterns(example["input"], zh_patterns)
        phone_results = [r for r in results if r.type == "phone"]

        if example["should_match"]:
            assert len(phone_results) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in phone_results)
        else:
            assert len(phone_results) == 0, f"Should NOT match: {example['description']}"


class TestChineseIdNumber:
    @parametrize_examples("zh_id_number.json")
    def test_should_match_or_reject_when_id_input(self, zh_patterns, example):
        results = match_patterns(example["input"], zh_patterns)
        id_results = [r for r in results if r.type == "id_number"]

        if example["should_match"]:
            assert len(id_results) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in id_results)
        else:
            assert len(id_results) == 0, f"Should NOT match: {example['description']}"


class TestBankCard:
    @parametrize_examples("zh_bank_card.json")
    def test_should_match_or_reject_when_bank_card_input(self, zh_patterns, example):
        results = match_patterns(example["input"], zh_patterns)
        card_results = [r for r in results if r.type == "bank_card"]

        if example["should_match"]:
            assert len(card_results) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in card_results)
        else:
            assert len(card_results) == 0, f"Should NOT match: {example['description']}"


class TestLicensePlate:
    @parametrize_examples("zh_license_plate.json")
    def test_should_match_or_reject_when_license_plate_input(self, zh_patterns, example):
        results = match_patterns(example["input"], zh_patterns)
        plate_results = [r for r in results if r.type == "license_plate"]

        if example["should_match"]:
            assert len(plate_results) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in plate_results)
        else:
            assert len(plate_results) == 0, f"Should NOT match: {example['description']}"


class TestAddress:
    @parametrize_examples("zh_address.json")
    def test_should_match_or_reject_when_address_input(self, zh_patterns, example):
        results = match_patterns(example["input"], zh_patterns)
        addr_results = [r for r in results if r.type == "address"]

        if example["should_match"]:
            assert len(addr_results) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in addr_results)
        else:
            assert len(addr_results) == 0, f"Should NOT match: {example['description']}"


class TestMultiplePII:
    def test_should_detect_both_types_when_phone_and_id_in_text(self, zh_patterns):
        text = "手机13812345678，身份证110101199003074610"

        results = match_patterns(text, zh_patterns)
        types = {r.type for r in results}

        assert "phone" in types
        assert "id_number" in types

    def test_should_return_empty_when_no_pii(self, zh_patterns):
        results = match_patterns("今天天气不错", zh_patterns)

        assert results == []

    def test_should_return_empty_when_text_is_empty(self, zh_patterns):
        results = match_patterns("", zh_patterns)

        assert results == []
