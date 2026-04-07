"""Tests for Chinese regex patterns — data-driven from JSON fixtures."""

from argus_redact.pure.patterns import match_patterns

from tests.conftest import assert_pattern_match, parametrize_examples


class TestChinesePhone:
    @parametrize_examples("zh_phone.json")
    def test_should_match_or_reject_when_phone_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "phone")


class TestChineseIdNumber:
    @parametrize_examples("zh_id_number.json")
    def test_should_match_or_reject_when_id_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "id_number")


class TestBankCard:
    @parametrize_examples("zh_bank_card.json")
    def test_should_match_or_reject_when_bank_card_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "bank_card")


class TestPassport:
    @parametrize_examples("zh_passport.json")
    def test_should_match_or_reject_when_passport_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "passport")


class TestLicensePlate:
    @parametrize_examples("zh_license_plate.json")
    def test_should_match_or_reject_when_license_plate_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "license_plate")


class TestAddress:
    @parametrize_examples("zh_address.json")
    def test_should_match_or_reject_when_address_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "address")


class TestChinesePerson:
    @parametrize_examples("zh_person.json")
    def test_should_match_or_reject_when_person_input(self, zh_patterns, example):
        from argus_redact.lang.zh.person import detect_person_names
        from argus_redact.pure.patterns import match_patterns as mp

        text = example["input"]
        structural, _ = mp(text, zh_patterns)
        person_results = detect_person_names(text, pii_entities=structural)

        if example["should_match"]:
            assert len(person_results) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in person_results), (
                    f"Expected '{example['expected_text']}' but got "
                    f"{[r.text for r in person_results]}: {example['description']}"
                )
        else:
            assert len(person_results) == 0, f"Should NOT match: {example['description']}"


class TestSocialAccount:
    @parametrize_examples("zh_social_account.json")
    def test_should_match_or_reject_when_social_account_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example)


class TestCreditCode:
    @parametrize_examples("zh_credit_code.json")
    def test_should_match_or_reject_when_credit_code_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "credit_code")


class TestChineseDateOfBirth:
    @parametrize_examples("zh_date_of_birth.json")
    def test_should_match_or_reject_when_dob_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "date_of_birth")


class TestChineseMilitaryId:
    @parametrize_examples("zh_military_id.json")
    def test_should_match_or_reject_when_military_id_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "military_id")


class TestChineseSocialSecurity:
    @parametrize_examples("zh_social_security.json")
    def test_should_match_or_reject_when_social_security_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "social_security")


class TestJobTitle:
    @parametrize_examples("zh_job_title.json")
    def test_should_match_or_reject_when_job_title_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "job_title")


class TestOrganization:
    @parametrize_examples("zh_organization.json")
    def test_should_match_or_reject_when_org_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "organization")


class TestSchool:
    @parametrize_examples("zh_school.json")
    def test_should_match_or_reject_when_school_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "school")


class TestEthnicity:
    @parametrize_examples("zh_ethnicity.json")
    def test_should_match_or_reject_when_ethnicity_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "ethnicity")


class TestWorkplace:
    @parametrize_examples("zh_workplace.json")
    def test_should_match_or_reject_when_workplace_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "workplace")


class TestCriminalRecord:
    @parametrize_examples("zh_criminal_record.json")
    def test_should_match_or_reject_when_criminal_record_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "criminal_record")


class TestFinancial:
    @parametrize_examples("zh_financial.json")
    def test_should_match_or_reject_when_financial_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "financial")


class TestBiometric:
    @parametrize_examples("zh_biometric.json")
    def test_should_match_or_reject_when_biometric_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "biometric")


class TestMedical:
    @parametrize_examples("zh_medical.json")
    def test_should_match_or_reject_when_medical_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "medical")


class TestReligion:
    @parametrize_examples("zh_religion.json")
    def test_should_match_or_reject_when_religion_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "religion")


class TestPolitical:
    @parametrize_examples("zh_political.json")
    def test_should_match_or_reject_when_political_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "political")


class TestSexualOrientation:
    @parametrize_examples("zh_sexual_orientation.json")
    def test_should_match_or_reject_when_sexual_orientation_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        assert_pattern_match(results, example, "sexual_orientation")


class TestSelfReference:
    @parametrize_examples("zh_self_reference.json")
    def test_should_match_or_reject_when_self_reference_input(self, zh_patterns, example):
        results, _ = match_patterns(example["input"], zh_patterns)
        typed = [r for r in results if r.type == "self_reference"]

        if example["should_match"]:
            if "expected_count" in example:
                assert len(typed) == example["expected_count"], (
                    f"Expected {example['expected_count']} matches: {example['description']}"
                )
            else:
                assert len(typed) >= 1, f"Expected match: {example['description']}"
                if "expected_text" in example:
                    assert any(r.text == example["expected_text"] for r in typed), (
                        f"Expected '{example['expected_text']}' but got "
                        f"{[r.text for r in typed]}: {example['description']}"
                    )
        else:
            assert len(typed) == 0, f"Should NOT match: {example['description']}"


class TestMultiplePII:
    def test_should_detect_both_types_when_phone_and_id_in_text(self, zh_patterns):
        text = "手机13812345678，身份证110101199003074610"

        results, _ = match_patterns(text, zh_patterns)
        types = {r.type for r in results}

        assert "phone" in types
        assert "id_number" in types

    def test_should_return_empty_when_no_pii(self, zh_patterns):
        results, _ = match_patterns("今天天气不错", zh_patterns)

        assert results == []

    def test_should_return_empty_when_text_is_empty(self, zh_patterns):
        results, _ = match_patterns("", zh_patterns)

        assert results == []
