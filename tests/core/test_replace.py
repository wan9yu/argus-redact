"""Tests for replacer — converts pattern matches to redacted text + key."""

import pytest

from argus_redact.pure.replacer import replace
from tests.conftest import make_match


class TestReplaceBasic:
    """Core replacement behavior."""

    def test_should_redact_phone_when_single_phone_entity(self):
        entities = [make_match("13812345678", "phone", 3)]
        text = "电话是13812345678"

        redacted, key, _ = replace(text, entities, seed=42)

        assert "13812345678" not in redacted
        assert len(key) == 1
        assert "13812345678" in key.values()

    def test_should_use_pseudonym_when_entity_is_person(self):
        entities = [make_match("张三", "person", 0)]

        redacted, key, _ = replace("张三说了话", entities, seed=42)

        assert "张三" not in redacted
        assert redacted.endswith("说了话")
        assert list(key.keys())[0].startswith("P-")

    def test_should_redact_all_when_multiple_entity_types(self):
        entities = [
            make_match("张三", "person", 0),
            make_match("13812345678", "phone", 6),
        ]

        redacted, key, _ = replace("张三的电话是13812345678", entities, seed=42)

        assert "张三" not in redacted
        assert "13812345678" not in redacted
        assert len(key) == 2

    def test_should_use_same_pseudonym_when_same_entity_appears_twice(self):
        entities = [
            make_match("张三", "person", 0),
            make_match("张三", "person", 3),
        ]

        redacted, key, _ = replace("张三和张三", entities, seed=42)

        person_entries = {k: v for k, v in key.items() if v == "张三"}
        assert len(person_entries) == 1


class TestReplaceStrategies:
    """Different entity types use different default strategies."""

    def test_should_use_pseudonym_prefix_when_person(self):
        entities = [make_match("张三", "person", 0)]

        _, key, _ = replace("张三", entities, seed=42)

        assert list(key.keys())[0].startswith("P-")

    def test_should_mask_with_stars_when_phone(self):
        entities = [make_match("13812345678", "phone", 0)]

        _, key, _ = replace("13812345678", entities, seed=42)

        replacement = list(key.keys())[0]
        assert "138" in replacement
        assert "5678" in replacement
        assert "*" in replacement

    def test_should_use_remove_label_when_id_number(self):
        entities = [make_match("110101199003074610", "id_number", 0)]

        _, key, _ = replace("110101199003074610", entities, seed=42)

        replacement = list(key.keys())[0]
        assert replacement.startswith("ID-")  # pseudonym-style for LLM survival

    def test_should_mask_with_domain_when_email(self):
        entities = [make_match("zhang@example.com", "email", 0)]

        _, key, _ = replace("zhang@example.com", entities, seed=42)

        replacement = list(key.keys())[0]
        assert "@" in replacement or "*" in replacement

    def test_should_mask_prefix_suffix_when_bank_card(self):
        entities = [make_match("4111111111111111", "bank_card", 0)]

        _, key, _ = replace("4111111111111111", entities, seed=42)

        replacement = list(key.keys())[0]
        assert replacement.startswith("411")
        assert replacement.endswith("1111")
        assert "*" in replacement


class TestReplaceRightToLeft:
    """Replacement must work right-to-left to preserve offsets."""

    def test_should_preserve_surrounding_text_when_entities_in_middle(self):
        entities = [
            make_match("张三", "person", 1),
            make_match("李四", "person", 4),
        ]

        redacted, key, _ = replace("A张三B李四C", entities, seed=42)

        assert "张三" not in redacted
        assert "李四" not in redacted
        assert redacted.startswith("A")
        assert redacted.endswith("C")


class TestReplaceSeedDeterminism:
    """Same seed + same input = same output."""

    def test_should_produce_same_output_when_same_seed(self):
        entities = [make_match("张三", "person", 0)]

        r1 = replace("张三说话", entities, seed=42)
        r2 = replace("张三说话", entities, seed=42)

        assert r1 == r2

    def test_should_produce_different_output_when_different_seeds(self):
        entities = [make_match("张三", "person", 0)]

        r1 = replace("张三说话", entities, seed=42)
        r2 = replace("张三说话", entities, seed=99)

        assert r1[0] != r2[0]
        assert r1[1] != r2[1]


class TestReplaceEdgeCases:
    """Edge cases."""

    def test_should_return_original_when_no_entities(self):
        redacted, key, _ = replace("普通文本", [], seed=42)

        assert redacted == "普通文本"
        assert key == {}

    def test_should_return_empty_when_text_is_empty(self):
        redacted, key, _ = replace("", [], seed=42)

        assert redacted == ""
        assert key == {}

    def test_should_redact_when_entity_spans_entire_text(self):
        entities = [make_match("AB", "person", 0)]

        redacted, key, _ = replace("AB", entities, seed=42)

        assert "AB" not in redacted
        assert len(key) == 1

    def test_should_reuse_existing_pseudonym_when_key_provided(self):
        existing_key = {"P-037": "张三"}
        entities = [
            make_match("张三", "person", 0),
            make_match("李四", "person", 3),
        ]

        redacted, key, _ = replace("张三和李四", entities, seed=42, key=existing_key)

        assert "P-037" in redacted
        assert key["P-037"] == "张三"
        assert len(key) == 2


class TestReplaceCollisionNumbering:
    """Multiple same-type entities with remove strategy get numbered."""

    def test_should_assign_unique_labels_when_two_id_numbers(self):
        entities = [
            make_match("110101199003074610", "id_number", 0),
            make_match("220102198805061234", "id_number", 19),
        ]

        _, key, _ = replace("110101199003074610,220102198805061234", entities, seed=42)

        assert len(key) == 2
        assert len(set(key.keys())) == 2


class TestReplaceReturns3Tuple:
    """Lockdown for v0.6.0 replace() signature: (text, key, aliases) and no aliases_out kwarg."""

    def test_replace_returns_three_values(self):
        from argus_redact._types import PatternMatch
        from argus_redact.pure.replacer import replace

        entities = [PatternMatch(text="13812345678", type="phone", start=0, end=11, layer=1)]
        result = replace("13812345678", entities, seed=42)
        assert len(result) == 3
        text, key, aliases = result
        assert isinstance(text, str)
        assert isinstance(key, dict)
        assert isinstance(aliases, dict)

    def test_replace_no_aliases_out_kwarg(self):
        import pytest
        from argus_redact._types import PatternMatch
        from argus_redact.pure.replacer import replace

        with pytest.raises(TypeError, match="aliases_out"):
            replace(
                "x",
                [PatternMatch(text="x", type="phone", start=0, end=1, layer=1)],
                aliases_out={},
            )


# ─── Mutation-testing-killers ──────────────────────────────────────────
#
# Each of the following tests targets a specific class of mutation that
# survived an initial mutmut pass on `pure/replacer.py`. They lock down
# behaviour that is otherwise exercised only indirectly.


class TestReplaceCollisionResolution:
    """``_resolve_collision`` numbers conflicting labels uniquely.

    Many ``mask`` / ``category`` strategies emit deterministic labels (``[LOCATION]``,
    ``138****5678``); when several different originals collapse to the same masked
    output, the second / third occurrence gets a circled-number suffix.
    """

    def test_should_dedupe_when_two_phones_mask_to_same_pattern(self):
        # Both 138 prefix and 5678 suffix → mask collision on 138****5678
        entities = [
            make_match("13812345678", "phone", 0),
            make_match("13899995678", "phone", 12),
        ]

        _, key, _ = replace("13812345678 13899995678", entities, seed=42)

        # Two distinct keys (no overwrite); originals preserved
        assert len(key) == 2
        assert "13812345678" in key.values()
        assert "13899995678" in key.values()

    def test_should_keep_first_label_unsuffixed_when_no_collision(self):
        entities = [
            make_match("13812345678", "phone", 0),
            make_match("13955554444", "phone", 12),
        ]

        _, key, _ = replace("13812345678 13955554444", entities, seed=42)

        assert "138****5678" in key
        assert "139****4444" in key


class TestReplaceMaskValueDefaults:
    """``_mask_value`` per-type prefix/suffix defaults."""

    def test_should_show_3_prefix_4_suffix_when_phone_mask(self):
        entities = [make_match("13812345678", "phone", 0)]

        _, key, _ = replace("13812345678", entities, seed=42)

        replacement = next(iter(key))
        assert replacement.startswith("138")
        assert replacement.endswith("5678")
        # Asymmetric prefix/suffix: 3 != 4. Killing default-int 0 → 1 mutants
        # depends on exact star count = 11 - 3 - 4 = 4.
        assert replacement.count("*") == 4

    def test_should_show_6_prefix_4_suffix_when_bank_card_mask(self):
        entities = [make_match("4111111111111234", "bank_card", 0)]

        _, key, _ = replace("4111111111111234", entities, seed=42)

        replacement = next(iter(key))
        assert replacement.startswith("411111")
        assert replacement.endswith("1234")
        # 16 chars - 6 - 4 = 6 stars (kills `prefix_len + suffix_len` → `-`)
        assert replacement.count("*") == 6

    def test_should_mask_entire_value_when_shorter_than_window(self):
        # 5 chars total, default phone window is 3+4=7 → fully masked
        entities = [make_match("12345", "phone", 0)]

        _, key, _ = replace("12345", entities, seed=42)

        replacement = next(iter(key))
        assert replacement == "*****"


class TestReplaceMaskEmail:
    """Email masking shows local-prefix + ``*`` padding + domain."""

    def test_should_keep_first_letter_of_local_part_when_email_masked(self):
        entities = [make_match("alice@example.com", "email", 0)]

        _, key, _ = replace("alice@example.com", entities, seed=42)

        replacement = next(iter(key))
        assert replacement.startswith("a")
        assert replacement.endswith("@example.com")
        assert "*" in replacement

    def test_should_use_min_3_stars_when_local_part_short(self):
        # local-part length 1 → max(0, 3) = 3 stars
        entities = [make_match("a@example.com", "email", 0)]

        _, key, _ = replace("a@example.com", entities, seed=42)

        replacement = next(iter(key))
        # Exactly "a***@example.com" — kills `max(len(local) - 1, 3)` mutants
        assert replacement == "a***@example.com"


class TestReplaceConfigValidation:
    """``_validate_config`` rejects unknown strategies — for **every** entry,
    not just the first one."""

    def test_should_reject_when_invalid_strategy_appears_after_valid_one(self):
        # `continue` → `break` mutant would pass validation here because the
        # first entry is fine; only the second has the bad strategy.
        config = {
            "person": {"strategy": "pseudonym"},
            "phone": {"strategy": "totally-bogus"},
        }
        entities = [make_match("13812345678", "phone", 0)]

        with pytest.raises(ValueError, match="totally-bogus"):
            replace("13812345678", entities, seed=42, config=config)


class TestReplaceTypeSeedDerivation:
    """Per-type pseudonym generators use different seeds so two same-prefix
    types don't collide on the first generated code."""

    def test_should_assign_distinct_codes_when_two_remove_types_share_prefix_pool(self):
        # Two different types both fall through to remove → pseudonym-style
        # codes; both seeded from `pseudo_seed_int + _type_seed_offset(type)`.
        # The arith mutant `+` → `-` would still produce distinct codes by
        # coincidence; this test asserts each type-prefix appears at all.
        entities = [
            make_match("a@x.com", "criminal_record", 0),
            make_match("b@x.com", "medical", 10),
        ]

        _, key, _ = replace("a@x.com   b@x.com", entities, seed=42)

        replacements = list(key.keys())
        assert any(r.startswith("CRIM-") for r in replacements)
        assert any(r.startswith("MED-") for r in replacements)


class TestReplaceOrgPseudonymSeedOffset:
    """Organization generator must use a different seed offset from the person
    generator so a single salt doesn't produce the same code for first
    person + first organization seen."""

    def test_should_assign_different_codes_to_first_person_and_first_org(self):
        entities = [
            make_match("张三", "person", 0),
            make_match("阿里巴巴", "organization", 4),
        ]

        _, key, _ = replace("张三 在 阿里巴巴", entities, seed=42)

        # P-N for person, O-N for organization — different prefixes
        assert any(k.startswith("P-") for k in key)
        assert any(k.startswith("O-") for k in key)
        # And different code numbers (mutmut_73: + 1 → - 1 on org seed)
        person_code = next(k for k in key if k.startswith("P-"))
        org_code = next(k for k in key if k.startswith("O-"))
        person_n = int(person_code.split("-")[1])
        org_n = int(org_code.split("-")[1])
        # Different seeds produce different codes
        assert person_n != org_n


class TestReplaceReuseExistingKey:
    """When ``key=`` is provided, the existing pseudonym map must be honored,
    not blanked out."""

    def test_should_keep_existing_mapping_when_passing_key(self):
        # Kill `existing_key=None` mutants — they would re-roll the code for
        # 张三 instead of reusing the caller-supplied P-99999.
        existing = {"P-99999": "张三"}
        entities = [make_match("张三", "person", 0)]

        _, key, _ = replace("张三说话", entities, seed=42, key=existing)

        assert key.get("P-99999") == "张三"


class TestReplaceMaskNameCJK:
    """``_mask_name`` Chinese-name redaction: 张* / 李** / 欧阳**."""

    def test_should_mask_two_char_name_to_single_char_plus_star(self):
        # name_mask isn't a default; configure it explicitly
        entities = [make_match("张三", "person", 0)]
        config = {"person": {"strategy": "name_mask"}}

        _, key, _ = replace("张三", entities, seed=42, config=config)

        replacement = next(iter(key))
        assert replacement == "张*"

    def test_should_mask_three_char_name_to_first_plus_two_stars(self):
        entities = [make_match("欧阳锋", "person", 0)]
        config = {"person": {"strategy": "name_mask"}}

        _, key, _ = replace("欧阳锋", entities, seed=42, config=config)

        replacement = next(iter(key))
        # Kills `length - 1` mutants — must equal exactly "欧**"
        assert replacement == "欧**"

    def test_should_mask_four_char_name_keeping_first_two(self):
        entities = [make_match("司马相如", "person", 0)]
        config = {"person": {"strategy": "name_mask"}}

        _, key, _ = replace("司马相如", entities, seed=42, config=config)

        # 4+ char names: first 2 visible, rest stars
        replacement = next(iter(key))
        assert replacement == "司马**"


class TestReplaceLandlineMask:
    """``_mask_landline`` keeps area code + last 3 digits."""

    def test_should_keep_area_code_and_last_3_when_dashed(self):
        # "010-12345678" → "010-*****678"
        entities = [make_match("010-12345678", "phone", 0)]
        config = {"phone": {"strategy": "landline_mask"}}

        _, key, _ = replace("010-12345678", entities, seed=42, config=config)

        replacement = next(iter(key))
        assert replacement.startswith("010-")
        assert replacement.endswith("678")
        # 12345678 → ***** + last 3 → 5 stars
        assert replacement.count("*") == 5

    def test_should_guess_3_digit_area_code_when_starts_with_01(self):
        # 01012345678 → area "010", number 12345678
        entities = [make_match("01012345678", "phone", 0)]
        config = {"phone": {"strategy": "landline_mask"}}

        _, key, _ = replace("01012345678", entities, seed=42, config=config)

        replacement = next(iter(key))
        assert replacement.startswith("010")
        assert replacement.endswith("678")
