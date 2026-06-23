"""Tests for the 'realistic' strategy dispatch in pure/replacer.py."""

import random
import re

import pytest

from argus_redact.pure.replacer import (
    VALID_STRATEGIES,
    _faker_reserved_cached,
    _find_faker_reserved,
    _resolve_realistic_faker,
    replace,
)
from argus_redact.specs import zh as _zh  # noqa: F401  ensure registration
from argus_redact.specs.registry import PIITypeDef, register, unregister

from tests.conftest import make_match


class TestRealisticStrategy:
    def test_realistic_should_be_in_valid_strategies(self):
        assert "realistic" in VALID_STRATEGIES

    def test_realistic_should_call_faker_reserved_for_phone(self):
        text = "请拨打 13912345678"
        entities = [make_match("13912345678", "phone", 4)]
        config = {"phone": {"strategy": "realistic"}}
        redacted, key, _ = replace(text, entities, config=config, salt=42)

        assert "13912345678" not in redacted
        fakes = list(key.keys())
        assert len(fakes) == 1
        assert fakes[0].startswith("19999"), f"Got {fakes[0]}"
        assert key[fakes[0]] == "13912345678"

    def test_realistic_should_be_deterministic_with_same_seed(self):
        text = "联系 13912345678"
        entities = [make_match("13912345678", "phone", 3)]
        config = {"phone": {"strategy": "realistic"}}
        a, _, _ = replace(text, entities, config=config, salt=7)
        b, _, _ = replace(text, entities, config=config, salt=7)
        assert a == b

    def test_realistic_should_fall_back_to_pseudonym_when_no_faker_reserved(self):
        text = "公司名 ABC公司"
        entities = [make_match("ABC公司", "organization", 4)]
        config = {"organization": {"strategy": "realistic"}}
        redacted, key, _ = replace(text, entities, config=config, salt=42)

        fakes = list(key.keys())
        assert len(fakes) == 1
        assert fakes[0].startswith("O-"), f"Got {fakes[0]}"

    @pytest.mark.parametrize(
        "prefix, token, type_",
        [
            # date_of_birth noise only shifts a full Y-M-D date; a bare year-month
            # "2000年1月" has no day → identity → re-roll exhaustion.
            ("生日", "2000年1月", "date_of_birth"),
            # age noise shifts an ASCII-digit run; a Chinese-numeral age "零岁" has
            # no digits → identity → exhaustion. (Same class as the DOB bug — the
            # general fallback must cover every "noise" faker, not just dates.)
            ("年龄", "零岁", "age"),
        ],
    )
    def test_realistic_falls_back_to_pseudonym_when_faker_cannot_fake(self, prefix, token, type_):
        """A noise faker that can't fake the value must fail closed to a
        pseudonym, not raise — the entity stays redacted, the original is gone."""
        text = prefix + token
        entities = [make_match(token, type_, len(prefix))]
        config = {type_: {"strategy": "realistic"}}
        redacted, key, _ = replace(text, entities, config=config, salt=42)

        assert token not in redacted
        fakes = list(key)
        assert len(fakes) == 1
        assert fakes[0] != token
        assert key[fakes[0]] == token

    def test_redact_pseudonym_llm_does_not_crash_on_unfakeable_date(self):
        """Regression: year-month / Chinese-numeral DOBs the noise faker can't
        shift previously crashed redact_pseudonym_llm with a ValueError. They
        must now fail closed (pseudonym), removing the date from both outputs."""
        from argus_redact import redact_pseudonym_llm

        for text, token in [
            ("生日2000年1月", "2000年1月"),
            ("生日00年1月", "00年1月"),
            ("出生于十一月十五日", "十一月十五日"),
            ("生日三月", "三月"),
        ]:
            r = redact_pseudonym_llm(text, salt=b"\x00" * 32, lang="zh")
            assert token not in r.audit_text, f"{token!r} leaked in audit_text: {r.audit_text!r}"
            assert token not in r.downstream_text, (
                f"{token!r} leaked in downstream_text: {r.downstream_text!r}"
            )

    def test_realistic_should_re_roll_on_collision(self):
        """Pre-claim the first-attempt fake; re-roll must produce a different one."""
        text = "联系 13912345678"
        entities = [make_match("13912345678", "phone", 3)]
        config = {"phone": {"strategy": "realistic"}}

        # First, learn what the first-attempt fake would be
        _, first_key, _ = replace(text, entities, config=config, salt=7)
        first_fake = next(iter(first_key))

        # Now seed the replace() with a key that already claims first_fake for a different original
        # → forces _generate_unique_fake to re-roll
        pre_claimed = {first_fake: "13900000000"}
        _, second_key, _ = replace(
            text, entities, config=config, salt=7, key=pre_claimed
        )

        # Find the new fake (anything NOT first_fake)
        new_fakes = [k for k in second_key if k != first_fake]
        assert len(new_fakes) == 1, "Re-roll should have produced one new fake"
        assert new_fakes[0].startswith("19999"), f"Got {new_fakes[0]}"
        assert second_key[new_fakes[0]] == "13912345678"


class TestLangAwareLookup:
    """`_find_faker_reserved` must prefer entity's detected lang, then 'shared', then any.

    Critical for v0.5.1 where en + zh both register `phone`/`address`/`person`.
    """

    def setup_method(self):
        # Save any existing en/phone registration so teardown can restore it
        # (specs/en.py registers a real one in v0.5.1+).
        from argus_redact.specs.registry import _REGISTRY

        self._original_en_phone = _REGISTRY.get(("en", "phone"))

        def _en_phone_faker(value: str, rng: random.Random) -> tuple[str, list[str]]:
            return "(555) 555-0100", []

        register(
            PIITypeDef(
                name="phone",
                lang="en",
                format="(NNN) NNN-NNNN",
                faker_reserved=_en_phone_faker,
            )
        )
        _faker_reserved_cached.cache_clear()

    def teardown_method(self):
        if self._original_en_phone is not None:
            register(self._original_en_phone)
        else:
            unregister("en", "phone")
        _faker_reserved_cached.cache_clear()

    def test_should_prefer_detected_lang(self):
        # v0.7.5: built-in zh/phone is callable-less; lang preference resolves
        # through `_resolve_realistic_faker` (built-in zh association vs. the
        # custom en callable registered in setup). The detected lang must win.

        # zh detected → built-in zh fake_phone_reserved (199-99 prefix)
        kind, ref = _resolve_realistic_faker("phone", ["zh"])
        assert kind == "builtin", f"Expected zh built-in, got {kind}:{ref}"
        assert ref == "fake_phone_reserved", f"Expected zh faker name, got {ref}"

        # en detected → custom _en_phone_faker (555 prefix), via the callback path
        kind, ref = _resolve_realistic_faker("phone", ["en"])
        assert kind == "custom", f"Expected en custom, got {kind}:{ref}"
        result, _ = ref("415-555-1234", random.Random(1))
        assert "(555)" in result, f"Expected en phone, got {result}"

    def test_should_fall_through_to_shared_when_lang_not_registered(self):
        # 'ja' not registered → falls through; with no shared/phone, returns first available
        faker = _find_faker_reserved("phone", ["ja"])
        # Either zh or en faker is acceptable as fallback (any-match)
        assert faker is not None

    def test_should_return_none_when_no_faker_reserved_anywhere(self):
        assert _find_faker_reserved("nonexistent_type_xyz", ["zh", "en"]) is None

    def test_replace_should_use_lang_preference(self):
        # When replace() gets langs=["en"], should pick en faker for phone
        text = "call (415) 555-1234"
        entities = [make_match("(415) 555-1234", "phone", 5)]
        config = {"phone": {"strategy": "realistic"}}
        _, key, _ = replace(text, entities, config=config, salt=42, langs=["en"])
        fake = next(iter(key))
        assert "(555)" in fake, f"Expected en phone shape, got {fake}"


class TestFakerTupleEnforced:
    """v0.6.0: faker_reserved must return tuple[str, list[str]]; bare string raises."""

    def test_bare_string_faker_raises_type_error(self):
        def bad_faker(value, rng):
            return "FAKE"  # legacy bare-string return

        register(
            PIITypeDef(
                name="bad_faker_test_type",
                lang="shared",
                format="test",
                faker_reserved=bad_faker,
            )
        )
        try:
            with pytest.raises((TypeError, ValueError)):
                replace(
                    "orig value",
                    [make_match("orig", "bad_faker_test_type", 0)],
                    config={"bad_faker_test_type": {"strategy": "realistic"}},
                    salt=b"saltsaltsaltsaltsaltsaltsaltsalt",
                )
        finally:
            unregister("shared", "bad_faker_test_type")


class TestRealisticNumeric:
    def test_realistic_age_should_shift_within_band(self):
        text = "年龄32岁"
        entities = [make_match("32岁", "age", 2)]
        config = {"age": {"strategy": "realistic"}}
        redacted, key, _ = replace(text, entities, config=config, salt=42)

        fakes = list(key.keys())
        assert len(fakes) == 1
        fake = fakes[0]
        assert "岁" in fake
        n = int(re.search(r"\d+", fake).group())
        assert n != 32, "Identity mapping not avoided"
        assert 27 <= n <= 37, f"Expected 32 ±5, got {n}"
