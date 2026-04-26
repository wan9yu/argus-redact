"""Tests for the 'realistic' strategy dispatch in pure/replacer.py."""

from argus_redact.pure.replacer import VALID_STRATEGIES, replace
from argus_redact.specs import zh as _zh  # noqa: F401  ensure registration

from tests.conftest import make_match


class TestRealisticStrategy:
    def test_realistic_should_be_in_valid_strategies(self):
        assert "realistic" in VALID_STRATEGIES

    def test_realistic_should_call_faker_reserved_for_phone(self):
        text = "请拨打 13912345678"
        entities = [make_match("13912345678", "phone", 4)]
        config = {"phone": {"strategy": "realistic"}}
        redacted, key = replace(text, entities, config=config, seed=42)

        assert "13912345678" not in redacted
        fakes = list(key.keys())
        assert len(fakes) == 1
        assert fakes[0].startswith("19999"), f"Got {fakes[0]}"
        assert key[fakes[0]] == "13912345678"

    def test_realistic_should_be_deterministic_with_same_seed(self):
        text = "联系 13912345678"
        entities = [make_match("13912345678", "phone", 3)]
        config = {"phone": {"strategy": "realistic"}}
        a, _ = replace(text, entities, config=config, seed=7)
        b, _ = replace(text, entities, config=config, seed=7)
        assert a == b

    def test_realistic_should_fall_back_to_pseudonym_when_no_faker_reserved(self):
        text = "公司名 ABC公司"
        entities = [make_match("ABC公司", "organization", 4)]
        config = {"organization": {"strategy": "realistic"}}
        redacted, key = replace(text, entities, config=config, seed=42)

        fakes = list(key.keys())
        assert len(fakes) == 1
        assert fakes[0].startswith("O-"), f"Got {fakes[0]}"

    def test_realistic_should_re_roll_on_collision(self):
        """Pre-claim the first-attempt fake; re-roll must produce a different one."""
        text = "联系 13912345678"
        entities = [make_match("13912345678", "phone", 3)]
        config = {"phone": {"strategy": "realistic"}}

        # First, learn what the first-attempt fake would be
        _, first_key = replace(text, entities, config=config, seed=7)
        first_fake = next(iter(first_key))

        # Now seed the replace() with a key that already claims first_fake for a different original
        # → forces _generate_unique_fake to re-roll
        pre_claimed = {first_fake: "13900000000"}
        _, second_key = replace(
            text, entities, config=config, seed=7, key=pre_claimed
        )

        # Find the new fake (anything NOT first_fake)
        new_fakes = [k for k in second_key if k != first_fake]
        assert len(new_fakes) == 1, "Re-roll should have produced one new fake"
        assert new_fakes[0].startswith("19999"), f"Got {new_fakes[0]}"
        assert second_key[new_fakes[0]] == "13912345678"
