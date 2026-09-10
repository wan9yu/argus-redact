"""Tests for `strategy_overrides` parameter on redact_pseudonym_llm().

v0.5.5: callers can override the per-type strategy chosen by the active profile
on a per-call basis without forking the profile. Audit pass is unaffected
(audit_text always produces placeholders for compliance archive).
"""

import pytest

from argus_redact.glue.redact_pseudonym_llm import redact_pseudonym_llm
from argus_redact.specs.profiles import _PSEUDONYM_LLM_STRATEGIES


class TestStrategyOverridesBasic:
    def test_phone_override_should_replace_downstream_with_placeholder_when_strategy_is_remove(
        self,
    ):
        text = "请拨打 13912345678 联系王建国"

        result = redact_pseudonym_llm(
            text,
            lang="zh",
            salt=b"fixed-salt-for-test",
            strategy_overrides={"phone": "remove"},
        )

        # phone fake is no longer the realistic 199-99 reserved range
        assert "19999" not in result.downstream_text
        # original phone is fully removed
        assert "13912345678" not in result.downstream_text
        # placeholder for phone is PHON-NNNNN
        assert "PHON-" in result.downstream_text

    def test_address_override_should_change_downstream_only_when_strategy_is_mask(self):
        # Address is in the profile (realistic by default). Override to mask
        # — verify downstream changes shape, audit still placeholder.
        text = "地址北京市朝阳区建国路100号"
        baseline = redact_pseudonym_llm(text, lang="zh", salt=b"fixed")

        result = redact_pseudonym_llm(
            text,
            lang="zh",
            salt=b"fixed",
            strategy_overrides={"address": "mask"},
        )

        # Override changed the downstream shape relative to baseline
        assert result.downstream_text != baseline.downstream_text
        # Audit is identical between the two (placeholder)
        assert result.audit_text == baseline.audit_text


class TestStrategyOverridesValidation:
    def test_strategy_override_should_raise_value_error_when_strategy_is_invalid(self):
        with pytest.raises(ValueError) as exc:
            redact_pseudonym_llm(
                "电话13912345678",
                lang="zh",
                salt=b"fixed-salt-for-test",
                strategy_overrides={"phone": "bogus"},
            )
        assert "Must be one of:" in str(exc.value)
        assert "realistic" in str(exc.value)


class TestStrategyOverridesDoesNotAffectAudit:
    def test_audit_text_should_remain_placeholder_when_downstream_strategy_is_overridden(self):
        text = "请拨打 13912345678 联系王建国"
        # Override phone to "mask" — downstream gets masked digits
        # but audit must still emit placeholders (compliance archive).

        result = redact_pseudonym_llm(
            text,
            lang="zh",
            salt=b"fixed-salt-for-test",
            strategy_overrides={"phone": "mask"},
        )

        # downstream got mask treatment (139****5678 etc.)
        assert "13912345678" not in result.downstream_text
        # audit got placeholder, not the mask form
        assert "139****" not in result.audit_text
        assert "PHON-" in result.audit_text
        # Original phone fully redacted in audit too
        assert "13912345678" not in result.audit_text


class TestStrategyOverridesDoesNotPolluteProfile:
    def test_strategy_overrides_should_not_mutate_the_static_profile_table(self):
        # Snapshot the profile config before any call
        before = {k: dict(v) for k, v in _PSEUDONYM_LLM_STRATEGIES.items()}

        redact_pseudonym_llm(
            "电话13912345678",
            lang="zh",
            salt=b"fixed-salt-for-test",
            strategy_overrides={"phone": "remove"},
        )

        # The static profile table must be unchanged
        after = {k: dict(v) for k, v in _PSEUDONYM_LLM_STRATEGIES.items()}
        assert after == before, "strategy_overrides leaked into static profile config"

        # And a subsequent call without overrides goes back to baseline behavior
        baseline = redact_pseudonym_llm(
            "电话13912345678",
            lang="zh",
            salt=b"fixed-salt",
        )
        # baseline downstream uses realistic 199-99 reserved range
        assert "19999" in baseline.downstream_text
