"""Tests for compliance profiles and per-type filtering."""

from argus_redact import redact


class TestProfileFiltering:
    def test_should_detect_all_types_with_default_profile(self):
        text = "手机13812345678，身份证110101199003074610"
        result, key = redact(text, lang="zh", mode="fast")
        assert len(key) >= 2

    def test_should_accept_profile_parameter(self):
        text = "手机13812345678"
        result, key = redact(text, lang="zh", mode="fast", profile="pipl")
        assert len(key) >= 1

    def test_should_accept_profile_default(self):
        text = "手机13812345678"
        result, key = redact(text, lang="zh", mode="fast", profile="default")
        assert len(key) >= 1

    def test_should_raise_on_unknown_profile(self):
        import pytest

        with pytest.raises(ValueError, match="Unknown profile"):
            redact("test", lang="zh", mode="fast", profile="nonexistent")


class TestTypeFiltering:
    def test_should_filter_by_types_whitelist(self):
        text = "手机13812345678，身份证110101199003074610"
        _, key = redact(text, lang="zh", mode="fast", types=["phone"])
        # Should only detect phone, not id_number
        values = list(key.values())
        assert any("138" in v for v in values)
        # id_number should not be in key
        assert not any("110101" in v for v in values)

    def test_should_filter_by_types_exclude(self):
        text = "手机13812345678，身份证110101199003074610"
        _, key = redact(text, lang="zh", mode="fast", types_exclude=["phone"])
        # Should detect id_number but not phone
        values = list(key.values())
        assert any("110101" in v for v in values)
        assert not any("138" in v for v in values)

    def test_types_and_types_exclude_are_mutually_exclusive(self):
        import pytest

        with pytest.raises(ValueError, match="mutually exclusive"):
            redact("test", lang="zh", mode="fast", types=["phone"], types_exclude=["id_number"])

    def test_should_return_empty_key_when_type_not_present(self):
        text = "手机13812345678"
        _, key = redact(text, lang="zh", mode="fast", types=["id_number"])
        assert len(key) == 0


class TestProfileStrategy:
    """Compliance profiles should override strategies for stricter privacy."""

    def test_pipl_should_not_use_mask_for_phone(self):
        """PIPL profile: phone should use pseudonym, not mask (mask leaks prefix+suffix)."""
        text = "手机13812345678"
        redacted, key = redact(text, lang="zh", mode="fast", profile="pipl")

        # Full phone number must not appear; mask pattern (138****5678) must not appear
        assert "13812345678" not in redacted
        assert "****" not in redacted

    def test_pipl_should_not_use_mask_for_email(self):
        text = "邮箱zhang@example.com"
        redacted, key = redact(text, lang="zh", mode="fast", profile="pipl")

        assert "zhang" not in redacted
        assert "example.com" not in redacted

    def test_default_profile_still_uses_mask(self):
        """Default profile keeps mask for usability."""
        text = "手机13812345678"
        redacted, key = redact(text, lang="zh", mode="fast")

        # Default mask pattern: 138****5678
        assert "****" in redacted

    def test_hipaa_should_not_use_mask_for_phone(self):
        text = "phone 123-456-7890"
        redacted, key = redact(text, lang="en", mode="fast", profile="hipaa")

        assert "123-456-7890" not in redacted
        assert "****" not in redacted

    def test_pipl_should_not_use_mask_for_phone_landline(self):
        """PIPL profile: landline should be fully redacted, not partially masked."""
        text = "座机010-12345678"
        redacted, key = redact(text, lang="zh", mode="fast", profile="pipl")

        assert "010-12345678" not in redacted
        assert "****" not in redacted

    def test_gdpr_should_not_use_mask_for_phone_landline(self):
        """GDPR profile: landline should be fully redacted, not partially masked."""
        text = "座机010-12345678"
        redacted, key = redact(text, lang="zh", mode="fast", profile="gdpr")

        assert "010-12345678" not in redacted
        assert "****" not in redacted

    def test_hipaa_should_not_use_mask_for_phone_landline(self):
        """HIPAA profile: landline should be fully redacted, not partially masked."""
        text = "座机010-12345678"
        redacted, key = redact(text, lang="zh", mode="fast", profile="hipaa")

        assert "010-12345678" not in redacted
        assert "****" not in redacted


class TestStrictStrategyCoverage:
    """_STRICT_STRATEGIES must cover every mask-default type in the registry."""

    def test_strict_strategies_covers_all_mask_default_types(self):
        """Any type whose default strategy is 'mask' must have a non-leaky override
        in _STRICT_STRATEGIES — so compliance profiles never silently leave a
        partial-reveal mask in place.
        """
        from argus_redact.specs.profiles import _STRICT_STRATEGIES
        from argus_redact.specs.registry import list_types

        mask_type_names = {t.name for t in list_types() if t.strategy == "mask"}
        missing = mask_type_names - set(_STRICT_STRATEGIES.keys())
        assert not missing, (
            f"_STRICT_STRATEGIES is missing overrides for mask-default types: {sorted(missing)}. "
            f"Add each to _STRICT_STRATEGIES with a non-leaky strategy ('remove' or 'pseudonym')."
        )
