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
