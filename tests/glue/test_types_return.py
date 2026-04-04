"""Tests for redact() with_types parameter and max_pseudonym_length utility."""

from argus_redact import redact


class TestWithTypes:
    def test_should_return_types_dict_when_with_types(self):
        redacted, key, types = redact(
            "手机13812345678，身份证110101199003074610",
            mode="fast", seed=42, with_types=True,
        )
        assert isinstance(types, dict)
        assert len(types) == len(key)
        for replacement in key:
            assert replacement in types

    def test_should_map_replacement_to_pii_type(self):
        _, key, types = redact(
            "手机13812345678，身份证110101199003074610",
            mode="fast", seed=42, with_types=True,
        )
        type_values = set(types.values())
        assert "phone" in type_values
        assert "id_number" in type_values

    def test_should_return_2tuple_when_no_with_types(self):
        result = redact("手机13812345678", mode="fast", seed=42)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_should_handle_no_pii(self):
        _, key, types = redact("今天天气不错", mode="fast", with_types=True)
        assert key == {}
        assert types == {}

    def test_should_work_with_multiple_same_type(self):
        _, key, types = redact(
            "手机13812345678和13998765432",
            mode="fast", seed=42, with_types=True,
        )
        phone_types = [t for t in types.values() if t == "phone"]
        assert len(phone_types) >= 1


class TestMaxPseudonymLength:
    def test_should_return_positive_int(self):
        from argus_redact.pure.pseudonym import max_pseudonym_length
        length = max_pseudonym_length()
        assert isinstance(length, int)
        assert length > 0

    def test_should_cover_default_prefixes(self):
        from argus_redact.pure.pseudonym import max_pseudonym_length
        # Default format: PREFIX-NNNNN (e.g. "PLATE-00123" = 11 chars)
        length = max_pseudonym_length()
        assert length >= 11  # longest default prefix "PLATE" + "-" + 5 digits

    def test_should_respect_custom_config(self):
        from argus_redact.pure.pseudonym import max_pseudonym_length
        length = max_pseudonym_length(config={"phone": {"strategy": "pseudonym", "prefix": "TELEPHONE"}})
        assert length >= len("TELEPHONE-00000")
