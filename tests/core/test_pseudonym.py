"""Tests for pseudonym generation."""

from argus_redact.pure.pseudonym import PseudonymGenerator


class TestPseudonymGenerator:
    """Stateful generator that tracks used codes and entity mappings."""

    def test_should_return_same_code_when_same_entity_requested_twice(self):
        gen = PseudonymGenerator(seed=42)

        a = gen.get("张三")
        b = gen.get("张三")

        assert a == b

    def test_should_return_different_codes_when_different_entities(self):
        gen = PseudonymGenerator(seed=42)

        a = gen.get("张三")
        b = gen.get("李四")

        assert a != b

    def test_should_produce_unique_codes_when_many_entities(self):
        gen = PseudonymGenerator(seed=42)

        codes = [gen.get(f"person_{i}") for i in range(50)]

        assert len(set(codes)) == 50

    def test_should_reuse_code_when_entity_exists_in_key(self):
        existing = {"P-037": "张三"}
        gen = PseudonymGenerator(seed=42, existing_key=existing)

        code = gen.get("张三")

        assert code == "P-037"

    def test_should_generate_new_code_when_entity_not_in_existing_key(self):
        existing = {"P-037": "张三"}
        gen = PseudonymGenerator(seed=42, existing_key=existing)

        code = gen.get("李四")

        assert code != "P-037"
        assert code.startswith("P-")

    def test_should_avoid_collision_when_existing_key_is_dense(self):
        existing = {f"P-{i}": f"person_{i}" for i in range(1, 100)}
        gen = PseudonymGenerator(seed=42, existing_key=existing, code_range=(1, 200))

        new_code = gen.get("new_person")

        assert new_code not in existing

    def test_should_use_custom_prefix_when_specified(self):
        gen = PseudonymGenerator(seed=42, prefix="O")

        code = gen.get("阿里巴巴")

        assert code.startswith("O-")

    def test_should_expand_range_without_stack_overflow(self):
        """When range is exhausted, should expand and continue (no recursion)."""
        # Fill up a tiny range completely
        gen = PseudonymGenerator(seed=42, code_range=(1, 3))
        codes = set()
        for i in range(10):
            code = gen.get(f"person_{i}")
            codes.add(code)
        # Should have generated 10 unique codes by expanding range
        assert len(codes) == 10

    def test_should_emit_5_digit_zero_padded_suffix(self):
        """Generator output layout is ``<prefix>-NNNNN`` with zero-padded 5-digit suffix."""
        gen = PseudonymGenerator(seed=42, code_range=(1, 1))
        code = gen.get("x")
        prefix, num = code.split("-")
        assert prefix == "P"
        assert len(num) == 5
        assert num.isdigit()


# ─── Mutation-testing-killers ──────────────────────────────────────────


class TestMaxPseudonymLengthInvariants:
    """``max_pseudonym_length`` returns the upper bound on a pseudonym string,
    used by the streaming buffer to size flush windows. Off-by-one would let
    a real pseudonym overflow the buffer and leak through."""

    def test_should_return_dash_plus_5_digits_layout(self):
        from argus_redact.pure.pseudonym import max_pseudonym_length

        # Default prefixes top out at "GH-TOKEN" (8 chars). 8 + "-" + 5 = 14.
        # Any mutant that returns 8 (no-prefix fallback) instead of computing
        # from DEFAULT_PREFIXES is killed.
        result = max_pseudonym_length()
        assert result == 14

    def test_should_grow_when_user_config_has_longer_prefix(self):
        from argus_redact.pure.pseudonym import max_pseudonym_length

        # Custom 10-char prefix → 10 + 1 + 5 = 16
        config = {"person": {"prefix": "VERYLONGPRE"}}  # 11 chars
        result = max_pseudonym_length(config)
        assert result == 11 + 1 + 5

    def test_should_skip_non_dict_config_entries_silently(self):
        from argus_redact.pure.pseudonym import max_pseudonym_length

        # `and` → `or` mutant on the inner check would treat any truthy
        # type_config (e.g. a string) as having a "prefix" key — and try
        # to .add(), exploding. This call must not raise.
        config = {"person": "not a dict"}  # type: ignore[dict-item]
        # Should silently skip non-dict entries
        result = max_pseudonym_length(config)
        assert result == 14  # baseline DEFAULT_PREFIXES result
