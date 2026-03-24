"""Tests for pseudonym generation."""

import pytest

from argus_redact.pure.pseudonym import generate_pseudonym, PseudonymGenerator


class TestGeneratePseudonym:
    """Single pseudonym code generation."""

    def test_default_prefix(self):
        code = generate_pseudonym(seed=42)
        assert code.startswith("P-")

    def test_custom_prefix(self):
        code = generate_pseudonym(prefix="O", seed=42)
        assert code.startswith("O-")

    def test_code_in_range(self):
        code = generate_pseudonym(seed=42, code_range=(1, 999))
        num = int(code.split("-")[1])
        assert 1 <= num <= 999

    def test_seed_determinism(self):
        a = generate_pseudonym(seed=42)
        b = generate_pseudonym(seed=42)
        assert a == b

    def test_different_seeds_differ(self):
        a = generate_pseudonym(seed=42)
        b = generate_pseudonym(seed=99)
        assert a != b

    def test_no_seed_is_random(self):
        """Without seed, codes should vary (probabilistically)."""
        codes = {generate_pseudonym() for _ in range(20)}
        assert len(codes) > 1


class TestPseudonymGenerator:
    """Stateful generator that tracks used codes and entity mappings."""

    def test_same_entity_same_code(self):
        gen = PseudonymGenerator(seed=42)
        a = gen.get("张三")
        b = gen.get("张三")
        assert a == b

    def test_different_entities_different_codes(self):
        gen = PseudonymGenerator(seed=42)
        a = gen.get("张三")
        b = gen.get("李四")
        assert a != b

    def test_codes_are_unique(self):
        gen = PseudonymGenerator(seed=42)
        codes = [gen.get(f"person_{i}") for i in range(50)]
        assert len(set(codes)) == 50

    def test_with_existing_key(self):
        """Reuse pseudonyms from an existing key."""
        existing = {"P-037": "张三"}
        gen = PseudonymGenerator(seed=42, existing_key=existing)
        code = gen.get("张三")
        assert code == "P-037"

    def test_new_entity_with_existing_key(self):
        existing = {"P-037": "张三"}
        gen = PseudonymGenerator(seed=42, existing_key=existing)
        code = gen.get("李四")
        assert code != "P-037"  # no collision with existing
        assert code.startswith("P-")

    def test_no_collision_with_existing(self):
        """New codes must not collide with existing key entries."""
        existing = {f"P-{i}": f"person_{i}" for i in range(1, 100)}
        gen = PseudonymGenerator(seed=42, existing_key=existing, code_range=(1, 200))
        new_code = gen.get("new_person")
        assert new_code not in existing

    def test_custom_prefix(self):
        gen = PseudonymGenerator(seed=42, prefix="O")
        code = gen.get("阿里巴巴")
        assert code.startswith("O-")
