"""Tests for pseudonym generation."""

from argus_redact.pure.pseudonym import PseudonymGenerator, generate_pseudonym


class TestGeneratePseudonym:
    """Single pseudonym code generation."""

    def test_should_use_default_prefix_when_none_specified(self):
        code = generate_pseudonym(seed=42)

        assert code.startswith("P-")

    def test_should_use_custom_prefix_when_specified(self):
        code = generate_pseudonym(prefix="O", seed=42)

        assert code.startswith("O-")

    def test_should_stay_in_range_when_range_specified(self):
        code = generate_pseudonym(seed=42, code_range=(1, 999))

        num = int(code.split("-")[1])
        assert 1 <= num <= 999

    def test_should_produce_same_code_when_same_seed(self):
        a = generate_pseudonym(seed=42)
        b = generate_pseudonym(seed=42)

        assert a == b

    def test_should_produce_different_codes_when_different_seeds(self):
        a = generate_pseudonym(seed=42)
        b = generate_pseudonym(seed=99)

        assert a != b

    def test_should_vary_when_no_seed(self):
        codes = {generate_pseudonym() for _ in range(20)}

        assert len(codes) > 1


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
