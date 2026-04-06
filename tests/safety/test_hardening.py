"""Tests for hardening: collision auto-expand, config file, pseudonym format."""

import json

from argus_redact import redact
from argus_redact.pure.pseudonym import PseudonymGenerator, generate_pseudonym


class TestPseudonymAutoExpand:
    def test_should_auto_expand_when_range_exhausted(self):
        gen = PseudonymGenerator(seed=42, code_range=(1, 5))

        codes = set()
        for i in range(10):
            code = gen.get(f"entity_{i}")
            codes.add(code)

        assert len(codes) == 10

    def test_should_use_5_digit_format(self):
        code = generate_pseudonym(seed=42)

        parts = code.split("-")
        assert len(parts[1]) == 5


class TestConfigFilePath:
    def test_should_load_json_config_from_file(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(
            json.dumps({"phone": {"strategy": "remove", "replacement": "[TEL]"}}),
        )

        redacted, key = redact(
            "电话13812345678",
            seed=42,
            mode="fast",
            config=str(config_file),
        )

        assert "13812345678" not in redacted
        assert any("[TEL]" in k for k in key)

    def test_should_load_yaml_config_from_file(self, tmp_path):
        import importlib.util

        if not importlib.util.find_spec("yaml"):
            import pytest

            pytest.skip("pyyaml not installed")

        config_file = tmp_path / "config.yaml"
        config_file.write_text("phone:\n  strategy: remove\n  replacement: '[TEL]'\n")

        redacted, key = redact(
            "电话13812345678",
            seed=42,
            mode="fast",
            config=str(config_file),
        )

        assert "13812345678" not in redacted
        assert any("[TEL]" in k for k in key)
