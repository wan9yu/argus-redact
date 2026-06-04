"""Tests for hardening: collision auto-expand, config file, pseudonym format."""

import json

from argus_redact import redact
from argus_redact.pure.pseudonym import PseudonymGenerator


class TestPseudonymAutoExpand:
    def test_should_auto_expand_when_range_exhausted(self):
        gen = PseudonymGenerator(seed=42, code_range=(1, 5))

        codes = set()
        for i in range(10):
            code = gen.get(f"entity_{i}")
            codes.add(code)

        assert len(codes) == 10


class TestConfigFilePath:
    def test_should_load_json_config_from_file(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(
            json.dumps({"phone": {"strategy": "remove", "replacement": "[TEL]"}}),
            encoding="utf-8",
        )

        redacted, key = redact(
            "电话13812345678",
            salt=42,
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
        config_file.write_text(
            "phone:\n  strategy: remove\n  replacement: '[TEL]'\n", encoding="utf-8"
        )

        redacted, key = redact(
            "电话13812345678",
            salt=42,
            mode="fast",
            config=str(config_file),
        )

        assert "13812345678" not in redacted
        assert any("[TEL]" in k for k in key)


def test_redact_middleware_no_longer_exists():
    """v0.6.10: RedactMiddleware was a no-op stub (no __call__); deleted in favor of redact_body."""
    import argus_redact.integrations.fastapi_middleware as m

    assert not hasattr(m, "RedactMiddleware"), (
        "RedactMiddleware was a no-op (__init__ only); use redact_body endpoint helper instead"
    )


def test_streaming_buffer_module_gone():
    """v0.6.10: _StreamingBuffer was private; replaced by StreamingRestorer logic in v0.5.x."""
    import pytest

    with pytest.raises(ImportError):
        from argus_redact.glue import _streaming_buffer  # noqa


def test_generate_pseudonym_function_gone_but_class_stays():
    """v0.6.10: standalone function duplicated PseudonymGenerator class API; deleted."""
    import argus_redact.pure.pseudonym as p

    assert not hasattr(p, "generate_pseudonym"), "function should be deleted"
    assert hasattr(p, "PseudonymGenerator"), "class must stay"
