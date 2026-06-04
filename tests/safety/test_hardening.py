"""Tests for hardening: collision auto-expand, config file, pseudonym format."""

import json
from pathlib import Path

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


def test_server_bearer_uses_compare_digest():
    """v0.6.10: constant-time comparison closes the timing side-channel."""
    src = (Path(__file__).resolve().parents[2] / "src/argus_redact/server.py").read_text()
    auth_idx = src.find("authorization")
    assert auth_idx != -1, "could not locate auth check in server.py"
    auth_section = src[auth_idx:auth_idx + 800]
    assert "compare_digest" in auth_section, (
        "server bearer comparison still uses raw != — must use secrets.compare_digest"
    )


def test_demo_salt_carries_security_warning():
    """v0.6.10: DEMO_SALT must be marked clearly as HF-demo-only.

    Without this guard, a copy-paste of the demo's hardcoded salt into a
    production setup would silently make all fakes derivable from observed
    input. The comment is the only signal a copying developer would see.
    """
    src = (Path(__file__).resolve().parents[2] / "demo/app.py").read_text()
    assert "Hardcoded for a public HF demo" in src, (
        "demo/app.py DEMO_SALT must carry explicit public-demo warning comment"
    )
    assert "secrets.token_bytes" in src, (
        "warning comment must point at the production-grade alternative"
    )
