"""Tests for CLI --strategy-override flag (v0.5.5).

Mirrors the per-call `strategy_overrides` parameter on `redact_pseudonym_llm`
so shell pipelines can change per-type strategy without writing Python.
"""

import json
import subprocess
import sys

import pytest


def run_cli(*args, stdin=None):
    result = subprocess.run(
        [sys.executable, "-m", "argus_redact.cli.main", *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.returncode, result.stdout, result.stderr


class TestParseStrategyOverride:
    """Direct unit tests on the _parse_strategy_override helper."""

    def test_parse_basic_pair(self):
        from argus_redact.cli.main import _parse_strategy_override

        out = _parse_strategy_override("phone:realistic,address:remove")
        assert out == {"phone": "realistic", "address": "remove"}

    def test_parse_empty_or_none(self):
        from argus_redact.cli.main import _parse_strategy_override

        assert _parse_strategy_override(None) is None
        assert _parse_strategy_override("") is None

    def test_parse_extra_whitespace(self):
        from argus_redact.cli.main import _parse_strategy_override

        out = _parse_strategy_override(" phone : realistic , address : remove ")
        assert out == {"phone": "realistic", "address": "remove"}

    def test_parse_invalid_pair_no_colon_raises(self):
        from argus_redact.cli.main import _parse_strategy_override

        with pytest.raises(ValueError) as exc:
            _parse_strategy_override("phone")
        assert "phone" in str(exc.value)

    def test_parse_empty_type_or_strategy_raises(self):
        from argus_redact.cli.main import _parse_strategy_override

        with pytest.raises(ValueError):
            _parse_strategy_override(":realistic")
        with pytest.raises(ValueError):
            _parse_strategy_override("phone:")


class TestCliEndToEnd:
    def test_should_apply_override_when_profile_is_pseudonym_llm(self, tmp_path):
        key_file = tmp_path / "key.json"

        code, stdout, stderr = run_cli(
            "redact",
            "-k", str(key_file),
            "--profile", "pseudonym-llm",
            "--strategy-override", "phone:remove",
            stdin="请拨打 13912345678 联系王建国",
        )

        assert code == 0, f"stderr: {stderr}"
        payload = json.loads(stdout)
        # Override took effect: phone is no longer realistic 199-99
        assert "19999" not in payload["downstream_text"]
        # And original phone is gone
        assert "13912345678" not in payload["downstream_text"]
        # Placeholder shape PHON-NNNNN appears
        assert "PHON-" in payload["downstream_text"]

    def test_should_reject_override_without_pseudonym_llm_profile(self, tmp_path):
        key_file = tmp_path / "key.json"

        code, _, stderr = run_cli(
            "redact",
            "-k", str(key_file),
            "--strategy-override", "phone:remove",
            stdin="电话13912345678",
        )

        assert code != 0, "should error when profile is not pseudonym-llm"
        assert "pseudonym-llm" in stderr.lower() or "strategy-override" in stderr.lower()

    def test_should_error_on_malformed_override(self, tmp_path):
        key_file = tmp_path / "key.json"

        code, _, stderr = run_cli(
            "redact",
            "-k", str(key_file),
            "--profile", "pseudonym-llm",
            "--strategy-override", "phone-realistic",  # missing colon
            stdin="电话13912345678",
        )

        assert code != 0
