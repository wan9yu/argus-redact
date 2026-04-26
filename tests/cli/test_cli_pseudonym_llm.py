"""Tests for `argus-redact redact --profile pseudonym-llm`.

The pseudonym-llm profile emits structured JSON with three text forms:
audit_text (placeholder), downstream_text (realistic), display_text (marked).
"""

import json
import subprocess
import sys


def run_cli(*args, stdin=None):
    result = subprocess.run(
        [sys.executable, "-m", "argus_redact.cli.main", *args],
        input=stdin,
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


class TestPseudonymLLMProfile:
    def test_should_emit_json_with_three_text_forms(self, tmp_path):
        key_file = tmp_path / "key.json"

        code, stdout, stderr = run_cli(
            "redact",
            "-k",
            str(key_file),
            "--profile",
            "pseudonym-llm",
            stdin="请拨打 13912345678 联系王建国",
        )

        assert code == 0, f"stderr: {stderr}"
        payload = json.loads(stdout)
        assert set(payload.keys()) >= {"audit_text", "downstream_text", "display_text", "key"}
        assert "13912345678" not in payload["downstream_text"]
        assert "19999" in payload["downstream_text"]
        assert "ⓕ" in payload["display_text"]

    def test_key_file_should_contain_unified_mapping(self, tmp_path):
        key_file = tmp_path / "key.json"

        code, _, _ = run_cli(
            "redact",
            "-k",
            str(key_file),
            "--profile",
            "pseudonym-llm",
            stdin="请拨打 13912345678",
        )

        assert code == 0
        assert key_file.exists()
        key = json.loads(key_file.read_text())
        # Original phone must appear as a value in the unified key
        assert "13912345678" in key.values()

    def test_should_round_trip_via_restore_command(self, tmp_path):
        key_file = tmp_path / "key.json"
        text = "请拨打 13912345678 联系王建国"

        code, stdout, _ = run_cli(
            "redact",
            "-k",
            str(key_file),
            "--profile",
            "pseudonym-llm",
            stdin=text,
        )
        assert code == 0
        payload = json.loads(stdout)

        # Restore downstream_text via the key file
        code2, restored, _ = run_cli(
            "restore",
            "-k",
            str(key_file),
            stdin=payload["downstream_text"],
        )
        assert code2 == 0
        assert restored.strip() == text


class TestStandardProfileBackwardCompat:
    def test_pipl_profile_should_still_emit_text(self, tmp_path):
        """--profile pipl (non-pseudonym-llm) keeps original text-output behavior."""
        key_file = tmp_path / "key.json"

        code, stdout, stderr = run_cli(
            "redact",
            "-k",
            str(key_file),
            "--profile",
            "pipl",
            "-s",
            "42",
            stdin="电话13812345678",
        )

        assert code == 0, f"stderr: {stderr}"
        # Should be plain text, not JSON
        assert not stdout.strip().startswith("{")
        assert "13812345678" not in stdout

    def test_no_profile_should_keep_default_behavior(self, tmp_path):
        """Existing CLI calls without --profile must continue working unchanged."""
        key_file = tmp_path / "key.json"

        code, stdout, _ = run_cli(
            "redact",
            "-k",
            str(key_file),
            "-s",
            "42",
            stdin="电话13812345678",
        )

        assert code == 0
        assert not stdout.strip().startswith("{")
        assert "13812345678" not in stdout
