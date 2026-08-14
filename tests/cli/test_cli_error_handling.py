"""CLI cluster — clean `Error:` + nonzero exit instead of a raw traceback.

Three `cmd_redact` crashes fixed:
  - `--seed abc` (non-int seed) -> uncaught ValueError from int(args.seed).
  - `--profile pseudonym-llm` with no `--seed` -> realistic strategy needs a
    salt, uncaught ValueError from inside redact_pseudonym_llm.
  - `--lang zh,` (trailing comma) -> empty segment -> "Unknown language ''".
"""

from __future__ import annotations

import subprocess
import sys

from tests.cli.conftest import run_cli


class TestSeedValidation:
    def test_non_int_seed_gives_clean_error(self, tmp_path):
        key_file = tmp_path / "key.json"

        code, stdout, stderr = run_cli(
            "redact",
            "-k",
            str(key_file),
            "-m",
            "fast",
            "-s",
            "abc",
            stdin="电话13812345678",
        )

        assert code != 0
        assert "Error:" in stderr
        assert "Traceback" not in stderr
        assert "--seed" in stderr


class TestPseudonymLlmRequiresSeed:
    def test_pseudonym_llm_without_seed_gives_clean_error(self, tmp_path):
        key_file = tmp_path / "key.json"

        code, stdout, stderr = run_cli(
            "redact",
            "-k",
            str(key_file),
            "-m",
            "fast",
            "--profile",
            "pseudonym-llm",
            stdin="电话13812345678",
        )

        assert code != 0
        assert "Error:" in stderr
        assert "Traceback" not in stderr
        assert "--seed" in stderr

    def test_pseudonym_llm_with_seed_succeeds(self, tmp_path):
        key_file = tmp_path / "key.json"

        code, stdout, stderr = run_cli(
            "redact",
            "-k",
            str(key_file),
            "-m",
            "fast",
            "-s",
            "42",
            "--profile",
            "pseudonym-llm",
            stdin="电话13812345678",
        )

        assert code == 0, stderr
        assert "Traceback" not in stderr


class TestTrailingCommaLang:
    def test_trailing_comma_lang_is_filtered_not_crashed(self, tmp_path):
        key_file = tmp_path / "key.json"

        code, stdout, stderr = run_cli(
            "redact",
            "-k",
            str(key_file),
            "-m",
            "fast",
            "-l",
            "zh,",
            "-s",
            "42",
            stdin="电话13812345678",
        )

        assert code == 0, stderr
        assert "Traceback" not in stderr
        assert "13812345678" not in stdout


class TestOversizedSeed:
    def test_oversized_seed_gives_clean_error_not_traceback(self, tmp_path):
        # int(args.seed) accepts arbitrarily large ints; the salt->8-byte
        # coercion then raised an uncaught OverflowError (missed by the CLI's
        # (ValueError, TypeError, FileNotFoundError) net) -> raw traceback.
        key_file = tmp_path / "key.json"

        code, stdout, stderr = run_cli(
            "redact",
            "-k",
            str(key_file),
            "-m",
            "fast",
            "-s",
            "18446744073709551616",  # 2**64 — one past the 8-byte range
            "--profile",
            "pseudonym-llm",
            stdin="电话13812345678",
        )

        assert code != 0
        assert "Error:" in stderr
        assert "Traceback" not in stderr
        assert "OverflowError" not in stderr
        assert "out of range" in stderr


class TestNonUtf8Stdin:
    def test_non_utf8_stdin_gives_clean_error_not_traceback(self, tmp_path):
        # The file branch already guards UnicodeDecodeError; the stdin branch
        # decoded raw bytes as UTF-8 with no guard -> raw traceback. run_cli
        # pins text=True/encoding=utf-8, so bytes stdin needs a direct call.
        key_file = tmp_path / "key.json"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "argus_redact.cli.main",
                "redact",
                "-k",
                str(key_file),
                "-m",
                "fast",
                "-s",
                "42",
            ],
            input=b"\xff\xfe\x00 not utf-8",
            capture_output=True,
        )
        stderr = result.stderr.decode("utf-8", errors="replace")

        assert result.returncode == 1
        assert "Error:" in stderr
        assert "Traceback" not in stderr
        assert "UnicodeDecodeError" not in stderr
        assert "not valid UTF-8" in stderr


class TestProfileConfigCliRegression:
    def test_profile_and_config_file_together_succeeds(self, tmp_path):
        """(b) library-level C1 fix exercised end-to-end through the CLI."""
        import json

        key_file = tmp_path / "key.json"
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"phone": {"strategy": "mask"}}), encoding="utf-8")

        code, stdout, stderr = run_cli(
            "redact",
            "-k",
            str(key_file),
            "-m",
            "fast",
            "-c",
            str(config_file),
            "--profile",
            "gdpr",
            stdin="电话13812345678",
        )

        assert code == 0, stderr
        assert "Traceback" not in stderr
