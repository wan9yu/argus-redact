"""CLI cluster — clean `Error:` + nonzero exit instead of a raw traceback.

Three `cmd_redact` crashes fixed:
  - `--seed abc` (non-int seed) -> uncaught ValueError from int(args.seed).
  - `--profile pseudonym-llm` with no `--seed` -> realistic strategy needs a
    salt, uncaught ValueError from inside redact_pseudonym_llm.
  - `--lang zh,` (trailing comma) -> empty segment -> "Unknown language ''".
"""

from __future__ import annotations

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
