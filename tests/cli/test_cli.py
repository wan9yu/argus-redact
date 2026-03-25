"""Tests for CLI — argus-redact redact / restore / info."""

import json
import subprocess
import sys


def run_cli(*args, stdin=None):
    """Run argus-redact CLI and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [sys.executable, "-m", "argus_redact.cli.main", *args],
        input=stdin,
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


class TestRedactCommand:
    def test_should_redact_stdin_when_pipe_mode(self, tmp_path):
        key_file = tmp_path / "key.json"

        code, stdout, _ = run_cli(
            "redact",
            "-k",
            str(key_file),
            "-m",
            "fast",
            "-s",
            "42",
            stdin="电话13812345678",
        )

        assert code == 0
        assert "13812345678" not in stdout
        assert key_file.exists()
        key = json.loads(key_file.read_text())
        assert "13812345678" in key.values()

    def test_should_redact_file_when_input_file_given(self, tmp_path):
        input_file = tmp_path / "input.txt"
        input_file.write_text("邮箱zhang@example.com")
        key_file = tmp_path / "key.json"

        code, stdout, _ = run_cli(
            "redact",
            str(input_file),
            "-k",
            str(key_file),
            "-m",
            "fast",
        )

        assert code == 0
        assert "zhang@example.com" not in stdout

    def test_should_write_output_file_when_o_flag(self, tmp_path):
        key_file = tmp_path / "key.json"
        output_file = tmp_path / "out.txt"

        code, _, _ = run_cli(
            "redact",
            "-k",
            str(key_file),
            "-o",
            str(output_file),
            "-m",
            "fast",
            "-s",
            "42",
            stdin="电话13812345678",
        )

        assert code == 0
        assert output_file.exists()
        assert "13812345678" not in output_file.read_text()

    def test_should_reuse_key_when_key_file_exists(self, tmp_path):
        key_file = tmp_path / "key.json"

        run_cli("redact", "-k", str(key_file), "-m", "fast", "-s", "42", stdin="电话13812345678")
        key1 = json.loads(key_file.read_text())

        run_cli(
            "redact", "-k", str(key_file), "-m", "fast", "-s", "42", stdin="邮箱test@example.com"
        )
        key2 = json.loads(key_file.read_text())

        assert len(key2) > len(key1)
        # Original phone mapping preserved
        for k, v in key1.items():
            assert key2[k] == v

    def test_should_exit_1_when_input_file_not_found(self, tmp_path):
        key_file = tmp_path / "key.json"

        code, _, stderr = run_cli(
            "redact",
            "/nonexistent/file.txt",
            "-k",
            str(key_file),
        )

        assert code == 1

    def test_should_support_lang_flag(self, tmp_path):
        key_file = tmp_path / "key.json"

        code, stdout, _ = run_cli(
            "redact",
            "-k",
            str(key_file),
            "-m",
            "fast",
            "-l",
            "zh",
            stdin="电话13812345678",
        )

        assert code == 0
        assert "13812345678" not in stdout


class TestRestoreCommand:
    def test_should_restore_stdin_when_pipe_mode(self, tmp_path):
        key_file = tmp_path / "key.json"
        key_file.write_text(json.dumps({"P-037": "王五", "P-012": "张三"}))

        code, stdout, _ = run_cli(
            "restore",
            "-k",
            str(key_file),
            stdin="P-037和P-012开会",
        )

        assert code == 0
        assert "王五" in stdout
        assert "张三" in stdout

    def test_should_restore_file_when_input_file_given(self, tmp_path):
        key_file = tmp_path / "key.json"
        key_file.write_text(json.dumps({"P-037": "王五"}))
        input_file = tmp_path / "input.txt"
        input_file.write_text("P-037说了话")

        code, stdout, _ = run_cli(
            "restore",
            str(input_file),
            "-k",
            str(key_file),
        )

        assert code == 0
        assert "王五" in stdout

    def test_should_write_output_file_when_o_flag(self, tmp_path):
        key_file = tmp_path / "key.json"
        key_file.write_text(json.dumps({"P-037": "王五"}))
        output_file = tmp_path / "out.txt"

        code, _, _ = run_cli(
            "restore",
            "-k",
            str(key_file),
            "-o",
            str(output_file),
            stdin="P-037说了话",
        )

        assert code == 0
        assert "王五" in output_file.read_text()

    def test_should_exit_4_when_key_file_not_found(self):
        code, _, stderr = run_cli(
            "restore",
            "-k",
            "/nonexistent/key.json",
            stdin="some text",
        )

        assert code == 4

    def test_should_exit_5_when_key_file_invalid(self, tmp_path):
        key_file = tmp_path / "key.json"
        key_file.write_text("not valid json{{{")

        code, _, stderr = run_cli(
            "restore",
            "-k",
            str(key_file),
            stdin="some text",
        )

        assert code == 5


class TestRedactRestoreRoundtrip:
    def test_should_recover_original_when_redact_then_restore(self, tmp_path):
        key_file = tmp_path / "key.json"
        original = "张三电话13812345678，邮箱zhang@test.com"

        _, redacted, _ = run_cli(
            "redact",
            "-k",
            str(key_file),
            "-m",
            "fast",
            "-s",
            "42",
            stdin=original,
        )

        _, restored, _ = run_cli(
            "restore",
            "-k",
            str(key_file),
            stdin=redacted.strip(),
        )

        assert "13812345678" in restored
        assert "zhang@test.com" in restored


class TestInfoCommand:
    def test_should_show_version_when_info(self):
        code, stdout, _ = run_cli("info")

        assert code == 0
        assert "argus-redact" in stdout
        assert "0.1.2" in stdout

    def test_should_show_all_languages_when_info(self):
        code, stdout, _ = run_cli("info")

        assert "zh" in stdout
        assert "en" in stdout
        assert "ja" in stdout
        assert "ko" in stdout


class TestCliErrors:
    def test_should_show_help_when_no_subcommand(self):
        code, _, stderr = run_cli()

        # argparse shows help on stderr or stdout depending on version
        assert code != 0 or "usage" in (stderr + _).lower()
