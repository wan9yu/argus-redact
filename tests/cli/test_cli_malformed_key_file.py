"""The CLI's malformed-input nets have three holes.

The HTTP face already answers 400 'key must be a JSON object'. The CLI:

  1. accepted a key file holding a JSON ARRAY on ``redact``, silently ignored
     it, exited 0, and OVERWROTE the operator's file — data destroyed with no
     error at all;
  2. raised a raw ``IsADirectoryError`` traceback when the input path was a
     directory (``_safe_io.safe_read_text`` raises an ``OSError`` subclass,
     which is not in the ``(ValueError, TypeError, FileNotFoundError)`` net);
  3. raised a raw ``TypeError: key must be a Mapping, got list`` traceback on
     ``restore`` with the same array key file — the exception is raised
     outside the handler's try block.
"""

from __future__ import annotations

import json

from tests.cli.conftest import run_cli


class TestNonObjectKeyFile:
    def test_redact_rejects_array_key_file_and_leaves_it_intact(self, tmp_path):
        key_file = tmp_path / "L.json"
        original = "[1, 2, 3]"
        key_file.write_text(original, encoding="utf-8")

        code, stdout, stderr = run_cli(
            "redact", "-k", str(key_file), "-m", "fast", stdin="联系 13800138000"
        )

        assert code != 0, f"exited 0 having destroyed the file; stdout={stdout!r}"
        assert "Error:" in stderr
        assert "Traceback" not in stderr
        # The operator's file must survive a rejected run.
        assert json.loads(key_file.read_text(encoding="utf-8")) == [1, 2, 3]

    def test_restore_rejects_array_key_file_cleanly(self, tmp_path):
        key_file = tmp_path / "list.json"
        key_file.write_text("[1, 2, 3]", encoding="utf-8")

        code, stdout, stderr = run_cli("restore", "-k", str(key_file), stdin="x")

        assert code != 0
        assert "Error:" in stderr
        assert "Traceback" not in stderr

    def test_redact_still_accepts_a_real_existing_key_file(self, tmp_path):
        """Positive control — the object case must keep merging."""
        key_file = tmp_path / "k.json"
        key_file.write_text(
            json.dumps({"138****9999": "13800139999"}, ensure_ascii=False), encoding="utf-8"
        )

        code, stdout, stderr = run_cli(
            "redact", "-k", str(key_file), "-m", "fast", stdin="联系 13800138000"
        )

        assert code == 0, stderr
        merged = json.loads(key_file.read_text(encoding="utf-8"))
        assert merged["138****9999"] == "13800139999"


class TestDirectoryAsInput:
    def test_redact_directory_input_gives_clean_error(self, tmp_path):
        adir = tmp_path / "adir"
        adir.mkdir()
        key_file = tmp_path / "k.json"

        code, stdout, stderr = run_cli("redact", str(adir), "-k", str(key_file), "-m", "fast")

        assert code != 0
        assert "Error:" in stderr
        assert "Traceback" not in stderr

    def test_restore_directory_input_gives_clean_error(self, tmp_path):
        adir = tmp_path / "adir"
        adir.mkdir()
        key_file = tmp_path / "k.json"
        key_file.write_text("{}", encoding="utf-8")

        code, stdout, stderr = run_cli("restore", str(adir), "-k", str(key_file))

        assert code != 0
        assert "Error:" in stderr
        assert "Traceback" not in stderr
