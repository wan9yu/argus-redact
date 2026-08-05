"""Tests for CLI — argus-redact redact / restore / info."""

import argparse
import importlib.util
import json

import pytest

from argus_redact import __version__
from argus_redact.cli.main import cmd_info
from tests.cli.conftest import run_cli

_REAL_FIND_SPEC = importlib.util.find_spec


def _patch_ner_engines(monkeypatch, *, hanlp: bool, spacy: bool):
    """Force ``importlib.util.find_spec`` to report hanlp/spacy availability,
    delegating every other module name to the real lookup (so the adapter
    module checks — which do reflect real installed files — are untouched)."""

    def fake(name, *args, **kwargs):
        if name == "hanlp":
            return object() if hanlp else None
        if name == "spacy":
            return object() if spacy else None
        return _REAL_FIND_SPEC(name, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "find_spec", fake)


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
        key = json.loads(key_file.read_text(encoding="utf-8"))
        assert "13812345678" in key.values()

    def test_should_redact_file_when_input_file_given(self, tmp_path):
        input_file = tmp_path / "input.txt"
        input_file.write_text("邮箱zhang@example.com", encoding="utf-8")
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
        assert "13812345678" not in output_file.read_text(encoding="utf-8")

    def test_should_reuse_key_when_key_file_exists(self, tmp_path):
        key_file = tmp_path / "key.json"

        run_cli("redact", "-k", str(key_file), "-m", "fast", "-s", "42", stdin="电话13812345678")
        key1 = json.loads(key_file.read_text(encoding="utf-8"))

        run_cli(
            "redact", "-k", str(key_file), "-m", "fast", "-s", "42", stdin="邮箱test@example.com"
        )
        key2 = json.loads(key_file.read_text(encoding="utf-8"))

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
        key_file.write_text(json.dumps({"P-037": "王五", "P-012": "张三"}), encoding="utf-8")

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
        key_file.write_text(json.dumps({"P-037": "王五"}), encoding="utf-8")
        input_file = tmp_path / "input.txt"
        input_file.write_text("P-037说了话", encoding="utf-8")

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
        key_file.write_text(json.dumps({"P-037": "王五"}), encoding="utf-8")
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
        assert "王五" in output_file.read_text(encoding="utf-8")

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
        key_file.write_text("not valid json{{{", encoding="utf-8")

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
        assert __version__ in stdout

    def test_should_show_all_languages_when_info(self):
        code, stdout, _ = run_cli("info")

        assert "zh" in stdout
        assert "en" in stdout
        assert "ja" in stdout
        assert "ko" in stdout
        assert "de" in stdout
        assert "uk" in stdout
        assert "in" in stdout
        assert "br" in stdout
        # Per-lang detail line must survive: regex pattern-count marker.
        # Guards against a regression that drops the per-language detail line.
        # (The "+ NER" marker is exercised separately in
        # TestInfoCommandHonesty — it depends on whether hanlp/spacy are
        # actually installed, which this process-wide subprocess call can't
        # control deterministically.)
        assert "regex (" in stdout


class TestInfoCommandHonesty:
    """H2 — `info` must not claim NER/Ollama capability it can't back up.

    "+ NER" used to fire on the adapter module existing alone, even with
    hanlp/spacy absent (contradicting the Layer-2 "✗" the same output shows).
    The Ollama/L3 line used to read success off of `requests` being
    importable, which says nothing about whether an Ollama endpoint is
    actually reachable.
    """

    def test_no_ner_label_when_engines_absent(self, monkeypatch, capsys):
        _patch_ner_engines(monkeypatch, hanlp=False, spacy=False)

        cmd_info(argparse.Namespace())

        stdout = capsys.readouterr().out
        assert "+ NER" not in stdout, (
            "info must not print '+ NER' when neither hanlp nor spacy is installed"
        )
        assert "2 Entity (NER)          ✗" in stdout

    def test_ner_label_present_when_engines_installed(self, monkeypatch, capsys):
        """Control: don't over-suppress — with the engines available, "+ NER"
        must still appear for languages that ship an adapter."""
        _patch_ner_engines(monkeypatch, hanlp=True, spacy=True)

        cmd_info(argparse.Namespace())

        stdout = capsys.readouterr().out
        assert "+ NER" in stdout
        assert "2 Entity (NER)          ✓" in stdout

    def test_zh_ner_label_depends_only_on_hanlp(self, monkeypatch, capsys):
        """zh's NER engine is hanlp, not spaCy — spaCy alone must not light
        up zh's "+ NER"."""
        _patch_ner_engines(monkeypatch, hanlp=False, spacy=True)

        cmd_info(argparse.Namespace())

        lines = capsys.readouterr().out.splitlines()
        zh_line = next(line for line in lines if line.strip().startswith("zh "))
        assert "+ NER" not in zh_line

    def test_ollama_line_does_not_claim_readiness_from_requests_alone(self, capsys):
        cmd_info(argparse.Namespace())

        stdout = capsys.readouterr().out
        assert "not probed" in stdout, (
            "the Ollama/L3 line must say the endpoint was not probed, "
            "not imply readiness merely because `requests` imports"
        )
        assert "3 Semantic (Ollama)     ✓" not in stdout


class TestMCPInfoHonesty:
    """Parallel check for the MCP `redact_info` tool — same NER-gating fix."""

    def test_ner_flag_false_when_engines_absent(self, monkeypatch):
        pytest.importorskip("mcp")
        import asyncio

        from argus_redact.integrations import mcp_server

        _patch_ner_engines(monkeypatch, hanlp=False, spacy=False)

        result = asyncio.run(mcp_server.redact_info())

        data = json.loads(result)
        assert all(not info["ner"] for info in data["languages"].values()), (
            "MCP info must not report ner: true when neither hanlp nor spacy is installed"
        )

    def test_ner_flag_true_when_engines_installed(self, monkeypatch):
        pytest.importorskip("mcp")
        import asyncio

        from argus_redact.integrations import mcp_server

        _patch_ner_engines(monkeypatch, hanlp=True, spacy=True)

        result = asyncio.run(mcp_server.redact_info())

        data = json.loads(result)
        assert data["languages"]["zh"]["ner"] is True
        assert data["languages"]["en"]["ner"] is True


class TestSetupCommand:
    def test_de_uk_in_not_described_as_regex_only(self):
        """de/uk/in ship NER adapters — setup must not print 'regex only'."""
        for lang in ("de", "uk", "in"):
            _, stdout, stderr = run_cli("setup", "-l", lang)
            combined = stdout + stderr
            assert "regex only, no model to download" not in combined, (
                f"setup for '{lang}' incorrectly claimed regex-only (it ships a spaCy NER adapter)"
            )

    def test_br_is_regex_only(self):
        """br has no NER adapter — setup correctly says regex only."""
        _, stdout, stderr = run_cli("setup", "-l", "br")
        combined = stdout + stderr
        assert "regex only, no model to download" in combined


class TestAssessCommand:
    def test_should_assess_stdin_and_print_json(self):
        code, stdout, _ = run_cli(
            "assess",
            "-m",
            "fast",
            stdin="身份证110101199003074610",
        )

        assert code == 0
        data = json.loads(stdout)
        assert data["summary"]["risk_level"] == "critical"
        assert "PIPL Art.51" in data["compliance"]["pipl_articles"]

    def test_should_save_report_to_file(self, tmp_path):
        output_file = tmp_path / "report.json"

        code, _, stderr = run_cli(
            "assess",
            "-m",
            "fast",
            "-o",
            str(output_file),
            stdin="手机13812345678",
        )

        assert code == 0
        assert output_file.exists()
        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert data["summary"]["entities_detected"] >= 1

    def test_should_return_zero_risk_when_no_pii(self):
        code, stdout, _ = run_cli(
            "assess",
            "-m",
            "fast",
            stdin="今天天气不错",
        )

        assert code == 0
        data = json.loads(stdout)
        assert data["summary"]["risk_score"] == 0.0
        assert data["summary"]["risk_level"] == "none"

    def test_assess_reports_coverage_and_layers(self):
        """`coverage` and `layers_used` shipped in v0.8.7 and reached no face."""
        code, stdout, _ = run_cli(
            "assess", "-m", "fast", "-l", "zh", stdin="请联系张伟，电话 13812345678。"
        )
        assert code == 0
        data = json.loads(stdout)
        assert set(data["coverage"]) == {"uncovered", "narrow", "exhaustive"}
        assert data["layers_used"] == [1]
        assert data["residual_personal_data"] is True


class TestCliErrors:
    def test_should_show_help_when_no_subcommand(self):
        code, _, stderr = run_cli()

        # argparse shows help on stderr or stdout depending on version
        assert code != 0 or "usage" in (stderr + _).lower()


class TestLangCodeCollisionHint:
    """H5 — `uk`/`in` are argus locale-pack codes, not ISO-639-1 language codes
    (ISO-639-1 `uk` = Ukrainian, `in` = Indonesian). The collision itself is
    NOT fixed by changing the code values (that would break existing
    `uk`=British-English callers) — only by a clearer error message that
    catches a plausible mis-guess like `ua` (Ukrainian) or `id` (Indonesian).
    """

    def test_ua_unknown_lang_hints_at_uk_collision(self, tmp_path):
        key_file = tmp_path / "key.json"

        code, stdout, stderr = run_cli(
            "redact",
            "-k",
            str(key_file),
            "-m",
            "fast",
            "-l",
            "ua",
            stdin="hello",
        )

        assert code != 0
        assert "Error:" in stderr
        assert "uk" in stderr
        assert "British" in stderr
        assert "not Ukrainian" in stderr

    def test_id_unknown_lang_hints_at_in_collision(self, tmp_path):
        key_file = tmp_path / "key.json"

        code, stdout, stderr = run_cli(
            "redact",
            "-k",
            str(key_file),
            "-m",
            "fast",
            "-l",
            "id",
            stdin="hello",
        )

        assert code != 0
        assert "Error:" in stderr
        assert "'in'" in stderr
        assert "Indian" in stderr
        assert "not Indonesian" in stderr

    def test_uk_lang_still_works(self, tmp_path):
        """No behavior change: `uk` remains the British-English locale pack."""
        key_file = tmp_path / "key.json"

        code, stdout, stderr = run_cli(
            "redact",
            "-k",
            str(key_file),
            "-m",
            "fast",
            "-l",
            "uk",
            stdin="hello",
        )

        assert code == 0, stderr
        assert "Traceback" not in stderr
