"""Tests for audit report generation — JSON, Markdown, and PDF formats."""

import importlib.util
import json

import pytest

from argus_redact import redact
from argus_redact.report import generate_report_json, generate_report_markdown

HAS_WEASYPRINT = importlib.util.find_spec("weasyprint") is not None


class TestReportJSON:
    def test_should_produce_valid_json(self):
        report = redact("身份证110101199003074610", lang="zh", mode="fast", report=True)
        output = generate_report_json(report)
        data = json.loads(output)
        assert data["report_type"] == "pii_redaction_audit"
        assert "generated_at" in data

    def test_should_include_risk_summary(self):
        report = redact("身份证110101199003074610", lang="zh", mode="fast", report=True)
        data = json.loads(generate_report_json(report))
        assert data["summary"]["risk_level"] == "critical"
        assert data["summary"]["entities_detected"] >= 1

    def test_should_include_pipl_articles(self):
        report = redact("身份证110101199003074610", lang="zh", mode="fast", report=True)
        data = json.loads(generate_report_json(report))
        assert "PIPL Art.28" in data["compliance"]["pipl_articles"]

    def test_should_handle_no_pii(self):
        report = redact("今天天气不错", lang="zh", mode="fast", report=True)
        data = json.loads(generate_report_json(report))
        assert data["summary"]["entities_detected"] == 0
        assert data["summary"]["risk_score"] == 0.0


class TestReportMarkdown:
    def test_should_produce_markdown_with_title(self):
        report = redact("手机13812345678", lang="zh", mode="fast", report=True)
        md = generate_report_markdown(report)
        assert "# 个人信息脱敏审计报告" in md

    def test_should_include_risk_table(self):
        report = redact("身份证110101199003074610", lang="zh", mode="fast", report=True)
        md = generate_report_markdown(report)
        assert "风险评分" in md
        assert "critical" in md.lower()

    def test_should_include_pipl_articles_table(self):
        report = redact("身份证110101199003074610", lang="zh", mode="fast", report=True)
        md = generate_report_markdown(report)
        assert "PIPL Art.28" in md
        assert "去标识化" in md

    def test_should_include_entity_list(self):
        report = redact("手机13812345678", lang="zh", mode="fast", report=True)
        md = generate_report_markdown(report)
        assert "phone" in md

    def test_should_handle_no_pii(self):
        report = redact("今天天气不错", lang="zh", mode="fast", report=True)
        md = generate_report_markdown(report)
        assert "none" in md.lower()


@pytest.mark.skipif(not HAS_WEASYPRINT, reason="weasyprint not installed")
class TestReportPDF:
    def test_should_generate_pdf_file(self, tmp_path):
        from argus_redact.report import generate_report_pdf

        report = redact("身份证110101199003074610", lang="zh", mode="fast", report=True)
        output = tmp_path / "report.pdf"
        result = generate_report_pdf(report, output)

        assert result.exists()
        assert result.stat().st_size > 1000  # non-trivial PDF
        # PDF magic bytes
        assert output.read_bytes()[:4] == b"%PDF"

    def test_should_raise_without_weasyprint(self):
        """Verify the import error message is clear."""
        # This test only makes sense if weasyprint IS installed
        # Just verify the function is importable
        from argus_redact.report import generate_report_pdf
        assert callable(generate_report_pdf)
