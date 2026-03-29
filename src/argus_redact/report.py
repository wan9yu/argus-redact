"""Audit report generator — produce compliance-ready reports from RedactReport.

Generates Markdown, JSON, or PDF reports suitable for 等保 / PIPL备案 audits.
PDF generation requires: pip install markdown weasyprint
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from argus_redact._types import RedactReport


def generate_report_json(report: RedactReport) -> str:
    """Generate a machine-readable JSON audit report."""
    risk = report.risk
    if risk is None:
        from argus_redact.pure.risk import RiskResult
        risk = RiskResult(score=0.0, level="none")
    return json.dumps(
        {
            "report_type": "pii_redaction_audit",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "entities_detected": report.stats.get("total", 0),
                "risk_score": risk.score,
                "risk_level": risk.level,
            },
            "compliance": {
                "pipl_articles": list(risk.pipl_articles),
                "reasons": list(risk.reasons),
            },
            "entities": list(report.entities),
            "stats": report.stats,
        },
        ensure_ascii=False,
        indent=2,
    )


def generate_report_markdown(report: RedactReport) -> str:
    """Generate a human-readable Markdown audit report for 等保/PIPL备案."""
    risk = report.risk
    if risk is None:
        from argus_redact.pure.risk import RiskResult
        risk = RiskResult(score=0.0, level="none")
    lines = [
        "# 个人信息脱敏审计报告",
        "",
        f"> **生成时间**：{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"> **工具版本**：argus-redact",
        f"> **风险等级**：{risk.level.upper()} ({risk.score})",
        "",
        "---",
        "",
        "## 1. 风险评估摘要",
        "",
        f"| 指标 | 值 |",
        f"|------|------|",
        f"| 检测实体数 | {report.stats.get('total', 0)} |",
        f"| 风险评分 | {risk.score} / 1.0 |",
        f"| 风险等级 | {risk.level} |",
        f"| Layer 1 (正则) | {report.stats.get('layer_1', 0)} 个 |",
        f"| Layer 2 (NER) | {report.stats.get('layer_2', 0)} 个 |",
        f"| Layer 3 (语义) | {report.stats.get('layer_3', 0)} 个 |",
        "",
        "## 2. 适用 PIPL 条款",
        "",
        "| 条款 | 说明 |",
        "|------|------|",
    ]

    article_descriptions = {
        "PIPL Art.13": "个人信息处理的合法性基础",
        "PIPL Art.28": "去标识化处理要求",
        "PIPL Art.29": "敏感个人信息单独同意",
        "PIPL Art.51": "敏感个人信息定义与范围",
        "PIPL Art.55": "个人信息保护影响评估",
        "PIPL Art.56": "个人信息处理者记录义务",
    }

    for art in risk.pipl_articles:
        desc = article_descriptions.get(art, "")
        lines.append(f"| {art} | {desc} |")

    lines.extend([
        "",
        "## 3. 检测到的敏感信息",
        "",
        "| # | 类型 | 层级 | 置信度 | 处理方式 |",
        "|---|------|------|:------:|----------|",
    ])

    for i, entity in enumerate(report.entities, 1):
        etype = entity.get("type", "unknown")
        layer = entity.get("layer", 0)
        conf = entity.get("confidence", 0)
        replacement = entity.get("replacement", "—")
        lines.append(f"| {i} | {etype} | Layer {layer} | {conf:.0%} | `{replacement}` |")

    lines.extend([
        "",
        "## 4. 风险分析原因",
        "",
    ])

    for reason in risk.reasons:
        lines.append(f"- {reason}")

    lines.extend([
        "",
        "---",
        "",
        "*本报告由 argus-redact 自动生成，供等保评测 / PIPL 合规备案参考。*",
        "",
    ])

    return "\n".join(lines)


# ── PDF CSS (adapted from docs/generate_pdf.py) ──

_PDF_CSS = """
@page {
    size: A4;
    margin: 25mm 20mm 22mm 20mm;
    @bottom-left {
        content: "argus-redact · 个人信息脱敏审计报告";
        font-size: 7.5pt; color: #999;
        font-family: "PingFang SC", "Noto Sans CJK SC", sans-serif;
    }
    @bottom-right {
        content: counter(page);
        font-size: 7.5pt; color: #999;
    }
}
body {
    font-family: "PingFang SC", "Noto Sans CJK SC", "Microsoft YaHei",
                 "Helvetica Neue", Arial, sans-serif;
    font-size: 10.5pt; line-height: 1.75; color: #1F2937;
}
h1 { font-size: 20pt; font-weight: 700; color: #0F2A4A;
     border-bottom: 2.5pt solid #1A5276; padding-bottom: 8px; }
h2 { font-size: 14pt; font-weight: 600; color: #1A5276;
     border-bottom: 1pt solid #E5E7EB; padding-bottom: 5px; margin-top: 24px; }
blockquote { border-left: 3.5pt solid #1A8A7D; padding: 8px 16px;
             background: #F0FDFA; color: #4B5563; font-size: 9.5pt; }
blockquote strong { color: #0F2A4A; }
table { border-collapse: collapse; width: 100%; margin: 12px 0;
        font-size: 9.5pt; page-break-inside: avoid; }
th { font-weight: 600; text-align: left; padding: 8px 10px;
     border-bottom: 2pt solid #0F2A4A; color: #0F2A4A; }
td { padding: 6px 10px; border-bottom: 0.5pt solid #E5E7EB; color: #374151; }
th, td { border-left: none; border-right: none; }
code { font-family: "SF Mono", "Menlo", monospace; font-size: 9pt;
       background: #F3F4F6; padding: 1px 4px; border-radius: 3px; color: #1A5276; }
hr { border: none; border-top: 1pt solid #E5E7EB; margin: 20px 0; }
strong { color: #0F2A4A; }
em { color: #6B7280; font-size: 9pt; }
"""


def generate_report_pdf(report: RedactReport, output_path: str | Path) -> Path:
    """Generate a professional PDF audit report.

    Requires: pip install markdown weasyprint
    Returns the output path.
    """
    try:
        import markdown
        from weasyprint import HTML
    except ImportError:
        raise ImportError(
            "PDF generation requires 'markdown' and 'weasyprint'. "
            "Install with: pip install markdown weasyprint"
        )

    md_text = generate_report_markdown(report)
    html_body = markdown.markdown(md_text, extensions=["tables"])

    full_html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <title>个人信息脱敏审计报告 | argus-redact</title>
    <style>{_PDF_CSS}</style>
</head>
<body>
{html_body}
</body>
</html>"""

    output = Path(output_path)
    HTML(string=full_html).write_pdf(str(output))
    return output
