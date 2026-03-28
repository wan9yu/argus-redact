"""Audit report generator — produce compliance-ready reports from RedactReport.

Generates Markdown or JSON reports suitable for 等保 / PIPL备案 audits.
Can be converted to PDF via docs/generate_pdf.py's weasyprint approach.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

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
