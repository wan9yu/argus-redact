"""argus-redact Hugging Face Space demo.

Showcases: PII redaction, risk assessment, audit reports across 8 languages.
"""

import json

import gradio as gr

from argus_redact import __version__, redact, restore
from argus_redact.report import generate_report_markdown


# ── Tab 1: Redact ──

def run_redact(text, lang, mode, seed_str, names_str, profile):
    if not text.strip():
        return "", "{}", "", "", ""

    seed = int(seed_str) if seed_str.strip() else None
    lang_list = [code.strip() for code in lang.split(",")]
    lang_param = lang_list[0] if len(lang_list) == 1 else lang_list
    names = [n.strip() for n in names_str.split(",") if n.strip()] if names_str.strip() else None
    prof = profile if profile != "none" else None

    try:
        report = redact(
            text, lang=lang_param, mode=mode, seed=seed,
            names=names, profile=prof, report=True,
        )
    except Exception as e:
        return "", "{}", "", "", f"Error: {e}"

    restored_text = restore(report.redacted_text, report.key)
    key_json = json.dumps(report.key, ensure_ascii=False, indent=2)

    risk = report.risk
    risk_emoji = {"none": "⚪", "low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}
    risk_badge = f"{risk_emoji.get(risk.level, '⚪')} **{risk.level.upper()}** ({risk.score})"

    stats = report.stats
    entities_by_type = {}
    for e in report.entities:
        t = e.get("type", "unknown")
        entities_by_type[t] = entities_by_type.get(t, 0) + 1

    type_breakdown = " · ".join(f"{t}: {c}" for t, c in sorted(entities_by_type.items()))

    summary = (
        f"### {risk_badge}\n\n"
        f"**{stats.get('total', 0)} entities** detected in {stats.get('duration_ms', 0):.1f}ms\n\n"
        f"{type_breakdown}\n\n"
        f"**PIPL**: {', '.join(risk.pipl_articles)}"
    )

    return report.redacted_text, key_json, restored_text, summary, ""


# ── Tab 2: Risk Assessment ──

def run_assess(text, lang):
    if not text.strip():
        return "", "", ""

    lang_list = [code.strip() for code in lang.split(",")]
    lang_param = lang_list[0] if len(lang_list) == 1 else lang_list

    try:
        report = redact(text, lang=lang_param, mode="fast", report=True)
    except Exception as e:
        return f"Error: {e}", "", ""

    risk = report.risk
    risk_emoji = {"none": "⚪", "low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}

    # Risk gauge
    bar_len = int(risk.score * 20)
    bar = "█" * bar_len + "░" * (20 - bar_len)

    gauge = (
        f"# {risk_emoji.get(risk.level, '⚪')} Risk Level: {risk.level.upper()}\n\n"
        f"## Score: {risk.score} / 1.0\n\n"
        f"`[{bar}]`\n\n"
        f"---\n\n"
    )

    # Reasons
    if risk.reasons:
        gauge += "### Detected Sensitive Information\n\n"
        for r in risk.reasons:
            gauge += f"- {r}\n"
        gauge += "\n"

    # PIPL articles
    article_desc = {
        "PIPL Art.13": "合法性基础 (Lawful basis)",
        "PIPL Art.28": "去标识化 (De-identification)",
        "PIPL Art.29": "敏感信息单独同意 (Separate consent)",
        "PIPL Art.51": "敏感个人信息 (Sensitive PI)",
        "PIPL Art.55": "影响评估 (Impact assessment)",
        "PIPL Art.56": "记录义务 (Record-keeping)",
    }

    if risk.pipl_articles:
        gauge += "### Applicable PIPL Articles\n\n"
        gauge += "| Article | Requirement |\n|---------|-------------|\n"
        for art in risk.pipl_articles:
            gauge += f"| {art} | {article_desc.get(art, '')} |\n"

    # Entity details
    entities_md = ""
    if report.entities:
        entities_md = "| # | Type | Layer | Confidence | Replacement |\n"
        entities_md += "|---|------|-------|:----------:|-------------|\n"
        for i, e in enumerate(report.entities, 1):
            conf = e.get("confidence", 0)
            entities_md += f"| {i} | {e.get('type', '?')} | L{e.get('layer', 0)} | {conf:.0%} | `{e.get('replacement', '—')}` |\n"

    return gauge, entities_md, report.redacted_text


# ── Tab 3: Audit Report ──

def run_audit(text, lang):
    if not text.strip():
        return "", ""

    lang_list = [code.strip() for code in lang.split(",")]
    lang_param = lang_list[0] if len(lang_list) == 1 else lang_list

    try:
        report = redact(text, lang=lang_param, mode="fast", report=True)
    except Exception as e:
        return f"Error: {e}", ""

    md = generate_report_markdown(report)
    json_str = json.dumps(
        {
            "report_type": "pii_redaction_audit",
            "summary": {
                "entities_detected": report.stats.get("total", 0),
                "risk_score": report.risk.score,
                "risk_level": report.risk.level,
            },
            "compliance": {
                "pipl_articles": list(report.risk.pipl_articles),
            },
            "entities": list(report.entities),
        },
        ensure_ascii=False,
        indent=2,
    )
    return md, json_str


# ── Examples ──

REDACT_EXAMPLES = [
    # Level 1: Direct identifiers
    ["张三的手机号是13812345678，邮箱zhang@test.com", "zh", "fast", "42", "", "none"],
    ["身份证110101199003074610，银行卡6222021234567890123", "zh", "fast", "42", "", "none"],
    # Level 2+3: Sensitive attributes
    ["他是党员，确诊糖尿病，月薪2万元，民族：回族", "zh", "fast", "42", "", "pipl"],
    # English
    ["John Smith, SSN 123-45-6789, diagnosed with diabetes, salary $120,000", "en", "fast", "42", "John Smith", "none"],
    # Mixed zh+en
    ["张三，身份证110101199003074610，diagnosed with hypertension，月薪3万元", "zh,en", "fast", "42", "", "pipl"],
    # Level 3: All sensitive types
    ["他是基督徒，有前科，已经出柜，fingerprint collected", "zh,en", "fast", "42", "", "none"],
    # Multi-language
    ["田中太郎の携帯は090-1234-5678", "ja", "fast", "42", "田中太郎", "none"],
    ["CPF: 529.982.247-25, telefone +55 (11) 99876-5432", "br", "fast", "42", "", "none"],
]

ASSESS_EXAMPLES = [
    ["身份证110101199003074610，手机13812345678，确诊糖尿病", "zh"],
    ["SSN 123-45-6789, credit score 680, convicted of fraud", "en"],
    ["张三，月薪2万元，是穆斯林，有犯罪记录", "zh"],
    ["今天天气不错，项目进度正常", "zh"],
]


# ── UI ──

with gr.Blocks(title=f"argus-redact v{__version__}") as demo:
    gr.Markdown(
        f"""
        # 🛡️ argus-redact v{__version__}
        **Encrypt PII, not meaning. Locally.**

        8 languages · ~47 PII types · L1-L4 complete · Risk assessment · PIPL compliance · PDF audit reports

        [GitHub](https://github.com/wan9yu/argus-redact) ·
        [PyPI](https://pypi.org/project/argus-redact/) ·
        [Docs](https://github.com/wan9yu/argus-redact/tree/main/docs) ·
        `pip install argus-redact`
        """
    )

    with gr.Tabs():
        # ── Tab 1: Redact ──
        with gr.TabItem("🔒 Redact"):
            with gr.Row():
                with gr.Column(scale=1):
                    input_text = gr.Textbox(label="Input Text", placeholder="Enter text with PII...", lines=6)
                    names_input = gr.Textbox(label="Known Names (comma-separated)", placeholder="王一,John Smith")
                    with gr.Row():
                        lang = gr.Dropdown(
                            choices=["zh", "en", "ja", "ko", "de", "uk", "in", "br", "zh,en"],
                            value="zh", label="Language",
                        )
                        mode = gr.Dropdown(choices=["fast", "ner"], value="fast", label="Mode")
                        profile = gr.Dropdown(
                            choices=["none", "default", "pipl", "gdpr", "hipaa"],
                            value="none", label="Compliance Profile",
                        )
                        seed = gr.Textbox(value="42", label="Seed")
                    btn = gr.Button("🔒 Redact & Assess", variant="primary", size="lg")

                with gr.Column(scale=1):
                    risk_summary = gr.Markdown(label="Risk Assessment")
                    redacted_out = gr.Textbox(label="Redacted Text", lines=4)
                    restored_out = gr.Textbox(label="Restored Text", lines=4)
                    key_out = gr.Code(label="Key (JSON)", language="json")
                    error_out = gr.Textbox(label="", visible=False)

            btn.click(
                fn=run_redact,
                inputs=[input_text, lang, mode, seed, names_input, profile],
                outputs=[redacted_out, key_out, restored_out, risk_summary, error_out],
            )

            gr.Examples(
                examples=REDACT_EXAMPLES,
                inputs=[input_text, lang, mode, seed, names_input, profile],
                outputs=[redacted_out, key_out, restored_out, risk_summary, error_out],
                fn=run_redact, cache_examples=False,
            )

        # ── Tab 2: Risk Assessment ──
        with gr.TabItem("📊 Risk Assessment"):
            with gr.Row():
                with gr.Column(scale=1):
                    assess_input = gr.Textbox(label="Input Text", placeholder="Enter text to assess...", lines=6)
                    assess_lang = gr.Dropdown(
                        choices=["zh", "en", "zh,en", "ja", "ko"],
                        value="zh", label="Language",
                    )
                    assess_btn = gr.Button("📊 Assess Risk", variant="primary", size="lg")

                with gr.Column(scale=1):
                    risk_gauge = gr.Markdown(label="Risk Report")
                    entity_table = gr.Markdown(label="Detected Entities")
                    assess_redacted = gr.Textbox(label="Redacted Preview", lines=3)

            assess_btn.click(
                fn=run_assess,
                inputs=[assess_input, assess_lang],
                outputs=[risk_gauge, entity_table, assess_redacted],
            )

            gr.Examples(
                examples=ASSESS_EXAMPLES,
                inputs=[assess_input, assess_lang],
                outputs=[risk_gauge, entity_table, assess_redacted],
                fn=run_assess, cache_examples=False,
            )

        # ── Tab 3: Audit Report ──
        with gr.TabItem("📋 Audit Report"):
            with gr.Row():
                with gr.Column(scale=1):
                    audit_input = gr.Textbox(
                        label="Input Text", lines=6,
                        placeholder="Enter text to generate compliance audit report...",
                    )
                    audit_lang = gr.Dropdown(
                        choices=["zh", "en", "zh,en"],
                        value="zh", label="Language",
                    )
                    audit_btn = gr.Button("📋 Generate Report", variant="primary", size="lg")

                with gr.Column(scale=1):
                    audit_md = gr.Markdown(label="Audit Report (Markdown)")

            audit_json = gr.Code(label="Machine-Readable Report (JSON)", language="json")

            audit_btn.click(
                fn=run_audit,
                inputs=[audit_input, audit_lang],
                outputs=[audit_md, audit_json],
            )

            gr.Examples(
                examples=[
                    ["张三，身份证110101199003074610，手机13812345678，确诊糖尿病，月薪2万元，是穆斯林", "zh"],
                    ["John Smith, SSN 123-45-6789, diagnosed with cancer, credit score 580, registered Democrat", "en"],
                ],
                inputs=[audit_input, audit_lang],
                outputs=[audit_md, audit_json],
                fn=run_audit, cache_examples=False,
            )

    gr.Markdown(
        """
        ---
        **Capabilities:** 8 languages (zh/en/ja/ko/de/uk/in/br) · ~47 PII types across 4 levels ·
        Risk assessment with PIPL Art.13/28/29/51/55/56 mapping ·
        JSON/Markdown/PDF audit reports · Compliance profiles (PIPL/GDPR/HIPAA) ·
        LangChain / LlamaIndex / FastAPI / MCP integrations

        **Privacy:** All processing runs locally. No data leaves your device.
        """
    )

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)
