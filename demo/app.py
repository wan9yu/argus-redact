"""argus-redact Hugging Face Space demo.

The privacy layer between you and AI.
Three promises: Protected · Usable · Reversible.
"""

import json

import gradio as gr

from argus_redact import __version__, redact, restore


# ── Tab 1: Is it safe? ──

def check_safety(text, lang):
    if not text.strip():
        return "", ""

    lang_param = [c.strip() for c in lang.split(",")] if "," in lang else lang

    try:
        report = redact(text, lang=lang_param, mode="fast", report=True)
    except Exception as e:
        return f"Error: {e}", ""

    risk = report.risk
    total = report.stats.get("total", 0)

    level_display = {
        "none":     ("🟢", "Safe",     "Nothing about you is exposed. Safe to share with AI."),
        "low":      ("🟡", "Caution",  "Contains personal info, but not dangerous alone."),
        "medium":   ("🟡", "Caution",  "Contains personal info. Consider redacting before sharing."),
        "high":     ("🟠", "Danger",   "Can narrow down to you specifically. Redact before sharing."),
        "critical": ("🔴", "Exposed",  "Directly identifies you. Do NOT share with AI as-is."),
    }
    emoji, label, advice = level_display.get(risk.level, ("⚪", "Unknown", ""))

    bar_len = int(risk.score * 20)
    bar = "█" * bar_len + "░" * (20 - bar_len)

    gauge = f"""# {emoji} {label}

## `[{bar}]` {risk.score:.2f} / 1.0

### {advice}

---

"""

    if total > 0:
        gauge += f"### Found {total} piece(s) of personal information:\n\n"
        for e in report.entities:
            gauge += f"- **{e.get('type', '?')}** — `{e.get('replacement', '?')}`\n"
        gauge += "\n"

    article_desc = {
        "PIPL Art.13": "Lawful basis required",
        "PIPL Art.28": "De-identification required",
        "PIPL Art.29": "Separate consent for sensitive PI",
        "PIPL Art.51": "Contains sensitive personal information",
        "PIPL Art.55": "Impact assessment required",
        "PIPL Art.56": "Record-keeping obligation",
    }
    if risk.pipl_articles:
        gauge += "### Regulatory implications\n\n"
        for art in risk.pipl_articles:
            gauge += f"- {art}: {article_desc.get(art, '')}\n"

    preview = report.redacted_text if total > 0 else "*No changes needed — your text is safe.*"

    return gauge, preview


# ── Tab 2: Protect & Use ──

def protect_and_use(text, lang, mode, seed_str, names_str, profile):
    if not text.strip():
        return "", "", "", "", ""

    seed = int(seed_str) if seed_str.strip() else None
    lang_param = [c.strip() for c in lang.split(",")] if "," in lang else lang
    names = [n.strip() for n in names_str.split(",") if n.strip()] if names_str.strip() else None
    prof = profile if profile != "none" else None

    try:
        report = redact(
            text, lang=lang_param, mode=mode, seed=seed,
            names=names, profile=prof, report=True,
        )
    except Exception as e:
        return "", "", "", "", f"Error: {e}"

    restored_text = restore(report.redacted_text, report.key)
    key_json = json.dumps(report.key, ensure_ascii=False, indent=2)

    risk = report.risk
    emoji = {"none": "🟢", "low": "🟡", "medium": "🟡", "high": "🟠", "critical": "🔴"}

    entities_by_type = {}
    for e in report.entities:
        t = e.get("type", "?")
        entities_by_type[t] = entities_by_type.get(t, 0) + 1
    breakdown = " · ".join(f"{t}: {c}" for t, c in sorted(entities_by_type.items()))

    summary = (
        f"### {emoji.get(risk.level, '⚪')} {risk.level.upper()} ({risk.score})\n\n"
        f"**{report.stats.get('total', 0)} entities** protected in {report.stats.get('duration_ms', 0):.1f}ms\n\n"
        f"{breakdown}"
    )

    return report.redacted_text, key_json, restored_text, summary, ""


# ── Examples ──

CHECK_EXAMPLES = [
    ["张三的身份证110101199003074610，手机13812345678", "zh"],
    ["他是党员，确诊糖尿病，月薪2万元，民族：回族", "zh"],
    ["John, SSN 123-45-6789, diagnosed with cancer, credit score 580", "en"],
    ["今天天气不错，项目进度正常", "zh"],
    ["张三，身份证110101199003074610，diagnosed with hypertension，月薪3万元", "zh,en"],
    ["他是基督徒，有前科，已经出柜，fingerprint collected", "zh,en"],
]

PROTECT_EXAMPLES = [
    ["王五在协和医院做了体检，手机13812345678", "zh", "fast", "42", "王五", "none"],
    ["身份证110101199003074610，银行卡6222021234567890123", "zh", "fast", "42", "", "pipl"],
    ["John Smith, SSN 123-45-6789, salary $120,000", "en", "fast", "42", "John Smith", "none"],
    ["田中太郎の携帯は090-1234-5678", "ja", "fast", "42", "田中太郎", "none"],
    ["CPF: 529.982.247-25, telefone +55 (11) 99876-5432", "br", "fast", "42", "", "none"],
]


# ── UI ──

with gr.Blocks(title=f"argus-redact v{__version__}") as demo:
    gr.Markdown(
        f"""
        # 🛡️ argus-redact v{__version__}
        **The privacy layer between you and AI.**

        Your identity stays on your device — AI gets the meaning, not you.

        | 🛡️ Protected | 🧠 Usable | 🔄 Reversible |
        |:---:|:---:|:---:|
        | PII never leaves your device | AI still understands your text | One line to get everything back |

        [GitHub](https://github.com/wan9yu/argus-redact) ·
        [PyPI](https://pypi.org/project/argus-redact/) ·
        [Docs](https://github.com/wan9yu/argus-redact/tree/main/docs) ·
        `pip install argus-redact`
        """
    )

    with gr.Tabs():

        # ── Tab 1: Is it safe? ──
        with gr.TabItem("🔍 Is it safe?"):
            gr.Markdown("*Paste what you're about to send to AI. We'll tell you the risk.*")

            with gr.Row():
                with gr.Column(scale=1):
                    check_input = gr.Textbox(
                        label="Your text",
                        placeholder="Paste the message you want to send to ChatGPT / Claude / Gemini...",
                        lines=6,
                    )
                    check_lang = gr.Dropdown(
                        choices=["zh", "en", "zh,en", "ja", "ko", "de", "uk", "in", "br"],
                        value="zh", label="Language",
                    )
                    check_btn = gr.Button("🔍 Check", variant="primary", size="lg")

                with gr.Column(scale=1):
                    check_result = gr.Markdown(label="Privacy Assessment")
                    check_preview = gr.Textbox(label="What AI would see (after protection)", lines=4)

            check_btn.click(
                fn=check_safety,
                inputs=[check_input, check_lang],
                outputs=[check_result, check_preview],
            )

            gr.Examples(
                examples=CHECK_EXAMPLES,
                inputs=[check_input, check_lang],
                outputs=[check_result, check_preview],
                fn=check_safety, cache_examples=False,
            )

        # ── Tab 2: Protect & Use ──
        with gr.TabItem("🛡️ Protect & Use"):
            gr.Markdown("*Encrypt your PII. AI sees pseudonyms. You get everything back.*")

            with gr.Row():
                with gr.Column(scale=1):
                    protect_input = gr.Textbox(label="Original text", placeholder="Enter text with PII...", lines=6)
                    names_input = gr.Textbox(label="Known names (comma-separated)", placeholder="王一,John Smith")
                    with gr.Row():
                        protect_lang = gr.Dropdown(
                            choices=["zh", "en", "zh,en", "ja", "ko", "de", "uk", "in", "br"],
                            value="zh", label="Language",
                        )
                        protect_mode = gr.Dropdown(choices=["fast", "ner"], value="fast", label="Mode")
                        protect_profile = gr.Dropdown(
                            choices=["none", "default", "pipl", "gdpr", "hipaa"],
                            value="none", label="Profile",
                        )
                        protect_seed = gr.Textbox(value="42", label="Seed")
                    protect_btn = gr.Button("🛡️ Protect", variant="primary", size="lg")

                with gr.Column(scale=1):
                    protect_summary = gr.Markdown(label="Summary")
                    protect_redacted = gr.Textbox(label="① What AI sees (protected)", lines=3)
                    protect_restored = gr.Textbox(label="③ What you get back (restored)", lines=3)
                    protect_key = gr.Code(label="② Your key (keep this)", language="json")
                    protect_err = gr.Textbox(visible=False)

            protect_btn.click(
                fn=protect_and_use,
                inputs=[protect_input, protect_lang, protect_mode, protect_seed, names_input, protect_profile],
                outputs=[protect_redacted, protect_key, protect_restored, protect_summary, protect_err],
            )

            gr.Examples(
                examples=PROTECT_EXAMPLES,
                inputs=[protect_input, protect_lang, protect_mode, protect_seed, names_input, protect_profile],
                outputs=[protect_redacted, protect_key, protect_restored, protect_summary, protect_err],
                fn=protect_and_use, cache_examples=False,
            )

    gr.Markdown(
        """
        ---
        **Three Promises:** 🛡️ Protected — PII never leaves your device ·
        🧠 Usable — AI still understands your text ·
        🔄 Reversible — one line to get everything back

        **~47 PII types** · **8 languages** · **PIPL · GDPR · HIPAA** (as byproduct) ·
        LangChain · LlamaIndex · FastAPI · MCP Server
        """
    )

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)
