"""argus-redact Hugging Face Space demo.

The privacy layer between you and AI.
Three promises: Protected · Usable · Reversible.
Bilingual EN / 中文 for Gateway-driven traffic.
"""

import json
from pathlib import Path

import gradio as gr

from argus_redact import __version__, redact, redact_pseudonym_llm, restore

PRVL_CACHE = json.loads(
    (Path(__file__).resolve().parent / "prvl_cache.json").read_text(encoding="utf-8")
)
# ⚠️ Hardcoded for a public HF demo — anyone with this salt can derive all
# fakes from observed input. For production, generate per-deployment via
# `secrets.token_bytes(32)` and store out-of-band (env / KMS / secret manager).
DEMO_SALT = b"argus-redact-hf-demo-32byte-salt!"


# ──────────────────────────────────────────────────────────────
# Tab 1 handlers — STUBS (real implementation in T4)
# ──────────────────────────────────────────────────────────────

def do_three_form(text: str, lang: str) -> tuple[str, str, str, dict]:
    """Run pseudonym-llm redaction; return (audit, downstream, display, key).

    The key dict is stored in gr.State and consumed by do_restore_any so the
    user can paste any of the three forms (or LLM output containing the same
    pseudonyms) into a free-form box and restore back to original.
    """
    if not text.strip():
        return "", "", "", {}
    lang_param = [c.strip() for c in lang.split(",")] if "," in lang else lang
    try:
        result = redact_pseudonym_llm(text, lang=lang_param, salt=DEMO_SALT)
    except Exception as e:
        msg = f"⚠️ {type(e).__name__}: {e}"
        return msg, msg, msg, {}
    return result.audit_text, result.downstream_text, result.display_text, result.key


def do_restore_any(text: str, key_state: dict) -> str:
    """Restore pseudonyms in `text` using `key_state` from a previous magic call.

    Accepts any of the three text forms (audit/downstream/display) or LLM output
    that contains pseudonyms from the same call.
    """
    if not text.strip():
        return ""
    if not key_state:
        return "(Click 'Show me the magic' first to populate a key. / 先点'展示魔法'生成 key.)"
    try:
        return restore(text, key_state)
    except Exception as e:
        return f"⚠️ {type(e).__name__}: {e}"


# ──────────────────────────────────────────────────────────────
# Tab 2 handler — UNCHANGED from old app.py lines 14-73
# ──────────────────────────────────────────────────────────────

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
        "none":     ("🟢", "Safe / 安全",     "Nothing about you is exposed. Safe to share with AI. / 没有暴露任何身份信息。可以放心发给 AI。"),
        "low":      ("🟡", "Caution / 注意",  "Contains personal info, but not dangerous alone. / 含有个人信息，单独不致命。"),
        "medium":   ("🟡", "Caution / 注意",  "Contains personal info. Consider redacting before sharing. / 含有个人信息，建议保护后再分享。"),
        "high":     ("🟠", "Danger / 危险",   "Can narrow down to you specifically. Redact before sharing. / 可以缩窄到具体到你。建议保护后再分享。"),
        "critical": ("🔴", "Exposed / 暴露",  "Directly identifies you. Do NOT share with AI as-is. / 直接识别到你。不要直接发给 AI。"),
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
        gauge += f"### Found {total} piece(s) of personal info / 检测到 {total} 项个人信息:\n\n"
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
        gauge += "### Regulatory implications / 合规影响\n\n"
        for art in risk.pipl_articles:
            gauge += f"- {art}: {article_desc.get(art, '')}\n"

    preview = report.redacted_text if total > 0 else "*No changes needed — your text is safe. / 文本安全，无需保护。*"

    return gauge, preview


# ──────────────────────────────────────────────────────────────
# Tab 3 handler — UNCHANGED from old app.py lines 76-113
# (T6 will add a pseudonym-llm branch later)
# ──────────────────────────────────────────────────────────────

def protect_and_use(text, lang, mode, seed_str, names_str, profile):
    if not text.strip():
        return "", "", "", "", ""

    seed = int(seed_str) if seed_str.strip() else None
    lang_param = [c.strip() for c in lang.split(",")] if "," in lang else lang
    names = [n.strip() for n in names_str.split(",") if n.strip()] if names_str.strip() else None
    prof = profile if profile != "none" else None

    # pseudonym-llm profile uses a different API path (returns 3 text forms)
    if profile == "pseudonym-llm":
        try:
            result = redact_pseudonym_llm(
                text, lang=lang_param, mode=mode, salt=DEMO_SALT, names=names,
            )
        except Exception as e:
            return "", "", "", "", f"Error: {e}"
        restored_text = restore(result.downstream_text, result.key)
        key_json = json.dumps(result.key, ensure_ascii=False, indent=2)
        summary = (
            "### 🤖 pseudonym-llm profile / pseudonym-llm 模板\n\n"
            "**downstream_text** shown below — feed this to your LLM. / "
            "下方为 downstream_text — 喂给你的 LLM."
        )
        return result.downstream_text, key_json, restored_text, summary, ""

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
        f"**{report.stats.get('total', 0)} entities** protected in {report.stats.get('duration_ms', 0):.1f}ms / "
        f"在 {report.stats.get('duration_ms', 0):.1f}ms 内保护了 {report.stats.get('total', 0)} 个实体\n\n"
        f"{breakdown}"
    )

    return report.redacted_text, key_json, restored_text, summary, ""


# ──────────────────────────────────────────────────────────────
# Examples
# ──────────────────────────────────────────────────────────────

CHECK_EXAMPLES = [
    ["张三的身份证110101199003074610，手机13812345678", "zh"],
    ["他是党员，确诊糖尿病，月薪2万元，民族：回族", "zh"],
    ["John, SSN 123-45-6789, diagnosed with cancer, credit score 580", "en"],
    ["今天天气不错，项目进度正常", "zh"],
    ["张三，身份证110101199003074610，diagnosed with hypertension，月薪3万元", "zh,en"],
    ["他是基督徒，有前科，已经出柜，fingerprint collected", "zh,en"],
    ["求职者：男，回族，党员，已婚，有银行流水问题", "zh"],
    ["医患信息：王姓患者，确诊抑郁症 + 糖尿病，曾做心理咨询", "zh"],
]

PROTECT_EXAMPLES = [
    ["王五在协和医院做了体检，手机13812345678", "zh", "fast", "42", "王五", "none"],
    ["身份证110101199003074610，银行卡6222021234567890123", "zh", "fast", "42", "", "pipl"],
    ["John Smith, SSN 123-45-6789, salary $120,000", "en", "fast", "42", "John Smith", "none"],
    ["田中太郎の携帯は090-1234-5678", "ja", "fast", "42", "田中太郎", "none"],
    ["CPF: 529.982.247-25, telefone +55 (11) 99876-5432", "br", "fast", "42", "", "none"],
    ["黄芳的电话13912345678,在北京市朝阳区建国路100号", "zh", "fast", "42", "", "pseudonym-llm"],
]

MAGIC_EXAMPLES = [
    ["黄芳的电话13912345678,在北京市朝阳区建国路100号工作", "zh"],
    ["客户王建国,身份证310101199003074617,确诊糖尿病", "zh"],
    ["John Smith called from (415) 555-1234, SSN 123-45-6789", "en"],
    ["请联系赵敏 13800138000 关于订单号 ORD-2024-001", "zh"],
]


# ──────────────────────────────────────────────────────────────
# UI
# ──────────────────────────────────────────────────────────────

HEADER_MD = f"""
# 🛡️ argus-redact v{__version__}

**Encrypt PII, not meaning. Locally.** / **只加密 PII，不加密含义。在本地。**

| 🛡️ Protected / 保护 | 🧠 Usable / 可用 | 🔄 Reversible / 可逆 |
|:---:|:---:|:---:|
| PII never leaves your device<br/>PII 永远不离开你的设备 | AI still understands your text<br/>AI 仍能理解你的文本 | One line to get everything back<br/>一行代码原样恢复 |

**56 PII types · 8 languages · 0% PII leak across GPT-5 / Claude-Opus-4.5 / Gemini-2.5-Pro / GLM-4.5**

<a href="https://github.com/wan9yu/argus-redact" target="_blank" rel="noopener">GitHub</a> ·
<a href="https://pypi.org/project/argus-redact/" target="_blank" rel="noopener">PyPI</a> ·
<a href="https://github.com/wan9yu/argus-redact/tree/main/docs" target="_blank" rel="noopener">Docs</a> ·
<a href="https://github.com/wan9yu/argus-redact/blob/main/README.zh.md" target="_blank" rel="noopener">中文说明</a>

`pip install argus-redact`
"""

FOOTER_MD = """
---
**56 PII types · 8 languages · PIPL · GDPR · HIPAA · property-tested · mutation-audited (0 real bugs)**

**56 类 PII · 8 种语言 · 通过 PIPL/GDPR/HIPAA · 属性测试 · 变异测试（0 真 bug）**
"""

with gr.Blocks(title=f"argus-redact v{__version__}") as demo:
    gr.Markdown(HEADER_MD)

    with gr.Tabs():
        with gr.TabItem("✨ See the magic / 见证魔法"):
            gr.Markdown(
                "_Paste any sensitive text — see how argus-redact produces three text forms / "
                "粘贴任何敏感文本 — 看 argus-redact 如何产出三种文本形式_"
            )

            with gr.Row():
                with gr.Column(scale=1):
                    magic_input = gr.Textbox(
                        label="Your text / 你的文本",
                        placeholder="Type or paste — try a Chinese sentence with a phone number...",
                        value="黄芳的电话13912345678,在北京市朝阳区建国路100号工作",
                        lines=4,
                    )
                    magic_lang = gr.Dropdown(
                        choices=["zh", "en", "zh,en", "ja", "ko", "de", "uk", "in", "br"],
                        value="zh",
                        label="Language / 语言",
                    )
                    magic_btn = gr.Button(
                        "🎩 Show me the magic / 展示魔法",
                        variant="primary", size="lg",
                    )

            magic_key_state = gr.State(value={})

            with gr.Row():
                with gr.Column():
                    gr.Markdown("**📋 audit_text** · _Compliance archive / 合规归档_")
                    magic_audit = gr.Textbox(label=" ", lines=3, show_label=False)
                with gr.Column():
                    gr.Markdown("**🤖 downstream_text** · _Send to LLM / 喂给 LLM_")
                    magic_downstream = gr.Textbox(label=" ", lines=3, show_label=False)
                with gr.Column():
                    gr.Markdown("**👁️ display_text** · _Show in UI / 给人看_")
                    magic_display = gr.Textbox(label=" ", lines=3, show_label=False)

            magic_btn.click(
                fn=do_three_form,
                inputs=[magic_input, magic_lang],
                outputs=[magic_audit, magic_downstream, magic_display, magic_key_state],
            )

            gr.Examples(
                examples=MAGIC_EXAMPLES,
                inputs=[magic_input, magic_lang],
                outputs=[magic_audit, magic_downstream, magic_display, magic_key_state],
                fn=do_three_form,
                cache_examples=False,
            )

            gr.Markdown("---")
            gr.Markdown(
                "### ↩️ Restore from any form / 任意形式还原\n\n"
                "_Paste any of the three forms above (or LLM output that contains "
                "pseudonyms from the same call) and restore back to original. / "
                "粘贴上面任一形式（或包含同一次假名的 LLM 输出），还原回原文._"
            )
            with gr.Row():
                with gr.Column(scale=2):
                    restore_input = gr.Textbox(
                        label="Pasted text / 粘贴文本",
                        lines=3,
                    )
                with gr.Column(scale=1):
                    restore_btn = gr.Button("↩️ Restore / 还原", variant="secondary")
            restore_output = gr.Textbox(label="Restored / 已还原", lines=3)
            restore_btn.click(
                fn=do_restore_any,
                inputs=[restore_input, magic_key_state],
                outputs=[restore_output],
            )

            gr.Markdown("---")
            gr.Markdown(
                "### Real LLM proof / 真实 LLM 验证\n\n"
                "Look — 4 frontier LLMs really did reason about pseudonyms, and we "
                "restored their answers. Zero PII leaked.\n\n"
                "看 — 4 个前沿 LLM 真的基于假名推理，我们把答案还原回了原文。零 PII 泄漏。"
            )

            cache_rows = [
                [
                    r["model"],
                    r["downstream_text"],
                    r["llm_reply"],
                    f"{r['leaked']}/{r['total_pii']}",
                    f"{r['utility']:.2f}",
                ]
                for r in PRVL_CACHE["rows"]
            ]
            gr.Dataframe(
                headers=[
                    "LLM",
                    "What LLM saw / LLM 看到 (downstream_text)",
                    "LLM's reply / LLM 回答 (cached)",
                    "PII leaked / 泄漏",
                    "Utility / 效用",
                ],
                value=cache_rows,
                interactive=False,
                wrap=True,
            )
            gr.Markdown(
                f"_Source: {PRVL_CACHE['source_run']} · "
                f"Case: {PRVL_CACHE['case_id']} · Profile: {PRVL_CACHE['profile']} · "
                f"Utility judged by Claude-Opus-4.5 (LLM-as-judge)._"
            )

        with gr.TabItem("🔍 Check your text / 检查你的文本"):
            gr.Markdown(
                "_Paste what you're about to send to AI. We'll tell you the risk. / "
                "粘贴你要发给 AI 的文本，我们告诉你风险等级._"
            )

            with gr.Row():
                with gr.Column(scale=1):
                    check_input = gr.Textbox(
                        label="Your text / 你的文本",
                        placeholder="Paste the message you want to send to ChatGPT / Claude / Gemini / 粘贴你要发给 AI 的文本...",
                        lines=6,
                    )
                    check_lang = gr.Dropdown(
                        choices=["zh", "en", "zh,en", "ja", "ko", "de", "uk", "in", "br"],
                        value="zh",
                        label="Language / 语言",
                    )
                    check_btn = gr.Button(
                        "🔍 Check / 检查",
                        variant="primary", size="lg",
                    )

                with gr.Column(scale=1):
                    check_result = gr.Markdown(label="Privacy Assessment / 隐私评估")
                    check_preview = gr.Textbox(
                        label="What AI would see (after protection) / AI 看到的（已保护）",
                        lines=4,
                    )

            check_btn.click(
                fn=check_safety,
                inputs=[check_input, check_lang],
                outputs=[check_result, check_preview],
            )

            gr.Examples(
                examples=CHECK_EXAMPLES,
                inputs=[check_input, check_lang],
                outputs=[check_result, check_preview],
                fn=check_safety,
                cache_examples=False,
            )

        with gr.TabItem("🛡️ Try with options / 调参演示"):
            gr.Markdown(
                "_Encrypt your PII. AI sees pseudonyms. You get everything back. / "
                "加密 PII。AI 看假名。你拿回原文._"
            )

            with gr.Row():
                with gr.Column(scale=1):
                    protect_input = gr.Textbox(
                        label="Original text / 原文",
                        placeholder="Enter text with PII... / 输入含 PII 的文本...",
                        lines=6,
                    )
                    names_input = gr.Textbox(
                        label="Known names (comma-separated) / 已知人名（逗号分隔）",
                        placeholder="王一,John Smith",
                    )
                    with gr.Row():
                        protect_lang = gr.Dropdown(
                            choices=["zh", "en", "zh,en", "ja", "ko", "de", "uk", "in", "br"],
                            value="zh",
                            label="Language / 语言",
                        )
                        protect_mode = gr.Dropdown(
                            choices=["fast", "ner"],
                            value="fast",
                            label="Mode / 模式",
                        )
                        protect_profile = gr.Dropdown(
                            choices=["none", "default", "pipl", "gdpr", "hipaa", "pseudonym-llm"],
                            value="none",
                            label="Profile / 模板",
                        )
                        protect_seed = gr.Textbox(value="42", label="Seed / 种子")
                    protect_btn = gr.Button(
                        "🛡️ Protect / 保护",
                        variant="primary", size="lg",
                    )

                with gr.Column(scale=1):
                    protect_summary = gr.Markdown(label="Summary / 摘要")
                    protect_redacted = gr.Textbox(
                        label="① What AI sees (protected) / AI 看到的（已保护）",
                        lines=3,
                    )
                    protect_restored = gr.Textbox(
                        label="③ What you get back (restored) / 你拿回的（已还原）",
                        lines=3,
                    )
                    protect_key = gr.Code(
                        label="② Your key (keep this) / 你的密钥（保管好）",
                        language="json",
                    )
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
                fn=protect_and_use,
                cache_examples=False,
            )

    gr.Markdown(FOOTER_MD)

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)
