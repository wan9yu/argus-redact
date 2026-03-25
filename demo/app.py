"""argus-redact Hugging Face Space demo."""

import json

import gradio as gr

from argus_redact import __version__, redact, restore


def run_redact(text, lang, mode, seed_str, names_str):
    if not text.strip():
        return "", "{}", "", "No input text"

    seed = int(seed_str) if seed_str.strip() else None
    lang_list = [code.strip() for code in lang.split(",")]
    lang_param = lang_list[0] if len(lang_list) == 1 else lang_list

    names = None
    if names_str.strip():
        names = [n.strip() for n in names_str.split(",") if n.strip()]

    try:
        redacted_text, key, details = redact(
            text,
            lang=lang_param,
            mode=mode,
            seed=seed,
            names=names,
            detailed=True,
        )
    except Exception as e:
        return "", "{}", "", f"Error: {e}"

    restored_text = restore(redacted_text, key)

    key_json = json.dumps(key, ensure_ascii=False, indent=2)

    stats = details["stats"]
    summary = (
        f"Detected {stats['total']} PII entities "
        f"(Layer 1: {stats['layer_1']}, Layer 2: {stats['layer_2']}) "
        f"in {stats['duration_ms']:.1f}ms"
    )

    return redacted_text, key_json, restored_text, summary


EXAMPLES = [
    ["你好王一，你的手机号是18630303030", "zh", "fast", "42", "王一"],
    ["张三的手机号是13812345678，邮箱zhang@test.com", "zh", "fast", "42", "张三"],
    ["John Smith called (555) 123-4567, SSN 123-45-6789", "en", "fast", "42", "John Smith"],
    ["田中太郎の携帯は090-1234-5678", "ja", "fast", "42", "田中太郎"],
    ["김철수 전화번호 010-1234-5678", "ko", "fast", "42", "김철수"],
    ["Hans Müller, Steuer-ID: 12 345 678 901", "de", "fast", "42", "Hans Müller"],
    ["张三给John发了邮件zhang@test.com，电话13812345678", "zh,en", "fast", "42", "张三,John"],
]

with gr.Blocks(title=f"argus-redact v{__version__}") as demo:
    gr.Markdown(
        f"""
        # argus-redact v{__version__}
        **Encrypt PII, not meaning. Locally.**

        Three layers: Regex → NER → Semantic LLM. 7 languages. Reversible with per-message keys.

        [GitHub](https://github.com/wan9yu/argus-redact) |
        [PyPI](https://pypi.org/project/argus-redact/) |
        `pip install argus-redact`
        """
    )

    with gr.Row():
        with gr.Column():
            input_text = gr.Textbox(
                label="Input Text",
                placeholder="Enter text with PII...",
                lines=5,
            )
            names_input = gr.Textbox(
                label="Known Names (comma-separated)",
                placeholder="王一,张三,John Smith",
            )
            with gr.Row():
                lang = gr.Dropdown(
                    choices=["zh", "en", "ja", "ko", "de", "uk", "in", "zh,en", "zh,en,ja,ko"],
                    value="zh",
                    label="Language",
                )
                mode = gr.Dropdown(
                    choices=["fast", "ner"],
                    value="fast",
                    label="Mode",
                )
                seed = gr.Textbox(value="42", label="Seed (empty=random)")
            btn = gr.Button("Redact", variant="primary")

        with gr.Column():
            redacted_text = gr.Textbox(label="Redacted Text", lines=5)
            key_output = gr.Code(label="Key (JSON)", language="json")
            restored_text = gr.Textbox(label="Restored Text", lines=5)
            stats_output = gr.Textbox(label="Stats")

    btn.click(
        fn=run_redact,
        inputs=[input_text, lang, mode, seed, names_input],
        outputs=[redacted_text, key_output, restored_text, stats_output],
    )

    gr.Examples(
        examples=EXAMPLES,
        inputs=[input_text, lang, mode, seed, names_input],
        outputs=[redacted_text, key_output, restored_text, stats_output],
        fn=run_redact,
        cache_examples=False,
    )

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)
