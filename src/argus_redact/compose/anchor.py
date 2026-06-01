"""compose.prompt_anchor — system-prompt addendum for LLM-side anchoring.

Generates a system-prompt addendum asking the LLM to preserve redaction
placeholders verbatim. Empirically improves R-creative on summarize / advice
tasks where LLMs would otherwise abbreviate (P-83811 → "the person") or
retitle (黄芳 → "黄先生").

Template form: a 3-rule instruction (DO+DON'T+pragmatic) followed by an
explicit identifier list extracted from key.

Implementation locked at v0.6.9. Template text is snapshot-tested to
prevent silent drift.
"""

from __future__ import annotations


_TEMPLATE_ZH = """以下对话中出现的标识符是脱敏占位符。请遵循三条规则：
1. **完整保留**这些标识符 — 不要替换为称谓（如"先生/女士/总"），不要省略为缩写。
2. 不要主动猜测或还原它们对应的真实身份。
3. 标识符之间的语义关系可按上下文正常推理。

脱敏标识符清单：
{identifier_list}"""


_TEMPLATE_EN = """The following identifiers are redaction placeholders. Please follow three rules:
1. **Preserve these identifiers verbatim** — do not substitute with titles (e.g., "Mr./Ms./Sir"), do not abbreviate.
2. Do not attempt to guess or restore their original identities.
3. Reasoning about relationships between identifiers from context is fine.

Redaction placeholder list:
{identifier_list}"""


def prompt_anchor(key: dict, lang: str = "zh") -> str:
    """Generate a system-prompt addendum.

    Args:
        key: redaction key dict (pseudonym → original) from redact().
        lang: "zh" or "en". Unknown values fall back to "en".

    Returns:
        Multi-line string. Empty string if key is empty (no anchoring needed).
    """
    if not key:
        return ""
    template = _TEMPLATE_ZH if lang == "zh" else _TEMPLATE_EN
    identifier_list = "\n".join(f"  - {k}" for k in sorted(key.keys()))
    return template.format(identifier_list=identifier_list)
