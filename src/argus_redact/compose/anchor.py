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

import secrets
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class Anchor:
    """Round-trip guard carrier: a fresh provenance nonce + the in-scope pseudonym set."""

    nonce: str
    scope: frozenset


def make_anchor(key: Mapping[str, str]) -> Anchor:
    """Fresh per-exchange anchor: unpredictable nonce + scope = this call's pseudonyms."""
    return Anchor(nonce=secrets.token_hex(16), scope=frozenset(key))


_TEMPLATE_ZH = """以下对话中出现的标识符是脱敏占位符。请遵循三条规则：
1. **完整保留**这些标识符 — 不要替换为称谓（如"先生/女士/总"），不要省略为缩写。
2. 不要主动猜测或还原它们对应的真实身份。
3. 标识符之间的语义关系可按上下文正常推理。

脱敏标识符清单：
{identifier_list}"""


_TEMPLATE_EN = (
    "The following identifiers are redaction placeholders. Please follow three rules:\n"
    '1. **Preserve these identifiers verbatim** — do not substitute with titles (e.g., "Mr./Ms./Sir"), do not abbreviate.\n'  # noqa: E501
    "2. Do not attempt to guess or restore their original identities.\n"
    "3. Reasoning about relationships between identifiers from context is fine.\n"
    "\n"
    "Redaction placeholder list:\n"
    "{identifier_list}"
)

# CONTRACT: both instructions ask for the token LAST and ON ITS OWN LINE. That
# wording is load-bearing — the guarded restore's nonce stripper (`strip_nonce` in
# the Rust core's restore module) removes the token from the model's reply by
# exactly that shape, and a token left in the reply is handed back to the caller as
# part of the restored plaintext. If you reword these, update `strip_nonce` with
# them. Pinned by
# tests/compose/test_prompt_anchor_nonce.py::test_nonce_echo_instruction_shape.
_NONCE_ECHO_EN = "\n\nEnd your reply with this exact verification token on its own line: {nonce}"

_NONCE_ECHO_ZH = "\n\n请在回复末尾以独立的一行输出这个验证令牌：{nonce}"


def prompt_anchor(key: dict, lang: str = "zh", *, anchor: Anchor | None = None) -> str:
    """Generate a system-prompt addendum.

    Args:
        key: redaction key dict (pseudonym → original) from redact().
        lang: "zh" or "en". Unknown values fall back to "en".
        anchor: optional Anchor instance; when provided, appends a nonce-echo instruction
                for the LLM to verify its response integrity.

    Returns:
        Multi-line string. Empty string if key is empty (no anchoring needed).
        When anchor is given, appends a nonce-echo line for LLM verification.
    """
    if not key:
        return ""
    template = _TEMPLATE_ZH if lang == "zh" else _TEMPLATE_EN
    identifier_list = "\n".join(f"  - {k}" for k in sorted(key.keys()))
    result = template.format(identifier_list=identifier_list)

    if anchor is not None:
        nonce_echo = _NONCE_ECHO_ZH if lang == "zh" else _NONCE_ECHO_EN
        result += nonce_echo.format(nonce=anchor.nonce)

    return result
