"""compose.prompt_anchor — system-prompt addendum for LLM-side anchoring.

Status: signature locked at v0.6.7, implementation ships in v0.6.9.
See docs/architecture-layers.md §Layer 2 for the planned behavior.
"""

from __future__ import annotations


def prompt_anchor(key: dict, lang: str = "zh") -> str:
    """Generate a system-prompt addendum asking the LLM not to abbreviate,
    retitle, or pronoun-substitute pseudonyms.

    Args:
        key: the redaction key dict (pseudonym → original) from redact()
        lang: "zh" or "en"

    Returns:
        A string to prepend / append to the LLM system prompt.

    Raises:
        NotImplementedError: stub in v0.6.7; full implementation ships in v0.6.9.
    """
    raise NotImplementedError(
        "compose.prompt_anchor is shipping in v0.6.9. "
        "See docs/architecture-layers.md §Layer 2 for the planned behavior."
    )
