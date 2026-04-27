"""Chinese hints data — kinship vocabulary + command-mode prefixes.

Consumed by ``argus_redact.pure.hints``: kinship matches mark a self_reference
as Tier 1 (keep), command prefixes drive ``text_intent="instruction"``.
"""

from __future__ import annotations

# Exact kinship phrases — match against entity.text.
KINSHIP: frozenset[str] = frozenset({
    "我妈妈",
    "我爸爸",
    "我母亲",
    "我父亲",
    "我老公",
    "我老婆",
    "我丈夫",
    "我妻子",
    "我先生",
    "我太太",
    "我儿子",
    "我女儿",
    "我哥哥",
    "我姐姐",
    "我弟弟",
    "我妹妹",
    "我哥",
    "我姐",
    "我弟",
    "我妹",
    "我妈",
    "我爸",
    "我爷爷",
    "我奶奶",
    "我外公",
    "我外婆",
    "我叔叔",
    "我阿姨",
    "我舅舅",
    "我姑姑",
    "我家人",
    "我家里人",
    "我孩子",
})

# Command-mode prefixes — match against text.strip().startswith(...).
COMMAND_PREFIXES: tuple[str, ...] = (
    "我想问",
    "我想知道",
    "我需要",
    "我要问",
    "帮我",
    "请帮我",
    "请告诉我",
    "告诉我",
    "我想让你",
    "我希望你",
    "我要你",
    "麻烦帮我",
    "能帮我",
    "可以帮我",
)
