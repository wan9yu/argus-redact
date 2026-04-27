"""Korean hints data — kinship vocabulary + command-mode suffixes.

Consumed by ``argus_redact.pure.hints``.
"""

from __future__ import annotations

KINSHIP: frozenset[str] = frozenset({
    "저의 어머니",
    "제 아버지",
    "저의 아내",
    "저의 남편",
    "저의 아들",
    "저의 딸",
    "어머니",
    "아버지",
    "아내",
    "남편",
    "아이",
    "가족",
})

COMMAND_SUFFIXES: tuple[str, ...] = (
    "해주세요",
    "해 주세요",
    "가르쳐 주세요",
    "연락해 주세요",
    "도와주세요",
    "알려주세요",
)
