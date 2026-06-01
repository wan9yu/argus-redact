"""compose.expand_aliases — surname+title composite alias expansion.

Status: signature locked at v0.6.7, implementation ships in v0.6.9.
See docs/architecture-layers.md §Layer 2 for the planned behavior.
"""

from __future__ import annotations


def expand_aliases(key: dict, lang: str = "zh") -> dict:
    """Expand the key dict with surname+title composite aliases.

    For each Person entry in `key`, generate aliases like "<surname>先生" /
    "<surname>总" (zh) or "Mr. <surname>" / "Dr. <surname>" (en), mapping
    them to the same pseudonym so literal substring restore() catches them.

    Args:
        key: the redaction key dict from redact()
        lang: "zh" or "en"

    Returns:
        A new dict with original entries + alias entries.

    Raises:
        NotImplementedError: stub in v0.6.7; full implementation ships in v0.6.9.
    """
    raise NotImplementedError(
        "compose.expand_aliases is shipping in v0.6.9. "
        "See docs/architecture-layers.md §Layer 2 for the planned behavior."
    )
