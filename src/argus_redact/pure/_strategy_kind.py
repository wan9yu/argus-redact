"""Strategy → reversibility classification (leaf module).

The single source of truth for which redaction strategies are valid and which
produce ``restore()``-recoverable output. Kept dependency-free (no registry, no
replacer imports) so both ``pure.replacer`` and ``specs.registry`` can import it
top-level without re-creating the registry ↔ replacer cycle.
"""

from __future__ import annotations

VALID_STRATEGIES = (
    "pseudonym",
    "realistic",
    "mask",
    "remove",
    "category",
    "name_mask",
    "landline_mask",
    "keep",
)

# Strategies whose output can be mapped back to the original via the key dict.
# Adding a new strategy to VALID_STRATEGIES requires classifying it here.
_REVERSIBLE_STRATEGIES = frozenset({"pseudonym", "realistic", "remove", "keep"})


def is_strategy_reversible(strategy: str) -> bool:
    """Return True if ``strategy`` produces output that ``restore()`` can map
    back to the original value.

    Reversible: ``pseudonym`` / ``realistic`` / ``remove`` / ``keep``.
    Irreversible (lossy by design): ``mask`` / ``name_mask`` / ``landline_mask``
    / ``category``.

    Use in multi-turn dialog flows to fall through to a reversible strategy
    when the LLM response must be restored to original PII for follow-up.
    """
    if strategy not in VALID_STRATEGIES:
        raise ValueError(f"Unknown strategy '{strategy}'. Valid: {', '.join(VALID_STRATEGIES)}")
    return strategy in _REVERSIBLE_STRATEGIES
