"""Strategy → reversibility classification (leaf module).

The single source of truth for which redaction strategies are valid and which
produce ``restore()``-recoverable output. ``VALID_STRATEGIES`` is the PUBLIC,
user-selectable surface (what a caller's ``config`` / ``strategy_overrides`` is
validated against); ``_ALL_STRATEGIES`` adds the internal-only strategies argus
dispatches for the configs it builds itself. Kept dependency-free (no registry,
no replacer imports) so both ``pure.replacer`` and ``specs.registry`` can import
it top-level without re-creating the registry ↔ replacer cycle.
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

# Internal-only strategies: dispatched by the core and accepted for the configs
# argus builds itself, but deliberately absent from the PUBLIC user-selectable
# ``VALID_STRATEGIES`` above. ``remove_bracketed`` is the pseudonym-llm audit
# pass's bracketed ``[PREFIX-NNNNN]`` placeholder — it exists only to keep the
# audit key space disjoint from the realistic one and must NOT be selectable via
# a user's ``config`` / ``strategy_overrides``.
_INTERNAL_STRATEGIES = ("remove_bracketed",)

# Every strategy the core dispatch accepts = public + internal. Validation of an
# internally-built config (the pseudonym-llm audit pass) checks against this
# superset; user-facing validation checks against ``VALID_STRATEGIES`` alone.
_ALL_STRATEGIES = VALID_STRATEGIES + _INTERNAL_STRATEGIES

# Strategies whose output can be mapped back to the original via the key dict.
# Adding a new strategy (public OR internal) requires classifying it here.
# ``remove_bracketed`` emits a stable `[PREFIX-NNNNN]` pseudonym (like ``remove``
# but in a bracketed namespace disjoint from realistic codes — used by the
# pseudonym-llm audit pass); it is value-independent and LLM-round-trip-safe, so
# it is reversible.
_REVERSIBLE_STRATEGIES = frozenset({"pseudonym", "realistic", "remove", "remove_bracketed", "keep"})


def is_strategy_reversible(strategy: str) -> bool:
    """Return True if ``strategy`` produces a stable surrogate that survives
    an LLM round-trip and can be restored from the LLM's reply.

    This is NOT "can the key dict map the surrogate back to the original" —
    every strategy in ``VALID_STRATEGIES`` is key-recoverable (``redact()``
    always writes the substitution into the returned key, or leaves ``keep``
    output verbatim), so that broader question is always True and isn't what
    this function answers. This function answers a narrower, LLM-specific
    question: mask-family surrogates (``mask`` / ``name_mask`` /
    ``landline_mask`` / ``category``) are *content-derived* from the original
    value (e.g. ``138****5678``, plus a trailing ``①``-style disambiguator on
    collision), and that disambiguator is fragile under LLM normalization —
    an LLM may drop, reformat, or otherwise mangle it in its reply, breaking
    the restore(). ``pseudonym`` / ``realistic`` / ``remove`` / ``keep``
    surrogates don't depend on the original value's shape and survive an LLM
    round-trip reliably, so they're classified reversible here.

    Reversible (LLM-restore safe): ``pseudonym`` / ``realistic`` / ``remove``
    / ``keep``.
    Irreversible for this purpose (content-derived, fragile disambiguator):
    ``mask`` / ``name_mask`` / ``landline_mask`` / ``category``.

    Use in multi-turn dialog flows to fall through to a reversible strategy
    when the LLM response must be restored to original PII for follow-up.
    """
    # Classify across the full (public + internal) set so an internally-built
    # strategy is never "unclassified"; the user-facing error still lists only
    # the public, selectable strategies.
    if strategy not in _ALL_STRATEGIES:
        raise ValueError(f"Unknown strategy '{strategy}'. Valid: {', '.join(VALID_STRATEGIES)}")
    return strategy in _REVERSIBLE_STRATEGIES
