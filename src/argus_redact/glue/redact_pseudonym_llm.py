"""Public entry point for the pseudonym-llm profile.

Returns a PseudonymLLMResult dataclass with three text forms sharing one key dict.
"""

from __future__ import annotations

from argus_redact._types import PseudonymLLMResult
from argus_redact.glue.redact import redact as _redact
from argus_redact.pure.display_marker import mark_for_display, resolve_marker
from argus_redact.specs.profiles import get_profile

# Bytes prefix used to derive an int seed from a salt (replace() takes int seeds).
_SALT_SEED_BYTES = 8
_SALT_SEED_MASK = 0x7FFFFFFFFFFFFFFF


def redact_pseudonym_llm(
    text: str,
    *,
    display_marker: str | None = None,
    salt: bytes | None = None,
    lang: str | list[str] = "zh",
    mode: str = "fast",
    names: list[str] | None = None,
    types: list[str] | None = None,
    types_exclude: list[str] | None = None,
) -> PseudonymLLMResult:
    """Redact `text` with the pseudonym-llm profile, returning three text forms.

    - audit_text: placeholder labels (e.g., "[TEL-79329]") for compliance archive
    - downstream_text: realistic reserved-range fake (for LLM input)
    - display_text: realistic + marker (for human display)

    All three are reversible via the unified `key` dict using restore().

    Note: detection runs twice (once per replacement strategy). For mode="fast"
    this is negligible; for mode="ner"/"auto" it doubles NER/LLM cost. The
    duplication is necessary because audit_text and downstream_text need
    different replacement strategies on the same entity set.
    """
    profile = get_profile("pseudonym-llm")
    realistic_config = dict(profile["config"])
    # Audit pass uses the same type set with "remove" strategy so audit_text
    # contains [TYPE-NNNNN] placeholders.
    audit_config = {ent_type: {"strategy": "remove"} for ent_type in realistic_config}

    seed = _seed_from_salt(salt)
    pass_kwargs = {
        "lang": lang,
        "mode": mode,
        "names": names,
        "types": types,
        "types_exclude": types_exclude,
        "seed": seed,
    }

    downstream_text, key = _redact(text, config=realistic_config, **pass_kwargs)
    audit_text, audit_key = _redact(text, config=audit_config, **pass_kwargs)

    marker = resolve_marker(display_marker)
    display_text = mark_for_display(downstream_text, key, marker=marker)

    # Realistic and audit pseudonyms are disjoint by construction (digits/Chinese
    # vs [TYPE-NNNNN]), but defend against future drift with explicit collision check.
    unified_key = dict(key)
    for fake, original in audit_key.items():
        if fake in unified_key and unified_key[fake] != original:
            raise RuntimeError(
                f"Key collision: pseudonym {fake!r} maps to two different originals"
            )
        unified_key[fake] = original

    return PseudonymLLMResult(
        audit_text=audit_text,
        downstream_text=downstream_text,
        display_text=display_text,
        key=unified_key,
    )


def _seed_from_salt(salt: bytes | None) -> int | None:
    """Derive a 63-bit non-negative int seed from a salt.

    `random.Random(seed)` accepts arbitrary ints, but masking to 63 bits keeps
    the seed within a machine-word range for reproducibility across platforms.
    """
    if salt is None:
        return None
    return int.from_bytes(salt[:_SALT_SEED_BYTES].ljust(_SALT_SEED_BYTES, b"\x00"), "big") & _SALT_SEED_MASK
