"""``strategy="keep"`` outside the self_reference whitelist always downgrades.

H6 audit: pre-fix, keep would silently leak any text. Post-fix, only
self_reference pronouns and kinship phrases pass through verbatim; everything
else is downgraded to the type's default with SecurityWarning. This property
verifies the contract holds across arbitrary text and types.
"""

from __future__ import annotations

import warnings

from hypothesis import assume, given, strategies as st

from argus_redact import SecurityWarning
from argus_redact._types import PatternMatch
from argus_redact.pure.replacer import _KEEP_WHITELIST, replace
from tests.security.property.conftest import PROPERTY_SETTINGS


@PROPERTY_SETTINGS
@given(
    text=st.text(min_size=1, max_size=80),
    entity_type=st.sampled_from(["phone", "ssn", "id_number", "email", "person"]),
)
def test_keep_outside_whitelist_downgrades(text, entity_type):
    """For non-self_reference type with keep strategy, original is replaced."""
    assume(text not in _KEEP_WHITELIST)  # whitelisted pronouns are exempt
    assume(len(text.strip()) > 0)         # all-whitespace would be a no-op match

    entity = PatternMatch(
        text=text, type=entity_type, start=0, end=len(text), layer=1
    )
    full_text = f"{text} sample"

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        redacted, key, _ = replace(
            full_text, [entity], config={entity_type: {"strategy": "keep"}}, seed=42,
        )

    # Downgrade replaced the entity — original now lives in the reversible key
    # (substring check would false-positive when text is a digit/letter that
    # also appears in the generated replacement, e.g. text='0' in 'ID-03292').
    assert text in key.values(), (
        f"keep did not downgrade {text!r} as {entity_type}; key={key!r}"
    )
    # Warning was emitted.
    assert any(
        issubclass(w.category, SecurityWarning) for w in captured
    ), f"no SecurityWarning emitted for keep downgrade on {entity_type}"


@PROPERTY_SETTINGS
@given(text=st.sampled_from(sorted(_KEEP_WHITELIST)))
def test_keep_inside_whitelist_preserves(text):
    """Whitelisted pronouns / kinship under self_reference are preserved verbatim."""
    entity = PatternMatch(
        text=text, type="self_reference", start=0, end=len(text), layer=1
    )
    redacted, _key, _ = replace(
        f"{text} sample", [entity], config={"self_reference": {"strategy": "keep"}}
    )
    assert text in redacted
