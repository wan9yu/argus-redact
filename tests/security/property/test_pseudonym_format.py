"""``pseudonym``-strategy output matches ``^<prefix>-\\d{1,5}$`` for any input.

Format invariant — downstream LLMs rely on the regular shape to round-trip.
"""

from __future__ import annotations

import re

from hypothesis import given, settings, strategies as st

from argus_redact._types import PatternMatch
from argus_redact.pure.replacer import DEFAULT_PREFIXES, replace
from tests.security.property.conftest import PROPERTY_SETTINGS


@settings(parent=PROPERTY_SETTINGS, max_examples=200)
@given(
    text=st.text(min_size=1, max_size=50),
    entity_type=st.sampled_from(["person", "organization"]),
    seed=st.integers(min_value=0, max_value=2**31 - 1),
)
def test_pseudonym_output_format(text, entity_type, seed):
    """Any pseudonym replacement of any text matches the expected shape."""
    entity = PatternMatch(
        text=text, type=entity_type, start=0, end=len(text), layer=1
    )
    redacted, key, _ = replace(
        f"{text} suffix",
        [entity],
        config={entity_type: {"strategy": "pseudonym"}},
        seed=seed,
    )

    fake_codes = list(key.keys())
    if not fake_codes:
        return

    prefix = DEFAULT_PREFIXES.get(entity_type, "P")
    pattern = re.compile(rf"^{re.escape(prefix)}-\d{{1,5}}$")
    for fake in fake_codes:
        assert pattern.match(fake), (
            f"pseudonym output {fake!r} does not match {pattern.pattern}"
        )
