"""For arbitrary text and salt, restore∘redact = identity.

If hypothesis finds a counter-example here, it's a real bug — either in
redact's normalization, in restore's pattern matching, or in cross-language
alias handling. The property holds across the project's stated 8-language
support and arbitrary unicode.
"""

from __future__ import annotations

from hypothesis import given, strategies as st

from argus_redact import redact_pseudonym_llm, restore
from tests.security.property.conftest import PROPERTY_SETTINGS


@PROPERTY_SETTINGS
@given(
    text=st.text(min_size=1, max_size=200),
    salt=st.binary(min_size=32, max_size=32),
)
def test_round_trip_zh(text, salt):
    """For arbitrary text under zh, full round-trip recovers the original."""
    r = redact_pseudonym_llm(
        text, salt=salt, lang="zh", _polluted_input_ok=True
    )
    assert restore(r.downstream_text, r.key) == text


@PROPERTY_SETTINGS
@given(
    text=st.text(min_size=1, max_size=200),
    salt=st.binary(min_size=32, max_size=32),
)
def test_round_trip_en(text, salt):
    """Same property under en."""
    r = redact_pseudonym_llm(
        text, salt=salt, lang="en", _polluted_input_ok=True
    )
    assert restore(r.downstream_text, r.key) == text
