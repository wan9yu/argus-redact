"""``from_state(export_state(r), salt)`` after feeding chunks preserves aggregate_key.

Salt held out-of-band; accumulated_key serializes; redactor reconstructible.
"""

from __future__ import annotations

import json

from hypothesis import given, settings, strategies as st

from argus_redact.compose import StreamingRedactor
from argus_redact.pure.reserved_range_scanner import scan_for_pollution
from tests.security.property.conftest import PROPERTY_SETTINGS


# StreamingRedactor defaults to ``strict_input=True``, which rejects input
# containing reserved-range pseudonym values (the very strings the pipeline
# emits as fake replacements). With ``st.text()`` over the full Unicode range,
# hypothesis occasionally synthesizes a short string that collides with a
# reserved zh person name (e.g. ``偕鸳``), causing the redactor to raise
# ``PseudonymPollutionError`` before the round-trip can even run.
#
# That's not a property-test signal — it's an unwritten precondition of the
# test ("aggregate_key round-trips for *valid*, non-polluted input"). Filter
# pathological inputs out at the strategy level rather than loosening the
# assertion: the bit-equality assertion is the real contract we want to lock.
def _is_unpolluted(chunks: list[str]) -> bool:
    return not scan_for_pollution("".join(chunks))


@settings(parent=PROPERTY_SETTINGS, max_examples=50)
@given(
    chunks=st.lists(
        st.text(min_size=1, max_size=80), min_size=1, max_size=5
    ).filter(_is_unpolluted),
    salt=st.binary(min_size=32, max_size=32),
)
def test_state_round_trip_preserves_aggregate_key(chunks, salt):
    """Feed chunks → export → from_state → aggregate_key matches."""
    r1 = StreamingRedactor(salt=salt)
    for c in chunks:
        r1.feed(c)
    r1.flush()
    state = r1.export_state()
    assert "salt" not in state, "v0.6.2 contract: salt omitted by default"

    encoded = json.dumps(state)
    state2 = json.loads(encoded)

    r2 = StreamingRedactor.from_state(state2, salt=salt)
    assert r2.aggregate_key() == r1.aggregate_key()
