"""``from_state(export_state(r), salt)`` after feeding chunks preserves aggregate_key.

Validates the v0.6.2 contract: salt is held out-of-band, accumulated_key
serializes correctly, redactor identity reconstructible mid-session.
"""

from __future__ import annotations

import json

from hypothesis import HealthCheck, given, settings, strategies as st

from argus_redact import StreamingRedactor


_HSettings = settings(
    database=None,
    deadline=None,
    max_examples=50,
    suppress_health_check=[HealthCheck.too_slow],
)


@_HSettings
@given(
    chunks=st.lists(
        st.text(min_size=1, max_size=80), min_size=1, max_size=5
    ),
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
