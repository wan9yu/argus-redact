"""Producer-side guards must have a matching consumer-side rejection.

Every invariant the redact/produce path enforces at creation must be rejected
symmetrically on the restore/consume path — otherwise a corruption or forgery
between the two halves lands on code that validates nothing. A new producer
guard without its restore twin should fail here.
"""

import pytest

from argus_redact.pure.restore import restore


def test_empty_replacement_producer_guard_has_restore_twin():
    # PRODUCER: replace.rs refuses to write an empty replacement into the key.
    # CONSUMER twin: restore() must reject a key that contains an empty-string
    # entry (the only way one could arrive is corruption/hand-building).
    with pytest.raises(ValueError):
        restore("abc", {"": "SECRET"}, guard=False)
