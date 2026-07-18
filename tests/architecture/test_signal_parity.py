"""Per-signal-per-surface parity: regression-locks that every Python surface
capable of producing a compliance signal (``keep_downgraded``, ``mask_collision``,
``alias_collision``) actually surfaces it, instead of silently dropping it.

Three surfaces exist for ``keep_downgraded``/``mask_collision``:

  (a) the one-shot public ``redact(detailed=True)`` path (glue ``_replace_and_emit``
      -> ``_core.replace``'s ``signals`` dict);
  (b) the structured ``redact_csv``/``redact_json`` path, backed by the stateful
      ``_core.StructuredRedactor`` session (``structured.py``'s
      ``session.mask_collisions`` reads, mirrored here to build the matching
      security_event);
  (c) the wasm ``redact()`` result, which carries both signals additively on its
      JS-visible object — covered by
      ``crates/argus-redact-wasm/tests/parity.rs::redact_result_carries_signals``,
      not re-asserted here.

``alias_collisions`` only has ONE Python-observable surface: restore-with-aliases.
wasm ``restore`` takes no ``aliases`` parameter, so its collision list is
structurally always empty — asserting on it there would be vacuous, so no wasm
assertion is added for this signal.
"""

from __future__ import annotations

import warnings

import pytest

from argus_redact import redact, restore
from argus_redact.exceptions import SecurityWarning
from argus_redact.pure.replacer import (
    make_structured_session,
    mask_collision_event,
    replace_into_session,
)
from argus_redact.structured import redact_csv
from tests.conftest import make_match

# Two distinct CN mobile numbers that both mask to "138****5678" (mask only shows
# the first 3 + last 4 digits) -- a real mask-family collision, not a contrived one.
_COLLIDING_PHONES = ("13812345678", "13800005678")


def test_redact_surfaces_both_keep_downgraded_and_mask_collision():
    """One `redact(detailed=True)` call whose input BOTH downgrades a `keep`
    entity (bank_card has no self_reference/kinship whitelist entry) AND causes
    a mask-family collision (two phones masking to the same visible label) must
    surface BOTH security_events -- proving neither signal starves the other
    when they co-occur in the same call."""
    text = f"卡号4111111111111111 电话{_COLLIDING_PHONES[0]} 和 {_COLLIDING_PHONES[1]}"
    config = {"bank_card": {"strategy": "keep"}, "phone": {"strategy": "mask"}}

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        _redacted, _key, details = redact(
            text, lang="zh", mode="fast", config=config, detailed=True
        )

    codes = [e["reason_code"] for e in details["security_events"]]
    assert "keep_downgraded" in codes, "keep_downgraded event missing from redact() security_events"
    assert "mask_collision" in codes, "mask_collision event missing from redact() security_events"


def test_structured_redact_csv_public_surface_warns_and_preserves_both_originals():
    """The PUBLIC `redact_csv` entry point, over a column of collision-prone
    phone values, must warn about the collision AND still keep both originals
    recoverable in the returned key (signal-not-remove, mirroring the one-shot
    contract)."""
    csv_text = "phone\n" + "\n".join(_COLLIDING_PHONES)
    config = {"phone": {"strategy": "mask"}}

    with pytest.warns(SecurityWarning, match="collided"):
        _redacted_csv, key = redact_csv(csv_text, config=config)

    assert set(key.values()) == set(_COLLIDING_PHONES)


def test_structured_session_mask_collisions_getter_drives_a_mask_collision_event():
    """`redact_csv`/`redact_json` read `session.mask_collisions` (a
    `StructuredRedactor` getter, structured.py:154/269) to build their
    SecurityWarning. Drive that SAME getter directly, over the SAME
    collision-prone phone column, and confirm the resulting event is the
    `mask_collision` shape the one-shot path produces -- the structured
    surface's session-based signal, not just its warning text."""
    config = {"phone": {"strategy": "mask"}}
    session = make_structured_session(config=config)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        for phone in _COLLIDING_PHONES:
            entities = [make_match(phone, "phone", 0)]
            replace_into_session(session, phone, entities, config=config, langs=["zh"])

    event = mask_collision_event(list(session.mask_collisions))
    assert event is not None, "mask_collision event missing from structured security_events"
    assert event["reason_code"] == "mask_collision"


def test_restore_with_aliases_surfaces_alias_collision():
    """A key with two fakes -> two originals whose aliases collide on one
    string must yield an `alias_collision` event from
    `restore(..., aliases=..., guard=False, detailed=True)` -- the only Python
    surface that can produce this signal (wasm restore takes no aliases)."""
    key = {"P-1": "Alice", "P-2": "Bob"}
    aliases = {"P-1": ["Shared"], "P-2": ["Shared"]}

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        _restored, details = restore(
            "hello Shared", key, aliases=aliases, guard=False, detailed=True
        )

    codes = [e["reason_code"] for e in details["security_events"]]
    assert "alias_collision" in codes, (
        "alias_collision event missing from restore() security_events"
    )


def test_restore_full_compat_shape():
    """A public `redact()` -> `restore()` round-trip proves the core
    `restore_full` compat wrapper's `str` view is unchanged: the text half of
    what `_core.restore` returns (independent of the `signals` dict alongside
    it) still reads back byte-identical to the original input."""
    original = "张三的手机号是13812345678"

    redacted, key = redact(original, lang="zh", mode="fast")
    restored = restore(redacted, key, guard=False)

    assert restored == original
