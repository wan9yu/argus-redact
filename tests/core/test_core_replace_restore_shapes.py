"""Direct return-shape tests for the PyO3 bindings `_core.replace` /
`_core.restore`.

Both bindings return ONE object per call ending in a `signals` dict slot
instead of a wide positional tuple: `_core.replace(...)` unpacks to
`(redacted, key, aliases, signals)` with `signals = {"keep_downgraded": bool,
"mask_collisions": list[str]}`; `_core.restore(...)` unpacks to
`(restored, signals)` with `signals = {"alias_collisions": list[str]}`. This
locks that shape directly at the binding boundary — the higher-level
`pure.replacer.replace` / `pure.restore.restore` wrappers build the frozen
public views on top of it and are covered elsewhere (e.g.
`tests/core/test_replace.py`, `tests/core/test_alias_collision.py`).
"""

from __future__ import annotations

import argus_redact._core as _core

from argus_redact.pure.replacer import _KEEP_WHITELIST, DEFAULT_PREFIXES, _build_type_info
from tests.conftest import make_match


def _rust_entities(entities):
    return [
        _core.PatternMatch(e.text, e.type, e.start, e.end, e.confidence, e.layer) for e in entities
    ]


def test_core_replace_returns_four_tuple_with_signals_dict():
    entities = [make_match("张三", "person", 0)]
    type_info, custom_fakers = _build_type_info(entities, None, ["zh"])

    redacted, key, aliases, signals = _core.replace(
        "张三说话",
        _rust_entities(entities),
        salt=42,
        key=None,
        type_info=type_info,
        person_prefix=DEFAULT_PREFIXES["person"],
        org_prefix=DEFAULT_PREFIXES["organization"],
        unified_prefix=None,
        keep_whitelist=_KEEP_WHITELIST,
        custom_fakers=custom_fakers if custom_fakers else None,
    )

    assert isinstance(redacted, str)
    assert isinstance(key, dict)
    assert isinstance(aliases, dict)
    assert isinstance(signals, dict)
    assert isinstance(signals["keep_downgraded"], bool)
    assert isinstance(signals["mask_collisions"], list)


def test_core_replace_signals_keep_downgraded_true_on_downgrade():
    # bank_card has no self_reference/kinship whitelist entry, so a "keep"
    # strategy config downgrades — mirrors pure/replacer.py's
    # `_keep_downgraded_entities` selection.
    entities = [make_match("4111111111111111", "bank_card", 0)]
    type_info, custom_fakers = _build_type_info(
        entities, {"bank_card": {"strategy": "keep"}}, ["en"]
    )

    _redacted, _key, _aliases, signals = _core.replace(
        "4111111111111111",
        _rust_entities(entities),
        salt=42,
        key=None,
        type_info=type_info,
        person_prefix=DEFAULT_PREFIXES["person"],
        org_prefix=DEFAULT_PREFIXES["organization"],
        unified_prefix=None,
        keep_whitelist=_KEEP_WHITELIST,
        custom_fakers=custom_fakers if custom_fakers else None,
    )

    assert signals["keep_downgraded"] is True


def test_core_restore_returns_two_tuple_with_signals_dict():
    restored, signals = _core.restore("P-00001说话", {"P-00001": "张三"})

    assert restored == "张三说话"
    assert isinstance(signals, dict)
    assert isinstance(signals["alias_collisions"], list)


def test_core_restore_signals_alias_collisions_populated_on_collision():
    # Two distinct fakes claim the same alias string -> the losing claim lands
    # in alias_collisions (mirrors tests/core/test_alias_collision.py).
    key = {"P-1": "Alice", "P-2": "Bob"}
    aliases = {"P-1": ["Shared"], "P-2": ["Shared"]}

    _restored, signals = _core.restore("hello Shared", key, aliases=aliases)

    assert signals["alias_collisions"] == ["Shared"]
