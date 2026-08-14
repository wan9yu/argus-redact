"""Lang-aware default-strategy parity guard (v0.8.10).

``_resolve_default_strategy`` used to be lang-blind: ``lookup(name)[0].strategy``,
picking whichever typedef happened to register first regardless of the entity's
actual language. No currently-registered type disagrees on ``strategy`` across
languages (dormant today — this is a forward-looking correctness fix, not an
observed bug), but the function is now lang-aware: it prefers a typedef
registered for one of the entity's detected languages, then ``'shared'``, then
whichever typedef happens to be first (the old lang-blind fallback), mirroring
the SAME preference order ``_resolve_realistic_faker`` already uses for the
realistic-faker lookup.

This sweeps every registered ``(lang, name)`` pair and proves the value
``_resolve_default_strategy`` reports for that pair is EXACTLY what the real
runtime path applies: ``_build_type_info`` threads its result into
``_core.build_type_info`` (the already-built Rust extension — no rebuild
required) as ``registry_defaults``, and with no per-call config override, the
entity's effective strategy in the returned info dict must equal it. A drift
here would mean the Python resolver's answer is not actually what gets applied
to redaction for that language.
"""

from __future__ import annotations

import pytest

from argus_redact._core_loader import HAS_CORE
from argus_redact.pure.replacer import _build_type_info, _resolve_default_strategy
from argus_redact.specs.registry import list_types
from tests.conftest import make_match

_ALL_LANG_NAME_PAIRS = sorted({(td.lang, td.name) for td in list_types()})


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_at_least_all_registered_pairs_swept():
    """Sanity: the sweep covers the full registry, not a hardcoded handful."""
    assert len(_ALL_LANG_NAME_PAIRS) >= 40, (
        f"expected the full (lang, name) registry sweep (>=40 pairs), got "
        f"{len(_ALL_LANG_NAME_PAIRS)}"
    )


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
@pytest.mark.parametrize("lang, name", _ALL_LANG_NAME_PAIRS)
def test_default_strategy_matches_rust_applied_strategy(lang, name):
    """Python-reported default strategy == what the Rust extension actually
    applies, per (lang, name) — not just per name."""
    entities = [make_match(name, name, 0)]
    info, _custom_fakers = _build_type_info(entities, config=None, langs=[lang])

    expected = _resolve_default_strategy(name, [lang])
    assert info[name]["strategy"] == expected, (
        f"{lang}/{name}: Rust-applied strategy {info[name]['strategy']!r} != "
        f"Python-reported default {expected!r}"
    )


def test_resolve_default_strategy_prefers_the_detected_language():
    """A type registered under two languages with DIFFERENT default strategies
    resolves to the typedef matching the caller's detected language, not
    whichever one happened to register first — the bug this task fixes."""
    from argus_redact.specs.registry import PIITypeDef, register, unregister

    name = "_test_lang_split_strategy_type"
    try:
        register(PIITypeDef(name=name, lang="en", format="x", strategy="mask", sensitivity=1))
        register(PIITypeDef(name=name, lang="zh", format="x", strategy="remove", sensitivity=1))

        assert _resolve_default_strategy(name, ["en"]) == "mask"
        assert _resolve_default_strategy(name, ["zh"]) == "remove"
    finally:
        unregister("en", name)
        unregister("zh", name)


def test_resolve_default_strategy_falls_back_to_shared_then_first():
    """No matching detected language (including none given at all) → prefer
    'shared' → else the first-registered typedef (the old lang-blind
    fallback), never an error — the SAME 3-tier order
    ``_resolve_realistic_faker`` already uses."""
    from argus_redact.specs.registry import PIITypeDef, register, unregister

    name = "_test_lang_fallback_strategy_type"
    try:
        register(PIITypeDef(name=name, lang="en", format="x", strategy="mask", sensitivity=1))
        register(
            PIITypeDef(name=name, lang="shared", format="x", strategy="pseudonym", sensitivity=1)
        )

        # A detected language absent from the registry falls back to 'shared'.
        assert _resolve_default_strategy(name, ["fr"]) == "pseudonym"
        # No langs at all also falls back to 'shared' (not first-registered).
        assert _resolve_default_strategy(name) == "pseudonym"
    finally:
        unregister("en", name)
        unregister("shared", name)


def test_resolve_default_strategy_falls_back_to_first_registered_when_no_shared():
    """No detected-lang match and no 'shared' registration → the first-
    registered typedef (the old lang-blind behaviour), never an error."""
    from argus_redact.specs.registry import PIITypeDef, register, unregister

    name = "_test_lang_fallback_no_shared_type"
    try:
        register(PIITypeDef(name=name, lang="en", format="x", strategy="mask", sensitivity=1))
        assert _resolve_default_strategy(name, ["fr"]) == "mask"
        assert _resolve_default_strategy(name) == "mask"
    finally:
        unregister("en", name)
