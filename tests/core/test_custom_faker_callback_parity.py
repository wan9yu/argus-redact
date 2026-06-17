"""Bit-identity gate: custom faker_reserved — old (_replace_python) vs new (replace) path.

Task 10 of v0.7.4: 840-case differential fuzz proving that the Rust-callback path
(``replace()``) and the pure-Python path (``_replace_python()``) produce
byte-identical ``(redacted, key, aliases)`` tuples for every custom faker type,
salt, and lang combination.

A divergence here = a real bit-identity bug in Tasks 6–9. The assertion is NOT
weakened; if ANY case diverges the failing test reports the minimal repro and the
suite fails.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from argus_redact._core_loader import HAS_CORE
from argus_redact.pure.replacer import _faker_reserved_cached, _replace_python, replace
from argus_redact.pure.restore import restore
from argus_redact.specs.registry import PIITypeDef, register, unregister
from tests.conftest import make_match

# ---------------------------------------------------------------------------
# Custom faker definitions
# ---------------------------------------------------------------------------
# 1. Phone-ish: no aliases, format "555-XXX-XXXX" — uses randint only.
# 2. Person-ish: EMITS ALIASES (cross-name variant), uses choice from a small pool
#    → collision-prone with a pool of 3.
# 3. Medical-ish: record ID "MRN-XXXXXXXX", no aliases, purely deterministic.

_PHONE_POOL_PREFIX = ("555", "800", "888")  # small prefix pool → collision-prone
_PERSON_POOL = ("Alice", "Bob", "Charlie")  # intentionally tiny → collision-prone


def _phone_faker(value: str, rng) -> tuple[str, list[str]]:
    """Fake phone: 555-NNN-NNNN. No aliases, uses randint only."""
    prefix = rng.choice(_PHONE_POOL_PREFIX)
    mid = "".join(str(rng.randint(0, 9)) for _ in range(3))
    tail = "".join(str(rng.randint(0, 9)) for _ in range(4))
    return f"{prefix}-{mid}-{tail}", []


def _person_faker(value: str, rng) -> tuple[str, list[str]]:
    """Fake person: chosen from a tiny pool, with a pinyin-style alias.

    The pool has only 3 names → deliberate collision risk that exercises
    the re-roll logic when the first choice is already in ``used``.
    """
    name = rng.choice(_PERSON_POOL)
    alias = name.lower() + "_alias"
    return name, [alias]


def _medical_faker(value: str, rng) -> tuple[str, list[str]]:
    """Fake medical record number: MRN-XXXXXXXX (8 hex chars). No aliases."""
    hex_chars = "0123456789ABCDEF"
    digits = "".join(rng.choice(hex_chars) for _ in range(8))
    return f"MRN-{digits}", []


# ---------------------------------------------------------------------------
# Fixture: register / unregister all three custom types
# ---------------------------------------------------------------------------

_CUSTOM_TYPES = [
    PIITypeDef(
        name="test_parity_phone",
        lang="shared",
        format="555-NNN-NNNN",
        strategy="realistic",
        faker_reserved=_phone_faker,
    ),
    PIITypeDef(
        name="test_parity_person",
        lang="shared",
        format="Name",
        strategy="realistic",
        faker_reserved=_person_faker,
    ),
    PIITypeDef(
        name="test_parity_mrn",
        lang="shared",
        format="MRN-XXXXXXXX",
        strategy="realistic",
        faker_reserved=_medical_faker,
    ),
]

_CUSTOM_NAMES = [td.name for td in _CUSTOM_TYPES]


@pytest.fixture(autouse=True)
def _register_custom_types():
    """Register the three test types, clear the LRU cache, then tear down."""
    for td in _CUSTOM_TYPES:
        register(td)
    _faker_reserved_cached.cache_clear()
    yield
    for td in _CUSTOM_TYPES:
        unregister(td.lang, td.name)
    _faker_reserved_cached.cache_clear()


# ---------------------------------------------------------------------------
# Curated (text, entities) scenarios
#
# Fuzz axes: salt (32 random bytes) × lang (zh / en / zh+en).
# Scenario axis: curated, covering:
#   - single entity per custom type
#   - multi-entity (same type twice → dedup)
#   - multiple types in one text
#   - entity at start / end / middle
#   - alias-emitting type (person)
#   - collision-prone type (person, 3-name pool)
#   - medical type with no aliases
# ---------------------------------------------------------------------------

_PHONE_VALUE = "415-555-9876"
_PERSON_VALUE = "Wang Fang"
_MRN_VALUE = "MRN-ORIG0001"

_SCENARIOS: list[tuple[str, list]] = [
    # phone — middle of sentence
    (
        f"Call me at {_PHONE_VALUE} tomorrow.",
        [make_match(_PHONE_VALUE, "test_parity_phone", 11)],
    ),
    # phone — at sentence start
    (
        f"{_PHONE_VALUE} is my number.",
        [make_match(_PHONE_VALUE, "test_parity_phone", 0)],
    ),
    # phone — at sentence end (no trailing punctuation)
    (
        f"number is {_PHONE_VALUE}",
        [make_match(_PHONE_VALUE, "test_parity_phone", 10)],
    ),
    # person — alias-emitting type
    (
        f"Contact {_PERSON_VALUE} for details.",
        [make_match(_PERSON_VALUE, "test_parity_person", 8)],
    ),
    # person — two occurrences of same value (dedup path)
    (
        f"{_PERSON_VALUE} called {_PERSON_VALUE} again.",
        [
            make_match(_PERSON_VALUE, "test_parity_person", 0),
            make_match(_PERSON_VALUE, "test_parity_person", len(_PERSON_VALUE) + 8),
        ],
    ),
    # medical — no aliases, pure hex output
    (
        f"Patient record: {_MRN_VALUE}.",
        [make_match(_MRN_VALUE, "test_parity_mrn", 16)],
    ),
    # mixed: phone + person in same text
    (
        f"Call {_PERSON_VALUE} at {_PHONE_VALUE}.",
        [
            make_match(_PERSON_VALUE, "test_parity_person", 5),
            make_match(_PHONE_VALUE, "test_parity_phone", 5 + len(_PERSON_VALUE) + 4),
        ],
    ),
    # mixed: all three types
    (
        f"{_PERSON_VALUE} has {_MRN_VALUE} and phone {_PHONE_VALUE}.",
        [
            make_match(_PERSON_VALUE, "test_parity_person", 0),
            make_match(_MRN_VALUE, "test_parity_mrn", len(_PERSON_VALUE) + 5),
            make_match(
                _PHONE_VALUE,
                "test_parity_phone",
                len(_PERSON_VALUE) + 5 + len(_MRN_VALUE) + 11,
            ),
        ],
    ),
    # empty entity list (both paths must return (text, {}, {}) with no error)
    (
        "No PII here.",
        [],
    ),
]


# ---------------------------------------------------------------------------
# 840-case differential fuzz
# ---------------------------------------------------------------------------

_FUZZ_SETTINGS = settings(
    max_examples=840,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    database=None,
)


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available — parity requires both paths")
@_FUZZ_SETTINGS
@given(
    salt=st.binary(min_size=32, max_size=32),
    lang=st.sampled_from([["zh"], ["en"], ["zh", "en"]]),
    scenario_idx=st.integers(min_value=0, max_value=len(_SCENARIOS) - 1),
)
def test_custom_faker_old_vs_new_parity(salt: bytes, lang: list[str], scenario_idx: int):
    """840-case differential fuzz: _replace_python == replace for every custom faker.

    Exercises:
    - All 9 curated scenarios (phone / person / medical / multi / dedup / empty)
    - 32-byte fuzzed salt → covers full HMAC entropy space
    - All three lang vectors (zh, en, zh+en) → tests lang-preference lookup
    - Alias-emitting person faker → aliases dict must match exactly
    - Collision-prone 3-name pool → re-roll logic must be identical
    """
    text, entities = _SCENARIOS[scenario_idx]

    # Invariant: every curated entity span must slice to its own .text value.
    # A bad offset causes cosmetically corrupted redactions; catch it loudly here.
    for ent in entities:
        assert text[ent.start : ent.end] == ent.text, (
            f"Scenario {scenario_idx}: entity {ent.type!r} span [{ent.start}:{ent.end}] "
            f"→ {text[ent.start:ent.end]!r} != {ent.text!r} in {text!r}"
        )

    config = {name: {"strategy": "realistic"} for name in _CUSTOM_NAMES}

    old = _replace_python(text, entities, salt=salt, langs=lang, config=config)
    new = replace(text, entities, salt=salt, langs=lang, config=config)

    assert old == new, (
        f"BIT-IDENTITY DIVERGENCE detected!\n"
        f"  scenario_idx={scenario_idx}\n"
        f"  text={text!r}\n"
        f"  entities={entities!r}\n"
        f"  salt={salt.hex()}\n"
        f"  lang={lang!r}\n"
        f"  old (Python) = {old!r}\n"
        f"  new (Rust+cb) = {new!r}\n"
        f"This is a real bug in Tasks 6–9, not a test issue."
    )


# ---------------------------------------------------------------------------
# Targeted tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_custom_faker_tuple_enforcement():
    """A faker that returns a bare string (not tuple) must raise on BOTH paths.

    Both _replace_python and replace must enforce the tuple contract uniformly.
    """

    def _bad_faker(value: str, rng) -> str:
        return "FLAT-STRING"

    td = PIITypeDef(
        name="test_parity_bad_faker",
        lang="shared",
        format="BAD",
        strategy="realistic",
        faker_reserved=_bad_faker,
    )
    register(td)
    _faker_reserved_cached.cache_clear()

    text = "bad BAD bad"
    entities = [make_match("BAD", "test_parity_bad_faker", 4)]
    config = {"test_parity_bad_faker": {"strategy": "realistic"}}

    try:
        with pytest.raises((TypeError, ValueError)):
            _replace_python(text, entities, salt=b"x" * 32, config=config)

        with pytest.raises((TypeError, ValueError)):
            replace(text, entities, salt=b"x" * 32, config=config)
    finally:
        unregister("shared", "test_parity_bad_faker")
        _faker_reserved_cached.cache_clear()


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_custom_faker_multi_lang_preference():
    """zh+en same-named type → correct lang-preferred variant on BOTH paths.

    Register test_parity_person for both zh and en with different fakers.
    With langs=["zh"], zh variant must win on both paths.
    """

    def _zh_person_faker(value: str, rng) -> tuple[str, list[str]]:
        return "ZH-FAKE", []

    def _en_person_faker(value: str, rng) -> tuple[str, list[str]]:
        return "EN-FAKE", []

    td_zh = PIITypeDef(
        name="test_parity_lang_person",
        lang="zh",
        format="Name",
        strategy="realistic",
        faker_reserved=_zh_person_faker,
    )
    td_en = PIITypeDef(
        name="test_parity_lang_person",
        lang="en",
        format="Name",
        strategy="realistic",
        faker_reserved=_en_person_faker,
    )
    register(td_zh)
    register(td_en)
    _faker_reserved_cached.cache_clear()

    text = "contact LiMing today"
    entities = [make_match("LiMing", "test_parity_lang_person", 8)]
    config = {"test_parity_lang_person": {"strategy": "realistic"}}
    salt = b"\x00" * 32

    try:
        old_zh = _replace_python(text, entities, salt=salt, langs=["zh"], config=config)
        new_zh = replace(text, entities, salt=salt, langs=["zh"], config=config)
        assert old_zh == new_zh, (
            f"zh-lang parity failed: old={old_zh!r} new={new_zh!r}"
        )
        # zh faker should produce ZH-FAKE, not EN-FAKE
        assert "ZH-FAKE" in old_zh[0], (
            f"Expected ZH-FAKE in redacted text, got {old_zh[0]!r}"
        )

        old_en = _replace_python(text, entities, salt=salt, langs=["en"], config=config)
        new_en = replace(text, entities, salt=salt, langs=["en"], config=config)
        assert old_en == new_en, (
            f"en-lang parity failed: old={old_en!r} new={new_en!r}"
        )
        assert "EN-FAKE" in old_en[0], (
            f"Expected EN-FAKE in redacted text, got {old_en[0]!r}"
        )
    finally:
        unregister("zh", "test_parity_lang_person")
        unregister("en", "test_parity_lang_person")
        _faker_reserved_cached.cache_clear()


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_custom_faker_collision_reroll():
    """Pre-seeding key with the faker's first output forces a re-roll.

    Both paths must re-roll to the SAME unique fake when the first-attempt
    fake is already in the key (simulating a prior entity with same output).

    Strategy: use _phone_faker's first output for a given (salt, value) as a
    pre-existing key entry, then verify both paths produce the same second fake.
    """
    from argus_redact.pure.replacer import _ShakeRng, _seed_from_value

    salt = b"\x42" * 32
    value = _PHONE_VALUE
    etype = "test_parity_phone"
    config = {etype: {"strategy": "realistic"}}

    # Compute the first fake from the HMAC seed (same as _generate_unique_fake attempt 0)
    seed = _seed_from_value(value, etype, salt)
    rng = _ShakeRng(seed=seed)
    first_fake, _ = _phone_faker(value, rng)

    # Pre-populate key with first_fake → forces re-roll on both paths
    pre_key = {first_fake: "some_other_original"}

    text = f"Call {value} please."
    entities = [make_match(value, etype, 5)]

    old = _replace_python(text, entities, salt=salt, key=pre_key.copy(), config=config)
    new = replace(text, entities, salt=salt, key=pre_key.copy(), config=config)

    assert old == new, (
        f"Collision re-roll parity failed:\n  old={old!r}\n  new={new!r}"
    )

    # Sanity: the re-rolled fake should NOT be the first_fake
    old_redacted, old_key, _ = old
    assert first_fake not in old_redacted or old_key.get(first_fake) != value, (
        f"Re-roll must produce a different fake than {first_fake!r}"
    )


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_no_custom_uses_builtin_rust_path():
    """Built-in-only entities must produce empty custom_fakers → Rust path taken.

    Use a built-in type (phone / zh) without any custom faker to verify:
    1. The call succeeds (no regression).
    2. The output is a valid (redacted, key, aliases) triple.
    3. The fake is NOT the original value (it was redacted).
    """
    # Use a built-in zh phone value that the zh phone faker covers.
    builtin_value = "13912345678"
    text = f"Phone: {builtin_value}"
    entities = [make_match(builtin_value, "phone", 7)]

    redacted, key, aliases = replace(
        text,
        entities,
        salt=b"\x01" * 32,
        langs=["zh"],
    )

    assert builtin_value not in redacted, (
        f"Built-in phone must be redacted, found original in: {redacted!r}"
    )
    assert len(key) >= 1, f"Expected at least one key entry, got {key!r}"
    # aliases may be empty for phone (no cross-language alias expected)
    assert isinstance(aliases, dict)


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_custom_faker_roundtrip():
    """restore() on a custom-faker-redacted text must return the original.

    Uses the medical type (no aliases, deterministic). Verifies that the key
    produced by replace() can be fed to restore() to recover the original text.
    """
    text = f"Patient {_MRN_VALUE} needs review."
    entities = [make_match(_MRN_VALUE, "test_parity_mrn", 8)]
    config = {"test_parity_mrn": {"strategy": "realistic"}}
    salt = b"\xDE\xAD" * 16

    redacted, key, aliases = replace(
        text,
        entities,
        salt=salt,
        langs=["en"],
        config=config,
    )

    assert _MRN_VALUE not in redacted, (
        f"Original MRN must not appear in redacted text: {redacted!r}"
    )
    assert len(key) == 1, f"Expected 1 key entry, got {key!r}"

    # Restore using the key
    restored = restore(redacted, key)
    assert restored == text, (
        f"restore() failed: expected {text!r}, got {restored!r}"
    )
