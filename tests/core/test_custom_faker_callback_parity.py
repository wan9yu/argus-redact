"""Frozen golden: custom faker_reserved through the Rust-callback redact path.

A custom ``faker_reserved`` callable (one not resolvable by the Rust core's
by-function-name faker dispatch) is invoked mid-loop via the Rust
``PyFakerFactory`` callback. The differential fuzz that once proved this path
byte-identical to the (now-deleted) pure-Python orchestrator has been frozen
into a fixed-corpus golden: a deterministic set of (scenario, salt, lang) cases
whose ``replace()`` output — ``(redacted, key, aliases)`` — is pinned here.

A divergence means the custom-faker callback path changed shape; the golden is
deliberately reviewable (regenerate only when the change is intended). The
custom fakers below genuinely fire (phone digits, alias-emitting person, MRN
hex), and the entity-span guard from the original fuzz is preserved.
"""

from __future__ import annotations

import pytest

from argus_redact._core_loader import HAS_CORE
from argus_redact.pure.replacer import _clear_faker_caches, replace
from argus_redact.pure.restore import restore
from argus_redact.specs.registry import PIITypeDef, register, unregister
from tests.conftest import make_match

# ---------------------------------------------------------------------------
# Custom faker definitions (deterministic from the seeded RNG)
# ---------------------------------------------------------------------------
# 1. Phone-ish: no aliases, format "PFX-NNN-NNNN" — choice + randint.
# 2. Person-ish: EMITS ALIASES (cross-name variant), choice from a tiny pool
#    → collision-prone with a pool of 3.
# 3. Medical-ish: record ID "MRN-XXXXXXXX" (hex), no aliases.

_PHONE_POOL_PREFIX = ("555", "800", "888")  # small prefix pool → collision-prone
_PERSON_POOL = ("Alice", "Bob", "Charlie")  # intentionally tiny → collision-prone


def _phone_faker(value: str, rng) -> tuple[str, list[str]]:
    """Fake phone: PFX-NNN-NNNN. No aliases, uses choice + randint."""
    prefix = rng.choice(_PHONE_POOL_PREFIX)
    mid = "".join(str(rng.randint(0, 9)) for _ in range(3))
    tail = "".join(str(rng.randint(0, 9)) for _ in range(4))
    return f"{prefix}-{mid}-{tail}", []


def _person_faker(value: str, rng) -> tuple[str, list[str]]:
    """Fake person: chosen from a tiny pool, with a lowercase alias.

    The pool has only 3 names → deliberate collision risk that exercises the
    re-roll logic when the first choice is already in ``used``.
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
    _clear_faker_caches()
    yield
    for td in _CUSTOM_TYPES:
        unregister(td.lang, td.name)
    _clear_faker_caches()


# ---------------------------------------------------------------------------
# Curated (text, entities) scenarios
#
# Covers: single entity per custom type; multi-entity (same value twice →
# dedup); multiple types in one text; entity at start / end / middle; the
# alias-emitting type (person); the collision-prone 3-name pool; and the
# empty-entity-list base case.
# ---------------------------------------------------------------------------

_PHONE_VALUE = "415-555-9876"
_PERSON_VALUE = "Wang Fang"
_MRN_VALUE = "MRN-ORIG0001"

_SCENARIOS: list[tuple[str, list]] = [
    # 0: phone — middle of sentence
    (
        f"Call me at {_PHONE_VALUE} tomorrow.",
        [make_match(_PHONE_VALUE, "test_parity_phone", 11)],
    ),
    # 1: phone — at sentence start
    (
        f"{_PHONE_VALUE} is my number.",
        [make_match(_PHONE_VALUE, "test_parity_phone", 0)],
    ),
    # 2: phone — at sentence end (no trailing punctuation)
    (
        f"number is {_PHONE_VALUE}",
        [make_match(_PHONE_VALUE, "test_parity_phone", 10)],
    ),
    # 3: person — alias-emitting type
    (
        f"Contact {_PERSON_VALUE} for details.",
        [make_match(_PERSON_VALUE, "test_parity_person", 8)],
    ),
    # 4: person — two occurrences of same value (dedup path)
    (
        f"{_PERSON_VALUE} called {_PERSON_VALUE} again.",
        [
            make_match(_PERSON_VALUE, "test_parity_person", 0),
            make_match(_PERSON_VALUE, "test_parity_person", len(_PERSON_VALUE) + 8),
        ],
    ),
    # 5: medical — no aliases, pure hex output
    (
        f"Patient record: {_MRN_VALUE}.",
        [make_match(_MRN_VALUE, "test_parity_mrn", 16)],
    ),
    # 6: mixed: phone + person in same text
    (
        f"Call {_PERSON_VALUE} at {_PHONE_VALUE}.",
        [
            make_match(_PERSON_VALUE, "test_parity_person", 5),
            make_match(_PHONE_VALUE, "test_parity_phone", 5 + len(_PERSON_VALUE) + 4),
        ],
    ),
    # 7: mixed: all three types
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
    # 8: empty entity list → (text, {}, {}) with no error
    (
        "No PII here.",
        [],
    ),
]

# Fixed salts (named so the golden table is readable). Two distinct non-zero
# salts plus all-zero exercise full HMAC entropy without a fuzz loop.
_SALTS: dict[str, bytes] = {
    "00": b"\x00" * 32,
    "42": b"\x42" * 32,
    "ab": bytes.fromhex("ab") * 32,
}
# Two lang vectors: en-only and zh+en (lang-preference lookup).
_LANGS: dict[str, list[str]] = {
    "en": ["en"],
    "zhen": ["zh", "en"],
}

# ---------------------------------------------------------------------------
# Frozen goldens — captured from replace() (Rust-callback path), src build.
# Key: (scenario_idx, salt_name, lang_name) → (redacted, key, aliases).
# Dict equality is order-insensitive, so key-dict insertion order is irrelevant.
# ---------------------------------------------------------------------------

_GOLDEN: dict[tuple[int, str, str], tuple] = {
    (0, "00", "en"): ("Call me at 800-146-9612 tomorrow.", {"800-146-9612": _PHONE_VALUE}, {}),
    (0, "00", "zhen"): ("Call me at 800-146-9612 tomorrow.", {"800-146-9612": _PHONE_VALUE}, {}),
    (0, "42", "en"): ("Call me at 800-815-6779 tomorrow.", {"800-815-6779": _PHONE_VALUE}, {}),
    (0, "42", "zhen"): ("Call me at 800-815-6779 tomorrow.", {"800-815-6779": _PHONE_VALUE}, {}),
    (0, "ab", "en"): ("Call me at 888-613-7820 tomorrow.", {"888-613-7820": _PHONE_VALUE}, {}),
    (0, "ab", "zhen"): ("Call me at 888-613-7820 tomorrow.", {"888-613-7820": _PHONE_VALUE}, {}),
    (1, "00", "en"): ("800-146-9612 is my number.", {"800-146-9612": _PHONE_VALUE}, {}),
    (1, "00", "zhen"): ("800-146-9612 is my number.", {"800-146-9612": _PHONE_VALUE}, {}),
    (1, "42", "en"): ("800-815-6779 is my number.", {"800-815-6779": _PHONE_VALUE}, {}),
    (1, "42", "zhen"): ("800-815-6779 is my number.", {"800-815-6779": _PHONE_VALUE}, {}),
    (1, "ab", "en"): ("888-613-7820 is my number.", {"888-613-7820": _PHONE_VALUE}, {}),
    (1, "ab", "zhen"): ("888-613-7820 is my number.", {"888-613-7820": _PHONE_VALUE}, {}),
    (2, "00", "en"): ("number is 800-146-9612", {"800-146-9612": _PHONE_VALUE}, {}),
    (2, "00", "zhen"): ("number is 800-146-9612", {"800-146-9612": _PHONE_VALUE}, {}),
    (2, "42", "en"): ("number is 800-815-6779", {"800-815-6779": _PHONE_VALUE}, {}),
    (2, "42", "zhen"): ("number is 800-815-6779", {"800-815-6779": _PHONE_VALUE}, {}),
    (2, "ab", "en"): ("number is 888-613-7820", {"888-613-7820": _PHONE_VALUE}, {}),
    (2, "ab", "zhen"): ("number is 888-613-7820", {"888-613-7820": _PHONE_VALUE}, {}),
    (3, "00", "en"): (
        "Contact Alice for details.",
        {"Alice": _PERSON_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (3, "00", "zhen"): (
        "Contact Alice for details.",
        {"Alice": _PERSON_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (3, "42", "en"): (
        "Contact Alice for details.",
        {"Alice": _PERSON_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (3, "42", "zhen"): (
        "Contact Alice for details.",
        {"Alice": _PERSON_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (3, "ab", "en"): (
        "Contact Alice for details.",
        {"Alice": _PERSON_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (3, "ab", "zhen"): (
        "Contact Alice for details.",
        {"Alice": _PERSON_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (4, "00", "en"): (
        "Alice called Alice again.",
        {"Alice": _PERSON_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (4, "00", "zhen"): (
        "Alice called Alice again.",
        {"Alice": _PERSON_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (4, "42", "en"): (
        "Alice called Alice again.",
        {"Alice": _PERSON_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (4, "42", "zhen"): (
        "Alice called Alice again.",
        {"Alice": _PERSON_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (4, "ab", "en"): (
        "Alice called Alice again.",
        {"Alice": _PERSON_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (4, "ab", "zhen"): (
        "Alice called Alice again.",
        {"Alice": _PERSON_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (5, "00", "en"): ("Patient record: MRN-BE472253.", {"MRN-BE472253": _MRN_VALUE}, {}),
    (5, "00", "zhen"): ("Patient record: MRN-BE472253.", {"MRN-BE472253": _MRN_VALUE}, {}),
    (5, "42", "en"): ("Patient record: MRN-6F7045CE.", {"MRN-6F7045CE": _MRN_VALUE}, {}),
    (5, "42", "zhen"): ("Patient record: MRN-6F7045CE.", {"MRN-6F7045CE": _MRN_VALUE}, {}),
    (5, "ab", "en"): ("Patient record: MRN-CBEFABEC.", {"MRN-CBEFABEC": _MRN_VALUE}, {}),
    (5, "ab", "zhen"): ("Patient record: MRN-CBEFABEC.", {"MRN-CBEFABEC": _MRN_VALUE}, {}),
    (6, "00", "en"): (
        "Call Alice at 800-146-9612.",
        {"Alice": _PERSON_VALUE, "800-146-9612": _PHONE_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (6, "00", "zhen"): (
        "Call Alice at 800-146-9612.",
        {"Alice": _PERSON_VALUE, "800-146-9612": _PHONE_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (6, "42", "en"): (
        "Call Alice at 800-815-6779.",
        {"Alice": _PERSON_VALUE, "800-815-6779": _PHONE_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (6, "42", "zhen"): (
        "Call Alice at 800-815-6779.",
        {"Alice": _PERSON_VALUE, "800-815-6779": _PHONE_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (6, "ab", "en"): (
        "Call Alice at 888-613-7820.",
        {"Alice": _PERSON_VALUE, "888-613-7820": _PHONE_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (6, "ab", "zhen"): (
        "Call Alice at 888-613-7820.",
        {"Alice": _PERSON_VALUE, "888-613-7820": _PHONE_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (7, "00", "en"): (
        "Alice has MRN-BE472253 and phone 800-146-9612.",
        {"Alice": _PERSON_VALUE, "MRN-BE472253": _MRN_VALUE, "800-146-9612": _PHONE_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (7, "00", "zhen"): (
        "Alice has MRN-BE472253 and phone 800-146-9612.",
        {"Alice": _PERSON_VALUE, "MRN-BE472253": _MRN_VALUE, "800-146-9612": _PHONE_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (7, "42", "en"): (
        "Alice has MRN-6F7045CE and phone 800-815-6779.",
        {"Alice": _PERSON_VALUE, "MRN-6F7045CE": _MRN_VALUE, "800-815-6779": _PHONE_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (7, "42", "zhen"): (
        "Alice has MRN-6F7045CE and phone 800-815-6779.",
        {"Alice": _PERSON_VALUE, "MRN-6F7045CE": _MRN_VALUE, "800-815-6779": _PHONE_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (7, "ab", "en"): (
        "Alice has MRN-CBEFABEC and phone 888-613-7820.",
        {"Alice": _PERSON_VALUE, "MRN-CBEFABEC": _MRN_VALUE, "888-613-7820": _PHONE_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (7, "ab", "zhen"): (
        "Alice has MRN-CBEFABEC and phone 888-613-7820.",
        {"Alice": _PERSON_VALUE, "MRN-CBEFABEC": _MRN_VALUE, "888-613-7820": _PHONE_VALUE},
        {"Alice": ["alice_alias"]},
    ),
    (8, "00", "en"): ("No PII here.", {}, {}),
    (8, "00", "zhen"): ("No PII here.", {}, {}),
    (8, "42", "en"): ("No PII here.", {}, {}),
    (8, "42", "zhen"): ("No PII here.", {}, {}),
    (8, "ab", "en"): ("No PII here.", {}, {}),
    (8, "ab", "zhen"): ("No PII here.", {}, {}),
}


# ---------------------------------------------------------------------------
# Fixed-corpus golden (replaces the 840-case differential fuzz)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
@pytest.mark.parametrize("salt_name", list(_SALTS))
@pytest.mark.parametrize("lang_name", list(_LANGS))
@pytest.mark.parametrize("scenario_idx", range(len(_SCENARIOS)))
def test_custom_faker_callback_golden(scenario_idx: int, salt_name: str, lang_name: str):
    """replace() output through the custom-faker callback path is frozen.

    Exercises all curated scenarios (phone / person+aliases / MRN / multi /
    dedup / empty) across fixed salts and lang vectors. The custom fakers fire
    (phone digits, alias-emitting person, MRN hex) and the result must equal the
    pinned ``(redacted, key, aliases)`` golden.
    """
    text, entities = _SCENARIOS[scenario_idx]

    # Invariant from the original fuzz: every entity span must slice to its
    # own .text value. A bad offset corrupts redactions; catch it loudly.
    for ent in entities:
        assert text[ent.start : ent.end] == ent.text, (
            f"Scenario {scenario_idx}: entity {ent.type!r} span "
            f"[{ent.start}:{ent.end}] → {text[ent.start : ent.end]!r} != "
            f"{ent.text!r} in {text!r}"
        )

    config = {name: {"strategy": "realistic"} for name in _CUSTOM_NAMES}
    salt = _SALTS[salt_name]
    lang = _LANGS[lang_name]

    got = replace(text, entities, salt=salt, langs=lang, config=config)
    expected = _GOLDEN[(scenario_idx, salt_name, lang_name)]

    assert got == expected, (
        f"GOLDEN MISMATCH\n"
        f"  scenario_idx={scenario_idx} salt={salt_name} lang={lang_name}\n"
        f"  text={text!r}\n"
        f"  got      = {got!r}\n"
        f"  expected = {expected!r}\n"
        f"Regenerate the golden only if this change is intentional."
    )


# ---------------------------------------------------------------------------
# Targeted tests (new-path only)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_custom_faker_tuple_enforcement():
    """A faker that returns a bare string (not a tuple) must raise through replace()."""

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
    _clear_faker_caches()

    text = "bad BAD bad"
    entities = [make_match("BAD", "test_parity_bad_faker", 4)]
    config = {"test_parity_bad_faker": {"strategy": "realistic"}}

    try:
        with pytest.raises((TypeError, ValueError)):
            replace(text, entities, salt=b"x" * 32, config=config)
    finally:
        unregister("shared", "test_parity_bad_faker")
        _clear_faker_caches()


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_custom_faker_multi_lang_preference():
    """zh+en same-named type → replace() picks the lang-preferred variant.

    Register test_parity_lang_person for both zh and en with different fakers.
    With langs=["zh"] the zh variant must win; with langs=["en"], the en variant.
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
    _clear_faker_caches()

    text = "contact LiMing today"
    entities = [make_match("LiMing", "test_parity_lang_person", 8)]
    config = {"test_parity_lang_person": {"strategy": "realistic"}}
    salt = b"\x00" * 32

    try:
        redacted_zh, _, _ = replace(text, entities, salt=salt, langs=["zh"], config=config)
        assert "ZH-FAKE" in redacted_zh, f"Expected ZH-FAKE in redacted text, got {redacted_zh!r}"

        redacted_en, _, _ = replace(text, entities, salt=salt, langs=["en"], config=config)
        assert "EN-FAKE" in redacted_en, f"Expected EN-FAKE in redacted text, got {redacted_en!r}"
    finally:
        unregister("zh", "test_parity_lang_person")
        unregister("en", "test_parity_lang_person")
        _clear_faker_caches()


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_custom_faker_collision_reroll():
    """Pre-seeding the key with the faker's first output forces a re-roll.

    Compute the faker's attempt-0 output from the HMAC seed, pre-populate the
    key with it, then verify replace() re-rolls to a different unique fake.
    """
    import argus_redact._core as _core

    salt = b"\x42" * 32
    value = _PHONE_VALUE
    etype = "test_parity_phone"
    config = {etype: {"strategy": "realistic"}}

    # Attempt-0 output (same derivation the Rust re-roll loop uses internally).
    seed = _core.seed_from_value(value, etype, salt)
    rng = _core.ShakeRng(seed=seed)
    first_fake, _ = _phone_faker(value, rng)

    # Pre-populate the key with first_fake → forces a re-roll.
    pre_key = {first_fake: "some_other_original"}

    text = f"Call {value} please."
    entities = [make_match(value, etype, 5)]

    redacted, key, _ = replace(text, entities, salt=salt, key=pre_key.copy(), config=config)

    # The pre-seeded fake must still map to its original (untouched), and the
    # entity must have re-rolled to a *different* unique fake.
    assert key[first_fake] == "some_other_original"
    rerolled = next(k for k, v in key.items() if v == value)
    assert rerolled != first_fake, f"Re-roll must produce a different fake than {first_fake!r}"
    assert value not in redacted, f"Original must not appear in redacted text: {redacted!r}"


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_no_custom_uses_builtin_rust_path():
    """Built-in-only entities → empty custom_fakers → Rust path produces a valid triple."""
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
    assert isinstance(aliases, dict)


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_custom_faker_roundtrip():
    """restore() on a custom-faker-redacted text must return the original."""
    text = f"Patient {_MRN_VALUE} needs review."
    entities = [make_match(_MRN_VALUE, "test_parity_mrn", 8)]
    config = {"test_parity_mrn": {"strategy": "realistic"}}
    salt = b"\xde\xad" * 16

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

    restored = restore(redacted, key, guard=False)
    assert restored == text, f"restore() failed: expected {text!r}, got {restored!r}"
