"""Built-in fakers resolve callable-less via the `_core` association.

v0.7.5 Phase C / Task 11. Built-in `PIITypeDef`s no longer carry a
`faker_reserved=` callable; `_build_type_info` resolves the built-in
`faker_name` through `_core.builtin_faker_name(type, lang)`, driven by the
SAME Python lang-preference order `_resolve_realistic_faker` uses
(detected langs → "shared" → any registered). Custom adapters (a real
`faker_reserved` callable not in `_core.builtin_faker_names()`) are unchanged:
they still route through the Rust `PyFakerFactory` callback.

The lang-preference ORDER is the #1 bit-identity risk — a reorder silently
runs the wrong-language faker. These tests pin both the resolved `faker_name`
and the observable fake shape per language.
"""

from __future__ import annotations

import random

import argus_redact._core as _core

from argus_redact.pure.replacer import (
    _build_type_info,
    _clear_faker_caches,
    replace,
)
from argus_redact.specs import en as _en  # noqa: F401  ensure registration
from argus_redact.specs import shared as _shared  # noqa: F401
from argus_redact.specs import zh as _zh  # noqa: F401
from argus_redact.specs.registry import PIITypeDef, register, unregister
from tests.conftest import make_match


class TestBuiltinCallableLess:
    def test_builtin_phone_redacts_with_no_faker_reserved_on_registration(self):
        """zh/phone has `faker_reserved=None`; realistic redaction still fires,
        resolving the faker via `_core.builtin_faker_name`."""
        from argus_redact.specs.registry import get

        td = get("zh", "phone")
        assert td.faker_reserved is None, (
            "Built-in zh/phone must be callable-less (faker_reserved dropped)"
        )

        text = "请拨打 13912345678"
        entities = [make_match("13912345678", "phone", 4)]
        config = {"phone": {"strategy": "realistic"}}
        redacted, key, _ = replace(text, entities, config=config, salt=42, langs=["zh"])

        assert "13912345678" not in redacted
        fakes = list(key.keys())
        assert len(fakes) == 1
        # zh phone faker uses the 199-99 reserved prefix.
        assert fakes[0].startswith("19999"), f"Got {fakes[0]}"
        assert key[fakes[0]] == "13912345678"

    def test_build_type_info_resolves_builtin_faker_name(self):
        """`_build_type_info` populates `faker_name` from the `_core` association
        (not from any Python callable) and flags it built-in, not custom."""
        entities = [make_match("13912345678", "phone", 0)]
        config = {"phone": {"strategy": "realistic"}}
        info, custom = _build_type_info(entities, config, ["zh"])

        assert info["phone"]["faker_name"] == "fake_phone_reserved"
        assert info["phone"]["custom_faker"] is False
        assert "phone" not in custom


class TestLangPreferenceOrder:
    """`phone` is registered for both zh and en; the resolved built-in faker
    must follow detected-lang preference EXACTLY (the `_resolve_realistic_faker`
    order: detected langs → 'shared' → any registered)."""

    def test_faker_name_resolves_zh_for_zh_langs(self):
        info, _ = _build_type_info(
            [make_match("13912345678", "phone", 0)],
            {"phone": {"strategy": "realistic"}},
            ["zh"],
        )
        assert info["phone"]["faker_name"] == "fake_phone_reserved"
        # Cross-check the SSOT association directly.
        assert _core.builtin_faker_name("phone", "zh") == "fake_phone_reserved"

    def test_faker_name_resolves_en_for_en_langs(self):
        info, _ = _build_type_info(
            [make_match("(415) 555-1234", "phone", 0)],
            {"phone": {"strategy": "realistic"}},
            ["en"],
        )
        assert info["phone"]["faker_name"] == "fake_phone_en_reserved"
        assert _core.builtin_faker_name("phone", "en") == "fake_phone_en_reserved"

    def test_zh_langs_produce_zh_shaped_fake(self):
        text = "请拨打 13912345678"
        _, key, _ = replace(
            text,
            [make_match("13912345678", "phone", 4)],
            config={"phone": {"strategy": "realistic"}},
            salt=42,
            langs=["zh"],
        )
        fake = next(iter(key))
        assert fake.startswith("19999"), f"Expected zh phone shape, got {fake}"

    def test_en_langs_produce_en_shaped_fake(self):
        text = "call (415) 555-1234"
        _, key, _ = replace(
            text,
            [make_match("(415) 555-1234", "phone", 5)],
            config={"phone": {"strategy": "realistic"}},
            salt=42,
            langs=["en"],
        )
        fake = next(iter(key))
        # en phone faker uses the NANP 555-01XX reserved range.
        assert "(555)" in fake or "555-01" in fake, f"Expected en phone shape, got {fake}"


class TestCustomFakerStillRoutesViaCallback:
    """A custom `faker_reserved` callable (name NOT in `_core.builtin_faker_names()`)
    must still be flagged custom and dispatched via the Rust callback."""

    def setup_method(self):
        def _account_faker(value: str, rng: random.Random) -> tuple[str, list[str]]:
            digits = "".join(str(rng.randint(0, 9)) for _ in range(10))
            return "TEST-" + digits, []

        self._faker = _account_faker
        register(
            PIITypeDef(
                name="callable_less_test_account",
                lang="shared",
                format="ACC-NNNNNNNNNN",
                strategy="realistic",
                faker_reserved=_account_faker,
            )
        )
        _clear_faker_caches()

    def teardown_method(self):
        unregister("shared", "callable_less_test_account")
        _clear_faker_caches()

    def test_custom_type_flagged_custom_and_in_custom_fakers(self):
        entities = [make_match("ACC-9876543210", "callable_less_test_account", 0)]
        config = {"callable_less_test_account": {"strategy": "realistic"}}
        info, custom = _build_type_info(entities, config, ["en"])

        assert info["callable_less_test_account"]["custom_faker"] is True
        assert info["callable_less_test_account"]["faker_name"] is None
        assert custom["callable_less_test_account"] is self._faker

    def test_custom_type_redacts_via_callback(self):
        text = "Account number ACC-9876543210"
        start = text.index("ACC-9876543210")
        entities = [make_match("ACC-9876543210", "callable_less_test_account", start)]
        config = {"callable_less_test_account": {"strategy": "realistic"}}
        redacted, key, _ = replace(text, entities, config=config, salt=42, langs=["en"])

        assert "ACC-9876543210" not in redacted
        fake = next(iter(key))
        assert fake.startswith("TEST-"), f"Custom faker must run; got {fake}"
        assert key[fake] == "ACC-9876543210"
