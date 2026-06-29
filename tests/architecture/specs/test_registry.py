"""Tests for PII type registry — verify consistency with patterns and replacer."""

import pytest

from argus_redact.lang.zh.patterns import PATTERNS as ZH_PATTERNS
from argus_redact.specs import get, list_types, lookup
from argus_redact.specs import zh as _zh_import  # noqa: F401 — trigger registration
from tests.architecture.test_risk_data_parity import EXPECTED_TYPE_COUNT


class TestRegistryBasics:
    def test_should_have_zh_types_registered(self):
        zh_types = list_types("zh")
        names = {t.name for t in zh_types}
        assert "phone" in names
        assert "id_number" in names
        assert "bank_card" in names
        assert "passport" in names
        assert "license_plate" in names
        assert "address" in names
        assert "person" in names

    def test_should_get_by_lang_and_name(self):
        phone = get("zh", "phone")
        assert phone.name == "phone"
        assert phone.lang == "zh"
        assert phone.length == 11

    def test_should_lookup_across_languages(self):
        phones = lookup("phone")
        langs = {t.lang for t in phones}
        assert "zh" in langs

    def test_should_raise_on_unknown_type(self):
        import pytest

        with pytest.raises(KeyError):
            get("zh", "nonexistent")


class TestConsistencyWithPatterns:
    """Verify that specs match the actual patterns in lang/zh/patterns.py."""

    def test_every_pattern_type_has_a_spec(self):
        pattern_types = {p["type"] for p in ZH_PATTERNS}
        spec_types = {t.name for t in list_types("zh")}
        # phone_landline is separate in specs but uses "phone" type in patterns
        spec_types.add("phone")
        for ptype in pattern_types:
            assert ptype in spec_types, f"Pattern type '{ptype}' has no spec"

    def test_spec_label_matches_at_least_one_pattern_label(self):
        """Each spec label should appear in at least one pattern of the same type."""
        for typedef in list_types("zh"):
            if typedef.name == "phone_landline":
                continue
            pattern_labels = {p["label"] for p in ZH_PATTERNS if p["type"] == typedef.name}
            if pattern_labels:
                assert typedef.label in pattern_labels, (
                    f"Spec label '{typedef.label}' for {typedef.name} "
                    f"not found in pattern labels: {pattern_labels}"
                )

    @pytest.mark.parametrize("lang", ["zh", "en", "shared"])
    def test_typedef_strategy_is_runtime_ssot(self, lang):
        """v0.6.8: PIITypeDef.strategy is the runtime SSOT (DEFAULT_STRATEGIES
        is being deleted in C2). This test verifies replace() uses the typedef.

        Per-language coverage replaces the previous zh-only test.
        """
        from argus_redact._types import PatternMatch
        from argus_redact.pure.replacer import replace
        from argus_redact.specs.registry import list_types as _list_types

        for typedef in _list_types(lang):
            # Construct a minimal entity of this type
            text = "PII placeholder text"
            entity = PatternMatch(
                text="PII",
                type=typedef.name,
                start=0,
                end=3,
                confidence=1.0,
            )
            # Call replace() with no override config — should resolve strategy from typedef
            redacted, key, _ = replace(text, [entity], salt=42)

            # Loose invariant: typedef.strategy != "keep" should produce SOME
            # transformation (entity text changed OR key dict populated).
            # `keep` strategy is whitelist-only and leaves text unchanged.
            if typedef.strategy == "keep":
                # keep is only valid for self_reference types; if a non-self_reference
                # typedef has strategy=keep, that's an audit HIGH-6 issue, but here
                # we just verify it doesn't crash.
                pass
            else:
                assert "PII" not in redacted or len(key) > 0, (
                    f"[{lang}] {typedef.name} (strategy={typedef.strategy}): "
                    f"replace() didn't transform the entity. "
                    f"text={text!r} redacted={redacted!r} key={key!r}"
                )


class TestSpecExamples:
    """Verify that spec examples actually match our patterns."""

    def test_examples_should_match_patterns(self):
        from argus_redact.lang.shared.patterns import PATTERNS as SHARED
        from argus_redact.pure.patterns import match_patterns

        for typedef in list_types("zh"):
            if typedef.name in ("phone_landline", "person", "hobby"):
                # phone_landline has separate examples tested elsewhere
                # person names are detected by person.py, not by PATTERNS regex
                # hobby is framework-detected (evidence_detector), no regex —
                # validated by tests/core/test_hobby_detect.py
                continue
            for example in typedef.examples:
                results, _ = match_patterns(example, ZH_PATTERNS + SHARED)
                matched_types = {r.type for r in results}
                assert typedef.name in matched_types, (
                    f"Spec example '{example}' for {typedef.lang}/{typedef.name} "
                    f"did not match. Got types: {matched_types}"
                )

    def test_counterexamples_should_not_match(self):
        from argus_redact.lang.shared.patterns import PATTERNS as SHARED
        from argus_redact.pure.patterns import match_patterns

        for typedef in list_types("zh"):
            for counter in typedef.counterexamples:
                results, _ = match_patterns(counter, ZH_PATTERNS + SHARED)
                matched_types = {r.type for r in results}
                assert typedef.name not in matched_types, (
                    f"Spec counterexample '{counter}' for {typedef.lang}/{typedef.name} "
                    f"should NOT match but did"
                )


class TestSpecModuleCompleteness:
    """Guard: auto-discovery in specs/__init__.py covers every register()-calling module.

    With pkgutil.iter_modules any new specs/*.py that calls register() is
    automatically imported.  This test verifies (a) every register()-calling
    spec module is in the set the auto-discovery actually imports — so a bad
    exclusion rule that drops a module is caught immediately — and (b) the
    current type count is stable.
    """

    def test_every_register_module_is_discovered(self):
        """Every register()-calling spec module must be imported by the auto-discovery.

        ``register_modules`` is computed from the source text with a FIXED,
        independent exclusion set (``__init__``, ``_*``, ``gen_*``, and the
        ``registry`` module that DEFINES — not calls — register).  It is
        deliberately NOT coupled to the discovery's own ``_EXCLUDED_*`` rules:
        coupling them would let a wrong discovery exclusion shrink BOTH sides
        together and silently pass (the tautology this guard replaces).

        ``imported`` reuses the SAME ``_discover_spec_modules()`` helper that
        ``specs/__init__.py`` runs at import time.  So a future register()-
        module that a wrong discovery rule drops appears in ``register_modules``
        but NOT in ``imported`` → the subset assertion fails.
        """
        import re
        from pathlib import Path

        import argus_redact.specs as _specs_pkg
        from argus_redact.specs import _discover_spec_modules

        # Independent definition of "a type-registering spec module" — kept
        # separate from the discovery's exclusion constants on purpose.
        _IGNORE_PREFIXES = ("_", "gen_")
        _IGNORE_NAMES = frozenset({"__init__", "registry"})  # registry DEFINES register()
        # Match a register() CALL, not the `def register(` definition or
        # `unregister(` — avoids false positives from any module that only
        # mentions the symbol without calling it to register a type.
        _REGISTER_CALL = re.compile(r"(?<!un)(?<!def )register\s*\(")

        specs_dir = Path(_specs_pkg.__file__).parent
        register_modules = set()
        for py in sorted(specs_dir.glob("*.py")):
            stem = py.stem
            if stem in _IGNORE_NAMES:
                continue
            if any(stem.startswith(p) for p in _IGNORE_PREFIXES):
                continue
            if _REGISTER_CALL.search(py.read_text(encoding="utf-8")):
                register_modules.add(stem)

        # Sanity: the known type-registering modules must be detected (non-vacuous).
        assert {"zh", "en", "shared", "intl"} <= register_modules, (
            f"expected the canonical register-modules to be detected, "
            f"got {sorted(register_modules)}"
        )

        imported = set(_discover_spec_modules())
        missing = register_modules - imported
        assert not missing, (
            f"register()-calling spec module(s) NOT imported by auto-discovery: "
            f"{sorted(missing)} — these would silently never register their PII "
            f"types (silent type absence + understated coverage)"
        )

    def test_registered_type_count_matches_expected(self):
        """Type count must not drift from the frozen baseline in test_risk_data_parity.py.

        This mirrors the half-1 check in test_risk_data_parity.py but lives in
        the specs tests so it fails fast before the heavier parity check runs.
        """
        count = len(list_types())
        assert count == EXPECTED_TYPE_COUNT, (
            f"Expected {EXPECTED_TYPE_COUNT} registered PII types, got {count}. "
            f"A specs module may have been silently dropped or a new one added "
            f"without updating the frozen baseline in test_risk_data_parity.py."
        )


class TestRegistryStrategyValidity:
    """Guard: every registered type's strategy is a member of VALID_STRATEGIES.

    register() does not validate the strategy literal (unlike user-facing
    _validate_config). A typo (e.g. "pseudonum") would be silently accepted and
    then crash or no-op at runtime when replace() encounters it.
    """

    def test_all_registered_strategies_are_valid(self):
        from argus_redact.pure._strategy_kind import VALID_STRATEGIES

        invalid = [
            f"{td.lang}/{td.name}: strategy={td.strategy!r}"
            for td in list_types()
            if td.strategy not in VALID_STRATEGIES
        ]
        assert not invalid, f"Registered types with invalid strategy: {invalid}"


class TestSpecCompleteness:
    """Every spec should have minimum required fields."""

    def test_every_spec_has_examples(self):
        for typedef in list_types("zh"):
            assert len(typedef.examples) > 0, f"{typedef.lang}/{typedef.name} has no examples"

    def test_every_spec_has_description(self):
        for typedef in list_types("zh"):
            assert typedef.description, f"{typedef.lang}/{typedef.name} has no description"

    def test_every_spec_has_source(self):
        for typedef in list_types("zh"):
            assert typedef.source, f"{typedef.lang}/{typedef.name} has no source reference"

    def test_every_spec_has_label(self):
        for typedef in list_types("zh"):
            assert typedef.label, f"{typedef.lang}/{typedef.name} has no label"

    def test_every_spec_has_sensitivity(self):
        for typedef in list_types("zh"):
            assert hasattr(typedef, "sensitivity"), (
                f"{typedef.lang}/{typedef.name} has no sensitivity field"
            )
            assert typedef.sensitivity in (1, 2, 3, 4), (
                f"{typedef.lang}/{typedef.name} sensitivity={typedef.sensitivity} not in 1-4"
            )

    def test_critical_types_have_high_sensitivity(self):
        critical_types = {"id_number", "bank_card", "social_security"}
        for typedef in list_types("zh"):
            if typedef.name in critical_types:
                assert typedef.sensitivity == 4, (
                    f"{typedef.name} should be sensitivity=4 (critical), got {typedef.sensitivity}"
                )
