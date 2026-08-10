"""Robustness + leak-closure tests for the structured (JSON / CSV) faces.

Each class pins one hardening the stateless-per-cell → session refactor left
open: a PII dict KEY that recursed only over values, a CSV cell over
``csv.field_size_limit()`` that crashed the shared parser, an uncaught
``RecursionError`` on a deeply-nested document, a numeric list-index path
selector that silently matched nothing, a numeric leaf that passed through
un-scanned, realistic-strategy aliases dropped on the restore face, and a
header PII probe that re-ran the full redact pipeline (re-warning + minting
discarded pseudonyms) per cell.
"""

import csv
import warnings

import pytest

from argus_redact import SecurityWarning
from argus_redact.structured import redact_csv, redact_json, restore_csv, restore_json

# A 32-byte salt sidesteps the low-entropy-salt SecurityWarning so a
# ``pytest.warns`` match= assertion pins the warning under test, not a
# vacuous pass on the unrelated salt warning.
_HI_SALT = bytes(range(32))


def _deep(n: int, leaf: str = "x") -> dict:
    """An ``n``-deep nested dict wrapping a single leaf value."""
    d: dict = {"v": leaf}
    for _ in range(n):
        d = {"k": d}
    return d


# ══════════════════════════════════════════════════════════════
# dict-KEY leak — a PII key is emitted verbatim (values-only recursion)
# ══════════════════════════════════════════════════════════════


class TestDictKeyLeak:
    def test_phone_number_dict_key_triggers_security_warning(self):
        data = {"13800138000": "some label"}
        with pytest.warns(SecurityWarning, match="key"):
            redact_json(data, mode="fast", lang="zh", salt=_HI_SALT)

    def test_pii_dict_key_is_preserved_verbatim(self):
        # Documented: keys are structural identifiers, preserved verbatim (like a
        # CSV header). The warning is the mitigation, not key-redaction.
        data = {"13800138000": "x"}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, mode="fast", lang="zh", salt=42)
        assert "13800138000" in out

    def test_ordinary_dict_key_does_not_warn(self):
        # Value carries PII (redacted) but the key "name" is not PII → no key
        # warning. Non-vacuity for the positive test above.
        data = {"name": "李四15900001234"}
        with warnings.catch_warnings(record=True) as rec:
            warnings.simplefilter("always")
            redact_json(data, mode="fast", lang="zh", salt=_HI_SALT)
        assert not [w for w in rec if "key" in str(w.message)]


# ══════════════════════════════════════════════════════════════
# CSV cell over csv.field_size_limit() — uncaught _csv.Error
# ══════════════════════════════════════════════════════════════


class TestCsvFieldSizeLimit:
    def test_redact_csv_handles_cell_over_field_size_limit(self):
        big = "a" * (csv.field_size_limit() + 100)
        csv_text = f"header\n{big}"
        redacted, key = redact_csv(csv_text, mode="fast", salt=42)
        assert big in redacted  # a huge non-PII cell survives, no crash

    def test_restore_csv_handles_cell_over_field_size_limit(self):
        big = "a" * (csv.field_size_limit() + 100)
        csv_text = f"header\n{big}"
        restored = restore_csv(csv_text, {})
        assert big in restored

    def test_field_size_limit_is_restored_after_parse(self):
        # The bump must be scoped to the parse, not leaked into the caller's
        # process-global csv state.
        before = csv.field_size_limit()
        redact_csv("header\nx", mode="fast", salt=42)
        assert csv.field_size_limit() == before


# ══════════════════════════════════════════════════════════════
# Deeply-nested JSON — uncaught RecursionError on both walks
# ══════════════════════════════════════════════════════════════


class TestDeepJsonRecursion:
    def test_redact_json_deep_raises_valueerror_not_recursionerror(self):
        with pytest.raises(ValueError, match="depth"):
            redact_json(_deep(1000), mode="fast", salt=42)

    def test_restore_json_deep_raises_valueerror_not_recursionerror(self):
        with pytest.raises(ValueError, match="depth"):
            restore_json(_deep(1000), {})

    def test_shallow_json_within_limit_still_redacts(self):
        redacted, key = redact_json(_deep(40, "手机13800138000"), mode="fast", salt=42)
        assert "13800138000" not in str(redacted)


# ══════════════════════════════════════════════════════════════
# paths scoping — numeric list index + zero-match warning
# ══════════════════════════════════════════════════════════════


class TestPathsNumericIndex:
    def test_numeric_list_index_path_redacts_leaf(self):
        data = {"users": [{"ssn": "110101199003074610"}]}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, paths=["users.0.ssn"], mode="fast", salt=42)
        assert "110101199003074610" not in str(out)
        assert len(key) == 1

    def test_numeric_index_matches_every_list_position(self):
        # A numeric index is treated as a wildcard (the walk carries "*" for all
        # list positions), so users.0.ssn redacts EVERY element's ssn. Documented
        # limitation — a specific index cannot be singled out.
        data = {"users": [{"ssn": "110101199003074610"}, {"ssn": "440524188001010014"}]}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, paths=["users.0.ssn"], mode="fast", salt=42)
        assert "110101199003074610" not in str(out)
        assert "440524188001010014" not in str(out)

    def test_paths_matching_numeric_leaf_with_pii_redacts_it(self):
        # A numeric JSON leaf can now be targeted by `paths=` too (v0.8.10):
        # matching it is not string-leaf-only.
        data = {"phone": 13800138000, "note": "no pii here"}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, paths=["phone"], mode="fast", lang="zh", salt=42)
        assert out["phone"] != 13800138000
        assert len(key) == 1

    def test_paths_targeting_numeric_leaf_does_not_false_positive_zero_match(self):
        # A `paths=` selector that DOES match a numeric leaf must not be reported
        # as a zero-match selector — the numeric branch must participate in the
        # same target-hit bookkeeping the string-leaf branch does.
        data = {"age": 30, "note": "手机13800138000"}
        with warnings.catch_warnings(record=True) as rec:
            warnings.simplefilter("always")
            redact_json(data, paths=["age"], mode="fast", lang="zh", salt=_HI_SALT)
        assert not [w for w in rec if "matched no" in str(w.message)]

    def test_segment_list_path_targets_a_dotted_key(self):
        # A caller-supplied path selector may be a pre-split list of segments
        # instead of a dot-notation string, so a key containing a literal "."
        # (unreachable via dot-notation) can still be targeted.
        data = {"a.b": "手机13800138000", "safe": "no pii here"}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, paths=[["a.b"]], mode="fast", lang="zh", salt=42)
        assert "13800138000" not in str(out["a.b"])
        assert out["safe"] == "no pii here"

    def test_zero_match_selector_warns_on_nonempty_subtree(self):
        data = {"name": "张三", "note": "手机13800138000"}
        with pytest.warns(SecurityWarning, match="matched no"):
            redact_json(data, paths=["nonexistent.field"], mode="fast", salt=_HI_SALT)

    def test_matching_selector_does_not_warn_zero_match(self):
        data = {"note": "手机13800138000"}
        with warnings.catch_warnings(record=True) as rec:
            warnings.simplefilter("always")
            redact_json(data, paths=["note"], mode="fast", salt=_HI_SALT)
        assert not [w for w in rec if "matched no" in str(w.message)]


# ══════════════════════════════════════════════════════════════
# numeric / bool / None leaves — string-only scope
# ══════════════════════════════════════════════════════════════


class TestNumericLeafScope:
    def test_numeric_leaf_with_pii_gets_redacted(self):
        # PREFERRED route (v0.8.10): a numeric JSON leaf (e.g. a phone/national-ID
        # stored as a JSON number, not a string) is coerced to str for DETECTION
        # and, when it carries PII, actually redacted — it no longer silently
        # passes through with only a warning.
        data = {"phone": 13800138000}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, mode="fast", lang="zh", salt=42)
        assert out["phone"] != 13800138000
        assert isinstance(out["phone"], str)
        assert "13800138000" not in out["phone"]
        assert len(key) == 1

    def test_numeric_leaf_redaction_round_trips_through_restore_json(self):
        data = {"phone": 13800138000}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, mode="fast", lang="zh", salt=42)
        restored = restore_json(out, key)
        # Restored as the coerced-to-str original — the redacted leaf legitimately
        # becomes a placeholder string, so restore gives back the string form.
        assert restored["phone"] == "13800138000"

    def test_numeric_leaf_with_pii_no_longer_emits_the_out_of_scope_warning(self):
        # Non-vacuity for the redaction above: the leak the old "numeric leaves
        # are out of scope" warning flagged is now closed by actually redacting,
        # so that warning must not fire.
        data = {"phone": 13800138000}
        with warnings.catch_warnings(record=True) as rec:
            warnings.simplefilter("always")
            redact_json(data, mode="fast", lang="zh", salt=_HI_SALT)
        assert not [w for w in rec if "numeric" in str(w.message)]

    def test_numeric_leaf_without_pii_preserves_int_type_and_value(self):
        data = {"age": 30}
        with warnings.catch_warnings(record=True) as rec:
            warnings.simplefilter("always")
            out, key = redact_json(data, mode="fast", lang="zh", salt=_HI_SALT)
        assert out["age"] == 30
        assert type(out["age"]) is int
        assert not [w for w in rec if "numeric" in str(w.message)]

    def test_numeric_leaf_without_pii_preserves_float_fidelity(self):
        data = {"score": 3.14159}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, mode="fast", lang="zh", salt=42)
        assert out["score"] == 3.14159
        assert type(out["score"]) is float

    def test_numeric_leaf_without_pii_preserves_large_int_fidelity(self):
        # Arbitrary-precision Python ints (beyond 64-bit range) must round-trip
        # byte-for-byte — the leaf is never actually coerced in the output, only
        # probed as a string for detection.
        big = 12345678901234567890123456789
        data = {"ref": big}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, mode="fast", lang="zh", salt=42)
        assert out["ref"] == big
        assert type(out["ref"]) is int

    def test_ordinary_numeric_and_bool_and_none_do_not_warn(self):
        data = {"age": 30, "active": True, "deleted": None}
        with warnings.catch_warnings(record=True) as rec:
            warnings.simplefilter("always")
            out, key = redact_json(data, mode="fast", lang="zh", salt=_HI_SALT)
        assert not [w for w in rec if "numeric" in str(w.message)]
        assert out == {"age": 30, "active": True, "deleted": None}


# ══════════════════════════════════════════════════════════════
# structured aliases — realistic-strategy alias survives restore
# ══════════════════════════════════════════════════════════════


class TestStructuredAliases:
    _CFG = {"person": {"strategy": "realistic"}}

    def _fake_and_alias(self, key, aliases, original):
        fake = next(f for f, o in key.items() if o == original)
        assert aliases.get(fake), "realistic person faker must emit aliases"
        return fake, aliases[fake][0]

    def test_realistic_alias_survives_structured_json_restore(self):
        data = {"note": "我叫张伟，请联系我"}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key, aliases = redact_json(
                data, mode="fast", lang="zh", salt=42, config=self._CFG, with_aliases=True
            )
        _fake, alias = self._fake_and_alias(key, aliases, "张伟")
        # An LLM rewrote the fake into its (pinyin) alias form.
        llm_out = {"reply": f"你好 {alias}"}
        restored = restore_json(llm_out, key, aliases=aliases)
        assert "张伟" in restored["reply"]

    def test_json_alias_is_not_restored_without_aliases(self):
        # Non-vacuity: the alias only round-trips because aliases were threaded.
        data = {"note": "我叫张伟，请联系我"}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key, aliases = redact_json(
                data, mode="fast", lang="zh", salt=42, config=self._CFG, with_aliases=True
            )
        _fake, alias = self._fake_and_alias(key, aliases, "张伟")
        restored = restore_json({"reply": f"你好 {alias}"}, key)
        assert "张伟" not in restored["reply"]

    def test_realistic_alias_survives_structured_csv_restore(self):
        csv_text = "note\n我叫张伟"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            redacted, key, aliases = redact_csv(
                csv_text, mode="fast", lang="zh", salt=42, config=self._CFG, with_aliases=True
            )
        _fake, alias = self._fake_and_alias(key, aliases, "张伟")
        restored = restore_csv(f"note\n你好{alias}", key, aliases=aliases)
        assert "张伟" in restored

    def test_with_aliases_is_opt_in_default_arity_unchanged(self):
        data = {"note": "我叫张伟"}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            assert len(redact_json(data, mode="fast", salt=42, config=self._CFG)) == 2
            assert (
                len(redact_json(data, mode="fast", salt=42, config=self._CFG, with_types=True)) == 3
            )
            assert (
                len(redact_json(data, mode="fast", salt=42, config=self._CFG, with_aliases=True))
                == 3
            )
            assert (
                len(
                    redact_json(
                        data,
                        mode="fast",
                        salt=42,
                        config=self._CFG,
                        with_types=True,
                        with_aliases=True,
                    )
                )
                == 4
            )


class TestStructuredAliasesRejection:
    """restore_json/restore_csv both build their session via
    `make_structured_restorer`, which funnels `aliases` through the shared
    `_normalize_aliases` seam — a malformed shape must raise ValueError
    before the document/CSV is ever walked, not silently corrupt it."""

    def test_restore_json_rejects_bare_string_alias_value(self):
        with pytest.raises(ValueError):
            restore_json({"note": "hello"}, {"P-1": "Alice"}, aliases={"P-1": "abc"})

    def test_restore_json_rejects_non_str_alias_element(self):
        with pytest.raises(ValueError):
            restore_json({"note": "hello"}, {"P-1": "Alice"}, aliases={"P-1": [123]})

    def test_restore_csv_rejects_bare_string_alias_value(self):
        with pytest.raises(ValueError):
            restore_csv("note\nhello", {"P-1": "Alice"}, aliases={"P-1": "abc"})

    def test_restore_csv_rejects_non_str_alias_element(self):
        with pytest.raises(ValueError):
            restore_csv("note\nhello", {"P-1": "Alice"}, aliases={"P-1": [123]})


# ══════════════════════════════════════════════════════════════
# header PII probe — detect-only, no re-warn / no discarded pseudonyms
# ══════════════════════════════════════════════════════════════


class TestHeaderProbeNoWaste:
    def test_header_probe_does_not_re_emit_low_entropy_salt_warning(self):
        # A PII header row (triggers the header warning) with a low-entropy salt.
        # Exactly ONE low-entropy-salt warning (the document-level one) must fire
        # — not one per header cell from a full redact() probe.
        csv_text = "张三,13812345678\n李四,15900001234"
        with warnings.catch_warnings(record=True) as rec:
            warnings.simplefilter("always")
            redact_csv(csv_text, mode="fast", salt=42, has_header=True)
        salt_warnings = [w for w in rec if "low-entropy salt" in str(w.message)]
        assert len(salt_warnings) == 1, f"probe re-emitted salt warnings: {len(salt_warnings)}"

    def test_header_probe_still_warns_when_header_carries_pii(self):
        csv_text = "张三,13812345678\n李四,15900001234"
        with pytest.warns(SecurityWarning, match="header"):
            redact_csv(csv_text, mode="fast", salt=_HI_SALT, has_header=True)
