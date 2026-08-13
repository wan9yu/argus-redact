"""Leak-closure for non-str / non-int-float scalar leaves in redact_json.

Before this hardening, ``_walk`` scanned only ``str`` and ``int``/``float``
leaves; every OTHER scalar type (``Decimal`` from a SQL NUMERIC column or
``json.loads(..., parse_float=Decimal)``, ``bytes`` from msgpack ``raw=True`` /
BSON, ``UUID``) fell through a bare ``return obj`` — forwarded verbatim in
plaintext, un-scanned. Worse, because such a leaf never registered as a
"leaf seen", a ``paths=`` selector that matched nothing was ALSO wrongly
suppressed (the "matched no leaf" warning depends on a leaf having been seen).

These tests pin the fixed invariants: a coerce-and-scan path for the faithfully
str()-able scalars (Decimal / UUID) and a utf-8-decode-and-scan path for
bytes/bytearray, an ``un-scannable`` SecurityWarning for anything still
un-coercible, and symmetric decode-and-restore on ``restore_json``.
"""

import warnings
from decimal import Decimal
from uuid import UUID

import pytest

from argus_redact import SecurityWarning
from argus_redact.structured import redact_json, restore_json

# A 32-byte salt sidesteps the low-entropy-salt SecurityWarning so a
# ``pytest.warns`` match= assertion pins the warning under test.
_HI_SALT = bytes(range(32))


def _ignore_warnings():
    ctx = warnings.catch_warnings()
    ctx.__enter__()
    warnings.simplefilter("ignore")
    return ctx


# ══════════════════════════════════════════════════════════════
# Decimal leaf — coerce-and-scan via str(), same contract as int/float
# ══════════════════════════════════════════════════════════════


class TestDecimalLeaf:
    def test_decimal_leaf_with_pii_is_redacted_not_forwarded_verbatim(self):
        # A Decimal phone (every SQL NUMERIC column / parse_float=Decimal
        # produces one) must be scanned via str() and redacted, not forwarded
        # verbatim as a Decimal.
        data = {"phone": Decimal("13800138000")}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, mode="fast", lang="zh", salt=42)
        assert out["phone"] != Decimal("13800138000")
        assert isinstance(out["phone"], str)
        assert "13800138000" not in str(out["phone"])
        assert len(key) == 1

    def test_clean_decimal_leaf_round_trips_as_original_decimal(self):
        # Fidelity mirror of the int/float arm: a Decimal with no detectable PII
        # is NOT coerced to str — it round-trips byte-for-byte as the original
        # Decimal object (str is used only as the detection probe).
        data = {"amount": Decimal("19.99")}
        with warnings.catch_warnings(record=True) as rec:
            warnings.simplefilter("always")
            out, key = redact_json(data, mode="fast", lang="zh", salt=_HI_SALT)
        assert out["amount"] == Decimal("19.99")
        assert type(out["amount"]) is Decimal
        assert not [w for w in rec if "un-scannable" in str(w.message)]

    def test_redacted_decimal_leaf_round_trips_through_restore_json(self):
        data = {"phone": Decimal("13800138000")}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, mode="fast", lang="zh", salt=42)
        restored = restore_json(out, key)
        # The redacted leaf became a placeholder string, so restore gives back
        # the coerced-to-str original — coherent with the int/float contract.
        assert restored["phone"] == "13800138000"


# ══════════════════════════════════════════════════════════════
# UUID leaf — coerce-and-scan via str()
# ══════════════════════════════════════════════════════════════


class TestUuidLeaf:
    def test_clean_uuid_leaf_round_trips_as_original_uuid_without_unscannable_warning(self):
        # A UUID is scanned via str() (no detectable phone/ID PII in the
        # canonical form), so it round-trips as the original UUID and must NOT
        # be flagged as an un-scannable leaf.
        u = UUID("550e8400-e29b-41d4-a716-446655440000")
        data = {"trace": u}
        with warnings.catch_warnings(record=True) as rec:
            warnings.simplefilter("always")
            out, key = redact_json(data, mode="fast", lang="zh", salt=_HI_SALT)
        assert out["trace"] == u
        assert type(out["trace"]) is UUID
        assert not [w for w in rec if "un-scannable" in str(w.message)]


# ══════════════════════════════════════════════════════════════
# bytes / bytearray leaf — utf-8-decode-and-scan
# ══════════════════════════════════════════════════════════════


class TestBytesLeaf:
    def test_bytes_leaf_with_pii_is_redacted_not_forwarded_verbatim(self):
        # A national-ID stored as a byte string (msgpack raw=True / BSON) must
        # be utf-8-decoded, scanned, and redacted — not forwarded verbatim.
        data = {"id": b"110101199003074258"}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, mode="fast", lang="zh", salt=42)
        assert not isinstance(out["id"], (bytes, bytearray))
        assert isinstance(out["id"], str)
        assert "110101199003074258" not in out["id"]
        assert len(key) == 1

    def test_bytearray_leaf_with_pii_is_redacted(self):
        data = {"id": bytearray(b"110101199003074258")}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, mode="fast", lang="zh", salt=42)
        assert not isinstance(out["id"], (bytes, bytearray))
        assert "110101199003074258" not in str(out["id"])

    def test_clean_bytes_leaf_round_trips_as_original_bytes(self):
        data = {"blob": b"hello world"}
        with warnings.catch_warnings(record=True) as rec:
            warnings.simplefilter("always")
            out, key = redact_json(data, mode="fast", lang="zh", salt=_HI_SALT)
        assert out["blob"] == b"hello world"
        assert type(out["blob"]) is bytes
        assert not [w for w in rec if "un-scannable" in str(w.message)]

    def test_bytes_leaf_targeted_by_paths_is_redacted_not_leaked_with_empty_key(self):
        # The brief's second repro: redact_json({"a": b"<pii>"}, paths=["a"])
        # must redact (decode + scan the targeted leaf), never silently leak
        # with an empty key.
        data = {"a": b"13800138000"}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, paths=["a"], mode="fast", lang="zh", salt=42)
        assert "13800138000" not in str(out["a"])
        assert len(key) == 1

    def test_redacted_bytes_leaf_round_trips_through_restore_json(self):
        data = {"id": b"110101199003074258"}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, mode="fast", lang="zh", salt=42)
        restored = restore_json(out, key)
        assert restored["id"] == "110101199003074258"

    def test_restore_json_decodes_and_restores_a_placeholder_delivered_as_bytes(self):
        # Symmetric mirror: a placeholder that arrives at restore as a byte
        # string (a leaf re-serialized through msgpack raw=True) is decoded and
        # restored — before the fix restore_json returned bytes verbatim.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json({"note": "手机13800138000"}, mode="fast", lang="zh", salt=42)
        placeholder = out["note"]
        assert isinstance(placeholder, str)
        restored = restore_json({"note": placeholder.encode("utf-8")}, key)
        assert "13800138000" in str(restored["note"])

    def test_restore_json_passes_through_a_clean_byte_string_unchanged(self):
        # A byte string with no placeholder round-trips as the ORIGINAL bytes.
        assert restore_json({"blob": b"hello world"}, {"P-1": "Alice"})["blob"] == b"hello world"


# ══════════════════════════════════════════════════════════════
# un-scannable leaf — new warning class + selector-missed no longer suppressed
# ══════════════════════════════════════════════════════════════


class TestUnscannableLeaf:
    def test_arbitrary_object_leaf_emits_unscannable_security_warning(self):
        data = {"x": object()}
        with pytest.warns(SecurityWarning, match="un-scannable"):
            redact_json(data, mode="fast", lang="zh", salt=_HI_SALT)

    def test_non_decodable_bytes_leaf_emits_unscannable_warning_and_passes_through(self):
        data = {"x": b"\xff\xfe"}
        with pytest.warns(SecurityWarning, match="un-scannable"):
            out, key = redact_json(data, mode="fast", lang="zh", salt=_HI_SALT)
        assert out["x"] == b"\xff\xfe"

    def test_unscannable_leaf_no_longer_suppresses_selector_missed_warning(self):
        # The compound bug: an un-scannable leaf never registered as "leaf seen",
        # so a paths= selector that matched nothing was wrongly SUPPRESSED. Now
        # the leaf is seen, so the selector-missed warning fires.
        data = {"a": object()}
        with pytest.warns(SecurityWarning, match="matched no"):
            redact_json(data, paths=["nonexistent"], mode="fast", lang="zh", salt=_HI_SALT)

    def test_ordinary_numeric_bool_none_still_do_not_emit_unscannable_warning(self):
        # Non-vacuity: the new warning must not fire for the primitive leaves the
        # existing arms handle (None in particular is a benign JSON-null
        # passthrough, not an un-scannable leak).
        data = {"age": 30, "active": True, "deleted": None, "score": 1.5, "name": "no pii"}
        with warnings.catch_warnings(record=True) as rec:
            warnings.simplefilter("always")
            out, key = redact_json(data, mode="fast", lang="zh", salt=_HI_SALT)
        assert not [w for w in rec if "un-scannable" in str(w.message)]
        assert out["deleted"] is None


# ══════════════════════════════════════════════════════════════
# The brief's combined repro — Decimal + bytes leak beside int forms
# ══════════════════════════════════════════════════════════════


class TestBriefCombinedRepro:
    def test_decimal_and_bytes_pii_redacted_beside_the_int_forms(self):
        data = {
            "phone": Decimal("13800138000"),
            "id": b"110101199003074258",
            "phone_ok": 13800138000,
            "idc": 110101199003074258,
        }
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out, key = redact_json(data, lang="zh", mode="fast", salt=42)
        blob = repr(out)
        assert "13800138000" not in blob
        assert "110101199003074258" not in blob
        assert not isinstance(out["phone"], Decimal)
        assert not isinstance(out["id"], (bytes, bytearray))
