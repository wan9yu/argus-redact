"""Equivalence snapshot for structured (CSV / JSON) redaction.

Pins the exact redacted text AND key produced by ``redact_csv`` / ``redact_json``
on a document carrying both REPEATED and DISTINCT PII across cells/leaves (same
salt). The literal snapshots below were captured from the stateless per-cell
implementation; a refactor that keeps the accumulation key in Rust across cells
(one session instead of re-threading the growing key per cell) must reproduce
them byte-for-byte. Any drift here is an observable behaviour change.

The repeated-original assertions pin reverse-index reuse: the same phone in two
different cells/leaves must map to the SAME code (not a fresh dangling alias).

The classes above only ever draw ONE pseudonym per document (a single "person"
across all cells/leaves), which cannot distinguish a persisted-RNG session from
one that reseeds fresh per cell — both mint the same first code. The whole
byte-identity argument for the session refactor rests on the SECOND and later
draws matching a per-cell-reseeded reference too. `TestPersistedRngContinuation`
below pins that: two DISTINCT person names in separate cells/leaves, each
drawing a pseudonym from the SAME persisted generator in sequence, with the
second draw's literal code asserted.
"""

import warnings

from argus_redact import restore
from argus_redact.structured import redact_csv, redact_json, restore_csv, restore_json

# A high-salt-warning-free capture is not needed: salt=42 is deterministic and
# the low-entropy SecurityWarning is irrelevant to the mapping under test.

# ── CSV: repeated phone (cols "phone" + "note", row 1) + distinct PII (row 2) ──
_CSV_INPUT = (
    "name,phone,note\n张三,13812345678,电话13812345678\n李四,15900001234,身份证110101199003074610"
)
_CSV_REDACTED = (
    "name,phone,note\r\n张三,138****5678,电话138****5678\r\n李四,159****1234,身份证ID-03292"
)
_CSV_KEY = {
    "138****5678": "13812345678",
    "159****1234": "15900001234",
    "ID-03292": "110101199003074610",
}

# ── JSON: repeated phone ("a" + "b.c") + distinct PII across leaves ──
_JSON_INPUT = {
    "a": "电话13812345678",
    "b": {"c": "再次13812345678", "d": "身份证110101199003074610"},
    "e": ["邮箱foo@bar.com", "李四15900001234"],
    "f": 30,
}
_JSON_REDACTED = {
    "a": "电话138****5678",
    "b": {"c": "再次138****5678", "d": "身份证ID-03292"},
    "e": ["邮箱f***@bar.com", "P-83811159****1234"],
    "f": 30,
}
_JSON_KEY = {
    "138****5678": "13812345678",
    "159****1234": "15900001234",
    "ID-03292": "110101199003074610",
    "P-83811": "李四",
    "f***@bar.com": "foo@bar.com",
}

# ── JSON with_types ──
_JT_INPUT = {"phone": "手机13812345678", "id": "身份证110101199003074610"}
_JT_REDACTED = {"phone": "手机138****5678", "id": "身份证ID-03292"}
_JT_KEY = {"138****5678": "13812345678", "ID-03292": "110101199003074610"}
_JT_TYPES = {"138****5678": "phone", "ID-03292": "id_number"}


def _ignore_salt_warning():
    warnings.simplefilter("ignore")


class TestCsvEquivalence:
    def test_csv_redacted_text_and_key_byte_identical(self):
        with warnings.catch_warnings():
            _ignore_salt_warning()
            redacted, key = redact_csv(_CSV_INPUT, mode="fast", salt=42, has_header=True)
        assert redacted == _CSV_REDACTED
        assert key == _CSV_KEY

    def test_csv_repeated_original_reuses_same_code_across_cells(self):
        with warnings.catch_warnings():
            _ignore_salt_warning()
            redacted, key = redact_csv(_CSV_INPUT, mode="fast", salt=42, has_header=True)
        # 13812345678 appears in the "phone" cell and the "note" cell of row 1.
        # Exactly one key entry maps back to it, and its code appears twice.
        codes = [code for code, original in key.items() if original == "13812345678"]
        assert codes == ["138****5678"]
        assert redacted.count("138****5678") == 2


class TestJsonEquivalence:
    def test_json_redacted_text_and_key_byte_identical(self):
        with warnings.catch_warnings():
            _ignore_salt_warning()
            redacted, key = redact_json(_JSON_INPUT, mode="fast", salt=42)
        assert redacted == _JSON_REDACTED
        assert key == _JSON_KEY

    def test_json_repeated_original_reuses_same_code_across_leaves(self):
        with warnings.catch_warnings():
            _ignore_salt_warning()
            redacted, key = redact_json(_JSON_INPUT, mode="fast", salt=42)
        # 13812345678 appears in leaf "a" and leaf "b.c" → one code, reused.
        codes = [code for code, original in key.items() if original == "13812345678"]
        assert codes == ["138****5678"]
        assert redacted["a"].endswith("138****5678")
        assert redacted["b"]["c"].endswith("138****5678")


class TestJsonWithTypesEquivalence:
    def test_json_with_types_byte_identical(self):
        with warnings.catch_warnings():
            _ignore_salt_warning()
            redacted, key, types = redact_json(_JT_INPUT, mode="fast", salt=42, with_types=True)
        assert redacted == _JT_REDACTED
        assert key == _JT_KEY
        assert types == _JT_TYPES


# ── Persisted-RNG continuation: two DISTINCT persons, sequential draws ──
#
# Each cell/leaf pairs a person name with an adjacent phone number: the zh
# person detector needs a proximity signal (fast mode has no NER), so a bare
# name alone would not confirm. The phone match itself is incidental to this
# test — the crux is the two person codes.
_CRUX_CSV_INPUT = "note\n张三15900001111\n李四15900002222"
_CRUX_CSV_REDACTED = "note\r\nP-83811159****1111\r\nP-14593159****2222"
_CRUX_CSV_KEY = {
    "159****1111": "15900001111",
    "159****2222": "15900002222",
    "P-83811": "张三",
    "P-14593": "李四",
}

_CRUX_JSON_INPUT = {"a": "张三15900001111", "b": {"c": "李四15900002222"}}
_CRUX_JSON_REDACTED = {"a": "P-83811159****1111", "b": {"c": "P-14593159****2222"}}
_CRUX_JSON_KEY = {
    "P-83811": "张三",
    "P-14593": "李四",
    "159****1111": "15900001111",
    "159****2222": "15900002222",
}

# ── with_types: the SAME original repeated across two leaves must reuse the
# SAME code, and that code must map to a single type in the type map ──
_CRUX_JT_INPUT = {"x": "张三15900001111", "y": {"z": "张三15900001111"}}
_CRUX_JT_REDACTED = {"x": "P-83811159****1111", "y": {"z": "P-83811159****1111"}}
_CRUX_JT_KEY = {"159****1111": "15900001111", "P-83811": "张三"}
_CRUX_JT_TYPES = {"P-83811": "person", "159****1111": "phone"}


class TestPersistedRngContinuation:
    """Pins the SECOND (and later) draw from the persisted person generator.

    A generator re-seeded fresh per cell and preloaded from the growing key is
    provably identical to one whose RNG persists across cells (see the
    ``ReplaceSession`` byte-identity doc-comment in
    ``crates/argus-redact-core/src/replace.rs``) — but a test with only one
    person in the whole document can't tell the two apart: both mint the same
    first code regardless of which path is taken. These snapshots pin the
    SECOND draw (``P-14593`` for 李四, following ``P-83811`` for 张三), which is
    exactly what would regress if the persisted generator's RNG state ever
    diverged from the per-cell-reseeded reference.
    """

    def test_csv_two_persons_sequential_draws_pin_second_code(self):
        with warnings.catch_warnings():
            _ignore_salt_warning()
            redacted, key = redact_csv(
                _CRUX_CSV_INPUT, mode="fast", salt=42, has_header=True, lang="zh"
            )
        assert redacted == _CRUX_CSV_REDACTED
        assert key == _CRUX_CSV_KEY
        assert key["P-83811"] == "张三"
        assert key["P-14593"] == "李四"
        assert "P-83811" != "P-14593"
        restored = restore(redacted, key, guard=False)
        assert restored == _CRUX_CSV_INPUT.replace("\n", "\r\n")

    def test_json_two_persons_sequential_draws_pin_second_code(self):
        with warnings.catch_warnings():
            _ignore_salt_warning()
            redacted, key = redact_json(_CRUX_JSON_INPUT, mode="fast", salt=42, lang="zh")
        assert redacted == _CRUX_JSON_REDACTED
        assert key == _CRUX_JSON_KEY
        assert key["P-83811"] == "张三"
        assert key["P-14593"] == "李四"
        assert "P-83811" != "P-14593"
        restored_a = restore(redacted["a"], key, guard=False)
        restored_c = restore(redacted["b"]["c"], key, guard=False)
        assert restored_a == _CRUX_JSON_INPUT["a"]
        assert restored_c == _CRUX_JSON_INPUT["b"]["c"]

    def test_json_with_types_repeated_original_across_leaves_reuses_code(self):
        with warnings.catch_warnings():
            _ignore_salt_warning()
            redacted, key, types = redact_json(
                _CRUX_JT_INPUT, mode="fast", salt=42, lang="zh", with_types=True
            )
        assert redacted == _CRUX_JT_REDACTED
        assert key == _CRUX_JT_KEY
        assert types == _CRUX_JT_TYPES
        # The same original ("张三") in two leaves reuses the SAME code, which
        # maps to a single type entry (not two divergent ones).
        assert redacted["x"] == redacted["y"]["z"]
        assert types["P-83811"] == "person"


# ── Path-scoped JSON golden (the gateway wire-face shape) ──
#
# The gateway threads argus over provider payloads with a `paths=` selector so
# only the model-facing text leaves are redacted; every other leaf (a decoy no
# path selects) must survive verbatim. `probe-structured-parity.py` exercises
# all 24 gateway path patterns as a version-diff probe; this pins ONE
# representative scenario as a committed golden so a redacted-output / key /
# decoy-survival drift REDs a normal test run (the probe is not collected).
_PATH_INPUT = {
    "model": "gpt-4o",
    "system": "联系人王建国，电话13912345678",
    "messages": [
        {"role": "user", "content": "我叫李明明，手机13800138000"},
        {"role": "assistant", "content": "同事张伟"},
    ],
    "metadata": {"trace": "联系人赵敏13611136111"},
}
_PATH_REDACTED = {
    "model": "gpt-4o",
    "system": "联系人王建国，电话13912345678",  # decoy leaf: no path selects it
    "messages": [
        {"role": "user", "content": "我叫P-83811，手机138****8000"},
        {"role": "assistant", "content": "同事P-14593"},
    ],
    "metadata": {"trace": "联系人赵敏13611136111"},  # decoy leaf: no path selects it
}
_PATH_KEY = {
    "138****8000": "13800138000",
    "P-83811": "李明明",
    "P-14593": "张伟",
}


class TestPathScopedJsonGolden:
    def test_path_scoped_redaction_and_decoys_byte_identical(self):
        import copy

        with warnings.catch_warnings():
            _ignore_salt_warning()
            redacted, key = redact_json(
                copy.deepcopy(_PATH_INPUT),
                mode="fast",
                lang="zh",
                salt=42,
                paths=["messages[*].content"],
            )
        assert redacted == _PATH_REDACTED
        assert key == _PATH_KEY

    def test_path_scoped_roundtrip_restores_original(self):
        import copy

        with warnings.catch_warnings():
            _ignore_salt_warning()
            redacted, key = redact_json(
                copy.deepcopy(_PATH_INPUT),
                mode="fast",
                lang="zh",
                salt=42,
                paths=["messages[*].content"],
            )
        assert restore_json(copy.deepcopy(redacted), key) == _PATH_INPUT


# ── CSV round-trip through restore_csv ──
#
# The equivalence snapshots above restore CSV via the string `restore()`; the
# probe covers restore_json only. This pins the dedicated `restore_csv` face:
# parse → restore → reserialize reconstructs the data (line endings normalise to
# the writer's \r\n, so the round-trip target is the reserialized input).
_RT_CSV_INPUT = "name,phone\n张三,13812345678\n李四,15900001234"
_RT_CSV_REDACTED = "name,phone\r\n张三,138****5678\r\n李四,159****1234"
_RT_CSV_KEY = {"138****5678": "13812345678", "159****1234": "15900001234"}
_RT_CSV_RESTORED = "name,phone\r\n张三,13812345678\r\n李四,15900001234"


class TestCsvRestoreRoundTrip:
    def test_redact_then_restore_csv_reconstructs_data(self):
        with warnings.catch_warnings():
            _ignore_salt_warning()
            redacted, key = redact_csv(_RT_CSV_INPUT, mode="fast", lang="zh", salt=42)
        assert redacted == _RT_CSV_REDACTED
        assert key == _RT_CSV_KEY
        restored = restore_csv(redacted, key)
        assert restored == _RT_CSV_RESTORED
        # The reserialized restore equals the reserialized input (line endings
        # normalised to the csv writer's \r\n) — no cell lost or split.
        assert restored == _RT_CSV_INPUT.replace("\n", "\r\n")


# ── Cross-instance determinism ──
#
# Two independent calls with the same salt must produce byte-identical output
# AND key — the property the gateway relies on to reproduce a redaction (and to
# diff two argus versions with `probe-structured-parity.py`). Distinct from the
# equivalence snapshots (which pin absolute literals): this pins that the
# function is a pure function of (input, salt), holding across fresh sessions.
_DET_JSON = {"a": "李明明13800138000", "b": {"c": "张伟"}}
_DET_CSV = "name,phone\n张三,13812345678\n李四,15900001234"


class TestCrossInstanceDeterminism:
    def test_redact_json_is_deterministic_across_instances(self):
        import copy

        with warnings.catch_warnings():
            _ignore_salt_warning()
            r1, k1 = redact_json(copy.deepcopy(_DET_JSON), mode="fast", lang="zh", salt=42)
            r2, k2 = redact_json(copy.deepcopy(_DET_JSON), mode="fast", lang="zh", salt=42)
        assert r1 == r2
        assert k1 == k2

    def test_redact_csv_is_deterministic_across_instances(self):
        with warnings.catch_warnings():
            _ignore_salt_warning()
            r1, k1 = redact_csv(_DET_CSV, mode="fast", lang="zh", salt=42)
            r2, k2 = redact_csv(_DET_CSV, mode="fast", lang="zh", salt=42)
        assert r1 == r2
        assert k1 == k2
