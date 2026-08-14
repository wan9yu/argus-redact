"""Identity-splice regression for ``redact_pseudonym_llm``'s unified key.

``redact_pseudonym_llm`` runs two replace passes over one detection: a realistic
pass (``downstream_text``/``downstream_key``, shown to the LLM) and an audit pass
(``audit_text``/``audit_key``, the compliance-archive placeholders). It returns a
single unified ``key`` that restore() consumes.

When more persons are detected than the realistic reserved-name pool holds
(zh ~13), the realistic pass falls back to bare ``P-NNNNN`` pseudonyms for the
tail. The audit pass historically emitted the SAME bare ``P-NNNNN`` codes, and a
blind ``{**key, **audit_key}`` union let the audit mapping OVERWRITE the realistic
one. A ``P-NNNNN`` code shown to the LLM then stood for person X while the unified
key mapped it to person Y, so restore() of the LLM reply spliced Y's real name
onto X's statement and X's name was lost — silently, with no warning.

Invariants pinned here:
- No code in the unified key maps to a different original than ``downstream_key``.
- restore(downstream_text, unified_key) recovers every real name.
- The same holds through ``StreamingRedactor.aggregate_key``.
"""

import pytest

from argus_redact import is_strategy_reversible, redact, restore
from argus_redact.glue.redact_pseudonym_llm import (
    PseudonymKeyCollisionError,
    _merge_pseudonym_keys,
    _put_key_checked,
    redact_pseudonym_llm,
)
from argus_redact.streaming import StreamingRedactor

# 16 distinct zh names — exceeds the ~13-name realistic reserved pool, forcing the
# realistic person pass into its bare ``P-NNNNN`` fallback for the tail names.
_NAMES = [
    "王小明",
    "赵华杰",
    "张三丰",
    "刘洋波",
    "陈明宇",
    "黄芳华",
    "孙悦然",
    "朱琳琳",
    "高翔宇",
    "林峰岩",
    "徐静怡",
    "马超群",
    "郭强生",
    "何丽娜",
    "邓艾青",
    "冯绍峰",
]
_TEXT = "。".join(f"客户{n}提出了问题" for n in _NAMES) + "。"


def test_unified_key_never_remaps_a_downstream_code():
    r = redact_pseudonym_llm(_TEXT, salt=5, lang="zh", mode="fast", _polluted_input_ok=True)
    remapped = {
        code: (original, r.key.get(code))
        for code, original in r.downstream_key.items()
        if r.key.get(code) != original
    }
    assert not remapped, (
        "unified key remapped LLM-facing codes to different originals "
        f"(identity splice): {remapped}"
    )


def test_restore_with_unified_key_recovers_every_name():
    r = redact_pseudonym_llm(_TEXT, salt=5, lang="zh", mode="fast", _polluted_input_ok=True)
    restored = restore(r.downstream_text, r.key, guard=False)
    missing = [n for n in _NAMES if n not in restored]
    assert not missing, f"restore lost real names via a unified-key collision: {missing}"


def test_audit_codes_are_bracketed_and_realistic_codes_are_not():
    # The disjointness guarantee: audit-face codes live in a bracketed namespace
    # ("[" ... "]"), realistic (LLM-facing) codes never contain "[". This is what
    # makes it structurally impossible for an audit code to equal a realistic
    # bare-P pool-exhaustion fallback and overwrite its restore mapping.
    r = redact_pseudonym_llm(_TEXT, salt=5, lang="zh", mode="fast", _polluted_input_ok=True)
    audit_only = {c: o for c, o in r.key.items() if c not in r.downstream_key}
    assert audit_only, "expected audit-space codes in the unified key"
    assert all(c.startswith("[") and c.endswith("]") for c in audit_only), (
        f"audit codes must be bracketed: {list(audit_only)[:5]}"
    )
    assert all("[" not in c for c in r.downstream_key), (
        "realistic (LLM-facing) codes must never be bracketed"
    )


def test_merge_pseudonym_keys_raises_on_hand_built_collision():
    # A code mapping to two different originals must fail loud, not silently drop.
    realistic = {"P-00001": "Alice", "Q-00002": "Bob"}
    audit = {"P-00001": "Carol"}  # same code, different original
    with pytest.raises(PseudonymKeyCollisionError) as exc:
        _merge_pseudonym_keys(realistic, audit)
    assert "P-00001" in str(exc.value)
    # The message must not leak the originals (PII).
    assert "Alice" not in str(exc.value) and "Carol" not in str(exc.value)


def test_merge_pseudonym_keys_tolerates_identical_remap():
    # The same code mapping to the SAME original in both keys is idempotent.
    merged = _merge_pseudonym_keys({"P-1": "Alice"}, {"P-1": "Alice", "[P-2]": "Alice"})
    assert merged == {"P-1": "Alice", "[P-2]": "Alice"}


def test_put_key_checked_raises_on_streaming_aggregate_collision():
    # The streaming aggregate uses the same primitive; a code already mapped to one
    # original must not be re-pointed at another.
    acc = {"P-9": "Alice"}
    _put_key_checked(acc, "P-9", "Alice")  # idempotent, no raise
    with pytest.raises(PseudonymKeyCollisionError):
        _put_key_checked(acc, "P-9", "Bob")


def test_streaming_aggregate_key_recovers_every_name():
    r = StreamingRedactor(salt=5, lang="zh", mode="fast", strict_input=False)
    r.feed(_TEXT)
    r.flush()
    agg = r.aggregate_key()
    # The chunk emit surfaces the realistic (LLM-facing) codes too; whatever the
    # stream emitted downstream must restore to the right original from the
    # aggregate key.
    out = StreamingRedactor(salt=5, lang="zh", mode="fast", strict_input=False)
    down = out.feed(_TEXT).downstream_text + out.flush().downstream_text
    restored = restore(down, agg, guard=False)
    missing = [n for n in _NAMES if n not in restored]
    assert not missing, f"streaming aggregate key lost real names: {missing}"


# ``remove_bracketed`` is the audit pass's INTERNAL strategy. It is dispatched by
# the core and used for the config argus builds itself, but it is deliberately
# NOT part of the public, user-selectable strategy surface — a user must not be
# able to reach the bracketed audit namespace via config / strategy_overrides.
def test_remove_bracketed_rejected_from_public_redact_config():
    with pytest.raises(ValueError) as exc:
        redact(
            "电话13800138000",
            config={"phone": {"strategy": "remove_bracketed"}},
            salt=1,
            lang="zh",
            mode="fast",
        )
    assert "remove_bracketed" in str(exc.value)
    assert "Unknown strategy" in str(exc.value)


def test_remove_bracketed_rejected_from_strategy_overrides():
    with pytest.raises(ValueError) as exc:
        redact_pseudonym_llm(
            "客户王建国来访",
            salt=5,
            lang="zh",
            mode="fast",
            names=["王建国"],
            strict_input=False,
            strategy_overrides={"person": "remove_bracketed"},
        )
    assert "remove_bracketed" in str(exc.value)


def test_remove_bracketed_absent_from_public_valid_strategies():
    # The public tuple a user's config is validated against must not list it.
    from argus_redact.pure.replacer import VALID_STRATEGIES

    assert "remove_bracketed" not in VALID_STRATEGIES


def test_remove_bracketed_still_classified_reversible():
    # Internal, but still classified (not "unclassified") so the reversibility
    # SSOT covers it; is_strategy_reversible must not raise on it.
    assert is_strategy_reversible("remove_bracketed") is True


def test_audit_pass_still_uses_remove_bracketed_end_to_end():
    # The audit face is unchanged by the visibility restriction: bracketed
    # placeholders, disjoint from the realistic codes, full restore.
    r = redact_pseudonym_llm(
        "客户王建国来访", salt=5, lang="zh", mode="fast", names=["王建国"], strict_input=False
    )
    audit_only = [c for c in r.key if c not in r.downstream_key]
    assert audit_only and all(c.startswith("[") and c.endswith("]") for c in audit_only)
    assert restore(r.downstream_text, r.key, guard=False) == "客户王建国来访"
