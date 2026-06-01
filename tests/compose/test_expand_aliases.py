"""compose.expand_aliases tests — structural + round-trip."""
from __future__ import annotations

from argus_redact.compose import expand_aliases


def test_empty_key_returns_empty_dict():
    assert expand_aliases({}, lang="zh") == {}
    assert expand_aliases({}, lang="en") == {}


def test_single_zh_person_expands_5_aliases():
    key = {"P-83811": "黄芳"}
    expanded = expand_aliases(key, lang="zh")
    # Original entry preserved
    assert expanded["P-83811"] == "黄芳"
    # 5 aliases: 黄先生 / 黄女士 / 黄总 / 黄老师 / 黄医生 — all map to "黄芳"
    assert expanded["黄先生"] == "黄芳"
    assert expanded["黄女士"] == "黄芳"
    assert expanded["黄总"] == "黄芳"
    assert expanded["黄老师"] == "黄芳"
    assert expanded["黄医生"] == "黄芳"
    # No other aliases added
    assert len(expanded) == 6  # 1 original + 5 aliases


def test_single_en_person_expands_5_aliases():
    key = {"P-83811": "John Brown"}
    expanded = expand_aliases(key, lang="en")
    assert expanded["P-83811"] == "John Brown"
    assert expanded["Mr. Brown"] == "John Brown"
    assert expanded["Mrs. Brown"] == "John Brown"
    assert expanded["Ms. Brown"] == "John Brown"
    assert expanded["Dr. Brown"] == "John Brown"
    assert expanded["Prof. Brown"] == "John Brown"
    assert len(expanded) == 6


def test_compound_zh_surname():
    """欧阳 / 司马 etc. — 2-char surname handled."""
    key = {"P-001": "欧阳锋"}
    expanded = expand_aliases(key, lang="zh")
    assert expanded["欧阳先生"] == "欧阳锋"
    assert expanded["欧阳总"] == "欧阳锋"
    # Single-char surname is NOT applied (otherwise "欧先生" would appear, which is wrong)
    assert "欧先生" not in expanded


def test_multi_token_en_with_trailing_initial():
    """John F. Smith → Smith (skip 'F.' single-letter initial)."""
    key = {"P-001": "John F. Smith"}
    expanded = expand_aliases(key, lang="en")
    assert expanded["Mr. Smith"] == "John F. Smith"
    assert expanded["Dr. Smith"] == "John F. Smith"
    # Should NOT generate "Mr. F." or "Mr. F"
    assert "Mr. F." not in expanded
    assert "Mr. F" not in expanded


def test_non_person_pseudonym_skipped():
    """MED-NNNNN / O-NNNNN / etc. — not expanded (no surname semantics)."""
    key = {"MED-001": "diabetes type 2", "O-002": "Acme Corp"}
    expanded = expand_aliases(key, lang="en")
    # Original entries preserved
    assert expanded["MED-001"] == "diabetes type 2"
    assert expanded["O-002"] == "Acme Corp"
    # No aliases generated
    assert len(expanded) == 2


def test_mixed_key_only_persons_expanded():
    """Mixed Person + non-Person — only Person entries generate aliases."""
    key = {
        "P-83811": "黄芳",
        "MED-001": "diabetes type 2",
        "138****5678": "13912345678",
    }
    expanded = expand_aliases(key, lang="zh")
    # Original entries preserved
    assert expanded["P-83811"] == "黄芳"
    assert expanded["MED-001"] == "diabetes type 2"
    assert expanded["138****5678"] == "13912345678"
    # Aliases only for the Person
    assert expanded["黄先生"] == "黄芳"
    # 3 originals + 5 aliases for 黄芳 = 8 entries
    assert len(expanded) == 8


def test_alias_collision_not_overwritten():
    """If alias already in key (rare), keep original mapping."""
    key = {
        "P-001": "黄芳",
        "黄先生": "EXISTING_VALUE",  # rare edge case
    }
    expanded = expand_aliases(key, lang="zh")
    # The existing "黄先生" entry is NOT overwritten
    assert expanded["黄先生"] == "EXISTING_VALUE"
    # Other aliases still added
    assert expanded["黄总"] == "黄芳"


def test_original_dict_not_mutated():
    """expand_aliases must return a new dict, leaving input untouched."""
    key = {"P-83811": "黄芳"}
    snapshot = dict(key)
    _ = expand_aliases(key, lang="zh")
    assert key == snapshot  # untouched


def test_identity_preservation_all_original_entries_kept():
    """Every (pseudonym → original) pair from input remains in output."""
    key = {
        "P-001": "张三",
        "P-002": "李四",
        "MED-001": "asthma",
    }
    expanded = expand_aliases(key, lang="zh")
    for pseudonym, original in key.items():
        assert expanded[pseudonym] == original


def test_unknown_lang_falls_back_to_en():
    """Unknown lang code uses EN titles."""
    key = {"P-001": "John Brown"}
    expanded = expand_aliases(key, lang="fr")
    assert "Mr. Brown" in expanded  # EN title was applied


def test_round_trip_restore_with_surname_title_in_llm_output():
    """End-to-end: simulated LLM emits "黄先生"; expanded key restores to "黄芳"."""
    from argus_redact import restore

    # Simulate what would come from a redact() call:
    # text = "黄芳的电话13912345678"
    # → redacted = "P-XXXXX的电话138****5678"
    # → key = {"P-XXXXX": "黄芳", "138****5678": "13912345678"}
    key = {"P-83811": "黄芳", "138****5678": "13912345678"}

    # LLM emits the surname+title form instead of the placeholder:
    llm_output = "你好黄先生，请确认 138****5678 这个号码"

    # Without expand_aliases: restore() can't reach "黄先生"
    restored_naive = restore(llm_output, key)
    assert "黄先生" in restored_naive  # NOT restored — naive restore fails

    # With expand_aliases: restore() resolves "黄先生" → "黄芳"
    expanded = expand_aliases(key, lang="zh")
    restored = restore(llm_output, expanded)
    assert "黄芳" in restored
    assert "黄先生" not in restored
    assert "13912345678" in restored
