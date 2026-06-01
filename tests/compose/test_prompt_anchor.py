"""compose.prompt_anchor tests — structural + snapshot."""
from __future__ import annotations

from argus_redact.compose import prompt_anchor


def test_empty_key_returns_empty_string():
    assert prompt_anchor({}, lang="zh") == ""
    assert prompt_anchor({}, lang="en") == ""


def test_zh_contains_3_rules_and_keyword_phrases():
    result = prompt_anchor({"P-83811": "黄芳", "138****5678": "13912345678"}, lang="zh")
    assert "完整保留" in result
    assert "不要替换为称谓" in result
    assert "不要主动猜测" in result
    assert "P-83811" in result
    assert "138****5678" in result


def test_en_contains_3_rules_and_keyword_phrases():
    result = prompt_anchor({"P-83811": "Huang Fang"}, lang="en")
    assert "Preserve these identifiers verbatim" in result
    assert "do not substitute with titles" in result
    assert "do not attempt to guess" in result.lower()
    assert "P-83811" in result


def test_unknown_lang_falls_back_to_en():
    result = prompt_anchor({"P-001": "X"}, lang="fr")
    assert "Preserve" in result  # EN template phrase


def test_identifiers_sorted_for_determinism():
    """Order matters for snapshot stability + downstream prompt-cache hits."""
    result = prompt_anchor({"P-99": "x", "P-01": "y", "MED-50": "z"}, lang="zh")
    # Sorted alphabetically: MED-50, P-01, P-99
    idx_med = result.find("MED-50")
    idx_p01 = result.find("P-01")
    idx_p99 = result.find("P-99")
    assert idx_med < idx_p01 < idx_p99


def test_zh_template_snapshot():
    """Lock the zh template text. Drift catches itself."""
    result = prompt_anchor({"P-001": "test"}, lang="zh")
    expected = (
        "以下对话中出现的标识符是脱敏占位符。请遵循三条规则：\n"
        "1. **完整保留**这些标识符 — 不要替换为称谓（如\"先生/女士/总\"），不要省略为缩写。\n"
        "2. 不要主动猜测或还原它们对应的真实身份。\n"
        "3. 标识符之间的语义关系可按上下文正常推理。\n"
        "\n"
        "脱敏标识符清单：\n"
        "  - P-001"
    )
    assert result == expected


def test_en_template_snapshot():
    """Lock the en template text. Drift catches itself."""
    result = prompt_anchor({"P-001": "test"}, lang="en")
    expected = (
        "The following identifiers are redaction placeholders. Please follow three rules:\n"
        "1. **Preserve these identifiers verbatim** — do not substitute with titles (e.g., \"Mr./Ms./Sir\"), do not abbreviate.\n"
        "2. Do not attempt to guess or restore their original identities.\n"
        "3. Reasoning about relationships between identifiers from context is fine.\n"
        "\n"
        "Redaction placeholder list:\n"
        "  - P-001"
    )
    assert result == expected
