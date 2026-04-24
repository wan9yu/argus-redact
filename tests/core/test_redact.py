"""Tests for redact() — the public API.

Organized by user concern, not implementation detail:
- Basic: core detection and roundtrip
- SelfReference: first-person pronoun handling (tiers 1-3)
- Grammar: English verb normalization after self-reference replacement
- Config: per-type strategy configuration
- Detailed: detailed=True metadata output
- MultiLanguage: mixed language detection
- NER: Layer 2 integration (mocked)
- Semantic: Layer 3 integration (mocked)
- Seed/Key/Mode/Errors: behavioral guarantees
"""

from unittest.mock import MagicMock, patch

import pytest
from argus_redact import redact, restore
from argus_redact._types import NEREntity
from argus_redact.impure.ner import NERAdapter

from tests.conftest import parametrize_examples


# ── Helpers ──


def _mock_ner_adapter(entity_map: dict[str, list[NEREntity]]):
    adapter = MagicMock(spec=NERAdapter)

    def detect(text):
        for key, entities in entity_map.items():
            if key in text:
                return entities
        return []

    adapter.detect.side_effect = detect
    return adapter


def _mock_semantic_adapter(entity_map: dict[str, list[NEREntity]]):
    adapter = MagicMock()

    def detect(text):
        for key, entities in entity_map.items():
            if key in text:
                return entities
        return []

    adapter.detect.side_effect = detect
    return adapter


# ══════════════════════════════════════════════════════════════
# Basic detection and roundtrip
# ══════════════════════════════════════════════════════════════


class TestRedactBasic:
    def test_should_remove_phone_when_text_contains_phone(self):
        redacted, key = redact("电话13812345678", seed=42, mode="fast")

        assert "13812345678" not in redacted
        assert "13812345678" in key.values()

    def test_should_remove_id_when_text_contains_id(self):
        redacted, key = redact("身份证110101199003074610", seed=42, mode="fast")

        assert "110101199003074610" not in redacted

    def test_should_remove_email_when_text_contains_email(self):
        redacted, key = redact("邮箱zhang@example.com", seed=42, mode="fast")

        assert "zhang@example.com" not in redacted

    def test_should_return_unchanged_when_no_pii(self):
        text = "今天天气不错"
        redacted, key = redact(text, seed=42, mode="fast")

        assert redacted == text
        assert key == {}

    def test_should_return_empty_when_text_is_empty(self):
        redacted, key = redact("", seed=42, mode="fast")

        assert redacted == ""
        assert key == {}

    def test_should_remove_all_when_multiple_pii_types(self):
        text = "电话13812345678，邮箱test@example.com"
        redacted, key = redact(text, seed=42, mode="fast")

        assert "13812345678" not in redacted
        assert "test@example.com" not in redacted
        assert len(key) == 2


class TestRedactRoundtrip:
    @parametrize_examples("redact_roundtrip.json")
    def test_should_recover_pii_when_redact_then_restore(self, example):
        original = example["input"]
        redacted, key = redact(original, seed=42, mode="fast")

        if example["pii_values"]:
            for pii in example["pii_values"]:
                assert pii not in redacted, f"PII '{pii}' still in redacted: {example['description']}"
            restored = restore(redacted, key)
            for pii in example["pii_values"]:
                assert pii in restored, f"PII '{pii}' not recovered: {example['description']}"
        else:
            assert redacted == original
            assert key == {}


# ══════════════════════════════════════════════════════════════
# Self-reference (first-person pronouns)
# ══════════════════════════════════════════════════════════════


class TestRedactSelfReference:
    """Tier 1: replace when other PII present. Tier 2: skip. Tier 3: ignore commands."""

    # Tier 1: with PII → replace
    def test_should_replace_wo_when_text_contains_pii_zh(self):
        redacted, key = redact("我确诊了糖尿病", seed=42, mode="fast")
        assert "我" not in redacted
        assert "我" in key.values()

    def test_should_replace_I_when_text_contains_pii_en(self):
        redacted, key = redact("I was diagnosed with diabetes", seed=42, mode="fast", lang="en")
        assert " I " not in redacted

    def test_should_roundtrip_when_self_reference_zh(self):
        original = "我在协和医院做了体检，医生说我血糖偏高"
        redacted, key = redact(original, seed=42, mode="fast")
        restored = restore(redacted, key)
        assert "我" not in redacted
        assert "我" in restored

    def test_should_roundtrip_when_kinship_zh(self):
        original = "我妈在301医院住院"
        redacted, key = redact(original, seed=42, mode="fast")
        restored = restore(redacted, key)
        assert "我妈" not in redacted
        assert "我妈" in restored

    def test_should_use_same_pseudonym_for_all_wo_in_text(self):
        redacted, key = redact("我去了医院，我很担心", seed=42, mode="fast")
        wo_codes = [code for code, val in key.items() if val == "我"]
        assert len(wo_codes) == 1

    # Tier 2: no PII → skip
    def test_should_not_replace_wo_when_no_pii_zh(self):
        redacted, key = redact("我觉得天气很好", seed=42, mode="fast")
        assert "我" in redacted
        assert key == {}

    def test_should_not_replace_I_when_no_pii_en(self):
        redacted, key = redact("I think this is a good plan", seed=42, mode="fast", lang="en")
        assert redacted.startswith("I ")
        assert key == {}

    def test_should_not_replace_women_when_no_pii_zh(self):
        redacted, key = redact("我们今天开会讨论一下", seed=42, mode="fast")
        assert "我们" in redacted

    # Tier 3: commands → ignore
    def test_should_ignore_wo_in_command_zh(self):
        redacted, key = redact("我想问一下怎么用Python", seed=42, mode="fast")
        assert "我" in redacted
        assert key == {}

    def test_should_ignore_I_in_command_en(self):
        redacted, key = redact("Can you help me with Python?", seed=42, mode="fast", lang="en")
        assert "me" in redacted

    # Kinship: always Tier 1
    def test_should_always_replace_kinship_zh(self):
        redacted, key = redact("我妈最近身体不好", seed=42, mode="fast")
        assert "我妈" not in redacted


class TestRedactSelfReferenceGrammar:
    """English grammar normalization after first-person replacement."""

    def test_should_fix_I_am_to_is(self):
        redacted, _ = redact("I am diagnosed with diabetes", seed=42, mode="fast", lang="en")
        assert " am " not in redacted
        assert " is " in redacted

    def test_should_fix_I_have_to_has(self):
        redacted, _ = redact("I have diabetes and hypertension", seed=42, mode="fast", lang="en")
        assert " have " not in redacted
        assert " has " in redacted

    def test_should_fix_Im_contraction(self):
        redacted, _ = redact("I'm diagnosed with diabetes", seed=42, mode="fast", lang="en")
        assert "'m " not in redacted

    def test_should_fix_I_was_stays_was(self):
        redacted, _ = redact("I was diagnosed with diabetes", seed=42, mode="fast", lang="en")
        assert " was " in redacted

    def test_should_not_change_grammar_for_zh(self):
        redacted, _ = redact("我很开心", seed=42, mode="fast")
        assert "很开心" in redacted

    def test_should_restore_grammar_on_roundtrip(self):
        original = "I'm feeling sick. I have diabetes."
        redacted, key = redact(original, seed=42, mode="fast", lang="en")
        restored = restore(redacted, key)
        assert "I have" in restored or "I'm" in restored


# ══════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════


class TestRedactConfig:
    @parametrize_examples("redact_config.json")
    def test_should_apply_config_when_provided(self, example):
        redacted, key = redact(
            example["input"], seed=42, mode="fast", config=example["config"],
        )
        assert example["entity_text"] not in redacted
        replacement = [k for k, v in key.items() if v == example["entity_text"]]
        assert len(replacement) == 1
        r = replacement[0]
        if "replacement_should_start_with" in example:
            assert r.startswith(example["replacement_should_start_with"])
        if "replacement_should_contain" in example:
            assert example["replacement_should_contain"] in r


class TestRedactConfigValidation:
    def test_should_raise_when_invalid_strategy(self):
        with pytest.raises(ValueError):
            redact("test", config={"phone": {"strategy": "invalid"}})

    def test_should_accept_none_config(self):
        redacted, key = redact("电话13812345678", seed=42, mode="fast", config=None)
        assert "13812345678" not in redacted

    def test_should_accept_dict_config(self):
        config = {"phone": {"strategy": "remove", "replacement": "[PHONE]"}}
        redacted, key = redact("电话13812345678", seed=42, mode="fast", config=config)
        assert "13812345678" not in redacted
        assert any("[PHONE]" in k for k in key)

    def test_should_roundtrip_with_config(self):
        config = {"phone": {"strategy": "remove", "replacement": "[PHONE]"}}
        text = "电话13812345678"
        redacted, key = redact(text, seed=42, mode="fast", config=config)
        restored = restore(redacted, key)
        assert "13812345678" in restored


# ══════════════════════════════════════════════════════════════
# Detailed mode
# ══════════════════════════════════════════════════════════════


class TestDetailedMode:
    def test_should_return_3_tuple_when_detailed_true(self):
        result = redact("电话13812345678", detailed=True, seed=42, mode="fast")
        assert len(result) == 3

    def test_should_return_2_tuple_when_detailed_false(self):
        result = redact("电话13812345678", seed=42, mode="fast")
        assert len(result) == 2

    def test_should_include_entities_in_details(self):
        _, _, details = redact("电话13812345678", detailed=True, seed=42, mode="fast")
        assert "entities" in details
        assert len(details["entities"]) >= 1

    def test_should_include_entity_fields(self):
        _, _, details = redact("电话13812345678", detailed=True, seed=42, mode="fast")
        entity = details["entities"][0]
        for field in ("original", "replacement", "type", "layer", "start", "end", "confidence"):
            assert field in entity

    def test_should_tag_regex_as_layer_1(self):
        _, _, details = redact("电话13812345678", detailed=True, seed=42, mode="fast")
        assert details["entities"][0]["layer"] == 1

    def test_should_include_layer_counts_in_stats(self):
        _, _, details = redact("电话13812345678", detailed=True, seed=42, mode="fast")
        stats = details["stats"]
        assert stats["layer_1"] >= 1
        assert stats["layer_2"] == 0
        assert stats["layer_3"] == 0

    def test_should_include_duration_ms_in_stats(self):
        _, _, details = redact("电话13812345678", detailed=True, seed=42, mode="fast")
        assert details["stats"]["duration_ms"] >= 0

    def test_should_show_correct_entity_info(self):
        _, key, details = redact("电话13812345678", detailed=True, seed=42, mode="fast")
        entity = details["entities"][0]
        assert entity["original"] == "13812345678"
        assert entity["replacement"] in key
        assert entity["type"] == "phone"

    def test_should_return_empty_entities_when_no_pii(self):
        _, _, details = redact("今天天气不错", detailed=True, seed=42, mode="fast")
        assert details["entities"] == []
        assert details["stats"]["total"] == 0

    def test_should_show_multiple_entities(self):
        _, _, details = redact("电话13812345678，邮箱test@example.com", detailed=True, seed=42, mode="fast")
        assert len(details["entities"]) == 2
        types = {e["type"] for e in details["entities"]}
        assert types == {"phone", "email"}


# ══════════════════════════════════════════════════════════════
# Multi-language
# ══════════════════════════════════════════════════════════════


class TestMultiLanguageRedact:
    @parametrize_examples("mixed_lang.json")
    def test_should_redact_and_restore_when_mixed_language(self, example):
        original = example["input"]
        lang = example.get("lang", ["zh", "en"])
        redacted, key = redact(original, seed=42, mode="fast", lang=lang)

        if example["pii_values"]:
            for pii in example["pii_values"]:
                assert pii not in redacted, f"PII '{pii}' still in redacted: {example['description']}"
            restored = restore(redacted, key)
            for pii in example["pii_values"]:
                assert pii in restored, f"PII '{pii}' not recovered: {example['description']}"
        else:
            assert redacted == original
            assert key == {}


class TestMixedLanguageSensitive:
    @parametrize_examples("mixed_zh_en_sensitive.json")
    def test_should_detect_in_mixed_text(self, example):
        text = example["input"]
        report = redact(text, lang=["zh", "en"], mode="fast", seed=42, report=True)
        detected_types = {e["type"] for e in report.entities}

        if example["should_match"]:
            assert example["type"] in detected_types, (
                f"Expected '{example['type']}' in {detected_types}: {example['description']}"
            )
        else:
            assert example["type"] not in detected_types, (
                f"Should NOT match '{example['type']}': {example['description']}"
            )

    @parametrize_examples("mixed_zh_en_sensitive.json")
    def test_should_roundtrip_when_mixed(self, example):
        if not example["should_match"]:
            return
        text = example["input"]
        redacted, key = redact(text, lang=["zh", "en"], mode="fast", seed=42)
        restored = restore(redacted, key)
        assert isinstance(restored, str)


# ══════════════════════════════════════════════════════════════
# NER integration (mocked)
# ══════════════════════════════════════════════════════════════


class TestRedactWithNER:
    def test_should_detect_person_name_when_ner_mode(self):
        adapter = _mock_ner_adapter({"张三": [NEREntity("张三", "person", 0, 2, 0.95)]})
        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact("张三去了北京", seed=42, mode="ner", lang="zh")
        assert "张三" not in redacted
        assert "张三" in key.values()

    def test_should_detect_person_name_when_auto_mode(self):
        adapter = _mock_ner_adapter({"张三": [NEREntity("张三", "person", 0, 2, 0.95)]})
        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact("张三去了北京", seed=42, mode="auto", lang="zh")
        assert "张三" not in redacted

    def test_should_skip_ner_when_fast_mode(self):
        adapter = _mock_ner_adapter({"张三": [NEREntity("张三", "person", 0, 2, 0.95)]})
        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact("张三去了北京", seed=42, mode="fast", lang="zh")
        assert "张三" in redacted
        adapter.detect.assert_not_called()

    def test_should_merge_ner_and_regex(self):
        adapter = _mock_ner_adapter({"张三": [NEREntity("张三", "person", 0, 2, 0.95)]})
        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact("张三的手机号是13812345678", seed=42, mode="ner", lang="zh")
        assert "张三" not in redacted
        assert "13812345678" not in redacted
        assert len(key) == 2

    def test_should_roundtrip_with_ner(self):
        adapter = _mock_ner_adapter({"张三": [NEREntity("张三", "person", 0, 2, 0.95)]})
        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact("张三说了话", seed=42, mode="ner", lang="zh")
        restored = restore(redacted, key)
        assert "张三" in restored


class TestMultiLanguageNER:
    def test_should_redact_chinese_name(self):
        adapter = _mock_ner_adapter({"张三": [NEREntity("张三", "person", 0, 2, 0.95)]})
        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact("张三在北京工作", seed=42, mode="ner", lang="zh")
        assert "张三" not in redacted
        assert restore(redacted, key) == "张三在北京工作"

    def test_should_redact_mixed_zh_en_names(self):
        adapter = _mock_ner_adapter({
            "张三": [NEREntity("张三", "person", 0, 2, 0.95), NEREntity("John", "person", 3, 7, 0.90)],
        })
        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact("张三和John在星巴克聊天", seed=42, mode="ner", lang=["zh", "en"])
        assert "张三" not in redacted
        assert "John" not in redacted
        restored = restore(redacted, key)
        assert "张三" in restored and "John" in restored

    def test_should_redact_three_language_names(self):
        adapter = _mock_ner_adapter({
            "张三": [
                NEREntity("张三", "person", 0, 2, 0.95),
                NEREntity("田中", "person", 3, 5, 0.90),
                NEREntity("김철수", "person", 6, 9, 0.88),
            ],
        })
        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact("张三和田中和김철수开会", seed=42, mode="ner", lang=["zh", "ja", "ko"])
        for name in ("张三", "田中", "김철수"):
            assert name not in redacted
        restored = restore(redacted, key)
        for name in ("张三", "田中", "김철수"):
            assert name in restored

    def test_should_keep_names_when_fast_mode(self):
        adapter = _mock_ner_adapter({"张三": [NEREntity("张三", "person", 0, 2, 0.95)]})
        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact("张三在北京工作", seed=42, mode="fast", lang="zh")
        assert "张三" in redacted
        adapter.detect.assert_not_called()


# ══════════════════════════════════════════════════════════════
# Semantic / Layer 3 (mocked)
# ══════════════════════════════════════════════════════════════


class TestRedactWithSemantic:
    def test_should_detect_implicit_pii_when_auto_mode(self):
        adapter = _mock_semantic_adapter({"那个地方": [NEREntity("那个地方", "location", 8, 12, 0.7)]})
        with patch("argus_redact.glue.redact._get_semantic_adapter", return_value=adapter):
            redacted, key = redact("老王说他上周在那个地方见了人", seed=42, mode="auto", lang="zh")
        assert "那个地方" not in redacted

    def test_should_skip_semantic_when_ner_mode(self):
        adapter = _mock_semantic_adapter({"那个地方": [NEREntity("那个地方", "location", 8, 12, 0.7)]})
        with patch("argus_redact.glue.redact._get_semantic_adapter", return_value=adapter):
            redacted, key = redact("老王说他上周在那个地方见了人", seed=42, mode="ner", lang="zh")
        assert "那个地方" in redacted
        adapter.detect.assert_not_called()

    def test_should_skip_semantic_when_fast_mode(self):
        adapter = _mock_semantic_adapter({"那个地方": [NEREntity("那个地方", "location", 8, 12, 0.7)]})
        with patch("argus_redact.glue.redact._get_semantic_adapter", return_value=adapter):
            redacted, key = redact("老王说他上周在那个地方见了人", seed=42, mode="fast", lang="zh")
        assert "那个地方" in redacted

    def test_should_merge_all_three_layers_when_auto(self):
        ner = MagicMock()
        ner.detect.return_value = [NEREntity("老王", "person", 0, 2, 0.85)]
        sem = _mock_semantic_adapter({"那个地方": [NEREntity("那个地方", "location", 8, 12, 0.7)]})
        with (
            patch("argus_redact.glue.redact._get_ner_adapters", return_value=[ner]),
            patch("argus_redact.glue.redact._get_semantic_adapter", return_value=sem),
        ):
            text = "老王说他上周在那个地方见了人，电话13812345678"
            redacted, key = redact(text, seed=42, mode="auto", lang="zh")
        for pii in ("老王", "那个地方", "13812345678"):
            assert pii not in redacted
        restored = restore(redacted, key)
        for pii in ("老王", "那个地方", "13812345678"):
            assert pii in restored

    def test_should_continue_when_semantic_fails(self):
        adapter = MagicMock()
        adapter.detect.side_effect = Exception("LLM timeout")
        with patch("argus_redact.glue.redact._get_semantic_adapter", return_value=adapter):
            redacted, key = redact("电话13812345678", seed=42, mode="auto", lang="zh")
        assert "13812345678" not in redacted


# ══════════════════════════════════════════════════════════════
# Behavioral guarantees
# ══════════════════════════════════════════════════════════════


class TestRedactSeedDeterminism:
    def test_should_produce_same_output_when_same_seed(self):
        text = "电话13812345678"
        r1 = redact(text, seed=42, mode="fast")
        r2 = redact(text, seed=42, mode="fast")
        assert r1 == r2


class TestRedactKeyReuse:
    def test_should_grow_key_when_new_entity(self):
        _, key = redact("电话13812345678", seed=42, mode="fast")
        size1 = len(key)
        _, key = redact("邮箱test@example.com", seed=42, mode="fast", key=key)
        assert len(key) > size1

    def test_should_keep_same_size_when_same_entity(self):
        _, key1 = redact("电话13812345678", seed=42, mode="fast")
        _, key2 = redact("再说一次13812345678", seed=42, mode="fast", key=key1)
        assert len(key2) == len(key1)


class TestRedactMode:
    def test_should_raise_when_invalid_mode(self):
        with pytest.raises(ValueError):
            redact("text", mode="invalid")

    def test_should_redact_when_fast_mode(self):
        redacted, key = redact("13812345678", seed=42, mode="fast")
        assert "13812345678" not in redacted

    def test_should_default_to_fast_mode(self):
        # English name is L2-NER only; default must NOT trigger a surprise NER load.
        redacted, key = redact("John Smith called me", seed=42, lang="en")
        assert "John Smith" in redacted
        assert key == {}


class TestRedactLangAuto:
    """End-to-end `redact(text, lang='auto')` routing via script detection."""

    def test_should_redact_chinese_when_auto_on_zh_text(self):
        # Pure zh text: auto detects zh, regex matches Chinese phone
        redacted, key = redact("客户的手机号是13812345678", seed=42, mode="fast", lang="auto")
        assert "13812345678" not in redacted

    def test_should_redact_shared_types_regardless_of_lang(self):
        # IBAN is a shared pattern, must be caught under lang="auto" (routes to en)
        text = "Transfer from DE89370400440532013000 received"
        redacted, key = redact(text, seed=42, mode="fast", lang="auto")
        assert "DE89370400440532013000" not in redacted

    def test_should_redact_both_when_mixed_zh_en(self):
        # Mixed text: phone (shared regex) + US passport-style would need specific langs
        text = "客户Apple公司的电话13812345678"
        redacted, key = redact(text, seed=42, mode="fast", lang="auto")
        assert "13812345678" not in redacted

    def test_should_not_crash_on_empty_text(self):
        redacted, key = redact("", seed=42, mode="fast", lang="auto")
        assert redacted == ""
        assert key == {}

    def test_should_not_crash_on_symbols_only(self):
        redacted, key = redact("!@#$%^&*()", seed=42, mode="fast", lang="auto")
        assert key == {}

    def test_should_detect_credentials_under_auto(self):
        # Credentials are shared types, auto must route properly regardless of lang
        text = "API_KEY=sk-ant-api03-FAKE0000000000000000000000000000abcdefghij"
        redacted, key = redact(text, seed=42, mode="fast", lang="auto")
        assert "sk-ant-api03-FAKE0000000000000000000000000000abcdefghij" not in redacted


class TestRedactTypeErrors:
    def test_should_raise_type_error_when_text_is_not_string(self):
        with pytest.raises(TypeError):
            redact(123)
