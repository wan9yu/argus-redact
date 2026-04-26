"""Full integration tests with real HanLP NER + regex — slow, skip in CI.

Run with: pytest tests/impure/test_integration_ner.py -m ner -v
"""

import importlib.util

import pytest

from argus_redact import redact, restore

HAS_HANLP = importlib.util.find_spec("hanlp") is not None

pytestmark = pytest.mark.ner


@pytest.fixture(scope="module")
def _warm_up_model():
    """Load HanLP model once for the entire module."""
    if not HAS_HANLP:
        pytest.skip("hanlp not installed")
    redact("预热模型", mode="ner", seed=1, lang="zh")


class TestFullPipelineWithRealNER:
    """End-to-end: regex + real HanLP NER + merger + replacer + restore."""

    def test_should_redact_person_and_phone(self, _warm_up_model):
        text = "张三的手机号是13812345678"

        redacted, key = redact(text, seed=42, mode="ner", lang="zh")

        assert "张三" not in redacted
        assert "13812345678" not in redacted
        restored = restore(redacted, key)
        assert "张三" in restored
        assert "13812345678" in restored

    def test_should_redact_person_location_org(self, _warm_up_model):
        text = "王五在腾讯的深圳总部工作"

        redacted, key = redact(text, seed=42, mode="ner", lang="zh")

        assert "王五" not in redacted
        restored = restore(redacted, key)
        assert "王五" in restored

    def test_should_redact_multiple_persons(self, _warm_up_model):
        text = "张三和李四在星巴克讨论了去阿里面试的事"

        redacted, key = redact(text, seed=42, mode="ner", lang="zh")

        assert "张三" not in redacted
        assert "李四" not in redacted
        restored = restore(redacted, key)
        assert "张三" in restored
        assert "李四" in restored

    def test_should_redact_person_with_email_and_id(self, _warm_up_model):
        text = "张三的邮箱是zhang@test.com，身份证110101199003074610"

        redacted, key = redact(text, seed=42, mode="ner", lang="zh")

        assert "张三" not in redacted
        assert "zhang@test.com" not in redacted
        assert "110101199003074610" not in redacted
        restored = restore(redacted, key)
        assert "张三" in restored
        assert "zhang@test.com" in restored
        assert "110101199003074610" in restored

    def test_should_handle_dense_pii_paragraph(self, _warm_up_model):
        text = (
            "客户王五，手机13812345678，邮箱wang@corp.com，"
            "身份证110101199003074610，在阿里巴巴杭州总部工作"
        )

        redacted, key = redact(text, seed=42, mode="ner", lang="zh")

        assert "王五" not in redacted
        assert "13812345678" not in redacted
        assert "wang@corp.com" not in redacted
        assert "110101199003074610" not in redacted
        restored = restore(redacted, key)
        assert "王五" in restored
        assert "13812345678" in restored
        assert "wang@corp.com" in restored
        assert "110101199003074610" in restored

    def test_should_preserve_non_pii_text(self, _warm_up_model):
        text = "今天天气不错，适合出去散步"

        redacted, key = redact(text, seed=42, mode="ner", lang="zh")

        assert redacted == text or len(key) == 0

    def test_should_use_same_pseudonym_for_repeated_name(self, _warm_up_model):
        text = "张三很紧张，张三准备了很久"

        redacted, key = redact(text, seed=42, mode="ner", lang="zh")

        person_entries = {k: v for k, v in key.items() if v == "张三"}
        assert len(person_entries) == 1
        pseudonym = list(person_entries.keys())[0]
        assert redacted.count(pseudonym) == 2

    def test_should_support_key_reuse_across_calls(self, _warm_up_model):
        text1 = "张三去了北京"
        _, key = redact(text1, seed=42, mode="ner", lang="zh")

        text2 = "张三和李四在上海"
        redacted2, key = redact(text2, seed=42, mode="ner", lang="zh", key=key)

        assert "张三" not in redacted2
        assert "李四" not in redacted2
        assert len([v for v in key.values() if v == "张三"]) == 1
