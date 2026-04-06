"""Tests for names whitelist — user-provided names to always redact."""

from argus_redact import redact, restore


class TestNamesWhitelist:
    def test_should_redact_provided_name(self):
        redacted, key = redact(
            "你好王一，今天天气不错",
            names=["王一"],
            seed=42,
            mode="fast",
        )

        assert "王一" not in redacted
        assert "王一" in key.values()

    def test_should_redact_multiple_names(self):
        redacted, key = redact(
            "王一和张三在聊天",
            names=["王一", "张三"],
            seed=42,
            mode="fast",
        )

        assert "王一" not in redacted
        assert "张三" not in redacted

    def test_should_redact_name_and_phone_together(self):
        redacted, key = redact(
            "王一的手机号是18630303030",
            names=["王一"],
            seed=42,
            mode="fast",
        )

        assert "王一" not in redacted
        assert "18630303030" not in redacted
        assert len(key) == 2

    def test_should_roundtrip_with_names(self):
        original = "你好王一，你的手机号是18630303030"
        redacted, key = redact(
            original,
            names=["王一"],
            seed=42,
            mode="fast",
        )
        restored = restore(redacted, key)

        assert "王一" in restored
        assert "18630303030" in restored

    def test_should_use_pseudonym_for_names(self):
        redacted, key = redact(
            "王一在这里",
            names=["王一"],
            seed=42,
            mode="fast",
        )

        replacement = [k for k, v in key.items() if v == "王一"][0]
        assert replacement.startswith("P-")

    def test_should_handle_same_name_twice(self):
        redacted, key = redact(
            "王一说王一要去",
            names=["王一"],
            seed=42,
            mode="fast",
        )

        person_entries = [k for k, v in key.items() if v == "王一"]
        assert len(person_entries) == 1
        assert redacted.count(person_entries[0]) == 2

    def test_should_handle_empty_names_list(self):
        redacted, key = redact("你好王一", names=[], seed=42, mode="fast")

        assert redacted == "你好王一"

    def test_should_handle_no_names_parameter(self):
        redacted, key = redact("你好王一", seed=42, mode="fast")

        assert "王一" in redacted  # not detected without names or NER

    def test_should_work_with_english_names(self):
        redacted, key = redact(
            "Hello John Smith, your email is john@test.com",
            names=["John Smith"],
            seed=42,
            mode="fast",
            lang="en",
        )

        assert "John Smith" not in redacted
        assert "john@test.com" not in redacted

    def test_should_merge_with_regex_results(self):
        _, key = redact(
            "王一的身份证110101199003074610",
            names=["王一"],
            seed=42,
            mode="fast",
        )

        types_found = set()
        for k, v in key.items():
            if v == "王一":
                types_found.add("person")
            elif v == "110101199003074610":
                types_found.add("id_number")

        assert "person" in types_found
        assert "id_number" in types_found

    def test_should_combine_names_with_ner(self):
        """names + NER = 1+1>2: known names always hit, NER catches unknown."""
        from unittest.mock import MagicMock, patch

        from argus_redact._types import NEREntity

        # NER detects "李四" but not "王一"
        adapter = MagicMock()
        adapter.detect.return_value = [
            NEREntity("李四", "person", 3, 5, 0.9),
        ]

        with patch(
            "argus_redact.glue.redact._get_ner_adapters",
            return_value=[adapter],
        ):
            redacted, key = redact(
                "王一和李四的电话13812345678",
                names=["王一"],
                seed=42,
                mode="ner",
            )

        assert "王一" not in redacted
        assert "李四" not in redacted
        assert "13812345678" not in redacted
        assert len(key) == 3
