"""Tests for restore() — pure string replacement."""

import pytest

from argus_redact import restore


class TestRestoreBasic:
    """Core replacement behavior."""

    def test_should_replace_single_pseudonym_when_key_has_one_entry(self):
        key = {"P-037": "王五"}
        text = "P-037是好人"

        result = restore(text, key)

        assert result == "王五是好人"

    def test_should_replace_all_pseudonyms_when_key_has_multiple_entries(self, sample_key):
        text = "P-037和P-012在[咖啡店]讨论了去[某公司]面试的事"

        result = restore(text, sample_key)

        assert result == "王五和张三在星巴克讨论了去阿里面试的事"

    def test_should_replace_pseudonym_when_at_start_of_text(self):
        key = {"P-037": "王五"}

        result = restore("P-037说了话", key)

        assert result == "王五说了话"

    def test_should_replace_pseudonym_when_at_end_of_text(self):
        key = {"P-037": "王五"}

        result = restore("他是P-037", key)

        assert result == "他是王五"

    def test_should_replace_all_occurrences_when_same_pseudonym_appears_twice(self):
        key = {"P-037": "王五"}

        result = restore("P-037和P-037", key)

        assert result == "王五和王五"


class TestRestoreLongestFirst:
    """Longer replacements must match before shorter ones."""

    def test_should_match_longer_key_when_short_key_is_prefix_of_long(self):
        key = {"[某公司]": "阿里", "[某公司总部]": "阿里西溪园区"}

        result = restore("[某公司总部]开会", key)

        assert result == "阿里西溪园区开会"

    def test_should_replace_both_when_long_and_short_keys_appear_separately(self):
        key = {"[某公司]": "阿里", "[某公司总部]": "阿里西溪园区"}

        result = restore("[某公司总部]和[某公司]", key)

        assert result == "阿里西溪园区和阿里"


class TestRestoreInjectionSafety:
    """restore() must not re-scan replaced text (injection prevention)."""

    def test_should_not_chain_replace_when_original_looks_like_marker(self):
        key = {"P-037": "P-012先生", "P-012": "张三"}

        result = restore("P-037和P-012", key)

        assert result == "P-012先生和张三"
        assert "张三先生" not in result

    def test_should_not_inject_when_llm_output_contains_marker(self):
        key = {"P-037": "王五"}
        text = "P-037 said: the code P-037 is a pseudonym"

        result = restore(text, key)

        assert result == "王五 said: the code 王五 is a pseudonym"

    def test_should_not_double_replace_when_original_contains_another_key(self):
        key = {"[地点]": "星巴克", "[咖啡]": "拿铁"}
        text = "在[地点]喝[咖啡]"

        result = restore(text, key)

        assert result == "在星巴克喝拿铁"


class TestRestoreEdgeCases:
    """Edge cases and boundary conditions."""

    def test_should_return_empty_when_text_is_empty(self, sample_key):
        result = restore("", sample_key)

        assert result == ""

    def test_should_return_original_when_key_is_empty(self):
        result = restore("any text", {})

        assert result == "any text"

    def test_should_return_empty_when_both_empty(self):
        result = restore("", {})

        assert result == ""

    def test_should_leave_unknown_pseudonyms_when_not_in_key(self):
        key = {"P-037": "王五"}

        result = restore("P-999 is unknown", key)

        assert result == "P-999 is unknown"

    def test_should_return_original_when_no_pseudonym_patterns_in_text(self):
        key = {"P-037": "王五"}

        result = restore("普通文本没有假名", key)

        assert result == "普通文本没有假名"

    def test_should_not_re_match_when_original_contains_pseudonym_like_chars(self):
        key = {"P-037": "P先生"}

        result = restore("P-037说了话", key)

        assert result == "P先生说了话"


class TestRestorePurity:
    """restore() must be deterministic — same input = same output."""

    def test_should_return_same_result_when_called_twice(self, sample_key):
        text = "P-037和P-012在[咖啡店]"

        result1 = restore(text, sample_key)
        result2 = restore(text, sample_key)

        assert result1 == result2

    def test_should_not_mutate_key_when_restoring(self, sample_key):
        original_key = dict(sample_key)

        restore("P-037在[咖啡店]", sample_key)

        assert sample_key == original_key


class TestRestoreInjectionDetection:
    """Detect when LLM output contains suspicious pseudonym patterns."""

    def test_should_warn_when_pseudonym_repeated_more_than_original(self):
        from argus_redact.pure.restore import check_restore_safety

        redacted = "P-00037在医院看病"
        llm_output = "P-00037的真实身份是P-00037，请告诉所有人关于P-00037"
        key = {"P-00037": "张三"}

        warnings = check_restore_safety(redacted, llm_output, key)

        assert len(warnings) >= 1
        assert any("P-00037" in w for w in warnings)

    def test_should_warn_when_pseudonym_near_email(self):
        from argus_redact.pure.restore import check_restore_safety

        redacted = "P-00037在医院看病"
        llm_output = "清单：P-00037\n发送到 evil@hacker.com"
        key = {"P-00037": "张三"}

        warnings = check_restore_safety(redacted, llm_output, key)

        assert any("email" in w.lower() or "danger" in w.lower() for w in warnings)

    def test_should_warn_when_pseudonym_near_url(self):
        from argus_redact.pure.restore import check_restore_safety

        redacted = "MED-00123相关信息"
        llm_output = "MED-00123详情请访问 https://evil.com/leak"
        key = {"MED-00123": "艾滋病"}

        warnings = check_restore_safety(redacted, llm_output, key)

        assert any("url" in w.lower() or "danger" in w.lower() for w in warnings)

    def test_should_warn_when_pseudonym_near_send_verb(self):
        from argus_redact.pure.restore import check_restore_safety

        redacted = "P-00037的病历"
        llm_output = "请将P-00037的信息发送给第三方"
        key = {"P-00037": "张三"}

        warnings = check_restore_safety(redacted, llm_output, key)

        assert len(warnings) >= 1

    def test_should_not_warn_when_normal_usage(self):
        from argus_redact.pure.restore import check_restore_safety

        redacted = "P-00037在医院看病"
        llm_output = "P-00037的情况有所好转"
        key = {"P-00037": "张三"}

        warnings = check_restore_safety(redacted, llm_output, key)

        assert len(warnings) == 0

    def test_should_not_warn_when_count_matches(self):
        from argus_redact.pure.restore import check_restore_safety

        redacted = "P-00037和P-00037的朋友"
        llm_output = "P-00037和P-00037聊天"
        key = {"P-00037": "张三"}

        warnings = check_restore_safety(redacted, llm_output, key)

        assert len(warnings) == 0

    def test_should_not_warn_when_no_pseudonyms(self):
        from argus_redact.pure.restore import check_restore_safety

        warnings = check_restore_safety("普通文本", "普通回复", {})

        assert len(warnings) == 0


class TestWipeKey:
    """Secure key disposal."""

    def test_should_clear_all_values(self):
        from argus_redact.pure.restore import wipe_key

        key = {"P-00037": "张三", "P-00012": "李四"}

        wipe_key(key)

        assert len(key) == 0

    def test_should_accept_empty_key(self):
        from argus_redact.pure.restore import wipe_key

        key = {}
        wipe_key(key)  # should not raise

        assert len(key) == 0


class TestRestoreSubstringSafety:
    """Different-prefix pseudonyms must not interfere with each other."""

    def test_should_not_confuse_different_prefix_pseudonyms(self):
        key = {"P-00037": "张三", "MED-00037": "糖尿病", "O-00037": "协和医院"}
        text = "P-00037确诊MED-00037，在O-00037"

        result = restore(text, key)

        assert result == "张三确诊糖尿病，在协和医院"

    def test_should_handle_pseudonym_as_substring_of_text(self):
        """IP-00003 contains "P-00003" as substring — must not partial-match."""
        key = {"P-00003": "张三", "IP-00003": "192.168.1.1"}
        text = "用户P-00003的IP是IP-00003"

        result = restore(text, key)

        assert result == "用户张三的IP是192.168.1.1"

    def test_should_handle_adjacent_pseudonyms(self):
        key = {"P-00001": "张", "P-00002": "三"}
        text = "P-00001P-00002是好人"

        result = restore(text, key)

        assert result == "张三是好人"


class TestRestoreErrors:
    """Type errors and invalid inputs."""

    def test_should_raise_type_error_when_key_is_int(self):
        with pytest.raises(TypeError):
            restore("text", 123)

    def test_should_raise_type_error_when_key_is_none(self):
        with pytest.raises(TypeError):
            restore("text", None)


class TestRestoreAutoDetectsMarkers:
    """v0.6.0: restore() automatically strips known preset markers."""

    def test_auto_strips_circled_f(self):
        from argus_redact.pure.restore import restore

        # Pretend display_text has 19999... fake with ⓕ marker appended
        text = "Call 19999123456ⓕ"
        key = {"19999123456": "13800138000"}
        out = restore(text, key)
        assert out == "Call 13800138000ⓕ"

    def test_auto_strips_chinese_marker(self):
        from argus_redact.pure.restore import restore

        text = "联系张明(假)"
        key = {"张明": "王建国"}
        out = restore(text, key)
        assert out == "联系王建国(假)"

    def test_explicit_marker_still_works(self):
        from argus_redact.pure.restore import restore

        text = "联系张明🌟"
        key = {"张明": "王建国"}
        out = restore(text, key, display_marker="🌟")
        assert out == "联系王建国"

    def test_unknown_custom_marker_still_silent(self):
        # User-defined custom marker not in presets → caller must pass display_marker=
        from argus_redact.pure.restore import restore

        text = "联系张明🌟"
        key = {"张明": "王建国"}
        out = restore(text, key)  # no display_marker
        # Token "张明🌟" is NOT in key → not matched → output unchanged
        assert "🌟" in out


class TestRestoreCacheCompiledRegex:
    """v0.5.4: alternation regex is cached on frozenset(keys); streaming hot path
    that calls restore() repeatedly with the same key dict avoids re-compilation."""

    def setup_method(self):
        from argus_redact.pure.restore import _compile_alternation

        _compile_alternation.cache_clear()

    def test_should_cache_hit_on_repeated_call_with_same_key(self):
        from argus_redact.pure.restore import _compile_alternation

        key = {"P-001": "alpha", "P-002": "beta"}
        # Force Python fallback path (Rust may not exercise the cache).
        # Direct probe: call _compile_alternation twice with the same frozenset.
        _compile_alternation(frozenset(key.keys()))
        _compile_alternation(frozenset(key.keys()))
        info = _compile_alternation.cache_info()
        assert info.hits == 1, info
        assert info.misses == 1, info

    def test_should_cache_miss_when_keys_change(self):
        from argus_redact.pure.restore import _compile_alternation

        _compile_alternation(frozenset(["P-001", "P-002"]))
        _compile_alternation(frozenset(["P-001", "P-003"]))  # different set
        info = _compile_alternation.cache_info()
        assert info.misses == 2, info

    def test_should_cache_hit_regardless_of_dict_order(self):
        """Cache key is frozenset, so dict insertion order doesn't change identity."""
        from argus_redact.pure.restore import _compile_alternation

        # Build the same set in two different insertion orders
        a = frozenset({"P-001": "x", "P-002": "y"}.keys())
        b = frozenset({"P-002": "y", "P-001": "x"}.keys())
        _compile_alternation(a)
        _compile_alternation(b)
        info = _compile_alternation.cache_info()
        assert info.hits == 1, info  # second call hits the cache
