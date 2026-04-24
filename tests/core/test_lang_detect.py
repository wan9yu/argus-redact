"""Tests for detect_languages() — script-based language detection for lang='auto'."""

import pytest


class TestDetectLanguagesPureScripts:
    """Single-script inputs route to the expected language pack."""

    def test_should_detect_zh_when_cjk_only(self):
        from argus_redact.pure.lang_detect import detect_languages

        assert detect_languages("客户身份证号码是110101199003074610") == ["zh"]

    def test_should_detect_en_when_ascii_letters_only(self):
        from argus_redact.pure.lang_detect import detect_languages

        assert detect_languages("The quick brown fox jumps over the lazy dog") == ["en"]

    def test_should_detect_ja_when_hiragana_present(self):
        from argus_redact.pure.lang_detect import detect_languages

        assert detect_languages("田中さんの電話番号は090-1234-5678です") == ["ja"]

    def test_should_detect_ja_when_katakana_present(self):
        from argus_redact.pure.lang_detect import detect_languages

        assert detect_languages("メールアドレスはtanaka@example.com") == ["ja", "en"]

    def test_should_detect_ko_when_hangul_present(self):
        from argus_redact.pure.lang_detect import detect_languages

        assert detect_languages("김철수 주민등록번호는 900101-1234567") == ["ko"]


class TestDetectLanguagesMixed:
    """Mixed-script inputs return multiple language codes."""

    def test_should_detect_zh_and_en_when_mixed(self):
        from argus_redact.pure.lang_detect import detect_languages

        result = detect_languages("客户John Smith的手机号13812345678")
        assert "zh" in result
        assert "en" in result

    def test_should_detect_ja_and_en_when_katakana_and_latin(self):
        from argus_redact.pure.lang_detect import detect_languages

        result = detect_languages("User名はJohn Smithです")
        assert "ja" in result
        assert "en" in result

    def test_should_detect_ko_and_en_when_hangul_and_latin(self):
        from argus_redact.pure.lang_detect import detect_languages

        result = detect_languages("이름은 John Smith 입니다")
        assert "ko" in result
        assert "en" in result


class TestDetectLanguagesCJKDisambiguation:
    """CJK chars (U+4E00-U+9FFF) are ambiguous — rules prevent double-counting."""

    def test_should_not_add_zh_when_hiragana_present(self):
        from argus_redact.pure.lang_detect import detect_languages

        # Japanese text with kanji + hiragana → should route to ja only, not zh
        assert "zh" not in detect_languages("田中さんの会社")

    def test_should_not_add_zh_when_hangul_present(self):
        from argus_redact.pure.lang_detect import detect_languages

        # Korean text with hanja + hangul → ko only
        assert "zh" not in detect_languages("김철수 大韓民國")


class TestDetectLanguagesLatinThreshold:
    """Latin letter detection requires a minimum count to avoid false-add."""

    def test_should_not_add_en_when_stray_letters_only(self):
        from argus_redact.pure.lang_detect import detect_languages

        # Chinese text with 1-2 stray Latin letters (single letter brand / initial)
        # should NOT trigger English route
        result = detect_languages("她去了Q区")  # 1 Latin char
        assert "en" not in result
        assert "zh" in result

    def test_should_add_en_when_three_or_more_latin_letters(self):
        from argus_redact.pure.lang_detect import detect_languages

        result = detect_languages("客户Apple公司")  # 5 Latin chars
        assert "en" in result


class TestDetectLanguagesFallback:
    """When no script is detectable, fallback to ['zh']."""

    def test_should_fallback_when_empty(self):
        from argus_redact.pure.lang_detect import detect_languages

        assert detect_languages("") == ["zh"]

    def test_should_fallback_when_only_punctuation(self):
        from argus_redact.pure.lang_detect import detect_languages

        assert detect_languages("!@#$%^&*()_+-=[]{}|;:',.<>?/") == ["zh"]

    def test_should_fallback_when_only_digits(self):
        from argus_redact.pure.lang_detect import detect_languages

        assert detect_languages("1234567890") == ["zh"]

    def test_should_fallback_when_only_whitespace(self):
        from argus_redact.pure.lang_detect import detect_languages

        assert detect_languages("   \n\t\r  ") == ["zh"]


class TestDetectLanguagesReturnShape:
    """Return value contract."""

    def test_should_return_list_of_strings(self):
        from argus_redact.pure.lang_detect import detect_languages

        result = detect_languages("hello world")
        assert isinstance(result, list)
        assert all(isinstance(x, str) for x in result)

    def test_should_return_deduplicated(self):
        from argus_redact.pure.lang_detect import detect_languages

        # Multiple triggers of same language shouldn't duplicate
        result = detect_languages("客户Apple 张三 Microsoft 李四")
        assert result.count("zh") == 1
        assert result.count("en") == 1
