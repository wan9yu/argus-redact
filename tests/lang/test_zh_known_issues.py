"""Known precision issues — tests marked xfail to document expected behavior.

These tests document cases where regex-based detection is imprecise.
Fixing requires candidate+scoring (like person.py) which is planned but not yet implemented.
"""

import pytest
from argus_redact.pure.patterns import match_patterns
from argus_redact.lang.zh.patterns import PATTERNS as ZH_PATTERNS
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS

ALL = ZH_PATTERNS + SHARED_PATTERNS


class TestOrganizationPrecision:
    """Organization regex eats preceding CJK chars that aren't part of the name."""

    @pytest.mark.xfail(reason="Regex CJK prefix over-matching — needs candidate+scoring")
    def test_should_not_eat_verb_prefix(self):
        results = [r for r in match_patterns("就职于腾讯公司", ALL) if r.type == "organization"]
        assert len(results) == 1
        assert results[0].text == "腾讯公司"  # actual: "就职于腾讯公司"

    @pytest.mark.xfail(reason="Regex CJK prefix over-matching — needs candidate+scoring")
    def test_should_not_eat_preposition(self):
        results = [r for r in match_patterns("去北京协和医院看病", ALL) if r.type == "organization"]
        assert len(results) == 1
        assert results[0].text == "北京协和医院"  # actual: "去北京协和医院"


class TestSchoolPrecision:
    """School regex eats preceding CJK chars that aren't part of the name."""

    @pytest.mark.xfail(reason="Regex CJK prefix over-matching — needs candidate+scoring")
    def test_should_not_eat_verb_prefix(self):
        results = [r for r in match_patterns("毕业于北京大学", ALL) if r.type == "school"]
        assert len(results) == 1
        assert results[0].text == "北京大学"  # actual: "毕业于北京大学"

    @pytest.mark.xfail(reason="Regex CJK prefix over-matching — needs candidate+scoring")
    def test_should_not_eat_preposition(self):
        results = [r for r in match_patterns("在清华大学读书", ALL) if r.type == "school"]
        assert len(results) == 1
        assert results[0].text == "清华大学"  # actual: "在清华大学"


class TestJobTitlePrecision:
    """Job title regex eats preceding CJK chars."""

    @pytest.mark.xfail(reason="Regex CJK prefix over-matching — needs candidate+scoring")
    def test_should_match_exact_title(self):
        results = [r for r in match_patterns("科室的李主任", ALL) if r.type == "job_title"]
        assert len(results) == 1
        assert results[0].text == "李主任"  # actual: "科室的李主任"
