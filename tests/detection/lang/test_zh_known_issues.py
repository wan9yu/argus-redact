"""Precision tests for organization/school/job_title boundary detection.

These tests verify that prefix trimming correctly separates verb prefixes
(就职于, 毕业于, 去, 在, etc.) from entity names.
"""

from argus_redact.pure.patterns import match_patterns
from argus_redact.lang.zh.patterns import PATTERNS as ZH_PATTERNS
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS

ALL = ZH_PATTERNS + SHARED_PATTERNS


class TestOrganizationPrecision:
    def test_should_not_eat_verb_prefix(self):
        results = [r for r in match_patterns("就职于腾讯公司", ALL) if r.type == "organization"]
        assert len(results) == 1
        assert results[0].text == "腾讯公司"

    def test_should_not_eat_preposition(self):
        results = [r for r in match_patterns("去北京协和医院看病", ALL) if r.type == "organization"]
        assert len(results) == 1
        assert results[0].text == "北京协和医院"

    def test_should_match_full_name_without_prefix(self):
        results = [r for r in match_patterns("腾讯计算机系统有限公司", ALL) if r.type == "organization"]
        assert len(results) == 1
        assert results[0].text == "腾讯计算机系统有限公司"


class TestSchoolPrecision:
    def test_should_not_eat_verb_prefix(self):
        results = [r for r in match_patterns("毕业于北京大学", ALL) if r.type == "school"]
        assert len(results) == 1
        assert results[0].text == "北京大学"

    def test_should_not_eat_preposition(self):
        results = [r for r in match_patterns("在清华大学读书", ALL) if r.type == "school"]
        assert len(results) == 1
        assert results[0].text == "清华大学"

    def test_should_match_full_name_without_prefix(self):
        results = [r for r in match_patterns("人大附中的学生", ALL) if r.type == "school"]
        assert len(results) == 1
        assert results[0].text == "人大附中"


class TestJobTitlePrecision:
    def test_should_not_eat_particle_prefix(self):
        results = [r for r in match_patterns("科室的李主任", ALL) if r.type == "job_title"]
        assert len(results) == 1
        assert results[0].text == "李主任"

    def test_should_match_full_title_without_prefix(self):
        results = [r for r in match_patterns("技术总监负责", ALL) if r.type == "job_title"]
        assert len(results) == 1
        assert results[0].text == "技术总监"
