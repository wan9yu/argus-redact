"""Precision tests for organization/school/job_title boundary detection.

These tests verify that prefix trimming correctly separates verb prefixes
(就职于, 毕业于, 去, 在, etc.) from entity names.
"""

import argus_redact._core as _core

from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.lang.zh.patterns import PATTERNS as ZH_PATTERNS
from argus_redact.pure.patterns import match_patterns

ALL = ZH_PATTERNS + SHARED_PATTERNS


def _orgs_schools(text):
    """(type, text) org/school detections from the full production path ``detect_l1``.

    The named org/school validator runs in the Rust core (both ``detect_l1`` and
    ``_core.match_patterns`` apply it — a failing validator drops the match to a
    near-miss). We assert against ``detect_l1`` because it is the end-to-end pipeline
    the caller actually gets, not a lower-level regex probe.
    """
    layer1, *_ = _core.detect_l1(text, ["zh"], [])
    return [(m.type, m.text) for m in layer1 if m.type in ("organization", "school")]


class TestOrganizationPrecision:
    def test_should_not_eat_verb_prefix(self):
        results, _ = match_patterns("就职于腾讯公司", ALL)
        results = [r for r in results if r.type == "organization"]
        assert len(results) == 1
        assert results[0].text == "腾讯公司"

    def test_should_not_eat_preposition(self):
        results, _ = match_patterns("去北京协和医院看病", ALL)
        results = [r for r in results if r.type == "organization"]
        assert len(results) == 1
        assert results[0].text == "北京协和医院"

    def test_should_match_full_name_without_prefix(self):
        results, _ = match_patterns("腾讯计算机系统有限公司", ALL)
        results = [r for r in results if r.type == "organization"]
        assert len(results) == 1
        assert results[0].text == "腾讯计算机系统有限公司"


class TestSchoolPrecision:
    def test_should_not_eat_verb_prefix(self):
        results, _ = match_patterns("毕业于北京大学", ALL)
        results = [r for r in results if r.type == "school"]
        assert len(results) == 1
        assert results[0].text == "北京大学"

    def test_should_not_eat_preposition(self):
        results, _ = match_patterns("在清华大学读书", ALL)
        results = [r for r in results if r.type == "school"]
        assert len(results) == 1
        assert results[0].text == "清华大学"

    def test_should_match_full_name_without_prefix(self):
        results, _ = match_patterns("人大附中的学生", ALL)
        results = [r for r in results if r.type == "school"]
        assert len(results) == 1
        assert results[0].text == "人大附中"


class TestJobTitlePrecision:
    def test_should_not_eat_particle_prefix(self):
        results, _ = match_patterns("科室的李主任", ALL)
        results = [r for r in results if r.type == "job_title"]
        assert len(results) == 1
        assert results[0].text == "李主任"

    def test_should_match_full_title_without_prefix(self):
        results, _ = match_patterns("技术总监负责", ALL)
        results = [r for r in results if r.type == "job_title"]
        assert len(results) == 1
        assert results[0].text == "技术总监"


class TestOrganizationFalsePositiveRejection:
    """Gateway P2: business prose carrying a legal/industry suffix must NOT redact.

    The validator rejects a candidate whose name (leading noise + longest suffix
    stripped) is empty or entirely generic. Asserted against ``detect_l1`` — the
    full production pipeline the caller receives.
    """

    def test_organization_should_reject_when_name_is_only_a_legal_suffix(self):
        assert _orgs_schools("有限公司") == []

    def test_organization_should_reject_when_a_verb_precedes_bare_suffix(self):
        assert _orgs_schools("这个需求需要改成公司统一处理") == []

    def test_organization_should_reject_when_a_quantifier_precedes_bare_suffix(self):
        assert _orgs_schools("这是一家公司") == []

    def test_organization_should_reject_when_a_verb_precedes_bare_group_word(self):
        assert _orgs_schools("我们要成立集团来运营这块业务") == []

    def test_organization_should_reject_when_a_preposition_run_precedes_bare_suffix(self):
        assert _orgs_schools("把这个项目挂到有限公司名下") == []

    def test_organization_should_reject_when_name_is_a_category_word(self):
        assert _orgs_schools("上市公司信息披露要求很严") == []

    def test_organization_should_reject_when_a_demonstrative_precedes_bare_suffix(self):
        assert _orgs_schools("这家公司管理混乱") == []
        assert _orgs_schools("那家公司倒闭了") == []
        assert _orgs_schools("几家公司联合竞标") == []

    def test_organization_should_reject_when_a_scope_word_precedes_bare_group(self):
        assert _orgs_schools("整个集团都在裁员") == []

    def test_organization_should_reject_when_noise_prefix_leaves_bare_suffix(self):
        # the leading-noise strip reduces 请查一下公司 to a bare 公司 → rejected
        assert _orgs_schools("请查一下公司税号") == []


class TestSchoolFalsePositiveRejection:
    def test_school_should_reject_when_a_demonstrative_precedes_bare_suffix(self):
        assert _orgs_schools("这所大学很难考") == []
        assert _orgs_schools("那所中学离家很近") == []


class TestNamePlusGenericSuffixStillOrg:
    """Recall guard: a real name + a category word is STILL detected as an org."""

    def test_organization_should_still_match_when_a_brand_name_precedes_generic_suffix(self):
        assert ("organization", "腾讯分公司") in _orgs_schools("腾讯分公司也在招人")

    def test_organization_should_still_match_when_name_includes_generic_bank_suffix(self):
        assert ("organization", "中国建设银行") in _orgs_schools("中国建设银行今天发布了公告")

    def test_organization_should_still_match_when_name_includes_generic_management_suffix(self):
        assert ("organization", "华夏基金管理有限公司") in _orgs_schools(
            "华夏基金管理有限公司调整了持仓"
        )
