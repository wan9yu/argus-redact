"""Parity lock for the zh organization / school regexes.

These patterns match the LONGEST ``(2-12 CJK prefix) + (suffix)`` at each
position, ending at the suffix (regardless of trailing CJK), with the suffix
alternation ordered longest-first so the longest applicable suffix wins.

Any rewrite of the patterns (e.g. atomic groups, reordered alternations) MUST
keep these spans bit-identical. This is the hard parity gate: a single changed
span here means the rewrite altered match results, which is forbidden.

Spans come from the production path (``_core.detect_l1``) and cover the full
match (optional prefix + group). Each ``(type, start, end, text)`` is pinned
from the current engine output.
"""
import argus_redact._core as _core
import pytest


def _org_school(text):
    """Return [(type, start, end, text)] for organization/school L1 matches."""
    layer1, _person, _regions, _job_titles, _framework, _hints, _near = _core.detect_l1(text, ["zh"], [])
    return [
        (m.type, m.start, m.end, m.text)
        for m in layer1
        if m.type in ("organization", "school")
    ]


# (input, expected [(type, start, end, text)]) — pinned baseline.
CORPUS = [
    # multi-suffix → longest applicable suffix wins (集团, not stopping at 保险)
    ("中国平安保险集团", [("organization", 0, 8, "中国平安保险集团")]),
    # suffix (银行) followed by trailing CJK → match ends at the suffix (中国银行)
    ("中国银行北京分行", [("organization", 0, 4, "中国银行")]),
    # org whose first char (有) is also an optional prefix-word
    ("有限公司", [("organization", 0, 4, "有限公司")]),
    ("北京大学", [("school", 0, 4, "北京大学")]),
    ("清华大学附属中学", [("school", 0, 8, "清华大学附属中学")]),
    ("某某科技有限公司", [("organization", 0, 8, "某某科技有限公司")]),
    ("在阿里巴巴集团工作", [("organization", 1, 7, "阿里巴巴集团")]),
    ("毕业于北京师范大学", [("school", 3, 9, "北京师范大学")]),
    ("张三在华为技术有限公司", [("organization", 0, 11, "张三在华为技术有限公司")]),
    # multi-org / multi-school sentences
    (
        "他在腾讯科技有限公司上班，她在北京大学读书。",
        [
            ("organization", 0, 10, "他在腾讯科技有限公司"),
            ("school", 13, 19, "她在北京大学"),
        ],
    ),
    (
        "我先去工商银行，再到中国人民大学，最后回深圳市人民医院。",
        [
            ("organization", 0, 7, "我先去工商银行"),
            ("school", 8, 16, "再到中国人民大学"),
            ("organization", 17, 27, "最后回深圳市人民医院"),
        ],
    ),
    (
        "字节跳动有限公司和阿里巴巴集团都在杭州。",
        [
            ("organization", 0, 8, "字节跳动有限公司"),
            ("organization", 8, 15, "和阿里巴巴集团"),
        ],
    ),
    (
        "她毕业于清华大学，就职于百度在线网络技术有限公司。",
        [
            ("school", 0, 8, "她毕业于清华大学"),
            ("organization", 12, 24, "百度在线网络技术有限公司"),
        ],
    ),
    (
        "上海交通大学医学院附属瑞金医院",
        [
            ("school", 0, 9, "上海交通大学医学院"),
            ("organization", 1, 15, "海交通大学医学院附属瑞金医院"),
        ],
    ),
    (
        "中国工商银行股份有限公司北京分行营业部",
        [("organization", 0, 12, "中国工商银行股份有限公司")],
    ),
]


@pytest.mark.parametrize("text,expected", CORPUS, ids=[c[0] for c in CORPUS])
def test_org_school_parity(text, expected):
    assert _org_school(text) == expected
