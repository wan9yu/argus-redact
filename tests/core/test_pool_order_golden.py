"""Exhaustive pool-order frozen golden for all _core pool accessors.

These tests lock the FULL sequence of every pool a built-in faker selects from.
Any reorder of a pool element — even at an index not exercised by the per-faker
Rust goldens — will fail here.

Captured from the live build at commit a9f2249+ (T12 review).  No Python-faker
module dependency: compares _core accessors to hardcoded literals only.  These
tests survive Task 13's deletion of the Python pool modules.
"""

import argus_redact._core as _core

# ── zh person names ──────────────────────────────────────────────────────────


def test_reserved_person_names_zh_order():
    assert list(_core.reserved_person_names_zh()) == [
        "张三",
        "李四",
        "王五",
        "赵六",
        "钱七",
        "焦大",
        "茗烟",
        "傻大姐",
        "彩云",
        "佩凤",
        "偕鸳",
        "卷帘",
        "毕马温",
    ]


def test_reserved_person_names_aliases_zh_order():
    assert list(_core.reserved_person_names_aliases_zh()) == [
        ("张三", ["Zhang San", "Zhang3", "ZhangSan"]),
        ("李四", ["Li Si", "Li4", "LiSi"]),
        ("王五", ["Wang Wu", "Wang5", "WangWu"]),
        ("赵六", ["Zhao Liu", "Zhao6", "ZhaoLiu"]),
        ("钱七", ["Qian Qi", "Qian7", "QianQi"]),
        ("焦大", ["Jiao Da", "JiaoDa"]),
        ("茗烟", ["Ming Yan", "MingYan"]),
        ("傻大姐", ["Sha Dajie", "Silly Big Sister"]),
        ("彩云", ["Cai Yun", "CaiYun"]),
        ("佩凤", ["Pei Feng", "PeiFeng"]),
        ("偕鸳", ["Xie Yuan", "XieYuan"]),
        ("卷帘", ["Juan Lian", "JuanLian"]),
        ("毕马温", ["Bi Mawen", "BiMawen"]),
    ]


# ── zh cities ────────────────────────────────────────────────────────────────


def test_reserved_cities_zh_order():
    assert list(_core.reserved_cities_zh()) == [
        ("滨海市", "东江区", ["八荒街", "九垣街", "十方路", "万象路"]),
        ("滨海市", "西陆区", ["青鸾街", "白虎街", "玄武路"]),
        ("滨海市", "北原区", ["朱雀路", "麒麟街"]),
    ]


def test_reserved_addresses_zh_aliases_order():
    assert list(_core.reserved_addresses_zh_aliases()) == [
        (("滨海市", "东江区", "八荒街"), ["Bahuang Street, Dongjiang District, Binhai City"]),
        (("滨海市", "东江区", "九垣街"), ["Jiuyuan Street, Dongjiang District, Binhai City"]),
        (("滨海市", "东江区", "十方路"), ["Shifang Road, Dongjiang District, Binhai City"]),
        (("滨海市", "东江区", "万象路"), ["Wanxiang Road, Dongjiang District, Binhai City"]),
        (("滨海市", "西陆区", "青鸾街"), ["Qingluan Street, Xilu District, Binhai City"]),
        (("滨海市", "西陆区", "白虎街"), ["Baihu Street, Xilu District, Binhai City"]),
        (("滨海市", "西陆区", "玄武路"), ["Xuanwu Road, Xilu District, Binhai City"]),
        (("滨海市", "北原区", "朱雀路"), ["Zhuque Road, Beiyuan District, Binhai City"]),
        (("滨海市", "北原区", "麒麟街"), ["Qilin Street, Beiyuan District, Binhai City"]),
    ]


# ── en person names ──────────────────────────────────────────────────────────


def test_reserved_person_names_en_order():
    assert list(_core.reserved_person_names_en()) == [
        "John Doe",
        "Jane Doe",
        "Jane Roe",
        "John Roe",
        "Richard Roe",
        "Mary Roe",
        "John Q. Public",
        "Alice Liddell",
        "Pat Roe",
        "Sandy Doe",
    ]


def test_reserved_person_names_aliases_en_order():
    assert list(_core.reserved_person_names_aliases_en()) == [
        ("John Doe", ["约翰·多伊", "约翰多伊"]),
        ("Jane Doe", ["简·多伊", "简多伊"]),
        ("Jane Roe", ["简·罗", "简罗"]),
        ("John Roe", ["约翰·罗", "约翰罗"]),
        ("Richard Roe", ["理查德·罗", "理查德罗"]),
        ("Mary Roe", ["玛丽·罗", "玛丽罗"]),
        ("John Q. Public", ["约翰·Q·普布利克"]),
        ("Alice Liddell", ["爱丽丝·利德尔", "爱丽丝利德尔"]),
        ("Pat Roe", ["帕特·罗", "帕特罗"]),
        ("Sandy Doe", ["桑迪·多伊", "桑迪多伊"]),
    ]


# ── en addresses ─────────────────────────────────────────────────────────────


def test_reserved_addresses_en_order():
    assert list(_core.reserved_addresses_en()) == [
        "1313 Mockingbird Lane, Springfield, USA",
        "742 Evergreen Terrace, Springfield, USA",
        "221B Baker Street, London, UK",
        "12 Grimmauld Place, London, UK",
        "1630 Revello Drive, Sunnydale, USA",
        "31 Spooner Street, Quahog, USA",
    ]


def test_reserved_addresses_en_aliases_order():
    assert list(_core.reserved_addresses_en_aliases()) == [
        ("1313 Mockingbird Lane, Springfield, USA", ["美国斯普林菲尔德嘲鸫巷1313号"]),
        ("742 Evergreen Terrace, Springfield, USA", ["美国斯普林菲尔德常青露台742号"]),
        ("221B Baker Street, London, UK", ["英国伦敦贝克街221B号"]),
        ("12 Grimmauld Place, London, UK", ["英国伦敦格里莫广场12号"]),
        ("1630 Revello Drive, Sunnydale, USA", ["美国阳光镇雷维洛大道1630号"]),
        ("31 Spooner Street, Quahog, USA", ["美国奎霍格斯普纳街31号"]),
    ]


# ── RFC / shared pools ───────────────────────────────────────────────────────


def test_rfc2606_domains_order():
    assert list(_core.rfc2606_domains()) == [
        "example.com",
        "example.org",
        "example.net",
    ]


def test_rfc5737_prefixes_order():
    assert list(_core.rfc5737_prefixes()) == [
        "192.0.2",
        "198.51.100",
        "203.0.113",
    ]


def test_rfc7042_mac_prefix():
    assert _core.rfc7042_mac_prefix() == "00:00:5E:00:53"


# ── zh document-ID single-value pools ────────────────────────────────────────


def test_passport_prefixes_zh_order():
    assert list(_core.passport_prefixes_zh()) == ["E", "G"]


def test_plate_special_prefixes_zh_order():
    assert list(_core.plate_special_prefixes_zh()) == ["测", "领"]


def test_hkid_reserved_letter():
    assert _core.hkid_reserved_letter() == "Z"


def test_twid_reserved_letter():
    assert _core.twid_reserved_letter() == "W"


def test_macau_reserved_lead():
    assert _core.macau_reserved_lead() == "9"


def test_twarc_reserved_prefix():
    assert _core.twarc_reserved_prefix() == "WW"
