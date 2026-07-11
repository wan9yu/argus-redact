#!/usr/bin/env python3
"""Regenerate the embedded zh person-name RON (the SSOT).

The single source of truth for fast-mode (no-NER) Chinese person-name detection
is the embedded Rust RON at::

    crates/argus-redact-core/data/zh_person.ron

It bundles four pools: ``surnames`` + ``compound_surnames`` (a curated surname
list, carried verbatim below) and ``not_names`` + ``common_words`` (derived from
jieba's ``dict.txt`` by the filter rules in :func:`derive_jieba_pools`, plus the
manually-curated ``OVERRIDE_COMMON_WORDS`` set).

This script rebuilds that RON deterministically. Run it after bumping jieba or
editing the curation sets, then review the diff before committing — the RON is
golden-locked by ``tests/detection/lang/test_person_data_parity.py`` (frozen
counts + sha256), so any change must be a deliberate, reviewed re-freeze.

Source for the derived pools:
  jieba dict.txt (MIT license, ~349K entries) — https://github.com/fxsjy/jieba
  Pinned at jieba 0.42.1 (the version the committed RON was built from). The
  output is byte-identical to the committed RON under that version; a different
  jieba dict will drift the derived pools.

The surname pools (``surnames`` / ``compound_surnames``) are NOT derived here —
they are the curated list carried as canonical literals below. This is a
different set from the jieba pos-filter ``SURNAMES`` further down: the filter
set decides which jieba entries to inspect; the pool is the detection surname
list stored byte-for-byte in the RON (order-load-bearing).

Usage:
    pip install jieba   # pinned: jieba==0.42.1
    python scripts/build_zh_dicts.py            # write the RON in place
    python scripts/build_zh_dicts.py --check     # verify only, write nothing
    python scripts/build_zh_dicts.py --out PATH  # write to a scratch path
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# ── Curated surname pools (carried verbatim from the committed RON) ───────────
# These are the detection surname list, NOT the jieba pos-filter SURNAMES set
# below. They originated in the (now-deleted) lang.zh.surnames module and are the
# byte-for-byte, order-load-bearing pool the RON stores. Edit deliberately.
SURNAMES_POOL = (
    "王李张刘陈杨赵黄周吴徐孙胡朱高林何郭马罗"
    "梁宋郑谢韩唐冯于董萧程曹袁邓许傅沈曾彭吕"
    "苏卢蒋蔡贾丁魏薛叶阎余潘杜戴夏钟汪田任姜"
    "范方石姚谭廖邹熊金陆郝孔白崔康毛邱秦江史顾"
    "侯邵孟龙万段漕钱汤尹黎易常武乔贺赖龚文庞"
    "樊兰殷施陶洪翟安颜倪严牛温芦季俞章鲁葛伍"
    "韦申尤毕聂丛焦向柳邢骆岳齐沿雷詹欧"
    "莫缪邝靳邬滕佟翁"
)

COMPOUND_SURNAMES = (
    "上官",
    "东方",
    "令狐",
    "公孙",
    "南宫",
    "司徒",
    "司马",
    "宇文",
    "尉迟",
    "慕容",
    "欧阳",
    "皇甫",
    "端木",
    "西门",
    "诸葛",
    "长孙",
)

# ── jieba pos-filter surname set (used to FILTER dict.txt entries) ────────────
# Distinct from SURNAMES_POOL above: this decides which jieba words are
# candidate surname-prefixed entries worth keeping/rejecting. As a set it
# currently coincides with SURNAMES_POOL, but the two are maintained separately.
SURNAMES = set(
    "王李张刘陈杨赵黄周吴徐孙胡朱高林何郭马罗"
    "梁宋郑谢韩唐冯于董萧程曹袁邓许傅沈曾彭吕"
    "苏卢蒋蔡贾丁魏薛叶阎余潘杜戴夏钟汪田任姜"
    "范方石姚谭廖邹熊金陆郝孔白崔康毛邱秦江史顾"
    "侯邵孟龙万段漕钱汤尹黎易常武乔贺赖龚文庞"
    "樊兰殷施陶洪翟安颜倪严牛温芦季俞章鲁葛伍"
    "韦申尤毕聂丛焦向柳邢骆岳齐沿雷詹欧"
)

# Common words misclassified as nr (person name) in jieba dict.
# Manually curated: these are verbs, nouns, or adjectives, not names.
OVERRIDE_COMMON_WORDS = {
    # Verbs
    "张开",
    "张贴",
    "张望",
    "陈述",
    "陈列",
    "陈设",
    "许可",
    "安抚",
    "杜绝",
    "谢恩",
    "谢谢",
    "顾问",
    "顾客",
    "高悬",
    "林立",
    # Nouns (things / concepts)
    "武功",
    "武林",
    "文明",
    "文武",
    "雷达",
    "陆军",
    "苏军",
    "胡同",
    "胡子",
    "胡闹",
    "胡涂",
    "王朝",
    "王爷",
    "王公",
    "王府",
    "王子",
    "王八",
    "洪水",
    "洪武",
    "金殿",
    "金刚",
    "金石",
    "金陵",
    "金黄",
    "金字塔",
    "白雪",
    "白领",
    "白宫",
    "白莲",
    "白石",
    "白白",
    "白布",
    "白发",
    "高峰",
    "高潮",
    "高明",
    "高僧",
    "高薪",
    "高三",
    "齐声",
    "齐全",
    "丛林",
    "安静",
    "安危",
    "温泉",
    "黄金",
    "石英",
    "石狮",
    "石林",
    "石柱",
    "石家庄",
    "梁山",
    "秦岭",
    "秦汉",
    "洪山",
    "洪湖",
    "常德",
    "向东",
    "向阳",
    "马匹",
    "马背",
    "马夫",
    "马来",
    "马克",
    "马刺",
    "马丁",
    "乔木",
    "毛巾",
    "叶子",
    "兰花",
    "杨柳",
    "杜鹃",
    "杜鹃花",
    "范畴",
    "史诗",
    "岳父",
    "孙子",
    "孔子",
    "康复",
    "朱红",
    "魏晋",
    "林木",
    "林子",
    "唐僧",
    "黎明",
    "季后赛",
    "黄鹤楼",
    "黄金周",
    "黄龙",
    "龙亭",
    "胡萝卜",
    "马其顿",
    "牛顿",
    "周转",
    "周密",
    "钟祥",
    "钟祥市",
    "罗刹",
    "尤伯杯",
    "高陵",
    "金平",
    "罗田",
    "黄石",
}

# Manually-curated not-name entries that jieba's dict.txt does NOT mark, added to
# block false-positive name candidates from surnames whose common words jieba
# misses (e.g. 莫名 for the 莫 surname). Unioned into the derived not_names.
MANUAL_NOT_NAMES = ("莫名",)


def _is_cjk(word: str) -> bool:
    return all("一" <= c <= "鿿" for c in word)


def derive_jieba_pools(dict_path: str) -> tuple[list[str], list[str]]:
    """Derive (not_names, common_words) from jieba's dict.txt, sorted.

    not_names: surname-prefixed 2/3-char CJK words that jieba does NOT tag as
        ``nr`` (person name), unioned with the curated OVERRIDE_COMMON_WORDS.
    common_words: high-frequency (freq >= 50) 2-char CJK words that jieba does
        NOT tag as ``nr`` — used for swallow detection.
    """
    negative: set[str] = set()
    common: set[str] = set()
    with open(dict_path, encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(" ")
            if len(parts) < 3:
                continue
            word, freq_s, pos = parts[0], parts[1], parts[2]
            if not _is_cjk(word):
                continue
            if len(word) in (2, 3) and word[0] in SURNAMES and pos != "nr":
                negative.add(word)
            if len(word) == 2 and int(freq_s) >= 50 and pos != "nr":
                common.add(word)

    negative |= OVERRIDE_COMMON_WORDS
    return sorted(set(negative) | set(MANUAL_NOT_NAMES)), sorted(common)


def _emit_list(name: str, items: list[str]) -> str:
    lines = [f"    {name}: ["]
    lines += [f'        "{it}",' for it in items]
    lines.append("    ],")
    return "\n".join(lines)


def render_ron(not_names: list[str], common_words: list[str]) -> str:
    """Render the zh_person.ron content in the committed deterministic format."""
    parts = [
        "// zh person-name detection pools (SSOT).",
        "// Generated by mirroring the pure-Python sources:",
        "//   surnames/compound_surnames = lang.zh.surnames.{SURNAMES,COMPOUND_SURNAMES}",
        "//   not_names/common_words     = lang.zh.person._load_{negative_dict,common_words}()",
        "// List pools are sorted for a deterministic file; order does not affect matching.",
        "// SURNAMES is stored byte-for-byte (no reorder/dedup).",
        "ZhPersonData(",
        f'    surnames: "{SURNAMES_POOL}",',
        _emit_list("compound_surnames", sorted(COMPOUND_SURNAMES)),
        _emit_list("not_names", not_names),
        _emit_list("common_words", common_words),
        ")",
    ]
    return "\n".join(parts) + "\n"


def _default_out() -> Path:
    return (
        Path(__file__).resolve().parent.parent
        / "crates"
        / "argus-redact-core"
        / "data"
        / "zh_person.ron"
    )


def _jieba_dict_path() -> str:
    import jieba

    return os.path.join(os.path.dirname(jieba.__file__), "dict.txt")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output path (default: crates/argus-redact-core/data/zh_person.ron)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the target RON matches the regenerated content; write nothing",
    )
    args = parser.parse_args(argv)

    out = args.out if args.out is not None else _default_out()

    not_names, common_words = derive_jieba_pools(_jieba_dict_path())
    content = render_ron(not_names, common_words)

    print(f"not_names: {len(not_names)} entries")
    print(f"common_words: {len(common_words)} entries")

    if args.check:
        if not out.exists():
            print(f"--check: target does not exist: {out}", file=sys.stderr)
            return 1
        current = out.read_text(encoding="utf-8")
        if current == content:
            print(f"--check: {out} is up to date.")
            return 0
        print(f"--check: {out} differs from regenerated content.", file=sys.stderr)
        return 1

    out.write_text(content, encoding="utf-8")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
