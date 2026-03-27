#!/usr/bin/env python3
"""Build Chinese negative dictionary and common words from jieba dict.

Generates two files in src/argus_redact/lang/zh/:
  - not_names.txt: surname-prefixed words that are NOT person names
  - common_words.txt: high-frequency 2-char words for swallow detection

Source: jieba dict.txt (MIT license, ~349K entries)
  https://github.com/fxsjy/jieba

Usage:
    pip install jieba
    python scripts/build_zh_dicts.py
"""

from __future__ import annotations

import os
from pathlib import Path

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
    "张开", "张贴", "张望", "陈述", "陈列", "陈设", "许可", "安抚",
    "杜绝", "谢恩", "谢谢", "顾问", "顾客", "高悬", "林立",
    # Nouns (things / concepts)
    "武功", "武林", "文明", "文武", "雷达", "陆军", "苏军",
    "胡同", "胡子", "胡闹", "胡涂",
    "王朝", "王爷", "王公", "王府", "王子", "王八",
    "洪水", "洪武", "金殿", "金刚", "金石", "金陵", "金黄", "金字塔",
    "白雪", "白领", "白宫", "白莲", "白石", "白白", "白布", "白发",
    "高峰", "高潮", "高明", "高僧", "高薪", "高三",
    "齐声", "齐全", "丛林", "安静", "安危",
    "温泉", "黄金", "石英", "石狮", "石林", "石柱", "石家庄",
    "梁山", "秦岭", "秦汉", "洪山", "洪湖", "常德",
    "向东", "向阳", "马匹", "马背", "马夫", "马来", "马克",
    "马刺", "马丁", "乔木", "毛巾", "叶子", "兰花",
    "杨柳", "杜鹃", "杜鹃花", "范畴", "史诗",
    "岳父", "孙子", "孔子", "康复", "朱红", "魏晋",
    "林木", "林子", "唐僧", "黎明", "季后赛",
    "黄鹤楼", "黄金周", "黄龙", "龙亭",
    "胡萝卜", "马其顿", "牛顿",
    "周转", "周密", "钟祥", "钟祥市",
    "罗刹", "尤伯杯",
    "高陵", "金平", "罗田", "黄石",
}


def _is_cjk(word: str) -> bool:
    return all("\u4e00" <= c <= "\u9fff" for c in word)


def build(dict_path: str, output_dir: Path) -> None:
    # ── not_names.txt ──
    negative = set()
    with open(dict_path) as f:
        for line in f:
            parts = line.strip().split(" ")
            if len(parts) < 3:
                continue
            word, _freq, pos = parts[0], int(parts[1]), parts[2]
            if len(word) not in (2, 3) or word[0] not in SURNAMES or not _is_cjk(word):
                continue
            if pos != "nr":
                negative.add(word)

    negative |= OVERRIDE_COMMON_WORDS

    not_names_path = output_dir / "not_names.txt"
    not_names_path.write_text("\n".join(sorted(negative)) + "\n", encoding="utf-8")
    print(f"not_names.txt: {len(negative)} entries ({not_names_path})")

    # ── common_words.txt ──
    common = set()
    with open(dict_path) as f:
        for line in f:
            parts = line.strip().split(" ")
            if len(parts) < 3:
                continue
            word, freq, pos = parts[0], int(parts[1]), parts[2]
            if len(word) == 2 and freq >= 50 and pos != "nr" and _is_cjk(word):
                common.add(word)

    common_path = output_dir / "common_words.txt"
    common_path.write_text("\n".join(sorted(common)) + "\n", encoding="utf-8")
    print(f"common_words.txt: {len(common)} entries ({common_path})")


def main() -> None:
    import jieba

    dict_path = os.path.join(os.path.dirname(jieba.__file__), "dict.txt")
    output_dir = Path(__file__).parent.parent / "src" / "argus_redact" / "lang" / "zh"

    if not output_dir.exists():
        raise FileNotFoundError(f"Output directory not found: {output_dir}")

    build(dict_path, output_dir)
    print("Done.")


if __name__ == "__main__":
    main()
