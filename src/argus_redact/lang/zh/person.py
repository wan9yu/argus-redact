"""Chinese person name detection — candidate generation + evidence scoring.

Unlike structural PII (phone numbers, ID cards) which are self-identifying by
format, Chinese person names are ambiguous: "张明" could be a name or part of
a sentence. This module detects names by accumulating multiple weak signals.

Pipeline:
  1. Generate candidates: surname + 1-2 CJK chars, filtered by negative dict
  2. Score each candidate against evidence signals
  3. Resolve variants (2-char vs 3-char) at the same position
  4. Threshold: score >= 0.8 → confirmed person entity
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from argus_redact._types import PatternMatch
from argus_redact.lang.zh.surnames import COMPOUND_SURNAMES, SURNAMES

_CJK = r"\u4e00-\u9fff"
_DATA_DIR = Path(__file__).parent


# ── Data loading ──


@lru_cache(maxsize=1)
def _load_negative_dict() -> frozenset[str]:
    """Surname-prefixed words that are NOT names (e.g., 王国, 高中, 黄金).

    Built from jieba dict (non-nr POS) + hand-curated overrides.
    See scripts/build_zh_dicts.py for generation.
    """
    words = (_DATA_DIR / "not_names.txt").read_text(encoding="utf-8").strip().split("\n")
    return frozenset(words)


@lru_cache(maxsize=1)
def _load_common_words() -> frozenset[str]:
    """High-frequency 2-char Chinese words for swallow detection.

    When a 3-char candidate like "张三预" is found, we check if "预" + next char
    forms a common word (e.g., "预订"). If so, the 3-char was a false match.
    See scripts/build_zh_dicts.py for generation.
    """
    words = (_DATA_DIR / "common_words.txt").read_text(encoding="utf-8").strip().split("\n")
    return frozenset(words)


# ── Candidate generation ──


@dataclass
class NameCandidate:
    text: str
    start: int
    end: int


# Particles / function words that cannot be the last char of a given name.
_NOT_NAME_CHARS = frozenset(
    "的了在是有和与把被让从到给向因为而又也都就才会能要可将已完开做吗呢吧啊哦呀嘛啦哈嗯着过去来"
)

# Compiled regex patterns for candidate extraction
_COMPOUND_PAT = re.compile(
    r"(?:" + "|".join(re.escape(s) for s in COMPOUND_SURNAMES) + r")"
    r"[" + _CJK + r"]{1,2}"
)
_SINGLE_PAT = re.compile(r"[" + SURNAMES + r"][" + _CJK + r"]{1,2}")

# Honorific suffix — used both in scoring and in trimming
_HONORIFIC_SUFFIX = re.compile(
    r"^(?:先生|女士|老师|教授|医生|同学|师傅|经理|总监|主任|"
    r"院长|局长|部长|校长|董事长|同志|阿姨|叔叔|哥|姐|弟|妹)"
)
_HONORIFIC_HEADS = frozenset("先女老教医同师经总主院局部校董阿叔哥姐弟妹志")


def _trim_candidate(word: str, start: int, text: str) -> tuple[str, int, int]:
    """Trim trailing particles / honorific heads from a greedy regex match.

    Examples:
        "张明的" → "张明"   (particle "的")
        "张明先" → "张明"   (honorific head: "先" + "生" = "先生")
        "何秀珍" → "何秀珍" (no trim needed)
    """
    # Strip trailing particles
    while len(word) > 2 and word[-1] in _NOT_NAME_CHARS:
        word = word[:-1]
    if len(word) == 2 and word[-1] in _NOT_NAME_CHARS:
        return "", start, start

    # Strip if last char starts an honorific suffix in the following text
    if len(word) == 3 and word[-1] in _HONORIFIC_HEADS:
        remaining = word[-1] + text[start + len(word) : start + len(word) + 2]
        if _HONORIFIC_SUFFIX.match(remaining):
            word = word[:2]

    return word, start, start + len(word)


def generate_candidates(text: str) -> list[NameCandidate]:
    """Find all surname + 1-2 CJK sequences, filtered by negative dict.

    For 3-char single-surname matches, emits both 3-char and 2-char variants
    so that the scoring/resolution phase can pick the best one.
    """
    if not text:
        return []

    neg = _load_negative_dict()
    candidates: list[NameCandidate] = []
    seen_starts: set[int] = set()

    def _emit(m: re.Match, is_compound: bool = False) -> None:
        word, start, end = _trim_candidate(m.group(), m.start(), text)
        if not word or start in seen_starts:
            return

        variants: list[NameCandidate] = []
        # If the 2-char prefix is a known non-name (e.g. "任何"), the 3-char
        # extension ("任何评") is almost never a real name either — issue #12.
        prefix_blocked = len(word) == 3 and not is_compound and word[:2] in neg
        if word not in neg and not prefix_blocked:
            variants.append(NameCandidate(text=word, start=start, end=end))
        # For 3-char single-surname matches, also offer the 2-char variant
        if len(word) == 3 and not is_compound:
            short = word[:2]
            if short not in neg:
                variants.append(NameCandidate(text=short, start=start, end=start + 2))

        if variants:
            candidates.extend(variants)
            seen_starts.add(start)

    # Compound surnames first (longer match wins)
    for m in _COMPOUND_PAT.finditer(text):
        _emit(m, is_compound=True)

    # Single surnames — skip positions already claimed by compound matches
    for m in _SINGLE_PAT.finditer(text):
        if m.start() in seen_starts:
            continue
        if any(m.start() >= c.start and m.end() <= c.end for c in candidates):
            continue
        _emit(m)

    candidates.sort(key=lambda c: c.start)
    return candidates


# ── Evidence scoring ──


# Context prefix words — strong signal when immediately before the name
_CONTEXT_PREFIX = re.compile(
    r"(?:"
    # Formal role words
    r"客户|患者|用户|旅客|车主|联系人|收件人|寄件人|"
    r"登记人|开户人|申请人|报案人|委托人|当事人|嫌疑人|"
    r"负责人|经办人|签收人|担保人|受益人|借款人|"
    r"持卡人|被保险人|投保人|参会人员|"
    r"主治医生|医生|护士|教授|老板|同事|朋友|同学|"
    r"姓名|乘客|住户|业主|租户|房东|"
    # Conversational / intro phrases
    r"我是|我叫|这是|那是|找|叫做|叫作|本人|"
    r"通知|转告|联系|致电|询问"
    r")[：:\s]?$"
)

# PII-related suffixes — strong signal: possessive + PII type keyword
_PII_SUFFIX = re.compile(
    r"^(?:的(?:手机|电话|身份证|银行卡|账[户号]|地址|邮[箱件]|护照|车牌)|"
    r"[，,](?:身份证|电话|手机|银行卡))"
)

# Parenthesized phone right after name — strong signal
_PAREN_PHONE = re.compile(r"^[（(]\s*1[3-9]\d{9}")

_CONTEXT_WINDOW = 20


def score_candidate(
    candidate: NameCandidate,
    text: str,
    *,
    pii_entities: list[PatternMatch] | None = None,
) -> float:
    """Score a name candidate based on multiple evidence signals.

    Signals (additive, capped at 1.0):
      - Name length:     3-char +0.4, 4+ char +0.5, 2-char +0.3
      - Context prefix:  +0.6  ("客户", "我是", etc.)
      - Honorific suffix:+0.5  ("先生", "女士", etc.)
      - PII suffix:      +0.5  ("的手机号", "，身份证")
      - Paren phone:     +0.5  ("（13812345678）")
      - PII proximity:   +0.5 (≤50 chars) or +0.3 (≤150 chars)
    """
    before = text[max(0, candidate.start - _CONTEXT_WINDOW) : candidate.start]
    after = text[candidate.end : candidate.end + _CONTEXT_WINDOW]

    # Collect evidence signals
    evidence = 0.0
    if _CONTEXT_PREFIX.search(before):
        evidence += 0.6
    if _HONORIFIC_SUFFIX.match(after):
        evidence += 0.5
    if _PII_SUFFIX.match(after):
        evidence += 0.5
    if _PAREN_PHONE.match(after):
        evidence += 0.5

    if pii_entities:
        for pii in pii_entities:
            distance = min(abs(candidate.start - pii.end), abs(pii.start - candidate.end))
            if distance <= 50:
                evidence += 0.5
                break
            elif distance <= 150:
                evidence += 0.3
                break

    # No evidence signal → don't match at L1b (leave to L2 NER)
    if evidence == 0.0:
        return 0.0

    # Base score by name length + evidence
    if len(candidate.text) >= 4:
        score = 0.5
    elif len(candidate.text) == 3:
        score = 0.4
    else:
        score = 0.3

    return min(score + evidence, 1.0)


# ── Variant resolution ──


def _resolve_variants(
    grouped: dict[int, list[tuple[NameCandidate, float]]],
    text: str,
    threshold: float,
) -> list[tuple[NameCandidate, float]]:
    """For each start position, pick the best variant above threshold.

    Rules:
      1. If only one variant passes → use it.
      2. If both 2-char and 3-char pass → prefer 3-char (more specific),
         UNLESS the 3-char swallowed the first char of a following common word.
    """
    common = _load_common_words()
    results: list[tuple[NameCandidate, float]] = []

    for _start, variants in grouped.items():
        passing = [(c, s) for c, s in variants if s >= threshold]
        if not passing:
            continue

        if len(passing) == 1:
            results.append(passing[0])
            continue

        # Multiple variants: prefer longest, check for swallow
        passing.sort(key=lambda x: -len(x[0].text))
        best, best_score = passing[0]

        if len(best.text) == 3:
            last_char = best.text[-1]
            after = text[best.end : best.end + 2]
            following = last_char + after
            swallowed = any(following[:i] in common for i in range(2, len(following) + 1))
            if swallowed:
                short = [(c, s) for c, s in passing if len(c.text) == 2]
                if short:
                    best, best_score = short[0]

        results.append((best, best_score))

    return results


# ── Public API ──

_SCORE_THRESHOLD = 0.8


def detect_person_names(
    text: str,
    *,
    pii_entities: list[PatternMatch] | None = None,
    known_names: list[str] | None = None,
    threshold: float = _SCORE_THRESHOLD,
) -> list[PatternMatch]:
    """Detect Chinese person names via candidate generation + evidence scoring.

    Args:
        text: Input text.
        pii_entities: Structural PII already detected by Layer 1 (phone, ID, etc.).
            Used as proximity signal — names near PII score higher.
        known_names: User-provided names to always match (confidence=1.0).
            Bypasses candidate generation and scoring entirely.
        threshold: Minimum score to confirm a candidate (default 0.8).

    Returns:
        List of PatternMatch with type="person" for confirmed names.
    """
    if not text:
        return []

    results: list[PatternMatch] = []
    occupied: set[tuple[int, int]] = set()

    # Known names — exact match, bypass scoring
    if known_names:
        for name in known_names:
            if not name:
                continue
            for m in re.finditer(re.escape(name), text):
                results.append(
                    PatternMatch(
                        text=name,
                        type="person",
                        start=m.start(),
                        end=m.end(),
                        confidence=1.0,
                    )
                )
                occupied.add((m.start(), m.end()))

    # Candidate generation → scoring → variant resolution
    candidates = generate_candidates(text)

    # Filter self_reference from PII entities (not structural PII for proximity scoring)
    structural_pii = (
        [p for p in pii_entities if p.type != "self_reference"] if pii_entities else None
    )

    grouped: dict[int, list[tuple[NameCandidate, float]]] = {}
    for c in candidates:
        if any(c.start >= s and c.end <= e for s, e in occupied):
            continue
        s = score_candidate(c, text, pii_entities=structural_pii)
        grouped.setdefault(c.start, []).append((c, s))

    for best, best_score in _resolve_variants(grouped, text, threshold):
        results.append(
            PatternMatch(
                text=best.text,
                type="person",
                start=best.start,
                end=best.end,
                confidence=best_score,
            )
        )

    results.sort(key=lambda r: r.start)
    return results
