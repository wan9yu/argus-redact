//! Chinese person-name detection — Rust port of `lang/zh/person.py`.
//!
//! This is a byte-faithful port of the full detector: candidate generation
//! (`generate_candidates` + `_trim_candidate` + the `NameCandidate` dataclass),
//! evidence scoring (`score_candidate`), variant resolution
//! (`_resolve_variants`) and the public `detect_person_names` entry point.
//! `detect_person_names` is the only `pub` surface; the rest stays
//! crate-internal and is consumed transitively through it.
//!
//! ## Char offsets, not byte offsets
//!
//! Python `re` match positions and `NameCandidate.start/end` are **character**
//! (Unicode scalar) offsets on a `str`. `fancy_regex` returns **byte** offsets.
//! Every regex offset that reaches a `NameCandidate` or the `seen_starts` set is
//! converted via [`crate::reserved_range::byte_to_char_offset`], and the trim
//! loop operates entirely in char-space (a `Vec<char>` over the matched word),
//! so a multi-byte CJK word is never byte-sliced.

use std::collections::HashSet;
use std::sync::LazyLock;

use fancy_regex::Regex;

use crate::person_data::{
    common_words_zh_set, compound_surnames_zh, not_names_zh_set, surnames_zh,
};
use crate::reserved_range::byte_to_char_offset;
use crate::types::PatternMatch;

/// CJK unified ideographs range — the character class body used by both
/// `_SINGLE_PAT` and `_COMPOUND_PAT`. Mirrors Python `_CJK = r"一-鿿"`.
const CJK: &str = r"\u{4e00}-\u{9fff}";

/// Particles / function words that cannot be the last char of a given name.
/// Mirrors Python `_NOT_NAME_CHARS` (45 chars).
const NOT_NAME_CHARS: &str =
    "的了在是有和与把被让从到给向因为而又也都就才会能要可将已完开做吗呢吧啊哦呀嘛啦哈嗯着过去来";

/// Heads of honorific suffixes — mirrors Python `_HONORIFIC_HEADS`.
const HONORIFIC_HEADS: &str = "先女老教医同师经总主院局部校董阿叔哥姐弟妹志";

static NOT_NAME_CHARS_SET: LazyLock<HashSet<char>> =
    LazyLock::new(|| NOT_NAME_CHARS.chars().collect());

static HONORIFIC_HEADS_SET: LazyLock<HashSet<char>> =
    LazyLock::new(|| HONORIFIC_HEADS.chars().collect());

/// `_COMPOUND_PAT` — compound surname (alternation) + 1-2 CJK chars.
///
/// Python builds this as
/// `(?:s1|s2|...)[一-鿿]{1,2}` with each compound surname
/// `re.escape`-d. The compound pool is 2-char CJK literals (nothing to escape),
/// but we escape anyway to match the Python construction exactly.
static COMPOUND_PAT: LazyLock<Regex> = LazyLock::new(|| {
    let alt = compound_surnames_zh()
        .iter()
        .map(|s| fancy_regex::escape(s).into_owned())
        .collect::<Vec<_>>()
        .join("|");
    let pat = format!(r"(?:{alt})[{CJK}]{{1,2}}");
    Regex::new(&pat)
        .unwrap_or_else(|e| panic!("person_zh: _COMPOUND_PAT compile failed: {e}\nPattern: {pat}"))
});

/// `_SINGLE_PAT` — single surname char class + 1-2 CJK chars.
///
/// Python: `re.compile(r"[" + SURNAMES + r"][" + _CJK + r"]{1,2}")`.
/// `SURNAMES` is the byte-for-byte single-char surname string used as a char
/// class body.
static SINGLE_PAT: LazyLock<Regex> = LazyLock::new(|| {
    let surnames = surnames_zh();
    let pat = format!(r"[{surnames}][{CJK}]{{1,2}}");
    Regex::new(&pat)
        .unwrap_or_else(|e| panic!("person_zh: _SINGLE_PAT compile failed: {e}\nPattern: {pat}"))
});

/// `_HONORIFIC_SUFFIX` — anchored match of an honorific word at string start.
/// Mirrors Python `_HONORIFIC_SUFFIX`.
static HONORIFIC_SUFFIX: LazyLock<Regex> = LazyLock::new(|| {
    let pat = concat!(
        r"^(?:先生|女士|老师|教授|医生|同学|师傅|经理|总监|主任|",
        r"院长|局长|部长|校长|董事长|同志|阿姨|叔叔|哥|姐|弟|妹)"
    );
    Regex::new(pat)
        .unwrap_or_else(|e| panic!("person_zh: _HONORIFIC_SUFFIX compile failed: {e}"))
});

/// A candidate person name. `start`/`end` are **character** offsets into the
/// source text, matching Python `NameCandidate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NameCandidate {
    pub text: String,
    pub start: usize,
    pub end: usize,
}

/// Trim trailing particles / honorific heads from a greedy regex match.
///
/// Direct port of `_trim_candidate(word, start, text)`. `word` arrives as the
/// matched substring; `start` is the **char** offset of the match in `text`.
/// `chars` is the whole source text as a shared `&[char]` slice (collected once
/// by `detect_person_names` and threaded down, mirroring `person_en.rs`), used
/// here only by the 3-char honorific-head branch's following-text lookahead.
/// Returns `(trimmed_word, start, end)` where `end` is a char offset.
///
/// All length / indexing / slicing is char-based (the Python `word[-1]`,
/// `len(word)`, `word[:-1]`, `word[:2]` are str/char operations).
fn trim_candidate(word: &str, start: usize, text_chars: &[char]) -> (String, usize, usize) {
    // Work on a Vec<char> so all operations stay in char-space.
    let mut chars: Vec<char> = word.chars().collect();

    // Strip trailing particles:
    //   while len(word) > 2 and word[-1] in _NOT_NAME_CHARS: word = word[:-1]
    while chars.len() > 2 && NOT_NAME_CHARS_SET.contains(chars.last().unwrap()) {
        chars.pop();
    }

    // if len(word) == 2 and word[-1] in _NOT_NAME_CHARS: return "", start, start
    if chars.len() == 2 && NOT_NAME_CHARS_SET.contains(chars.last().unwrap()) {
        return (String::new(), start, start);
    }

    // Strip if last char starts an honorific suffix in the following text:
    //   if len(word) == 3 and word[-1] in _HONORIFIC_HEADS:
    //       remaining = word[-1] + text[start + len(word) : start + len(word) + 2]
    //       if _HONORIFIC_SUFFIX.match(remaining): word = word[:2]
    if chars.len() == 3 && HONORIFIC_HEADS_SET.contains(chars.last().unwrap()) {
        let after_start = start + chars.len();
        let after_end = (start + chars.len() + 2).min(text_chars.len());
        let following_slice: String = if after_start <= text_chars.len() {
            text_chars[after_start..after_end].iter().collect()
        } else {
            String::new()
        };
        let remaining = format!("{}{}", chars[chars.len() - 1], following_slice);
        if HONORIFIC_SUFFIX.is_match(&remaining).unwrap_or(false) {
            chars.truncate(2);
        }
    }

    let len = chars.len();
    let trimmed: String = chars.into_iter().collect();
    (trimmed, start, start + len)
}

/// Find all surname + 1-2 CJK sequences, filtered by the negative dict.
///
/// Direct port of `generate_candidates(text)`. For 3-char single-surname
/// matches, emits both the 3-char and 2-char variants so the scoring/resolution
/// phase can pick the best one. Returns candidates sorted by `start`.
///
/// Takes BOTH `text: &str` (the fancy_regex `find_iter` for the compound +
/// single patterns runs on the whole text string) AND `chars: &[char]` (the
/// shared whole-text char slice, threaded into `trim_candidate` so its
/// following-text lookahead never re-collects the input).
pub(crate) fn generate_candidates(text: &str, chars: &[char]) -> Vec<NameCandidate> {
    if text.is_empty() {
        return Vec::new();
    }

    let neg = not_names_zh_set();
    let mut candidates: Vec<NameCandidate> = Vec::new();
    let mut seen_starts: HashSet<usize> = HashSet::new();

    // Mirror the Python `_emit` closure. `m_text` is the matched substring,
    // `m_start` is the match's CHAR start offset.
    //
    //   def _emit(m, is_compound=False):
    //       word, start, end = _trim_candidate(m.group(), m.start(), text)
    //       if not word or start in seen_starts: return
    //       variants = []
    //       prefix_blocked = len(word) == 3 and not is_compound and word[:2] in neg
    //       if word not in neg and not prefix_blocked:
    //           variants.append(NameCandidate(word, start, end))
    //       if len(word) == 3 and not is_compound:
    //           short = word[:2]
    //           if short not in neg:
    //               variants.append(NameCandidate(short, start, start + 2))
    //       if variants:
    //           candidates.extend(variants)
    //           seen_starts.add(start)
    let emit = |m_text: &str,
                m_start: usize,
                is_compound: bool,
                candidates: &mut Vec<NameCandidate>,
                seen_starts: &mut HashSet<usize>| {
        let (word, start, end) = trim_candidate(m_text, m_start, chars);
        if word.is_empty() || seen_starts.contains(&start) {
            return;
        }

        let word_chars: Vec<char> = word.chars().collect();
        let word_len = word_chars.len();
        let prefix2: String = word_chars.iter().take(2).collect();

        let mut variants: Vec<NameCandidate> = Vec::new();

        // The 2-char prefix being a known non-name blocks the 3-char extension.
        // (Computed BEFORE `word`/`prefix2` are moved into the variants below.)
        let prefix_blocked = word_len == 3 && !is_compound && neg.contains(&prefix2);
        if !neg.contains(&word) && !prefix_blocked {
            variants.push(NameCandidate { text: word, start, end });
        }
        // For 3-char single-surname matches, also offer the 2-char variant.
        if word_len == 3 && !is_compound && !neg.contains(&prefix2) {
            variants.push(NameCandidate { text: prefix2, start, end: start + 2 });
        }

        if !variants.is_empty() {
            candidates.extend(variants);
            seen_starts.insert(start);
        }
    };

    // Compound surnames first (longer match wins).
    //   for m in _COMPOUND_PAT.finditer(text): _emit(m, is_compound=True)
    for m in COMPOUND_PAT.find_iter(text) {
        let m = m.unwrap();
        let m_start = byte_to_char_offset(text, m.start());
        emit(m.as_str(), m_start, true, &mut candidates, &mut seen_starts);
    }

    // Single surnames — skip positions already claimed by compound matches.
    //   for m in _SINGLE_PAT.finditer(text):
    //       if m.start() in seen_starts: continue
    //       if any(m.start() >= c.start and m.end() <= c.end for c in candidates): continue
    //       _emit(m)
    for m in SINGLE_PAT.find_iter(text) {
        let m = m.unwrap();
        let m_start = byte_to_char_offset(text, m.start());
        let m_end = byte_to_char_offset(text, m.end());
        if seen_starts.contains(&m_start) {
            continue;
        }
        if candidates
            .iter()
            .any(|c| m_start >= c.start && m_end <= c.end)
        {
            continue;
        }
        emit(m.as_str(), m_start, false, &mut candidates, &mut seen_starts);
    }

    // candidates.sort(key=lambda c: c.start)
    candidates.sort_by_key(|c| c.start);
    candidates
}

// ── Evidence scoring ──
//
// Direct port of `score_candidate` (+ its constants) from `lang/zh/person.py`.
//
// ## Bit-identity
//
// The scores must match Python's f64 EXACTLY (the golden corpus locks values
// like `0.8999999999999999`). IEEE-754 addition is commutative but not
// associative, so the accumulation structure is mirrored line-for-line:
//   - `evidence` starts at `0.0` and each fired signal does `evidence += w`
//     in the SAME order as Python (context-prefix, honorific, PII-suffix,
//     paren-phone, then the single proximity bucket).
//   - the zero-evidence short-circuit (`evidence == 0.0 → 0.0`) runs BEFORE the
//     base is chosen, exactly as in Python.
//   - the final value is `(score + evidence).min(1.0)` — base first, evidence
//     second, then the cap — matching Python `min(score + evidence, 1.0)`.

/// `_CONTEXT_PREFIX` — context words immediately before the name (a strong
/// signal). Python applies this with `re.search` (unanchored); the pattern is
/// `$`-anchored at the end so it only matches at the tail of the `before`
/// window. fancy_regex `is_match` is a search, matching `re.search`.
static CONTEXT_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    let pat = concat!(
        r"(?:",
        // Formal role words
        r"客户|患者|用户|旅客|车主|联系人|收件人|寄件人|",
        r"登记人|开户人|申请人|报案人|委托人|当事人|嫌疑人|",
        r"负责人|经办人|签收人|担保人|受益人|借款人|",
        r"持卡人|被保险人|投保人|参会人员|",
        r"主治医生|医生|护士|教授|老板|同事|朋友|同学|",
        r"姓名|乘客|住户|业主|租户|房东|",
        // Conversational / intro phrases
        r"我是|我叫|这是|那是|找|叫做|叫作|本人|",
        r"通知|转告|联系|致电|询问",
        r")[：:\s\x1c-\x1f]?$"
    );
    Regex::new(pat)
        .unwrap_or_else(|e| panic!("person_zh: _CONTEXT_PREFIX compile failed: {e}"))
});

/// `_PII_SUFFIX` — possessive + PII-type keyword right after the name. Python
/// applies this with `re.match` (anchored at start); the pattern is also
/// `^`-anchored, so search ≡ match here.
static PII_SUFFIX: LazyLock<Regex> = LazyLock::new(|| {
    let pat = concat!(
        r"^(?:的(?:手机|电话|身份证|银行卡|账[户号]|地址|邮[箱件]|护照|车牌)|",
        r"[，,](?:身份证|电话|手机|银行卡))"
    );
    Regex::new(pat).unwrap_or_else(|e| panic!("person_zh: _PII_SUFFIX compile failed: {e}"))
});

/// `_PAREN_PHONE` — a parenthesized mobile number right after the name. Python
/// applies this with `re.match` (anchored); pattern is `^`-anchored.
static PAREN_PHONE: LazyLock<Regex> = LazyLock::new(|| {
    let pat = r"^[（(][\s\x1c-\x1f]*1[3-9]\d{9}";
    Regex::new(pat).unwrap_or_else(|e| panic!("person_zh: _PAREN_PHONE compile failed: {e}"))
});

/// `_CONTEXT_WINDOW` = 20 — number of **chars** (not bytes) of context examined
/// on each side of the candidate.
const CONTEXT_WINDOW: usize = 20;

// Signal weights — transcribed from `score_candidate`. Kept as named f64 consts
// so the `+=` order is auditable against the Python source.
const W_CONTEXT_PREFIX: f64 = 0.6;
const W_HONORIFIC_SUFFIX: f64 = 0.5;
const W_PII_SUFFIX: f64 = 0.5;
const W_PAREN_PHONE: f64 = 0.5;
const W_PROXIMITY_NEAR: f64 = 0.5; // distance <= 50
const W_PROXIMITY_MID: f64 = 0.3; // distance <= 150
const PROXIMITY_NEAR: usize = 50;
const PROXIMITY_MID: usize = 150;

// Base score by candidate length (in chars).
const BASE_LEN_4PLUS: f64 = 0.5;
const BASE_LEN_3: f64 = 0.4;
const BASE_LEN_2: f64 = 0.3;

/// Score a name candidate against multiple evidence signals.
///
/// Direct port of `score_candidate(candidate, text, *, pii_entities)`. Returns a
/// bit-identical f64 to the Python reference.
///
/// `chars` is the whole source text as a shared `&[char]` slice (collected once
/// by `detect_person_names` and threaded in, so per-candidate scoring no longer
/// re-materializes the entire input — mirrors `person_en.rs`). `candidate`
/// offsets are **char** offsets into `chars`; `pii_entities[i].start` / `.end`
/// are also char offsets (Python uses `pii.start` / `pii.end` directly). Only
/// `start`/`end` are read off each entity — the `type != "self_reference"`
/// filter lives in `detect_person_names` (T5), not here.
pub(crate) fn score_candidate(
    candidate: &NameCandidate,
    chars: &[char],
    pii_entities: &[PatternMatch],
) -> f64 {
    // before = text[max(0, candidate.start - _CONTEXT_WINDOW) : candidate.start]
    // after  = text[candidate.end : candidate.end + _CONTEXT_WINDOW]
    // These are CHAR slices in Python; compute them in char-space so a
    // multi-byte CJK window is never byte-sliced. `chars` is the shared
    // whole-text slice (no per-call re-collect).
    let text_chars = chars;
    let n = text_chars.len();

    let before_start = candidate.start.saturating_sub(CONTEXT_WINDOW);
    let before_end = candidate.start.min(n);
    let before: String = if before_start <= before_end {
        text_chars[before_start..before_end].iter().collect()
    } else {
        String::new()
    };

    let after_start = candidate.end.min(n);
    let after_end = (candidate.end + CONTEXT_WINDOW).min(n);
    let after: String = if after_start <= after_end {
        text_chars[after_start..after_end].iter().collect()
    } else {
        String::new()
    };

    // Collect evidence signals — same order as Python:
    //   evidence = 0.0
    //   if _CONTEXT_PREFIX.search(before):   evidence += 0.6
    //   if _HONORIFIC_SUFFIX.match(after):   evidence += 0.5
    //   if _PII_SUFFIX.match(after):         evidence += 0.5
    //   if _PAREN_PHONE.match(after):        evidence += 0.5
    let mut evidence = 0.0_f64;
    if CONTEXT_PREFIX.is_match(&before).unwrap_or(false) {
        evidence += W_CONTEXT_PREFIX;
    }
    if HONORIFIC_SUFFIX.is_match(&after).unwrap_or(false) {
        evidence += W_HONORIFIC_SUFFIX;
    }
    if PII_SUFFIX.is_match(&after).unwrap_or(false) {
        evidence += W_PII_SUFFIX;
    }
    if PAREN_PHONE.is_match(&after).unwrap_or(false) {
        evidence += W_PAREN_PHONE;
    }

    // Proximity to structural PII — first entity within a bucket wins (break).
    //   for pii in pii_entities:
    //       distance = min(abs(candidate.start - pii.end), abs(pii.start - candidate.end))
    //       if distance <= 50:    evidence += 0.5; break
    //       elif distance <= 150: evidence += 0.3; break
    //
    // `abs(...)` over usize char offsets — use abs_diff so subtraction never
    // underflows; abs_diff(a, b) == |a - b| matches Python's abs() on ints.
    for pii in pii_entities {
        let distance = candidate
            .start
            .abs_diff(pii.end)
            .min(pii.start.abs_diff(candidate.end));
        if distance <= PROXIMITY_NEAR {
            evidence += W_PROXIMITY_NEAR;
            break;
        } else if distance <= PROXIMITY_MID {
            evidence += W_PROXIMITY_MID;
            break;
        }
    }

    // No evidence signal → don't match at L1b (leave to L2 NER).
    //   if evidence == 0.0: return 0.0
    if evidence == 0.0_f64 {
        return 0.0;
    }

    // Base score by name length (chars) + evidence.
    //   if len(candidate.text) >= 4: score = 0.5
    //   elif len(candidate.text) == 3: score = 0.4
    //   else: score = 0.3
    let name_len = candidate.text.chars().count();
    let score = if name_len >= 4 {
        BASE_LEN_4PLUS
    } else if name_len == 3 {
        BASE_LEN_3
    } else {
        BASE_LEN_2
    };

    // return min(score + evidence, 1.0)
    (score + evidence).min(1.0)
}

// ── Variant resolution ──
//
// Direct port of `_resolve_variants` from `lang/zh/person.py`.

/// `_SCORE_THRESHOLD` — default minimum score to confirm a candidate. Exposed
/// so the binding layer (T7) can supply Python's `threshold=_SCORE_THRESHOLD`
/// keyword default; `detect_person_names` itself takes the threshold explicitly.
pub const SCORE_THRESHOLD: f64 = 0.8;

/// A start-position group: the candidates that share a start char offset, each
/// paired with its score. Kept as a `Vec` of `(start, variants)` so iteration
/// follows Python's insertion-ordered `dict` exactly (groups appear in the
/// order their start was first seen, which — since `generate_candidates` sorts
/// by start — is ascending start).
type Grouped = Vec<(usize, Vec<(NameCandidate, f64)>)>;

/// For each start position, pick the best variant above threshold.
///
/// Direct port of `_resolve_variants(grouped, text, threshold)`:
///
/// ```python
/// common = _load_common_words()
/// results = []
/// for _start, variants in grouped.items():
///     passing = [(c, s) for c, s in variants if s >= threshold]
///     if not passing:
///         continue
///     if len(passing) == 1:
///         results.append(passing[0])
///         continue
///     # Multiple variants: prefer longest, check for swallow
///     passing.sort(key=lambda x: -len(x[0].text))
///     best, best_score = passing[0]
///     if len(best.text) == 3:
///         last_char = best.text[-1]
///         after = text[best.end : best.end + 2]
///         following = last_char + after
///         swallowed = any(following[:i] in common for i in range(2, len(following) + 1))
///         if swallowed:
///             short = [(c, s) for c, s in passing if len(c.text) == 2]
///             if short:
///                 best, best_score = short[0]
///     results.append((best, best_score))
/// return results
/// ```
///
/// ## Bit-identity notes
///
/// - The `passing` filter is `s >= threshold` (a 0.8 score at the default 0.8
///   threshold passes).
/// - The longest-wins sort is `key=lambda x: -len(x[0].text)` — a STABLE sort
///   (Python `list.sort`), so equal-length variants keep insertion order. We
///   use `sort_by_key` (stable), NEVER `sort_unstable`.
/// - The swallow `after` is a CHAR slice `text[best.end : best.end+2]` that
///   Python clamps silently when it runs past the end; we OOB-guard with
///   `best.end + 2 <= char_len` and otherwise take whatever chars remain.
/// - `following[:i] for i in range(2, len(following)+1)` checks the length-2 up
///   to length-`len(following)` prefixes of `following`; when `following` has
///   fewer than 2 chars (i.e. no following char) the range is empty → no
///   swallow.
fn resolve_variants(
    grouped: &Grouped,
    chars: &[char],
    threshold: f64,
) -> Vec<(NameCandidate, f64)> {
    let common = common_words_zh_set();
    // `chars` is the shared whole-text char slice (no per-call re-collect).
    let text_chars = chars;
    let char_len = text_chars.len();
    let mut results: Vec<(NameCandidate, f64)> = Vec::new();

    for (_start, variants) in grouped {
        // passing = [(c, s) for c, s in variants if s >= threshold]
        let mut passing: Vec<(NameCandidate, f64)> = variants
            .iter()
            .filter(|(_, s)| *s >= threshold)
            .cloned()
            .collect();

        if passing.is_empty() {
            continue;
        }

        if passing.len() == 1 {
            results.push(passing.into_iter().next().unwrap());
            continue;
        }

        // Multiple variants: prefer longest (STABLE sort), check for swallow.
        //   passing.sort(key=lambda x: -len(x[0].text))
        passing.sort_by_key(|(c, _)| std::cmp::Reverse(c.text.chars().count()));
        let (mut best, mut best_score) = passing[0].clone();

        // if len(best.text) == 3:
        let best_len = best.text.chars().count();
        if best_len == 3 {
            let last_char = best.text.chars().next_back().unwrap();
            // after = text[best.end : best.end + 2]  (char slice, clamps at end)
            let after_start = best.end.min(char_len);
            let after_end = if best.end + 2 <= char_len {
                best.end + 2
            } else {
                char_len
            };
            let after: String = if after_start <= after_end {
                text_chars[after_start..after_end].iter().collect()
            } else {
                String::new()
            };
            // following = last_char + after
            let following: Vec<char> = {
                let mut v = vec![last_char];
                v.extend(after.chars());
                v
            };
            // swallowed = any(following[:i] in common for i in range(2, len(following)+1))
            // `(2..=following_len)` is empty when `following_len < 2` (matches the
            // Python `range(2, len+1)` empty case); `.any` short-circuits like the
            // original `break`.
            let following_len = following.len();
            let swallowed = (2..=following_len).any(|i| {
                let prefix: String = following[..i].iter().collect();
                common.contains(&prefix)
            });
            if swallowed {
                // short = [(c, s) for c, s in passing if len(c.text) == 2]
                // if short: best, best_score = short[0]
                if let Some((c, s)) = passing
                    .iter()
                    .find(|(c, _)| c.text.chars().count() == 2)
                {
                    best = c.clone();
                    best_score = *s;
                }
            }
        }

        results.push((best, best_score));
    }

    results
}

// ── Public API ──

/// Detect Chinese person names via candidate generation + evidence scoring.
///
/// Direct port of `detect_person_names(text, *, pii_entities, known_names,
/// threshold)`. The Python keyword-argument defaults (`pii_entities=None`,
/// `known_names=None`, `threshold=_SCORE_THRESHOLD`) are resolved at the binding
/// layer; here every argument is explicit. Pass an empty slice for "no
/// pii_entities" / "no known_names" and [`SCORE_THRESHOLD`] (0.8) for the
/// default threshold.
///
/// ```python
/// if not text:
///     return []
/// results = []
/// occupied = set()
/// if known_names:
///     for name in known_names:
///         if not name:
///             continue
///         for m in re.finditer(re.escape(name), text):
///             results.append(PatternMatch(text=name, type="person",
///                                         start=m.start(), end=m.end(),
///                                         confidence=1.0))
///             occupied.add((m.start(), m.end()))
/// candidates = generate_candidates(text)
/// structural_pii = ([p for p in pii_entities if p.type != "self_reference"]
///                   if pii_entities else None)
/// grouped = {}
/// for c in candidates:
///     if any(c.start >= s and c.end <= e for s, e in occupied):
///         continue
///     s = score_candidate(c, text, pii_entities=structural_pii)
///     grouped.setdefault(c.start, []).append((c, s))
/// for best, best_score in _resolve_variants(grouped, text, threshold):
///     results.append(PatternMatch(text=best.text, type="person",
///                                 start=best.start, end=best.end,
///                                 confidence=best_score))
/// results.sort(key=lambda r: r.start)
/// return results
/// ```
///
/// ## Bit-identity notes
///
/// - `PatternMatch` fields mirror Python exactly: `type_ = "person"`,
///   `confidence` = the score (1.0 for known names), `start`/`end` = char
///   offsets, and `layer = 0` — Python's `detect_person_names` constructs
///   `PatternMatch(...)` WITHOUT a `layer` kwarg, so the dataclass default
///   (`layer = 0`) applies.
/// - known_names are matched FIRST via a (non-overlapping) `re.finditer` of the
///   escaped name and appended at `confidence = 1.0`, each claiming an
///   `(start, end)` occupied span.
/// - The occupancy test skips a candidate fully contained in an occupied span:
///   `c.start >= s && c.end <= e`.
/// - The pii_entities filter drops entries whose `type == "self_reference"`
///   BEFORE scoring (the scorer itself does not filter).
/// - The final sort is STABLE by `start` (Python `list.sort`), so for an equal
///   start a known-name result (appended first) precedes a candidate result.
pub fn detect_person_names(
    text: &str,
    pii_entities: &[PatternMatch],
    known_names: &[String],
    threshold: f64,
) -> Vec<PatternMatch> {
    if text.is_empty() {
        return Vec::new();
    }

    // Materialize the whole text as a char slice ONCE, then thread `&chars`
    // through candidate generation, scoring and variant resolution — mirroring
    // `person_en.rs`. Previously each helper re-collected `text.chars()`, making
    // per-candidate scoring O(candidates × n) on dense-CJK input.
    let chars: Vec<char> = text.chars().collect();

    let mut results: Vec<PatternMatch> = Vec::new();
    // occupied spans as (start, end) char offsets, in insertion order (a Vec is
    // enough — membership is tested by a linear `any`, mirroring the Python set
    // comprehension, and the order does not affect the boolean result).
    let mut occupied: Vec<(usize, usize)> = Vec::new();

    // Known names — exact match, bypass scoring.
    if !known_names.is_empty() {
        for name in known_names {
            if name.is_empty() {
                continue;
            }
            // re.finditer(re.escape(name), text) — non-overlapping, char offsets.
            let pat = fancy_regex::escape(name);
            // fancy_regex (regex-automata) has a ~10MB compiled-size cap, so a
            // pathological multi-MB single name returns Err. Python's `re` never
            // errors here — it compiles even a huge literal and simply finds no
            // match. Match that parity by skipping only the uncompilable name;
            // every compilable name still matches exactly as before, keeping the
            // normal-case output byte-identical. (Such a name cannot appear in a
            // ≤1MB text anyway, so skipping it == Python's effective no-match.)
            let re = match Regex::new(&pat) {
                Ok(re) => re,
                Err(_) => continue,
            };
            for m in re.find_iter(text) {
                let m = m.unwrap();
                let start = byte_to_char_offset(text, m.start());
                let end = byte_to_char_offset(text, m.end());
                results.push(PatternMatch {
                    text: name.clone(),
                    type_: "person".to_string(),
                    start,
                    end,
                    confidence: 1.0,
                    layer: 0,
                });
                occupied.push((start, end));
            }
        }
    }

    // Candidate generation → scoring → variant resolution.
    let candidates = generate_candidates(text, &chars);

    // Filter self_reference from PII entities (not structural PII for proximity
    // scoring). Python passes `None` when pii_entities is empty/None; an empty
    // slice is equivalent for the scorer (the `if pii_entities:` proximity guard
    // simply doesn't fire), so we always pass a (possibly empty) slice.
    let structural_pii: Vec<PatternMatch> = pii_entities
        .iter()
        .filter(|p| p.type_ != "self_reference")
        .cloned()
        .collect();

    // grouped: dict[start] -> list[(candidate, score)], insertion-ordered.
    //
    // `generate_candidates` returns candidates STABLE-sorted by `start`, and the
    // occupancy filter below only REMOVES elements (order preserved), so equal
    // starts are already contiguous. A linear adjacent-grouping pass therefore
    // reproduces Python's insertion-ordered `dict.setdefault` exactly: each new
    // start opens a fresh bucket, equal-start candidates append to the last
    // bucket. (No HashMap index needed.)
    let mut grouped: Grouped = Vec::new();
    for c in candidates {
        // if any(c.start >= s and c.end <= e for s, e in occupied): continue
        if occupied.iter().any(|&(s, e)| c.start >= s && c.end <= e) {
            continue;
        }
        let s = score_candidate(&c, &chars, &structural_pii);
        // grouped.setdefault(c.start, []).append((c, s))
        match grouped.last_mut() {
            Some((start, variants)) if *start == c.start => variants.push((c, s)),
            _ => {
                let start = c.start;
                grouped.push((start, vec![(c, s)]));
            }
        }
    }

    for (best, best_score) in resolve_variants(&grouped, &chars, threshold) {
        results.push(PatternMatch {
            text: best.text,
            type_: "person".to_string(),
            start: best.start,
            end: best.end,
            confidence: best_score,
            layer: 0,
        });
    }

    // results.sort(key=lambda r: r.start) — STABLE.
    results.sort_by_key(|r| r.start);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: assert generate_candidates output equals the expected
    // (text, start, end) triples in order.
    fn assert_candidates(input: &str, expected: &[(&str, usize, usize)]) {
        let chars: Vec<char> = input.chars().collect();
        let got: Vec<(String, usize, usize)> = generate_candidates(input, &chars)
            .into_iter()
            .map(|c| (c.text, c.start, c.end))
            .collect();
        let exp: Vec<(String, usize, usize)> = expected
            .iter()
            .map(|(t, s, e)| (t.to_string(), *s, *e))
            .collect();
        assert_eq!(got, exp, "input: {input:?}");
    }

    // ── Expected values below were CAPTURED FROM THE LIVE PYTHON reference ──
    // For each input we ran:
    //   python -c "from argus_redact.lang.zh.person import generate_candidates as g; \
    //     print([(c.text,c.start,c.end) for c in g('INPUT')])"
    // and hard-coded the exact output here, so the Rust port is golden-locked
    // to the Python behavior.

    #[test]
    fn single_surname_two_char_name() {
        // "联系张三吧" — 张三 at chars 2..4; trailing 吧 is a particle that ends
        // the regex match, so only 张三 is produced.
        // Python: [('张三', 2, 4)]
        assert_candidates("联系张三吧", &[("张三", 2, 4)]);
    }

    #[test]
    fn single_surname_three_char_emits_two_and_three() {
        // "我叫何秀珍" — 3-char single-surname name: emits both 3-char and
        // 2-char variant at the same start.
        // Python: [('何秀珍', 2, 5), ('何秀', 2, 4)]
        assert_candidates("我叫何秀珍", &[("何秀珍", 2, 5), ("何秀", 2, 4)]);
    }

    #[test]
    fn compound_surname_name() {
        // "找欧阳娜娜" — compound surname 欧阳 + 娜娜; compound matches are NOT
        // split into a 2-char variant (is_compound=True).
        // Python: [('欧阳娜娜', 1, 5)]
        assert_candidates("找欧阳娜娜", &[("欧阳娜娜", 1, 5)]);
    }

    #[test]
    fn trailing_particle_trimmed() {
        // "张明的手机" — greedy match grabs 张明的, trim strips trailing 的,
        // leaving 张明 (chars 0..2).
        // Python: [('张明', 0, 2)]
        assert_candidates("张明的手机", &[("张明", 0, 2)]);
    }

    #[test]
    fn honorific_head_not_trimmed_when_head_is_third_char() {
        // "王先生你好" — greedy single-pat match is 王先生. The honorific-head
        // trim only fires when word[-1] (the 3rd char) is in _HONORIFIC_HEADS;
        // here word[-1] is 生 (NOT a head — the head is 先), so NO trim, and the
        // 3-char + 2-char variants are both emitted.
        // Python: [('王先生', 0, 3), ('王先', 0, 2)]
        assert_candidates("王先生你好", &[("王先生", 0, 3), ("王先", 0, 2)]);
    }

    #[test]
    fn honorific_head_trimmed_when_suffix_matches() {
        // "张大哥来了" — greedy match 张大哥 (chars 0..3). word[-1] is 哥, which IS
        // in _HONORIFIC_HEADS, and remaining = "哥" + "来了" matches the single-
        // char honorific 哥 (^哥 in _HONORIFIC_SUFFIX) → trim to 张大. The word is
        // now 2 chars, so only the 2-char candidate is emitted.
        // Python: [('张大', 0, 2)]
        assert_candidates("张大哥来了", &[("张大", 0, 2)]);
    }

    #[test]
    fn negative_dict_filtered() {
        // "在王国里面" — 王国 is in the negative dict (NOT a name). The 3-char
        // greedy match 王国里 → 2-char prefix 王国 is in neg (prefix_blocked),
        // and 王国 itself filtered; 王国里 also blocked. No name emitted here.
        // Python: [] (王国 filtered, prefix-block kills the 3-char)
        assert_candidates("在王国里面", &[]);
    }

    #[test]
    fn emoji_prefixed_char_offsets() {
        // Multi-byte emoji prefix to exercise char-vs-byte offset conversion.
        // "🎉联系张三吧" — 张三 now at char offset 3..5 (emoji is 1 char,
        // 4 bytes). If byte offsets leaked, start would be wrong.
        // Python: [('张三', 3, 5)]
        assert_candidates("🎉联系张三吧", &[("张三", 3, 5)]);
    }

    #[test]
    fn adjacent_overlapping_surname_starts() {
        // "张三李四" — both 张 and 李 are surnames, but finditer is
        // non-overlapping: the greedy match at 0 is 张三李 (张 + 2 CJK), which
        // consumes 李 at index 2. The next scan position is char 3 (四, not a
        // surname), so 李四 is never produced. Emits 张三李 + the 张三 variant.
        // Python: [('张三李', 0, 3), ('张三', 0, 2)]
        assert_candidates("张三李四", &[("张三李", 0, 3), ("张三", 0, 2)]);
    }

    #[test]
    fn three_char_variant_pair() {
        // "高金水" — bare 3-char single-surname name, no trailing context.
        // Emits the 3-char and 2-char variants at the same start.
        // Python: [('高金水', 0, 3), ('高金', 0, 2)]
        assert_candidates("高金水", &[("高金水", 0, 3), ("高金", 0, 2)]);
    }

    #[test]
    fn empty_input() {
        assert_candidates("", &[]);
    }

    // ── score_candidate — bit-identity golden tests ──
    //
    // EVERY expected f64 below was CAPTURED FROM LIVE PYTHON and is asserted with
    // EXACT `==` (not approx). IEEE-754 addition is not associative, so the float
    // values (e.g. `0.8999999999999999`) pin the accumulation order. Capture
    // command (pyenv 3.11.3):
    //   python3 - <<'PY'
    //   from argus_redact.lang.zh.person import score_candidate, NameCandidate
    //   from argus_redact._types import PatternMatch
    //   def find(text, sub):
    //       i = text.index(sub); return NameCandidate(sub, i, i+len(sub))
    //   print(repr(score_candidate(find("客户张三","张三"), "客户张三",
    //                              pii_entities=None)))
    //   PY
    // (proximity cases build a NameCandidate at a known char offset over a neutral
    // filler text and a PatternMatch at a computed start/end — see comments).

    fn cand(text: &str, start: usize, end: usize) -> NameCandidate {
        NameCandidate { text: text.to_string(), start, end }
    }

    fn pii(start: usize, end: usize) -> PatternMatch {
        PatternMatch {
            text: "x".to_string(),
            type_: "phone".to_string(),
            start,
            end,
            confidence: 1.0,
            layer: 1,
        }
    }

    // Test wrapper: collect the whole text into the shared char slice (as
    // `detect_person_names` does once at runtime) and forward to the
    // `&[char]`-taking `score_candidate`.
    fn score(candidate: &NameCandidate, text: &str, pii_entities: &[PatternMatch]) -> f64 {
        let chars: Vec<char> = text.chars().collect();
        score_candidate(candidate, &chars, pii_entities)
    }

    // ── Base-by-length (each carries a context-prefix signal so it doesn't zero
    //    out). These also exercise the cap at 1.0 for len 3/4. ──

    #[test]
    fn base_len2_context_prefix() {
        // "我的客户张三你好" — 张三 at chars 4..6; before window ends with "客户"
        // → context-prefix fires. base 0.3 + 0.6 = 0.8999999999999999 (the
        // classic non-associative float — locks accumulation order).
        // Python: 0.8999999999999999
        let s = score(&cand("张三", 4, 6), "我的客户张三你好", &[]);
        assert_eq!(s, 0.8999999999999999);
    }

    #[test]
    fn base_len3_context_prefix_caps() {
        // "我的客户何秀珍来电" — 何秀珍 at 4..7. base 0.4 + 0.6 = 1.0.
        // Python: 1.0
        let s = score(&cand("何秀珍", 4, 7), "我的客户何秀珍来电", &[]);
        assert_eq!(s, 1.0);
    }

    #[test]
    fn base_len4_context_prefix_caps() {
        // "我的客户欧阳娜娜来电" — 欧阳娜娜 (compound) at 4..8. base 0.5 + 0.6 = 1.1
        // → capped to 1.0.
        // Python: 1.0
        let s = score(&cand("欧阳娜娜", 4, 8), "我的客户欧阳娜娜来电", &[]);
        assert_eq!(s, 1.0);
    }

    // ── Each signal in isolation (2-char base 0.3). ──

    #[test]
    fn signal_context_prefix_only() {
        // "客户张三" — before="客户" → context-prefix. base 0.3 + 0.6.
        // Python: 0.8999999999999999
        let s = score(&cand("张三", 2, 4), "客户张三", &[]);
        assert_eq!(s, 0.8999999999999999);
    }

    #[test]
    fn signal_honorific_suffix_only() {
        // "张三先生你好" — after="先生你好...", honorific 先生 matches. 0.3 + 0.5.
        // Python: 0.8
        let s = score(&cand("张三", 0, 2), "张三先生你好", &[]);
        assert_eq!(s, 0.8);
    }

    #[test]
    fn signal_pii_suffix_only() {
        // "张三的手机号码" — after="的手机号码" → PII-suffix 的手机. 0.3 + 0.5.
        // Python: 0.8
        let s = score(&cand("张三", 0, 2), "张三的手机号码", &[]);
        assert_eq!(s, 0.8);
    }

    #[test]
    fn signal_paren_phone_only() {
        // "张三（13812345678）" — after starts with （138... → paren-phone. 0.3+0.5.
        // Python: 0.8
        let s = score(&cand("张三", 0, 2), "张三（13812345678）", &[]);
        assert_eq!(s, 0.8);
    }

    // ── Proximity buckets — boundary cases 49/50/51 and 149/150/151.
    //    Candidate "甲甲" at chars 200..202 over a 400-char neutral filler (no
    //    regex signal fires). The PII entity is placed AFTER the candidate so
    //    distance = pii.start - candidate.end. base 0.3 + bucket weight. ──

    fn prox_after(distance: usize) -> f64 {
        let text: String = "甲".repeat(400);
        let c = cand("甲甲", 200, 202);
        let ps = 202 + distance; // pii.start - candidate.end == distance
        let p = pii(ps, ps + 5);
        score(&c, &text, &[p])
    }

    fn prox_before(distance: usize) -> f64 {
        let text: String = "甲".repeat(400);
        let c = cand("甲甲", 200, 202);
        let pe = 200 - distance; // candidate.start - pii.end == distance
        let p = pii(pe - 5, pe);
        score(&c, &text, &[p])
    }

    #[test]
    fn proximity_after_boundaries() {
        // <= 50 → +0.5 (0.8); 51..=150 → +0.3 (0.6); > 150 → 0.0 (zero evidence).
        // Python: 49→0.8, 50→0.8, 51→0.6, 149→0.6, 150→0.6, 151→0.0
        assert_eq!(prox_after(49), 0.8);
        assert_eq!(prox_after(50), 0.8);
        assert_eq!(prox_after(51), 0.6);
        assert_eq!(prox_after(149), 0.6);
        assert_eq!(prox_after(150), 0.6);
        assert_eq!(prox_after(151), 0.0);
    }

    #[test]
    fn proximity_before_boundaries() {
        // Same buckets measured on the entity-before gap.
        // Python: 49→0.8, 50→0.8, 51→0.6, 149→0.6, 150→0.6, 151→0.0
        assert_eq!(prox_before(49), 0.8);
        assert_eq!(prox_before(50), 0.8);
        assert_eq!(prox_before(51), 0.6);
        assert_eq!(prox_before(149), 0.6);
        assert_eq!(prox_before(150), 0.6);
        assert_eq!(prox_before(151), 0.0);
    }

    // ── Zero-evidence short-circuit → 0.0. ──

    #[test]
    fn zero_evidence_no_signals() {
        // Neutral filler, no PII → evidence == 0.0 → 0.0.
        // Python: 0.0
        let text: String = "甲".repeat(400);
        let s = score(&cand("甲甲", 200, 202), &text, &[]);
        assert_eq!(s, 0.0);
    }

    #[test]
    fn zero_evidence_far_pii() {
        // PII far beyond the 150 bucket → no proximity signal → 0.0.
        // Python: 0.0
        assert_eq!(prox_after(200), 0.0);
    }

    // ── Below-cap base + single signal (clean stacking witnesses). ──

    #[test]
    fn len3_proximity_mid_bucket() {
        // 何秀珍 (3 chars) at 200..203 + PII at distance 150 → base 0.4 + 0.3 = 0.7.
        // Python: 0.7
        let text: String = "甲".repeat(400);
        let c = cand("何秀珍", 200, 203);
        let p = pii(203 + 150, 203 + 155);
        assert_eq!(score(&c, &text, &[p]), 0.7);
    }

    #[test]
    fn len4_proximity_mid_bucket() {
        // 欧阳娜娜 (4 chars) at 200..204 + PII at distance 150 → base 0.5 + 0.3 = 0.8.
        // Python: 0.8
        let text: String = "甲".repeat(400);
        let c = cand("欧阳娜娜", 200, 204);
        let p = pii(204 + 150, 204 + 155);
        assert_eq!(score(&c, &text, &[p]), 0.8);
    }

    #[test]
    fn len3_honorific() {
        // 何秀珍 + 先生 → base 0.4 + 0.5 = 0.9.
        // Python: 0.9
        let s = score(&cand("何秀珍", 0, 3), "何秀珍先生你好", &[]);
        assert_eq!(s, 0.9);
    }

    #[test]
    fn len3_pii_suffix() {
        // 何秀珍 + 的手机 → base 0.4 + 0.5 = 0.9.
        // Python: 0.9
        let s = score(&cand("何秀珍", 0, 3), "何秀珍的手机号码", &[]);
        assert_eq!(s, 0.9);
    }

    // ── MULTIPLE signals stacking — exercise multi-term f64 accumulation order
    //    AND the cap at 1.0. ──

    #[test]
    fn multi_signal_context_prefix_plus_honorific_caps() {
        // "客户何秀珍先生你好" — 何秀珍 at 2..5. before="客户" (context-prefix +0.6),
        // after="先生你好..." (honorific +0.5). evidence accumulates 0.6 then 0.5;
        // base 0.4 + 1.1 = 1.5 → capped 1.0.
        // Python: 1.0
        let s = score(&cand("何秀珍", 2, 5), "客户何秀珍先生你好", &[]);
        assert_eq!(s, 1.0);
    }

    #[test]
    fn multi_signal_context_prefix_plus_pii_suffix_plus_proximity_caps() {
        // "请联系客户张三的手机号码" — 张三 at 5..7. before ends "客户" (+0.6),
        // after="的手机号码" (PII-suffix +0.5), plus a nearby PII entity (+0.5).
        // Three evidence terms accumulate (0.6, 0.5, 0.5); base 0.3 + 1.6 → cap 1.0.
        // Python: 1.0
        let text = "请联系客户张三的手机号码";
        let c = cand("张三", 5, 7);
        let p = pii(9, 20); // within 50 chars of the candidate
        assert_eq!(score(&c, text, &[p]), 1.0);
    }

    // ── detect_person_names — orchestrator golden tests ──
    //
    // Inputs are drawn from the engineered T1 golden corpus
    // (tests/core/fixtures/zh_person_detection_v076.json) AND the behavioral
    // corpus (tests/fixtures/zh_person.json), plus a handful of orchestrator
    // edge cases (multiple known-name hits, candidate-inside-occupied skip,
    // multi-name texts). EVERY expected tuple below — including the EXACT f64
    // confidence (asserted with `==`) — was CAPTURED FROM LIVE PYTHON
    // (pyenv 3.11.3) via:
    //
    //   python3 - <<'PY'
    //   from argus_redact.lang.zh.person import detect_person_names as d
    //   from argus_redact._types import PatternMatch
    //   res = d(text, pii_entities=pii, known_names=known, threshold=thr)
    //   print([(m.text, m.start, m.end, m.confidence, m.type, m.layer) for m in res])
    //   PY
    //
    // The fixture cases were fed through the SAME entry point with their own
    // pii_entities / known_names / threshold fields. Python builds each result
    // as PatternMatch(text, type="person", start, end, confidence) with NO
    // `layer` kwarg, so layer defaults to 0 — every expected row carries
    // type "person" + layer 0.

    fn pm(start: usize, end: usize, ty: &str) -> PatternMatch {
        PatternMatch {
            text: "x".to_string(),
            type_: ty.to_string(),
            start,
            end,
            confidence: 1.0,
            layer: 1,
        }
    }

    /// (text, start, end, confidence) projection — confidence compared EXACTLY.
    fn detect(
        text: &str,
        pii: &[PatternMatch],
        known: &[&str],
        thr: f64,
    ) -> Vec<(String, usize, usize, f64)> {
        let known: Vec<String> = known.iter().map(|s| s.to_string()).collect();
        detect_person_names(text, pii, &known, thr)
            .into_iter()
            .map(|m| {
                // Every result must be type="person", layer=0 (Python defaults).
                assert_eq!(m.type_, "person");
                assert_eq!(m.layer, 0);
                (m.text, m.start, m.end, m.confidence)
            })
            .collect()
    }

    #[test]
    fn detect_default_threshold() {
        assert_eq!(SCORE_THRESHOLD, 0.8);
    }

    #[test]
    fn detect_basic_two_char() {
        // T1 zh_corpus_person_basic_two_char "客户张三的手机号是13812345678".
        // Python: [('张三', 2, 4, 1.0)]
        assert_eq!(
            detect("客户张三的手机号是13812345678", &[], &[], 0.8),
            vec![("张三".to_string(), 2, 4, 1.0)]
        );
    }

    #[test]
    fn detect_basic_three_char() {
        // T1 zh_corpus_person_basic_three_char "联系人王小明，电话13912345678".
        // Python: [('王小明', 3, 6, 1.0)]
        assert_eq!(
            detect("联系人王小明，电话13912345678", &[], &[], 0.8),
            vec![("王小明".to_string(), 3, 6, 1.0)]
        );
    }

    #[test]
    fn detect_variant_tie_prefer_three_char() {
        // T1 zh_variant_tie_prefer_3char "客户何秀珍已登记" — both 何秀珍 and 何秀
        // pass; longest-wins keeps the 3-char (no swallow).
        // Python: [('何秀珍', 2, 5, 1.0)]
        assert_eq!(
            detect("客户何秀珍已登记", &[], &[], 0.8),
            vec![("何秀珍".to_string(), 2, 5, 1.0)]
        );
    }

    #[test]
    fn detect_swallow_prefer_two_char() {
        // T1 zh_swallow_prefer_2char "张三预订了机票" with a phone PII at 0..0.
        // 张三预 swallowed "预订" (a common word) → drop to 张三. Score lands
        // exactly at the 0.8 threshold via the proximity bucket.
        // Python: [('张三', 0, 2, 0.8)]
        let pii = [pm(0, 0, "phone")];
        assert_eq!(
            detect("张三预订了机票", &pii, &[], 0.8),
            vec![("张三".to_string(), 0, 2, 0.8)]
        );
    }

    #[test]
    fn detect_threshold_boundary_passes_at_0_8() {
        // T1 zh_float_2char_strong_at_threshold — 张明 + phone exactly within the
        // 50-char proximity bucket → score 0.8, which passes `>= 0.8`.
        // Python: [('张明', 0, 2, 0.8)]
        let text: String = format!("张明{}", "，".repeat(50));
        // phone placed so distance(candidate, pii) == 50 (start 52, len 11).
        let pii = [pm(52, 63, "phone")];
        assert_eq!(
            detect(&text, &pii, &[], 0.8),
            vec![("张明".to_string(), 0, 2, 0.8)]
        );
    }

    #[test]
    fn detect_threshold_boundary_fails_below_0_8() {
        // T1 zh_float_2char_weak_below_threshold — same 张明 but the phone is in
        // the mid bucket (distance 120) → score 0.6 < 0.8 → no match.
        // Python: []
        let text: String = format!("张明{}", "，".repeat(120));
        let pii = [pm(122, 133, "phone")];
        assert!(detect(&text, &pii, &[], 0.8).is_empty());
    }

    #[test]
    fn detect_non_default_threshold_0_7() {
        // T1 zh_threshold_0_7_passes_3char — 何秀珍 + phone in mid bucket → 0.7,
        // which fails the default 0.8 but passes a 0.7 threshold (`>=`).
        // Python: [('何秀珍', 0, 3, 0.7)]
        let text: String = format!("何秀珍{}", "，".repeat(120));
        let pii = [pm(123, 134, "phone")];
        assert_eq!(
            detect(&text, &pii, &[], 0.7),
            vec![("何秀珍".to_string(), 0, 3, 0.7)]
        );
    }

    #[test]
    fn detect_known_names_bypass() {
        // T1 zh_known_names_bypass "下午和高明开会讨论方案", known=['高明'] →
        // exact match at confidence 1.0, bypassing scoring.
        // Python: [('高明', 3, 5, 1.0)]
        assert_eq!(
            detect("下午和高明开会讨论方案", &[], &["高明"], 0.8),
            vec![("高明".to_string(), 3, 5, 1.0)]
        );
    }

    #[test]
    fn detect_known_names_multiple_occurrences() {
        // "高明和高明", known=['高明'] — non-overlapping finditer yields two hits,
        // each claiming its own occupied span; both emitted at 1.0.
        // Python: [('高明', 0, 2, 1.0), ('高明', 3, 5, 1.0)]
        assert_eq!(
            detect("高明和高明", &[], &["高明"], 0.8),
            vec![
                ("高明".to_string(), 0, 2, 1.0),
                ("高明".to_string(), 3, 5, 1.0),
            ]
        );
    }

    #[test]
    fn detect_known_name_occupies_candidate_span() {
        // "客户张三的手机号13800000000", known=['张三'] — the scored candidate 张三
        // at 2..4 is fully inside the occupied span (2..4) and is skipped; only
        // the known-name result (confidence 1.0) survives.
        // Python: [('张三', 2, 4, 1.0)]
        assert_eq!(
            detect("客户张三的手机号13800000000", &[], &["张三"], 0.8),
            vec![("张三".to_string(), 2, 4, 1.0)]
        );
    }

    #[test]
    fn detect_self_reference_filtered() {
        // T1 zh_self_reference_filtered — the only PII entity is a
        // self_reference, which is dropped before proximity scoring → 张明 gets
        // no evidence → no match.
        // Python: []
        let text: String = format!("张明{}13812345678", "，".repeat(200));
        let pii = [pm(3, 4, "self_reference")];
        assert!(detect(&text, &pii, &[], 0.8).is_empty());
    }

    #[test]
    fn detect_self_reference_filtered_phone_survives() {
        // self_reference dropped, but a real phone within 50 chars survives the
        // filter → 客户张三 still scores via context-prefix + proximity → 1.0.
        // Python: [('张三', 2, 4, 1.0)]
        let pii = [pm(0, 1, "self_reference"), pm(4, 15, "phone")];
        assert_eq!(
            detect("客户张三", &pii, &[], 0.8),
            vec![("张三".to_string(), 2, 4, 1.0)]
        );
    }

    #[test]
    fn detect_emoji_offset_char_space() {
        // T1 zh_emoji_offset "😀客户张明的手机号13812345678" — the emoji is 1 char
        // (4 bytes); offsets must be char-space, so 张明 is at 3..5.
        // Python: [('张明', 3, 5, 1.0)]
        assert_eq!(
            detect("😀客户张明的手机号13812345678", &[], &[], 0.8),
            vec![("张明".to_string(), 3, 5, 1.0)]
        );
    }

    #[test]
    fn detect_emoji_offset_multi() {
        // T1 zh_emoji_offset_multi "🎉🎊客户李芳，电话13912345678" — two emoji
        // prefix → 李芳 at char 4..6.
        // Python: [('李芳', 4, 6, 1.0)]
        assert_eq!(
            detect("🎉🎊客户李芳，电话13912345678", &[], &[], 0.8),
            vec![("李芳".to_string(), 4, 6, 1.0)]
        );
    }

    #[test]
    fn detect_compound_vs_single() {
        // T1 zh_compound_vs_single "客户欧阳明已登记" — compound surname 欧阳 +
        // 明; compound matches are not split into a 2-char variant.
        // Python: [('欧阳明', 2, 5, 1.0)]
        assert_eq!(
            detect("客户欧阳明已登记", &[], &[], 0.8),
            vec![("欧阳明".to_string(), 2, 5, 1.0)]
        );
    }

    #[test]
    fn detect_particle_trim_float_confidence() {
        // T1 zh_particle_trim "客户张明了解情况" — greedy 张明了 trims trailing 了
        // → 张明 (2 chars). context-prefix only → 0.3 + 0.6 = 0.8999999999999999
        // (the non-associative float pins accumulation order through the
        // orchestrator).
        // Python: [('张明', 2, 4, 0.8999999999999999)]
        assert_eq!(
            detect("客户张明了解情况", &[], &[], 0.8),
            vec![("张明".to_string(), 2, 4, 0.8999999999999999)]
        );
    }

    #[test]
    fn detect_proximity_through_orchestrator() {
        // Bare "张三" with a phone PII entity adjacent (start 2) → proximity-only
        // evidence (distance 0) → 0.3 + 0.5 = 0.8 → passes.
        // Python: [('张三', 0, 2, 0.8)]
        let pii = [pm(2, 13, "phone")];
        assert_eq!(
            detect("张三", &pii, &[], 0.8),
            vec![("张三".to_string(), 0, 2, 0.8)]
        );
    }

    #[test]
    fn detect_multiple_names_final_sort_by_start() {
        // "客户张三和联系人李芳，电话13800000000" — two scored names; results are
        // STABLE-sorted by start. The phone at 13..24 is within the 50-char
        // proximity bucket of BOTH names, so each gets context-prefix (+0.6) +
        // proximity (+0.5) on top of its base, capping at 1.0.
        // Python: [('张三', 2, 4, 1.0), ('李芳', 8, 10, 1.0)]
        let pii = [pm(13, 24, "phone")];
        assert_eq!(
            detect("客户张三和联系人李芳，电话13800000000", &pii, &[], 0.8),
            vec![
                ("张三".to_string(), 2, 4, 1.0),
                ("李芳".to_string(), 8, 10, 1.0),
            ]
        );
    }

    #[test]
    fn detect_no_match_generic_text() {
        // T1 zh_corpus_no_person_generic "今天天气不错" — no surname-led
        // candidate with evidence → no match.
        // Python: []
        assert!(detect("今天天气不错", &[], &[], 0.8).is_empty());
    }

    #[test]
    fn detect_no_match_bare_name_no_evidence() {
        // Behavioral corpus no_person_standalone "张三说了话" — a real name but no
        // structural evidence → L1b declines (leaves it to L2 NER).
        // Python: []
        assert!(detect("张三说了话", &[], &[], 0.8).is_empty());
    }

    #[test]
    fn detect_empty_text() {
        assert!(detect("", &[], &[], 0.8).is_empty());
    }

    #[test]
    fn pathological_known_name_does_not_panic() {
        // A known_names list mixing a PATHOLOGICAL oversized CJK name with a normal
        // name: the oversized name's escaped pattern exceeds fancy_regex's compiled-
        // size cap and Regex::new returns Err. The pre-port Python `re` never errors
        // here, so we must NOT panic — the per-name loop `continue`s past the
        // uncompilable name. The normal name still matches exactly at confidence
        // 1.0; the oversized name (which cannot occur in a bounded text) matches
        // nothing.
        let huge: String = std::iter::repeat('张').take(500_000).collect();
        // Sanity: the oversized name alone is what trips the compiler — proves the
        // skip path is actually exercised, not dead code.
        assert!(
            Regex::new(&fancy_regex::escape(&huge)).is_err(),
            "expected the oversized literal to exceed fancy_regex's size cap"
        );
        let got = detect("联系李雷", &[], &[&huge, "李雷"], 0.8);
        // 李雷 is matched at 1.0 (known name); the oversized name matches nothing.
        assert_eq!(got, vec![("李雷".to_string(), 2, 4, 1.0)]);
    }
}
