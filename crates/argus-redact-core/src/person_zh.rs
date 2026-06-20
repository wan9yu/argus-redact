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

/// `_COMPOUND_PAT` — compound surname (alternation) + 1-3 CJK chars.
///
/// Built as `(?:s1|s2|...)[一-鿿]{1,3}` with each compound surname
/// `re.escape`-d. The compound pool is 2-char CJK literals (nothing to escape),
/// but we escape anyway. The `{1,3}` upper bound (raised from `{1,2}`) lets a
/// compound surname carry a triple given name such as `欧阳娜娜娜` (compound
/// `欧阳` + `娜娜娜`). The golden regeneration confirmed this is a net recall
/// gain with no spurious matches (the evidence scorer still gates every
/// candidate), so COMPOUND stays at `{1,3}` rather than reverting to `{1,2}`.
static COMPOUND_PAT: LazyLock<Regex> = LazyLock::new(|| {
    let alt = compound_surnames_zh()
        .iter()
        .map(|s| fancy_regex::escape(s).into_owned())
        .collect::<Vec<_>>()
        .join("|");
    let pat = format!(r"(?:{alt})[{CJK}]{{1,3}}");
    Regex::new(&pat)
        .unwrap_or_else(|e| panic!("person_zh: _COMPOUND_PAT compile failed: {e}\nPattern: {pat}"))
});

/// `_SINGLE_PAT` — single surname char class + 1-3 CJK chars.
///
/// `re.compile(r"[" + SURNAMES + r"][" + _CJK + r"]{1,3}")`. `SURNAMES` is the
/// byte-for-byte single-char surname string used as a char class body. The
/// `{1,3}` upper bound (raised from `{1,2}`) lets a single surname carry a
/// 3-char given name such as a foreign transliteration `马尔克斯` (`马` +
/// `尔克斯`). `generate_candidates` then offers the 4-char word plus shorter
/// prefix variants so the scorer / variant resolver can pick the right length;
/// `interior_name_len` truncates over-grabbed particle / honorific tails.
///
/// PRECISION GUARD: a 4-char single-surname match whose two trailing chars form
/// a common word is ambiguous — it can be a 2-char name + a swallowed verb
/// (`张三预订` = `张三` + `预订` "to book") or a genuine foreign name whose tail is
/// coincidentally common (`马尔克斯` — `克斯` ∈ common_words too). The dictionary
/// alone cannot tell them apart, so the 4-char swallow check in
/// `resolve_variants` breaks the tie with the strongest upstream NAME signal: a
/// `_CONTEXT_PREFIX` right before the candidate keeps the full 4-char name
/// (`客户马尔克斯` → `马尔克斯`); its absence treats the common-word tail as a
/// swallowed word and down-shifts to the 2-char root (`给张三转账` → `张三`),
/// preserving the verb for downstream function-calling.
static SINGLE_PAT: LazyLock<Regex> = LazyLock::new(|| {
    let surnames = surnames_zh();
    let pat = format!(r"[{surnames}][{CJK}]{{1,3}}");
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
///
/// ## Mutation coverage note
///
/// Only the 2-char-ending-in-particle empty return is uniquely observable in the
/// `generate_candidates` output (see `trim_two_char_surname_plus_particle_blocked`);
/// the trailing-particle loop (`len > 2`) and the honorific-head trailing trim are
/// MASKED by [`interior_name_len`], which the `emit` closure runs immediately after
/// `trim_candidate` and which re-derives the SAME truncation from index 2 onward.
/// Their cargo-mutants survivors are therefore equivalent under composition for the
/// detector's output, and the Python golden/parity suite (`tests/core`,
/// `tests/detection/lang`) covers them end-to-end (cargo-mutants runs only the Rust
/// unit tests). The discarded `end` return value (`start + len`) is dead in the
/// caller (`let (word, start, _end) = …`), so its arithmetic mutant is equivalent.
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

/// Find the first INTERIOR break point in a greedy regex match, returning the
/// valid name length (in chars) when the match over-grabbed past the real name.
///
/// `trim_candidate` only strips *trailing* particles / honorifics, which was
/// sufficient under the old `{1,2}` cap (the match never reached past one
/// over-grabbed char). With the raised `{1,3}` cap a single- or compound-surname
/// match can grab two extra chars, so a particle or honorific can land in the
/// MIDDLE of the match (`张明的手` — the particle `的` is the 3rd char, not the
/// last; `刘伟先生` — the honorific `先生` is fully inside). Trailing-only
/// trimming then leaves the over-grabbed tail attached.
///
/// This replicates the old `{1,2}`-cap + `trim_candidate` behavior, generalized
/// to the one extra char `{1,3}` can grab. It scans the given-name region and
/// returns the valid name length:
///   - **Particle** (`_NOT_NAME_CHARS`: `的`, `了`, `已`, `因`, `完`, …) at index
///     `i >= 2` — a name never contains one, so the name ends at `i`. (Index 1,
///     the first given char, is never particle-trimmed: `trim_candidate`'s
///     `len > 2` guard left it alone, and the 2-char-ending-in-particle case is
///     already handled in `trim_candidate` before we get here.)
///   - **Honorific head** (`_HONORIFIC_HEADS`) that actually starts an honorific
///     suffix (`先生`, `女士`, `董事长`, …) right there. This mirrors the OLD
///     `trim_candidate` honorific quirk, which only fired when the head was the
///     LAST char of the old 3-char match:
///       - head at index 2 (old's last position) → EXCLUDE the honorific, name
///         ends at index 2 (`刘伟先生` → `刘伟`);
///       - head at index 1 → the honorific stayed in the old 3-char match (the
///         last char `生` was not itself a head), so INCLUDE it: the name ends at
///         the END of the honorific suffix (`王先生你` → `王先生`), dropping any
///         further over-grab.
///
/// `word_chars` is the matched word; `start` its char offset; `text_chars` the
/// whole-text slice (for the honorific lookahead, identical to
/// `trim_candidate`). Returns `word_chars.len()` when there is no interior break
/// (the common case — every char is a valid given-name char, e.g. `马尔克斯`,
/// `欧阳娜娜娜`).
///
/// ## Mutation coverage note
///
/// The honorific lookahead window-end `start + i + 3` is robust to widening: the
/// `^`-anchored `_HONORIFIC_SUFFIX` matches a fixed-length prefix, so a window that
/// only GROWS (`i + 3` → `i * 3`, for the reachable `i >= 1`) does not change the
/// match — that survivor is equivalent. The `start + i` → `start * i` survivor IS
/// killed (`interior_honorific_head_at_index_two_truncates`: at start 0 the product
/// zeroes the lookahead offset and the suffix is missed). The `n > 1` guard
/// (vs `n >= 1`) differs only at `n == 1`, which the `emit` 2-char floor makes
/// unreachable → equivalent.
fn interior_name_len(word_chars: &[char], start: usize, text_chars: &[char]) -> usize {
    let n = word_chars.len();
    // Honorific suffix match length (in chars) when `word_chars[i]` is a head
    // that starts a suffix in the text, else None. Probes `head + following two
    // chars`, exactly as `trim_candidate` does, and measures how many chars the
    // suffix actually spans (`先生` = 2, `董事长` = 3).
    let honorific_suffix_len = |i: usize| -> Option<usize> {
        if !HONORIFIC_HEADS_SET.contains(&word_chars[i]) {
            return None;
        }
        let after_start = start + i + 1;
        let after_end = (start + i + 3).min(text_chars.len());
        let following: String = if after_start <= after_end {
            text_chars[after_start..after_end].iter().collect()
        } else {
            String::new()
        };
        let remaining = format!("{}{}", word_chars[i], following);
        // `HONORIFIC_SUFFIX` is `^`-anchored; the match length is the suffix's
        // char count.
        HONORIFIC_SUFFIX
            .find(&remaining)
            .ok()
            .flatten()
            .map(|m| remaining[..m.end()].chars().count())
    };

    // Index 1: the first given char. The OLD code never particle-trimmed it, but
    // if it is an honorific head starting a suffix the honorific is INCLUDED and
    // the name ends at the suffix's end (the `王先生你` → `王先生` quirk).
    if n > 1 {
        if let Some(sfx) = honorific_suffix_len(1) {
            return (1 + sfx).min(n);
        }
    }

    // Index 2 onward: particle ends the name here; an honorific head at index 2
    // EXCLUDES the honorific (name ends at index 2). The index `i` is the return
    // value (the truncation length) and is also passed to `honorific_suffix_len`,
    // so an enumerate-over-slice rewrite would not be clearer here.
    #[allow(clippy::needless_range_loop)]
    for i in 2..n {
        let ch = word_chars[i];
        if NOT_NAME_CHARS_SET.contains(&ch) {
            return i;
        }
        if honorific_suffix_len(i).is_some() {
            return i;
        }
    }
    n
}

/// Find all surname + 1-3 CJK sequences, filtered by the negative dict.
///
/// Port of `generate_candidates(text)`. For 3-/4-char single-surname matches it
/// emits the full word plus shorter prefix variants (2-char, and 3-char for a
/// 4-char match) so the scoring / resolution phase can pick the best one;
/// `interior_name_len` first truncates an over-grabbed particle / honorific
/// tail. Returns candidates sorted by `start`.
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

    // `_emit` — register a candidate (plus shorter prefix variants) so the
    // scorer / variant resolver downstream can pick the best length.
    //
    // `m_text` is the matched substring, `m_start` its CHAR start offset.
    //
    // ## Interior truncation (the `{1,3}` recall extension)
    //
    // `trim_candidate` already stripped *trailing* particles / honorifics. With
    // the raised `{1,3}` cap a match can over-grab past the real name so a
    // particle / honorific lands in the MIDDLE (`张明的手`, `刘伟先生`,
    // `欧阳明已登`). `interior_name_len` finds that first interior break and we
    // truncate the word to it, UNIFORMLY for single AND compound matches, before
    // building any candidate. This is `trim_candidate`'s philosophy applied at
    // the interior cut, and it leaves the old `{1,2}`-cap behavior unchanged
    // (a 2-/3-char match has no interior break to find).
    //
    // ## Variant philosophy (single-surname matches only; compound matches are
    //    never split — they carry a fixed compound surname head)
    //
    // The 2-char prefix (`surname + first given char`) is the candidate ROOT. If
    // that root is a known non-name (`prefix2 in neg`) the whole match is a
    // non-name and is fully blocked — NO variant of any length is emitted. This
    // is the `prefix_blocked` rule, applied uniformly to 3- AND 4-char matches.
    //
    // When the root is not blocked we offer, longest-first, the shorter prefixes
    // so the resolver can shrink an over-greedy match to its real name length:
    //   - len-3 match  → [word(3), prefix2]            (unchanged from before)
    //   - len-4 match  → [word(4), prefix3, prefix2]   (new, for `{1,3}` cap)
    // Each emitted variant is itself gated on `not in neg` (a prefix that is a
    // known non-name is not emitted), mirroring the original 3-char gating. The
    // len-2 prefix needs no separate neg-check beyond the root block above
    // (`prefix2 not in neg` is the un-blocked precondition).
    //
    // The original Python closure only handled len-3; the len-4 arm + the
    // interior truncation are the T7 recall extension for the `{1,3}` cap.
    let emit = |m_text: &str,
                m_start: usize,
                is_compound: bool,
                candidates: &mut Vec<NameCandidate>,
                seen_starts: &mut HashSet<usize>| {
        let (word, start, _end) = trim_candidate(m_text, m_start, chars);
        // Mutation note: the `||` → `&&` survivor here is equivalent. The empty-word
        // half is independently re-guarded below (`word_chars.len() < 2`), and the
        // seen-start dedup half is never reached with an already-seen start — the
        // single-pat loop pre-filters `seen_starts` (and inserts only on emit), and
        // the compound loop's matches are non-overlapping, so `emit` is never invoked
        // twice for one start. With no input that reaches the dedup path, the `&&`
        // mutant produces identical output.
        if word.is_empty() || seen_starts.contains(&start) {
            return;
        }

        // Truncate at the first interior particle / honorific (no-op when there
        // is none). `chars` is the whole-text slice for the honorific lookahead.
        let mut word_chars: Vec<char> = word.chars().collect();
        let valid_len = interior_name_len(&word_chars, start, chars);
        word_chars.truncate(valid_len);

        // A truncation can drop the word below 2 chars only if `valid_len < 2`,
        // which `interior_name_len` never returns (it scans from index 2), so a
        // truncated word is always >= 2 chars. Still, guard defensively.
        if word_chars.len() < 2 {
            return;
        }

        let word_len = word_chars.len();
        let word: String = word_chars.iter().collect();
        let end = start + word_len;
        let prefix2: String = word_chars.iter().take(2).collect();
        let prefix3: String = word_chars.iter().take(3).collect();

        let mut variants: Vec<NameCandidate> = Vec::new();

        // A single-surname match of length 3 or 4 — the shape that offers prefix
        // variants and is gated on the 2-char root. Deduped here and reused below.
        let single_multi = !is_compound && (word_len == 3 || word_len == 4);

        // The 2-char root being a known non-name blocks every variant of a
        // single-surname 3-/4-char match. (Computed BEFORE `word`/`prefix2`/
        // `prefix3` are moved into the variants below.)
        let prefix_blocked = single_multi && neg.contains(&prefix2);

        // Full word (len 2/3/4 for single, any for compound), longest variant.
        if !neg.contains(&word) && !prefix_blocked {
            variants.push(NameCandidate { text: word, start, end });
        }
        // For a 4-char single-surname match, also offer the 3-char prefix
        // (gated on the 3-char prefix itself not being a known non-name).
        if word_len == 4 && !is_compound && !prefix_blocked && !neg.contains(&prefix3) {
            variants.push(NameCandidate { text: prefix3, start, end: start + 3 });
        }
        // For 3-/4-char single-surname matches, also offer the 2-char variant.
        // (`prefix2 not in neg` is the un-blocked precondition above.)
        if single_multi && !neg.contains(&prefix2) {
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
        // fancy_regex yields Err on backtrack-limit / stack overflow for
        // pathological input; Python's `re` never errors here. Stop gracefully
        // rather than panicking, mirroring patterns.rs.
        let Ok(m) = m else { break };
        let m_start = byte_to_char_offset(text, m.start());
        emit(m.as_str(), m_start, true, &mut candidates, &mut seen_starts);
    }

    // Single surnames — skip positions already claimed by compound matches.
    //   for m in _SINGLE_PAT.finditer(text):
    //       if m.start() in seen_starts: continue
    //       if any(m.start() >= c.start and m.end() <= c.end for c in candidates): continue
    //       _emit(m)
    for m in SINGLE_PAT.find_iter(text) {
        // Stop gracefully on backtrack-limit / overflow Err (see COMPOUND_PAT
        // above); bit-identical on all non-pathological input.
        let Ok(m) = m else { break };
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
    // Mutation note: the `candidate.end + CONTEXT_WINDOW` → `candidate.end *
    // CONTEXT_WINDOW` survivor is equivalent. `end >= 2` always (min 2-char name),
    // so the product only GROWS the window; the three `after` signals
    // (`_HONORIFIC_SUFFIX`, `_PII_SUFFIX`, `_PAREN_PHONE`) are all `^`-anchored
    // prefix matches, so a wider `after` never changes whether they fire.
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
// Port of `_resolve_variants` from `lang/zh/person.py`; extended in T7 (4-char swallow).

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
/// Port of `_resolve_variants(grouped, text, threshold)`, with a T7 extension:
/// the Python original only swallow-checks a 3-char best; this also handles the
/// 4-char single-surname best the raised `{1,3}` cap introduces (the
/// `best_len == 4` branch — a common-word tail down-shifts to the 2-char root
/// UNLESS a context-prefix justifies the full name; see `SINGLE_PAT`).
///
/// The 3-char path below is byte-identical to the Python:
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
        //
        // Mutation note: this 3-char swallow arm is a faithful port of the
        // pre-`{1,3}`-cap Python, retained for parity, but a genuine SWALLOW is
        // effectively unreachable under the current cap — if the 3rd name char plus
        // the next text char form a CJK common word, the greedy `[surname][CJK]{1,3}`
        // already grabbed 4 chars and routes through the `best_len == 4` branch
        // instead. So the arm's surviving arithmetic / `==`-find mutants (the `after`
        // window offsets and the 2-char `.find`) cannot be reached by a swallow-firing
        // input; the NON-swallow path (e.g. `客户何秀珍已登记`) is exercised but is
        // insensitive to those edits (the `^`-anchored common-word check is unaffected
        // by a wider `after` window). The 4-char arm's equivalent gate IS killed
        // (`detect_four_char_real_name_no_common_tail_kept`).
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
        } else if best_len == 4 {
            // 4-char single-surname swallow (the `{1,3}`-cap extension). The
            // 2-char tail `best.text[2:4]` (e.g. the verb 转账 / 预订 in
            // 张三转账 / 张三预订) being a common word means the greedy match
            // likely absorbed a following word, so down-shift to the 2-char root.
            //
            // BUT a real 4-char foreign name can ALSO have a common-word tail
            // (马尔克斯 — 克斯 ∈ common_words), indistinguishable from a verb by
            // the dictionary alone. We break the tie with the strongest upstream
            // NAME signal: a `_CONTEXT_PREFIX` immediately before the candidate
            // (客户 / 联系人 / 我叫 / …). When that signal is present the full
            // 4-char name is kept (客户马尔克斯 → 马尔克斯); when it is absent the
            // common-word tail is treated as a swallowed word and we down-shift
            // (给张三转账 → 张三), preserving the verb for downstream
            // function-calling. This re-runs the SAME `_CONTEXT_PREFIX` over the
            // SAME ±20 `before` window `score_candidate` uses.
            let tail: String = best.text.chars().skip(2).take(2).collect();
            if tail.chars().count() == 2 && common.contains(&tail) {
                // before = text[max(0, best.start - _CONTEXT_WINDOW) : best.start]
                let before_start = best.start.saturating_sub(CONTEXT_WINDOW);
                let before_end = best.start.min(char_len);
                let before: String = if before_start <= before_end {
                    text_chars[before_start..before_end].iter().collect()
                } else {
                    String::new()
                };
                let has_context_prefix = CONTEXT_PREFIX.is_match(&before).unwrap_or(false);
                if !has_context_prefix {
                    if let Some((c, s)) = passing
                        .iter()
                        .find(|(c, _)| c.text.chars().count() == 2)
                    {
                        best = c.clone();
                        best_score = *s;
                    }
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
                // Stop gracefully on backtrack-limit / overflow Err rather than
                // panicking; bit-identical on all non-pathological input.
                let Ok(m) = m else { break };
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
        // non-overlapping: with the {1,3} cap the greedy match at 0 is the full
        // 张三李四 (张 + 3 CJK), which consumes 李 at index 2. The next scan
        // position is past 四, so 李四 is never produced. None of 李/四 is a
        // particle/honorific, so interior_name_len keeps all 4 chars; _emit then
        // offers the 4-char word + 3-char + 2-char prefixes at the same start.
        // (Old {1,2}: greedy 张三李 → [('张三李',0,3),('张三',0,2)].)
        assert_candidates(
            "张三李四",
            &[("张三李四", 0, 4), ("张三李", 0, 3), ("张三", 0, 2)],
        );
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

    #[test]
    fn single_surname_four_char_emits_full_and_prefixes() {
        // "马尔克斯" — foreign transliteration, single surname 马 + 3 chars. With
        // the {1,3} cap the greedy single-pat match is the full 4-char word; the
        // len-4 _emit arm offers the 4-char word + the 3-char prefix + the 2-char
        // prefix at the same start (longest-first), so the resolver can shrink to
        // the right length.
        assert_candidates(
            "马尔克斯",
            &[("马尔克斯", 0, 4), ("马尔克", 0, 3), ("马尔", 0, 2)],
        );
    }

    #[test]
    fn single_surname_four_char_with_context() {
        // "客户马尔克斯" — same name behind a context prefix; candidate generation
        // is independent of scoring, so the same variant set is produced at the
        // shifted start (2).
        assert_candidates(
            "客户马尔克斯",
            &[("马尔克斯", 2, 6), ("马尔克", 2, 5), ("马尔", 2, 4)],
        );
    }

    #[test]
    fn compound_surname_four_char_triple_given() {
        // "欧阳娜娜娜" — compound surname 欧阳 + triple given 娜娜娜. With COMPOUND
        // at {1,3} the full 5-char compound word is matched; compound matches are
        // NOT split into shorter variants (is_compound=True).
        assert_candidates("欧阳娜娜娜", &[("欧阳娜娜娜", 0, 5)]);
    }

    // ── Mutation-kill guards (cargo-mutants survivors) ───────────────────────

    #[test]
    fn trim_two_char_surname_plus_particle_blocked() {
        // trim_candidate L137 `len == 2 && last in _NOT_NAME_CHARS → return ""`.
        // "李的" is a 2-char greedy match (the space stops the regex): surname 李 +
        // the particle 的. trim returns the empty word, so NO candidate is emitted —
        // this is the ONE trim behavior `interior_name_len` (which scans only from
        // index 2) does not also produce. Mutating `==` to `!=` skips the empty
        // return, leaking "李的" (not in the negative dict) as a spurious candidate.
        assert_candidates("李的 abc", &[]);
    }

    #[test]
    fn interior_honorific_head_at_index_two_truncates() {
        // interior_name_len honorific lookahead (L209-210). "刘伟先生你好" greedy
        // single match is 刘伟先 (刘 + 伟先); the honorific head 先 sits at index 2
        // and `先` + the following `生` forms the suffix 先生, so the name ends at
        // index 2 → 刘伟. This pins the lookahead window arithmetic `start + i + …`:
        // the `start + i` term mutated to `start * i` zeroes the offset at start 0
        // (i ≠ 0), so the lookahead reads the wrong following text, the 先生 suffix
        // is not recognized, and 刘伟先 leaks instead of truncating to 刘伟.
        assert_candidates("刘伟先生你好", &[("刘伟", 0, 2)]);
    }

    #[test]
    fn single_match_nested_in_compound_is_skipped() {
        // generate_candidates containment skip (the `m_start >= c.start && m_end <=
        // c.end` `.any`). The COMPOUND match 诸葛李明 (诸葛 + 李明) claims 0..4 first.
        // 诸 is NOT a single surname but 葛 IS, so the SEPARATE single-pat finditer
        // pass independently matches 葛李明 at start 1 — a start NOT in `seen_starts`
        // (only 0 is) — so it REACHES the containment check, which finds it nested in
        // 0..4 (`1 >= 0 && 4 <= 4`) and skips it. Mutating `>=` to `<` (`1 < 0` →
        // false) stops the skip, leaking the nested 葛李明 / 葛李 as extra candidates.
        // (Using a compound whose FIRST char is also a single surname, e.g. 欧阳,
        // would not reach this check: the single pass matches at start 0, which
        // `seen_starts` already filters earlier.)
        assert_candidates("诸葛李明", &[("诸葛李明", 0, 4)]);
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
        // With the SINGLE {1,3} cap the greedy match is the 4-char 张三预订, whose
        // 2-char tail 预订 ("to book") is a common word AND there is no context-
        // prefix before 张三 → the 4-char swallow down-shift treats 预订 as a
        // swallowed word and drops to 张三. Score lands exactly at the 0.8
        // threshold via the proximity bucket.
        // Python (pre-port {1,2}): [('张三', 0, 2, 0.8)] — same final result.
        let pii = [pm(0, 0, "phone")];
        assert_eq!(
            detect("张三预订了机票", &pii, &[], 0.8),
            vec![("张三".to_string(), 0, 2, 0.8)]
        );
    }

    #[test]
    fn detect_single_surname_four_char_foreign_name() {
        // 客户马尔克斯已登记 — the {1,3} cap lets 马 carry the 3-char given name
        // 尔克斯; 马尔克斯 is detected at its full 4-char length. Its tail 克斯 is
        // also a common word, but the context-prefix 客户 marks it as a real name,
        // so the 4-char swallow down-shift is NOT applied. base 0.5 + 0.6 → 1.0.
        assert_eq!(
            detect("客户马尔克斯已登记", &[], &[], 0.8),
            vec![("马尔克斯".to_string(), 2, 6, 1.0)]
        );
    }

    #[test]
    fn detect_four_char_swallow_without_context_prefix() {
        // 给张三转账5000元... — 张三转账 is a 4-char match whose tail 转账 ("to
        // transfer") is a common word, with NO context-prefix before 张三 → the
        // swallow down-shift drops to 张三, preserving the verb 转账 downstream. A
        // bank-card PII supplies proximity evidence (within 50 chars).
        let pii = [pm(14, 30, "bank_card")];
        assert_eq!(
            detect("给张三转账5000元到银行卡4111111111111111", &pii, &[], 0.8),
            vec![("张三".to_string(), 1, 3, 0.8)]
        );
    }

    #[test]
    fn detect_compound_four_char_triple_given() {
        // 客户欧阳娜娜娜已登记 — the COMPOUND {1,3} cap lets 欧阳 carry the triple
        // given name 娜娜娜 → 欧阳娜娜娜 detected at its full 5-char length.
        assert_eq!(
            detect("客户欧阳娜娜娜已登记", &[], &[], 0.8),
            vec![("欧阳娜娜娜".to_string(), 2, 7, 1.0)]
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
    fn detect_four_char_real_name_no_common_tail_kept() {
        // resolve_variants 4-char swallow gate (L750) `tail.count() == 2 &&
        // common.contains(tail)`. "马尔斯顿" is a 4-char single-surname foreign name
        // whose tail 斯顿 is NOT a common word, with NO context-prefix; a phone right
        // after supplies proximity so the 4-char (1.0) AND 2-char (0.8) variants both
        // pass. HEAD: tail not common → `&&` short-circuits false → no down-shift →
        // keeps the full 4-char name. Mutating `&&` to `||` makes the gate fire on
        // `tail.count() == 2` alone (always true for a 4-char best) → with no
        // context-prefix it down-shifts to the 2-char root 马尔, dropping the name.
        let pii = [pm(4, 15, "phone")];
        assert_eq!(
            detect("马尔斯顿13800138000", &pii, &[], 0.8),
            vec![("马尔斯顿".to_string(), 0, 4, 1.0)]
        );
    }

    #[test]
    fn detect_known_name_does_not_occupy_later_candidate() {
        // detect_person_names occupancy containment (L920) `c.start >= s &&
        // c.end <= e`. Known name 张三 claims 0..2; a SEPARATE scored name 李芳 later
        // (behind the context-prefix 客户) is NOT contained in 0..2 → kept. HEAD:
        // `20 >= 0 && 22 <= 2` = false → not skipped. Mutating `&&` to `||` makes it
        // `20 >= 0 || …` = true → the later 李芳 is wrongly treated as occupied and
        // dropped, so only the known name would survive.
        assert_eq!(
            detect("张三的电话是13800138000，客户李芳", &[], &["张三"], 0.8),
            vec![
                ("张三".to_string(), 0, 2, 1.0),
                ("李芳".to_string(), 20, 22, 0.8999999999999999),
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

    #[test]
    #[ignore = "expensive (~1MB single-token scan); proves the find_iter no-panic fix. Run via `cargo test -- --ignored`."]
    fn pathological_single_token_does_not_panic() {
        // A ~1MB single repeated CJK char can trip fancy_regex's backtrack limit /
        // stack overflow inside COMPOUND_PAT / SINGLE_PAT.find_iter (and the
        // per-name known_names emit), which previously PANICKED via `.unwrap()`.
        // The graceful `let Ok(m) = m else { break }` must return a Vec instead.
        let pathological: String = std::iter::repeat('张').take(1_000_000).collect();
        // Just calling it must not panic; the result is whatever the graceful scan
        // produces — we only assert it returns a Vec.
        let _got = detect_person_names(&pathological, &[], &[], 0.8);
        // Also exercise the per-name known_names emit path on the same input.
        let _got2 =
            detect_person_names(&pathological, &[], &["李雷".to_string()], 0.8);
    }
}






