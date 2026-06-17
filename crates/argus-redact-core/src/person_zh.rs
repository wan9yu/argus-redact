//! Chinese person-name candidate generation — Rust port of the candidate-gen
//! half of `lang/zh/person.py`.
//!
//! This is a byte-faithful port of `generate_candidates` + `_trim_candidate` +
//! the `NameCandidate` dataclass. Scoring (`score_candidate`), variant
//! resolution (`_resolve_variants`) and the public `detect_person_names`
//! entry point are ported in later tasks (T4/T5); this module stays
//! crate-internal until then.
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

use crate::person_data::{compound_surnames_zh, not_names_zh_set, surnames_zh};
use crate::reserved_range::byte_to_char_offset;

/// CJK unified ideographs range — the character class body used by both
/// `_SINGLE_PAT` and `_COMPOUND_PAT`. Mirrors Python `_CJK = r"一-鿿"`.
const CJK: &str = r"\u{4e00}-\u{9fff}";

/// Particles / function words that cannot be the last char of a given name.
/// Mirrors Python `_NOT_NAME_CHARS` (43 chars).
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
/// Returns `(trimmed_word, start, end)` where `end` is a char offset.
///
/// All length / indexing / slicing is char-based (the Python `word[-1]`,
/// `len(word)`, `word[:-1]`, `word[:2]` are str/char operations).
fn trim_candidate(word: &str, start: usize, text: &str) -> (String, usize, usize) {
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
        let text_chars: Vec<char> = text.chars().collect();
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
pub(crate) fn generate_candidates(text: &str) -> Vec<NameCandidate> {
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
        let (word, start, end) = trim_candidate(m_text, m_start, text);
        if word.is_empty() || seen_starts.contains(&start) {
            return;
        }

        let word_chars: Vec<char> = word.chars().collect();
        let word_len = word_chars.len();
        let prefix2: String = word_chars.iter().take(2).collect();

        let mut variants: Vec<NameCandidate> = Vec::new();

        // The 2-char prefix being a known non-name blocks the 3-char extension.
        let prefix_blocked = word_len == 3 && !is_compound && neg.contains(&prefix2);
        if !neg.contains(&word) && !prefix_blocked {
            variants.push(NameCandidate { text: word.clone(), start, end });
        }
        // For 3-char single-surname matches, also offer the 2-char variant.
        if word_len == 3 && !is_compound {
            let short = prefix2;
            if !neg.contains(&short) {
                variants.push(NameCandidate { text: short, start, end: start + 2 });
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: assert generate_candidates output equals the expected
    // (text, start, end) triples in order.
    fn assert_candidates(input: &str, expected: &[(&str, usize, usize)]) {
        let got: Vec<(String, usize, usize)> = generate_candidates(input)
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
}
