//! Unicode normalization for PII detection (port of pure/normalize.py).
//!
//! Pipeline:
//!   1. ASCII fast-path (skip everything if pure ASCII)
//!   2. Strip invisible / zero-width / direction-control / text-smuggling
//!      characters (build char-index offset map)
//!   2b. Fold combining accents/diacritics (NFD-decompose, drop the nonspacing mark)
//!       so ASCII-anchored tokens survive a diacritic; offset map preserved
//!   3. Replace confusables (Latin/Cyrillic/Greek/Coptic look-alikes -> ASCII), 1:1
//!   4. Per-char NFKC normalization (each source char normalized independently —
//!      NO cross-char composition) — only run if the joined string isn't already NFKC
//!   5. Contextual digit normalization (Chinese-digit sequences -> ASCII digits)
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::canonical_combining_class;
use unicode_normalization::is_nfkc;

const MIN_DIGIT_SEQ: usize = 7; // shortest PII (phone fragments)

/// Unicode `Default_Ignorable_Code_Point` — 17 merged ranges / 4174 code points.
///
/// Sorted and non-overlapping; [`is_invisible`] binary-searches it. This is the
/// full derived property, not a curated list: the previously hand-enumerated
/// carriers (zero-width, bidi controls, word joiner, variation selectors, the Tag
/// block) are all members of it, so this is a strict WIDENING — nothing that was
/// stripped before stops being stripped.
///
/// Widening matters because a hand-list is a denylist, and a denylist is exactly
/// the wrong shape for text smuggling: every code point the list forgets is a free
/// splitter. `U+206A`..`U+206F` (deprecated format controls), `U+2065`,
/// `U+FFF0`..`U+FFF8`, `U+1D173`..`U+1D17A` (musical formatting) and the whole
/// `U+E0080`..`U+E0FFF` unassigned tail all render invisibly in mainstream text
/// stacks and all used to survive normalization.
const DEFAULT_IGNORABLE: &[(char, char)] = &[
    ('\u{00ad}', '\u{00ad}'),   // SOFT HYPHEN
    ('\u{034f}', '\u{034f}'),   // COMBINING GRAPHEME JOINER
    ('\u{061c}', '\u{061c}'),   // ARABIC LETTER MARK
    ('\u{115f}', '\u{1160}'),   // HANGUL CHOSEONG/JUNGSEONG FILLER
    ('\u{17b4}', '\u{17b5}'),   // KHMER VOWEL INHERENT AQ/AA
    ('\u{180b}', '\u{180f}'),   // MONGOLIAN FVS1-4 + VOWEL SEPARATOR
    ('\u{200b}', '\u{200f}'),   // ZERO WIDTH SPACE .. RIGHT-TO-LEFT MARK
    ('\u{202a}', '\u{202e}'),   // bidi embedding/override controls
    ('\u{2060}', '\u{206f}'),   // WORD JOINER .. NOMINAL DIGIT SHAPES (incl. isolates)
    ('\u{3164}', '\u{3164}'),   // HANGUL FILLER
    ('\u{fe00}', '\u{fe0f}'),   // VARIATION SELECTOR-1..16
    ('\u{feff}', '\u{feff}'),   // ZERO WIDTH NO-BREAK SPACE (BOM)
    ('\u{ffa0}', '\u{ffa0}'),   // HALFWIDTH HANGUL FILLER
    ('\u{fff0}', '\u{fff8}'),   // reserved, treated as ignorable
    ('\u{1bca0}', '\u{1bca3}'), // SHORTHAND FORMAT CONTROLS
    ('\u{1d173}', '\u{1d17a}'), // MUSICAL SYMBOL BEGIN BEAM .. END PHRASE
    ('\u{e0000}', '\u{e0fff}'), // Tag block + VS17..256 + the unassigned tail
];

fn is_invisible(c: char) -> bool {
    // Invisible / zero-width / direction-control characters stripped BEFORE
    // detection so text-smuggling can't split a token and fail-open a regex
    // (→ PII leak). Detection-side only: spans map back to the ORIGINAL text and
    // the emitted output is char-sliced from the original, so stripping these here
    // never corrupts legitimate output — a variation selector that is genuinely
    // part of the surrounding (non-PII) text survives in the output untouched.
    //
    // Membership = Unicode Default_Ignorable_Code_Point (see DEFAULT_IGNORABLE).
    if c < '\u{00ad}' {
        return false; // ASCII fast-path: no ignorable below U+00AD
    }
    DEFAULT_IGNORABLE
        .binary_search_by(|&(lo, hi)| {
            if c < lo {
                std::cmp::Ordering::Greater
            } else if c > hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn is_droppable_mark(c: char) -> bool {
    // A nonspacing combining mark we fold away to de-accent ASCII-anchored tokens
    // (Latin/Greek/Cyrillic accents, etc.).
    //
    // We test canonical_combining_class != 0 (nonspacing marks) rather than
    // is_combining_mark, which would ALSO match *spacing* marks (Mc, ccc=0) such as
    // Indic vowel signs (e.g. U+093E DEVANAGARI VOWEL SIGN AA); those are kept.
    // This is a deliberately broad de-accenter: it also drops nonspacing marks that
    // are meaning-bearing in some scripts (e.g. Devanagari nukta U+093C / virama
    // U+094D, Thai/Lao tone marks, Arabic harakat, Hebrew niqqud), so the *internal*
    // normalized form of such text is lossy. That is acceptable under the current
    // detector set (PII patterns are ASCII / Latin / CJK-digit based; no detector
    // matches those scripts) AND restore is lossless — spans map back to the
    // ORIGINAL text, so surrounding script text is preserved verbatim in the output.
    // Revisit this filter (add per-script exemptions) if/when detection expands to
    // Indic/Thai/Arabic/Hebrew/etc. scripts.
    //
    // Exception: U+3099 / U+309A (CJK voiced / semi-voiced sound marks) are nonspacing
    // (Mn, ccc=8) but are NOT diacritics — they distinguish CJK letters (で=de vs て=te)
    // that the Japanese detector and the normalize parity corpus exercise. Dropping
    // them silently rewrites Japanese, so they are kept.
    if matches!(c, '\u{3099}' | '\u{309a}') {
        return false;
    }
    canonical_combining_class(c) != 0
}

fn confusable(c: char) -> char {
    // Cyrillic / Greek / Coptic look-alikes -> ASCII Latin, 1:1. Generated from
    // the Unicode UTS #39 confusables data + curated overlay (parity-gated by
    // tests/architecture/test_confusables_parity.py). See src/confusables.rs.
    crate::confusables::confusable_map()
        .get(&c)
        .copied()
        .unwrap_or(c)
}

pub(crate) fn cn_digit(c: char) -> Option<char> {
    // _CN_DIGIT_MAP (normalize.py:98-118): 19 entries -> ASCII digit char
    Some(match c {
        '一'=>'1','二'=>'2','三'=>'3','四'=>'4','五'=>'5','六'=>'6','七'=>'7','八'=>'8','九'=>'9','零'=>'0',
        '壹'=>'1','贰'=>'2','叁'=>'3','肆'=>'4','伍'=>'5','陆'=>'6','柒'=>'7','捌'=>'8','玖'=>'9',
        _ => return None,
    })
}

/// Non-decimal (`No`/`So`) characters whose NFKC fold CONTAINS an ASCII digit.
///
/// 222 code points / 19 merged ranges: superscripts (¹²³), subscripts (₀-₉),
/// vulgar fractions (½ → "1⁄2"), circled/parenthesised/full-stop digits (①⑴⒈),
/// CJK compat month/hour/day symbols (㋀ → "1月"), squared units (㎟ → "mm2"),
/// and the SMP digit-full-stop block (🄀).
///
/// These are NOT decimal digits (`Nd`), but folding them manufactures ASCII digits
/// that fuse with a neighbouring PII number and break the `(?<!\d)` / `(?!\d)`
/// boundary anchors — the same fail-open shape the CJK-homograph guard in
/// `normalize_digit_sequences` defends against.
const NFKC_DIGIT_YIELDING_NON_DECIMAL: &[(char, char)] = &[
    ('\u{b2}', '\u{b3}'),       // ²..³   SUPERSCRIPT TWO/THREE
    ('\u{b9}', '\u{b9}'),       // ¹      SUPERSCRIPT ONE
    ('\u{bc}', '\u{be}'),       // ¼..¾   VULGAR FRACTIONS
    ('\u{2070}', '\u{2070}'),   // ⁰      SUPERSCRIPT ZERO
    ('\u{2074}', '\u{2079}'),   // ⁴..⁹   SUPERSCRIPT FOUR..NINE
    ('\u{2080}', '\u{2089}'),   // ₀..₉   SUBSCRIPT ZERO..NINE
    ('\u{2150}', '\u{215f}'),   // ⅐..⅟   VULGAR FRACTIONS
    ('\u{2189}', '\u{2189}'),   // ↉      VULGAR FRACTION ZERO THIRDS
    ('\u{2460}', '\u{249b}'),   // ①..⒛   CIRCLED / PARENTHESISED / FULL-STOP DIGITS
    ('\u{24ea}', '\u{24ea}'),   // ⓪      CIRCLED DIGIT ZERO
    ('\u{3251}', '\u{325f}'),   // ㉑..㉟  CIRCLED NUMBER 21..35
    ('\u{32b1}', '\u{32cb}'),   // ㊱..㋋  CIRCLED NUMBER 36.. / MONTH SYMBOLS
    ('\u{3358}', '\u{3370}'),   // ㍘..㍰  TELEGRAPH HOUR SYMBOLS
    ('\u{3378}', '\u{3379}'),   // ㍸..㍹  SQUARE DM SQUARED/CUBED
    ('\u{339f}', '\u{33a6}'),   // ㎟..㎦  SQUARE MM SQUARED..KM CUBED
    ('\u{33a8}', '\u{33a8}'),   // ㎨      SQUARE M OVER S SQUARED
    ('\u{33af}', '\u{33af}'),   // ㎯      SQUARE RAD OVER S SQUARED
    ('\u{33e0}', '\u{33fe}'),   // ㏠..㏾  TELEGRAPH DAY SYMBOLS
    ('\u{1f100}', '\u{1f10a}'), // 🄀..🄊   DIGIT ZERO FULL STOP (SMP)
];

pub(crate) fn is_nfkc_digit_yielding_non_decimal(c: char) -> bool {
    if c < '\u{b2}' {
        return false; // ASCII + Latin-1 head fast-path
    }
    NFKC_DIGIT_YIELDING_NON_DECIMAL
        .binary_search_by(|&(lo, hi)| {
            if c < lo {
                std::cmp::Ordering::Greater
            } else if c > hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// A char the regex layer already sees as `\d` (ASCII or any other `Nd`), i.e.
/// one that needs no manufacturing. `Nl` (Roman numerals) folds to LETTERS, so it
/// is not a digit either way; counting it here only widens a run's denominator.
pub(crate) fn is_plain_digit_char(c: char) -> bool {
    c.is_ascii_digit() || (c.is_numeric() && !is_nfkc_digit_yielding_non_decimal(c))
}

/// Decide, per source char, whether the step-3 NFKC fold of a `No`/`So`
/// digit-yielder must be SUPPRESSED.
///
/// Same majority rule as the CJK-digit-homograph guard in
/// [`normalize_digit_sequences`], applied one step earlier: scan maximal
/// digit-ish runs (digits + `_DIGIT_SEPS` interior separators) and fold the
/// non-decimal members only when they are a strict MAJORITY of the run.
///
/// * `¹` after an 11-digit phone → 1 of 12 → minority → NOT folded, so the phone
///   keeps its `(?!\d)` boundary and is still detected (`13800138000¹`).
/// * `①③⑧⓪⓪①③⑧⓪⓪⓪` → 11 of 11 → majority → folded, so a number written
///   entirely in circled digits is still recovered.
/// * `x²³` → 2 of 2 → majority → folded to `x23`, unchanged from before.
fn suppressed_nfkc_folds(chars: &[char]) -> Option<Vec<bool>> {
    let n = chars.len();
    let mut mask: Option<Vec<bool>> = None;
    let mut i = 0;
    while i < n {
        let exotic = is_nfkc_digit_yielding_non_decimal(chars[i]);
        if !exotic && !is_plain_digit_char(chars[i]) {
            i += 1;
            continue;
        }
        let mut exotic_idx: Vec<usize> = Vec::new();
        let mut total = 0usize;
        while i < n {
            if is_nfkc_digit_yielding_non_decimal(chars[i]) {
                exotic_idx.push(i);
                total += 1;
            } else if is_plain_digit_char(chars[i]) {
                total += 1;
            } else if !is_digit_sep(chars[i]) {
                break;
            }
            i += 1;
        }
        // Strict majority to fold — a minority of non-decimals in a run of real
        // digits is a neighbour (footnote marker, fraction, unit), not part of
        // the number, and folding it fuses the two and fails the regex open.
        if !exotic_idx.is_empty() && exotic_idx.len() * 2 <= total {
            let m = mask.get_or_insert_with(|| vec![false; n]);
            for idx in exotic_idx {
                m[idx] = true;
            }
        }
    }
    mask
}

pub(crate) fn is_digit_sep(c: char) -> bool {
    // _DIGIT_SEPS (normalize.py:120): " \t.-/，、·;；:："
    matches!(c, ' '|'\t'|'.'|'-'|'/'|'，'|'、'|'·'|';'|'；'|':'|'：')
}

fn digit_value(c: char) -> Option<char> {
    // Python: _CN_DIGIT_MAP.get(c) or (c if c.isdigit() else None)
    // `is_numeric()` (Nd|Nl|No) == Python str.isdigit() (Numeric_Type Decimal/Digit)
    // for every char that reaches this step: it runs AFTER NFKC, which folds the
    // categories where the two differ (Roman numerals Nl → letters, vulgar
    // fractions No-Numeric → "1⁄2"). The surviving digits are Nd (incl. Arabic-Indic,
    // Devanagari, …), where both agree. Matches Python's `ch if ch.isdigit()` —
    // the non-ASCII digit char is kept as-is (not folded to ASCII), same as Python.
    cn_digit(c).or(if c.is_numeric() { Some(c) } else { None })
}

fn normalize_digit_sequences(chars: &mut [char]) {
    let n = chars.len();
    let mut i = 0;
    while i < n {
        if digit_value(chars[i]).is_none() {
            i += 1;
            continue;
        }
        let mut run: Vec<usize> = vec![i]; // indices of digit chars
        let first = digit_value(chars[i]).unwrap();
        let mut ascii: Vec<char> = vec![first];
        i += 1;
        while i < n {
            if is_digit_sep(chars[i]) {
                i += 1;
                continue;
            }
            match digit_value(chars[i]) {
                Some(d) => {
                    run.push(i);
                    ascii.push(d);
                    i += 1;
                }
                None => break,
            }
        }
        // Count CJK digits in the run. Fold only when they are a strict MAJORITY:
        // a genuine Chinese-digit number (一三八零零…) is all/mostly CJK, whereas a
        // name/word char that is also a digit homograph (三 in 张三, 四 in 李四)
        // abutting an ASCII PII number is a lone minority. Folding such a boundary
        // homograph would merge it into the digit run and break the PII regex's
        // `(?<!\d)` anchor — leaking e.g. "张三13800138000". The majority test keeps
        // the homograph intact so the adjacent phone/id/card still matches.
        let cn_count = run.iter().filter(|&&idx| cn_digit(chars[idx]).is_some()).count();
        if run.len() >= MIN_DIGIT_SEQ && cn_count * 2 > run.len() {
            for (k, &idx) in run.iter().enumerate() {
                chars[idx] = ascii[k];
            }
        }
    }
}

/// Normalize text for PII detection, returning an offset map.
///
/// Returns `(normalized_text, offset_map)` where `offset_map[i]` is the original
/// char index of the i-th output char. `offset_map` is `None` when the text is
/// unchanged (identity mapping).
pub fn normalize_text(text: &str) -> (String, Option<Vec<usize>>) {
    match normalize_core(text) {
        None => (text.to_string(), None),
        Some((chars, offset_map)) => finalize(&chars, &offset_map, text, true),
    }
}

/// Normalize text for PERSON-NAME detection — identical to [`normalize_text`]
/// EXCEPT it skips the Chinese-digit-sequence step (step 4).
///
/// ## Why person detection skips the digit step
///
/// The digit-sequence step rewrites a run of ≥7 digit-like chars (containing at
/// least one CJK digit) to ASCII — it exists so a phone/ID written in Chinese
/// digits (`一三八…` → `138…`) is caught by the regex layer. But CJK *names*
/// share characters with the digit map (`三`=3, `五`=5, `九`=9, …): a name like
/// `张三` adjacent to a phone number forms one long digit run, so `三` folds to
/// `3` and the surname-regex no longer sees a name — dropping a real, common
/// detection. Digit runs are PII for the regex layer, never names, so person
/// detection genuinely does not need them folded. The OTHER folds (invisible
/// strip, accent fold, confusable, NFKC) are NAME-PRESERVING — they turn an
/// obfuscated name back INTO a name (`Ｊohn`→`John`, `José`→`Jose`, `Ѕmith`→
/// `Smith`) — so person detection keeps those. Resulting spans map back to the
/// ORIGINAL via the returned offset map, exactly like the full-normalization path.
///
/// Both views derive from the SAME [`normalize_core`] intermediate (steps 1–3),
/// so they STRUCTURALLY share char positions and offset map — only the optional
/// step-4 digit fold changes some char VALUES.
pub fn normalize_text_for_person(text: &str) -> (String, Option<Vec<usize>>) {
    match normalize_core(text) {
        None => (text.to_string(), None),
        Some((chars, offset_map)) => finalize(&chars, &offset_map, text, false),
    }
}

/// Steps 1–3 of the normalization pipeline (the expensive, shared prefix):
/// invisible-strip + combining-mark fold + confusables + per-char NFKC. Returns
/// the post-step-3 `(chars, offset_map)`, or `None` for the pure-ASCII fast-path.
///
/// Both [`normalize_text`] and [`normalize_text_for_person`] run this ONCE and
/// derive their views via [`finalize`]; that makes the "two views share the same
/// positions + offset map, only digit VALUES differ" property STRUCTURAL rather
/// than coincidental.
pub(crate) fn normalize_core(text: &str) -> Option<(Vec<char>, Vec<usize>)> {
    if text.is_ascii() {
        return None;
    }
    // Step 1: strip invisible, build char-index offset map
    let mut chars: Vec<char> = Vec::new();
    let mut offset_map: Vec<usize> = Vec::new();
    for (i, ch) in text.chars().enumerate() {
        if !is_invisible(ch) {
            chars.push(ch);
            offset_map.push(i);
        }
    }
    // Step 1b: fold combining accents/diacritics (NFD-decompose, drop the mark),
    // keeping the offset map. Folds both precomposed (á) and decomposed (a + ◌́)
    // accents so ASCII-anchored tokens (email/phone) survive a diacritic.
    //
    // We decompose a char ONLY when its NFD actually contains a droppable mark, and
    // otherwise keep the ORIGINAL char untouched. Decomposing unconditionally would
    // shatter precomposed Hangul syllables (한 → 3 jamo) — and the per-char NFKC in
    // Step 3 does NOT recompose across separate chars, so the output would silently
    // ship decomposed jamo and break Korean detection.
    let mut folded_chars: Vec<char> = Vec::with_capacity(chars.len());
    let mut folded_map: Vec<usize> = Vec::with_capacity(offset_map.len());
    // Decompose each char ONCE into this reusable buffer (char::nfd yields ≤4
    // chars), then both check for a droppable mark and push from the buffer —
    // avoiding the double `ch.nfd()` of the check-then-loop form.
    let mut nfd_buf: Vec<char> = Vec::with_capacity(4);
    for (&ch, &src) in chars.iter().zip(offset_map.iter()) {
        nfd_buf.clear();
        nfd_buf.extend(ch.nfd());
        if !nfd_buf.iter().copied().any(is_droppable_mark) {
            folded_chars.push(ch); // no accent to fold — keep the char as-is
            folded_map.push(src);
            continue;
        }
        for &d in &nfd_buf {
            if is_droppable_mark(d) {
                continue; // drop the accent; its base char keeps `src`
            }
            folded_chars.push(d);
            folded_map.push(src);
        }
    }
    chars = folded_chars;
    offset_map = folded_map;
    // Step 2: confusables (1:1)
    for c in chars.iter_mut() {
        *c = confusable(*c);
    }
    // Step 3: per-char NFKC (only if the joined string isn't already NFKC)
    let joined: String = chars.iter().collect();
    if !is_nfkc(&joined) {
        // Which No/So digit-yielders must stay unfolded (minority-of-run rule).
        let suppressed = suppressed_nfkc_folds(&chars);
        let mut new_chars: Vec<char> = Vec::new();
        let mut new_map: Vec<usize> = Vec::new();
        for (si, ch) in joined.chars().enumerate() {
            if suppressed.as_ref().is_some_and(|m| m[si]) {
                new_chars.push(ch); // keep verbatim: folding it would fuse a neighbour's digits
                new_map.push(offset_map[si]);
                continue;
            }
            for c in ch.nfkc() {
                // per-char: no cross-char composition
                new_chars.push(c);
                new_map.push(offset_map[si]);
            }
        }
        chars = new_chars;
        offset_map = new_map;
    }
    Some((chars, offset_map))
}

/// Derive a final normalized view from a [`normalize_core`] intermediate:
/// clone `chars`, apply step 4 (Chinese-digit-sequence fold) iff `digit_sequences`,
/// then join. Returns `(text.to_string(), None)` when the result equals the
/// original `text` (identity mapping), else `(result, Some(offset_map))`.
pub(crate) fn finalize(
    chars: &[char],
    offset_map: &[usize],
    text: &str,
    digit_sequences: bool,
) -> (String, Option<Vec<usize>>) {
    let mut chars = chars.to_vec();
    // Step 4: Chinese-digit-sequence normalization (skipped for person detection,
    // which must not let a digit run swallow a CJK name char — see
    // `normalize_text_for_person`).
    if digit_sequences {
        normalize_digit_sequences(&mut chars);
    }
    let result: String = chars.iter().collect();
    if result == text {
        (text.to_string(), None)
    } else {
        (result, Some(offset_map.to_vec()))
    }
}

/// Map `(start, end)` spans from normalized text back to original text positions.
pub fn map_spans_to_original(
    spans: &[(usize, usize)],
    offset_map: Option<&[usize]>,
    original_len: usize,
) -> Vec<(usize, usize)> {
    let Some(map) = offset_map else {
        return spans.to_vec();
    };
    spans
        .iter()
        .map(|&(start, end)| {
            let orig_start = if start < map.len() {
                map[start]
            } else {
                original_len
            };
            let orig_end = if end > 0 && end - 1 < map.len() {
                map[end - 1] + 1
            } else {
                original_len
            };
            (orig_start, orig_end)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_fastpath() {
        assert_eq!(normalize_text("hello 123"), ("hello 123".into(), None));
    }

    #[test]
    fn confusable_cyrillic() {
        let (out, map) = normalize_text("\u{0430}bc"); // а(Cyrillic)bc
        assert_eq!(out, "abc");
        assert!(map.is_some());
    }

    #[test]
    fn confusable_generated_capital_s() {
        // U+0405 (Ѕ, CYRILLIC DZE) is a newly-covered confusable -> 'S'.
        let (out, map) = normalize_text("\u{0405}mith"); // Ѕmith
        assert_eq!(out, "Smith");
        assert!(map.is_some());
    }

    #[test]
    fn confusable_curated_cyrillic_ve() {
        // Curated в (U+0432) -> 'b' must still fold.
        let (out, _map) = normalize_text("\u{0432}ad"); // вad
        assert_eq!(out, "bad");
    }

    #[test]
    fn cn_digit_phone() {
        let (out, _map) = normalize_text("一三八零零一三八零零零");
        assert_eq!(out, "13800138000");
    }

    #[test]
    fn lone_cjk_homograph_not_folded_into_ascii_run() {
        // SECURITY: a lone CJK-digit homograph (三=3 in the name 张三) abutting an
        // ASCII PII number is a MINORITY of the run (1 CJK + 11 ASCII = 12 chars).
        // It must NOT fold — folding 三→3 would merge it into the phone digits and
        // break the zh phone regex's `(?<!\d)` anchor, leaking the phone AND the name.
        assert_eq!(
            normalize_text("张三13800138000").0,
            "张三13800138000"
        );
        // Same with a bare homograph, no name: still a lone minority → intact.
        assert_eq!(normalize_text("三13800138000").0, "三13800138000");
    }

    #[test]
    fn genuine_all_cjk_run_still_folds() {
        // An all-CJK number is 100% CJK → strict majority → still folds (no regression).
        assert_eq!(normalize_text("一三八零零一三八零零零").0, "13800138000");
    }

    #[test]
    fn majority_cjk_mixed_run_still_folds() {
        // 7-char run, 6 CJK + 1 ASCII: cn_count(6)*2 = 12 > 7 → strict majority → folds.
        assert_eq!(normalize_text("一二三四五六7").0, "1234567");
    }

    #[test]
    fn short_cn_unchanged() {
        // 三月三日 — not a 7+ digit run → unchanged → None
        assert_eq!(normalize_text("三月三日"), ("三月三日".into(), None));
    }

    #[test]
    fn person_norm_skips_cn_digit_step() {
        // The Chinese-digit run that normalize_text folds to ASCII must be left
        // INTACT by the person variant — so a name char that is a digit homograph
        // (三=3) survives. Full norm folds the whole run to "13800138000"; the
        // person variant keeps the CN digits, so (being digit-free of any other
        // change) it returns None / the original text.
        assert_eq!(normalize_text("一三八零零一三八零零零").0, "13800138000");
        assert_eq!(
            normalize_text_for_person("一三八零零一三八零零零"),
            ("一三八零零一三八零零零".into(), None)
        );
    }

    #[test]
    fn person_norm_keeps_name_preserving_folds() {
        // The person variant still applies the NON-digit folds: fullwidth NFKC,
        // confusable, accent — so an obfuscated NAME still becomes a name.
        assert_eq!(normalize_text_for_person("\u{FF2A}ohn").0, "John"); // Ｊ→J
        assert_eq!(normalize_text_for_person("\u{0405}mith").0, "Smith"); // Cyrillic Ѕ→S
        assert_eq!(normalize_text_for_person("Jos\u{00E9}").0, "Jose"); // é→e
    }

    #[test]
    fn person_norm_same_positions_as_full_norm() {
        // The digit step is an in-place value substitution, so the person variant
        // and the full variant share the SAME offset map (positions) — only some
        // char values differ. This is what lets layer1 (full-norm coords) be used
        // as the zh detector's pii_entities against the person-detect-text.
        //
        // Use a name abutting a genuine all-CJK number so the full-norm digit step
        // fires on a strict-majority run: 张 + 三八零零一三八零零零 (10 CJK digits).
        // Full norm folds the digit run to ASCII (and 三 here IS part of that number);
        // person norm keeps the CJK chars. A LONE homograph next to an ASCII number
        // (张三13800138000) must NOT fold — that case is covered by
        // `lone_cjk_homograph_not_folded_into_ascii_run`.
        let text = "张三八零零一三八零零零";
        let (full, fmap) = normalize_text(text);
        let (person, pmap) = normalize_text_for_person(text);
        // Full norm folds the CJK-digit run; person norm keeps it.
        assert!(full.contains("张3800138000"));
        assert!(person.contains("张三八零零一三八零零零"));
        // Positions line up: full norm produced a map; person norm produced none
        // here (digit step was its only change), and that map is the identity over
        // the same length, so any layer1 span in full coords addresses the same
        // char index in the original / person text.
        assert!(fmap.is_some());
        assert!(pmap.is_none());
        assert_eq!(full.chars().count(), person.chars().count());
    }

    #[test]
    fn fullwidth_nfkc() {
        let (out, _m) = normalize_text("\u{FF11}\u{FF12}\u{FF13}"); // １２３
        assert_eq!(out, "123");
    }

    #[test]
    fn map_spans_identity_when_none() {
        assert_eq!(map_spans_to_original(&[(1, 3)], None, 10), vec![(1, 3)]);
    }

    // ── Text-smuggling invisible-character classes (roadmap #67) ─────────────
    // A token split by an interior invisible from any of these classes must
    // normalize to the CLEAN token so the regex layer still fires (fail-open =
    // PII leak otherwise). Each class gets its own test; the offset map still
    // maps every surviving char back to its original index.

    #[test]
    fn strip_word_joiner_u2060() {
        // WORD JOINER (U+2060) interior to an email must be stripped so the email
        // regex sees a contiguous token.
        let (out, map) = normalize_text("john\u{2060}doe@example.com");
        assert_eq!(out, "johndoe@example.com");
        assert!(map.is_some());
    }

    #[test]
    fn strip_invisible_math_operators_u2061_u2064() {
        // U+2061..U+2064 (FUNCTION APPLICATION / INVISIBLE TIMES / INVISIBLE
        // SEPARATOR / INVISIBLE PLUS) — one per digit boundary of a phone-like run.
        let (out, map) = normalize_text("13800\u{2061}138\u{2062}00\u{2063}0\u{2064}0");
        assert_eq!(out, "138001380000");
        assert!(map.is_some());
    }

    #[test]
    fn strip_variation_selectors_fe00_fe0f() {
        // Variation selectors U+FE00..U+FE0F interior to a token are stripped.
        let (out, map) = normalize_text("Jo\u{FE00}hn\u{FE0F}Smith");
        assert_eq!(out, "JohnSmith");
        assert!(map.is_some());
    }

    #[test]
    fn strip_ideographic_variation_selectors_e0100_e01ef() {
        // Ideographic variation selectors U+E0100..U+E01EF interior to a token.
        let (out, map) = normalize_text("Jane\u{E0100}Doe\u{E01EF}");
        assert_eq!(out, "JaneDoe");
        assert!(map.is_some());
    }

    #[test]
    fn strip_tag_block_e0000_e007f() {
        // Unicode Tag block U+E0000..U+E007F (the modern "ASCII smuggling" carrier)
        // interior to a token is stripped. Use a LANGUAGE TAG (U+E0001), a TAG
        // latin letter (U+E0061 = tag 'a'), and CANCEL TAG (U+E007F).
        let (out, map) = normalize_text("acc\u{E0001}ount\u{E0061}42\u{E007F}99");
        assert_eq!(out, "account4299");
        assert!(map.is_some());
    }

    #[test]
    fn smuggled_email_offset_maps_back_to_original() {
        // Offset map must still map each surviving char back to its ORIGINAL index
        // so redaction spans cover the real token (invisible carrier included).
        let original = "a\u{2060}b@x.io";
        let (out, map) = normalize_text(original);
        assert_eq!(out, "ab@x.io");
        let m = map.unwrap();
        assert_eq!(m[0], 0); // 'a' at original index 0
        assert_eq!(m[1], 2); // 'b' at original index 2 (index 1 was the U+2060)
        assert_eq!(m.len(), out.chars().count());
    }

    // ── Default_Ignorable_Code_Point completeness ────────────────────────────
    // The strip list is the FULL Unicode Default_Ignorable_Code_Point set, not a
    // hand-picked subset. Anything in that set renders as nothing, so a model or
    // a user can splice one into a PII token and (pre-fix) split it away from the
    // detector. Each newly-covered class gets a case here.

    /// Every code point Unicode marks Default_Ignorable_Code_Point, as ranges.
    /// Kept in the TEST so the production predicate and the table are two
    /// independent statements of the same fact.
    const DEFAULT_IGNORABLE_RANGES: &[(u32, u32)] = &[
        (0x00AD, 0x00AD),
        (0x034F, 0x034F),
        (0x061C, 0x061C),
        (0x115F, 0x1160),
        (0x17B4, 0x17B5),
        (0x180B, 0x180F),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x206F),
        (0x3164, 0x3164),
        (0xFE00, 0xFE0F),
        (0xFEFF, 0xFEFF),
        (0xFFA0, 0xFFA0),
        (0xFFF0, 0xFFF8),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0000, 0xE0FFF),
    ];

    #[test]
    fn every_default_ignorable_code_point_is_stripped() {
        for &(lo, hi) in DEFAULT_IGNORABLE_RANGES {
            for cp in lo..=hi {
                let Some(ch) = char::from_u32(cp) else { continue };
                assert!(
                    is_invisible(ch),
                    "U+{cp:04X} is Default_Ignorable but is_invisible() says otherwise"
                );
            }
        }
    }

    #[test]
    fn strip_newly_covered_smuggling_carriers() {
        // One representative per class the original 4-group table missed.
        for carrier in [
            '\u{034F}',  // COMBINING GRAPHEME JOINER (Mn but ccc=0, so the mark fold misses it)
            '\u{061C}',  // ARABIC LETTER MARK
            '\u{115F}',  // HANGUL CHOSEONG FILLER
            '\u{17B4}',  // KHMER VOWEL INHERENT AQ
            '\u{180E}',  // MONGOLIAN VOWEL SEPARATOR
            '\u{2065}',  // unassigned, but Default_Ignorable
            '\u{206F}',  // NOMINAL DIGIT SHAPES (deprecated format control)
            '\u{3164}',  // HANGUL FILLER
            '\u{FFA0}',  // HALFWIDTH HANGUL FILLER
            '\u{FFF8}',  // unassigned, but Default_Ignorable
            '\u{1BCA0}', // SHORTHAND FORMAT LETTER OVERLAP
            '\u{1D173}', // MUSICAL SYMBOL BEGIN BEAM
            '\u{E0080}', // Tag-block tail (unassigned, Default_Ignorable)
        ] {
            let original = format!("john{carrier}doe@example.com");
            let (out, map) = normalize_text(&original);
            assert_eq!(out, "johndoe@example.com", "carrier U+{:04X}", carrier as u32);
            assert!(map.is_some(), "carrier U+{:04X} produced no offset map", carrier as u32);
        }
    }

    #[test]
    fn smuggled_carrier_span_covers_the_whole_original_token() {
        // SPAN-AWARE on purpose. With the carrier NOT stripped, the email regex
        // still "detects" something — it just detects the tail (`doe@x.io`) and
        // the span misses the `john` in front, so the redaction leaks the local
        // part. Asserting only "an email was found" is green on the bug; the
        // span is what actually distinguishes fixed from broken.
        let original = "john\u{034F}doe@x.io";
        let (out, map) = normalize_text(original);
        assert_eq!(out, "johndoe@x.io");
        let m = map.expect("offset map");
        let mapped =
            map_spans_to_original(&[(0, out.chars().count())], Some(&m), original.chars().count());
        assert_eq!(orig_slice(original, mapped[0]), original);
    }

    #[test]
    fn detection_recovers_numbers_a_stripped_invisible_would_fuse() {
        // Stripping the full Default_Ignorable set closes the text-smuggling that
        // SPLITS a token (`john<inv>doe` → `johndoe`, detected). Its cost is the
        // opposite shape: an invisible BETWEEN two complete numbers fuses them into
        // one long run the digit regex cannot bound — a LEAK the pure-strip reading
        // cannot see. The detection fan-out closes that hole: it additionally
        // reads each stripped-invisible-between-digits as the boundary it renders as,
        // so both numbers are recovered.
        //
        // Detection over the split text is therefore a SUPERSET of detection over the
        // pre-fused run — and, the property the earlier form of this test guarded, it
        // is IDENTICAL across every carrier class (the answer no longer depends on
        // which invisible was used). Superseding the old strict-equality assertion is
        // the intended, security-improving behaviour change: the equality once held
        // only because BOTH readings leaked; now the split reading detects while the
        // bare fused run (no boundary anywhere) still cannot.
        let fused = "1380013800013900139000"; // 22 contiguous digits: no bounded phone
        let a = crate::redact_l1::detect_l1(fused, &["zh".to_string()], &[]).unwrap();
        assert_eq!(a.layer1.len(), 0, "a bare 22-digit run bounds no phone");

        let mut split_counts = std::collections::HashSet::new();
        for carrier in ['\u{2060}', '\u{00ad}', '\u{3164}', '\u{034f}', '\u{115f}', '\u{e0080}'] {
            let split = format!("13800138000{carrier}13900139000");
            let b = crate::redact_l1::detect_l1(&split, &["zh".to_string()], &[]).unwrap();
            // Superset over the fused reading — the fan-out never detects fewer.
            assert!(
                b.layer1.len() >= a.layer1.len(),
                "U+{:04X}: fan-out must never detect less than the fused reading",
                carrier as u32
            );
            // Both real phones are recovered via the keep-boundary reading.
            let phones = b.layer1.iter().filter(|e| e.type_ == "phone").count();
            assert_eq!(
                phones, 2,
                "U+{:04X}: both phones must be recovered once the invisible reads as a boundary",
                carrier as u32
            );
            split_counts.insert(b.layer1.len());
        }
        // Consistency across carrier classes — the answer does not depend on which
        // invisible was used to split the number.
        assert_eq!(
            split_counts.len(),
            1,
            "detection must not depend on which invisible carrier was used"
        );
    }

    #[test]
    fn smuggled_carrier_detects_the_whole_email_end_to_end() {
        // The same property through the real detector: the entity span must
        // cover the carrier AND the local part in front of it.
        let original = "contact john\u{034F}doe@x.io now";
        let r = crate::redact_l1::detect_l1(original, &["en".to_string()], &[]).unwrap();
        let email = r
            .layer1
            .iter()
            .find(|e| e.type_ == "email")
            .expect("email entity");
        assert_eq!(orig_slice(original, (email.start, email.end)), "john\u{034F}doe@x.io");
    }

    #[test]
    fn non_ascii_digit_in_cn_run_matches_python() {
        // 6 CN digits + Arabic-Indic ٤ (U+0664, is_numeric, NFKC-stable) = 7-char run.
        // Python str.isdigit('٤') is True, so it joins the run; CN digits fold to ASCII,
        // ٤ is kept as-is (Python writes `ch`, not an ASCII fold). is_ascii_digit would
        // have broken the run → no conversion. is_numeric reproduces Python.
        let (out, _m) = normalize_text("一二三\u{0664}五六七");
        assert_eq!(out, "123\u{0664}567");
    }

    #[test]
    fn offset_map_after_strip_and_cn_digits() {
        // invisible char at index 0 stripped; then a CN-digit phone
        let (out, map) = normalize_text("\u{200b}一三八零零一三八零零零");
        assert_eq!(out, "13800138000");
        let m = map.unwrap();
        // first surviving char was original index 1 (after the stripped zero-width)
        assert_eq!(m[0], 1);
        assert_eq!(m.len(), out.chars().count());
    }

    #[test]
    fn nfkc_expansion_maps_to_source_index() {
        // a ligature/compat char that NFKC-expands to multiple chars maps all to one source idx
        let (out, map) = normalize_text("ﬁx"); // ﬁ (U+FB01) → "fi"
        assert_eq!(out, "fix");
        let m = map.unwrap();
        assert_eq!(m[0], 0); // 'f' from source idx 0
        assert_eq!(m[1], 0); // 'i' also from source idx 0
        assert_eq!(m[2], 1); // 'x' from source idx 1
    }

    // Helper: slice the ORIGINAL string by a char-index span (the offset map and
    // map_spans_to_original both work in CHAR indices, not byte indices).
    fn orig_slice(original: &str, span: (usize, usize)) -> String {
        original
            .chars()
            .skip(span.0)
            .take(span.1 - span.0)
            .collect()
    }

    #[test]
    fn combining_precomposed_cafe_maps_back_to_full() {
        // "café" = c,a,f,é(U+00E9 precomposed). é → e + U+0301(dropped). Output "cafe",
        // one output char per source char, identity offset map.
        let original = "caf\u{00e9}";
        let (out, map) = normalize_text(original);
        assert_eq!(out, "cafe");
        let m = map.unwrap();
        assert_eq!(m, vec![0, 1, 2, 3]); // each output char inherits its source index
        // A span over the whole normalized token maps back to the WHOLE precomposed original.
        let mapped = map_spans_to_original(&[(0, 4)], Some(&m), original.chars().count());
        assert_eq!(mapped, vec![(0, 4)]);
        assert_eq!(orig_slice(original, mapped[0]), "caf\u{00e9}");
    }

    #[test]
    fn combining_decomposed_cafe_trailing_mark_behavior() {
        // "cafe" + U+0301 (decomposed): the accent is the LAST char of the token.
        // Source chars: c(0) a(1) f(2) e(3) ́(4). The mark is dropped; the surviving
        // 4 base chars keep indices 0..3. Output "cafe", offset map length 4.
        let original = "cafe\u{0301}";
        assert_eq!(original.chars().count(), 5); // 4 base + 1 combining mark
        let (out, map) = normalize_text(original);
        assert_eq!(out, "cafe");
        let m = map.unwrap();
        assert_eq!(m.len(), 4); // mark dropped: 4 output chars
        assert_eq!(m, vec![0, 1, 2, 3]);
        // Mapping the [0,4) span back: orig_end = map[3]+1 = 4, which points JUST PAST
        // the base 'e' and does NOT cover the trailing combining mark at original index 4.
        // KNOWN cosmetic artifact: redacting this span removes the PII ("cafe") but leaves
        // the orphaned U+0301 behind. This is NOT a PII leak — documented, not "fixed" here.
        let mapped = map_spans_to_original(&[(0, 4)], Some(&m), original.chars().count());
        assert_eq!(mapped, vec![(0, 4)]);
        assert_eq!(orig_slice(original, mapped[0]), "cafe"); // base chars covered
        // The trailing mark lives at original char index 4, outside the mapped [0,4) span.
        let tail: Vec<char> = original.chars().skip(4).collect();
        assert_eq!(tail, vec!['\u{0301}']); // orphaned mark remains after redaction
    }

    #[test]
    fn combining_mid_token_mark_covered_by_span() {
        // A decomposed mark MID-token, on a Cyrillic confusable: а(U+0430, →'a') + U+0301,
        // wrapped by ASCII so the mark is strictly interior. Source chars:
        // x(0) а(1) ́(2) y(3). The mark drops; the surviving base chars keep 0,1,3.
        let original = "x\u{0430}\u{0301}y";
        assert_eq!(original.chars().count(), 4);
        let (out, map) = normalize_text(original);
        assert_eq!(out, "xay"); // Cyrillic а folds to ASCII a; accent dropped
        let m = map.unwrap();
        assert_eq!(m, vec![0, 1, 3]); // note: index 2 (the mark) is skipped
        // A span over the whole token [0,3): orig_start=map[0]=0, orig_end=map[2]+1=4.
        // The mark's original index 2 falls INSIDE [0,4), so it IS covered/replaced.
        let mapped = map_spans_to_original(&[(0, 3)], Some(&m), original.chars().count());
        assert_eq!(mapped, vec![(0, 4)]);
        assert_eq!(orig_slice(original, mapped[0]), "x\u{0430}\u{0301}y"); // mark included
    }

    #[test]
    fn combining_fullwidth_digits_with_stray_accent() {
        // Fullwidth digit run (NFKC → ASCII) interleaved with a stray combining accent.
        // The accent must be dropped (Step 1b, before NFKC) and digits must still fold.
        // Source: １(0) ２(1) ́(2) ３(3). Mark drops at Step 1b; survivors keep 0,1,3;
        // then per-char NFKC folds the fullwidth digits to ASCII.
        let original = "\u{ff11}\u{ff12}\u{0301}\u{ff13}";
        let (out, map) = normalize_text(original);
        assert_eq!(out, "123"); // accent gone, fullwidth digits normalized
        let m = map.unwrap();
        assert_eq!(m.len(), 3); // one per surviving digit
        assert_eq!(m, vec![0, 1, 3]); // index 2 (the dropped mark) skipped
        let mapped = map_spans_to_original(&[(0, 3)], Some(&m), original.chars().count());
        // orig_start=0, orig_end=map[2]+1=4 — spans across the dropped mark.
        assert_eq!(mapped, vec![(0, 4)]);
        assert_eq!(orig_slice(original, mapped[0]), original); // whole original covered
    }

    #[test]
    fn combining_pure_ascii_returns_none() {
        // ASCII fast-path: no marks possible, identity mapping → None.
        assert_eq!(normalize_text("hello"), ("hello".into(), None));
    }

    #[test]
    fn combining_cjk_voicing_mark_preserved() {
        // U+3099 / U+309A (CJK voiced / semi-voiced sound marks) are nonspacing (Mn,
        // ccc=8) but are NOT diacritics: they distinguish CJK letters. で (U+3067, "de")
        // NFD-decomposes to て (U+3066, "te") + U+3099. Dropping U+3099 would silently
        // rewrite Japanese (de → te). The voicing mark must be PRESERVED so the
        // precomposed syllable round-trips unchanged through normalization.
        assert_eq!(canonical_combining_class('\u{3099}'), 8); // nonspacing but kept
        assert!(!is_droppable_mark('\u{3099}'));
        assert!(!is_droppable_mark('\u{309a}'));
        // "日本語ですよ" must pass through unchanged (no accents to fold, voicing kept).
        assert_eq!(
            normalize_text("\u{65e5}\u{672c}\u{8a9e}\u{3067}\u{3059}\u{3088}"),
            ("\u{65e5}\u{672c}\u{8a9e}\u{3067}\u{3059}\u{3088}".into(), None)
        );
    }

    #[test]
    fn combining_hangul_not_shattered() {
        // Precomposed Hangul syllables NFD-decompose into conjoining jamo (all ccc=0,
        // none droppable). Step 1b must NOT decompose them — it keeps the original char
        // when there is no mark to drop — so the output stays precomposed (byte-identical)
        // and Korean detection is unaffected. (Unconditional NFD would emit decomposed
        // jamo, since per-char NFKC in Step 3 does not recompose across separate chars.)
        let original = "\u{d55c}\u{ad6d}\u{c5b4}"; // 한국어
        assert_eq!(normalize_text(original), (original.to_string(), None));
    }

    #[test]
    fn combining_indic_spacing_mark_preserved() {
        // U+093E DEVANAGARI VOWEL SIGN AA is a SPACING mark (Mc, ccc=0). It must be
        // PRESERVED — we only drop NONSPACING marks (Mn, ccc!=0). Proves we test
        // canonical_combining_class, not is_combining_mark (which would match Mc too).
        assert_eq!(canonical_combining_class('\u{093e}'), 0); // spacing: ccc 0 → kept
        assert_eq!(canonical_combining_class('\u{0301}'), 230); // nonspacing accent → dropped
        let (out, _map) = normalize_text("\u{0915}\u{093e}"); // क + ◌ा (vowel sign AA)
        assert!(
            out.contains('\u{093e}'),
            "Indic spacing vowel sign U+093E must survive Step 1b; got {out:?}"
        );
    }

    // ── Mutation-kill guards (cargo-mutants survivors) ───────────────────────

    #[test]
    fn cn_digit_financial_and_nine_arms_fold() {
        // cn_digit match arms for 九 and the formal/financial digits 壹-玖 were
        // unexercised by the Rust suite (the phone tests use only 一二三…八零). Each
        // arm maps a CJK digit to its ASCII value; deleting any arm makes that char
        // a non-digit, so a run containing it no longer reaches the 7+ majority
        // fold. A single all-CJK run over every financial arm folds to ASCII.
        // 壹贰叁肆伍陆柒捌玖 (9 chars, 100% CJK) → strict majority → "123456789".
        assert_eq!(normalize_text("壹贰叁肆伍陆柒捌玖").0, "123456789");
        // A run including 九 (first-row nine) + 零: 七八九零壹贰叁 → "7890123".
        assert_eq!(normalize_text("七八九零壹贰叁").0, "7890123");
    }

    #[test]
    fn digit_sequence_majority_boundary_strict() {
        // normalize_digit_sequences L121 `cn_count * 2 > run.len()` — the STRICT
        // majority test, plus the per-step `i += 1` run-walk (L98).
        //
        // 4 CJK (一二三四) + 3 ASCII (567) = "1234567", folded (4*2=8 > 7).
        assert_eq!(normalize_text("一二三四567").0, "1234567");
        // 3 CJK (一二三) + 4 ASCII (4567) — minority CJK → run left UNFOLDED; the CJK
        // digits stay as the original chars (3*2=6, NOT > 7). This pins `*` vs `+`:
        // a `*`→`+` mutant turns the 4-CJK fold case above into `4+2=6 > 7` false →
        // would NOT fold (HEAD folds), so the two opposite outcomes lock it.
        assert_eq!(normalize_text("一二三4567").0, "一二三4567");
        // EXACT-HALF boundary: 4 CJK + 4 ASCII = 8 chars, `4*2 = 8`, NOT > 8 → HEAD
        // does NOT fold. Mutating `>` to `>=` (`8 >= 8` true) WOULD fold it, so
        // asserting the run stays as original chars kills the `>=` survivor.
        assert_eq!(normalize_text("一二三四5678").0, "一二三四5678");
        // Leading-ASCII run that pins the per-step advance `i += 1` (L98). The first
        // digit is ASCII '5'; the run is 7 chars (1 ASCII + 4 CJK + 2 ASCII), 4 CJK →
        // 4*2=8 > 7 → folds to "5123467". A `+=`→`*=` mutant leaves `i` parked on the
        // first index, re-counting it: the run length inflates to 8 while cn_count
        // stays 4 → `8 > 8` false → would NOT fold. (`*=` here does not loop forever
        // because the inner loop's own `i += 1` still advances past the second char.)
        assert_eq!(normalize_text("5一二三四67").0, "5123467");
    }

    #[test]
    fn is_digit_sep_joins_separated_digit_run() {
        // is_digit_sep (L71-74) lets a separator (space/dot/-/，/…) sit INSIDE a
        // digit run without breaking it, so "一二三-四五六-七" is one 7-digit run
        // that folds to "123-456-7"... no — the seps are SKIPPED, not emitted, so
        // the folded run drops them: the run collects 7 CJK digits → "1234567" with
        // the separators removed from the digit positions only (they remain in text
        // at their own indices). Mutating `is_digit_sep` to always-`false` would
        // break the run at the first separator (each sub-run < 7) → no fold.
        // Verify the separated CJK run still folds (the separator does not abort it).
        let out = normalize_text("一二三 四五六 七").0;
        assert!(
            out.starts_with('1') && out.contains('7') && !out.contains('一'),
            "separated CJK digit run must still fold; got {out:?}"
        );
    }

    #[test]
    fn map_spans_to_original_out_of_range_clamps() {
        // map_spans_to_original boundary clamps (L282, L287). For an out-of-range
        // span the helper must return `original_len` rather than indexing past the
        // offset map. Each mutated comparison would index out of bounds (panic) or
        // underflow on these spans, so asserting the clamped result kills them:
        //   - L282 `start < map.len()` → `<=`: span start == map.len() would index
        //     map[len] (panic); HEAD returns original_len.
        //   - L287 `end > 0` → `>=`: span end == 0 would compute `end - 1` (usize
        //     underflow panic); HEAD returns original_len.
        //   - L287 `end - 1 < map.len()` → `<=` and the `&&` → `||`: span end ==
        //     map.len() + 1 (or beyond) would index map[end-1] (panic); HEAD clamps.
        let map = vec![0_usize, 2, 4]; // len 3
        let orig_len = 6;
        // start == map.len() (3): orig_start clamps to original_len.
        assert_eq!(
            map_spans_to_original(&[(3, 5)], Some(&map), orig_len),
            vec![(6, 6)]
        );
        // end == 0: orig_end clamps to original_len (and `end - 1` is never reached).
        assert_eq!(
            map_spans_to_original(&[(0, 0)], Some(&map), orig_len),
            vec![(0, 6)]
        );
        // end == map.len() + 1 (4) with an in-range start: orig_end clamps; this
        // also exercises the `&&` guard (end > 0 is true, end-1 < len is false).
        assert_eq!(
            map_spans_to_original(&[(1, 4)], Some(&map), orig_len),
            vec![(2, 6)]
        );
        // A fully out-of-range span (both ends past the map): both clamp.
        assert_eq!(
            map_spans_to_original(&[(5, 9)], Some(&map), orig_len),
            vec![(6, 6)]
        );
    }

    // ---- Default_Ignorable strip table ----------------------------------

    #[test]
    fn default_ignorable_table_is_sorted_and_disjoint() {
        // binary_search_by over the table is only correct if it is sorted and
        // the ranges do not touch or overlap (touching ranges should be merged).
        let mut prev: Option<char> = None;
        for &(lo, hi) in DEFAULT_IGNORABLE {
            assert!(lo <= hi, "inverted range {lo:?}..{hi:?}");
            if let Some(p) = prev {
                assert!(p < lo, "unsorted or unmerged at {lo:?} (prev end {p:?})");
                assert!(
                    (p as u32) + 1 < (lo as u32),
                    "adjacent ranges must be merged: {p:?} then {lo:?}"
                );
            }
            prev = Some(hi);
        }
        let total: u32 = DEFAULT_IGNORABLE
            .iter()
            .map(|&(lo, hi)| hi as u32 - lo as u32 + 1)
            .sum();
        assert_eq!(DEFAULT_IGNORABLE.len(), 17);
        assert_eq!(total, 4174, "Unicode Default_Ignorable_Code_Point cardinality");
    }

    #[test]
    fn default_ignorable_is_a_superset_of_the_old_hand_list() {
        // Strict widening: every carrier the pre-table implementation stripped
        // must still be stripped. Nothing may silently stop being invisible.
        let old: Vec<char> = "\u{200b}\u{200c}\u{200d}\u{00ad}\u{feff}\u{200e}\u{200f}\
             \u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}\
             \u{2060}\u{2061}\u{2062}\u{2063}\u{2064}\u{fe00}\u{fe0f}\
             \u{e0000}\u{e0001}\u{e007f}\u{e0100}\u{e01ef}"
            .chars()
            .collect();
        for c in old {
            assert!(is_invisible(c), "regression: U+{:04X} no longer stripped", c as u32);
        }
    }

    #[test]
    fn default_ignorable_covers_the_carriers_the_hand_list_missed() {
        // The widening's payload: these render invisibly and used to survive
        // normalization, so each one was a free token-splitter.
        for c in [
            '\u{034f}', '\u{061c}', '\u{115f}', '\u{1160}', '\u{17b4}', '\u{180b}',
            '\u{180e}', '\u{180f}', '\u{2065}', '\u{206a}', '\u{206f}', '\u{3164}',
            '\u{ffa0}', '\u{fff0}', '\u{fff8}', '\u{1bca0}', '\u{1d173}', '\u{1d17a}',
            '\u{e0080}', '\u{e0fff}',
        ] {
            assert!(is_invisible(c), "U+{:04X} should be ignorable", c as u32);
        }
        // Neighbours just outside the ranges must NOT be stripped.
        for c in ['\u{034e}', '\u{2070}', '\u{3163}', '\u{3165}', '\u{e1000}', 'a', '中'] {
            assert!(!is_invisible(c), "U+{:04X} must survive", c as u32);
        }
    }

    #[test]
    fn ignorable_interior_to_a_digit_run_is_stripped_so_the_number_refuses() {
        // The point of the strip: a carrier hidden INSIDE a number must not split
        // it. U+206A is one of the newly covered ones.
        assert_eq!(normalize_text("1380013800\u{206a}0").0, "13800138000");
        assert_eq!(normalize_text("138001\u{e0200}38000").0, "13800138000");
    }

    // ---- No/So digit-yielding NFKC folds (boundary integrity) ------------

    #[test]
    fn digit_yielding_table_is_sorted_and_disjoint() {
        let mut prev: Option<char> = None;
        for &(lo, hi) in NFKC_DIGIT_YIELDING_NON_DECIMAL {
            assert!(lo <= hi);
            if let Some(p) = prev {
                assert!((p as u32) + 1 < (lo as u32), "unsorted/unmerged at {lo:?}");
            }
            prev = Some(hi);
        }
        let total: u32 = NFKC_DIGIT_YIELDING_NON_DECIMAL
            .iter()
            .map(|&(lo, hi)| hi as u32 - lo as u32 + 1)
            .sum();
        assert_eq!(total, 222);
    }

    #[test]
    fn minority_non_decimal_beside_a_number_is_not_folded() {
        // SECURITY: NFKC folds ¹ -> '1'. Folding it beside an 11-digit phone
        // manufactures a 12th digit, the phone regex's `(?!\d)` anchor fails and
        // the number leaks verbatim. Same shape as the CJK-homograph guard.
        assert_eq!(normalize_text("13800138000\u{b9}").0, "13800138000\u{b9}");
        assert_eq!(normalize_text("\u{b9}13800138000").0, "\u{b9}13800138000");
        // Multi-char folds are carriers too: ½ -> "1⁄2" puts a '1' against the run.
        assert_eq!(normalize_text("13800138000\u{bd}").0, "13800138000\u{bd}");
        assert_eq!(normalize_text("\u{bd}13800138000").0, "\u{bd}13800138000");
        // Circled, subscript, CJK compat month, squared unit.
        assert_eq!(normalize_text("13800138000\u{2460}").0, "13800138000\u{2460}");
        assert_eq!(normalize_text("13800138000\u{2085}").0, "13800138000\u{2085}");
        assert_eq!(normalize_text("13800138000\u{32c0}").0, "13800138000\u{32c0}");
        assert_eq!(normalize_text("13800138000\u{339f}").0, "13800138000\u{339f}");
    }

    #[test]
    fn majority_non_decimal_run_still_folds() {
        // A number written ENTIRELY in circled digits is obfuscated PII, not a
        // neighbour — the majority rule keeps folding it, so it is still detected.
        assert_eq!(
            normalize_text("\u{2460}\u{2462}\u{2467}\u{24ea}\u{24ea}\u{2460}\u{2462}\u{2467}\u{24ea}\u{24ea}\u{24ea}").0,
            "13800138000"
        );
        // And an isolated superscript/fraction/unit — no digit run to fuse with —
        // folds exactly as before (the frozen normalize parity corpus depends on it).
        assert_eq!(normalize_text("x\u{b2}\u{b3} super").0, "x23 super");
        assert_eq!(normalize_text("\u{bd}").0, "1\u{2044}2");
        assert_eq!(normalize_text("\u{339f}").0, "mm2");
    }

    #[test]
    fn suppressed_fold_keeps_the_offset_map_aligned() {
        // Suppressing the fold makes the normalized view IDENTICAL to the source,
        // so the map degrades to the identity (None) — the cheapest possible
        // outcome. Not folding never grows the map.
        assert_eq!(
            normalize_text("13800138000\u{bd}"),
            ("13800138000\u{bd}".to_string(), None)
        );
        // With something else in the text to normalize, the map is still 1:1 with
        // the emitted chars and the suppressed char occupies exactly one slot.
        let (out, map) = normalize_text("\u{ff21}13800138000\u{bd}"); // Ａ + phone + ½
        let map = map.expect("text changed => map present");
        assert_eq!(out, "A13800138000\u{bd}");
        assert_eq!(out.chars().count(), map.len());
        assert_eq!(map, (0..13).collect::<Vec<_>>());
        // A ½ with no digit run beside it DOES fold, still expanding 1 source -> 3.
        let (out2, map2) = normalize_text("\u{bd}\u{4e2d}");
        assert_eq!(out2, "1\u{2044}2\u{4e2d}");
        assert_eq!(map2.unwrap(), vec![0, 0, 0, 1]);
    }

    #[test]
    fn cjk_homograph_guard_is_undisturbed() {
        // The precedent this rule was modelled on must behave exactly as before.
        assert_eq!(normalize_text("张三13800138000").0, "张三13800138000");
        assert_eq!(normalize_text("一三八零零一三八零零零").0, "13800138000");
        assert_eq!(normalize_text("一二三四五六7").0, "1234567");
        assert_eq!(normalize_text("三月三日"), ("三月三日".into(), None));
    }

    #[test]
    fn ignorable_strip_and_fold_suppression_compose() {
        // The strip pass removes the carrier, then the fold pass sees the true neighbourhood: ¹ is a
        // minority of the fused run and still must not fold.
        assert_eq!(
            normalize_text("13800138000\u{206a}\u{b9}").0,
            "13800138000\u{b9}"
        );
    }
}

