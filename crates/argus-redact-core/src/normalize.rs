//! Unicode normalization for PII detection (port of pure/normalize.py).
//!
//! Pipeline:
//!   1. ASCII fast-path (skip everything if pure ASCII)
//!   2. Strip invisible / direction-control characters (build char-index offset map)
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

fn is_invisible(c: char) -> bool {
    // _INVISIBLE (normalize.py:19-38) — 16 codepoints
    matches!(c,
        '\u{200b}'|'\u{200c}'|'\u{200d}'|'\u{00ad}'|'\u{feff}'|'\u{200e}'|'\u{200f}'|
        '\u{202a}'|'\u{202b}'|'\u{202c}'|'\u{202d}'|'\u{202e}'|'\u{2066}'|'\u{2067}'|'\u{2068}'|'\u{2069}')
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

fn cn_digit(c: char) -> Option<char> {
    // _CN_DIGIT_MAP (normalize.py:98-118): 19 entries -> ASCII digit char
    Some(match c {
        '一'=>'1','二'=>'2','三'=>'3','四'=>'4','五'=>'5','六'=>'6','七'=>'7','八'=>'8','九'=>'9','零'=>'0',
        '壹'=>'1','贰'=>'2','叁'=>'3','肆'=>'4','伍'=>'5','陆'=>'6','柒'=>'7','捌'=>'8','玖'=>'9',
        _ => return None,
    })
}

fn is_digit_sep(c: char) -> bool {
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
        let mut new_chars: Vec<char> = Vec::new();
        let mut new_map: Vec<usize> = Vec::new();
        for (si, ch) in joined.chars().enumerate() {
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
}

