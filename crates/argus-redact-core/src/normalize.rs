//! Unicode normalization for PII detection (port of pure/normalize.py).
//!
//! Pipeline (must stay bit-identical to the Python original):
//!   1. ASCII fast-path (skip everything if pure ASCII)
//!   2. Strip invisible / direction-control characters (build char-index offset map)
//!   3. Replace confusables (Cyrillic/Greek -> Latin), 1:1
//!   4. Per-char NFKC normalization (each source char normalized independently —
//!      NO cross-char composition) — only run if the joined string isn't already NFKC
//!   5. Contextual digit normalization (Chinese-digit sequences -> ASCII digits)
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::is_nfkc;

const MIN_DIGIT_SEQ: usize = 7; // shortest PII (phone fragments)

fn is_invisible(c: char) -> bool {
    // _INVISIBLE (normalize.py:19-38) — 16 codepoints
    matches!(c,
        '\u{200b}'|'\u{200c}'|'\u{200d}'|'\u{00ad}'|'\u{feff}'|'\u{200e}'|'\u{200f}'|
        '\u{202a}'|'\u{202b}'|'\u{202c}'|'\u{202d}'|'\u{202e}'|'\u{2066}'|'\u{2067}'|'\u{2068}'|'\u{2069}')
}

fn confusable(c: char) -> char {
    // _CONFUSABLES (normalize.py:43-95): Cyrillic + Greek -> Latin, 1:1 (47 entries)
    match c {
        // Cyrillic -> Latin
        '\u{0430}'=>'a','\u{0435}'=>'e','\u{043e}'=>'o','\u{0440}'=>'p','\u{0441}'=>'c',
        '\u{0443}'=>'y','\u{0445}'=>'x','\u{0456}'=>'i','\u{04bb}'=>'h','\u{0432}'=>'b',
        '\u{043a}'=>'k','\u{043c}'=>'m','\u{0442}'=>'t','\u{043d}'=>'h','\u{0410}'=>'A',
        '\u{0412}'=>'B','\u{0415}'=>'E','\u{041a}'=>'K','\u{041c}'=>'M','\u{041d}'=>'H',
        '\u{041e}'=>'O','\u{0420}'=>'P','\u{0421}'=>'C','\u{0422}'=>'T','\u{0425}'=>'X','\u{0423}'=>'Y',
        // Greek -> Latin
        '\u{03bf}'=>'o','\u{03b1}'=>'a','\u{03b5}'=>'e','\u{03b9}'=>'i','\u{03ba}'=>'k',
        '\u{03bd}'=>'v','\u{03c1}'=>'p','\u{03c4}'=>'t','\u{039f}'=>'O','\u{0391}'=>'A',
        '\u{0392}'=>'B','\u{0395}'=>'E','\u{0397}'=>'H','\u{0399}'=>'I','\u{039a}'=>'K',
        '\u{039c}'=>'M','\u{039d}'=>'N','\u{03a1}'=>'P','\u{03a4}'=>'T','\u{03a7}'=>'X','\u{0396}'=>'Z',
        other => other,
    }
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
        let has_cn = run.iter().any(|&idx| cn_digit(chars[idx]).is_some());
        if run.len() >= MIN_DIGIT_SEQ && has_cn {
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
    if text.is_ascii() {
        return (text.to_string(), None);
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
    // Step 4: Chinese-digit-sequence normalization
    normalize_digit_sequences(&mut chars);

    let result: String = chars.iter().collect();
    if result == text {
        (text.to_string(), None)
    } else {
        (result, Some(offset_map))
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
    fn cn_digit_phone() {
        let (out, _map) = normalize_text("一三八零零一三八零零零");
        assert_eq!(out, "13800138000");
    }

    #[test]
    fn short_cn_unchanged() {
        // 三月三日 — not a 7+ digit run → unchanged → None
        assert_eq!(normalize_text("三月三日"), ("三月三日".into(), None));
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
}
