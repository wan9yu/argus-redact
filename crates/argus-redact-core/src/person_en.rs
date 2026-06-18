//! English person-name detection — Rust port of `lang/en/person.py`.
//!
//! Unlike the zh detector there is NO evidence scoring: English surnames have
//! minimal overlap with common words, so the algorithm is a surname-list match
//! plus a 1-2 token given-name look-back. `detect_person_names` is the only
//! `pub` surface.
//!
//! ## Char offsets, not byte offsets
//!
//! Python `re` match positions (`m.start()`/`m.end()`) and all
//! `PatternMatch.start/end` are **character** (Unicode scalar) offsets on a
//! `str`. `fancy_regex` returns **byte** offsets. Every regex offset that
//! reaches a result or the `seen_spans` set is converted via
//! [`crate::reserved_range::byte_to_char_offset`], and the adjacency-gap and
//! result-text slices operate in char-space (over a `Vec<char>` of the source),
//! so a non-ASCII char anywhere shifts offsets correctly. English text is
//! usually ASCII (byte == char), but the golden / adversarial tests exercise a
//! multi-byte prefix.

use std::collections::HashSet;
use std::sync::LazyLock;

use fancy_regex::Regex;

use crate::person_data::{given_names_en_set, surnames_en_set};
use crate::reserved_range::byte_to_char_offset;
use crate::types::PatternMatch;

/// `_TOKEN_PAT` — tokenize into "Capitalized" words or a single-letter initial
/// like `J.`. Mirrors Python `re.compile(r"\b[A-Z][a-z]+\b|\b[A-Z]\.")`.
/// Lowercase / punctuation runs between tokens act as gaps delimiting candidate
/// name spans.
static TOKEN_PAT: LazyLock<Regex> = LazyLock::new(|| {
    let pat = r"\b[A-Z][a-z]+\b|\b[A-Z]\.";
    Regex::new(pat)
        .unwrap_or_else(|e| panic!("person_en: _TOKEN_PAT compile failed: {e}\nPattern: {pat}"))
});

/// A `_TOKEN_PAT` match: its text plus **char** start/end offsets.
struct Token {
    word: String,
    start: usize,
    end: usize,
}

/// Detect English person names via surname-list match + optional given-name boost.
///
/// Direct port of `detect_person_names(text, *, known_names=None)`. The Python
/// keyword-argument default (`known_names=None`) is resolved at the binding
/// layer; here the caller passes an empty slice for "no known_names".
///
/// ```python
/// results: list[PatternMatch] = []
/// seen_spans: set[tuple[int, int]] = set()
///
/// # Phase 1: known_names exact match wins (confidence 1.0).
/// if known_names:
///     sorted_names = sorted((n for n in known_names if n), key=len, reverse=True)
///     if sorted_names:
///         known_pat = re.compile("|".join(re.escape(n) for n in sorted_names))
///         for m in known_pat.finditer(text):
///             span = (m.start(), m.end())
///             if span not in seen_spans:
///                 results.append(PatternMatch(text=m.group(0), type="person",
///                                             start=m.start(), end=m.end(),
///                                             confidence=1.0))
///                 seen_spans.add(span)
///
/// # Phase 2: tokenize, scan for surnames, look back.
/// tokens = list(_TOKEN_PAT.finditer(text))
/// for i, tok in enumerate(tokens):
///     word = tok.group()
///     if word not in SURNAME_SET:
///         continue
///     if i == 0:
///         continue
///     prev = tokens[i - 1]
///     gap = text[prev.end() : tok.start()]
///     if gap.strip(" \t.") != "":
///         continue
///     first = prev.group()
///     match_start = prev.start()
///     if i >= 2:
///         prev2 = tokens[i - 2]
///         gap2 = text[prev2.end() : prev.start()]
///         prev2_word = prev2.group().rstrip(".")
///         if gap2.strip(" \t.") == "" and prev2_word in GIVEN_NAME_SET:
///             match_start = prev2.start()
///             first = prev2.group()
///     span = (match_start, tok.end())
///     if span in seen_spans:
///         continue
///     first_clean = first.rstrip(".")
///     confidence = 1.0 if first_clean in GIVEN_NAME_SET else 0.9
///     results.append(PatternMatch(text=text[match_start : tok.end()],
///                                 type="person", start=match_start,
///                                 end=tok.end(), confidence=confidence))
///     seen_spans.add(span)
/// return results
/// ```
///
/// ## Bit-identity notes
///
/// - `PatternMatch` fields mirror Python exactly: `type_ = "person"`,
///   `start`/`end` = char offsets, `confidence` = 1.0 (known name, or
///   given-name-led) / 0.9 (surname with adjacent non-given-name leading token),
///   and `layer = 0` — Python's `PatternMatch(...)` is built WITHOUT a `layer`
///   kwarg, so the dataclass default (`layer = 0`) applies.
/// - Known names are matched FIRST via one alternation regex of the `re.escape`-d
///   names sorted longest-first (`key=len, reverse=True`, a STABLE sort), then a
///   non-overlapping `find_iter` (≡ `re.finditer`). Each hit is `seen_spans`-deduped
///   on the EXACT `(start, end)` char span.
/// - The adjacency gap test is the exact Python expression
///   `text[prev_end:tok_start].strip(" \t.") == ""` — the strip set is
///   space / tab / dot, replicated char-for-char.
/// - A leading token is `rstrip(".")`-cleaned before the `GIVEN_NAME_SET`
///   membership test (so an initial like `J.` is tested as `J`).
/// - Result ORDER is Python's append order: Phase-1 known names first (in
///   regex-match order), then Phase-2 surname matches (in token-scan order). No
///   final sort.
pub fn detect_person_names(text: &str, known_names: &[String]) -> Vec<PatternMatch> {
    let mut results: Vec<PatternMatch> = Vec::new();
    // (start, end) char spans already emitted — dedup is on the exact pair.
    let mut seen_spans: HashSet<(usize, usize)> = HashSet::new();

    // Source as chars so every slice / strip stays in char-space.
    let text_chars: Vec<char> = text.chars().collect();

    // ── Phase 1: known_names exact match (confidence 1.0). ──
    //   sorted_names = sorted((n for n in known_names if n), key=len, reverse=True)
    // Python `key=len` is the char length of the str; STABLE sort keeps the
    // original order among equal-length names.
    if !known_names.is_empty() {
        let mut sorted_names: Vec<&String> =
            known_names.iter().filter(|n| !n.is_empty()).collect();
        if !sorted_names.is_empty() {
            sorted_names
                .sort_by_key(|n| std::cmp::Reverse(n.chars().count()));
            // known_pat = "|".join(re.escape(n) for n in sorted_names)
            let alt = sorted_names
                .iter()
                .map(|n| fancy_regex::escape(n).into_owned())
                .collect::<Vec<_>>()
                .join("|");
            let known_pat = Regex::new(&alt).unwrap_or_else(|e| {
                panic!("person_en: known_names regex compile failed: {e}\nPattern: {alt}")
            });
            for m in known_pat.find_iter(text) {
                let m = m.unwrap();
                let start = byte_to_char_offset(text, m.start());
                let end = byte_to_char_offset(text, m.end());
                let span = (start, end);
                if !seen_spans.contains(&span) {
                    results.push(PatternMatch {
                        text: m.as_str().to_string(),
                        type_: "person".to_string(),
                        start,
                        end,
                        confidence: 1.0,
                        layer: 0,
                    });
                    seen_spans.insert(span);
                }
            }
        }
    }

    // ── Phase 2: tokenize, scan for surnames, look back. ──
    let surnames = surnames_en_set();
    let given_names = given_names_en_set();

    // tokens = list(_TOKEN_PAT.finditer(text)) — char offsets.
    let tokens: Vec<Token> = TOKEN_PAT
        .find_iter(text)
        .map(|m| {
            let m = m.unwrap();
            Token {
                word: m.as_str().to_string(),
                start: byte_to_char_offset(text, m.start()),
                end: byte_to_char_offset(text, m.end()),
            }
        })
        .collect();

    for i in 0..tokens.len() {
        let tok = &tokens[i];
        // if word not in SURNAME_SET: continue
        if !surnames.contains(&tok.word) {
            continue;
        }
        // if i == 0: continue  (a surname with no preceding token is not matched)
        if i == 0 {
            continue;
        }
        let prev = &tokens[i - 1];
        // gap = text[prev.end() : tok.start()]; if gap.strip(" \t.") != "": continue
        if !gap_is_blank(&text_chars, prev.end, tok.start) {
            continue;
        }

        // first = prev.group(); match_start = prev.start()
        let mut first: &str = &prev.word;
        let mut match_start = prev.start;

        // Optional prev2 extension: only when prev2 is itself a known given name.
        if i >= 2 {
            let prev2 = &tokens[i - 2];
            // gap2 = text[prev2.end() : prev.start()]
            // prev2_word = prev2.group().rstrip(".")
            let prev2_word = rstrip_dot(&prev2.word);
            if gap_is_blank(&text_chars, prev2.end, prev.start)
                && given_names.contains(prev2_word)
            {
                match_start = prev2.start;
                first = &prev2.word;
            }
        }

        let span = (match_start, tok.end);
        if seen_spans.contains(&span) {
            continue;
        }
        // first_clean = first.rstrip(".")
        // confidence = 1.0 if first_clean in GIVEN_NAME_SET else 0.9
        let first_clean = rstrip_dot(first);
        let confidence = if given_names.contains(first_clean) { 1.0 } else { 0.9 };

        // text = text[match_start : tok.end()] (char slice)
        let matched_text: String = text_chars[match_start..tok.end].iter().collect();
        results.push(PatternMatch {
            text: matched_text,
            type_: "person".to_string(),
            start: match_start,
            end: tok.end,
            confidence,
            layer: 0,
        });
        seen_spans.insert(span);
    }

    results
}

/// Python `text[a:b].strip(" \t.") == ""` over a char slice — true when the
/// gap is empty or contains only spaces, tabs, and dots. `a`/`b` are char
/// offsets; `a <= b` always holds for adjacent forward tokens.
fn gap_is_blank(text_chars: &[char], a: usize, b: usize) -> bool {
    if a >= b {
        return true;
    }
    text_chars[a..b]
        .iter()
        .all(|c| *c == ' ' || *c == '\t' || *c == '.')
}

/// Python `s.rstrip(".")` — strip trailing dots (only `.`, matching the source).
fn rstrip_dot(s: &str) -> &str {
    s.trim_end_matches('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (text, start, end, confidence) projection — confidence compared EXACTLY.
    /// Also asserts every result is `type_ == "person"` and `layer == 0`.
    fn detect(text: &str, known: &[&str]) -> Vec<(String, usize, usize, f64)> {
        let known: Vec<String> = known.iter().map(|s| s.to_string()).collect();
        detect_person_names(text, &known)
            .into_iter()
            .map(|m| {
                assert_eq!(m.type_, "person");
                assert_eq!(m.layer, 0);
                (m.text, m.start, m.end, m.confidence)
            })
            .collect()
    }

    fn row(text: &str, start: usize, end: usize, conf: f64) -> (String, usize, usize, f64) {
        (text.to_string(), start, end, conf)
    }

    // ── Expected values below were CAPTURED FROM LIVE PYTHON (pyenv 3.11.3) ──
    // Inputs sourced from the T1 en golden corpus
    // (tests/core/fixtures/en_person_detection_v076.json) and
    // tests/detection/lang/test_en_person.py. Capture command:
    //   python3 -c "
    //   from argus_redact.lang.en.person import detect_person_names as d
    //   print([(m.text, m.start, m.end, m.confidence) for m in d('TEXT', known_names=[...])])
    //   "
    // Each expectation below is the verbatim output and is asserted with `==`.

    #[test]
    fn known_names_exact_match() {
        // en_known_names_exact "O'Brien filed the report." known=["O'Brien"].
        // Python: [("O'Brien", 0, 7, 1.0)]
        assert_eq!(
            detect("O'Brien filed the report.", &["O'Brien"]),
            vec![row("O'Brien", 0, 7, 1.0)]
        );
    }

    #[test]
    fn surname_plus_known_given() {
        // en_surname_plus_known_given "Email John Smith today." — "John" is a
        // known given name → confidence 1.0; "Email" is not a given name so the
        // prev2 extension does not fire.
        // Python: [('John Smith', 6, 16, 1.0)]
        assert_eq!(
            detect("Email John Smith today.", &[]),
            vec![row("John Smith", 6, 16, 1.0)]
        );
    }

    #[test]
    fn surname_plus_unknown_given() {
        // en_surname_plus_unknown_given "Quincy Smith arrived." — "Quincy" is not
        // in GIVEN_NAME_SET but "Smith" is a surname → confidence 0.9.
        // Python: [('Quincy Smith', 0, 12, 0.9)]
        assert_eq!(
            detect("Quincy Smith arrived.", &[]),
            vec![row("Quincy Smith", 0, 12, 0.9)]
        );
    }

    #[test]
    fn single_surname_alone_no_match() {
        // en_single_surname_alone "Smith arrived." — a surname with no preceding
        // adjacent token (i == 0) is intentionally NOT matched.
        // Python: []
        assert!(detect("Smith arrived.", &[]).is_empty());
    }

    #[test]
    fn initial_form_j_smith() {
        // en_initial_form "J. Smith joined." — "J." is the single-initial token
        // form; rstrip('.') → "J" is not a given name → confidence 0.9. The dot
        // between "J." and "Smith" is inside the gap strip-set (space/tab/dot).
        // Python: [('J. Smith', 0, 8, 0.9)]
        assert_eq!(
            detect("J. Smith joined.", &[]),
            vec![row("J. Smith", 0, 8, 0.9)]
        );
    }

    #[test]
    fn adjacency_gap_negative() {
        // en_adjacency_gap_negative "John, Smith arrived." — the comma between
        // "John" and "Smith" is NOT in the strip-set (space/tab/dot), so the gap
        // is non-blank → no look-back → no match (a lone surname is not emitted).
        // Python: []
        assert!(detect("John, Smith arrived.", &[]).is_empty());
    }

    #[test]
    fn middle_initial_three_token() {
        // en_middle_initial "John A. Smith joined." — prev token "A." is adjacent
        // (gap " "); the prev2 extension fires because prev2 "John" is a given
        // name → match starts at "John", first_clean "John" in GIVEN → 1.0.
        // Python: [('John A. Smith', 0, 13, 1.0)]
        assert_eq!(
            detect("John A. Smith joined.", &[]),
            vec![row("John A. Smith", 0, 13, 1.0)]
        );
    }

    #[test]
    fn first_middle_last_three_token() {
        // en_first_middle_last "Mary Ann Johnson called." — prev "Ann" adjacent;
        // prev2 "Mary" is a given name → extend back to "Mary"; first_clean
        // "Mary" in GIVEN → 1.0.
        // Python: [('Mary Ann Johnson', 0, 16, 1.0)]
        assert_eq!(
            detect("Mary Ann Johnson called.", &[]),
            vec![row("Mary Ann Johnson", 0, 16, 1.0)]
        );
    }

    #[test]
    fn prev2_not_given_no_extension() {
        // "Foo John Smith." — prev "John" adjacent; prev2 "Foo" is NOT a given
        // name → no extension, match is "John Smith"; first_clean "John" in
        // GIVEN → 1.0.
        // Python: [('John Smith', 4, 14, 1.0)]
        assert_eq!(
            detect("Foo John Smith.", &[]),
            vec![row("John Smith", 4, 14, 1.0)]
        );
    }

    #[test]
    fn lowercase_surname_negative() {
        // en_lowercase_surname_negative "john smith called." — lowercase tokens
        // are not matched by _TOKEN_PAT → no surname token → no match.
        // Python: []
        assert!(detect("john smith called.", &[]).is_empty());
    }

    #[test]
    fn unknown_surname_negative() {
        // en_unknown_surname_negative "John Xeoplux arrived." — "Xeoplux" is not
        // in SURNAME_SET → no surname token to anchor → no match.
        // Python: []
        assert!(detect("John Xeoplux arrived.", &[]).is_empty());
    }

    #[test]
    fn no_capitalized_pattern() {
        // en_no_capitalized_pattern "call them later" — no capitalized token →
        // no tokens → no match.
        // Python: []
        assert!(detect("call them later", &[]).is_empty());
    }

    #[test]
    fn non_ascii_prefix_char_offsets() {
        // Multi-byte emoji prefix to exercise char-vs-byte offset conversion.
        // "🎉 Email John Smith today." — the emoji is 1 char (4 bytes), so
        // "John Smith" is at CHAR 8..18 (byte 11..21). If byte offsets leaked,
        // start/end would be wrong and the result text would mis-slice.
        // Python: [('John Smith', 8, 18, 1.0)]
        assert_eq!(
            detect("🎉 Email John Smith today.", &[]),
            vec![row("John Smith", 8, 18, 1.0)]
        );
    }

    #[test]
    fn dot_gap_title_prefix() {
        // "Mr. Smith arrived." — "Mr" is a token, the "." before "Smith" is in
        // the gap strip-set so the gap is blank; "Mr" is not a given name → 0.9,
        // and text[0:9] = "Mr. Smith".
        // Python: [('Mr. Smith', 0, 9, 0.9)]
        assert_eq!(
            detect("Mr. Smith arrived.", &[]),
            vec![row("Mr. Smith", 0, 9, 0.9)]
        );
    }

    #[test]
    fn call_john_smith_offset() {
        // test_en_person.py "Call John Smith at 555-1234" — "Call" is not a given
        // name, prev "John" is → match "John Smith" at 5..15, confidence 1.0.
        // Python: [('John Smith', 5, 15, 1.0)]
        assert_eq!(
            detect("Call John Smith at 555-1234", &[]),
            vec![row("John Smith", 5, 15, 1.0)]
        );
    }
}
