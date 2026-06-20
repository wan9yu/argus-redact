//! English person-name detection — surname-list match + given-name look-back,
//! evidence-gated to mirror the zh detector.
//!
//! The algorithm tokenizes capitalized words, identifies surname-pool tokens and
//! looks back 1-2 tokens for a leading given name / initial. A FULL `Given +
//! Surname` (both in the pools) or a user-supplied `known_names` match is
//! emitted high-confidence (recall preserved). A BARE surname-pool match — a
//! capitalized leading word that is NOT a known given name (`Quincy Smith`, `Lake
//! Park`, `York Stone`) — used to fire unconditionally at 0.9, over-redacting
//! noisy prose. It is now EVIDENCE-GATED exactly like zh's `score_candidate`:
//! `base + evidence`, a zero-evidence short-circuit, and emit only when the score
//! clears `threshold`. The corroboration signals are a title/honorific
//! immediately before the surname, a pool-independent **name-like** leading token
//! (alphabetic, length ≥ 2, not a common English / place word — this recovers
//! non-Anglo `Given Surname` names the SSA pool misses without reviving place
//! FPs), and proximity to other detected PII; with none, a lone capitalized
//! surname pair scores below threshold and is left to L2 NER rather than redacted
//! at L1. `detect_person_names` is the only `pub` surface.
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

use crate::person_data::{common_words_en_set, given_names_en_set, surnames_en_set};
use crate::reserved_range::byte_to_char_offset;
use crate::types::PatternMatch;

/// `_TOKEN_PAT` — tokenize into "Capitalized" words or a single-letter initial
/// like `J.`. Unicode-aware (replaces the old ASCII-only
/// `\b[A-Z][a-z]+\b|\b[A-Z]\.`), so accented names (`Renée`, `Müller`),
/// intra-word capitals (`McDonald`, `DeSantis`), apostrophes (`O'Brien` with
/// ASCII `'` or typographic `’`) and hyphens (`Jean-Paul`) each tokenize as ONE
/// token. Lowercase / punctuation runs between tokens act as gaps delimiting
/// candidate name spans.
///
/// The pattern is anchored with a leading lookbehind `(?<!\p{L})` so a token
/// never STARTS mid-word: `iPhone` does not yield a spurious `Phone` token (the
/// `P` is preceded by a letter). The first alternative is a capital followed by
/// a run of name-internal pieces, ending in a lowercase letter, so an all-caps
/// acronym like `ABC` does not match (no trailing lowercase) — the same behavior
/// as the old ASCII pattern. The second alternative is a single-capital initial
/// like `J.`.
///
/// A name-internal piece is one of:
///   - a plain letter `[\p{Ll}\p{Lu}]` (covers accents `Renée`/`Müller`/`José`
///     and intra-word caps `McDonald`/`DeSantis`);
///   - an apostrophe (ASCII `'` or typographic `’` U+2019) FOLLOWED BY AN
///     UPPERCASE letter `\p{Lu}` (covers `O'Brien`, `D'Angelo`) — crucially this
///     does NOT swallow a possessive `'s` (`Brown's` → `Brown`), because the
///     apostrophe there is followed by a lowercase `s`;
///   - a hyphen followed by any letter `\p{L}` (covers `Jean-Paul`).
///
/// Requiring the token to end in `\p{Ll}` then drops a trailing possessive so
/// `Brown's account` still tokenizes as `Brown` and the surname look-back fires.
static TOKEN_PAT: LazyLock<Regex> = LazyLock::new(|| {
    let pat = r"(?<!\p{L})\p{Lu}(?:[\p{Ll}\p{Lu}]|['\u{2019}]\p{Lu}|-\p{L})*\p{Ll}|(?<!\p{L})\p{Lu}\.";
    Regex::new(pat)
        .unwrap_or_else(|e| panic!("person_en: _TOKEN_PAT compile failed: {e}\nPattern: {pat}"))
});

/// A `_TOKEN_PAT` match: its text plus **char** start/end offsets.
struct Token {
    word: String,
    start: usize,
    end: usize,
}

/// `_TITLES` — honorifics / titles that, immediately before a surname,
/// CORROBORATE a bare (non-given-name-led) surname-pool match. Matched against
/// the leading token with its trailing dot stripped (`Mr.` → `Mr`), so both the
/// `Mr. Smith` (dot in the gap) and `Mr Smith` forms qualify. Lowercase-folded
/// before the lookup so `dr` / `Dr` / `DR` all match. Kept deliberately small —
/// the common English honorifics — to avoid widening the gate into ordinary
/// capitalized words.
static TITLES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "mr", "mrs", "ms", "mx", "miss", "dr", "prof", "professor", "sir",
        "madam", "madame", "rev", "reverend", "hon", "fr", "st", "capt",
        "captain", "lt", "sgt", "gen", "col", "maj", "sen", "rep", "gov",
        "pres", "president", "judge", "officer", "dame", "lord", "lady",
    ]
    .into_iter()
    .collect()
});

// ── Evidence scoring (mirrors `person_zh::score_candidate`) ──
//
// A bare surname-pool match (leading token NOT a known given name) is gated:
// `base + evidence`, zero-evidence → 0.0, emit only when `score >= threshold`.
// A given-name-led match and a `known_names` exact match bypass this entirely at
// confidence 1.0 (recall preserved). The weights are chosen so a single strong
// corroboration signal clears the default 0.8 threshold and an uncorroborated
// pair does not:
//   - title only:        base 0.3 + 0.6 = 0.9  → emit
//   - name-like lead:    base 0.3 + 0.5 = 0.8  → emit (== threshold passes)
//   - PII near (<=50):   base 0.3 + 0.5 = 0.8  → emit (== threshold passes)
//   - PII mid (<=150):   base 0.3 + 0.3 = 0.6  → suppress (weak, leave to L2)
//   - no evidence:       0.0                   → suppress
//
// The signals are OR'd additively (`(base + evidence).min(1.0)`), so a name-like
// leading token AND a nearby PII compound to 1.0 — they can only RAISE a score,
// never suppress one that already cleared the gate.
//
// ## Why a pool-independent name-like signal
//
// Given-name-led corroboration relies on the SSA given-name pool, which is
// Anglo-biased (it covers `Jose`/`Maria` but not `Marco`/`Wei`/`Mohammed`). That
// made the gate drop real `Given Surname` names by ethnicity: `Marco Rossi` was
// suppressed while `Jose Garcia` was kept. The name-like signal removes that bias
// LEXICALLY: a leading token is name-like when its lowercased form is NOT a common
// English word / place term (`common_words_en_set`). `Marco`/`Wei`/`Mohammed` are
// not common words → name-like → corroborate; `Central`/`Lake`/`Apple` ARE common
// / place words → not name-like → stay suppressed. This recovers non-Anglo names
// without reviving the place/noise FPs.

/// Flat base score for a bare-surname candidate. English surname matches carry
/// no length signal worth differentiating (the surname is one pool token), so a
/// single base is used rather than zh's per-char-length tiers.
const BARE_BASE: f64 = 0.3;
/// Title / honorific immediately before the surname.
const W_TITLE: f64 = 0.6;
/// Pool-independent "name-like leading token": the given-name slot is alphabetic,
/// length >= 2, and NOT a common English word / place term. Chosen so a name-like
/// lead ALONE clears the default 0.8 threshold (`BARE_BASE 0.3 + 0.5 = 0.8`),
/// recovering non-Anglo `Given Surname` names the SSA pool misses.
const W_NAME_LIKE: f64 = 0.5;
/// PII within the near proximity window.
const W_PROXIMITY_NEAR: f64 = 0.5;
/// PII within the mid proximity window.
const W_PROXIMITY_MID: f64 = 0.3;
/// Proximity buckets — char distance to the nearest detected PII entity. Same
/// bucket edges as `person_zh::score_candidate`.
const PROXIMITY_NEAR: usize = 50;
const PROXIMITY_MID: usize = 150;

/// Score a BARE-surname candidate (leading token not a given name) against the
/// corroboration signals, mirroring `person_zh::score_candidate`'s structure:
/// accumulate evidence, zero-evidence short-circuit, then `base + evidence`
/// capped at 1.0. `lead_clean` is the leading token with its trailing dot
/// stripped (used for the title + name-like tests); `start`/`end` are the
/// candidate's char offsets (for proximity). The signals (title / name-like /
/// proximity) are OR'd additively. Returns 0.0 when no signal fires.
fn score_bare_surname(
    lead_clean: &str,
    start: usize,
    end: usize,
    pii_entities: &[&PatternMatch],
) -> f64 {
    let mut evidence = 0.0_f64;

    // Title / honorific immediately before the surname (the leading token IS the
    // title). `Mr. Smith` / `Dr Smith` corroborate. A title occupies the title
    // slot, NOT the given-name slot, so it is mutually exclusive with the
    // name-like signal below — otherwise `Mr` (alphabetic, len 2, not a common
    // word) would ALSO score as name-like and double-count (title + name-like).
    let lead_lower = lead_clean.to_ascii_lowercase();
    if TITLES.contains(lead_lower.as_str()) {
        evidence += W_TITLE;
    } else if is_name_like(lead_clean) {
        // Pool-independent name-like leading token: `Marco Rossi`, `Wei Chen` (the
        // given-name slot is not in the SSA pool, but it is name-like, not a
        // common word) corroborate; `Central Park`, `Lake Park` (leading token IS
        // a common / place word) do not. See [`is_name_like`] for the guards.
        evidence += W_NAME_LIKE;
    }

    // Proximity to structural PII — first entity within a bucket wins (break).
    // `abs_diff` over usize char offsets == Python `abs(...)` on ints.
    for pii in pii_entities {
        let distance = start
            .abs_diff(pii.end)
            .min(pii.start.abs_diff(end));
        if distance <= PROXIMITY_NEAR {
            evidence += W_PROXIMITY_NEAR;
            break;
        } else if distance <= PROXIMITY_MID {
            evidence += W_PROXIMITY_MID;
            break;
        }
    }

    // No corroboration → don't match at L1 (leave to L2 NER).
    if evidence == 0.0_f64 {
        return 0.0;
    }

    (BARE_BASE + evidence).min(1.0)
}

/// Is the leading (given-name-slot) token "name-like"? — a pool-INDEPENDENT
/// corroboration test that distinguishes a real given name from a place / common
/// word lexically, not by ethnicity. True when ALL hold:
///   - the token is alphabetic (`char::is_alphabetic` for every char; an internal
///     hyphen in `Jean-Paul` and an apostrophe — ASCII `'` or typographic `’`
///     U+2019 — in `D'Andre` / `O'Shea` are allowed, see below, matching the
///     tokenizer's single-token support) — digits / other symbols are not names;
///   - its char length is >= 2 — a single-letter INITIAL (`J.` → `J`) is NOT
///     name-like, so `J. Smith` stays suppressed (matches the golden);
///   - its `to_ascii_lowercase()` (the caller already strips a trailing dot) is
///     NOT in [`common_words_en_set`] — `Central`/`Lake`/`Apple` are common /
///     place words and fail this, `Marco`/`Wei`/`Mohammed` pass.
///
/// Hyphenated names (`Jean-Paul`) and apostrophe names (`D'Andre`, `O'Shea`) are
/// name-like: the hyphen / apostrophe is allowed and the lowercased whole is not a
/// common word. ASCII lowercasing is
/// sufficient because the lexicon is ASCII; an accented leading token (`Renée`)
/// is name-like too (not in the set, alphabetic), but in the real pipeline the
/// detector runs after the accent fold, so this only matters for the raw detector.
fn is_name_like(lead_clean: &str) -> bool {
    // Length >= 2 chars — a single-letter initial is not name-like.
    if lead_clean.chars().count() < 2 {
        return false;
    }
    // Alphabetic (letters), with an internal hyphen allowed for `Jean-Paul` and
    // an apostrophe (ASCII `'` or typographic `’` U+2019) allowed for single-token
    // given names like `D'Andre` / `O'Shea` / `D'Angelo` — the tokenizer emits
    // these as ONE token, so the filter must match its support or the name leaks.
    if !lead_clean
        .chars()
        .all(|c| c.is_alphabetic() || c == '-' || c == '\'' || c == '\u{2019}')
    {
        return false;
    }
    // Not a common English word / place term.
    !common_words_en_set().contains(lead_clean.to_ascii_lowercase().as_str())
}

/// Detect English person names via surname-list match + given-name look-back,
/// evidence-gating bare-surname matches.
///
/// Param order mirrors `person_zh::detect_person_names` for consistency:
/// `(text, pii_entities, known_names, threshold)`. `pii_entities` are the L1
/// structural PII (phone / id / …) used as the proximity corroboration signal;
/// `threshold` is the minimum score a bare-surname candidate must clear to be
/// emitted (the pipeline default is 0.8). Pass an empty slice for "no
/// pii_entities" / "no known_names".
///
/// ## Confidence model
///
/// - **Phase 1 — `known_names` exact match** → confidence 1.0, bypasses the
///   gate (recall preserved). Matched FIRST via one alternation regex of the
///   `re.escape`-d names sorted longest-first, non-overlapping, `seen_spans`-
///   deduped on the exact `(start, end)` char span.
/// - **Phase 2 — surname-pool look-back**: tokenize, find surname-pool tokens,
///   look back 1-2 tokens for a leading given name / initial. Then:
///   - **given-name-led** (the leading or prev2 token is a known given name) →
///     confidence 1.0, bypasses the gate (this is the strong NAME signal —
///     `Given + Surname`, both in the pools — that preserves recall).
///   - **bare surname** (leading token is NOT a known given name — `Quincy
///     Smith`, `Lake Park`, `Mr. Smith`, `Marco Rossi`) → EVIDENCE-GATED via
///     [`score_bare_surname`]: a title/honorific immediately before the surname,
///     a **name-like** leading token (alphabetic, length ≥ 2, not a common
///     English / place word — see [`is_name_like`]), or proximity to a
///     `pii_entities` entry corroborates; with none, the score is below
///     `threshold` and the candidate is SUPPRESSED (left to L2 NER). The
///     name-like signal is pool-independent, so a real `Given Surname` whose
///     given name is outside the SSA pool (`Marco Rossi`, `Wei Chen`) is
///     recovered, while a place pair (`Central Park`) stays suppressed. When
///     emitted, the confidence is the gated score (`base + evidence`, ≤ 1.0). An
///     initial-led pair (`J. Smith`) is a bare surname whose leading token is a
///     single letter → not name-like, no corroboration → suppressed.
///
/// The adjacency gap test is `text[prev_end:tok_start].strip(" \t.") == ""` (the
/// strip set is space / tab / dot), so the `Mr. Smith` / `J. Smith` dot lands in
/// the gap and the pair still assembles. A leading token is `rstrip(".")`-cleaned
/// before the given-name / title membership tests (so `J.` tests as `J`, `Mr.`
/// as `Mr`). Result ORDER is append order: Phase-1 known names first, then
/// Phase-2 emitted surname matches in token-scan order; no final sort.
pub fn detect_person_names(
    text: &str,
    pii_entities: &[PatternMatch],
    known_names: &[String],
    threshold: f64,
) -> Vec<PatternMatch> {
    let mut results: Vec<PatternMatch> = Vec::new();
    // (start, end) char spans already emitted — dedup is on the exact pair.
    let mut seen_spans: HashSet<(usize, usize)> = HashSet::new();

    // Source as chars so every slice / strip stays in char-space.
    let text_chars: Vec<char> = text.chars().collect();

    // Structural PII for the bare-surname proximity gate — drop `self_reference`
    // exactly as `person_zh::detect_person_names` does (a "me" / "I" near a name
    // must not grant a proximity bonus). Built once and reused per candidate.
    let structural_pii: Vec<&PatternMatch> = pii_entities
        .iter()
        .filter(|p| p.type_ != "self_reference")
        .collect();

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
            // Shared per-match emit: append a known-name hit at confidence 1.0,
            // deduped on the exact (start, end) char span. Used by both the
            // normal alternation path and the per-name fallback so the emit
            // semantics stay identical.
            let emit = |re: &Regex,
                        results: &mut Vec<PatternMatch>,
                        seen_spans: &mut HashSet<(usize, usize)>| {
                for m in re.find_iter(text) {
                    // fancy_regex yields Err on backtrack-limit / stack overflow
                    // for pathological input (e.g. a ~1MB single token). Python's
                    // `re` never errors here; stop gracefully on the first Err
                    // rather than panicking, mirroring patterns.rs.
                    let Ok(m) = m else { break };
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
            };

            // known_pat = "|".join(re.escape(n) for n in sorted_names)
            let alt = sorted_names
                .iter()
                .map(|n| fancy_regex::escape(n).into_owned())
                .collect::<Vec<_>>()
                .join("|");
            match Regex::new(&alt) {
                Ok(known_pat) => {
                    // Normal case: one alternation, leftmost/longest over the
                    // whole pattern. Bit-identical to the pre-port Python.
                    emit(&known_pat, &mut results, &mut seen_spans);
                }
                Err(_) => {
                    // The alternation is too large for fancy_regex (regex-automata)
                    // to compile (~10MB cap), which happens only for a pathological
                    // known_names entry (e.g. a multi-MB single name). Python's `re`
                    // never errors here; match parity by best-effort matching each
                    // name whose OWN escaped pattern compiles, skipping the
                    // uncompilable one(s). The per-name order may differ slightly
                    // from the alternation, but this branch only fires on input that
                    // cannot appear in a bounded text — so exact parity is both
                    // unachievable and unobservable, and the normal path above is
                    // untouched.
                    for name in &sorted_names {
                        if let Ok(re) = Regex::new(&fancy_regex::escape(name)) {
                            emit(&re, &mut results, &mut seen_spans);
                        }
                    }
                }
            }
        }
    }

    // ── Phase 2: tokenize, scan for surnames, look back. ──
    let surnames = surnames_en_set();
    let given_names = given_names_en_set();

    // tokens = list(_TOKEN_PAT.finditer(text)) — char offsets.
    // `map_while(Result::ok)` stops at the first Err, mirroring the graceful
    // `Err(_) => break` convention in patterns.rs: fancy_regex returns Err on
    // backtrack-limit / stack overflow for pathological input (a ~1MB single
    // token), where Python's `re` never errors — so stop tokenizing rather than
    // panic. On all non-pathological input every match is Ok, so this is
    // bit-identical to the previous `.unwrap()`.
    let tokens: Vec<Token> = TOKEN_PAT
        .find_iter(text)
        .map_while(Result::ok)
        .map(|m| Token {
            word: m.as_str().to_string(),
            start: byte_to_char_offset(text, m.start()),
            end: byte_to_char_offset(text, m.end()),
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
        // first_clean = first.rstrip(".") — tested against the given-name pool
        // (given-name-led → high confidence) and, when bare, the title pool.
        let first_clean = rstrip_dot(first);

        // given-name-led (the leading token is a known given name) → strong NAME
        // signal, bypass the gate at confidence 1.0 (recall preserved). A bare
        // surname (leading token not a given name) is EVIDENCE-GATED: emit only
        // when a title / PII-proximity signal lifts it to >= threshold.
        let confidence = if given_names.contains(first_clean) {
            1.0
        } else {
            let score = score_bare_surname(first_clean, match_start, tok.end, &structural_pii);
            if score < threshold {
                // Uncorroborated lone capitalized surname pair — leave to L2 NER.
                continue;
            }
            score
        };

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
    /// Runs with NO pii_entities at the pipeline-default threshold (0.8), so a
    /// bare-surname pair with no title / proximity signal is suppressed.
    fn detect(text: &str, known: &[&str]) -> Vec<(String, usize, usize, f64)> {
        detect_with_pii(text, known, &[])
    }

    /// Like [`detect`] but with PII entities supplied for the proximity gate.
    fn detect_with_pii(
        text: &str,
        known: &[&str],
        pii: &[PatternMatch],
    ) -> Vec<(String, usize, usize, f64)> {
        let known: Vec<String> = known.iter().map(|s| s.to_string()).collect();
        detect_person_names(text, pii, &known, SCORE_THRESHOLD)
            .into_iter()
            .map(|m| {
                assert_eq!(m.type_, "person");
                assert_eq!(m.layer, 0);
                (m.text, m.start, m.end, m.confidence)
            })
            .collect()
    }

    /// Pipeline-default person threshold (mirrors `hints::DEFAULT_PERSON_THRESHOLD`
    /// and `person_zh::SCORE_THRESHOLD`). Bare-surname candidates must clear this.
    const SCORE_THRESHOLD: f64 = 0.8;

    fn row(text: &str, start: usize, end: usize, conf: f64) -> (String, usize, usize, f64) {
        (text.to_string(), start, end, conf)
    }

    fn pii(type_: &str, start: usize, end: usize) -> PatternMatch {
        PatternMatch {
            text: "x".to_string(),
            type_: type_.to_string(),
            start,
            end,
            confidence: 1.0,
            layer: 1,
        }
    }

    // ── Expectations below are the NEW evidence-gated behavior (the detector is
    // 100% Rust — the golden fixture + these unit tests ARE the spec, there is no
    // Python reference to stay bit-identical to). Given-name-led and known-name
    // matches stay high-confidence; a bare surname (leading token not a given
    // name) is emitted only when corroborated by a title or PII-proximity. ──

    /// Tokenize `text` into the matched word strings `TOKEN_PAT`
    /// produces — used to assert the Unicode-aware tokenizer treats accented /
    /// intra-word-cap / apostrophe / hyphen names as ONE token and never starts
    /// a token mid-word.
    fn tokens(text: &str) -> Vec<String> {
        TOKEN_PAT
            .find_iter(text)
            .map_while(Result::ok)
            .map(|m| m.as_str().to_string())
            .collect()
    }

    #[test]
    fn tokenizer_unicode_single_token() {
        // Each of these must tokenize as exactly ONE token (the old ASCII-only
        // `[A-Z][a-z]+` would have split or dropped them).
        assert_eq!(tokens("Renée"), vec!["Renée"]);
        assert_eq!(tokens("Müller"), vec!["Müller"]);
        assert_eq!(tokens("José"), vec!["José"]);
        assert_eq!(tokens("McDonald"), vec!["McDonald"]);
        assert_eq!(tokens("DeSantis"), vec!["DeSantis"]);
        assert_eq!(tokens("O'Brien"), vec!["O'Brien"]);
        // Typographic apostrophe U+2019.
        assert_eq!(tokens("O\u{2019}Brien"), vec!["O\u{2019}Brien"]);
        assert_eq!(tokens("Jean-Paul"), vec!["Jean-Paul"]);
    }

    #[test]
    fn tokenizer_does_not_start_midword() {
        // `iPhone` must NOT yield a `Phone` token: the leading lookbehind
        // `(?<!\p{L})` blocks a token starting at the inner capital `P` because
        // it is preceded by a letter.
        assert_eq!(tokens("iPhone"), Vec::<String>::new());
        // A capitalized word adjacent to a lowercased prefix word still tokenizes
        // normally when preceded by a non-letter (space).
        assert_eq!(tokens("my iPhone Smith"), vec!["Smith".to_string()]);
    }

    #[test]
    fn tokenizer_possessive_not_swallowed() {
        // A possessive `'s` must NOT be absorbed into the token (the apostrophe
        // is followed by lowercase `s`, not an uppercase letter), so the surname
        // look-back still anchors on the bare surname.
        assert_eq!(tokens("Brown's"), vec!["Brown".to_string()]);
        assert_eq!(tokens("O'Brien's"), vec!["O'Brien".to_string()]);
        // Regression guard: "Michael Brown's account" → ["Michael","Brown"].
        assert_eq!(
            tokens("Michael Brown's account"),
            vec!["Michael".to_string(), "Brown".to_string()]
        );
    }

    #[test]
    fn possessive_surname_still_detects() {
        // "Michael Brown's account" — Brown (not Brown's) is the surname token;
        // Michael is a known given name → 1.0 at 0..13.
        assert_eq!(
            detect("Michael Brown's account", &[]),
            vec![row("Michael Brown", 0, 13, 1.0)]
        );
    }

    #[test]
    fn tokenizer_acronym_and_initial() {
        // All-caps acronym does NOT match (first alt requires a trailing
        // lowercase) — same as the old ASCII pattern.
        assert_eq!(tokens("ABC"), Vec::<String>::new());
        // A single-capital initial `J.` still matches via the second alt.
        assert_eq!(tokens("J. Smith"), vec!["J.".to_string(), "Smith".to_string()]);
    }

    #[test]
    fn intra_word_cap_surname_detects() {
        // "Ronald McDonald" — Unicode tokenizer yields ["Ronald","McDonald"];
        // McDonald is a known surname, Ronald a known given name → 1.0.
        assert_eq!(
            detect("Ronald McDonald", &[]),
            vec![row("Ronald McDonald", 0, 15, 1.0)]
        );
    }

    #[test]
    fn apostrophe_surname_detects() {
        // "Sean O'Brien" — O'Brien is one token AND a known surname; Sean is a
        // known given name → 1.0. (Pre-fix the apostrophe split the token.)
        assert_eq!(
            detect("Sean O'Brien", &[]),
            vec![row("Sean O'Brien", 0, 12, 1.0)]
        );
    }

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
    fn surname_plus_unknown_given_name_like_emits() {
        // "Quincy Smith arrived." — "Quincy" is NOT in the SSA given-name pool,
        // but it IS name-like (alphabetic, len >= 2, not a common word) → base 0.3
        // + name-like 0.5 = 0.8 >= threshold, emitted at 0.8 with no title / PII.
        // (Before the name-like signal this pair was suppressed; the suppression
        // case is now demonstrated by `common_word_lead_stays_suppressed`, whose
        // leading token IS a common word.)
        assert_eq!(
            detect("Quincy Smith arrived.", &[]),
            vec![row("Quincy Smith", 0, 12, 0.8)]
        );
    }

    #[test]
    fn surname_plus_unknown_given_pii_proximity_corroborates() {
        // Same name-like pair WITH a phone number adjacent (within the near
        // window): name-like 0.5 + proximity-near 0.5 both fire → base 0.3 + 1.0,
        // capped at 1.0. The phone is at chars 14..24 (distance from the candidate
        // end at 12 is 2 → near bucket). The signals are additive — proximity
        // raises the already-emitting name-like score to the 1.0 cap.
        assert_eq!(
            detect_with_pii(
                "Quincy Smith, 4155551234",
                &[],
                &[pii("phone", 14, 24)],
            ),
            vec![row("Quincy Smith", 0, 12, 1.0)]
        );
    }

    #[test]
    fn name_like_lead_recovers_non_anglo_name() {
        // "Marco Rossi" — "Marco" is NOT in the SSA given-name pool, but it is
        // name-like (alphabetic, len >= 2, not a common word) and "Rossi" is a
        // pooled surname → base 0.3 + name-like 0.5 = 0.8 >= threshold, emitted at
        // 0.8 with NO title / PII corroboration. This is the fairness recovery: a
        // real Given+Surname name the Anglo-biased pool would otherwise drop.
        assert_eq!(
            detect("Marco Rossi called.", &[]),
            vec![row("Marco Rossi", 0, 11, 0.8)]
        );
        // Hyphenated non-Anglo given name — "Jean-Paul" is one token, name-like
        // (hyphen allowed), "Sartre" is pooled → 0.8.
        assert_eq!(
            detect("Jean-Paul Sartre spoke.", &[]),
            vec![row("Jean-Paul Sartre", 0, 16, 0.8)]
        );
    }

    #[test]
    fn name_like_compounds_with_proximity() {
        // "Quincy Smith" with an adjacent phone: name-like (0.5) AND proximity
        // (0.5) both fire → base 0.3 + 1.0, capped at 1.0. The signals are OR'd
        // additively and can only RAISE the score.
        assert_eq!(
            detect_with_pii("Quincy Smith, 4155551234", &[], &[pii("phone", 14, 24)]),
            vec![row("Quincy Smith", 0, 12, 1.0)]
        );
    }

    #[test]
    fn common_word_lead_stays_suppressed() {
        // "Central Park" / "Lake Park" — "Park" is a pooled surname, but the
        // leading token ("Central" / "Lake") IS a common / place word, so the
        // name-like signal does NOT fire and, with no title / PII, the score is
        // 0.0 < threshold → SUPPRESSED. The fairness fix must not revive these
        // place FPs.
        assert!(detect("Central Park is large.", &[]).is_empty());
        assert!(detect("Lake Park nearby.", &[]).is_empty());
        // "We visited Hyde Park yesterday" — anchor surname is "Park"; the leading
        // token "Hyde" is a curated place component in the common-word lexicon →
        // not name-like → suppressed. (Note "yesterday Park" never assembles: the
        // prev token would be "yesterday", lowercase, not a TOKEN_PAT match.)
        assert!(detect("We visited Hyde Park often.", &[]).is_empty());
    }

    #[test]
    fn apostrophe_lead_is_name_like() {
        // Single-token apostrophe given names tokenize as ONE token (the
        // tokenizer supports ASCII `'` and typographic `’` followed by a capital);
        // the name-like char filter must permit the apostrophe too, or the name
        // leaks. `D'Andre` / `O'Shea` / `D'Angelo` are name-like; the typographic
        // form is covered as well.
        assert!(is_name_like("D'Andre"));
        assert!(is_name_like("O'Shea"));
        assert!(is_name_like("D'Angelo"));
        assert!(is_name_like("O\u{2019}Shea"));
        // Hyphenated names stay name-like (regression guard).
        assert!(is_name_like("Jean-Paul"));
    }

    #[test]
    fn apostrophe_given_name_redacts() {
        // "D'Andre Williams" — "D'Andre" is one token, not in the SSA given-name
        // pool, but name-like (apostrophe allowed) and "Williams" is a pooled
        // surname → base 0.3 + name-like 0.5 = 0.8 >= threshold. Before the
        // apostrophe fix the leading token failed the char filter and the pair
        // was suppressed (the full name LEAKED).
        assert_eq!(
            detect("D'Andre Williams called.", &[]),
            vec![row("D'Andre Williams", 0, 16, 0.8)]
        );
    }

    #[test]
    fn removed_common_word_given_name_redacts() {
        // "Hope Johnson" — "hope" was removed from the common-word lexicon (it is
        // primarily a given name), so the leading token is now name-like and the
        // pair redacts. Before the removal "Hope" was a common word → not
        // name-like → the full name LEAKED. "Johnson" is a pooled surname.
        assert_eq!(
            detect("Hope Johnson arrived.", &[]),
            vec![row("Hope Johnson", 0, 12, 0.8)]
        );
        // A surname-pool word removed from the lexicon ("king") leads name-like as
        // a GIVEN slot while still anchoring as a surname.
        assert_eq!(
            detect("King Davis spoke.", &[]),
            vec![row("King Davis", 0, 10, 0.8)]
        );
    }

    #[test]
    fn added_place_word_lead_suppressed() {
        // "Golden Davis" — "golden" was ADDED to the common-word lexicon (a color,
        // not a given name and not a pooled surname), so the leading token is no
        // longer name-like and, with no title / PII, the pair is SUPPRESSED.
        // Before the addition "Golden" was name-like and false-positived at 0.8.
        assert!(detect("Golden Davis arrived.", &[]).is_empty());
        // "United Davis" — org/function word added to the lexicon → suppressed.
        assert!(detect("United Davis arrived.", &[]).is_empty());
    }

    #[test]
    fn initial_lead_not_name_like_still_suppressed() {
        // "J. Smith" — "J." rstrip('.') → "J" is a single letter (length 1), so
        // the name-like guard (length >= 2) rejects it. No title, no PII → 0.0 <
        // threshold → STILL suppressed, matching the golden. The name-like signal
        // must not turn an initial-led pair into an emission.
        assert!(detect("J. Smith joined.", &[]).is_empty());
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
        // "J. Smith joined." — "J." rstrip('.') → "J" is neither a given name nor
        // a title, and there is no PII signal → bare-surname score 0.0 < 0.8 →
        // SUPPRESSED. An initial alone is not corroboration (a deliberate recall
        // trade for precision; the full-name and titled forms still fire).
        assert!(detect("J. Smith joined.", &[]).is_empty());
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
        // "Mr. Smith arrived." — "Mr" is not a given name, but it IS a title; the
        // "." before "Smith" is in the gap strip-set so the pair assembles. The
        // title corroborates → base 0.3 + title 0.6 = 0.9 >= threshold, emitted
        // at 0.9, text[0:9] = "Mr. Smith". (Correctness win over the old ungated
        // 0.9 — the score is now justified by the title signal.)
        assert_eq!(
            detect("Mr. Smith arrived.", &[]),
            vec![row("Mr. Smith", 0, 9, 0.8999999999999999)]
        );
    }

    #[test]
    fn title_no_dot_prefix() {
        // "Dr Smith arrived." — title without a trailing dot still corroborates
        // (the title test lowercase-folds the rstrip'd leading token). base 0.3 +
        // title 0.6 = 0.9.
        assert_eq!(
            detect("Dr Smith arrived.", &[]),
            vec![row("Dr Smith", 0, 8, 0.8999999999999999)]
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

    // ── Mutation-kill guards (cargo-mutants survivors) ───────────────────────
    //
    // The cases below pin the exact boundary conditions the bare-surname evidence
    // gate flips, so a mutation in `score_bare_surname` / `is_name_like` changes
    // an observable result. Each uses a NON-name-like, NON-title leading token
    // ("Lake", a common/place word) for the proximity cases so ONLY the proximity
    // signal drives the score — a name-like lead would mask the proximity
    // mutation by clearing the gate on its own.

    /// score_bare_surname directly, so the proximity arithmetic / bucket edges are
    /// asserted on the raw f64 without the threshold gate folding distinct values
    /// to the same emit/suppress outcome. `lead` is "Lake" (common word → not
    /// name-like, not a title → zero non-proximity evidence).
    fn score_lake(distance: usize) -> f64 {
        // Candidate "Lake Park" spans chars 0..9. A PII entity placed after the
        // candidate at start = 9 + distance gives min(pend, pstart-9) == distance.
        let p = pii("phone", 9 + distance, 9 + distance + 11);
        score_bare_surname("Lake", 0, 9, &[&p])
    }

    #[test]
    fn score_bare_surname_proximity_near_bucket_edge() {
        // L186 `distance <= PROXIMITY_NEAR (50)`: at distance 50 the NEAR weight
        // (0.5) fires → base 0.3 + 0.5 = 0.8. Mutating `<=` to `>` would drop the
        // near bucket at the edge (distance 50 → falls through to the mid `<= 150`
        // → 0.6), changing the value.
        assert_eq!(score_lake(50), 0.8);
        assert_eq!(score_lake(49), 0.8);
        // Just past the near edge → mid bucket 0.3 → 0.6 (also kills a `>=`-style
        // off-by-one that would extend the near bucket to 51).
        assert_eq!(score_lake(51), 0.6);
    }

    #[test]
    fn score_bare_surname_proximity_mid_bucket_edge() {
        // L189 `distance <= PROXIMITY_MID (150)`: at distance 150 the MID weight
        // fires → base 0.3 + 0.3 = 0.6. Mutating `<=` to `>` drops the mid bucket
        // at the edge (150 → no proximity → zero evidence → 0.0). L190 `+=`
        // (W_PROXIMITY_MID) is also pinned: `-=` would give 0.3 - 0.3 = 0.0 →
        // zero-evidence short-circuit → 0.0; `*=` would give 0.3 * 0.3 = 0.09.
        assert_eq!(score_lake(150), 0.6);
        assert_eq!(score_lake(149), 0.6);
        // Past the mid edge → no proximity signal at all → zero evidence → 0.0.
        assert_eq!(score_lake(151), 0.0);
    }

    #[test]
    fn score_bare_surname_mid_bucket_value_exact() {
        // Redundant exact-value lock on the MID weight accumulation (L190 `+=`):
        // a lone mid-bucket proximity yields EXACTLY base 0.3 + 0.3 = 0.6, never
        // 0.0 (`-=`) or 0.09 (`*=`). Kept separate from the bucket-edge test so a
        // future edit to the edges does not silently relax this value check.
        assert_eq!(score_lake(100), 0.6);
    }

    #[test]
    fn is_name_like_two_char_boundary() {
        // L224 `chars().count() < 2`: a 2-char token IS name-like (the guard
        // rejects only single-letter initials). Mutating `<` to `<=` would reject
        // a 2-char token as too short. "Bo" is alphabetic, len 2, not a common
        // word, not a given name → name-like.
        assert!(is_name_like("Bo"));
        // The single-letter initial stays NOT name-like under either operator —
        // included so the test also documents the intended low end.
        assert!(!is_name_like("J"));
        // End-to-end: a 2-char name-like lead clears the gate (0.3 + 0.5 = 0.8).
        // Under the `<=` mutant "Bo" is not name-like → no signal → suppressed.
        assert_eq!(
            detect("Bo Smith arrived.", &[]),
            vec![row("Bo Smith", 0, 8, 0.8)]
        );
    }

    #[test]
    fn pathological_known_name_does_not_panic() {
        // A known_names list mixing a normal name with a PATHOLOGICAL oversized
        // name: the joined alternation exceeds fancy_regex's compiled-size cap and
        // Regex::new returns Err. The pre-port Python `re` never errors here, so we
        // must NOT panic — the Err branch falls back to per-name matching. The
        // normal name still matches at confidence 1.0 and the oversized name
        // (which cannot occur in a bounded text) matches nothing.
        let huge = "A".repeat(500_000);
        // Sanity: the oversized name alone (or in the alternation) is what trips the
        // compiler — proves the Err branch is actually exercised, not dead code.
        assert!(
            Regex::new(&fancy_regex::escape(&huge)).is_err(),
            "expected the oversized literal to exceed fancy_regex's size cap"
        );
        let got = detect("Email Alice please", &[&huge, "Alice"]);
        // Alice is matched at 1.0; the oversized name matches nothing; no panic.
        assert_eq!(got, vec![row("Alice", 6, 11, 1.0)]);
    }

    #[test]
    #[ignore = "expensive (~1MB single-token scan); proves the find_iter no-panic fix. Run via `cargo test -- --ignored`."]
    fn pathological_single_token_does_not_panic() {
        // A ~1MB single token can trip fancy_regex's backtrack limit / stack
        // overflow inside TOKEN_PAT.find_iter (and the known_names emit), which
        // previously PANICKED via `.unwrap()`. The graceful `map_while(Result::ok)`
        // / `let Ok(m) = m else { break }` must return a Vec instead of panicking.
        let pathological = "A".to_string() + &"a".repeat(1_000_000);
        // Just calling it must not panic; the result is whatever the graceful
        // scan produces (possibly empty) — we only assert it returns a Vec.
        let _got: Vec<PatternMatch> =
            detect_person_names(&pathological, &[], &[], SCORE_THRESHOLD);
        // Also exercise the known_names emit path on the same input.
        let _got2: Vec<PatternMatch> = detect_person_names(
            &pathological,
            &[],
            &["Alice".to_string()],
            SCORE_THRESHOLD,
        );
    }
}
