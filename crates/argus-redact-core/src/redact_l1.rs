//! Layer-1 detection orchestration — Rust port of the fast-mode L1 slice of
//! `glue/redact.py::_detect`.
//!
//! [`detect_l1`] reproduces the exact ordered sequence the Python `_detect` runs
//! before any merge/filter/boost, returning the **RAW** (unmerged) L1 entities +
//! the L1 hints + the near-misses. L2 (NER) and L3 (semantic) are NOT part of
//! this function — fast mode skips them, and full mode wires them in a later
//! caller step.
//!
//! ## The `_detect` → `detect_l1` mapping (fast-mode L1 portion)
//!
//! 1. `normalize_text(text)` → `(detect_text, offset_map)`. `use_normalized =
//!    offset_map.is_some()`.
//! 2. `match_patterns(detect_text, load_patterns(lang))` — `load_patterns`
//!    replicates `_load_patterns`: `builtin_patterns("shared") ++
//!    builtin_patterns(code)` for each lang (skipping a literal "shared" in the
//!    list, mirroring the Python loop). The core `match_patterns` returns ALL
//!    matches in ONE list; Python's `pure/patterns.py` splits them on confidence
//!    (`< 1.0` → near-miss, else result). We replicate that split here.
//! 3. If `use_normalized` and there are raw matches: `map_spans_to_original` the
//!    layer1 spans back to ORIGINAL-text offsets, rebuilding each match's `text`
//!    as `text[s..e]` (char-sliced) from the original — mirroring redact.py
//!    :210-228.
//! 4. `produce_hints_l1(layer1, text)` — using the ORIGINAL `text`, not
//!    `detect_text`.
//! 5. `get_person_threshold(hints)`.
//! 6. zh person detection first (if "zh" in lang) — honors threshold, receives
//!    `layer1` as `pii_entities`; then en (if "en" in lang) — ignores threshold.
//!    (Matches Python's `entities.extend(zh); entities.extend(en)` order.)
//! 7. Names-only fallback (redact.py:268-283): if NEITHER "zh" NOR "en" is in
//!    lang AND `names` is non-empty, each non-empty known name's literal,
//!    non-overlapping occurrences in the ORIGINAL text are emitted as `person`
//!    entities (confidence 1.0, `text = name`). Mutually exclusive with the
//!    zh/en branches.
//! 8. layer1 + person tagged `layer = LAYER_REGEX` (= 1). RAW output: no
//!    merge/filter/boost.
//!
//! ## [`DetectL1Result`] serves both consumers
//!
//! - **Fast mode** (caller T6) needs `layer1 ++ person` (via [`DetectL1Result::entities`])
//!   plus `hints` to merge/filter/boost.
//! - **Full mode** (caller T8) needs `layer1` *separately* (to recompute the FULL
//!   Python hints — `pii_density` / `near_miss_format` — over the L1a regex set)
//!   plus `near_misses`. Returning the four fields distinctly serves both without
//!   a re-match.

use fancy_regex::Regex;

use crate::data::builtin_patterns;
use crate::hints::{get_person_threshold, produce_hints_l1, Hint};
use crate::normalize::{map_spans_to_original, normalize_text};
use crate::patterns::{match_patterns, PatternConfig, PatternError};
use crate::reserved_range::byte_to_char_offset;
use crate::types::PatternMatch;
use crate::{person_en, person_zh};

/// Layer = 1 (regex). Mirrors `argus_redact.layers.LAYER_REGEX`.
const LAYER_REGEX: u8 = 1;

/// The raw (pre-merge) output of L1 detection.
///
/// `layer1` and `person` are kept distinct so full mode can recompute the full
/// Python hint set over the L1a regex entities; fast mode concatenates them via
/// [`DetectL1Result::entities`].
pub struct DetectL1Result {
    /// L1a regex matches (validator-clean), tagged `layer = 1`, spans in
    /// ORIGINAL-text offsets.
    pub layer1: Vec<PatternMatch>,
    /// L1b person-name matches (zh then en), tagged `layer = 1`.
    pub person: Vec<PatternMatch>,
    /// L1 hints (`text_intent` + `self_reference_tier`) over the ORIGINAL text.
    pub hints: Vec<Hint>,
    /// Validator near-misses (regex matched, validation failed) — confidence 0.3.
    pub near_misses: Vec<PatternMatch>,
}

impl DetectL1Result {
    /// `layer1 ++ person` — the fast-mode pre-merge entity list, in the same
    /// order Python builds via `entities.extend(layer1); entities.extend(person)`.
    pub fn entities(&self) -> Vec<PatternMatch> {
        let mut out = Vec::with_capacity(self.layer1.len() + self.person.len());
        out.extend(self.layer1.iter().cloned());
        out.extend(self.person.iter().cloned());
        out
    }
}

/// Build the L1 pattern set: `builtin_patterns("shared") ++ builtin_patterns(code)`
/// for each requested lang. Mirrors `_load_patterns` (incl. skipping a literal
/// "shared" inside the lang list). Order is preserved (RON file order per lang),
/// which the regex match precedence depends on.
fn load_patterns(lang: &[String]) -> Vec<PatternConfig> {
    let mut configs: Vec<PatternConfig> = Vec::new();
    let mut push = |p: &crate::data::PatternData| {
        configs.push(PatternConfig {
            type_: p.type_.clone(),
            pattern: p.pattern.clone(),
            check_context: p.check_context,
            group: p.group.clone(),
            validator: p.validator.clone(),
        });
    };
    for p in builtin_patterns("shared") {
        push(p);
    }
    for code in lang {
        if code == "shared" {
            continue;
        }
        for p in builtin_patterns(code) {
            push(p);
        }
    }
    configs
}

/// Tag entities with `layer` if not already tagged (port of `_tag_layer`:
/// `layer if e.layer == 0 else e.layer`).
fn tag_layer(entities: &mut [PatternMatch], layer: u8) {
    for e in entities.iter_mut() {
        if e.layer == 0 {
            e.layer = layer;
        }
    }
}

/// Run the fast-mode L1 detection sequence, returning the RAW (unmerged) result.
///
/// `lang` is the resolved language list (e.g. `["zh"]`, `["zh","en"]`). `names`
/// is the known-names list. No merge/filter/boost is applied.
pub fn detect_l1(
    text: &str,
    lang: &[String],
    names: &[String],
) -> Result<DetectL1Result, PatternError> {
    // 1. Normalize. use_normalized iff an offset map was produced.
    let (normalized, offset_map) = normalize_text(text);
    let use_normalized = offset_map.is_some();
    let detect_text: &str = if use_normalized { &normalized } else { text };

    // 2. Match patterns over detect_text. The core returns ALL matches in one
    //    list; split on confidence to mirror pure/patterns.py (confidence < 1.0
    //    → near-miss at 0.3; else → result). Both sub-lists keep the core's
    //    start-sorted order, matching Python (results are re-sorted by start —
    //    already start-sorted here; near_misses keep append order = start order).
    let all_matches = match_patterns(detect_text, &load_patterns(lang))?;
    let mut layer1_raw: Vec<PatternMatch> = Vec::new();
    let mut near_misses: Vec<PatternMatch> = Vec::new();
    for m in all_matches {
        if m.confidence < 1.0 {
            near_misses.push(PatternMatch {
                text: m.text,
                type_: m.type_,
                start: m.start,
                end: m.end,
                confidence: 0.3,
                layer: m.layer,
            });
        } else {
            layer1_raw.push(m);
        }
    }

    // 3. Map normalized offsets back to original text (only on the raw results,
    //    matching Python which maps `layer1_raw` only). Rebuild each match's text
    //    as the ORIGINAL char-slice text[s..e].
    let mut layer1: Vec<PatternMatch> = if use_normalized && !layer1_raw.is_empty() {
        let spans: Vec<(usize, usize)> =
            layer1_raw.iter().map(|e| (e.start, e.end)).collect();
        let orig_len = text.chars().count();
        let mapped = map_spans_to_original(&spans, offset_map.as_deref(), orig_len);
        layer1_raw
            .iter()
            .zip(mapped.iter())
            .map(|(e_orig, &(s, e))| PatternMatch {
                text: char_slice(text, s, e),
                type_: e_orig.type_.clone(),
                start: s,
                end: e,
                confidence: e_orig.confidence,
                layer: e_orig.layer,
            })
            .collect()
    } else {
        layer1_raw
    };

    // 4. Tag layer1 with LAYER_REGEX.
    tag_layer(&mut layer1, LAYER_REGEX);

    // 5. Hints from the ORIGINAL text (not detect_text).
    let hints = produce_hints_l1(&layer1, text);

    // 6. Person threshold from the text_intent hint.
    let threshold = get_person_threshold(&hints);

    // 7. Person detection: zh first (threshold + layer1 as pii_entities), then en
    //    (ignores threshold). Match Python's extend order.
    let mut person: Vec<PatternMatch> = Vec::new();
    if lang.iter().any(|c| c == "zh") {
        let mut zh = person_zh::detect_person_names(text, &layer1, names, threshold);
        tag_layer(&mut zh, LAYER_REGEX);
        person.extend(zh);
    }
    if lang.iter().any(|c| c == "en") {
        let mut en = person_en::detect_person_names(text, names);
        tag_layer(&mut en, LAYER_REGEX);
        person.extend(en);
    }

    // 8. Names-only fallback (redact.py:268-283): when NEITHER "zh" NOR "en" is
    //    in lang AND names is non-empty, the zh/en person detectors never run, so
    //    Python falls back to a literal scan of each known name over the ORIGINAL
    //    text. Mutually exclusive with the zh/en branches above (the condition
    //    guarantees it). Each name's NON-overlapping, case-sensitive, LITERAL
    //    occurrences (`re.finditer(re.escape(name), text)`) become person entities
    //    at confidence 1.0, with `text = name` (exactly as Python sets `text=name`,
    //    not the matched slice — equal for a literal match). Appended AFTER layer1
    //    in `.entities()`, matching Python's `entities.append` order.
    let has_zh = lang.iter().any(|c| c == "zh");
    let has_en = lang.iter().any(|c| c == "en");
    if !has_zh && !has_en && !names.is_empty() {
        for name in names {
            // Python `if not name: continue` — skip empty names.
            if name.is_empty() {
                continue;
            }
            // `re.finditer(re.escape(name), text)` — literal, non-overlapping.
            // re.escape output always compiles; the `if let Ok` guard mirrors the
            // no-panic convention used for known_names elsewhere so a pathological
            // name can't panic.
            if let Ok(re) = Regex::new(&fancy_regex::escape(name)) {
                for m in re.find_iter(text) {
                    let m = m.unwrap();
                    let start = byte_to_char_offset(text, m.start());
                    let end = byte_to_char_offset(text, m.end());
                    person.push(PatternMatch {
                        text: name.clone(),
                        type_: "person".to_string(),
                        start,
                        end,
                        confidence: 1.0,
                        layer: LAYER_REGEX,
                    });
                }
            }
        }
    }

    Ok(DetectL1Result {
        layer1,
        person,
        hints,
        near_misses,
    })
}

/// Slice `text` by CHAR offsets `[start, end)` (Python `text[start:end]`).
/// Offsets from `map_spans_to_original` are char indices; the original text may
/// hold multi-byte chars, so byte-slicing would be wrong.
fn char_slice(text: &str, start: usize, end: usize) -> String {
    text.chars().skip(start).take(end.saturating_sub(start)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Golden fixtures captured from LIVE Python ─────────────────────────────
    //
    // Each fixture is the RAW (pre-merge) `_detect` fast-mode output: the
    // entity list (layer1 ++ person, in that order) + the L1 hint summary +
    // near-misses. Captured by replaying redact.py::_detect lines ~199-264 (L1
    // portion; L2/L3 skipped in fast mode) against the live compiled core. See
    // the task notes — the values below ARE the live-Python output.

    /// (text, type, start, end, confidence, layer)
    type Ent = (&'static str, &'static str, usize, usize, f64, u8);
    /// text_intent intent, optional (tier, has_kinship)
    type HintSummary = (&'static str, Option<(u8, bool)>);

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn run(text: &str, lang: &[&str], names: &[&str]) -> DetectL1Result {
        detect_l1(text, &s(lang), &s(names)).unwrap()
    }

    fn assert_entities(got: &[PatternMatch], expected: &[Ent]) {
        let got_v: Vec<(String, String, usize, usize, f64, u8)> = got
            .iter()
            .map(|e| {
                (
                    e.text.clone(),
                    e.type_.clone(),
                    e.start,
                    e.end,
                    e.confidence,
                    e.layer,
                )
            })
            .collect();
        let exp_v: Vec<(String, String, usize, usize, f64, u8)> = expected
            .iter()
            .map(|&(t, ty, st, en, c, l)| (t.to_string(), ty.to_string(), st, en, c, l))
            .collect();
        assert_eq!(got_v, exp_v);
    }

    /// Compare the produced L1 hints against a captured summary:
    /// each expected entry is (text_intent, Option<(tier, has_kinship)>), in
    /// Python's emit order (self_reference_tier — when present — then text_intent).
    fn assert_hints(got: &[Hint], expected: &[HintSummary]) {
        use crate::hints::HintKind;
        // Reduce to the same shape Python's summary used: a flat tier (opt) + intent.
        let mut intent: Option<String> = None;
        let mut tier: Option<(u8, bool)> = None;
        for h in got {
            match &h.kind {
                HintKind::TextIntent { intent: i } => intent = Some(i.clone()),
                HintKind::SelfReferenceTier { tier: t, has_kinship: k } => {
                    tier = Some((*t, *k))
                }
            }
        }
        // expected always has exactly one text_intent entry (last); a tier entry
        // may precede it. Fold expected the same way.
        let mut exp_intent: Option<String> = None;
        let mut exp_tier: Option<(u8, bool)> = None;
        for &(ti, tr) in expected {
            exp_intent = Some(ti.to_string());
            if let Some(t) = tr {
                exp_tier = Some(t);
            }
        }
        assert_eq!(intent, exp_intent, "text_intent mismatch");
        assert_eq!(tier, exp_tier, "self_reference_tier mismatch");
    }

    fn assert_near_misses(got: &[PatternMatch], expected: &[(&str, &str, usize, usize)]) {
        let got_v: Vec<(String, String, usize, usize)> = got
            .iter()
            .map(|e| (e.text.clone(), e.type_.clone(), e.start, e.end))
            .collect();
        let exp_v: Vec<(String, String, usize, usize)> = expected
            .iter()
            .map(|&(t, ty, st, en)| (t.to_string(), ty.to_string(), st, en))
            .collect();
        assert_eq!(got_v, exp_v);
    }

    #[test]
    fn zh_phone_id_with_normalize_and_near_misses() {
        // normalize_text changes the text (CN punctuation/digits) → map-span path.
        // id_number/credit_code fail validation → near-misses.
        let r = run("我叫张伟，电话13800138000，身份证110101199003078888。", &["zh"], &[]);
        assert_entities(
            &r.entities(),
            &[
                ("我", "self_reference", 0, 1, 1.0, 1),
                ("13800138000", "phone", 7, 18, 1.0, 1),
                ("张伟", "person", 2, 4, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("self_reference_tier (tier=1)", Some((1, false))), ("narrative", None)]);
        assert_near_misses(
            &r.near_misses,
            &[
                ("110101199003078888", "id_number", 22, 40),
                ("110101199003078888", "credit_code", 22, 40),
            ],
        );
    }

    #[test]
    fn en_names_neutral() {
        let r = run("Contact John Smith or Mary Johnson at the office.", &["en"], &[]);
        assert_entities(
            &r.entities(),
            &[
                ("John Smith", "person", 8, 18, 1.0, 1),
                ("Mary Johnson", "person", 22, 34, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("neutral", None)]);
        assert!(r.near_misses.is_empty());
    }

    #[test]
    fn en_known_name_exact() {
        let r = run("Reach out to Zaphod about the project.", &["en"], &["Zaphod"]);
        assert_entities(&r.entities(), &[("Zaphod", "person", 13, 19, 1.0, 1)]);
        assert_hints(&r.hints, &[("neutral", None)]);
    }

    #[test]
    fn instruction_suppresses_threshold_tier3() {
        // "Please tell me" → instruction → person_threshold 1.2, but en ignores
        // threshold (surname-list match) so Michael Brown still appears.
        let r = run("Please tell me about Michael Brown's account.", &["en"], &[]);
        assert_entities(
            &r.entities(),
            &[
                ("me", "self_reference", 12, 14, 1.0, 1),
                ("Michael Brown", "person", 21, 34, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("self_reference_tier (tier=3)", Some((3, false))), ("instruction", None)]);
    }

    #[test]
    fn kinship_selfref_zh_tier1() {
        let r = run("我妈的电话是13912345678", &["zh"], &[]);
        assert_entities(
            &r.entities(),
            &[
                ("我妈", "self_reference", 0, 2, 1.0, 1),
                ("我", "self_reference", 0, 1, 1.0, 1),
                ("13912345678", "phone", 6, 17, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("self_reference_tier (tier=1,kin)", Some((1, true))), ("narrative", None)]);
    }

    #[test]
    fn emoji_multibyte_offsets() {
        // 😀 is a 2-char-wide-in-UTF16 / 4-byte char; offsets are CHAR positions.
        let r = run("联系王芳😀电话13700137000谢谢", &["zh"], &[]);
        assert_entities(
            &r.entities(),
            &[
                ("13700137000", "phone", 7, 18, 1.0, 1),
                ("王芳", "person", 2, 4, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("narrative", None)]);
    }

    #[test]
    fn org_school_jwt_validators() {
        let r = run(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U email a@b.com",
            &["en"],
            &[],
        );
        assert_entities(
            &r.entities(),
            &[
                (
                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                    "jwt",
                    0,
                    108,
                    1.0,
                    1,
                ),
                ("a@b.com", "email", 115, 122, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("narrative", None)]);
    }

    #[test]
    fn normalize_cn_digit_maps_back_to_original_text() {
        // detect_text becomes "...13800138000..." but the entity text is the
        // ORIGINAL "一三八零零一三八零零零" (map-span rebuilds text[s..e]).
        let r = run("电话一三八零零一三八零零零是我的号码", &["zh"], &[]);
        assert_entities(
            &r.entities(),
            &[
                ("一三八零零一三八零零零", "phone", 2, 13, 1.0, 1),
                ("我的", "self_reference", 14, 16, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("self_reference_tier (tier=1)", Some((1, false))), ("narrative", None)]);
    }

    #[test]
    fn zh_en_combined_order_zh_then_en() {
        // Both detectors run; person order is zh (张伟) then en (John Smith).
        let r = run("张伟 and John Smith met, phone 13800138000", &["zh", "en"], &[]);
        assert_entities(
            &r.entities(),
            &[
                ("13800138000", "phone", 29, 40, 1.0, 1),
                ("张伟", "person", 0, 2, 0.8, 1),
                ("John Smith", "person", 7, 17, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("narrative", None)]);
    }

    #[test]
    fn fullwidth_phone_nfkc_normalize() {
        // Fullwidth digits NFKC-fold in detect_text; entity text is the ORIGINAL
        // fullwidth run mapped back.
        let r = run("电话：１３８００１３８０００ 联系我", &["zh"], &[]);
        assert_entities(
            &r.entities(),
            &[
                ("１３８００１３８０００", "phone", 3, 14, 1.0, 1),
                ("我", "self_reference", 17, 18, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("self_reference_tier (tier=1)", Some((1, false))), ("narrative", None)]);
    }

    // ── Names-only fallback (redact.py:268-283) ──────────────────────────────
    //
    // When NEITHER "zh" NOR "en" is in lang AND names is non-empty, the zh/en
    // person detectors never run and Python falls back to a literal scan of each
    // known name over the ORIGINAL text. Expected values below were captured from
    // LIVE Python `_detect(..., mode="fast")`:
    //   python3 -c "
    //   from argus_redact.glue.redact import _detect
    //   ents,_,_,_ = _detect('TEXT', lang=['ja'], mode='fast', names=[...],
    //                        types=None, types_exclude=None)
    //   print([(e.text,e.type,e.start,e.end,e.confidence,e.layer) for e in ents])
    //   "

    #[test]
    fn names_only_fallback_differential() {
        // The reviewer's differential case: lang=["ja"] (neither zh nor en), so
        // the fallback fires for each known name. Python _detect output:
        //   [('Zaphod','person',8,14,1.0,1), ('Trillian','person',19,27,1.0,1)]
        let r = run("Talk to Zaphod and Trillian please", &["ja"], &["Zaphod", "Trillian"]);
        assert_entities(
            &r.entities(),
            &[
                ("Zaphod", "person", 8, 14, 1.0, 1),
                ("Trillian", "person", 19, 27, 1.0, 1),
            ],
        );
    }

    #[test]
    fn names_only_fallback_duplicate_occurrences() {
        // A name appearing twice → two non-overlapping matches. Python:
        //   [('Zaphod','person',0,6,1.0,1), ('Zaphod','person',11,17,1.0,1)]
        let r = run("Zaphod met Zaphod again", &["ja"], &["Zaphod"]);
        assert_entities(
            &r.entities(),
            &[
                ("Zaphod", "person", 0, 6, 1.0, 1),
                ("Zaphod", "person", 11, 17, 1.0, 1),
            ],
        );
    }

    #[test]
    fn names_only_fallback_empty_name_skipped() {
        // An empty name in the list is skipped (Python `if not name: continue`):
        // no match, no panic. Python: [('Zaphod','person',0,6,1.0,1)]
        let r = run("Zaphod is here", &["ja"], &["", "Zaphod"]);
        assert_entities(&r.entities(), &[("Zaphod", "person", 0, 6, 1.0, 1)]);
    }

    #[test]
    fn names_only_fallback_regex_special_char_literal() {
        // A name with a regex-special char ("A.") is matched LITERALLY (re.escape),
        // so it matches "A." and NOT "Ax" in "AxB". Python:
        //   [('A.','person',0,2,1.0,1)]
        let r = run("A. and AxB present", &["ja"], &["A."]);
        assert_entities(&r.entities(), &[("A.", "person", 0, 2, 1.0, 1)]);
    }

    #[test]
    fn names_only_fallback_not_fired_for_zh() {
        // When "zh" is in lang the zh person branch handles names; the fallback is
        // suppressed. The known name is still detected (via the zh branch) at the
        // SAME (text, span, conf, layer), so the entity output is identical — what
        // matters is the fallback condition (`!has_zh && !has_en`) excludes this.
        // Python _detect(lang=["zh"]): [('Zaphod','person',0,6,1.0,1)]
        let r = run("Zaphod here", &["zh"], &["Zaphod"]);
        assert_entities(&r.entities(), &[("Zaphod", "person", 0, 6, 1.0, 1)]);
    }

    #[test]
    fn names_only_fallback_not_fired_for_en() {
        // When "en" is in lang the en person branch handles names; the fallback is
        // suppressed. Python _detect(lang=["en"]): [('Zaphod','person',0,6,1.0,1)]
        let r = run("Zaphod here", &["en"], &["Zaphod"]);
        assert_entities(&r.entities(), &[("Zaphod", "person", 0, 6, 1.0, 1)]);
    }
}
