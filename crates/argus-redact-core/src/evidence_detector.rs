//! Reusable evidence-gated lexicon detector — the common skeleton shared by the
//! quasi-identifier detectors added under the detection-breadth roadmap.
//!
//! A detector is data: a [`DetectorConfig`] (a lexicon + a cue regex + scoring
//! weights + a type label). [`detect_with`] runs the SAME model `regions.rs` and
//! `occupation.rs` use — lexicon longest-match (first-char prefiltered) →
//! ±window → weighted signals (cue / multi-char-lexicon / PII proximity, with
//! configurable type exclusions) → threshold — and emits char-offset
//! `PatternMatch`es. Char-space throughout; a multi-byte CJK window is never
//! byte-sliced.
//!
//! NOTE: this is the COMMON subset only. The occupation suffix-run heuristic +
//! honorific guard and the region struct-suffix signal are detector-specific and
//! live in their own modules; those detectors are not migrated onto this
//! framework (they shipped CI-green + adversarially reviewed).

use std::collections::HashSet;

use fancy_regex::Regex;

use crate::types::PatternMatch;

const DEFAULT_WINDOW: usize = 40;
const DEFAULT_PROX_NEAR: usize = 50;
// Precision-safe weights for FREE-TEXT quasi-identifiers, where false positives
// are the dominant risk. A CUE alone fires (0.6 >= 0.5 threshold) — it is the
// strong signal that a token is being used personally (患有/过敏/喜欢/爱好). A
// known multi-char lexicon term and proximity to real PII each only CORROBORATE
// (0.3 < 0.5) — NEITHER fires on its own, so a bare lexicon hit in a general
// statement (`糖尿病很常见`) or a short term merely sitting near PII does not
// over-redact. Two weak signals combine to clear the gate (multi-char + PII
// proximity = 0.6).
//
// These weights / window / excludes are the FIXED v1 policy, shared by every
// framework detector (medical conditions, hobbies) — they all face the same
// free-text FP risk. What varies per detector is supplied to `new`: the lexicon,
// the cue regex, and the emitted type. Per-detector tuning of the weights/window
// is deliberately NOT exposed until a detector demonstrably needs different
// values — adding speculative knobs now would be unused surface.
const DEFAULT_W_CUE: f64 = 0.6;
const DEFAULT_W_LEXICON: f64 = 0.3;
const DEFAULT_W_PII_PROX: f64 = 0.3;
const DEFAULT_THRESHOLD: f64 = 0.5;
const DEFAULT_LEXICON_CONF_MIN: usize = 3;
const DEFAULT_EXCLUDES: &[&str] = &["self_reference", "organization"];

pub struct DetectorConfig {
    name_set: HashSet<&'static str>,
    first_chars: HashSet<char>,
    max_len: usize,
    cue: &'static Regex,
    type_: &'static str,
    window: usize,
    prox_near: usize,
    w_cue: f64,
    w_lexicon: f64,
    w_pii_prox: f64,
    threshold: f64,
    lexicon_conf_min: usize,
    excludes: &'static [&'static str],
}

impl DetectorConfig {
    pub fn new(lexicon: &[&'static str], cue: &'static Regex, type_: &'static str) -> Self {
        // The candidate scan probes by LENGTH (max_len..1) and checks `name_set`
        // membership, so the lexicon needs no ordering — only a membership set, a
        // first-char prefilter set, and the max char length.
        let name_set: HashSet<&'static str> = lexicon.iter().copied().collect();
        let first_chars: HashSet<char> =
            lexicon.iter().filter_map(|n| n.chars().next()).collect();
        let max_len = lexicon.iter().map(|n| n.chars().count()).max().unwrap_or(0);
        Self {
            name_set,
            first_chars,
            max_len,
            cue,
            type_,
            window: DEFAULT_WINDOW,
            prox_near: DEFAULT_PROX_NEAR,
            w_cue: DEFAULT_W_CUE,
            w_lexicon: DEFAULT_W_LEXICON,
            w_pii_prox: DEFAULT_W_PII_PROX,
            threshold: DEFAULT_THRESHOLD,
            lexicon_conf_min: DEFAULT_LEXICON_CONF_MIN,
            excludes: DEFAULT_EXCLUDES,
        }
    }

    /// Build a config from a `ZhLexicon` RON file's CONTENTS: parse it, promote the
    /// terms to `'static` for the process lifetime, and index them, then apply the
    /// cue regex + emitted type. Detector modules call this with their
    /// `include_str!`'d data inside a `OnceLock`, so the parse + leak happen once.
    /// `include_str!` must stay at the call site — its path is relative to the
    /// calling file. (Shared loader for the per-detector modules, which otherwise
    /// each duplicate the parse + `Box::leak` + index boilerplate.)
    pub fn from_ron(ron_src: &str, cue: &'static Regex, type_: &'static str) -> Self {
        let data: ZhLexicon = ron::from_str(ron_src).unwrap_or_else(|e| {
            panic!("evidence_detector: RON lexicon parse error for type '{type_}': {e}")
        });
        let lexicon: Vec<&'static str> =
            data.terms.into_iter().map(|s| &*Box::leak(s.into_boxed_str())).collect();
        Self::new(&lexicon, cue, type_)
    }
}

#[derive(serde::Deserialize)]
pub struct ZhLexicon {
    pub terms: Vec<String>,
}

fn candidates(chars: &[char], cfg: &DetectorConfig) -> Vec<(String, usize, usize)> {
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        if !cfg.first_chars.contains(&chars[i]) {
            i += 1;
            continue;
        }
        let hi = cfg.max_len.min(n - i);
        let mut matched = 0usize;
        for len in (1..=hi).rev() {
            let cand: String = chars[i..i + len].iter().collect();
            if cfg.name_set.contains(cand.as_str()) {
                out.push((cand, i, i + len));
                matched = len;
                break;
            }
        }
        i += matched.max(1);
    }
    out
}

pub fn detect_with(
    text: &str,
    pii_entities: &[PatternMatch],
    cfg: &DetectorConfig,
) -> Vec<PatternMatch> {
    if text.is_empty() {
        return Vec::new();
    }
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();

    for (name, start, end) in candidates(&chars, cfg) {
        let before_start = start.saturating_sub(cfg.window);
        let before: String = chars[before_start..start.min(n)].iter().collect();
        let after_end = (end + cfg.window).min(n);
        let after: String = chars[end.min(n)..after_end].iter().collect();

        let cue_hit = cfg.cue.is_match(&before).unwrap_or(false)
            || cfg.cue.is_match(&after).unwrap_or(false);

        let mut evidence = 0.0_f64;
        if cue_hit {
            evidence += cfg.w_cue;
        }
        // Every candidate is, by construction, a lexicon hit (the scan only emits
        // gazetteer/lexicon names), so the framework analogue of occupation's
        // `is_lexicon && multi_char` gate is just the char-count check here.
        // `end - start` IS the candidate's char length (char offsets) — no need to
        // re-scan `name`.
        if (end - start) >= cfg.lexicon_conf_min {
            evidence += cfg.w_lexicon;
        }
        for pii in pii_entities {
            if cfg.excludes.contains(&pii.type_.as_str()) {
                continue;
            }
            let distance = start.abs_diff(pii.end).min(pii.start.abs_diff(end));
            if distance <= cfg.prox_near {
                evidence += cfg.w_pii_prox;
                break;
            }
        }

        if evidence == 0.0_f64 {
            continue;
        }
        if evidence >= cfg.threshold {
            out.push(PatternMatch {
                text: name,
                type_: cfg.type_.to_string(),
                start,
                end,
                confidence: evidence.min(1.0),
                layer: 1,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;
    use std::sync::OnceLock;

    fn test_cfg() -> &'static DetectorConfig {
        static CELL: OnceLock<DetectorConfig> = OnceLock::new();
        CELL.get_or_init(|| {
            static CUE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"喜欢|爱好").unwrap());
            // 攀岩/书法 are 2-char (below lexicon_conf_min → no lexicon weight);
            // 马拉松 is 3-char (clears it → carries the multi-char corroboration).
            DetectorConfig::new(&["攀岩", "书法", "马拉松"], &CUE, "hobby")
        })
    }

    fn pm(text: &str, type_: &str, start: usize, end: usize) -> crate::types::PatternMatch {
        crate::types::PatternMatch {
            text: text.to_string(), type_: type_.to_string(),
            start, end, confidence: 1.0, layer: 0,
        }
    }

    #[test]
    fn cue_alone_fires() {
        // A cue (喜欢) is the strong signal: 0.6 >= 0.5 → fire, even for a 2-char term.
        let hits = detect_with("我喜欢攀岩。", &[], test_cfg());
        let hit = hits.iter().find(|h| h.text == "攀岩" && h.type_ == "hobby");
        assert!(hit.is_some(), "{hits:?}");
        // Pin the per-signal weight: cue only (2-char, no lexicon weight) ⇒ 0.6.
        assert!((hit.unwrap().confidence - 0.6).abs() < 1e-9, "cue-only confidence {:?}", hit);
    }

    #[test]
    fn cue_after_candidate_fires() {
        // The cue regex matches the AFTER window too (OR over before/after).
        let hits = detect_with("攀岩是我的爱好。", &[], test_cfg());
        assert!(hits.iter().any(|h| h.text == "攀岩"), "after-side cue: {hits:?}");
    }

    #[test]
    fn bare_term_skipped() {
        // Lexicon term present, no cue, no PII → zero evidence → skip (leave to L2).
        let hits = detect_with("攀岩是一项运动。", &[], test_cfg());
        assert!(hits.is_empty(), "expected skip, got {hits:?}");
    }

    #[test]
    fn multichar_lexicon_alone_insufficient() {
        // PRECISION: a known multi-char term with NO cue / NO PII must NOT fire on
        // mere lexicon presence (0.3 < 0.5) — a general statement, not personal.
        let hits = detect_with("马拉松是一项运动。", &[], test_cfg());
        assert!(hits.is_empty(), "bare multi-char term must not fire: {hits:?}");
    }

    #[test]
    fn multichar_plus_proximity_fires() {
        // A multi-char term NEAR real PII: lexicon 0.3 + proximity 0.3 = 0.6 → fire.
        let pii = vec![pm("13800138000", "phone", 0, 11)];
        let hits = detect_with("13800138000 马拉松", &pii, test_cfg());
        let hit = hits.iter().find(|h| h.text == "马拉松");
        assert!(hit.is_some(), "{hits:?}");
        // Pin the combined weight: lexicon 0.3 + proximity 0.3 ⇒ exactly 0.6.
        assert!((hit.unwrap().confidence - 0.6).abs() < 1e-9, "lexicon+prox confidence {:?}", hit);
    }

    #[test]
    fn pii_after_candidate_corroborates() {
        // Proximity min() also covers PII AFTER the candidate (pii.start vs end arm).
        let pii = vec![pm("13800138000", "phone", 4, 15)];
        let hits = detect_with("马拉松 13800138000", &pii, test_cfg());
        assert!(hits.iter().any(|h| h.text == "马拉松"), "after-side PII: {hits:?}");
    }

    #[test]
    fn short_term_proximity_alone_insufficient() {
        // PRECISION: a 2-char term (no lexicon-confidence weight) merely near PII
        // gets only proximity 0.3 < 0.5 → skip. Proximity corroborates, not fires.
        let pii = vec![pm("13800138000", "phone", 0, 11)];
        let hits = detect_with("13800138000 攀岩", &pii, test_cfg());
        assert!(hits.is_empty(), "short term + proximity-only must not fire: {hits:?}");
    }

    #[test]
    fn excluded_self_reference_does_not_corroborate() {
        // self_reference is excluded: a multi-char term near 我 keeps only lexicon
        // 0.3 (proximity excluded) < 0.5 → skip.
        let sr = vec![pm("我", "self_reference", 0, 1)];
        let hits = detect_with("我旁边有马拉松", &sr, test_cfg());
        assert!(hits.is_empty(), "self_reference must not corroborate: {hits:?}");
    }

    #[test]
    fn excluded_organization_does_not_corroborate() {
        // organization is ALSO excluded (load-bearing for precision): a multi-char
        // term beside an org PII keeps only lexicon 0.3 < 0.5 → skip. Pins the
        // second exclude so silently dropping it from DEFAULT_EXCLUDES fails here.
        let org = vec![pm("华为公司", "organization", 0, 4)];
        let hits = detect_with("华为公司旁边有马拉松", &org, test_cfg());
        assert!(hits.is_empty(), "organization must not corroborate: {hits:?}");
    }
}
