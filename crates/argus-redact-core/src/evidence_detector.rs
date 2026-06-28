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
use std::sync::LazyLock;

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
// These weights / window are the FIXED v1 policy, shared by every framework
// detector (medical conditions, hobbies) — they all face the same free-text FP
// risk. Proximity corroboration is gated by the shared `is_person_identifying`
// allowlist (only PII that names/contacts/locates a person counts), so it needs
// no per-detector configuration. What varies per detector is supplied to `new`:
// the lexicon, the cue regex, and the emitted type. Per-detector tuning of the
// weights/window is deliberately NOT exposed until a detector demonstrably needs
// different values — adding speculative knobs now would be unused surface.
const DEFAULT_W_CUE: f64 = 0.6;
const DEFAULT_W_LEXICON: f64 = 0.3;
const DEFAULT_W_PII_PROX: f64 = 0.3;
const DEFAULT_THRESHOLD: f64 = 0.5;
const DEFAULT_LEXICON_CONF_MIN: usize = 3;

/// Person-identifying PII types that may corroborate an evidence-gated
/// quasi-identifier (region/occupation/condition/hobby) BY PROXIMITY. The
/// principle: proximity corroboration answers "is a specific person present near
/// this candidate?" — only PII that names, contacts, or locates a specific
/// person answers yes. A technical token (url_token/jwt/api-key), an org name, a
/// weak attribute (age/gender), or a sensitive-but-non-locating attribute (a
/// disease name) does not identify *which* person, so it must not promote a bare
/// candidate to redaction by proximity alone.
///
/// This is an ALLOWLIST on purpose: a new technical type is safe by default
/// (it simply isn't here). When adding a NEW person-identifying entity type to
/// the detectors, add its exact emitted `type_` string HERE too, or it will not
/// corroborate. The `is_person_identifying_allowlist` test pins every entry.
///
/// Subsumes the old `["self_reference", "organization"]` denylist (both are
/// absent here, so they remain non-corroborators with no special-casing).
static PERSON_IDENTIFYING_PII: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        // names / contacts
        "person", "email", "phone", "wechat", "qq",
        // national / personal IDs
        "id_number", "hk_id", "tw_id", "macau_id", "taiwan_arc", "ssn",
        "aadhaar", "pan", "cpf", "nino", "nhs_number", "tax_id", "my_number", "rrn",
        // personal-financial
        "bank_card", "credit_card", "iban",
        // travel / border docs
        "passport", "us_passport", "eep", "hrp",
        // other personal anchors (incl. personal-location identifiers)
        "address", "postcode", "license_plate", "military_id", "social_security", "housing_fund",
        "date_of_birth",
    ]
    .into_iter()
    .collect()
});

/// True iff `type_` is a person-identifying PII type that may corroborate an
/// evidence-gated candidate by proximity. See [`PERSON_IDENTIFYING_PII`].
pub fn is_person_identifying(type_: &str) -> bool {
    PERSON_IDENTIFYING_PII.contains(type_)
}

/// Candidate-generation strategy: scans `chars` for lexicon hits, returning
/// `(matched_term, start_char_offset, end_char_offset)`. Language-specific —
/// CJK uses a char-substring scan; English uses word-boundary tokenization.
type CandidateScan = fn(&[char], &DetectorConfig) -> Vec<(String, usize, usize)>;

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
    /// How candidates are generated. `candidates_cjk` (default) is byte-for-byte
    /// today's scan; `candidates_word` is the English word-boundary scan.
    scan: CandidateScan,
    /// Lexicon-confidence proxy selector. `false` (zh default): a candidate
    /// corroborates (+w_lexicon) iff char-length `(end - start) >= lexicon_conf_min`.
    /// `true` (English): corroborates iff the term is MULTI-WORD (>= 2 whitespace
    /// tokens); `lexicon_conf_min` is ignored on that path.
    lexicon_conf_multiword: bool,
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
            scan: candidates_cjk, // zh default — byte-identical to today's behavior
            lexicon_conf_multiword: false, // zh default — char-count proxy
        }
    }

    /// Build a config from a `Lexicon` RON file's CONTENTS: parse it, promote the
    /// terms to `'static` for the process lifetime, and index them, then apply the
    /// cue regex + emitted type. Detector modules call this with their
    /// `include_str!`'d data inside a `OnceLock`, so the parse + leak happen once.
    /// `include_str!` must stay at the call site — its path is relative to the
    /// calling file. (Shared loader for the per-detector modules, which otherwise
    /// each duplicate the parse + `Box::leak` + index boilerplate.)
    pub fn from_ron(ron_src: &str, cue: &'static Regex, type_: &'static str) -> Self {
        let data: Lexicon = ron::from_str(ron_src).unwrap_or_else(|e| {
            panic!("evidence_detector: RON lexicon parse error for type '{type_}': {e}")
        });
        let lexicon: Vec<&'static str> =
            data.terms.into_iter().map(|s| &*Box::leak(s.into_boxed_str())).collect();
        Self::new(&lexicon, cue, type_)
    }

    /// English/word-boundary variant: same FIXED v1 weights, but the candidate
    /// scan is `candidates_word` (word-boundary tokenization — `nurse` never
    /// matches inside `nursery`) and the lexicon-confidence proxy is MULTI-WORD
    /// (>= 2 tokens) rather than the zh >= 3-char floor. Terms are lowercased into
    /// `name_set` / `first_chars` so matching is case-insensitive.
    pub fn new_word(lexicon: &[&'static str], cue: &'static Regex, type_: &'static str) -> Self {
        // Lowercase + leak so lowercased terms are 'static (mirrors from_ron's leak).
        let lowered: Vec<&'static str> = lexicon
            .iter()
            .map(|t| &*Box::leak(t.to_lowercase().into_boxed_str()))
            .collect();
        debug_assert!(
            lowered.iter().all(|t| t.split_whitespace().count() <= MAX_TOKEN_RUN),
            "evidence_detector: a lexicon term exceeds MAX_TOKEN_RUN tokens; raise the cap"
        );
        let mut cfg = Self::new(&lowered, cue, type_);
        cfg.scan = candidates_word;
        cfg.lexicon_conf_multiword = true;
        cfg
    }

    /// English counterpart of [`from_ron`]: parse a `Lexicon(terms: [...])` RON
    /// file, promote terms to `'static`, and build a word-boundary English config.
    pub fn from_ron_word(ron_src: &str, cue: &'static Regex, type_: &'static str) -> Self {
        let data: Lexicon = ron::from_str(ron_src).unwrap_or_else(|e| {
            panic!("evidence_detector: RON lexicon parse error for type '{type_}': {e}")
        });
        let lexicon: Vec<&'static str> =
            data.terms.into_iter().map(|s| &*Box::leak(s.into_boxed_str())).collect();
        Self::new_word(&lexicon, cue, type_)
    }
}

#[derive(serde::Deserialize)]
pub struct Lexicon {
    pub terms: Vec<String>,
}

/// CJK candidate scan: char-by-char, greedy longest-first, first-char-prefiltered
/// substring lookup against `name_set`. Chinese has no word delimiters, so a
/// substring scan is correct here. UNCHANGED body from the original `candidates`.
fn candidates_cjk(chars: &[char], cfg: &DetectorConfig) -> Vec<(String, usize, usize)> {
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

/// Longest curated lexicon phrase is a few tokens; cap the per-position run probe
/// so the scan stays linear in token count (mirrors how `candidates_cjk` is
/// bounded by `max_len`). 8 comfortably exceeds the longest curated en phrase.
const MAX_TOKEN_RUN: usize = 8;

/// English candidate scan: WORD-BOUNDARY matching. Tokenize on whitespace/punct
/// (apostrophe + hyphen kept intra-word, so `crohn's` / `type-2` stay one token),
/// then greedily match the longest run of consecutive tokens that is a lexicon
/// entry. A bare `nurse` never matches inside `nursery` because `nursery` is one
/// token (and `nurse != nursery` in `name_set`). Tokens are lowercased to match
/// the lowercased `name_set`; the EMITTED text is the verbatim source slice
/// `chars[start..end]` (matches `candidates_cjk`); the lowercased phrase is only
/// the lookup key.
fn candidates_word(chars: &[char], cfg: &DetectorConfig) -> Vec<(String, usize, usize)> {
    // 1) Tokenize into (lowercased text, start_char_off, end_char_off).
    let mut tokens: Vec<(String, usize, usize)> = Vec::new();
    let n = chars.len();
    let mut i = 0;
    while i < n {
        let c = chars[i];
        let is_word = c.is_alphanumeric() || c == '\'' || c == '-';
        if !is_word {
            i += 1;
            continue;
        }
        let start = i;
        let mut buf = String::new();
        while i < n && (chars[i].is_alphanumeric() || chars[i] == '\'' || chars[i] == '-') {
            for lc in chars[i].to_lowercase() {
                buf.push(lc);
            }
            i += 1;
        }
        tokens.push((buf, start, i));
    }

    // 2) Greedy longest-run lexicon match starting at each token.
    let mut out = Vec::new();
    let mut t = 0;
    while t < tokens.len() {
        // First-char prefilter: skip tokens that cannot start any lexicon term.
        if tokens[t]
            .0
            .chars()
            .next()
            .is_none_or(|fc| !cfg.first_chars.contains(&fc))
        {
            t += 1;
            continue;
        }
        let hi = MAX_TOKEN_RUN.min(tokens.len() - t);
        // A multi-token phrase may only span WHITESPACE between its tokens. A
        // non-whitespace gap means the tokens are a list ("rock, climbing"), not
        // the compound term ("rock climbing"), and spanning it would also swallow
        // that punctuation into the emitted verbatim slice. Cap the run at the
        // first non-whitespace gap.
        let mut max_run = 1usize;
        while max_run < hi {
            let gap_start = tokens[t + max_run - 1].2;
            let gap_end = tokens[t + max_run].1;
            if !chars[gap_start..gap_end].iter().all(|c| c.is_whitespace()) {
                break;
            }
            max_run += 1;
        }
        let mut matched_run = 0usize;
        for run in (1..=max_run).rev() {
            let phrase: String = tokens[t..t + run]
                .iter()
                .map(|(s, _, _)| s.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            if cfg.name_set.contains(phrase.as_str()) {
                let start = tokens[t].1;
                let end = tokens[t + run - 1].2;
                let surface: String = chars[start..end].iter().collect(); // verbatim source
                out.push((surface, start, end));
                matched_run = run;
                break;
            }
        }
        t += matched_run.max(1);
    }
    out
}

/// True if the candidate span contains >= 2 whitespace-separated tokens — the
/// English lexicon-confidence proxy ("a specific multi-word term corroborates").
fn is_multiword(span: &[char]) -> bool {
    span.split(|c: &char| c.is_whitespace())
        .filter(|run| !run.is_empty())
        .count()
        >= 2
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

    for (name, start, end) in (cfg.scan)(&chars, cfg) {
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
        // Lexicon-confidence corroboration (0.3). zh proxy: char-length >=
        // lexicon_conf_min (a multi-CHAR term). en proxy: MULTI-WORD (>= 2 tokens)
        // — 3 chars is trivial in English, so only a specific multi-word phrase
        // (`software engineer`) corroborates; a bare ambiguous word (`nurse`,
        // `chess`) must rely on a cue / PII proximity to clear the gate.
        let lexicon_conf = if cfg.lexicon_conf_multiword {
            is_multiword(&chars[start.min(n)..end.min(n)])
        } else {
            (end - start) >= cfg.lexicon_conf_min
        };
        if lexicon_conf {
            evidence += cfg.w_lexicon;
        }
        // Proximity corroboration: a PII that NAMES or CONTACTS a specific person
        // (phone/email/id/…) answers "is someone identifiable nearby?" and promotes
        // the candidate. A technical token (jwt/url_token/ip_address/api-key), an
        // org name, or a weak/sensitive attribute does NOT answer that question and
        // must not corroborate. The allowlist gate (is_person_identifying) enforces
        // this; new technical types are safe by default (not present in the list).
        for pii in pii_entities {
            if !is_person_identifying(&pii.type_) {
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
        // organization is NOT person-identifying (load-bearing for precision): a
        // multi-char term beside an org PII keeps only lexicon 0.3 < 0.5 → skip.
        // Pins that organization stays out of PERSON_IDENTIFYING_PII — adding it
        // to the allowlist would fail here.
        let org = vec![pm("华为公司", "organization", 0, 4)];
        let hits = detect_with("华为公司旁边有马拉松", &org, test_cfg());
        assert!(hits.is_empty(), "organization must not corroborate: {hits:?}");
    }

    #[test]
    fn framework_not_corroborated_by_technical_pii() {
        // A multi-char lexicon term (马拉松, 3 chars → W_LEXICON 0.3) near a jwt
        // (technical PII, non-person-identifying) with NO cue: under the old denylist
        // (which excluded only self_reference/organization) jwt corroborated, so
        // evidence = lexicon 0.3 + proximity 0.3 = 0.6 ≥ 0.5 → wrongly detected. Under
        // the allowlist, jwt is absent from PERSON_IDENTIFYING_PII → excluded →
        // evidence = 0.3 < 0.5 → not detected. Pins the allowlist for every framework detector.
        let jwt = vec![pm("tok", "jwt", 0, 3)];
        let hits = detect_with("tok马拉松", &jwt, test_cfg());
        assert!(
            hits.is_empty(),
            "technical PII (jwt) must not corroborate a framework candidate: {hits:?}"
        );
    }

    fn word_cfg() -> &'static DetectorConfig {
        static CELL: OnceLock<DetectorConfig> = OnceLock::new();
        CELL.get_or_init(|| {
            static CUE: LazyLock<Regex> =
                LazyLock::new(|| Regex::new(r"(?i)works as|enjoys").unwrap());
            // "nurse"/"chess" single-word (no multi-word lexicon weight);
            // "software engineer"/"rock climbing" multi-word (carry corroboration).
            DetectorConfig::new_word(
                &["nurse", "chess", "software engineer", "rock climbing"],
                &CUE,
                "job_title",
            )
        })
    }

    #[test]
    fn word_no_substring_match() {
        // PRECISION: "nurse" must NOT match inside "nursery" (word-boundary scan).
        let hits = detect_with("She works as a nursery assistant.", &[], word_cfg());
        assert!(
            !hits.iter().any(|h| h.text.to_lowercase() == "nurse"),
            "must not match nurse inside nursery: {hits:?}"
        );
    }

    #[test]
    fn word_cue_alone_fires() {
        // A cue ("works as") fires a single-word term: 0.6 >= 0.5.
        let hits = detect_with("She works as a nurse.", &[], word_cfg());
        let hit = hits.iter().find(|h| h.text.to_lowercase() == "nurse");
        assert!(hit.is_some(), "{hits:?}");
        assert!((hit.unwrap().confidence - 0.6).abs() < 1e-9, "cue-only {:?}", hit);
    }

    #[test]
    fn word_case_insensitive_match() {
        // Mixed-case source matches the lowercased name_set; emitted text is the
        // verbatim source slice.
        let hits = detect_with("She works as a Nurse.", &[], word_cfg());
        assert!(hits.iter().any(|h| h.text == "Nurse"), "verbatim source text: {hits:?}");
    }

    #[test]
    fn word_multiword_longest_run() {
        // "software engineer" (2-token run) wins; span covers both tokens.
        let hits = detect_with("He works as a software engineer.", &[], word_cfg());
        let hit = hits.iter().find(|h| h.text.to_lowercase() == "software engineer");
        assert!(hit.is_some(), "multi-word run: {hits:?}");
    }

    #[test]
    fn word_multiword_alone_insufficient() {
        // PRECISION: a multi-word term with NO cue / NO PII keeps only lexicon 0.3
        // < 0.5 → skip (multi-word proxy corroborates, does not fire).
        let hits = detect_with("Software engineer is a common role.", &[], word_cfg());
        assert!(hits.is_empty(), "bare multi-word must not fire: {hits:?}");
    }

    #[test]
    fn word_multiword_plus_proximity_fires() {
        // multi-word lexicon 0.3 + PII proximity 0.3 = 0.6 → fire.
        let pii = vec![pm("555-0100", "phone", 0, 8)];
        let hits = detect_with("555-0100 software engineer", &pii, word_cfg());
        let hit = hits.iter().find(|h| h.text.to_lowercase() == "software engineer");
        assert!(hit.is_some(), "{hits:?}");
        assert!((hit.unwrap().confidence - 0.6).abs() < 1e-9, "multiword+prox {:?}", hit);
    }

    #[test]
    fn word_single_term_proximity_alone_insufficient() {
        // PRECISION: single-word "chess" (no multi-word weight) merely near PII
        // gets only proximity 0.3 < 0.5 → skip.
        let pii = vec![pm("555-0100", "phone", 0, 8)];
        let hits = detect_with("555-0100 chess", &pii, word_cfg());
        assert!(hits.is_empty(), "single word + proximity-only must not fire: {hits:?}");
    }

    #[test]
    fn word_punct_between_tokens_not_spanned() {
        // PRECISION: "rock, climbing" is a LIST, not the compound "rock climbing".
        // The non-whitespace gap caps the run, so the phrase neither falsely
        // matches nor swallows the comma into the emitted span.
        let hits = detect_with("She enjoys rock, climbing.", &[], word_cfg());
        assert!(
            !hits.iter().any(|h| h.text.contains(',') || h.text.to_lowercase() == "rock climbing"),
            "punctuation gap must not be spanned: {hits:?}"
        );
    }

    #[test]
    fn word_whitespace_run_between_tokens_matches() {
        // Multiple spaces are still the compound term (whitespace-only gap): it
        // matches, and the emitted surface is verbatim (original spacing preserved).
        let hits = detect_with("He works as a software  engineer.", &[], word_cfg());
        assert!(
            hits.iter().any(|h|
                h.text.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
                    == "software engineer"),
            "whitespace-run multi-word should still match: {hits:?}"
        );
    }

    #[test]
    fn is_person_identifying_allowlist() {
        // Person-identifying types corroborate (representative across categories).
        for t in [
            "person", "email", "phone", "wechat", "qq",
            "id_number", "hk_id", "tw_id", "macau_id", "taiwan_arc", "ssn",
            "aadhaar", "pan", "cpf", "nino", "nhs_number", "tax_id", "my_number", "rrn",
            "bank_card", "credit_card", "iban",
            "passport", "us_passport", "eep", "hrp",
            "address", "postcode", "license_plate", "military_id", "social_security", "housing_fund",
            "date_of_birth",
        ] {
            assert!(is_person_identifying(t), "{t} must be a person-identifying corroborator");
        }
        // Technical / org-context / weak / sensitive / candidate types do NOT corroborate.
        for t in [
            "url_token", "ip_address", "mac_address", "jwt", "ssh_private_key",
            "openai_api_key", "anthropic_api_key", "aws_access_key", "github_token", "imei",
            "organization", "workplace", "school", "credit_code", "cnpj",
            "age", "gender",
            "medical", "biometric", "ethnicity", "political", "religion",
            "sexual_orientation", "financial", "criminal_record",
            "location", "job_title", "hobby", "self_reference",
        ] {
            assert!(!is_person_identifying(t), "{t} must NOT corroborate an evidence-gated candidate");
        }
    }
}
