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
        }
    }

    /// The indexed lexicon membership set. Exposed so the detector-specific
    /// modules (regions / occupation) reuse the SAME index `new` builds instead
    /// of re-deriving their own name_set from the gazetteer.
    pub(crate) fn name_set(&self) -> &HashSet<&'static str> {
        &self.name_set
    }

    /// Longest lexicon-name length in chars — the upper bound for a longest-match
    /// probe window. Reused by regions' parent-prefix absorption, so it need not
    /// re-derive its own max_len.
    pub(crate) fn max_len(&self) -> usize {
        self.max_len
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
}

#[derive(serde::Deserialize)]
pub struct Lexicon {
    pub terms: Vec<String>,
}

/// CJK candidate scan: char-by-char, greedy longest-first, first-char-prefiltered
/// substring lookup against `name_set`. Chinese has no word delimiters, so a
/// substring scan is correct here. Also reused by `regions::detect_regions_zh`,
/// whose gazetteer scan is this exact algorithm (single source).
pub(crate) fn candidates_cjk(
    chars: &[char],
    cfg: &DetectorConfig,
) -> Vec<(String, usize, usize)> {
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

/// A proximity index over the gated-in PII of ONE detector invocation, built
/// ONCE ([`ProximityIndex::build`]) and shared across every candidate so a
/// `k`-candidate × `k`-entity input costs O(k log k) instead of the former
/// O(k²) re-walk from zero per candidate.
///
/// It answers a single query ([`proximity_evidence`]): for a candidate span
/// `[start, end)` and a set of ascending `(edge, weight)` buckets, return the
/// proximity weight EXACTLY as the former linear scan did — the weight of the
/// FIRST gated entity (in the original iteration order) whose char distance
/// `min(|start − end_i|, |start_i − end|)` falls within a bucket, taking that
/// entity's own nearest bucket.
///
/// The `gate` (person: accept every already-filtered entity; the evidence-gated
/// detectors: the `is_person_identifying` allowlist) is a pure function of the
/// entity, identical for every candidate of an invocation, so it is applied ONCE
/// at build time — the index holds only gated-in entries, in their original
/// relative order.
pub(crate) struct ProximityIndex {
    /// Gated-in entries in original relative order. `entries[i]`'s position `i`
    /// is monotone in the ORIGINAL pii index, so the minimum `i` among a query's
    /// hits IS the minimum original index — the entity the former first-match
    /// scan selected.
    entries: Vec<ProxEntry>,
    /// `(end_i, i)` sorted by `end_i` — the BEFORE-side range query
    /// (`|start − end_i| ≤ E_max` ⇔ `end_i ∈ [start − E_max, start + E_max]`).
    by_end: Vec<(usize, usize)>,
    /// `(start_i, i)` sorted by `start_i` — the AFTER-side range query
    /// (`|start_i − end| ≤ E_max` ⇔ `start_i ∈ [end − E_max, end + E_max]`).
    by_start: Vec<(usize, usize)>,
}

struct ProxEntry {
    start: usize,
    end: usize,
    orig_idx: usize,
}

impl ProximityIndex {
    /// Build the index once for a detector invocation: apply `gate` to every
    /// entity in iteration order (so `orig_idx` is the position the former scan
    /// counted from) and index the survivors by end and by start for the two
    /// range queries. O(k log k).
    pub(crate) fn build<'a, I>(pii_entities: I, gate: impl Fn(&PatternMatch) -> bool) -> Self
    where
        I: IntoIterator<Item = &'a PatternMatch>,
    {
        let mut entries: Vec<ProxEntry> = Vec::new();
        for (orig_idx, pii) in pii_entities.into_iter().enumerate() {
            #[cfg(test)]
            PROX_PROBES.with(|c| c.set(c.get() + 1));
            if gate(pii) {
                entries.push(ProxEntry { start: pii.start, end: pii.end, orig_idx });
            }
        }
        let mut by_end: Vec<(usize, usize)> =
            entries.iter().enumerate().map(|(i, e)| (e.end, i)).collect();
        by_end.sort_unstable();
        let mut by_start: Vec<(usize, usize)> =
            entries.iter().enumerate().map(|(i, e)| (e.start, i)).collect();
        by_start.sort_unstable();
        Self { entries, by_end, by_start }
    }
}

/// Build a [`ProximityIndex`] gated by the shared `is_person_identifying`
/// allowlist — only PII that names/contacts/locates a specific person may
/// corroborate by proximity. The single call site of the `is_person_identifying`
/// gate for every evidence-gated CJK detector (occupation, region, and the
/// evidence detector itself), so they share ONE gate closure — identical to the
/// per-site `|pii| is_person_identifying(&pii.type_)` each formerly inlined.
pub(crate) fn build_person_identifying_index<'a, I>(pii_entities: I) -> ProximityIndex
where
    I: IntoIterator<Item = &'a PatternMatch>,
{
    ProximityIndex::build(pii_entities, |pii| is_person_identifying(&pii.type_))
}

/// The contiguous sub-slice of a `(key, idx)` list — sorted ascending by `key` —
/// whose keys lie in the inclusive `[lo, hi]` range, located by two binary
/// searches. Empty when nothing falls in range. Callers always pass `lo <= hi`
/// (both from the same position via `saturating_sub`/`saturating_add`); the
/// `to.max(from)` clamp keeps the helper honest (empty, never a panicking
/// reversed range) should that ever not hold.
fn range_slice(sorted: &[(usize, usize)], lo: usize, hi: usize) -> &[(usize, usize)] {
    let from = sorted.partition_point(|&(k, _)| k < lo);
    let to = sorted.partition_point(|&(k, _)| k <= hi);
    &sorted[from..to.max(from)]
}

/// Single proximity-corroboration weight for a candidate span `[start, end)`
/// against a prebuilt [`ProximityIndex`]. Returns the weight of the gated entity
/// with the MINIMUM original index among those within reach — "within reach" =
/// `min(|start − end_i|, |start_i − end|) ≤ E_max` (`E_max` = the largest bucket
/// edge) — using THAT entity's own nearest ascending bucket. Returns 0.0 when
/// nothing corroborates.
///
/// Byte-identical to the former linear scan (`for pii in pii_entities { if
/// !gate(pii) continue; distance = …; first bucket wins; break }`): that scan
/// returned the FIRST gated entity whose distance satisfied a bucket, i.e. the
/// minimum-index entity whose distance ≤ E_max (a distance > E_max matches no
/// bucket and is skipped), taking that entity's own first satisfying bucket. The
/// index reproduces exactly that selection — proven by the module tests'
/// differential oracle, which asserts the SAME selected index AND weight against
/// the retained naive scan over random, nested, end-side-only, unsorted and
/// two-bucket input.
///
/// `buckets` are `(max_char_distance, weight)` in ASCENDING distance order
/// (`debug_assert`ed); the char distance is `min(|start − pii.end|, |pii.start −
/// end|)` — the same `abs_diff` gap every detector uses (matches Python `abs()`
/// on int offsets). Each site keeps its own bucket edges/weights and gate policy
/// (fixed at build time), so behavior is unchanged. Caller does `evidence +=
/// proximity_evidence(...)` at the SAME point in its accumulation, preserving the
/// exact `+=` order the bit-identity goldens lock.
pub(crate) fn proximity_evidence(
    start: usize,
    end: usize,
    index: &ProximityIndex,
    buckets: &[(usize, f64)],
) -> f64 {
    proximity_evidence_indexed(start, end, index, buckets).1
}

/// Core of [`proximity_evidence`], also returning the selected entity's ORIGINAL
/// index (`None` when nothing is within reach) so the differential-oracle fuzz
/// can assert the SAME entity — not merely the same weight — as the naive scan.
fn proximity_evidence_indexed(
    start: usize,
    end: usize,
    index: &ProximityIndex,
    buckets: &[(usize, f64)],
) -> (Option<usize>, f64) {
    debug_assert!(
        buckets.windows(2).all(|w| w[0].0 <= w[1].0),
        "proximity buckets must be ascending by edge"
    );
    let Some(&(e_max, _)) = buckets.last() else {
        return (None, 0.0);
    };

    // Both-side reach: an entity is a hit iff |start − end_i| ≤ E_max (it ends
    // near the candidate's start — the BEFORE side) OR |start_i − end| ≤ E_max
    // (it starts near the candidate's end — the AFTER side). A single start-
    // sorted window keyed on the candidate would miss the before side, so query
    // both indexes and take the union. `saturating_sub` clamps the (never
    // negative) lower bound; positions are char offsets, so the upper bound never
    // overflows in practice (`saturating_add` guards it regardless). Selection is
    // by MINIMUM original index (`i` is monotone in it) — NOT by nearest — so a
    // farther-but-earlier entity wins exactly as the former first-match scan.
    let mut best: Option<usize> = None;
    for &(_, i) in range_slice(
        &index.by_end,
        start.saturating_sub(e_max),
        start.saturating_add(e_max),
    ) {
        #[cfg(test)]
        PROX_PROBES.with(|c| c.set(c.get() + 1));
        best = Some(best.map_or(i, |b: usize| b.min(i)));
    }
    for &(_, i) in range_slice(
        &index.by_start,
        end.saturating_sub(e_max),
        end.saturating_add(e_max),
    ) {
        #[cfg(test)]
        PROX_PROBES.with(|c| c.set(c.get() + 1));
        best = Some(best.map_or(i, |b: usize| b.min(i)));
    }

    let Some(i_star) = best else {
        return (None, 0.0);
    };
    // Bucket by the SELECTED entity's OWN distance — recomputed as the min of
    // both sides, NOT the side that satisfied the range query (the query only
    // decides membership; the former scan always bucketed on the full min). i* is
    // a hit, so distance ≤ E_max and the last (widest) bucket always matches.
    let entry = &index.entries[i_star];
    let distance = start.abs_diff(entry.end).min(entry.start.abs_diff(end));
    for &(edge, weight) in buckets {
        if distance <= edge {
            return (Some(entry.orig_idx), weight);
        }
    }
    (Some(entry.orig_idx), 0.0)
}

// `#[cfg(test)]` proximity operation-count counter — incremented once per entity
// examined (at index build, and per entry scanned by a range query), so a test
// can pin that the indexed sweep is LINEAR in the k-candidate × k-entity input
// while the retained naive scan is quadratic. Compiled out of the release
// `_core`: the counter and every increment live behind `#[cfg(test)]`, so it
// never exists in shipped code and cannot perturb the byte-identical output.
#[cfg(test)]
thread_local! {
    static PROX_PROBES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Slice the ±`window` before/after context of a `[start, end)` char span out of
/// the whole-text `chars` slice, in CHAR-space (a multi-byte CJK window is never
/// byte-sliced). Returns `(before, after)` where
/// `before = chars[max(0, start - window) .. start]` and
/// `after  = chars[end .. min(end + window, n)]`.
///
/// Single source for the before/after windowing copy-pasted across the person /
/// region / occupation / framework detectors. The `before_start <= before_end`
/// (and `after_start <= after_end`) guard is kept so the helper is safe for any
/// caller; at the current sites `start`/`end` are `candidates_cjk` offsets bounded
/// by `n`, so the guard never fires and the output is byte-identical to each
/// site's former inline slicing.
pub(crate) fn context_windows(
    chars: &[char],
    start: usize,
    end: usize,
    window: usize,
) -> (String, String) {
    let n = chars.len();

    let before_start = start.saturating_sub(window);
    let before_end = start.min(n);
    let before: String = if before_start <= before_end {
        chars[before_start..before_end].iter().collect()
    } else {
        String::new()
    };

    let after_start = end.min(n);
    let after_end = (end + window).min(n);
    let after: String = if after_start <= after_end {
        chars[after_start..after_end].iter().collect()
    } else {
        String::new()
    };

    (before, after)
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
    let mut out = Vec::new();

    // Build the proximity index ONCE for this invocation (gate applied here), then
    // share it across every candidate — see [`ProximityIndex`]. The gate is the
    // `is_person_identifying` allowlist: only PII that names/contacts/locates a
    // specific person may corroborate by proximity.
    let prox_index = build_person_identifying_index(pii_entities.iter());

    for (name, start, end) in candidates_cjk(&chars, cfg) {
        let (before, after) = context_windows(&chars, start, end, cfg.window);

        let cue_hit = cfg.cue.is_match(&before).unwrap_or(false)
            || cfg.cue.is_match(&after).unwrap_or(false);

        let mut evidence = 0.0_f64;
        if cue_hit {
            evidence += cfg.w_cue;
        }
        // Lexicon-confidence corroboration (0.3): a multi-CHAR term (char-length
        // >= lexicon_conf_min) corroborates, so a bare ambiguous 2-char term
        // (`攀岩`) must rely on a cue / PII proximity to clear the gate.
        if (end - start) >= cfg.lexicon_conf_min {
            evidence += cfg.w_lexicon;
        }
        // Proximity corroboration: a PII that NAMES or CONTACTS a specific person
        // (phone/email/id/…) answers "is someone identifiable nearby?" and promotes
        // the candidate. A technical token (jwt/url_token/ip_address/api-key), an
        // org name, or a weak/sensitive attribute does NOT answer that question and
        // must not corroborate. The allowlist gate (is_person_identifying) enforces
        // this; new technical types are safe by default (not present in the list).
        evidence += proximity_evidence(start, end, &prox_index, &[(cfg.prox_near, cfg.w_pii_prox)]);

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

    // ── Proximity: indexed sweep is byte-identical to the naive scan + linear ──

    /// The pre-index proximity scan, VERBATIM, as a differential oracle — the
    /// exact loop `proximity_evidence` carried before the indexed rewrite, plus a
    /// returned selected-index so the fuzz can assert the SAME entity (not merely
    /// the same weight). Increments the same `PROX_PROBES` counter (once per
    /// entity examined) as index build, so the teeth test can pin it O(k²).
    fn proximity_evidence_naive_indexed<'a, I>(
        start: usize,
        end: usize,
        pii_entities: I,
        buckets: &[(usize, f64)],
        gate: impl Fn(&PatternMatch) -> bool,
    ) -> (Option<usize>, f64)
    where
        I: IntoIterator<Item = &'a PatternMatch>,
    {
        for (idx, pii) in pii_entities.into_iter().enumerate() {
            PROX_PROBES.with(|c| c.set(c.get() + 1));
            if !gate(pii) {
                continue;
            }
            let distance = start.abs_diff(pii.end).min(pii.start.abs_diff(end));
            for &(edge, weight) in buckets {
                if distance <= edge {
                    return (Some(idx), weight);
                }
            }
        }
        (None, 0.0)
    }

    /// `detect_with` with the naive (un-indexed) proximity scan — shares the
    /// candidate scan, windowing and weights, so the ONLY difference from the
    /// production path is the proximity mechanism, making it a faithful
    /// differential oracle AND the teeth for the operation-count gate.
    fn detect_with_naive(
        text: &str,
        pii_entities: &[PatternMatch],
        cfg: &DetectorConfig,
    ) -> Vec<PatternMatch> {
        if text.is_empty() {
            return Vec::new();
        }
        let chars: Vec<char> = text.chars().collect();
        let mut out = Vec::new();
        for (name, start, end) in candidates_cjk(&chars, cfg) {
            let (before, after) = context_windows(&chars, start, end, cfg.window);
            let cue_hit = cfg.cue.is_match(&before).unwrap_or(false)
                || cfg.cue.is_match(&after).unwrap_or(false);
            let mut evidence = 0.0_f64;
            if cue_hit {
                evidence += cfg.w_cue;
            }
            if (end - start) >= cfg.lexicon_conf_min {
                evidence += cfg.w_lexicon;
            }
            evidence += proximity_evidence_naive_indexed(
                start,
                end,
                pii_entities.iter(),
                &[(cfg.prox_near, cfg.w_pii_prox)],
                |pii| is_person_identifying(&pii.type_),
            )
            .1;
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

    #[test]
    fn proximity_indexed_matches_naive_oracle_fuzz() {
        // Differential oracle: the indexed sweep must select the SAME entity AND
        // return the SAME weight as the naive scan for EVERY input. A hand-rolled
        // xorshift PRNG (fixed seed, fixed iterations, no crate dep) generates pii
        // lists that are random-length, nested/containing, end-side-only, and
        // UNSORTED, scored against random-width candidates with one- and two-bucket
        // configs, under BOTH a filtering gate (gated-out entries must not shift the
        // min-index selection) and the accept-all gate (the person path). Asserting
        // on the (index, weight) PAIR — not weight alone — is what catches a before-
        // side miss (a start-only window) or a closest-wins bug (overlap-only
        // selection): either can return the right weight while selecting the wrong
        // entity, and a sorted-only / overlap-only fuzz would pass through it.
        let types = ["person", "phone", "medical", "jwt", "email"];
        let mut state: u64 = 0xD1B5_4A32_D192_ED03;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            // Candidate span in a tight coordinate space so proximity actually fires.
            let cstart = (next() % 60) as usize;
            let cend = cstart + 1 + (next() % 8) as usize;
            // Random-length, unsorted, nested/containing, end-side-only pii list.
            let m = (next() % 8) as usize;
            let pii: Vec<PatternMatch> = (0..m)
                .map(|_| {
                    let s = (next() % 80) as usize;
                    let t = types[(next() as usize) % types.len()];
                    pm("x", t, s, s + 1 + (next() % 12) as usize)
                })
                .collect();
            // One- and two-bucket ASCENDING configs.
            let e0 = (next() % 12) as usize;
            let buckets: Vec<(usize, f64)> = if next() % 2 == 0 {
                vec![(e0, 0.5), (e0 + (next() % 12) as usize, 0.3)]
            } else {
                vec![(e0, 0.4)]
            };
            for use_gate in [true, false] {
                let gate = |p: &PatternMatch| {
                    if use_gate {
                        is_person_identifying(&p.type_)
                    } else {
                        true
                    }
                };
                let index = ProximityIndex::build(pii.iter(), gate);
                let got = proximity_evidence_indexed(cstart, cend, &index, &buckets);
                let want =
                    proximity_evidence_naive_indexed(cstart, cend, pii.iter(), &buckets, gate);
                assert_eq!(
                    got, want,
                    "indexed diverged from naive: cand=({cstart},{cend}) buckets={buckets:?} \
                     gate={use_gate} pii={:?}",
                    pii.iter().map(|p| (p.type_.as_str(), p.start, p.end)).collect::<Vec<_>>()
                );
            }
        }
    }

    fn count_cfg() -> &'static DetectorConfig {
        static CELL: OnceLock<DetectorConfig> = OnceLock::new();
        CELL.get_or_init(|| {
            // A cue that never matches the degenerate input, so scoring reaches the
            // proximity step for every candidate (the whole point of the gate).
            static CUE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"NEVERMATCH").unwrap());
            DetectorConfig::new(&["糖尿病"], &CUE, "conditions")
        })
    }

    /// `糖尿病×k` shape: k `conditions` candidates × k gated-out `medical`
    /// entities. Returns the proximity operation count for one detector run.
    fn prox_probes_conditions(k: usize) -> u64 {
        let input = "糖尿病".repeat(k);
        let pii: Vec<PatternMatch> = (0..k).map(|i| pm("糖", "medical", i * 3, i * 3 + 3)).collect();
        PROX_PROBES.with(|c| c.set(0));
        let _ = detect_with(&input, &pii, count_cfg());
        PROX_PROBES.with(|c| c.get())
    }

    fn prox_probes_conditions_naive(k: usize) -> u64 {
        let input = "糖尿病".repeat(k);
        let pii: Vec<PatternMatch> = (0..k).map(|i| pm("糖", "medical", i * 3, i * 3 + 3)).collect();
        PROX_PROBES.with(|c| c.set(0));
        let _ = detect_with_naive(&input, &pii, count_cfg());
        PROX_PROBES.with(|c| c.get())
    }

    #[test]
    fn conditions_proximity_probe_count_is_linear() {
        // Operation-count gate: the indexed sweep builds the (empty, all gated-out)
        // index ONCE — O(k) — and every candidate query then touches zero entries,
        // so doubling k ~doubles the count (~2×). Two consecutive doublings must
        // each stay well under the 3.0 midpoint. (Excluded from release:
        // `PROX_PROBES` is `#[cfg(test)]`.)
        let k400 = prox_probes_conditions(400);
        let k800 = prox_probes_conditions(800);
        let k1600 = prox_probes_conditions(1600);
        let r1 = k800 as f64 / k400 as f64;
        let r2 = k1600 as f64 / k800 as f64;
        assert!(
            r1 < 3.0 && r2 < 3.0,
            "proximity must be linear: probes(400)={k400} (800)={k800} (1600)={k1600}, \
             ratios {r1:.2}/{r2:.2} (quadratic would be ~4×)"
        );
    }

    #[test]
    fn naive_conditions_proximity_probe_count_is_quadratic() {
        // Pins that the linear gate above has real discriminating power. The naive
        // scan re-walks all k entities from zero for each of the k candidates →
        // O(k²), so doubling k ~quadruples the count (~4×). If the indexed rewrite
        // were reverted to the naive scan, the production ratio would flip from ~2×
        // to ~4× and `conditions_proximity_probe_count_is_linear` (< 3.0) would fail.
        let n400 = prox_probes_conditions_naive(400);
        let n800 = prox_probes_conditions_naive(800);
        let ratio = n800 as f64 / n400 as f64;
        assert!(
            ratio > 3.0,
            "naive proximity must be quadratic: probes(400)={n400} (800)={n800}, \
             ratio {ratio:.2} (linear would be ~2×)"
        );
    }

    /// `糖尿病×k` with PERSON_IDENTIFYING `phone` entities at ~3-char spacing, so
    /// the index is POPULATED (not the empty gated-out case) and every candidate's
    /// ±E_max query touches only a bounded window.
    fn prox_probes_conditions_gated_in(k: usize) -> u64 {
        let input = "糖尿病".repeat(k);
        let pii: Vec<PatternMatch> = (0..k).map(|i| pm("1", "phone", i * 3, i * 3 + 3)).collect();
        PROX_PROBES.with(|c| c.set(0));
        let _ = detect_with(&input, &pii, count_cfg());
        PROX_PROBES.with(|c| c.get())
    }

    #[test]
    fn conditions_proximity_query_is_sublinear_with_populated_index() {
        // Companion to the empty-index gate: pins the sub-linear range-QUERY path,
        // not just the O(k) build. With the index populated (phone entities), each
        // candidate's fixed-width ±E_max(50) window covers a bounded number of
        // entries regardless of k, so the total stays linear (~2×/doubling). A
        // `range_slice` that degraded to a full linear scan would make each query
        // O(k) → O(k²) total → ratio ~4× and THIS test would fail — which the
        // empty-index gate (trivially-empty queries) cannot catch.
        let k400 = prox_probes_conditions_gated_in(400);
        let k800 = prox_probes_conditions_gated_in(800);
        let k1600 = prox_probes_conditions_gated_in(1600);
        let r1 = k800 as f64 / k400 as f64;
        let r2 = k1600 as f64 / k800 as f64;
        assert!(
            r1 < 3.0 && r2 < 3.0,
            "populated-index proximity query must be linear: probes(400)={k400} (800)={k800} \
             (1600)={k1600}, ratios {r1:.2}/{r2:.2} (a full linear range scan would be ~4×)"
        );
    }
}
