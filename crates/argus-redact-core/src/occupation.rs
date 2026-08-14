//! Chinese OCCUPATION detection — evidence-gated, mirrors `regions.rs`.
//!
//! Loads `data/occupations/zh.ron` (a curated common-occupation lexicon, NOT a
//! coverage guarantee) once and exposes [`detect_occupation_zh`], which finds
//! occupation mentions (数学老师 / 主播 / 软件工程师 / 护士) ONLY on positive
//! evidence — an occupation-context cue, a high-confidence multi-char lexicon
//! hit, or proximity to other PII.
//!
//! The crux is PRECISION: occupation is the #1 residual re-identification
//! signal, but a bare title like `老师`/`医生` is also the tail of an
//! honorific-person use (`李老师`, `王医生`). Those belong to the PERSON detector
//! (person + honorific), NOT here, so a bare honorific-style title preceded by a
//! single CJK char (a likely surname) with no occupation cue is left alone. A
//! generic word that merely *ends* in a productive suffix without any cue is
//! likewise left for L2 NER rather than emitted at L1.
//!
//! ## Char offsets, not byte offsets
//!
//! Candidate offsets and `PatternMatch` offsets are **character** offsets, and a
//! multi-byte CJK window is never byte-sliced — the whole text is materialized
//! as a `Vec<char>` once and all windowing works in char-space (mirrors
//! `regions.rs` + `person_zh.rs`).

use std::sync::{LazyLock, OnceLock};

use fancy_regex::Regex;
use serde::Deserialize;

use crate::evidence_detector::{
    candidates_cjk, context_windows, is_person_identifying, proximity_evidence, DetectorConfig,
};

#[derive(Debug, Deserialize)]
struct ZhOccupationData {
    /// Curated common occupations (head + multi-char specifics). The long tail
    /// is caught by the productive-suffix heuristic in [`occupation_candidates`].
    occupations: Vec<String>,
}

fn zh_occupation_data() -> &'static ZhOccupationData {
    static CELL: OnceLock<ZhOccupationData> = OnceLock::new();
    CELL.get_or_init(|| {
        ron::from_str(include_str!("../data/occupations/zh.ron"))
            .unwrap_or_else(|e| panic!("RON parse error in data/occupations/zh.ron: {e}"))
    })
}

/// The lexicon as a shared [`DetectorConfig`], built once, and scanned by
/// [`candidates_cjk`] in pass 1 of [`occupation_candidates`] — the same shared
/// gazetteer scan `regions.rs` uses — so this module no longer hand-rolls its own
/// longest-match loop or re-derives its own index. `DetectorConfig::new` indexes
/// the occupation names into the membership set + first-char prefilter + max
/// char-length that `candidates_cjk` reads straight off the config. The names are
/// collected off `zh_occupation_data()` in lexicon order — `new` builds an
/// order-insensitive index (set / first_chars / max), so no longest-first sort is
/// needed. `candidates_cjk` uses `first_chars` as a top-of-loop prefilter; for
/// this lexicon it is a proven no-op — every lexicon term's first char is in the
/// set, so it never skips a position where a longest-match would emit — leaving
/// pass 1 byte-identical to the old hand-rolled scan. The config's cue / weights
/// are unused here: occupation runs its OWN evidence model and pass-2
/// productive-suffix heuristic in `detect_occupation_zh` / `occupation_candidates`.
fn occupation_detector() -> &'static DetectorConfig {
    static CELL: OnceLock<DetectorConfig> = OnceLock::new();
    CELL.get_or_init(|| {
        let names: Vec<&'static str> =
            zh_occupation_data().occupations.iter().map(|s| s.as_str()).collect();
        DetectorConfig::new(&names, &OCC_CUE, "job_title")
    })
}

// ── Productive-suffix heuristic ──
//
// The lexicon is bounded; the long tail of Chinese occupations is regular,
// ending in one of a small set of agentive suffixes. A 2-6 char run ending in
// such a suffix is an occupation CANDIDATE (it still must clear the evidence
// gate, so a bare suffix word with no cue is never emitted).

/// Single-char productive occupation suffixes (师/员/工/家/匠). A 2-6 char CJK
/// run ending in one of these is a candidate (`分析师`, `质检员`, `油漆工`,
/// `科学家`, `铁匠`).
const OCC_SUFFIX_CHARS: &[char] = &['师', '员', '工', '家', '匠'];

/// Multi-char productive occupation suffixes — agentive endings that are not a
/// single char (`主播`, `经理`, `教练`, `医生`, `护士`, `司机`, `演员` is
/// covered by 员). A 2-6 char run ending in one of these is a candidate.
const OCC_SUFFIX_WORDS: &[&str] = &["主播", "经理", "教练", "医生", "护士", "司机", "顾问"];

/// Bare honorific-style titles. When one of these appears immediately after a
/// single CJK char (a likely surname) with NO occupation cue, it is a
/// person+honorific (`李老师`, `王医生`, `张律师`) owned by the PERSON detector,
/// NOT an occupation — see the guard in [`detect_occupation_zh`].
const HONORIFIC_TITLES: &[&str] =
    &["老师", "医生", "师傅", "律师", "教授", "护士", "经理", "教练", "医师", "总监", "主任"];

// ── CJK helper ──

/// Is `c` a CJK unified ideograph? Used by both the suffix-run scan and the
/// honorific surname guard. Mirrors the `\u{4e00}-\u{9fff}` class person_zh uses.
fn is_cjk(c: char) -> bool {
    ('\u{4e00}'..='\u{9fff}').contains(&c)
}

// ── Evidence model ──

/// `_OCC_CUE` — occupation-context cue words. A hit anywhere in the ±window is
/// the strongest single signal that a token is being used as the speaker's /
/// subject's *profession* rather than as part of a name (honorific) or a
/// generic word. The `当.{0,4}的` / `做.{0,4}工作` alternatives allow a short
/// gap (`当老师的`, `做销售工作`).
static OCC_CUE: LazyLock<Regex> = LazyLock::new(|| {
    let pat = r"是一名|是位|是个|担任|从事|当.{0,4}的|职业|做.{0,4}工作|工作是|身为|作为一名|应聘|入职|当.{0,4}工作|是名|是一位";
    Regex::new(pat).unwrap_or_else(|e| panic!("occupation: _OCC_CUE compile failed: {e}"))
});

// Signal weights — named consts mirroring regions.rs / person_zh, so the `+=`
// order is auditable. Conservative starting values; task 12 tunes them.
const W_OCC_CUE: f64 = 0.6; // an occupation-context cue in the ±window
const W_OCC_LEXICON: f64 = 0.5; // a KNOWN multi-char lexicon occupation (high-confidence)
const W_OCC_PII_PROX: f64 = 0.3; // near person-identifying PII (the allowlist)
const OCC_PROX_NEAR: usize = 50;

/// Chars of context examined on each side of a candidate (matches regions'
/// wider window — an occupation cue like `他的职业是…` can sit a few chars off).
const OCC_WINDOW: usize = 40;

/// Default gate: a candidate must reach this evidence total to be emitted. The
/// lone-cue case (`是一名数学老师`) clears it (W_OCC_CUE 0.6 >= 0.5); a bare
/// suffix word with no cue/lexicon/PII signal stays at L2.
const OCC_THRESHOLD: f64 = 0.5;

/// Is `cand` a bare honorific-style title (a member of [`HONORIFIC_TITLES`])?
/// Such a token preceded by a single CJK surname char with no cue is a
/// person+honorific, not an occupation.
fn is_honorific_title(cand: &str) -> bool {
    HONORIFIC_TITLES.contains(&cand)
}

/// Scan `chars` for occupation candidates, returning non-overlapping
/// `(name, start_char, end_char, is_lexicon)` matches, longest-match-first at
/// each position. Combines lexicon hits (longest lexicon name at the position)
/// with the productive-suffix heuristic (a 2-6 char CJK run ending in a suffix),
/// always preferring the longest. `is_lexicon` records whether the chosen span
/// is a known lexicon occupation (drives the high-confidence `W_OCC_LEXICON`
/// weight).
///
/// Char offsets throughout (consistent with `PatternMatch`). Left-to-right
/// greedy: at each position take the longest candidate (lexicon OR suffix-run);
/// on a hit, advance past it so matches never overlap.
///
/// Two complementary passes, with LEXICON HITS winning:
///   1. A left-to-right greedy longest-match LEXICON scan, consuming each hit's
///      span (so `数学老师`, `带货主播`, `急诊科护士` are grabbed whole).
///   2. A suffix-run pass over the still-UNCONSUMED chars: each productive
///      suffix occurrence (师/员/工/家/匠 or 主播/经理/教练/医生/护士/司机/顾问)
///      that is not inside a lexicon span ANCHORS a candidate, and the run is
///      grown BACKWARD over contiguous CJK chars (up to [`SUFFIX_RUN_BACK`]
///      preceding chars), so a bare `XX师` long-tail occupation is caught
///      without the heuristic swallowing leading particles / cue words
///      (`一名数学老师` → the lexicon `数学老师`; an unknown `驯兽师` → `驯兽师`).
///
/// `is_lexicon` records whether a candidate came from pass 1 (drives the
/// high-confidence `W_OCC_LEXICON` weight). Returns candidates sorted by start.
fn occupation_candidates(chars: &[char]) -> Vec<(String, usize, usize, bool)> {
    let n = chars.len();

    // `consumed[k]` = char k is inside a lexicon span (pass 1 owns it).
    let mut consumed = vec![false; n];
    let mut out: Vec<(String, usize, usize, bool)> = Vec::new();

    // ── Pass 1: greedy longest-match lexicon scan ──
    // The shared gazetteer scan `regions.rs` uses; `candidates_cjk` reads the
    // occupation name_set / first_chars / max_len straight off the config, so the
    // loop is no longer hand-rolled here. `is_lexicon = true` for every span.
    for (cand, start, end) in candidates_cjk(chars, occupation_detector()) {
        consumed[start..end].fill(true);
        out.push((cand, start, end, true));
    }

    // ── Pass 2: suffix-run heuristic over unconsumed chars ──
    // Anchor at each productive-suffix END, grow backward over contiguous CJK
    // (bounded), require the whole run to be unconsumed.
    let mut j = 0;
    while j < n {
        // Is there a productive suffix ENDING at j (so the suffix's last char is
        // chars[j])? A single-char suffix ends at j when chars[j] is a suffix
        // char; a multi-char suffix word ends at j when chars[j-w+1..=j] == word.
        let suffix_len = productive_suffix_len_ending_at(chars, j);
        if let Some(slen) = suffix_len {
            let suffix_start = j + 1 - slen;
            // Grow backward over contiguous unconsumed CJK chars, up to
            // SUFFIX_RUN_BACK before the suffix; stop at a consumed char, a
            // non-CJK char, or the bound.
            let back_limit = suffix_start.saturating_sub(SUFFIX_RUN_BACK);
            let mut start = suffix_start;
            while start > back_limit && is_cjk(chars[start - 1]) && !consumed[start - 1] {
                start -= 1;
            }
            // A bare 1-char single-suffix run (just `师`) is not an occupation;
            // require length >= 2, the whole run unconsumed, and not overlapping
            // a lexicon span.
            let end = j + 1;
            if end - start >= 2 && (start..end).all(|k| !consumed[k]) {
                let cand: String = chars[start..end].iter().collect();
                out.push((cand, start, end, false));
                consumed[start..end].fill(true);
            }
        }
        j += 1;
    }

    out.sort_by_key(|(_, s, _, _)| *s);
    out
}

/// Max chars a bare suffix-run may extend BACKWARD before the suffix. Keeps the
/// heuristic tight (`工程师`, `分析师`, `质检员`) so it never swallows a leading
/// particle / cue. Real longer occupations live in the lexicon.
const SUFFIX_RUN_BACK: usize = 3;

/// If a productive occupation suffix ENDS at `chars[j]`, return its char length
/// (1 for a single-char suffix 师/员/工/家/匠; 2 for a multi-char suffix word
/// 主播/经理/…). Multi-char words take precedence (longest suffix wins).
fn productive_suffix_len_ending_at(chars: &[char], j: usize) -> Option<usize> {
    // Multi-char suffix word ending at j (all OCC_SUFFIX_WORDS are 2 chars).
    if j >= 1 {
        let two: String = chars[j - 1..=j].iter().collect();
        if OCC_SUFFIX_WORDS.contains(&two.as_str()) {
            return Some(2);
        }
    }
    // Single-char productive suffix.
    if OCC_SUFFIX_CHARS.contains(&chars[j]) {
        return Some(1);
    }
    None
}

/// Detect Chinese occupation mentions used as a *profession*, gated on positive
/// evidence. Mirrors `regions::detect_regions_zh`'s evidence model.
///
/// For each candidate from [`occupation_candidates`] this slices a `±OCC_WINDOW`
/// char window and accumulates:
///   - `+= W_OCC_CUE` if an occupation-context cue is in the before/after window,
///   - `+= W_OCC_LEXICON` if the candidate is a KNOWN multi-char lexicon
///     occupation (high-confidence even without a cue, e.g. 软件工程师 /
///     带货主播 / 急诊科护士) — but NOT for a bare ambiguous 2-char title
///     (老师/医生 alone still need a cue),
///   - one proximity bucket vs `pii_entities` (`<= OCC_PROX_NEAR` →
///     `W_OCC_PII_PROX`), first match wins (`break`), with only person-identifying
///     PII eligible (phone/email/id/…); technical tokens, org names, and weak/
///     sensitive attributes are excluded via `is_person_identifying` allowlist.
///
/// ## Honorific-person guard (critical FP)
///
/// `李老师` / `王医生` are person+honorific, owned by the PERSON detector. If the
/// candidate is a bare honorific-style title (老师/医生/师傅/律师/教授/护士/
/// 经理/教练/…) AND is immediately preceded by exactly one CJK char that could
/// be a surname (i.e. the char before THAT is not itself CJK), AND there is no
/// occupation cue in the window, the candidate is SKIPPED. A cue (`他是一名李老师`
/// — contrived but possible) overrides the guard; a multi-char lexicon
/// occupation (`数学老师`) is never a bare honorific title so is unaffected.
///
/// Zero evidence → skip (leave to L2 NER). Otherwise emit when the total clears
/// [`OCC_THRESHOLD`], with `confidence = evidence.min(1.0)`, `type_ =
/// "job_title"` and `layer = 1`.
pub fn detect_occupation_zh(
    text: &str,
    pii_entities: &[crate::types::PatternMatch],
) -> Vec<crate::types::PatternMatch> {
    if text.is_empty() {
        return Vec::new();
    }

    // Materialize the whole text as a char slice ONCE, then work in char-space.
    let chars: Vec<char> = text.chars().collect();

    let mut out: Vec<crate::types::PatternMatch> = Vec::new();

    for (name, start, end, is_lexicon) in occupation_candidates(&chars) {
        // before = chars[max(0, start - OCC_WINDOW) : start]
        // after  = chars[end : end + OCC_WINDOW]   (char slices)
        let (before, after) = context_windows(&chars, start, end, OCC_WINDOW);

        // Occupation-context cue anywhere in the ±window (before OR after).
        let cue_hit = OCC_CUE.is_match(&before).unwrap_or(false)
            || OCC_CUE.is_match(&after).unwrap_or(false);

        // ── Honorific-person guard ──
        // A bare honorific-style title (老师/医生/…) preceded by exactly ONE CJK
        // char (a likely surname) with no cue is a person+honorific, not an
        // occupation. "Exactly one" = the char at start-1 is CJK and either
        // start == 1 or the char at start-2 is NOT CJK (so 数学老师 — where 学
        // precedes and 数 is CJK before it — is NOT a single-surname prefix; it
        // is already a multi-char lexicon hit anyway and never reaches here as a
        // bare title).
        if !cue_hit && is_honorific_title(&name) && start >= 1 {
            let prev = chars[start - 1];
            let prev_is_lone_cjk = is_cjk(prev) && (start == 1 || !is_cjk(chars[start - 2]));
            if prev_is_lone_cjk {
                continue; // person+honorific — PERSON detector owns it.
            }
        }

        let mut evidence = 0.0_f64;

        if cue_hit {
            evidence += W_OCC_CUE;
        }

        // Known multi-char lexicon occupation — high-confidence even without a
        // cue (软件工程师/带货主播/急诊科护士). A bare ambiguous suffix-only
        // 2-char honorific title (老师/医生 alone) does NOT get this weight even
        // if it happens to be in the lexicon: it needs a cue.
        let multi_char = name.chars().count() >= 3;
        if is_lexicon && multi_char {
            evidence += W_OCC_LEXICON;
        }

        // Proximity to person-identifying PII — first entity within the near
        // bucket wins, via the shared `proximity_evidence` helper (occupation has
        // a single near bucket, no mid). Only PII that NAMES or CONTACTS a
        // specific person (phone/email/id/…) answers "is someone identifiable
        // nearby?" and corroborates. Technical tokens (ip_address/jwt/url_token/
        // api-key), org names, and weak/sensitive attributes do not. The allowlist
        // gate (is_person_identifying) enforces this; new technical types are safe
        // by default. This subsumes the old self_reference/organization denylist.
        evidence += proximity_evidence(
            start,
            end,
            pii_entities.iter(),
            &[(OCC_PROX_NEAR, W_OCC_PII_PROX)],
            |pii| is_person_identifying(&pii.type_),
        );

        if evidence >= OCC_THRESHOLD {
            out.push(crate::types::PatternMatch {
                text: name,
                type_: "job_title".to_string(),
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

    #[test]
    fn lexicon_loads_and_is_nonempty() {
        assert!(zh_occupation_data().occupations.len() > 100);
    }

    #[test]
    fn detects_occupation_with_cue() {
        for t in ["他是一名数学老师，教高三。", "她从事软件工程师工作。", "我担任急诊科护士。"] {
            let hits = detect_occupation_zh(t, &[]);
            assert!(hits.iter().any(|h| h.type_ == "job_title"), "no occupation in {t:?}: {hits:?}");
        }
    }

    #[test]
    fn known_multichar_occupation_fires_without_cue() {
        let hits = detect_occupation_zh("他是带货主播。", &[]); // 是 is a light cue; 带货主播 is high-confidence lexicon
        assert!(hits.iter().any(|h| h.text.contains("主播")), "带货主播 not detected: {hits:?}");
    }

    #[test]
    fn honorific_person_not_an_occupation_fp() {
        // 李老师/王医生 are person+honorific, NOT occupation entities.
        for t in ["李老师今天布置了作业。", "王医生很负责。"] {
            let hits = detect_occupation_zh(t, &[]);
            assert!(hits.iter().all(|h| h.type_ != "job_title"),
                    "honorific-person false-positive in {t:?}: {hits:?}");
        }
    }

    #[test]
    fn bare_title_without_cue_or_surname_does_not_fire() {
        // A bare suffix word with no cue, no surname prefix, no PII → leave to L2.
        let hits = detect_occupation_zh("这本书很厚。", &[]);
        assert!(hits.is_empty(), "unexpected occupation hit: {hits:?}");
    }

    fn pm(text: &str, type_: &str, start: usize, end: usize) -> crate::types::PatternMatch {
        crate::types::PatternMatch {
            text: text.to_string(),
            type_: type_.to_string(),
            start,
            end,
            confidence: 1.0,
            layer: 0,
        }
    }

    #[test]
    fn organization_does_not_corroborate_occupation() {
        // An org adjacent to a BARE suffix-run (驯兽师 — not in the lexicon, so
        // no W_OCC_LEXICON) must NOT make it fire: org proximity is excluded from
        // the proximity loop (mirrors regions), so evidence stays 0 → skip.
        let t = "腾讯的驯兽师";
        let org = vec![pm("腾讯", "organization", 0, 2)];
        assert!(
            detect_occupation_zh(t, &org)
                .iter()
                .all(|h| h.type_ != "job_title"),
            "organization must not corroborate a bare occupation"
        );
    }

    #[test]
    fn self_reference_does_not_corroborate_occupation() {
        // self_reference near a BARE suffix-run (驯兽师) must not corroborate it
        // (excluded from the proximity loop, mirrors regions).
        let t = "我旁边的驯兽师";
        let sr = vec![pm("我", "self_reference", 0, 1)];
        assert!(
            detect_occupation_zh(t, &sr)
                .iter()
                .all(|h| h.type_ != "job_title"),
            "self_reference must not corroborate a bare occupation"
        );
    }

    #[test]
    fn real_pii_corroborates_bare_suffix_run_with_cue() {
        // A bare suffix-run (驯兽师) with a cue fires; verifying the suffix
        // heuristic + cue path works end-to-end for the long tail.
        let hits = detect_occupation_zh("他从事驯兽师这个职业。", &[]);
        assert!(
            hits.iter().any(|h| h.text.contains("驯兽师") && h.type_ == "job_title"),
            "bare suffix-run with cue should fire: {hits:?}"
        );
    }

    #[test]
    fn occupation_ip_address_does_not_corroborate_guard() {
        // STATIC GUARD — not a fail-before/pass-after behavioral proof. Occupation's
        // W_OCC_PII_PROX=0.3 < OCC_THRESHOLD=0.5, so proximity alone NEVER fires an
        // occupation regardless of the PII type; this candidate was correctly not
        // detected both before and after the allowlist change. The test exists to
        // catch a FUTURE weight increase that would otherwise re-open the gap: if
        // W_OCC_PII_PROX is ever raised to ≥ 0.5, a technical token like ip_address
        // must STILL be excluded by the is_person_identifying allowlist and must not
        // make a bare occupation fire.
        //
        // A bare suffix-run occupation (驯兽师 — 3 chars, NOT in lexicon) with NO
        // cue, whose only nearby entity is an ip_address (technical, non-person-
        // identifying → absent from PERSON_IDENTIFYING_PII → excluded).
        let t = "驯兽师 192.168.1.1";
        // 驯兽师: chars 0-2 (end=3). ip starts at 4.
        let ip = vec![pm("192.168.1.1", "ip_address", 4, 15)];
        assert!(
            detect_occupation_zh(t, &ip)
                .iter()
                .all(|h| h.type_ != "job_title"),
            "technical PII (ip_address) must not corroborate a bare occupation: {:?}",
            detect_occupation_zh(t, &ip)
        );
    }

    #[test]
    fn phone_not_accidentally_excluded_from_occupation_allowlist() {
        // EXCLUSION GUARD — confirms `phone` is in the is_person_identifying
        // allowlist and is NOT accidentally skipped by the proximity gate. It is
        // NOT a proof that phone proximity DECIDES detection: the candidate 分析师
        // is a known multi-char LEXICON occupation (3 chars → W_OCC_LEXICON=0.5 ≥
        // OCC_THRESHOLD=0.5), so it fires on its lexicon weight alone; phone merely
        // adds corroboration (0.8 total). Given the weight design (W_OCC_PII_PROX=0.3
        // < threshold) no occupation candidate can ever make proximity the deciding
        // factor — so this asserts the allowlist does not WRONGLY exclude phone, not
        // that phone is load-bearing here.
        let t = "分析师 13812345678";
        // 分析师: chars 0-2 (end=3). phone starts at char 4.
        let phone = vec![pm("13812345678", "phone", 4, 15)];
        assert!(
            detect_occupation_zh(t, &phone)
                .iter()
                .any(|h| h.text == "分析师" && h.type_ == "job_title"),
            "phone must not prevent occupation detection (personal PII still corroborates): {:?}",
            detect_occupation_zh(t, &phone)
        );
    }
}
