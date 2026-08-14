//! Chinese admin-region gazetteer + evidence-gated bare-region detection (SSOT).
//!
//! Loads `data/regions/zh.ron` (GB/T 2260) once and uses it as the dictionary for
//! [`detect_regions_zh`], which finds bare admin-region mentions (北京 / 浦东新区)
//! used as a place a person is associated with, gated on positive evidence so
//! 北京时间 / 北京大学 don't fire. Shared by PyO3 + wasm; feeds the default
//! `remove` strategy for `location`.
use std::sync::{LazyLock, OnceLock};

use fancy_regex::Regex;
use serde::Deserialize;

use crate::evidence_detector::{
    candidates_cjk, context_windows, is_person_identifying, proximity_evidence, DetectorConfig,
};

#[derive(Debug, Deserialize)]
struct ZhRegionData {
    /// (name, level["province"|"city"|"district"], city_name, province_name)
    regions: Vec<(String, String, String, String)>,
}

fn zh_region_data() -> &'static ZhRegionData {
    static CELL: OnceLock<ZhRegionData> = OnceLock::new();
    CELL.get_or_init(|| {
        ron::from_str(include_str!("../data/regions/zh.ron"))
            .unwrap_or_else(|e| panic!("RON parse error in data/regions/zh.ron: {e}"))
    })
}

// ── Evidence-gated bare-region detection ──
//
// Modeled closely on `person_zh::score_candidate`: a candidate is found by a
// gazetteer scan (the analogue of `generate_candidates`), then a per-candidate
// evidence pass slices a before/after char window, accumulates weighted
// signals (`+=`), adds a proximity-to-PII bucket (first bucket wins, `break`),
// short-circuits to "skip" on zero evidence, and otherwise emits a
// `PatternMatch` with char offsets when the total clears a threshold.
//
// The crux is PRECISION: a bare region name like `北京` appears in
// `北京时间` / `北京大学` / `北京烤鸭` with no address meaning. The gate fires
// ONLY on positive evidence (an address-context cue, a structural-suffix
// continuation, or proximity to other PII), so a region mention with none of
// those is left for L2 NER rather than emitted at L1.

/// The gazetteer as a shared [`DetectorConfig`], built once. `DetectorConfig::new`
/// indexes the names into the SAME membership set / first-char prefilter / max
/// char-length this module used to build by hand, so the candidate scan reuses
/// `evidence_detector::candidates_cjk` — byte-identical to the hand-rolled region
/// scan this module used to carry — and the parent-prefix absorption reuses the
/// name set + max_len via the config's accessors. The names are collected
/// straight off `zh_region_data()` in gazetteer order: `new` builds an
/// order-insensitive index (set / first_chars / max), so no longest-first sort is
/// needed. The cue / weights the config also carries are unused here — region
/// detection layers its OWN signals (struct-suffix / cue / proximity) in
/// `detect_regions_zh`.
fn region_detector() -> &'static DetectorConfig {
    static CELL: OnceLock<DetectorConfig> = OnceLock::new();
    CELL.get_or_init(|| {
        let names: Vec<&'static str> =
            zh_region_data().regions.iter().map(|r| r.0.as_str()).collect();
        DetectorConfig::new(&names, &REGION_CUE, "location")
    })
}

/// Trailing administrative-division suffix chars a colloquial parent reference
/// drops (`上海市`→`上海`, `广东省`→`广东`, `海淀区`→`海淀`, `阿拉善盟`→`阿拉善`).
/// Used only by [`is_suffix_elided_region`] for parent-prefix absorption — never
/// by the candidate scan or evidence gate.
const REGION_ADMIN_SUFFIXES: &[char] = &['市', '省', '区', '县', '旗', '州', '盟'];

/// True if `prefix` is a gazetteer region name with its trailing admin suffix
/// elided (the colloquial parent form, e.g. `上海` for `上海市`). Tests each
/// admin suffix appended back against the gazetteer set; bounded, O(1) lookups.
/// A bare `prefix` of length < 1 or already ending in a name is handled by the
/// exact-name check at the call site, so this only covers the elided case.
fn is_suffix_elided_region(prefix: &str) -> bool {
    if prefix.is_empty() {
        return false;
    }
    let set = region_detector().name_set();
    REGION_ADMIN_SUFFIXES.iter().any(|suf| {
        let mut candidate = String::with_capacity(prefix.len() + suf.len_utf8());
        candidate.push_str(prefix);
        candidate.push(*suf);
        set.contains(candidate.as_str())
    })
}

/// `_REGION_CUE` — address-context cue words. A hit anywhere in the ±window is
/// the strongest single signal that a region name is being used as a *place a
/// person is associated with* rather than as part of a proper noun
/// (`北京大学`) or a fixed phrase (`北京时间`).
static REGION_CUE: LazyLock<Regex> = LazyLock::new(|| {
    // `住` already subsumes 现住/居住/居住在/租住; the rest are distinct
    // residence/registration/birthplace cues common in CN address phrasing.
    let pat = r"住|家在|家住|户籍|户口|籍贯|老家|来自|位于|坐落|工作于|工作单位|就职|任职|上班|租住|租房|搬到|搬去|定居|现居|落户|居住|出生";
    Regex::new(pat).unwrap_or_else(|e| panic!("regions: _REGION_CUE compile failed: {e}"))
});

/// Structural address-continuation heads. When the chars immediately AFTER a
/// candidate start with one of these, the region is the prefix of a finer
/// address span (`...浦东新区` + `张江路`), which is strong location evidence.
/// `市`/`省`/`区` overlap with names already ending in them; that is fine — the
/// check is on the FOLLOWING char, so `浦东新区` (ends in 区) only scores
/// W_REGION_STRUCT if it is itself followed by another structural head.
const REGION_STRUCT_HEADS: &[char] = &[
    '区', '市', '省', '路', '街', '号', '巷', '弄', '镇', '村', '县', '栋', '幢', '室', '座',
    '楼',
];

/// Multi-char structural continuations (checked as a leading substring of the
/// following text, since `小区`/`大厦`/`大道` are two chars).
const REGION_STRUCT_WORDS: &[&str] = &["小区", "大厦", "大道", "广场", "花园", "公寓", "村委"];

// Signal weights — named consts mirroring person_zh, so the `+=` order is
// auditable. Conservative starting values; task 8 tunes them against the
// fixture.
const W_REGION_CUE: f64 = 0.6; // an address-context cue in the ±window
const W_REGION_STRUCT: f64 = 0.5; // immediately followed by a structural suffix
const W_REGION_PII_PROX: f64 = 0.5; // within REGION_PROX_NEAR chars of other PII
const W_REGION_PII_MID: f64 = 0.3; // within REGION_PROX_MID chars
const REGION_PROX_NEAR: usize = 50;
const REGION_PROX_MID: usize = 150;

/// `_REGION_WINDOW` — chars of context examined on each side of a candidate.
/// Wider than person_zh's 20 because address cues (`户籍所在地为…`) can sit a
/// few more chars away from the region token; still char-space, never bytes.
const REGION_WINDOW: usize = 40;

/// Default gate: a candidate must reach this evidence total to be emitted. The
/// lone-cue case (`住在上海浦东新区`) clears it (W_REGION_CUE = 0.6 >= 0.5);
/// task 8 tunes this against the fixture corpus.
const REGION_THRESHOLD: f64 = 0.5;

/// Detect Chinese admin-region names used as *locations*, gated on positive
/// evidence. Mirrors `person_zh::score_candidate`'s evidence model.
///
/// The gazetteer scan reuses [`evidence_detector::candidates_cjk`] over the
/// shared [`region_detector`] config — a left-to-right greedy longest-match,
/// first-char-prefiltered, non-overlapping substring scan (byte-identical to the
/// hand-rolled scan this module used to carry). For each gazetteer candidate it
/// then slices a `±REGION_WINDOW` char window and accumulates:
///   - `+= W_REGION_CUE` if an address-context cue is in the before/after
///     window,
///   - `+= W_REGION_STRUCT` if the chars immediately after the candidate are a
///     structural address continuation,
///   - one proximity bucket vs `pii_entities` (`<= REGION_PROX_NEAR` →
///     `W_REGION_PII_PROX`, else `<= REGION_PROX_MID` → `W_REGION_PII_MID`),
///     first bucket wins (`break`), via `abs_diff` over char offsets exactly
///     like `score_candidate`.
///
/// Zero evidence → skip (leave to L2 NER). Otherwise emit when the total clears
/// [`REGION_THRESHOLD`], with `confidence = evidence.min(1.0)` and `layer = 1`.
///
/// `pii_entities[i].start/.end` are char offsets (same convention as
/// `score_candidate`).
pub(crate) fn detect_regions_zh(
    text: &str,
    pii_entities: &[crate::types::PatternMatch],
) -> Vec<crate::types::PatternMatch> {
    if text.is_empty() {
        return Vec::new();
    }

    // Materialize the whole text as a char slice ONCE, then work in char-space
    // — candidate offsets and PatternMatch offsets are char offsets, and a
    // multi-byte CJK window must never be byte-sliced (mirrors person_zh).
    let chars: Vec<char> = text.chars().collect();

    let mut out: Vec<crate::types::PatternMatch> = Vec::new();

    for (name, start, end) in candidates_cjk(&chars, region_detector()) {
        // before = chars[max(0, start - REGION_WINDOW) : start]
        // after  = chars[end : end + REGION_WINDOW]   (char slices)
        let (before, after) = context_windows(&chars, start, end, REGION_WINDOW);

        let mut evidence = 0.0_f64;

        // Address-context cue anywhere in the ±window (before OR after).
        if REGION_CUE.is_match(&before).unwrap_or(false)
            || REGION_CUE.is_match(&after).unwrap_or(false)
        {
            evidence += W_REGION_CUE;
        }

        // Structural-suffix continuation: the chars immediately AFTER the
        // candidate begin with a structural head (single-char) or word
        // (multi-char). `after` already starts exactly at the candidate end.
        let struct_hit = after
            .chars()
            .next()
            .is_some_and(|c| REGION_STRUCT_HEADS.contains(&c))
            || REGION_STRUCT_WORDS.iter().any(|w| after.starts_with(w));
        if struct_hit {
            evidence += W_REGION_STRUCT;
        }

        // Proximity to person-identifying PII — first entity within a bucket wins
        // (near before mid), via the shared `proximity_evidence` helper.
        //
        // Only PII that NAMES, CONTACTS, or LOCATES a specific person corroborates
        // (phone/person/id/email/…). Technical tokens (url_token/jwt/ip_address/
        // api-key), org names, weak attributes (age/gender), and sensitive-but-non-
        // locating attributes do NOT answer "is an identifiable person nearby?" and
        // must not promote a bare region to redaction by proximity alone. The gate
        // is an allowlist (is_person_identifying): new technical types are safe by
        // default. This subsumes the old self_reference/organization denylist —
        // both are simply absent from the allowlist.
        evidence += proximity_evidence(
            start,
            end,
            pii_entities.iter(),
            &[
                (REGION_PROX_NEAR, W_REGION_PII_PROX),
                (REGION_PROX_MID, W_REGION_PII_MID),
            ],
            |pii| is_person_identifying(&pii.type_),
        );

        if evidence >= REGION_THRESHOLD {
            out.push(crate::types::PatternMatch {
                text: name,
                type_: "location".to_string(),
                start,
                end,
                confidence: evidence.min(1.0),
                layer: 1,
            });
        }
    }

    // Parent-prefix absorption: 上海浦东新区 is a parent region glued to a
    // district; only the district cleared evidence above, leaving a bare 上海. If
    // an emitted region is immediately preceded (no gap) by another gazetteer
    // region name in `chars`, extend its span left to swallow the prefix so the
    // whole place reference is redacted as one unit.
    //
    // The gazetteer stores names WITH their admin suffix (`上海市`, `广东省`,
    // `海淀区`), but a parent written directly before a child is usually
    // colloquial and drops it (`上海`浦东新区, `广东`深圳市). So a prefix matches
    // if it equals a gazetteer name OR a gazetteer name minus its trailing admin
    // char. This only WIDENS an already-emitted match — it can never create a
    // new one, so the precision guards (北京时间/北京大学/北京烤鸭, which never
    // emit) are unaffected.
    // One reused probe buffer for every candidate `s` across every match. A long
    // parent chain probes millions of prefixes; `clear` keeps the capacity so no
    // per-probe heap allocation happens. Byte-identical: same prefix content,
    // same longest-match-first scan order, same membership test.
    let mut prefix = String::with_capacity(region_detector().max_len() * 4);
    for m in out.iter_mut() {
        // `m.end` never moves during the walk, so the widened span is always
        // `chars[m.start..m.end]`. Only slide `m.start` left here; materialize
        // `m.text` ONCE after the loop. Re-collecting the whole `chars[s..m.end]`
        // on every absorption step made a k-region chain O(k²) char copies — a
        // legal `上海市`×32000 input (288 KB, under the 1 MiB cap) burned tens of
        // seconds. Materialize-once drops it to O(k): byte-identical output (same
        // absorption decisions, same final `(text, start, end)`), only faster.
        loop {
            let probe_lo = m.start.saturating_sub(region_detector().max_len());
            let mut absorbed = false;
            for s in probe_lo..m.start {
                prefix.clear();
                prefix.extend(chars[s..m.start].iter());
                if region_detector().name_set().contains(prefix.as_str())
                    || is_suffix_elided_region(&prefix)
                {
                    m.start = s;
                    absorbed = true;
                    break;
                }
            }
            if !absorbed {
                break;
            }
        }
        m.text = chars[m.start..m.end].iter().collect();
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gazetteer_loads_and_is_nonempty() {
        assert!(zh_region_data().regions.len() > 3000);
    }

    #[test]
    fn detects_region_with_address_cue() {
        let hits = detect_regions_zh("他住在上海浦东新区，平时很忙。", &[]);
        assert!(
            hits.iter()
                .any(|h| h.text.contains("浦东新区") && h.type_ == "location"),
            "expected a location hit for 住在上海浦东新区, got {hits:?}"
        );
    }

    #[test]
    fn skips_region_without_evidence() {
        // 北京时间 / 北京大学 / 北京烤鸭 — region name present but no address cue.
        for t in ["现在是北京时间晚上8点。", "他考上了北京大学。", "我想吃北京烤鸭。"] {
            let hits = detect_regions_zh(t, &[]);
            assert!(hits.is_empty(), "false positive on {t:?}: {hits:?}");
        }
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
    fn self_reference_does_not_corroborate_region() {
        // `我很喜欢西湖区的风景` — `我` (self_reference) is near 西湖区 but must
        // NOT corroborate it: no cue, no struct, so the region stays at L2.
        let t = "我很喜欢西湖区的风景。";
        let sr = vec![pm("我", "self_reference", 0, 1)];
        assert!(
            detect_regions_zh(t, &sr).is_empty(),
            "self_reference must not corroborate a bare region"
        );
    }

    #[test]
    fn organization_does_not_corroborate_region() {
        // `海淀区中关村科技园…` — an org span adjacent to 海淀区 must NOT make
        // the bare region fire (orgs co-occur with place names routinely).
        let t = "海淀区中关村科技园聚集了大量互联网企业。";
        let org = vec![pm("中关村科技园", "organization", 3, 9)];
        assert!(
            detect_regions_zh(t, &org).is_empty(),
            "organization must not corroborate a bare region"
        );
    }

    #[test]
    fn real_pii_still_corroborates_region() {
        // A phone number (person-identifying PII) near a bare region SHOULD
        // still clear the proximity bucket — only person-identifying types are
        // in the allowlist (is_person_identifying), and phone is one of them.
        let t = "西湖区 13812345678";
        let phone = vec![pm("13812345678", "phone", 4, 15)];
        assert!(
            detect_regions_zh(t, &phone)
                .iter()
                .any(|h| h.text == "西湖区"),
            "real PII (phone) must still corroborate a region by proximity"
        );
    }

    #[test]
    fn region_not_corroborated_by_technical_pii() {
        // A bare region (西湖区) with NO address cue and NO structural suffix whose
        // ONLY nearby entity is a url_token: under the old hardcoded denylist,
        // url_token is not excluded so W_REGION_PII_PROX 0.5 ≥ threshold 0.5 →
        // wrongly detected. Under the allowlist approach, url_token is absent from
        // PERSON_IDENTIFYING_PII → excluded from the proximity loop → evidence = 0
        // → not detected. Pins the allowlist principle for region detection.
        //
        // "西湖区 http://x.com": 西湖区 chars 0-3, space 3, url starts at 4.
        // Distance min(0.abs_diff(16), 4.abs_diff(3)) = 1 ≤ REGION_PROX_NEAR.
        let t = "西湖区 http://x.com";
        let url = vec![pm("http://x.com", "url_token", 4, 16)];
        assert!(
            detect_regions_zh(t, &url).is_empty(),
            "technical PII (url_token) must not corroborate a bare region: {:?}",
            detect_regions_zh(t, &url)
        );
    }

    #[test]
    fn region_mixed_technical_and_personal_fires() {
        // A bare region near BOTH a url_token (technical, non-corroborating) AND a
        // phone (personal, corroborating): the url_token must be skipped and the
        // phone must still clear the proximity bucket. Region is detected.
        //
        // "西湖区 http://x.com 13812345678"
        //   西湖区: 0-3  url_token: 4-16  phone: 17-28
        let t = "西湖区 http://x.com 13812345678";
        let url = pm("http://x.com", "url_token", 4, 16);
        let phone = pm("13812345678", "phone", 17, 28);
        assert!(
            detect_regions_zh(t, &[url, phone]).iter().any(|h| h.text == "西湖区"),
            "phone must still corroborate region even when a url_token precedes it in the list"
        );
    }

    #[test]
    fn parent_prefix_absorption_span_is_byte_identical() {
        // Pins the exact absorbed span for a multi-region chain. `浦东新区`
        // (chars 5..9) is the only candidate that clears evidence (cue `住`);
        // parent-prefix absorption then slides the start left over the
        // suffix-elided parent `上海` (`上海市` minus 市), giving the single
        // widened unit `上海浦东新区` at [3, 9). The materialize-once fix must
        // reproduce this tuple exactly — same absorption decisions, same
        // `(text, start, end)`, just computed once instead of per step.
        let hits = detect_regions_zh("他住在上海浦东新区。", &[]);
        let loc: Vec<_> = hits.iter().filter(|h| h.type_ == "location").collect();
        assert_eq!(
            loc.len(),
            1,
            "expected exactly one location hit, got {hits:?}"
        );
        assert_eq!(loc[0].text, "上海浦东新区");
        assert_eq!((loc[0].start, loc[0].end), (3, 9));
    }

    #[test]
    fn parent_prefix_absorption_chain_stays_byte_identical() {
        // The degenerate parent-chain that used to blow up. The trailing `住`
        // (residence cue) makes every `上海市` candidate clear evidence, and each
        // walks the full chain leftward, absorbing all preceding parents and
        // stopping at 0 — so the emitted set is nested {上海市, 上海市上海市, …}.
        // Re-materializing `chars[s..end]` on every absorption step made a
        // k-region chain O(k²) char copies: a legal `上海市`×32000 (288 KB, under
        // the 1 MiB cap, reachable on a default `redact()`) burned ~34s and
        // outran the 30s scan deadline uninterruptibly. Materialize-once drops
        // each chain to O(k) — measured release scaling is 2× per input doubling
        // (linear), down from ~4× (quadratic). This pins the chain-scale output
        // as byte-identical: same absorption decisions, same final
        // (text, start, end), only computed once per match.
        let mut input = "上海市".repeat(3);
        input.push('住');
        let mut got: Vec<(String, usize, usize)> = detect_regions_zh(&input, &[])
            .into_iter()
            .map(|h| (h.text, h.start, h.end))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("上海市".to_string(), 0, 3),
                ("上海市上海市".to_string(), 0, 6),
                ("上海市上海市上海市".to_string(), 0, 9),
            ],
            "degenerate parent-chain absorption must stay byte-identical"
        );
    }

    #[test]
    fn residence_cues_detect_region() {
        // The cues added to _REGION_CUE (现居/户口/落户/出生) each fire on their
        // own (W_REGION_CUE 0.6 >= 0.5).
        for t in [
            "现居北京市海淀区。",
            "户口在西安市雁塔区。",
            "落户深圳市福田区。",
            "出生在重庆市渝中区。",
        ] {
            let hits = detect_regions_zh(t, &[]);
            assert!(
                !hits.is_empty(),
                "expected a location hit for residence cue in {t:?}, got {hits:?}"
            );
        }
    }
}
