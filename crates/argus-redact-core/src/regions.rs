//! Chinese admin-region gazetteer + quasi-identifier coarsening (SSOT).
//!
//! Loads `data/regions/zh.ron` (GB/T 2260) once and exposes `coarsen()`, which
//! maps a span containing an admin region to its city/province ancestor —
//! the core of the lossy `generalize` strategy. Shared by PyO3 + wasm.
use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, OnceLock};

use fancy_regex::Regex;
use serde::Deserialize;

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

/// name → (city, province). Names are not globally unique across provinces (e.g.
/// 朝阳区 exists in 北京 and 辽宁朝阳市); first-by-load-order wins — acceptable for
/// a coarsening heuristic. Built once.
fn region_index() -> &'static HashMap<&'static str, (&'static str, &'static str)> {
    static CELL: OnceLock<HashMap<&'static str, (&'static str, &'static str)>> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut m = HashMap::new();
        for (name, _level, city, province) in &zh_region_data().regions {
            m.entry(name.as_str())
                .or_insert((city.as_str(), province.as_str()));
        }
        m
    })
}

/// All region names sorted LONGEST-first (by char count), for greedy
/// longest-match scans.
fn region_names_longest_first() -> &'static [&'static str] {
    static CELL: OnceLock<Vec<&'static str>> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut names: Vec<&'static str> =
            zh_region_data().regions.iter().map(|r| r.0.as_str()).collect();
        names.sort_by(|a, b| b.chars().count().cmp(&a.chars().count()).then(a.cmp(b)));
        names
    })
    .as_slice()
}

/// Coarsen `span` to the requested level. Finds the FINEST (longest) region name
/// contained in `span`, then returns its `city` (level="city", default) or
/// `province` (level="province") ancestor. Returns `None` if no region is found
/// (caller falls back to the type's default strategy).
pub fn coarsen(span: &str, level: &str) -> Option<String> {
    // Greedy longest-match: names are pre-sorted longest-first, so the first
    // name that appears in the span is the most specific (上海市浦东新区 >
    // 浦东新区 > 上海市) — break on first hit.
    let name = region_names_longest_first()
        .iter()
        .find(|&&n| span.contains(n))
        .copied()?;
    let (city, province) = region_index().get(name).copied()?;
    Some(match level {
        "province" => province.to_string(),
        _ => city.to_string(), // default "city"
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

/// Membership set of every gazetteer region name, for O(1) longest-match
/// probing in [`region_candidates`]. Built once.
fn region_name_set() -> &'static HashSet<&'static str> {
    static CELL: OnceLock<HashSet<&'static str>> = OnceLock::new();
    CELL.get_or_init(|| region_names_longest_first().iter().copied().collect())
}

/// Longest region-name length in **chars**, the upper bound for the
/// longest-match probe window. Built once from the gazetteer.
fn region_max_len() -> usize {
    static CELL: OnceLock<usize> = OnceLock::new();
    *CELL.get_or_init(|| {
        region_names_longest_first()
            .iter()
            .map(|n| n.chars().count())
            .max()
            .unwrap_or(0)
    })
}

/// `_REGION_CUE` — address-context cue words. A hit anywhere in the ±window is
/// the strongest single signal that a region name is being used as a *place a
/// person is associated with* rather than as part of a proper noun
/// (`北京大学`) or a fixed phrase (`北京时间`).
static REGION_CUE: LazyLock<Regex> = LazyLock::new(|| {
    let pat =
        r"住|家在|家住|户籍|籍贯|老家|来自|位于|坐落|工作于|就职|任职|上班|租住|租房|搬到|搬去|定居";
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

/// Scan `chars` for gazetteer region names, returning non-overlapping
/// `(name, start_char, end_char)` matches, longest-match-first at each
/// position. Char offsets throughout (consistent with `person_zh` +
/// `PatternMatch`).
///
/// Left-to-right greedy: at each position try the longest possible substring
/// (down to length 1) and take the first gazetteer hit; on a hit, advance past
/// it so matches never overlap. O(text · max_name_len) with O(1) set lookups.
fn region_candidates(chars: &[char]) -> Vec<(String, usize, usize)> {
    let names = region_name_set();
    let max_len = region_max_len();
    let n = chars.len();
    let mut out: Vec<(String, usize, usize)> = Vec::new();

    let mut i = 0;
    while i < n {
        // Longest-match probe: try length max_len down to 1, first hit wins.
        let hi = max_len.min(n - i);
        let mut matched_len = 0usize;
        for len in (1..=hi).rev() {
            let cand: String = chars[i..i + len].iter().collect();
            if names.contains(cand.as_str()) {
                out.push((cand, i, i + len));
                matched_len = len;
                break;
            }
        }
        // Advance past the match (non-overlapping), or one char on a miss.
        i += matched_len.max(1);
    }

    out
}

/// Detect Chinese admin-region names used as *locations*, gated on positive
/// evidence. Mirrors `person_zh::score_candidate`'s evidence model.
///
/// For each gazetteer candidate found by [`region_candidates`] this slices a
/// `±REGION_WINDOW` char window, accumulates:
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
///
/// `#[allow(dead_code)]`: the detector + its private helpers/consts are wired
/// into the pipeline in a follow-up; until then nothing in the non-test build
/// reaches them. The `allow` on this entry point covers the whole transitive
/// surface (the helpers are only reachable through it).
#[allow(dead_code)]
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
    let n = chars.len();

    let mut out: Vec<crate::types::PatternMatch> = Vec::new();

    for (name, start, end) in region_candidates(&chars) {
        // before = chars[max(0, start - REGION_WINDOW) : start]
        // after  = chars[end : end + REGION_WINDOW]   (char slices)
        let before_start = start.saturating_sub(REGION_WINDOW);
        let before_end = start.min(n);
        let before: String = if before_start <= before_end {
            chars[before_start..before_end].iter().collect()
        } else {
            String::new()
        };

        let after_start = end.min(n);
        let after_end = (end + REGION_WINDOW).min(n);
        let after: String = if after_start <= after_end {
            chars[after_start..after_end].iter().collect()
        } else {
            String::new()
        };

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

        // Proximity to structural PII — first entity within a bucket wins
        // (break). abs_diff over usize char offsets == Python abs() on ints.
        for pii in pii_entities {
            let distance = start
                .abs_diff(pii.end)
                .min(pii.start.abs_diff(end));
            if distance <= REGION_PROX_NEAR {
                evidence += W_REGION_PII_PROX;
                break;
            } else if distance <= REGION_PROX_MID {
                evidence += W_REGION_PII_MID;
                break;
            }
        }

        // No evidence → don't match at L1 (leave to L2 NER).
        if evidence == 0.0_f64 {
            continue;
        }

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

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coarsens_district_to_city_and_province() {
        assert_eq!(coarsen("杭州西湖区文一路100号", "city").as_deref(), Some("杭州市"));
        assert_eq!(coarsen("杭州西湖区文一路100号", "province").as_deref(), Some("浙江省"));
        assert_eq!(coarsen("上海浦东新区建国路100号", "city").as_deref(), Some("上海市"));
        assert_eq!(coarsen("广州天河区天河路", "province").as_deref(), Some("广东省"));
    }

    #[test]
    fn no_region_returns_none() {
        assert_eq!(coarsen("一段没有地名的文本", "city"), None);
    }

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
}
