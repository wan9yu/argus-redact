//! Chinese admin-region gazetteer + evidence-gated bare-region detection (SSOT).
//!
//! Loads `data/regions/zh.ron` (GB/T 2260) once and uses it as the dictionary for
//! [`detect_regions_zh`], which finds bare admin-region mentions (北京 / 浦东新区)
//! used as a place a person is associated with, gated on positive evidence so
//! 北京时间 / 北京大学 don't fire. Shared by PyO3 + wasm; feeds the default
//! `remove` strategy for `location`.
use std::collections::HashSet;
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

/// First chars of every gazetteer region name, for a cheap prefilter before the
/// longest-match probe in [`region_candidates`]: a position whose char never
/// starts ANY region name cannot begin a match, so the probe (up to `max_len`
/// substring allocations + lookups) is skipped there. Pure speedup — the set of
/// emitted matches is unchanged. Built once.
fn region_first_chars() -> &'static HashSet<char> {
    static CELL: OnceLock<HashSet<char>> = OnceLock::new();
    CELL.get_or_init(|| {
        region_names_longest_first()
            .iter()
            .filter_map(|n| n.chars().next())
            .collect()
    })
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
    let set = region_name_set();
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
    let first_chars = region_first_chars();
    let max_len = region_max_len();
    let n = chars.len();
    let mut out: Vec<(String, usize, usize)> = Vec::new();

    let mut i = 0;
    while i < n {
        // Prefilter: if chars[i] never starts any region name, no candidate can
        // begin here — skip the (up to max_len) substring probe entirely. Keeps
        // the longest-match result identical; only avoids wasted work (the bulk
        // of any non-region text, e.g. phone/email runs).
        if !first_chars.contains(&chars[i]) {
            i += 1;
            continue;
        }
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
        //
        // Two entity types do NOT corroborate a bare region:
        //   - `self_reference` (我/我们) is whitelisted non-PII; letting it
        //     corroborate makes any `我 … <district>` with no address cue
        //     (`我很喜欢西湖区的风景`) falsely clear the threshold.
        //   - `organization` co-occurs with place names as a matter of course
        //     (`海淀区中关村科技园…`, `我们公司在黄浦区…`); an org being near a
        //     region is NOT evidence the region is a person's address, and the
        //     org span itself frequently mis-segments and leaves a bare region
        //     prefix un-absorbed. Org-near-region alone must not fire L1; a
        //     real address cue or structural suffix still will.
        // Person-identifying PII (phone/person/id/email) still counts.
        for pii in pii_entities {
            if pii.type_ == "self_reference" || pii.type_ == "organization" {
                continue;
            }
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
    for m in out.iter_mut() {
        loop {
            let probe_lo = m.start.saturating_sub(region_max_len());
            let mut absorbed = false;
            for s in probe_lo..m.start {
                let prefix: String = chars[s..m.start].iter().collect();
                if region_name_set().contains(prefix.as_str())
                    || is_suffix_elided_region(&prefix)
                {
                    m.text = chars[s..m.end].iter().collect();
                    m.start = s;
                    absorbed = true;
                    break;
                }
            }
            if !absorbed {
                break;
            }
        }
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
        // still clear the proximity bucket — only self_reference/organization
        // are excluded.
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
