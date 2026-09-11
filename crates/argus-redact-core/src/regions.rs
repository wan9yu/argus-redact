//! Chinese admin-region gazetteer + evidence-gated bare-region detection (SSOT).
//!
//! Loads `data/regions/zh.ron` (GB/T 2260) once and uses it as the dictionary for
//! [`detect_regions_zh`], which finds bare admin-region mentions (北京 / 浦东新区)
//! used as a place a person is associated with, gated on positive evidence so
//! 北京时间 / 北京大学 don't fire. Shared by PyO3 + wasm; feeds the default
//! `remove` strategy for `location`.
use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, OnceLock};

use fancy_regex::Regex;
use serde::Deserialize;

use crate::evidence_detector::{
    build_person_identifying_index, candidates_cjk, context_windows, proximity_evidence,
    DetectorConfig,
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
    let (chars, mut out) = region_candidates_scored(text, pii_entities);

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
    //
    // The leftward walk for one match is a pure function of its start: `m.end`,
    // `chars`, `max_len`, and the name set never change across the matches of one
    // call. So the walk is MEMOISED across matches (`absorb_start`): a degenerate
    // parent chain (`市辖区`×k住, `上海市`×k住) that used to re-probe every
    // prefix from each of its k matches — O(k²) membership probes — now probes
    // each chain position at most once, O(k) total. The memo is allocated lazily
    // on the first emitted match, so a zh document that emits nothing pays no
    // absorption cost. One reused `prefix` buffer serves every probe; `clear`
    // keeps its capacity so no per-probe heap allocation happens.
    let mut prefix = String::with_capacity(region_detector().max_len() * 4);
    let mut memo: Option<HashMap<usize, usize>> = None;
    // Pass 1: slide each match's start left via the memoised walk. `m.end` never
    // moves, so the widened span is always `chars[m.start..m.end]`. Do NOT
    // materialize `m.text` yet.
    for m in out.iter_mut() {
        let memo = memo.get_or_insert_with(HashMap::new);
        m.start = absorb_start(m.start, &chars, region_detector(), &mut prefix, memo);
    }

    // Pass 2 + 3: collapse same-start spans to the longest, then materialize text.
    collapse_to_longest_per_start(&chars, &mut out);

    out
}

/// Collapse region matches that share a start to the single longest (max `end`),
/// then materialize each surviving span's `text` from `chars`.
///
/// A shorter same-start span is fully contained in the longer one and coalesces to
/// it in the downstream overlap merge, so keeping only the longest is
/// output-identical. It is also what bounds allocation: a degenerate parent chain
/// (`市辖区`×k住 / `上海市`×k住) absorbs all k matches to the same start, and
/// materializing every nested prefix `chars[0..3], chars[0..6], …` would be Θ(k²)
/// text — a default-path remote memory-exhaustion vector. Emitting one span per
/// start makes the materialized text O(input). For non-degenerate input no two
/// matches share a start, so the collapse is a no-op there.
///
/// Shared by [`detect_regions_zh`] and its differential-test oracle so the two
/// differ only in the absorption WALK, never in this collapse.
fn collapse_to_longest_per_start(chars: &[char], out: &mut Vec<crate::types::PatternMatch>) {
    let mut max_end: HashMap<usize, usize> = HashMap::new();
    for m in out.iter() {
        let e = max_end.entry(m.start).or_insert(0);
        if m.end > *e {
            *e = m.end;
        }
    }
    let mut kept: HashSet<usize> = HashSet::new();
    out.retain(|m| max_end.get(&m.start) == Some(&m.end) && kept.insert(m.start));
    for m in out.iter_mut() {
        m.text = chars[m.start..m.end].iter().collect();
    }
}

/// The candidate scan + per-candidate evidence gate — everything before
/// parent-prefix absorption. Returns the materialized `chars` (needed by the
/// absorption walk) and the emitted matches with their pre-absorption spans.
/// Split out so the memoised absorption in [`detect_regions_zh`] and the
/// `#[cfg(test)]` naive-absorption oracle share ONE copy of the scoring logic —
/// the absorber is then the only thing that differs between them.
fn region_candidates_scored(
    text: &str,
    pii_entities: &[crate::types::PatternMatch],
) -> (Vec<char>, Vec<crate::types::PatternMatch>) {
    if text.is_empty() {
        return (Vec::new(), Vec::new());
    }

    // Materialize the whole text as a char slice ONCE, then work in char-space
    // — candidate offsets and PatternMatch offsets are char offsets, and a
    // multi-byte CJK window must never be byte-sliced (mirrors person_zh).
    let chars: Vec<char> = text.chars().collect();

    let mut out: Vec<crate::types::PatternMatch> = Vec::new();

    // Build the proximity index ONCE for this invocation (the `is_person_identifying`
    // allowlist gate is applied here), then share it across every candidate.
    let prox_index = build_person_identifying_index(pii_entities.iter());

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
            &prox_index,
            &[
                (REGION_PROX_NEAR, W_REGION_PII_PROX),
                (REGION_PROX_MID, W_REGION_PII_MID),
            ],
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

    (chars, out)
}

// `#[cfg(test)]` probe counter for the absorption walk. Incremented once per
// prefix membership probe (the `name_set().contains` / `is_suffix_elided_region`
// test on one candidate `s`) so a test can assert the walk is linear, not
// quadratic, in the chain length. Compiled out of the release `_core` — the
// counter and every increment live behind `#[cfg(test)]`, so it never exists in
// shipped code and cannot perturb the byte-identical output.
#[cfg(test)]
thread_local! {
    static PROBES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Resolve the leftward parent-prefix absorption for one emitted match, memoised.
///
/// Starting from `m_start`, repeatedly find the SMALLEST preceding position `s`
/// (within `cfg.max_len()` chars) whose `chars[s..p]` is a gazetteer name or a
/// suffix-elided parent, sliding left until no such prefix exists. The final
/// resting start is a pure function of `m_start` — `chars`, `max_len`, and the
/// name set are constant across the matches of one call — so it is memoised: an
/// explicit stack walks from `m_start` to the first already-known or fixed-point
/// position, then every stacked position is back-filled to that final start.
/// Each chain position is therefore probed at most once across all matches of a
/// call, so a degenerate parent chain costs O(k) probes total, not O(k²).
///
/// Iterative, never recursive: the chain depth can be the full candidate count.
/// Byte-identical to the naive per-match walk (same absorption decisions, same
/// final `(text, start, end)`), proven by the `absorb_start_naive` differential
/// oracle fuzz — memoisation only reuses results it would otherwise recompute.
fn absorb_start(
    m_start: usize,
    chars: &[char],
    cfg: &DetectorConfig,
    prefix: &mut String,
    memo: &mut HashMap<usize, usize>,
) -> usize {
    let max_len = cfg.max_len();
    let name_set = cfg.name_set();
    let mut stack: Vec<usize> = Vec::new();
    let mut p = m_start;
    let final_start = loop {
        if let Some(&known) = memo.get(&p) {
            break known;
        }
        let probe_lo = p.saturating_sub(max_len);
        let mut absorbed_to = None;
        for s in probe_lo..p {
            prefix.clear();
            prefix.extend(chars[s..p].iter());
            #[cfg(test)]
            PROBES.with(|c| c.set(c.get() + 1));
            if name_set.contains(prefix.as_str()) || is_suffix_elided_region(prefix.as_str()) {
                absorbed_to = Some(s);
                break;
            }
        }
        stack.push(p);
        match absorbed_to {
            Some(s) => p = s,
            None => break p,
        }
    };
    for &pos in &stack {
        memo.insert(pos, final_start);
    }
    final_start
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
        // widened unit `上海浦东新区` at [3, 9). The memoised absorption walk
        // (`absorb_start`) must reproduce this tuple exactly — same absorption
        // decisions, same `(text, start, end)`.
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
    fn parent_prefix_absorption_chain_emits_one_longest_span() {
        // The degenerate parent-chain. The trailing `住` (residence cue) makes
        // every `上海市` candidate clear evidence, and each absorbs the full chain
        // leftward, stopping at 0 — so all k matches share start 0 with nested
        // ends {3, 6, 9, …}. Materializing every nested prefix's text is Θ(k²) — a
        // default-path remote memory-exhaustion vector (`上海市`×k, under the 1 MiB
        // cap, reachable on a default `redact()`). Only the LONGEST span per start
        // is emitted now: the shorter nested spans are fully contained in it and
        // coalesce to it downstream, so the redacted output and the coalesced
        // report entity are unchanged, while the materialized text is O(input).
        let mut input = "上海市".repeat(3);
        input.push('住');
        let got: Vec<(String, usize, usize)> = detect_regions_zh(&input, &[])
            .into_iter()
            .map(|h| (h.text, h.start, h.end))
            .collect();
        assert_eq!(
            got,
            vec![("上海市上海市上海市".to_string(), 0, 9)],
            "degenerate parent-chain must emit only the longest absorbed span",
        );
    }

    #[test]
    fn parent_prefix_absorption_text_allocation_is_linear() {
        // Allocation gate (the op-count/probe gate cannot see this): the total
        // emitted entity text must stay O(input), not Θ(input²). Pre-fix, a
        // `市辖区`×k住 chain materialized Σ 3·k(k+1)/2 chars; now one span of ≤ input
        // length. Assert total emitted text ≤ input length for a chain that would
        // otherwise be quadratic.
        for k in [200usize, 400, 800] {
            let mut input = "市辖区".repeat(k);
            input.push('住');
            let total: usize = detect_regions_zh(&input, &[])
                .iter()
                .map(|h| h.text.chars().count())
                .sum();
            assert!(
                total <= input.chars().count(),
                "k={k}: total emitted region text {total} exceeds input {} — Θ(k²) allocation regressed",
                input.chars().count(),
            );
        }
    }

    // ── Parent-prefix absorption: memoisation is byte-identical + linear ──

    /// The pre-memoisation absorption walk, verbatim, as a differential oracle.
    /// A single naive left-slide per match with no memo — the exact loop
    /// `detect_regions_zh` carried before memoisation. Increments the same
    /// `PROBES` counter as the production walk, so `naive_absorption_probe_count_is_quadratic`
    /// can pin that the naive path is O(k²) — giving the sub-quadratic gate on the
    /// memoised path its discriminating power.
    fn absorb_start_naive(
        m_start: usize,
        chars: &[char],
        cfg: &DetectorConfig,
        prefix: &mut String,
    ) -> usize {
        let mut start = m_start;
        loop {
            let probe_lo = start.saturating_sub(cfg.max_len());
            let mut absorbed = false;
            for s in probe_lo..start {
                prefix.clear();
                prefix.extend(chars[s..start].iter());
                PROBES.with(|c| c.set(c.get() + 1));
                if cfg.name_set().contains(prefix.as_str())
                    || is_suffix_elided_region(prefix.as_str())
                {
                    start = s;
                    absorbed = true;
                    break;
                }
            }
            if !absorbed {
                break;
            }
        }
        start
    }

    /// `detect_regions_zh` with the naive (un-memoised) absorption walk. Shares
    /// the scoring via `region_candidates_scored`, so the ONLY difference from the
    /// production path is the absorber — making it a faithful differential oracle.
    fn detect_regions_zh_naive(
        text: &str,
        pii_entities: &[crate::types::PatternMatch],
    ) -> Vec<crate::types::PatternMatch> {
        let (chars, mut out) = region_candidates_scored(text, pii_entities);
        let mut prefix = String::with_capacity(region_detector().max_len() * 4);
        for m in out.iter_mut() {
            m.start = absorb_start_naive(m.start, &chars, region_detector(), &mut prefix);
        }
        // Apply the SAME longest-span-per-start collapse as production (the shared
        // helper), so the fuzz compares only the absorption WALK (memoised vs
        // naive), not the collapse — keeping it a faithful differential oracle.
        super::collapse_to_longest_per_start(&chars, &mut out);
        out
    }

    fn spans(hits: &[crate::types::PatternMatch]) -> Vec<(String, usize, usize)> {
        let mut v: Vec<(String, usize, usize)> =
            hits.iter().map(|h| (h.text.clone(), h.start, h.end)).collect();
        v.sort();
        v
    }

    #[test]
    fn absorption_memoised_matches_naive_oracle_fuzz() {
        // Differential oracle: the memoised walk must emit the SAME
        // (text, start, end) set as the naive walk on every input. A hand-rolled
        // xorshift PRNG (fixed seed, fixed iteration count, no crate dep) builds
        // region-ish inputs: dense runs of gazetteer names and admin suffixes
        // (where absorption actually walks) sprinkled with cue chars and noise, so
        // the fuzz exercises real chains, elided parents, and fixed points.
        let name_pool = ["市辖区", "上海市", "广东省", "海淀区", "浦东新区", "深圳市", "北京"];
        let suffix_pool = ['市', '省', '区', '县', '旗', '州', '盟'];
        let noise_pool = ['住', '家', '的', '，', '。', 'x', '路', '号'];

        let mut state: u64 = 0x9E3779B97F4A7C15;
        let mut next = || {
            // xorshift64
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..4000 {
            let len = (next() % 40) as usize;
            let mut input = String::new();
            for _ in 0..len {
                match next() % 10 {
                    0..=5 => input.push_str(name_pool[(next() as usize) % name_pool.len()]),
                    6..=7 => input.push(suffix_pool[(next() as usize) % suffix_pool.len()]),
                    _ => input.push(noise_pool[(next() as usize) % noise_pool.len()]),
                }
            }
            let got = spans(&detect_regions_zh(&input, &[]));
            let want = spans(&detect_regions_zh_naive(&input, &[]));
            assert_eq!(got, want, "memoised absorption diverged from naive on {input:?}");
        }
    }

    fn probes_for_chain(k: usize) -> u64 {
        PROBES.with(|c| c.set(0));
        let input = "市辖区".repeat(k) + "住";
        let _ = detect_regions_zh(&input, &[]);
        PROBES.with(|c| c.get())
    }

    #[test]
    fn regions_absorption_probe_count_is_subquadratic() {
        // Operation-count gate: the absorption walk must be LINEAR in the chain
        // length, not quadratic. `市辖区`×k住 emits k nested matches; a naive walk
        // re-probes ~max_len prefixes from each, O(k²) (ratio ~4× per doubling),
        // while the memoised walk probes each chain position once, O(k) (ratio
        // ~2×). Two consecutive doublings must each stay well under the 3.0
        // midpoint. (Excluded from release: `PROBES` is `#[cfg(test)]`.)
        let k400 = probes_for_chain(400);
        let k800 = probes_for_chain(800);
        let k1600 = probes_for_chain(1600);
        let r1 = k800 as f64 / k400 as f64;
        let r2 = k1600 as f64 / k800 as f64;
        assert!(
            r1 < 3.0 && r2 < 3.0,
            "absorption must be linear: probes(400)={k400} (800)={k800} (1600)={k1600}, \
             ratios {r1:.2}/{r2:.2} (quadratic would be ~4×)"
        );
    }

    fn probes_for_chain_naive(k: usize) -> u64 {
        PROBES.with(|c| c.set(0));
        let input = "市辖区".repeat(k) + "住";
        let _ = detect_regions_zh_naive(&input, &[]);
        PROBES.with(|c| c.get())
    }

    #[test]
    fn naive_absorption_probe_count_is_quadratic() {
        // Pins that the sub-quadratic gate on the MEMOISED path has real
        // discriminating power. The naive (pre-memo) oracle re-probes ~max_len
        // prefixes from each of the k nested matches → O(k²), so doubling k
        // ~quadruples the probe count (analytically ~4×). If the memoisation were
        // reverted, the memoised ratio would flip from ~2× to ~4× and
        // `regions_absorption_probe_count_is_subquadratic` (which asserts < 3.0)
        // would fail. Small k keeps this sub-second in a debug build.
        let n100 = probes_for_chain_naive(100);
        let n200 = probes_for_chain_naive(200);
        let ratio = n200 as f64 / n100 as f64;
        assert!(
            ratio > 3.0,
            "naive absorption must be quadratic: probes(100)={n100} (200)={n200}, \
             ratio {ratio:.2} (linear would be ~2×)"
        );
    }

    #[test]
    fn region_count_is_bounded_for_a_degenerate_chain() {
        // Every `市辖区` in `市辖区`×k住 clears evidence and absorbs left to start 0,
        // so all k candidates share start 0. Only the longest span per start is
        // emitted, so the count is 1 regardless of k — this is what bounds the
        // materialized text to O(input) instead of the Θ(k²) that emitting every
        // nested prefix would cost. The downstream coalesce produced one location
        // entity from the old k-match set anyway, so the redacted output and the
        // report are unchanged.
        for k in [3usize, 20, 100] {
            let input = "市辖区".repeat(k) + "住";
            assert_eq!(
                detect_regions_zh(&input, &[]).len(),
                1,
                "degenerate 市辖区×{k}住 must emit one longest span, not k"
            );
        }
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
