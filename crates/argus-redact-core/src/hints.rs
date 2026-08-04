//! L1 cross-layer hint logic — `pii_density`, `near_miss_format`, `text_intent`,
//! and `self_reference_tier`.
//!
//! Byte-for-byte port of `pure/hints.py`'s `produce_hints` (plus the
//! `get_person_threshold` / `filter_self_reference` consumers). Emission order
//! mirrors Python exactly: `pii_density`, then `near_miss_format` (one per
//! SURVIVING near-miss — a near-miss whose span is already claimed by an accepted
//! entity of a different type is suppressed), then the `text_intent` /
//! `self_reference_tier` decision tree.
//!
//! ## Cross-engine fidelity (Python `re` / `str` ↔ Rust / fancy_regex)
//!
//! Python `str.strip()` and `re`'s `\s` both treat U+001C–U+001F (FS/GS/RS/US)
//! as whitespace; Rust `char::is_whitespace()` and fancy_regex `\s` do NOT.
//! Two fixes keep `is_interaction_command` matching Python on ANY input:
//!
//! 1. The strip uses `py_strip` (NOT `str::trim`), trimming `py_is_space` chars.
//!    `py_is_space` == Python `str.isspace()` over the whole Unicode range; the
//!    only delta vs `char::is_whitespace()` is exactly U+001C–U+001F (verified by
//!    the `py_is_space_matches_python` codepoint sweep below).
//! 2. The command-pattern `\s` is widened to `[\s\x1c-\x1f]` at compile time in
//!    `hints_data::command_patterns` (see `widen_py_whitespace` there).

use crate::hints_data::{
    command_patterns, command_prefixes, command_suffixes, kinship_exact, kinship_prefixes,
};
use crate::types::PatternMatch;

/// Default person-name threshold — mirrors `pure/hints.py::_DEFAULT_PERSON_THRESHOLD`
/// (and `person_zh::SCORE_THRESHOLD`).
const DEFAULT_PERSON_THRESHOLD: f64 = 0.8;

// ── Hint representation ───────────────────────────────────────────────────────

/// The L1 hint kinds. (region=(0,0), source_layer=1 are constant for L1 hints —
/// the PyO3 binding encodes them when mapping to the Python `_types.Hint`.)
#[derive(Clone, Debug, PartialEq)]
pub enum HintKind {
    /// `pii_density`: bucketed count of non-self_reference L1 entities.
    PiiDensity { level: String, count: usize },
    /// `near_miss_format`: a validator-rejected format match (region = span).
    NearMissFormat { original_type: String, text: String, start: usize, end: usize },
    /// `text_intent`: "neutral" | "narrative" | "casual" | "instruction".
    TextIntent { intent: String },
    /// `self_reference_tier`: tier 1/2/3 + whether any self-ref is kinship.
    SelfReferenceTier { tier: u8, has_kinship: bool },
}

/// An L1 cross-layer hint (`pii_density`, `near_miss_format`, `text_intent`, or
/// `self_reference_tier`).
#[derive(Clone, Debug, PartialEq)]
pub struct Hint {
    pub kind: HintKind,
}

// ── Python whitespace fidelity ────────────────────────────────────────────────

/// True for chars Python `str.isspace()` treats as whitespace.
///
/// Equal to `char::is_whitespace()` plus U+001C–U+001F (FS/GS/RS/US) — the only
/// codepoints where Python diverges from Rust (verified by the codepoint sweep in
/// the tests). Used by `py_strip` and conceptually mirrored by the `\s` widening
/// in `hints_data::command_patterns`.
#[inline]
pub(crate) fn py_is_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

/// Python `str.strip()` (no args): trim leading/trailing `py_is_space` chars.
///
/// Deliberately NOT `str::trim()`, which would miss U+001C–U+001F.
pub(crate) fn py_strip(s: &str) -> &str {
    s.trim_matches(py_is_space)
}

/// Python `str.rstrip()` (no args): trim trailing `py_is_space` chars.
///
/// Deliberately NOT `str::trim_end()`, which would miss U+001C–U+001F.
pub(crate) fn py_rstrip(s: &str) -> &str {
    s.trim_end_matches(py_is_space)
}

// ── Predicates ────────────────────────────────────────────────────────────────

/// Port of `_is_kinship`: exact-set membership OR any kinship-prefix `startswith`.
fn is_kinship(text: &str) -> bool {
    if kinship_exact().contains(text) {
        return true;
    }
    kinship_prefixes().iter().any(|p| text.starts_with(p.as_str()))
}

/// Port of `_is_interaction_command`. Short-circuit order: prefixes → suffixes →
/// patterns (exactly mirrors the Python `if/if/return any(...)` structure).
fn is_interaction_command(text: &str) -> bool {
    let stripped = py_strip(text);
    if command_prefixes()
        .iter()
        .any(|p| stripped.starts_with(p.as_str()))
    {
        return true;
    }
    // Python guards with `if _COMMAND_SUFFIXES and any(...)`; the `and` short-circuit
    // is a no-op for matching when the pool is non-empty, but we keep the guard so an
    // empty pool can never spuriously match (it wouldn't anyway). `any` over empty is
    // false, so the explicit emptiness guard is purely defensive parity.
    let suffixes = command_suffixes();
    if !suffixes.is_empty() && suffixes.iter().any(|s| stripped.ends_with(s.as_str())) {
        return true;
    }
    command_patterns()
        .iter()
        .any(|p| p.is_match(stripped).unwrap_or(false))
}

// ── Producer (L1 subset of `produce_hints`) ───────────────────────────────────

/// Produce the L1 hints: `pii_density`, `near_miss_format`, `text_intent`,
/// `self_reference_tier`.
///
/// Exact port of the decision tree in `pure/hints.py::produce_hints`. Emission
/// order is bit-identity-critical: `pii_density` first (always), then one
/// `near_miss_format` per SURVIVING near-miss, then either `text_intent` (no
/// self-refs) or `self_reference_tier` followed by `text_intent`.
///
/// A near-miss is NOT surviving — no hint is emitted for it — when its span
/// overlaps an accepted entity of a DIFFERENT type: the region is already covered
/// by a real detection, so the "near miss" is only the other type's validator
/// disagreeing. Overlap is strict (`e.start < nm.end && nm.start < e.end`), so
/// merely ADJACENT spans (`e.end == nm.start`) keep the hint. A same-type claimer
/// also keeps it — that is one detector disagreeing with itself.
pub fn produce_hints_l1(
    entities: &[PatternMatch],
    text: &str,
    near_misses: &[PatternMatch],
) -> Vec<Hint> {
    let mut hints: Vec<Hint> = Vec::new();

    let self_refs: Vec<&PatternMatch> =
        entities.iter().filter(|e| e.type_ == "self_reference").collect();
    let others_count = entities.len() - self_refs.len();

    // pii_density (always; excludes self_reference).
    let level = if others_count >= 3 {
        "high"
    } else if others_count >= 1 {
        "medium"
    } else {
        "none"
    };
    hints.push(Hint {
        kind: HintKind::PiiDensity {
            level: level.to_string(),
            count: others_count,
        },
    });

    // near_miss_format (one per surviving near-miss) — but a near-miss whose span is
    // already claimed by an ACCEPTED entity of a DIFFERENT type is noise: the region is
    // covered by a real detection, and the "near miss" is only the other type's validator
    // disagreeing. A same-type claimer is NOT suppressed — that is one detector
    // disagreeing with itself, which is worth reporting.
    for nm in near_misses {
        let claimed_by_other_type = entities
            .iter()
            .any(|e| e.type_ != nm.type_ && e.start < nm.end && nm.start < e.end);
        if claimed_by_other_type {
            continue;
        }
        hints.push(Hint {
            kind: HintKind::NearMissFormat {
                original_type: nm.type_.clone(),
                text: nm.text.clone(),
                start: nm.start,
                end: nm.end,
            },
        });
    }

    if self_refs.is_empty() {
        let intent = if others_count > 0 { "narrative" } else { "neutral" };
        hints.push(Hint {
            kind: HintKind::TextIntent {
                intent: intent.to_string(),
            },
        });
        return hints;
    }

    let has_kinship = self_refs.iter().any(|e| is_kinship(&e.text));
    let has_other_pii = others_count > 0;
    let is_command = is_interaction_command(text);

    let tier: u8 = if is_command && !has_kinship && !has_other_pii {
        3
    } else if has_other_pii || has_kinship {
        1
    } else {
        2
    };
    hints.push(Hint {
        kind: HintKind::SelfReferenceTier { tier, has_kinship },
    });

    let intent = if is_command {
        "instruction"
    } else if has_other_pii {
        "narrative"
    } else {
        "casual"
    };
    hints.push(Hint {
        kind: HintKind::TextIntent {
            intent: intent.to_string(),
        },
    });

    hints
}

// ── Consumers ─────────────────────────────────────────────────────────────────

/// Port of `get_person_threshold`. Scans hints; on the first `text_intent`,
/// returns 1.2 for "instruction" or 0.8 for "narrative". Any other intent (or no
/// `text_intent` hint at all) yields the default 0.8.
pub fn get_person_threshold(hints: &[Hint]) -> f64 {
    for h in hints {
        if let HintKind::TextIntent { intent } = &h.kind {
            if intent == "instruction" {
                return 1.2; // effectively suppress most candidates
            } else if intent == "narrative" {
                return DEFAULT_PERSON_THRESHOLD;
            }
            // Other intents ("neutral"/"casual"): the Python loop does NOT return
            // here — it falls through to the trailing default. So do we.
        }
    }
    DEFAULT_PERSON_THRESHOLD
}

/// First `self_reference_tier` hint's tier, if any (port of `_get_self_reference_tier`).
pub(crate) fn get_self_reference_tier(hints: &[Hint]) -> Option<u8> {
    for h in hints {
        if let HintKind::SelfReferenceTier { tier, .. } = &h.kind {
            return Some(*tier);
        }
    }
    None
}

/// Port of `filter_self_reference`. Tier 1 keeps all entities; any other tier
/// (or no tier hint) drops `self_reference` entities.
pub fn filter_self_reference(entities: Vec<PatternMatch>, hints: &[Hint]) -> Vec<PatternMatch> {
    if get_self_reference_tier(hints) == Some(1) {
        return entities; // keep all
    }
    entities
        .into_iter()
        .filter(|e| e.type_ != "self_reference")
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pm(text: &str, type_: &str) -> PatternMatch {
        PatternMatch {
            text: text.to_string(),
            type_: type_.to_string(),
            start: 0,
            end: text.chars().count(),
            confidence: 1.0,
            layer: 0,
        }
    }

    /// Extract (intent, tier, has_kinship) from the produced L1 hints, mirroring
    /// the summarize() helper used against live Python.
    fn summarize(hints: &[Hint]) -> (Option<String>, Option<u8>, Option<bool>) {
        let mut intent = None;
        let mut tier = None;
        let mut has_kinship = None;
        for h in hints {
            match &h.kind {
                HintKind::TextIntent { intent: i } => intent = Some(i.clone()),
                HintKind::SelfReferenceTier { tier: t, has_kinship: k } => {
                    tier = Some(*t);
                    has_kinship = Some(*k);
                }
                HintKind::PiiDensity { .. } | HintKind::NearMissFormat { .. } => {}
            }
        }
        (intent, tier, has_kinship)
    }

    // ── produce_hints_l1 decision tree (expected captured from LIVE Python) ──
    //
    // Each case below was run through `argus_redact.pure.hints.produce_hints`
    // (filtered to text_intent + self_reference_tier). See task notes; the
    // captured values are encoded as the asserts.

    #[test]
    fn no_selfref_no_others_is_neutral() {
        let h = produce_hints_l1(&[], "hello world", &[]);
        assert_eq!(summarize(&h), (Some("neutral".into()), None, None));
        // pii_density + text_intent (no self_reference_tier, no near-misses).
        assert_eq!(h.len(), 2);
        assert!(matches!(h[0].kind, HintKind::PiiDensity { .. }));
    }

    #[test]
    fn no_selfref_with_others_is_narrative() {
        let ents = [pm("555-1234", "phone")];
        let h = produce_hints_l1(&ents, "call 555-1234", &[]);
        assert_eq!(summarize(&h), (Some("narrative".into()), None, None));
        // pii_density + text_intent.
        assert_eq!(h.len(), 2);
        assert!(matches!(h[0].kind, HintKind::PiiDensity { .. }));
    }

    #[test]
    fn selfref_plus_command_is_instruction_tier3() {
        let ents = [pm("me", "self_reference")];
        let h = produce_hints_l1(&ents, "please tell me about it", &[]);
        assert_eq!(summarize(&h), (Some("instruction".into()), Some(3), Some(false)));
        // pii_density + self_reference_tier + text_intent.
        assert_eq!(h.len(), 3);
        assert!(matches!(h[0].kind, HintKind::PiiDensity { .. }));
    }

    #[test]
    fn selfref_plus_other_pii_is_narrative_tier1() {
        let ents = [pm("me", "self_reference"), pm("555-1234", "phone")];
        let h = produce_hints_l1(&ents, "me and the number 555-1234 are here", &[]);
        assert_eq!(summarize(&h), (Some("narrative".into()), Some(1), Some(false)));
    }

    #[test]
    fn selfref_plus_kinship_is_casual_tier1() {
        // "我妈" is in _KINSHIP_EXACT; the text is not a command.
        let ents = [pm("我妈", "self_reference")];
        let h = produce_hints_l1(&ents, "我妈在这里", &[]);
        assert_eq!(summarize(&h), (Some("casual".into()), Some(1), Some(true)));
    }

    #[test]
    fn selfref_pure_is_casual_tier2() {
        let ents = [pm("me", "self_reference")];
        let h = produce_hints_l1(&ents, "just me here", &[]);
        assert_eq!(summarize(&h), (Some("casual".into()), Some(2), Some(false)));
    }

    #[test]
    fn command_with_pii_precedence_instruction_tier1() {
        // command wins → instruction even with other_pii; other_pii → tier 1.
        let ents = [pm("me", "self_reference"), pm("555-1234", "phone")];
        let h = produce_hints_l1(&ents, "please tell me about 555-1234", &[]);
        assert_eq!(summarize(&h), (Some("instruction".into()), Some(1), Some(false)));
    }

    #[test]
    fn kinship_plus_command_zh_is_instruction_tier1() {
        // 请帮我 is a command prefix; 我妈 kinship → command-but-kinship → tier 1.
        let ents = [pm("我妈", "self_reference")];
        let h = produce_hints_l1(&ents, "请帮我找我妈", &[]);
        assert_eq!(summarize(&h), (Some("instruction".into()), Some(1), Some(true)));
    }

    #[test]
    fn command_kinship_no_pii_is_instruction_tier1() {
        // English command + kinship self-ref, no other PII → tier 1 (not 3).
        let ents = [pm("我妈", "self_reference")];
        let h = produce_hints_l1(&ents, "please tell me about 我妈", &[]);
        assert_eq!(summarize(&h), (Some("instruction".into()), Some(1), Some(true)));
    }

    #[test]
    fn all_flags_is_instruction_tier1() {
        let ents = [pm("我妈", "self_reference"), pm("555-1234", "phone")];
        let h = produce_hints_l1(&ents, "请帮我找我妈 555-1234", &[]);
        assert_eq!(summarize(&h), (Some("instruction".into()), Some(1), Some(true)));
    }

    #[test]
    fn kinship_prefix_match() {
        // "my " is a kinship prefix → kinship via startswith.
        let ents = [pm("my brother", "self_reference")];
        let h = produce_hints_l1(&ents, "my brother lives here", &[]);
        let (intent, tier, hk) = summarize(&h);
        assert_eq!((intent, tier, hk), (Some("casual".into()), Some(1), Some(true)));
    }

    #[test]
    fn command_suffix_match_ja() {
        // "してください" is a command suffix; self-ref pure → instruction tier 3.
        let ents = [pm("私", "self_reference")];
        let h = produce_hints_l1(&ents, "それを教えてしてください", &[]);
        let (intent, tier, _) = summarize(&h);
        assert_eq!((intent, tier), (Some("instruction".into()), Some(3)));
    }

    #[test]
    fn multiple_self_refs_kinship_any() {
        // has_kinship is any(...) over self_refs.
        let ents = [pm("me", "self_reference"), pm("我妈", "self_reference")];
        let h = produce_hints_l1(&ents, "我妈 and me here", &[]);
        let (_, tier, hk) = summarize(&h);
        assert_eq!((tier, hk), (Some(1), Some(true)));
    }

    // ── near_miss suppression (mirrors pure/hints.py; see the Python-side tests in
    //    tests/core/test_hint_near_miss_suppression.py) ──

    fn pm_at(text: &str, type_: &str, start: usize) -> PatternMatch {
        PatternMatch {
            text: text.to_string(),
            type_: type_.to_string(),
            start,
            end: start + text.chars().count(),
            confidence: 0.9,
            layer: 1,
        }
    }

    fn near_miss_count(hints: &[Hint]) -> usize {
        hints
            .iter()
            .filter(|h| matches!(h.kind, HintKind::NearMissFormat { .. }))
            .count()
    }

    #[test]
    fn near_miss_suppressed_when_span_claimed_by_another_type() {
        // The en `credit_card` validator rejects a PAN that zh `bank_card` accepts;
        // the region is already covered, so the near-miss is noise.
        let ents = [pm_at("6217000000000001", "bank_card", 3)];
        let nms = [pm_at("6217000000000001", "credit_card", 3)];
        let h = produce_hints_l1(&ents, "卡号 6217000000000001", &nms);
        assert_eq!(near_miss_count(&h), 0);
        // Suppression must not disturb the bit-critical emission order of the rest.
        assert!(matches!(h[0].kind, HintKind::PiiDensity { .. }));
        assert!(matches!(h[1].kind, HintKind::TextIntent { .. }));
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn near_miss_kept_when_nothing_claims_the_span() {
        let nms = [pm_at("110101199003078888", "id_number", 3)];
        let h = produce_hints_l1(&[], "id 110101199003078888", &nms);
        assert_eq!(near_miss_count(&h), 1);
    }

    #[test]
    fn near_miss_kept_when_claimer_is_the_same_type() {
        // Same type = one detector disagreeing with itself; not the case we suppress.
        let ents = [pm_at("110101199003078888", "id_number", 3)];
        let nms = [pm_at("110101199003078888", "id_number", 3)];
        let h = produce_hints_l1(&ents, "id 110101199003078888", &nms);
        assert_eq!(near_miss_count(&h), 1);
    }

    #[test]
    fn near_miss_kept_when_other_type_entity_does_not_overlap() {
        // A different-type entity elsewhere in the text must not suppress it.
        let ents = [pm_at("13800138000", "phone", 0)];
        let nms = [pm_at("110101199003078888", "id_number", 15)];
        let h = produce_hints_l1(&ents, "13800138000 id 110101199003078888", &nms);
        assert_eq!(near_miss_count(&h), 1);
    }

    #[test]
    fn near_miss_kept_when_other_type_entity_merely_touches_the_span() {
        // The boundary case: TOUCHING is not OVERLAPPING. The comparison must stay
        // strict (`<`), never `<=` — an off-by-one there passes every other test in
        // this module while silently swallowing hints next to any adjacent entity.
        let text = "13800138000110101199003078888";
        // e.end == nm.start (entity immediately BEFORE the near-miss).
        let before = [pm_at("13800138000", "phone", 0)];
        let nms = [pm_at("110101199003078888", "id_number", 11)];
        assert_eq!(near_miss_count(&produce_hints_l1(&before, text, &nms)), 1);
        // nm.end == e.start (entity immediately AFTER the near-miss).
        let nms_first = [pm_at("13800138000", "id_number", 0)];
        let after = [pm_at("110101199003078888", "phone", 11)];
        assert_eq!(near_miss_count(&produce_hints_l1(&after, text, &nms_first)), 1);
    }

    // ── get_person_threshold (exact == captured from live Python) ──

    fn ti(intent: &str) -> Hint {
        Hint {
            kind: HintKind::TextIntent {
                intent: intent.to_string(),
            },
        }
    }

    #[test]
    fn person_threshold_instruction_is_1_2() {
        assert_eq!(get_person_threshold(&[ti("instruction")]), 1.2);
    }

    #[test]
    fn person_threshold_narrative_is_0_8() {
        assert_eq!(get_person_threshold(&[ti("narrative")]), 0.8);
    }

    #[test]
    fn person_threshold_neutral_casual_none_is_0_8() {
        assert_eq!(get_person_threshold(&[ti("neutral")]), 0.8);
        assert_eq!(get_person_threshold(&[ti("casual")]), 0.8);
        assert_eq!(get_person_threshold(&[]), 0.8);
        // Non-text_intent-only hint list also falls through to default.
        assert_eq!(
            get_person_threshold(&[Hint {
                kind: HintKind::SelfReferenceTier { tier: 2, has_kinship: false }
            }]),
            0.8
        );
    }

    // ── filter_self_reference (captured from live Python) ──

    fn srt(tier: u8) -> Hint {
        Hint {
            kind: HintKind::SelfReferenceTier { tier, has_kinship: false },
        }
    }

    fn ents_fixture() -> Vec<PatternMatch> {
        vec![pm("me", "self_reference"), pm("555", "phone")]
    }

    #[test]
    fn filter_tier1_keeps_self_reference() {
        let out = filter_self_reference(ents_fixture(), &[srt(1)]);
        let types: Vec<&str> = out.iter().map(|e| e.type_.as_str()).collect();
        assert_eq!(types, vec!["self_reference", "phone"]);
    }

    #[test]
    fn filter_tier2_and_tier3_drop_self_reference() {
        for t in [2u8, 3u8] {
            let out = filter_self_reference(ents_fixture(), &[srt(t)]);
            let types: Vec<&str> = out.iter().map(|e| e.type_.as_str()).collect();
            assert_eq!(types, vec!["phone"], "tier {t} should drop self_reference");
        }
    }

    #[test]
    fn filter_no_tier_hint_drops_self_reference() {
        let out = filter_self_reference(ents_fixture(), &[]);
        let types: Vec<&str> = out.iter().map(|e| e.type_.as_str()).collect();
        assert_eq!(types, vec!["phone"]);
    }

    // ── Cross-engine fidelity sweeps ──

    #[test]
    fn py_is_space_matches_python() {
        // Python `str.isspace()` is True for exactly 29 codepoints; Rust
        // `char::is_whitespace()` is True for 25. The delta is exactly
        // U+001C–U+001F (FS/GS/RS/US). Verify py_is_space == Python over the
        // entire Unicode scalar range, with NO delta beyond those four.
        //
        // The Python truth set (captured via a one-off sweep of
        // `chr(c).isspace()` for c in 0..0x110000):
        const PY_ISSPACE: &[u32] = &[
            0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x001C, 0x001D, 0x001E, 0x001F, 0x0020,
            0x0085, 0x00A0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
            0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
        ];
        let py_set: std::collections::HashSet<u32> = PY_ISSPACE.iter().copied().collect();
        for cp in 0u32..0x110000 {
            if let Some(c) = char::from_u32(cp) {
                assert_eq!(
                    py_is_space(c),
                    py_set.contains(&cp),
                    "py_is_space disagrees with Python str.isspace() at U+{cp:04X}"
                );
            }
        }
        // Spot the FS/GS/RS/US delta vs char::is_whitespace().
        for cp in 0x1Cu32..=0x1F {
            let c = char::from_u32(cp).unwrap();
            assert!(py_is_space(c) && !c.is_whitespace());
        }
    }

    #[test]
    fn py_strip_trims_information_separators() {
        // str::trim() would leave the FS/GS/RS/US in place; py_strip removes them.
        let s = "\u{1c}\u{1d}hello\u{1e}\u{1f}";
        assert_eq!(py_strip(s), "hello");
        // Mixed with ordinary whitespace.
        assert_eq!(py_strip(" \t\u{1f}x\u{1c}\n "), "x");
    }

    #[test]
    fn py_rstrip_trims_trailing_information_separators() {
        // py_rstrip removes trailing FS/GS/RS/US, leaving leading intact.
        assert_eq!(py_rstrip("abc\u{1c}\u{1f}"), "abc");
        // Preserves trailing whitespace on the left side.
        assert_eq!(py_rstrip("  x  "), "  x");
    }

    #[test]
    fn s_class_separator_matches_command_like_python() {
        // The de pattern uses `können\s+Sie`; Python `re` `\s` matches U+001D, so
        // _is_interaction_command("können\u{1d}Sie ...") is True in Python. The
        // widening transform must make is_interaction_command agree.
        assert!(is_interaction_command("können\u{1d}Sie helfen"));
        assert!(is_interaction_command("können Sie helfen")); // ordinary space too
    }

    #[test]
    fn b_boundary_zh_no_spurious_command_match() {
        // The en/de/br/in_ command patterns target ASCII-word phrases via `\b`.
        // fancy_regex `\b` could differ from Python `re` `\b` on CJK boundaries;
        // a plain zh sentence must NOT spuriously match any command pattern.
        // (Live Python: _is_interaction_command(zh) == False.)
        assert!(!is_interaction_command("这是一段中文测试文本没有命令"));
        // Also via the public path: produce_hints over a kinship self-ref in zh
        // narrative stays casual (no spurious instruction).
        let ents = [pm("我妈", "self_reference")];
        let h = produce_hints_l1(&ents, "我妈在这里没有任何命令词", &[]);
        let (intent, _, _) = summarize(&h);
        assert_eq!(intent, Some("casual".into()));
    }
}
