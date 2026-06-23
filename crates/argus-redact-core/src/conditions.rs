//! Chinese health-condition / allergy detection — instantiates the shared
//! `evidence_detector` framework, emitting `type="medical"`. Complements the
//! prefix-trigger medical regex in `data/zh.ron` (患有/确诊/服用<disease>) by
//! covering the SUFFIX-trigger allergy case (对X过敏) + free-text conditions it
//! misses; overlapping spans are deduped by the merger (longer wins).

use std::sync::{LazyLock, OnceLock};

use fancy_regex::Regex;

use crate::evidence_detector::{detect_with, DetectorConfig};
use crate::types::PatternMatch;

static CONDITION_CUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"过敏|患有|确诊|诊断|得了|病史|服用|症状")
        .unwrap_or_else(|e| panic!("conditions: cue compile failed: {e}"))
});

fn config() -> &'static DetectorConfig {
    static CELL: OnceLock<DetectorConfig> = OnceLock::new();
    CELL.get_or_init(|| {
        DetectorConfig::from_ron(include_str!("../data/conditions/zh.ron"), &CONDITION_CUE, "medical")
    })
}

/// Detect Chinese health conditions / allergies, gated on a health cue or PII
/// proximity. Emits `type="medical"`, `layer=1`.
pub(crate) fn detect_conditions_zh(text: &str, pii: &[PatternMatch]) -> Vec<PatternMatch> {
    detect_with(text, pii, config())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_allergy_suffix_trigger() {
        let hits = detect_conditions_zh("我对花生严重过敏。", &[]);
        assert!(hits.iter().any(|h| h.type_ == "medical"), "{hits:?}");
    }
    #[test]
    fn skips_bare_term_without_cue() {
        // 花生 alone (a food, no 过敏/患有 cue) → skip
        let hits = detect_conditions_zh("我喜欢吃花生。", &[]);
        assert!(hits.is_empty(), "{hits:?}");
    }
}
