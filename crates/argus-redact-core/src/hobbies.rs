//! Chinese hobby / interest detection — instantiates the shared `evidence_detector`
//! framework, emitting `type="hobby"` (a re-identification quasi-identifier, NOT a
//! regulated PII category). Gated on an interest cue (爱好/喜欢/经常) or PII
//! proximity, so a bare activity word in a non-personal context is left for L2.

use std::sync::{LazyLock, OnceLock};

use fancy_regex::Regex;

use crate::evidence_detector::{detect_with, DetectorConfig, ZhLexicon};
use crate::types::PatternMatch;

static HOBBY_CUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"爱好|喜欢|经常|平时|擅长")
        .unwrap_or_else(|e| panic!("hobbies: cue compile failed: {e}"))
});

fn lexicon() -> &'static Vec<&'static str> {
    static CELL: OnceLock<Vec<&'static str>> = OnceLock::new();
    CELL.get_or_init(|| {
        let data: ZhLexicon = ron::from_str(include_str!("../data/hobbies/zh.ron"))
            .unwrap_or_else(|e| panic!("RON parse error in data/hobbies/zh.ron: {e}"));
        data.terms.into_iter().map(|s| &*Box::leak(s.into_boxed_str())).collect()
    })
}

fn config() -> &'static DetectorConfig {
    static CELL: OnceLock<DetectorConfig> = OnceLock::new();
    CELL.get_or_init(|| DetectorConfig::new(lexicon(), &HOBBY_CUE, "hobby"))
}

pub(crate) fn detect_hobbies_zh(text: &str, pii: &[PatternMatch]) -> Vec<PatternMatch> {
    detect_with(text, pii, config())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_hobby_with_cue() {
        let hits = detect_hobbies_zh("我喜欢攀岩。", &[]);
        assert!(hits.iter().any(|h| h.type_ == "hobby"), "{hits:?}");
    }
    #[test]
    fn skips_bare_term_without_cue() {
        // 篮球 alone (in lexicon, no 喜欢/爱好 cue, no PII) → skip
        let hits = detect_hobbies_zh("篮球比赛很精彩。", &[]);
        assert!(hits.is_empty(), "{hits:?}");
    }
}
