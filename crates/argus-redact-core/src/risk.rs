//! Privacy-risk scoring — port of `pure/risk.assess_risk`. Pure + deterministic.
//! Compliance metadata is read from [`crate::risk_data`] (generated from the
//! Python registry SSOT). Bit-identity with the Python original is locked by
//! `tests/compliance/test_risk_golden.py`.

use std::collections::BTreeSet;

use crate::risk_data::{compliance_for, pipl_sensitive_pi, pipl_sort_rank};

/// Quasi-identifier combinations that amplify the score (first match wins).
const QUASI_ID_COMBOS: [[&str; 2]; 3] = [
    ["date_of_birth", "address"],
    ["date_of_birth", "phone"],
    ["address", "phone"],
];

/// Self-ref amplifies when combined with PIPL_SENSITIVE_PI ∪ these structural types.
const SELF_REF_EXTRA: [&str; 3] = ["phone", "id_number", "bank_card"];

const PIPL_ART_55: &str = "PIPL Art.55";

fn level_label(sensitivity: i64) -> &'static str {
    match sensitivity {
        1 => "low",
        2 => "medium",
        3 => "high",
        4 => "critical",
        _ => "unknown",
    }
}

/// Python `round(x, 2)`. Reachable scores are always 2-decimal multiples of 0.05
/// (sensitivity/4 ∈ {.0,.25,.5,.75,1.0} plus 0.05-multiple increments), so no true
/// 3rd-decimal tie ever occurs — half-away == half-even here. The golden's cutoff
/// vectors lock this.
fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/// Output of [`assess_risk`]; the Python shim wraps this into the frozen
/// `RiskResult` dataclass.
pub struct RiskOut {
    pub score: f64,
    pub level: String,
    pub entities: Vec<(String, i64)>,
    pub reasons: Vec<String>,
    pub pipl_articles: Vec<String>,
    pub gdpr_special_category: bool,
    pub hipaa_categories: Vec<String>,
}

pub fn assess_risk(entities: &[(String, i64)], lang: &str) -> RiskOut {
    if entities.is_empty() {
        return RiskOut {
            score: 0.0,
            level: "none".to_string(),
            entities: vec![],
            reasons: vec![],
            pipl_articles: vec![],
            gdpr_special_category: false,
            hipaa_categories: vec![],
        };
    }

    let max_sens = entities.iter().map(|(_, s)| *s).max().unwrap();
    let mut score = max_sens as f64 / 4.0;

    let types_found: BTreeSet<&str> = entities.iter().map(|(t, _)| t.as_str()).collect();

    // Reason per unique "type (label)" in first-seen order.
    let mut reasons: Vec<String> = Vec::new();
    for (t, s) in entities {
        let reason = format!("{} ({})", t, level_label(*s));
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }

    // Combination amplification.
    if entities.iter().filter(|(_, s)| *s >= 3).count() >= 2 {
        score += 0.1;
        reasons.push("multiple high/critical entities detected".to_string());
    }

    // Self-reference amplification: self_reference + any sensitive/structural type.
    if types_found.contains("self_reference") {
        let sensitive = pipl_sensitive_pi();
        if types_found
            .iter()
            .any(|t| sensitive.contains(*t) || SELF_REF_EXTRA.contains(t))
        {
            score += 0.15;
            reasons.push(
                "self-reference amplification: PII directly linked to user".to_string(),
            );
        }
    }

    // Quasi-id combo (first match only).
    for combo in QUASI_ID_COMBOS {
        if combo.iter().all(|t| types_found.contains(t)) {
            score += 0.1;
            let mut sorted = combo;
            sorted.sort_unstable();
            reasons.push(format!(
                "quasi-identifier combination: {}",
                sorted.join(" + ")
            ));
            break;
        }
    }

    if score > 1.0 {
        score = 1.0;
    }

    let level = if score < 0.3 {
        "low"
    } else if score < 0.6 {
        "medium"
    } else if score < 0.85 {
        "high"
    } else {
        "critical"
    }
    .to_string();

    // Compliance aggregation.
    let mut pipl_set: BTreeSet<String> = BTreeSet::new();
    let mut gdpr_special = false;
    let mut hipaa_set: BTreeSet<String> = BTreeSet::new();
    for (t, _) in entities {
        if let Some(meta) = compliance_for(lang, t) {
            for art in &meta.pipl_articles {
                pipl_set.insert(art.clone());
            }
            if meta.gdpr_special_category {
                gdpr_special = true;
            }
            if let Some(cat) = &meta.hipaa_phi_category {
                hipaa_set.insert(cat.clone());
            }
        }
    }
    if entities.len() >= 3 {
        pipl_set.insert(PIPL_ART_55.to_string());
    }
    // Sort by PIPL rank (BTreeSet gives a deterministic alpha pre-order; all
    // registry articles have unique ranks, so the result matches Python's sorted).
    let mut pipl_articles: Vec<String> = pipl_set.into_iter().collect();
    pipl_articles.sort_by_key(|a| pipl_sort_rank(a));

    RiskOut {
        score: round2(score),
        level,
        entities: entities.to_vec(),
        reasons,
        pipl_articles,
        gdpr_special_category: gdpr_special,
        hipaa_categories: hipaa_set.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_none() {
        let r = assess_risk(&[], "zh");
        assert_eq!(r.score, 0.0);
        assert_eq!(r.level, "none");
    }

    #[test]
    fn quasi_id_single_bonus() {
        let r = assess_risk(
            &[
                ("date_of_birth".into(), 2),
                ("address".into(), 2),
                ("phone".into(), 3),
            ],
            "zh",
        );
        let combos = r
            .reasons
            .iter()
            .filter(|x| x.starts_with("quasi-identifier combination"))
            .count();
        assert_eq!(combos, 1);
    }
}
