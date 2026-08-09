//! Embedded compliance data for `assess_risk` — generated from the Python
//! registry SSOT (`argus_redact.specs.gen_risk_data`). Parity-gated by
//! `tests/architecture/test_risk_data_parity.py`.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use serde::Deserialize;

/// Resolved per-type compliance metadata (one entry per registered (lang, name)).
#[derive(Debug, Deserialize)]
pub struct ComplianceMeta {
    pub lang: String,
    pub name: String,
    pub pipl_articles: Vec<String>,
    pub gdpr_special_category: bool,
    pub gdpr_art10: bool,
    pub hipaa_phi_category: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RiskData {
    types: Vec<ComplianceMeta>,
    pipl_sensitive_pi: Vec<String>,
    pipl_sort_order: Vec<(String, usize)>,
}

fn risk_data() -> &'static RiskData {
    static CELL: OnceLock<RiskData> = OnceLock::new();
    CELL.get_or_init(|| {
        ron::from_str(include_str!("../data/risk_data.ron"))
            .unwrap_or_else(|e| panic!("RON parse error in data/risk_data.ron: {}", e))
    })
}

/// Resolve compliance metadata the way Python `_lookup_typedef` does: exact
/// `(lang, name)` first, else the first registered entry with that `name`
/// (matching `lookup(name)[0]`; `types` is in registration order).
pub fn compliance_for(lang: &str, type_: &str) -> Option<&'static ComplianceMeta> {
    let types = &risk_data().types;
    types
        .iter()
        .find(|m| m.lang == lang && m.name == type_)
        .or_else(|| types.iter().find(|m| m.name == type_))
}

/// `PIPL_SENSITIVE_PI` as a membership set.
pub fn pipl_sensitive_pi() -> &'static HashSet<String> {
    static CELL: OnceLock<HashSet<String>> = OnceLock::new();
    CELL.get_or_init(|| risk_data().pipl_sensitive_pi.iter().cloned().collect())
}

/// PIPL article → sort rank; unknown articles get 999 (matches
/// `PIPL_SORT_ORDER.get(art, 999)`).
pub fn pipl_sort_rank(article: &str) -> usize {
    static CELL: OnceLock<HashMap<String, usize>> = OnceLock::new();
    let map = CELL.get_or_init(|| risk_data().pipl_sort_order.iter().cloned().collect());
    map.get(article).copied().unwrap_or(999)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_and_resolves() {
        // phone resolves via exact or any-lang fallback and is non-empty.
        let m = compliance_for("zh", "phone");
        assert!(m.is_some(), "phone must resolve");
        assert!(!pipl_sensitive_pi().is_empty());
        assert_eq!(pipl_sort_rank("PIPL Art.13"), 0);
        assert_eq!(pipl_sort_rank("PIPL Art.55"), 4);
        assert_eq!(pipl_sort_rank("nonexistent"), 999);
    }
}
