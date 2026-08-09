//! PyO3 binding for `assess_risk`. Rust computes; the Python shim
//! (`pure/risk.assess_risk`) wraps the returned tuple into the frozen
//! `RiskResult` dataclass.

use pyo3::prelude::*;

use argus_redact_core::risk::assess_risk as core_assess_risk;

type RiskTuple = (
    f64,             // score
    String,          // level
    Vec<(String, i64)>, // entities (type, sensitivity) in input order
    Vec<String>,     // reasons
    Vec<String>,     // pipl_articles
    bool,            // gdpr_special_category
    Vec<String>,     // hipaa_categories
    bool,            // gdpr_art10 (appended at the last index — v0.8.10)
);

#[pyfunction]
pub fn assess_risk(entities: Vec<(String, i64)>, lang: &str) -> PyResult<RiskTuple> {
    let out = core_assess_risk(&entities, lang);
    Ok((
        out.score,
        out.level,
        out.entities,
        out.reasons,
        out.pipl_articles,
        out.gdpr_special_category,
        out.hipaa_categories,
        out.gdpr_art10,
    ))
}
