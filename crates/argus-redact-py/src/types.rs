use pyo3::prelude::*;
use argus_redact_core::PatternMatch as CorePM;

/// A PII match detected by regex pattern. PyO3 wrapper over the pure-core type.
#[pyclass(name = "PatternMatch", frozen, get_all, from_py_object)]
#[derive(Clone)]
pub struct PyPatternMatch {
    pub text: String,
    #[pyo3(name = "type")]
    pub type_: String,
    pub start: usize,
    pub end: usize,
    pub confidence: f64,
    pub layer: u8,
}

impl From<CorePM> for PyPatternMatch {
    fn from(c: CorePM) -> Self {
        Self {
            text: c.text,
            type_: c.type_,
            start: c.start,
            end: c.end,
            confidence: c.confidence,
            layer: c.layer,
        }
    }
}

impl From<&PyPatternMatch> for CorePM {
    fn from(p: &PyPatternMatch) -> Self {
        CorePM {
            text: p.text.clone(),
            type_: p.type_.clone(),
            start: p.start,
            end: p.end,
            confidence: p.confidence,
            layer: p.layer,
        }
    }
}

#[pymethods]
impl PyPatternMatch {
    #[new]
    #[pyo3(signature = (text, type_, start, end, confidence=1.0, layer=0))]
    fn new(text: String, type_: String, start: usize, end: usize, confidence: f64, layer: u8) -> Self {
        Self { text, type_, start, end, confidence, layer }
    }

    fn __repr__(&self) -> String {
        format!(
            "PatternMatch(text='{}', type='{}', start={}, end={}, confidence={}, layer={})",
            self.text, self.type_, self.start, self.end, self.confidence, self.layer
        )
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.text == other.text
            && self.type_ == other.type_
            && self.start == other.start
            && self.end == other.end
    }

    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.text.hash(&mut hasher);
        self.type_.hash(&mut hasher);
        self.start.hash(&mut hasher);
        self.end.hash(&mut hasher);
        hasher.finish()
    }
}
