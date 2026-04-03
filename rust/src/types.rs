use pyo3::prelude::*;

/// A PII match detected by regex pattern.
#[pyclass(frozen, get_all)]
#[derive(Clone, Debug)]
pub struct PatternMatch {
    pub text: String,
    #[pyo3(name = "type")]
    pub type_: String,
    pub start: usize,
    pub end: usize,
    pub confidence: f64,
    pub layer: u8,
}

#[pymethods]
impl PatternMatch {
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
