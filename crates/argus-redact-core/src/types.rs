/// A PII match detected by regex pattern. Plain-Rust core type.
#[derive(Clone, Debug, PartialEq)]
pub struct PatternMatch {
    pub text: String,
    pub type_: String,
    pub start: usize,
    pub end: usize,
    pub confidence: f64,
    pub layer: u8,
}
