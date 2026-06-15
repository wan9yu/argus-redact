//! argus-redact core — pure-Rust PII detection/redaction primitives.
pub mod types;
pub mod merger;
pub mod restore;
pub mod patterns;

pub use types::PatternMatch;
pub use merger::merge_entities;
pub use restore::{restore, RestoreError};
pub use patterns::{match_patterns, PatternConfig, PatternError};
