//! argus-redact core — pure-Rust PII detection/redaction primitives.
pub mod types;
pub mod merger;
pub mod restore;
pub mod patterns;
pub mod pseudonym;
pub mod validators;
pub mod data;

pub use types::PatternMatch;
pub use merger::merge_entities;
pub use restore::{restore, RestoreError};
pub use patterns::{match_patterns, PatternConfig, PatternError};
pub use pseudonym::{PseudonymGenerator, RandomSource};
pub use validators::resolve_validator;
pub use data::{builtin_patterns, PatternData};
