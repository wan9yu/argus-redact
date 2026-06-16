//! argus-redact core — pure-Rust PII detection/redaction primitives.
pub mod types;
pub mod merger;
pub mod restore;
pub mod patterns;
pub mod pseudonym;
pub mod validators;
pub mod data;
pub mod lang_detect;
pub mod normalize;
pub mod grammar;
pub mod display_marker;
pub mod seed;
pub mod masks;

pub use types::PatternMatch;
pub use merger::merge_entities;
pub use restore::{restore, restore_full, RestoreError};
pub use patterns::{match_patterns, PatternConfig, PatternError};
pub use pseudonym::{PseudonymGenerator, RandomSource};
pub use validators::resolve_validator;
pub use data::{builtin_patterns, PatternData};
pub use lang_detect::detect_languages;
pub use normalize::{map_spans_to_original, normalize_text};
pub use grammar::{normalize_grammar_en, restore_grammar_en, is_self_ref};
pub use display_marker::{resolve_marker, mark_for_display, strip_display_markers, preset_marker_chars};
