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
pub mod shake_rng;
pub mod fakers;
pub mod person_data;
pub mod person_zh;
pub mod person_en;
pub mod reserved_range;
pub mod replace;

pub use types::PatternMatch;
pub use merger::merge_entities;
pub use restore::{restore, restore_full, check_restore_safety, RestoreError};
pub use patterns::{match_patterns, PatternConfig, PatternError};
pub use pseudonym::{PseudonymGenerator, RandomSource};
pub use validators::resolve_validator;
pub use data::{builtin_patterns, PatternData};
pub use lang_detect::detect_languages;
pub use normalize::{map_spans_to_original, normalize_text};
pub use grammar::{normalize_grammar_en, restore_grammar_en, is_self_ref, SELF_REF_PRONOUNS};
pub use display_marker::{resolve_marker, mark_for_display, strip_display_markers, PRESET_MARKER_CHARS};
pub use shake_rng::{seed_from_value, ShakeRng};
pub use fakers::{generate_unique_fake, resolve_faker, FakerFn};
pub use person_data::{
    common_words_zh, compound_surnames_zh, given_names_en, not_names_zh, surnames_en, surnames_zh,
};
pub use person_zh::SCORE_THRESHOLD;
pub use reserved_range::{scan_for_pollution, reserved_range_patterns};
pub use replace::{replace, FakerFactory, FakerResolution, PseudoFactory, ReplaceArgs, ReplaceResult, TypeInfo};
