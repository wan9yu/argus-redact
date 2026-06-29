//! argus-redact core — pure-Rust PII detection/redaction primitives.

/// Maximum accepted input size, in bytes. Enforced unconditionally at the Rust
/// core entry points (`match_patterns`, `detect_l1`) so direct `_core.*` callers
/// are capped identically to the Python wrapper (`pure/normalize.py`).
pub const MAX_INPUT_SIZE: usize = 1024 * 1024;

pub mod types;
pub mod merger;
pub mod restore;
pub mod patterns;
pub mod pseudonym;
pub mod mt19937;
pub mod validators;
pub mod data;
pub mod lang_detect;
pub mod normalize;
pub mod confusables;
pub mod grammar;
pub mod display_marker;
pub mod seed;
pub mod masks;
pub mod shake_rng;
pub mod fakers;
pub mod person_data;
pub mod hints_data;
pub mod risk_data;
pub mod risk;
pub mod hints;
pub mod person_zh;
pub mod person_en;
pub mod reserved_range;
pub mod replace;
pub mod typeinfo;
pub mod redact_l1;
pub mod streaming;
pub mod regions;
pub mod occupation;
pub mod evidence_detector;
pub mod conditions;
pub mod hobbies;

pub use types::PatternMatch;
pub use merger::{merge_entities, merge_entities_with_text};
pub use restore::{restore, restore_full, check_restore_safety, RestoreError};
pub use patterns::{match_patterns, PatternConfig, PatternError};
pub use pseudonym::{PseudonymGenerator, RandomSource};
pub use mt19937::{Mt19937, MtRandomSource};
pub use validators::resolve_validator;
pub use data::{builtin_patterns, PatternData};
pub use lang_detect::detect_languages;
pub use normalize::{map_spans_to_original, normalize_text};
pub use grammar::{normalize_grammar_en, restore_grammar_en, is_self_ref, SELF_REF_PRONOUNS};
pub use display_marker::{resolve_marker, mark_for_display, strip_display_markers, PRESET_MARKER_CHARS};
pub use shake_rng::{seed_from_value, ShakeRng};
pub use fakers::{generate_unique_fake, resolve_faker, FakerFn};
pub use person_data::{
    common_words_en, common_words_zh, compound_surnames_zh, given_names_en, not_names_zh,
    surnames_en, surnames_zh,
};
pub use hints_data::{
    command_patterns, command_prefixes, command_suffixes, kinship_exact, kinship_prefixes,
};
pub use hints::{
    filter_self_reference, get_person_threshold, produce_hints_l1, Hint, HintKind,
};
pub use person_zh::SCORE_THRESHOLD;
pub use reserved_range::{scan_for_pollution, reserved_range_patterns};
pub use replace::{replace, FakerFactory, FakerResolution, PseudoFactory, ReplaceArgs, ReplaceResult, TypeInfo};
pub use typeinfo::{build_type_info, Config, EntityConfig};
pub use redact_l1::{detect_l1, redact_l1, DetectL1Result, RedactL1Args};
pub use streaming::{
    context_cut, emit_possible, pem_begin_present,
    last_boundary_index, restorer_split, ContextCut, DetectSpans, EmitResult, RedactSegment,
    RestoreStrategy, StreamingRedactor, StreamingRestorer, CARRY_WINDOW, DEFAULT_MAX_BUFFER,
    EVIDENCE_CONTEXT_WINDOW,
};
