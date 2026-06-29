use pyo3::prelude::*;

mod types;
mod patterns;
mod merger;
mod restore;
mod pseudonym;
mod lang_detect;
mod normalize;
mod grammar;
mod display_marker;
mod reserved_range;
mod replace;
mod redact_l1;
mod streaming;
mod risk;
mod shake_rng;
mod seed;
mod masks;
mod fakers;
mod pools;
mod person;

/// argus-redact Rust core — high-performance pure functions over argus-redact-core.
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<types::PyPatternMatch>()?;
    m.add_function(wrap_pyfunction!(patterns::match_patterns, m)?)?;
    m.add_function(wrap_pyfunction!(patterns::builtin_patterns, m)?)?;
    m.add_function(wrap_pyfunction!(merger::merge_entities, m)?)?;
    m.add_function(wrap_pyfunction!(merger::merge_entities_with_text, m)?)?;
    m.add_function(wrap_pyfunction!(restore::restore, m)?)?;
    m.add_function(wrap_pyfunction!(restore::check_restore_safety, m)?)?;
    m.add_class::<pseudonym::PyPseudonymGenerator>()?;
    m.add_function(wrap_pyfunction!(lang_detect::detect_languages, m)?)?;
    m.add_function(wrap_pyfunction!(normalize::normalize_text, m)?)?;
    m.add_function(wrap_pyfunction!(normalize::map_spans_to_original, m)?)?;
    m.add_function(wrap_pyfunction!(grammar::normalize_grammar_en, m)?)?;
    m.add_function(wrap_pyfunction!(grammar::restore_grammar_en, m)?)?;
    m.add_function(wrap_pyfunction!(grammar::self_ref_pronouns, m)?)?;
    m.add_function(wrap_pyfunction!(display_marker::mark_for_display, m)?)?;
    m.add_function(wrap_pyfunction!(display_marker::strip_display_markers, m)?)?;
    m.add_function(wrap_pyfunction!(display_marker::resolve_marker, m)?)?;
    m.add_function(wrap_pyfunction!(display_marker::preset_marker_chars, m)?)?;
    m.add_function(wrap_pyfunction!(reserved_range::reserved_range_patterns, m)?)?;
    m.add_function(wrap_pyfunction!(reserved_range::scan_for_pollution, m)?)?;
    m.add_function(wrap_pyfunction!(replace::replace, m)?)?;
    m.add_function(wrap_pyfunction!(replace::build_type_info, m)?)?;
    // ── L1 engine bindings (detect / redact / hints) ──
    m.add_function(wrap_pyfunction!(redact_l1::detect_l1, m)?)?;
    m.add_function(wrap_pyfunction!(redact_l1::redact_l1, m)?)?;
    m.add_function(wrap_pyfunction!(redact_l1::produce_hints_l1, m)?)?;
    m.add_function(wrap_pyfunction!(redact_l1::get_person_threshold, m)?)?;
    m.add_function(wrap_pyfunction!(redact_l1::filter_self_reference, m)?)?;
    // ── streaming carry-window engine bindings ──
    m.add_function(wrap_pyfunction!(streaming::streaming_last_boundary_index, m)?)?;
    m.add_function(wrap_pyfunction!(streaming::streaming_restorer_split, m)?)?;
    m.add_function(wrap_pyfunction!(streaming::streaming_context_cut, m)?)?;
    m.add_function(wrap_pyfunction!(streaming::streaming_emit_possible, m)?)?;
    m.add_function(wrap_pyfunction!(streaming::streaming_unclosed_pem_opener_start, m)?)?;
    m.add_function(wrap_pyfunction!(streaming::streaming_pem_begin_present, m)?)?;
    m.add_function(wrap_pyfunction!(risk::assess_risk, m)?)?;
    m.add_class::<crate::shake_rng::PyShakeRng>()?;
    m.add_function(wrap_pyfunction!(shake_rng::seed_from_value, m)?)?;
    m.add_function(wrap_pyfunction!(seed::resolve_salt, m)?)?;
    m.add_function(wrap_pyfunction!(seed::type_seed_offset, m)?)?;
    m.add_function(wrap_pyfunction!(masks::mask_value, m)?)?;
    m.add_function(wrap_pyfunction!(masks::mask_name, m)?)?;
    m.add_function(wrap_pyfunction!(masks::mask_landline, m)?)?;
    m.add_function(wrap_pyfunction!(masks::resolve_collision, m)?)?;
    m.add_function(wrap_pyfunction!(fakers::generate_unique_fake, m)?)?;
    m.add_function(wrap_pyfunction!(fakers::builtin_faker_name, m)?)?;
    m.add_function(wrap_pyfunction!(fakers::builtin_faker_names, m)?)?;
    // ── pool accessors (zh) ──
    m.add_function(wrap_pyfunction!(pools::reserved_person_names_zh, m)?)?;
    m.add_function(wrap_pyfunction!(pools::reserved_person_names_aliases_zh, m)?)?;
    m.add_function(wrap_pyfunction!(pools::reserved_cities_zh, m)?)?;
    m.add_function(wrap_pyfunction!(pools::reserved_addresses_zh_aliases, m)?)?;
    m.add_function(wrap_pyfunction!(pools::passport_prefixes_zh, m)?)?;
    m.add_function(wrap_pyfunction!(pools::plate_special_prefixes_zh, m)?)?;
    m.add_function(wrap_pyfunction!(pools::hkid_reserved_letter, m)?)?;
    m.add_function(wrap_pyfunction!(pools::twid_reserved_letter, m)?)?;
    m.add_function(wrap_pyfunction!(pools::macau_reserved_lead, m)?)?;
    m.add_function(wrap_pyfunction!(pools::twarc_reserved_prefix, m)?)?;
    // ── pool accessors (en) ──
    m.add_function(wrap_pyfunction!(pools::reserved_person_names_en, m)?)?;
    m.add_function(wrap_pyfunction!(pools::reserved_person_names_aliases_en, m)?)?;
    m.add_function(wrap_pyfunction!(pools::reserved_addresses_en, m)?)?;
    m.add_function(wrap_pyfunction!(pools::reserved_addresses_en_aliases, m)?)?;
    // ── person-name pool accessors (zh) ──
    m.add_function(wrap_pyfunction!(pools::person_surnames_zh, m)?)?;
    m.add_function(wrap_pyfunction!(pools::person_compound_surnames_zh, m)?)?;
    m.add_function(wrap_pyfunction!(pools::person_not_names_zh, m)?)?;
    m.add_function(wrap_pyfunction!(pools::person_common_words_zh, m)?)?;
    // ── person-name pool accessors (en) ──
    m.add_function(wrap_pyfunction!(pools::person_given_names_en, m)?)?;
    m.add_function(wrap_pyfunction!(pools::person_surnames_en, m)?)?;
    m.add_function(wrap_pyfunction!(pools::person_common_words_en, m)?)?;
    // ── cross-layer hint pool accessors ──
    m.add_function(wrap_pyfunction!(pools::hint_kinship_exact, m)?)?;
    m.add_function(wrap_pyfunction!(pools::hint_kinship_prefixes, m)?)?;
    m.add_function(wrap_pyfunction!(pools::hint_command_prefixes, m)?)?;
    m.add_function(wrap_pyfunction!(pools::hint_command_suffixes, m)?)?;
    m.add_function(wrap_pyfunction!(pools::hint_command_patterns, m)?)?;
    // ── pool accessors (shared) ──
    m.add_function(wrap_pyfunction!(pools::rfc2606_domains, m)?)?;
    m.add_function(wrap_pyfunction!(pools::rfc5737_prefixes, m)?)?;
    m.add_function(wrap_pyfunction!(pools::rfc7042_mac_prefix, m)?)?;
    // ── person-name detectors (zh, en) ──
    m.add_function(wrap_pyfunction!(person::detect_person_names_zh, m)?)?;
    m.add_function(wrap_pyfunction!(person::detect_person_names_en, m)?)?;
    m.add_function(wrap_pyfunction!(person::score_person_candidates_en, m)?)?;
    Ok(())
}
