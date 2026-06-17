use pyo3::prelude::*;

// ── zh pool accessors ────────────────────────────────────────────────────────

/// Reserved zh person names pool (order-preserving, matches `RESERVED_PERSON_NAMES`).
#[pyfunction]
pub fn reserved_person_names_zh() -> Vec<String> {
    argus_redact_core::fakers::reserved_person_names_zh().to_vec()
}

/// Zh person-name → pinyin-aliases mapping as an ordered `[(name, aliases)]` list.
/// Order matches `RESERVED_PERSON_NAMES_ALIASES` (keyed on `reserved_person_names`).
#[pyfunction]
pub fn reserved_person_names_aliases_zh() -> Vec<(String, Vec<String>)> {
    argus_redact_core::fakers::reserved_person_names_aliases_zh_ordered()
}

/// Reserved zh city/district/streets triples (matches `RESERVED_CITIES`).
#[pyfunction]
pub fn reserved_cities_zh() -> Vec<(String, String, Vec<String>)> {
    argus_redact_core::fakers::reserved_cities_zh()
        .iter()
        .map(|(c, d, s)| (c.clone(), d.clone(), s.clone()))
        .collect()
}

/// Zh address → en-aliases mapping as an ordered `[((city,district,street), aliases)]` list.
/// Order matches `RESERVED_ADDRESSES_ZH_ALIASES`.
#[pyfunction]
pub fn reserved_addresses_zh_aliases() -> Vec<((String, String, String), Vec<String>)> {
    argus_redact_core::fakers::reserved_addresses_zh_aliases()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Passport prefix pool (matches `PASSPORT_PREFIXES`).
#[pyfunction]
pub fn passport_prefixes_zh() -> Vec<String> {
    argus_redact_core::fakers::passport_prefixes_zh().to_vec()
}

/// Plate special prefix pool (matches `PLATE_SPECIAL_PREFIXES`).
#[pyfunction]
pub fn plate_special_prefixes_zh() -> Vec<String> {
    argus_redact_core::fakers::plate_special_prefixes_zh().to_vec()
}

/// HKID reserved letter (matches `HKID_RESERVED_LETTER`).
#[pyfunction]
pub fn hkid_reserved_letter() -> String {
    argus_redact_core::fakers::hkid_reserved_letter().to_string()
}

/// TWID reserved letter (matches `TWID_RESERVED_LETTER`).
#[pyfunction]
pub fn twid_reserved_letter() -> String {
    argus_redact_core::fakers::twid_reserved_letter().to_string()
}

/// Macau ID reserved lead digit (matches `MACAU_RESERVED_LEAD`).
#[pyfunction]
pub fn macau_reserved_lead() -> String {
    argus_redact_core::fakers::macau_reserved_lead().to_string()
}

/// Taiwan ARC reserved prefix (matches `TWARC_RESERVED_PREFIX`).
#[pyfunction]
pub fn twarc_reserved_prefix() -> String {
    argus_redact_core::fakers::twarc_reserved_prefix().to_string()
}

// ── en pool accessors ────────────────────────────────────────────────────────

/// Reserved en person names pool (order-preserving, matches `RESERVED_PERSON_NAMES_EN`).
#[pyfunction]
pub fn reserved_person_names_en() -> Vec<String> {
    argus_redact_core::fakers::reserved_person_names_en().to_vec()
}

/// En person-name → zh-aliases mapping as an ordered `[(name, aliases)]` list.
/// Order matches `RESERVED_PERSON_NAMES_EN_ALIASES`.
#[pyfunction]
pub fn reserved_person_names_aliases_en() -> Vec<(String, Vec<String>)> {
    argus_redact_core::fakers::reserved_person_names_aliases_en_ordered()
}

/// Reserved en addresses pool (order-preserving, matches `RESERVED_ADDRESSES_EN`).
#[pyfunction]
pub fn reserved_addresses_en() -> Vec<String> {
    argus_redact_core::fakers::reserved_addresses_en().to_vec()
}

/// En address → zh-aliases mapping as an ordered `[(address, aliases)]` list.
/// Order matches `RESERVED_ADDRESSES_EN_ALIASES`.
#[pyfunction]
pub fn reserved_addresses_en_aliases() -> Vec<(String, Vec<String>)> {
    argus_redact_core::fakers::reserved_addresses_en_aliases()
}

// ── person-name pool accessors (zh, RON-backed) ──────────────────────────────

/// Single-char zh surnames as the exact `SURNAMES` string (matches `lang.zh.surnames.SURNAMES`).
#[pyfunction]
pub fn person_surnames_zh() -> String {
    argus_redact_core::person_data::surnames_zh().to_string()
}

/// Zh compound (2-char) surnames pool (matches `lang.zh.surnames.COMPOUND_SURNAMES` as a set).
#[pyfunction]
pub fn person_compound_surnames_zh() -> Vec<String> {
    argus_redact_core::person_data::compound_surnames_zh().to_vec()
}

/// Zh negative dict pool (matches `lang.zh.person._load_negative_dict()` as a set).
#[pyfunction]
pub fn person_not_names_zh() -> Vec<String> {
    argus_redact_core::person_data::not_names_zh().to_vec()
}

/// Zh common-words pool (matches `lang.zh.person._load_common_words()` as a set).
#[pyfunction]
pub fn person_common_words_zh() -> Vec<String> {
    argus_redact_core::person_data::common_words_zh().to_vec()
}

// ── person-name pool accessors (en, RON-backed) ──────────────────────────────

/// En given-names pool (matches `lang.en.given_names.GIVEN_NAME_SET` as a set).
#[pyfunction]
pub fn person_given_names_en() -> Vec<String> {
    argus_redact_core::person_data::given_names_en().to_vec()
}

/// En surnames pool (matches `lang.en.surnames.SURNAME_SET` as a set).
#[pyfunction]
pub fn person_surnames_en() -> Vec<String> {
    argus_redact_core::person_data::surnames_en().to_vec()
}

// ── shared pool accessors ────────────────────────────────────────────────────

/// RFC 2606 reserved email domains pool (matches `RFC2606_DOMAINS`).
#[pyfunction]
pub fn rfc2606_domains() -> Vec<String> {
    argus_redact_core::fakers::rfc2606_domains().to_vec()
}

/// RFC 5737 TEST-NET IPv4 prefix pool (matches `RFC5737_PREFIXES`).
#[pyfunction]
pub fn rfc5737_prefixes() -> Vec<String> {
    argus_redact_core::fakers::rfc5737_prefixes().to_vec()
}

/// RFC 7042 documentation MAC prefix (matches `RFC7042_MAC_PREFIX`).
#[pyfunction]
pub fn rfc7042_mac_prefix() -> String {
    argus_redact_core::fakers::rfc7042_mac_prefix().to_string()
}
