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
