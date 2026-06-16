//! Reserved-range realistic fakers, ported 1:1 from `specs/fakers_{zh,en,shared}_reserved.py`
//! and `specs/fakers_numeric.py`.
//!
//! ## Bit-identity contract
//!
//! The realistic strategy derives every fake value from a [`ShakeRng`] stream
//! keyed by `HMAC-SHA256(salt, "{type}:{value}")`. A faker that calls `rng` in a
//! different order — or with different ranges / digit counts — produces a
//! different byte consumption and therefore a different value AND a different
//! downstream stream. So each generator below replays the Python generator's
//! exact RNG-call sequence:
//!
//! - `rand_digits(n)` = `n ×` `randint(0, 9)` (each digit one call).
//! - `choice(seq)` = `seq[choice_index(len)]` (`choice_index` = `randint(0, len-1)`).
//! - check digits reuse the v0.7.1 [`crate::validators`] helpers — never re-ported.
//!
//! The per-faker golden tests at the bottom are the gate: each `(fake, aliases)`
//! is frozen from current Python for a fixed seed, and the Rust faker (seeded
//! identically) MUST reproduce it byte-for-byte. A divergence means the RNG order
//! is wrong — fix the Rust, never the golden.

use std::collections::HashMap;
use std::sync::OnceLock;

use fancy_regex::Regex;
use serde::Deserialize;

use crate::shake_rng::{seed_from_value, ShakeRng};
use crate::validators::{gb11643_check_char, hkid_check_digit, luhn_check_digit, twid_check_digit};

/// Max re-roll attempts in [`generate_unique_fake`] (mirrors `_MAX_REROLL_ATTEMPTS`).
pub const MAX_REROLL_ATTEMPTS: usize = 10;

// ── Pool data (embedded RON, parsed once) ───────────────────────────────────

#[derive(Debug, Deserialize)]
struct ZhFakerData {
    reserved_person_names: Vec<String>,
    reserved_person_names_aliases: HashMap<String, Vec<String>>,
    reserved_cities: Vec<(String, String, Vec<String>)>,
    reserved_addresses_zh_aliases: Vec<((String, String, String), Vec<String>)>,
    passport_prefixes: Vec<String>,
    plate_special_prefixes: Vec<String>,
    hkid_reserved_letter: String,
    twid_reserved_letter: String,
    macau_reserved_lead: String,
    twarc_reserved_prefix: String,
}

#[derive(Debug, Deserialize)]
struct EnFakerData {
    reserved_person_names_en: Vec<String>,
    reserved_person_names_en_aliases: HashMap<String, Vec<String>>,
    reserved_addresses_en: Vec<String>,
    reserved_addresses_en_aliases: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct SharedFakerData {
    rfc2606_domains: Vec<String>,
    rfc5737_prefixes: Vec<String>,
    rfc7042_mac_prefix: String,
}

fn zh_data() -> &'static ZhFakerData {
    static DATA: OnceLock<ZhFakerData> = OnceLock::new();
    DATA.get_or_init(|| {
        ron::from_str(include_str!("../data/fakers/zh.ron"))
            .unwrap_or_else(|e| panic!("RON parse error in fakers/zh.ron: {e}"))
    })
}

fn en_data() -> &'static EnFakerData {
    static DATA: OnceLock<EnFakerData> = OnceLock::new();
    DATA.get_or_init(|| {
        ron::from_str(include_str!("../data/fakers/en.ron"))
            .unwrap_or_else(|e| panic!("RON parse error in fakers/en.ron: {e}"))
    })
}

fn shared_data() -> &'static SharedFakerData {
    static DATA: OnceLock<SharedFakerData> = OnceLock::new();
    DATA.get_or_init(|| {
        ron::from_str(include_str!("../data/fakers/shared.ron"))
            .unwrap_or_else(|e| panic!("RON parse error in fakers/shared.ron: {e}"))
    })
}

// ── Public pool accessors (used by reserved_range.rs scanner) ───────────────

/// Reserved zh person names pool (order-preserving).
pub fn reserved_person_names_zh() -> &'static [String] {
    &zh_data().reserved_person_names
}

/// Reserved en person names pool.
pub fn reserved_person_names_en() -> &'static [String] {
    &en_data().reserved_person_names_en
}

/// Reserved en addresses pool.
pub fn reserved_addresses_en() -> &'static [String] {
    &en_data().reserved_addresses_en
}

/// Reserved city/district tuples: `(city, district, streets)`.
pub fn reserved_cities_zh() -> &'static [(String, String, Vec<String>)] {
    &zh_data().reserved_cities
}

/// HKID reserved letter (single char, e.g. `"Z"`).
pub fn hkid_reserved_letter() -> &'static str {
    &zh_data().hkid_reserved_letter
}

/// TWID reserved letter (single char, e.g. `"W"`).
pub fn twid_reserved_letter() -> &'static str {
    &zh_data().twid_reserved_letter
}

/// Macau ID reserved lead digit (single char, e.g. `"9"`).
pub fn macau_reserved_lead() -> &'static str {
    &zh_data().macau_reserved_lead
}

/// Taiwan ARC reserved prefix (e.g. `"WW"`).
pub fn twarc_reserved_prefix() -> &'static str {
    &zh_data().twarc_reserved_prefix
}

/// The faker function signature: `(original_value, rng) -> (fake, aliases)`.
pub type FakerFn = fn(&str, &mut ShakeRng) -> (String, Vec<String>);

// ── zh fakers ────────────────────────────────────────────────────────────────

/// `fake_phone_reserved` — `"19999"` + `rand_digits(6)`.
pub fn fake_phone_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    (format!("19999{}", rng.rand_digits(6)), vec![])
}

/// `fake_phone_landline_reserved` — `"099-"` + `rand_digits(8)`.
pub fn fake_phone_landline_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    (format!("099-{}", rng.rand_digits(8)), vec![])
}

/// `fake_id_number_reserved` — `"999"`+`rand_digits(3)`, year[1960,2005], month[1,12],
/// day[1,28], seq[0,999] (zero-padded), then the GB 11643 check char.
pub fn fake_id_number_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let area = format!("999{}", rng.rand_digits(3));
    let year = rng.randint(1960, 2005);
    let month = rng.randint(1, 12);
    let day = rng.randint(1, 28);
    let seq = rng.randint(0, 999);
    let body = format!("{area}{year}{month:02}{day:02}{seq:03}");
    let check = gb11643_check_char(&body);
    (format!("{body}{check}"), vec![])
}

/// `fake_bank_card_reserved` — `"999999"` + `rand_digits(9)` + Luhn check digit.
pub fn fake_bank_card_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let body = format!("999999{}", rng.rand_digits(9));
    let check = luhn_check_digit(&body);
    (format!("{body}{check}"), vec![])
}

/// `fake_passport_reserved` — `choice(PASSPORT_PREFIXES)` + `"99999"` + `rand_digits(3)`.
pub fn fake_passport_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let prefixes = &zh_data().passport_prefixes;
    let prefix = &prefixes[rng.choice_index(prefixes.len())];
    let serial = rng.rand_digits(3);
    (format!("{prefix}99999{serial}"), vec![])
}

/// `fake_license_plate_reserved` — `choice(PLATE_SPECIAL_PREFIXES)` +
/// `choice(ascii_uppercase)` + `"99999"`.
pub fn fake_license_plate_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let prefixes = &zh_data().plate_special_prefixes;
    let prefix = &prefixes[rng.choice_index(prefixes.len())];
    let letter = char::from(b'A' + rng.choice_index(26) as u8);
    (format!("{prefix}{letter}99999"), vec![])
}

/// `fake_address_reserved` — `choice(RESERVED_CITIES)` → `choice(streets)` →
/// `randint(1, 999)`. Aliases are the en transliterations with the number prepended.
pub fn fake_address_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let data = zh_data();
    let (city, district, streets) = &data.reserved_cities[rng.choice_index(data.reserved_cities.len())];
    let street = &streets[rng.choice_index(streets.len())];
    let num = rng.randint(1, 999);
    let fake = format!("{city}{district}{street}{num}号");
    let key = (city.clone(), district.clone(), street.clone());
    let base = data
        .reserved_addresses_zh_aliases
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_slice())
        .unwrap_or(&[]);
    let aliases = base.iter().map(|a| format!("{num} {a}")).collect();
    (fake, aliases)
}

/// `fake_person_reserved` — `choice(RESERVED_PERSON_NAMES)` + its pinyin aliases.
pub fn fake_person_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let data = zh_data();
    let fake = &data.reserved_person_names[rng.choice_index(data.reserved_person_names.len())];
    let aliases = data
        .reserved_person_names_aliases
        .get(fake)
        .cloned()
        .unwrap_or_default();
    (fake.clone(), aliases)
}

/// `fake_hkid_reserved` — `Z` letter + `rand_digits(6)` + HKID check char.
pub fn fake_hkid_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let letter = &zh_data().hkid_reserved_letter;
    let digits = rng.rand_digits(6);
    let check = hkid_check_digit(letter, &digits);
    (format!("{letter}{digits}({check})"), vec![])
}

/// `fake_twid_reserved` — `W` letter + `rand_digits(8)` + TWID check digit.
pub fn fake_twid_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let letter = &zh_data().twid_reserved_letter;
    let digits = rng.rand_digits(8);
    let lc = letter.chars().next().expect("twid letter is one char");
    let check = twid_check_digit(lc, &digits);
    (format!("{letter}{digits}{check}"), vec![])
}

/// `fake_macau_id_reserved` — `"9/"` + `rand_digits(6)` + `"/"` + `randint(0,9)`.
pub fn fake_macau_id_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let lead = &zh_data().macau_reserved_lead;
    let body = rng.rand_digits(6);
    let check = rng.randint(0, 9);
    (format!("{lead}/{body}/{check}"), vec![])
}

/// `fake_taiwan_arc_reserved` — `"WW"` + `rand_digits(8)`.
pub fn fake_taiwan_arc_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let prefix = &zh_data().twarc_reserved_prefix;
    (format!("{prefix}{}", rng.rand_digits(8)), vec![])
}

// ── en fakers ────────────────────────────────────────────────────────────────

/// `fake_phone_en_reserved` — `(555) 555-01XX`, `XX` = `randint(0, 99)` zero-padded.
pub fn fake_phone_en_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let last_two = rng.randint(0, 99);
    (format!("(555) 555-01{last_two:02}"), vec![])
}

/// `fake_ssn_en_reserved` — `999-GG-SSSS`, group = `randint(1, 99)`, serial = `randint(1, 9999)`.
pub fn fake_ssn_en_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let group = rng.randint(1, 99);
    let serial = rng.randint(1, 9999);
    (format!("999-{group:02}-{serial:04}"), vec![])
}

/// `fake_credit_card_en_reserved` — `"999999"` + `rand_digits(9)` + Luhn check digit.
pub fn fake_credit_card_en_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let body = format!("999999{}", rng.rand_digits(9));
    let check = luhn_check_digit(&body);
    (format!("{body}{check}"), vec![])
}

/// `fake_person_en_reserved` — `choice(RESERVED_PERSON_NAMES_EN)` + zh aliases.
pub fn fake_person_en_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let data = en_data();
    let fake = &data.reserved_person_names_en[rng.choice_index(data.reserved_person_names_en.len())];
    let aliases = data
        .reserved_person_names_en_aliases
        .get(fake)
        .cloned()
        .unwrap_or_default();
    (fake.clone(), aliases)
}

/// `fake_address_en_reserved` — `choice(RESERVED_ADDRESSES_EN)` + zh aliases.
pub fn fake_address_en_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let data = en_data();
    let fake = &data.reserved_addresses_en[rng.choice_index(data.reserved_addresses_en.len())];
    let aliases = data
        .reserved_addresses_en_aliases
        .get(fake)
        .cloned()
        .unwrap_or_default();
    (fake.clone(), aliases)
}

// ── shared fakers ──────────────────────────────────────────────────────────

/// `fake_email_reserved` — `user{randint(1000, 99999)}@{choice(RFC2606_DOMAINS)}`.
pub fn fake_email_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let local = rng.randint(1000, 99999);
    let domains = &shared_data().rfc2606_domains;
    let domain = &domains[rng.choice_index(domains.len())];
    (format!("user{local}@{domain}"), vec![])
}

/// `fake_ip_reserved` — IPv6 input (contains `:`) → `2001:db8::{randint(1,0xffff):x}`;
/// IPv4 → `{choice(RFC5737_PREFIXES)}.{randint(1, 254)}`.
///
/// NOTE the branch is chosen by the *input* value's shape, then the RNG is
/// called — so the byte consumption differs by branch, exactly like Python.
pub fn fake_ip_reserved(value: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    if value.contains(':') {
        let suffix = rng.randint(1, 0xFFFF);
        (format!("2001:db8::{suffix:x}"), vec![])
    } else {
        let prefixes = &shared_data().rfc5737_prefixes;
        let prefix = &prefixes[rng.choice_index(prefixes.len())];
        let last = rng.randint(1, 254);
        (format!("{prefix}.{last}"), vec![])
    }
}

/// `fake_mac_reserved` — `{RFC7042_MAC_PREFIX}:{randint(0, 255):02X}`.
pub fn fake_mac_reserved(_v: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let last_byte = rng.randint(0, 255);
    (format!("{}:{last_byte:02X}", shared_data().rfc7042_mac_prefix), vec![])
}

// ── numeric range-noise fakers ───────────────────────────────────────────────

const AGE_BAND: i64 = 5;
const AGE_FLOOR: i64 = 0;
const AGE_CEILING: i64 = 149;
const DOB_BAND_DAYS: i64 = 30;

static AGE_DIGITS_RE: OnceLock<Regex> = OnceLock::new();
fn age_digits_re() -> &'static Regex {
    AGE_DIGITS_RE.get_or_init(|| Regex::new(r"\d+").unwrap())
}

/// `fake_age_noise` — shift the first embedded integer by `randint(-5, 5)` (re-rolled
/// to ±1 when zero), clamped to `[0, 149]`. Returns the input unchanged if no digit.
///
/// `delta == 0 -> choice((-1, 1))` = `(-1, 1)[choice_index(2)]`, matching `_ShakeRng.choice`.
pub fn fake_age_noise(value: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let m = match age_digits_re().find(value) {
        Ok(Some(m)) => m,
        _ => return (value.to_string(), vec![]),
    };
    let original: i64 = match m.as_str().parse() {
        Ok(n) => n,
        // Overflow on an absurdly long digit run: Python would raise; in practice the
        // age regex caps the value far below i64. Fall back to identity to stay safe.
        Err(_) => return (value.to_string(), vec![]),
    };
    let mut delta = rng.randint(-AGE_BAND, AGE_BAND);
    if delta == 0 {
        delta = [-1, 1][rng.choice_index(2)];
    }
    let shifted = (original + delta).clamp(AGE_FLOOR, AGE_CEILING);
    let out = format!("{}{}{}", &value[..m.start()], shifted, &value[m.end()..]);
    (out, vec![])
}

/// One of the three `date_of_birth` formats Python recognizes, with named-group offsets.
struct DobMatch {
    start: usize,
    end: usize,
    year: i64,
    month: u32,
    day: u32,
    pat_index: usize,
    suffix: String, // group("suffix") for pat 0; "" otherwise
    sep: String,    // group("sep") for pat 1; "" otherwise
}

static DOB_PATTERNS: OnceLock<[Regex; 3]> = OnceLock::new();
fn dob_patterns() -> &'static [Regex; 3] {
    DOB_PATTERNS.get_or_init(|| {
        [
            Regex::new(r"(?P<y>\d{4})年(?P<m>\d{1,2})月(?P<d>\d{1,2})(?P<suffix>[日号])").unwrap(),
            Regex::new(r"(?P<y>\d{4})(?P<sep>[-/.])(?P<m>\d{1,2})[-/.](?P<d>\d{1,2})").unwrap(),
            Regex::new(r"(?P<m>\d{1,2})/(?P<d>\d{1,2})/(?P<y>\d{4})").unwrap(),
        ]
    })
}

fn first_dob_match(value: &str) -> Option<DobMatch> {
    for (pat_index, pat) in dob_patterns().iter().enumerate() {
        if let Ok(Some(caps)) = pat.captures(value) {
            let whole = caps.get(0).unwrap();
            let g = |name: &str| caps.name(name).map(|m| m.as_str().to_string());
            return Some(DobMatch {
                start: whole.start(),
                end: whole.end(),
                year: g("y").unwrap().parse().unwrap(),
                month: g("m").unwrap().parse().unwrap(),
                day: g("d").unwrap().parse().unwrap(),
                pat_index,
                suffix: g("suffix").unwrap_or_default(),
                sep: g("sep").unwrap_or_default(),
            });
        }
    }
    None
}

/// `fake_date_of_birth_noise` — shift the first recognized date by `randint(-30, 30)`
/// (re-rolled to ±7 when zero), preserving the original format. Identity if no match
/// or the components don't form a valid date.
pub fn fake_date_of_birth_noise(value: &str, rng: &mut ShakeRng) -> (String, Vec<String>) {
    let m = match first_dob_match(value) {
        Some(m) => m,
        None => return (value.to_string(), vec![]),
    };
    // Mirror Python's `date(...)` ValueError → identity (e.g. month=13, day=32).
    let ordinal = match ymd_to_ordinal(m.year, m.month, m.day) {
        Some(o) => o,
        None => return (value.to_string(), vec![]),
    };
    let mut delta = rng.randint(-DOB_BAND_DAYS, DOB_BAND_DAYS);
    if delta == 0 {
        delta = [-7, 7][rng.choice_index(2)];
    }
    let (sy, sm, sd) = ordinal_to_ymd(ordinal + delta);
    let new_text = match m.pat_index {
        0 => format!("{sy:04}年{sm}月{sd}{}", m.suffix),
        1 => format!("{sy:04}{0}{sm:02}{0}{sd:02}", m.sep),
        _ => format!("{sm:02}/{sd:02}/{sy:04}"),
    };
    let out = format!("{}{}{}", &value[..m.start], new_text, &value[m.end..]);
    (out, vec![])
}

// ── Proleptic Gregorian date arithmetic (no chrono dep) ──────────────────────
// Mirrors Python `datetime.date` + `timedelta(days=...)`. We convert (y,m,d) to a
// day ordinal, add the delta, and convert back — same result as `date + timedelta`.

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => if is_leap(year) { 29 } else { 28 },
        _ => 0,
    }
}

/// Days since a fixed epoch (proleptic Gregorian). Returns `None` for invalid dates,
/// mirroring Python `date()` raising `ValueError`.
fn ymd_to_ordinal(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    // Days before this year (proleptic Gregorian, from year 1).
    let y = year - 1;
    let mut days = y * 365 + y / 4 - y / 100 + y / 400;
    // Cumulative days before each month in a non-leap year.
    const CUM: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    days += CUM[(month - 1) as usize];
    if month > 2 && is_leap(year) {
        days += 1;
    }
    days += day as i64;
    Some(days)
}

fn ordinal_to_ymd(mut ordinal: i64) -> (i64, u32, u32) {
    // Estimate the year, then correct. Inverse of `ymd_to_ordinal`.
    let mut year = 1 + (ordinal - 1) * 400 / 146097;
    while ymd_to_ordinal(year + 1, 1, 1).unwrap() <= ordinal {
        year += 1;
    }
    while ymd_to_ordinal(year, 1, 1).unwrap() > ordinal {
        year -= 1;
    }
    ordinal -= ymd_to_ordinal(year, 1, 1).unwrap() - 1; // day-of-year (1-based)
    let mut month = 1u32;
    while ordinal > days_in_month(year, month) as i64 {
        ordinal -= days_in_month(year, month) as i64;
        month += 1;
    }
    (year, month, ordinal as u32)
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

/// Resolve a faker by its registry function name (e.g. `"fake_phone_reserved"`).
///
/// The function name is globally unique, so it disambiguates the zh/en same-named
/// types (`phone`/`person`/`address`) that the Python registry resolves via the
/// `(name, lang)` lookup in `_find_faker_reserved`. The T9 orchestrator does that
/// `(type, lang)` resolution and passes the resolved function name into Rust.
pub fn resolve_faker(name: &str) -> Option<FakerFn> {
    Some(match name {
        // zh
        "fake_phone_reserved" => fake_phone_reserved,
        "fake_phone_landline_reserved" => fake_phone_landline_reserved,
        "fake_id_number_reserved" => fake_id_number_reserved,
        "fake_bank_card_reserved" => fake_bank_card_reserved,
        "fake_passport_reserved" => fake_passport_reserved,
        "fake_license_plate_reserved" => fake_license_plate_reserved,
        "fake_address_reserved" => fake_address_reserved,
        "fake_person_reserved" => fake_person_reserved,
        "fake_hkid_reserved" => fake_hkid_reserved,
        "fake_twid_reserved" => fake_twid_reserved,
        "fake_macau_id_reserved" => fake_macau_id_reserved,
        "fake_taiwan_arc_reserved" => fake_taiwan_arc_reserved,
        // en
        "fake_phone_en_reserved" => fake_phone_en_reserved,
        "fake_ssn_en_reserved" => fake_ssn_en_reserved,
        "fake_credit_card_en_reserved" => fake_credit_card_en_reserved,
        "fake_address_en_reserved" => fake_address_en_reserved,
        "fake_person_en_reserved" => fake_person_en_reserved,
        // shared
        "fake_email_reserved" => fake_email_reserved,
        "fake_ip_reserved" => fake_ip_reserved,
        "fake_mac_reserved" => fake_mac_reserved,
        // numeric
        "fake_age_noise" => fake_age_noise,
        "fake_date_of_birth_noise" => fake_date_of_birth_noise,
        _ => return None,
    })
}

/// Re-roll a fake until it is unique within `used ∪ {value}`, mirroring
/// `_generate_unique_fake` (replacer.py:224–255).
///
/// Each attempt re-seeds with `seed_from_value(seed_input, type_, salt)` → a fresh
/// [`ShakeRng`] → the faker. On collision the seed input is suffixed `#{attempt}`.
/// Rejecting the input value itself is the identity-pass guard. Errors after
/// [`MAX_REROLL_ATTEMPTS`] attempts.
pub fn generate_unique_fake(
    faker: FakerFn,
    value: &str,
    type_: &str,
    salt: &[u8],
    used: &std::collections::HashSet<String>,
) -> Result<(String, Vec<String>), String> {
    let mut seed_input = value.to_string();
    let mut last: Option<String> = None;
    for attempt in 0..MAX_REROLL_ATTEMPTS {
        let master_key = seed_from_value(&seed_input, type_, salt);
        let mut rng = ShakeRng::new(&master_key);
        let (fake, aliases) = faker(value, &mut rng);
        // Reject identity-pass (fake == value) AND any already-used fake.
        if fake != value && !used.contains(&fake) {
            return Ok((fake, aliases));
        }
        last = Some(fake);
        seed_input = format!("{seed_input}#{attempt}");
    }
    Err(format!(
        "Could not generate unique fake for {type_} after {MAX_REROLL_ATTEMPTS} attempts (last: {last:?})"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seed a faker exactly as the orchestrator would: `seed_from_value(value, type_, salt)`
    /// with `salt = bytes(8)`, then a fresh `ShakeRng`. Returns `(fake, aliases)`.
    fn run(faker: FakerFn, value: &str, type_: &str) -> (String, Vec<String>) {
        let seed = seed_from_value(value, type_, &[0u8; 8]);
        let mut rng = ShakeRng::new(&seed);
        faker(value, &mut rng)
    }

    fn als(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // ── Per-faker golden vectors ─────────────────────────────────────────────
    // FROZEN from current Python via:
    //   PYTHONPATH=src python3 -c "
    //   from argus_redact.pure.replacer import _ShakeRng, _seed_from_value
    //   from argus_redact.specs.fakers_* import ...
    //   rng=_ShakeRng(_seed_from_value(value, type_, bytes(8))); print(fn(value, rng))"
    // These are the bit-identity gate. A mismatch means the Rust RNG-call order is
    // wrong — fix the Rust, never the golden.

    #[test]
    fn golden_zh() {
        assert_eq!(run(fake_phone_reserved, "x", "phone"), ("19999173357".into(), vec![]));
        assert_eq!(run(fake_phone_landline_reserved, "x", "phone_landline"), ("099-99825000".into(), vec![]));
        assert_eq!(run(fake_id_number_reserved, "x", "id_number"), ("999905198911095800".into(), vec![]));
        assert_eq!(run(fake_bank_card_reserved, "x", "bank_card"), ("9999998048759129".into(), vec![]));
        assert_eq!(run(fake_passport_reserved, "x", "passport"), ("G99999765".into(), vec![]));
        assert_eq!(run(fake_license_plate_reserved, "x", "license_plate"), ("领J99999".into(), vec![]));
        assert_eq!(
            run(fake_address_reserved, "x", "address"),
            ("滨海市西陆区白虎街328号".into(), als(&["328 Baihu Street, Xilu District, Binhai City"]))
        );
        assert_eq!(run(fake_person_reserved, "x", "person"), ("卷帘".into(), als(&["Juan Lian", "JuanLian"])));
        assert_eq!(run(fake_hkid_reserved, "x", "hk_id"), ("Z866262(9)".into(), vec![]));
        assert_eq!(run(fake_twid_reserved, "x", "tw_id"), ("W765329001".into(), vec![]));
        assert_eq!(run(fake_macau_id_reserved, "x", "macau_id"), ("9/106281/8".into(), vec![]));
        assert_eq!(run(fake_taiwan_arc_reserved, "x", "taiwan_arc"), ("WW21682889".into(), vec![]));
    }

    #[test]
    fn golden_en() {
        assert_eq!(run(fake_phone_en_reserved, "x", "phone"), ("(555) 555-0161".into(), vec![]));
        assert_eq!(run(fake_ssn_en_reserved, "x", "ssn"), ("999-72-5691".into(), vec![]));
        assert_eq!(run(fake_credit_card_en_reserved, "x", "credit_card"), ("9999993712566298".into(), vec![]));
        assert_eq!(
            run(fake_address_en_reserved, "x", "address"),
            ("742 Evergreen Terrace, Springfield, USA".into(), als(&["美国斯普林菲尔德常青露台742号"]))
        );
        assert_eq!(run(fake_person_en_reserved, "x", "person"), ("Jane Roe".into(), als(&["简·罗", "简罗"])));
    }

    #[test]
    fn golden_shared() {
        assert_eq!(run(fake_email_reserved, "x", "email"), ("user22601@example.com".into(), vec![]));
        assert_eq!(run(fake_ip_reserved, "8.8.8.8", "ip_address"), ("192.0.2.213".into(), vec![]));
        assert_eq!(run(fake_ip_reserved, "2001:4860:4860::8888", "ip_address"), ("2001:db8::3b4e".into(), vec![]));
        assert_eq!(run(fake_mac_reserved, "x", "mac_address"), ("00:00:5E:00:53:75".into(), vec![]));
    }

    #[test]
    fn golden_numeric() {
        assert_eq!(run(fake_age_noise, "我今年30岁", "age"), ("我今年27岁".into(), vec![]));
        assert_eq!(run(fake_date_of_birth_noise, "1990年3月7日", "date_of_birth"), ("1990年4月2日".into(), vec![]));
        assert_eq!(run(fake_date_of_birth_noise, "1990-03-07", "date_of_birth"), ("1990-03-30".into(), vec![]));
        assert_eq!(run(fake_date_of_birth_noise, "03/07/1990", "date_of_birth"), ("03/09/1990".into(), vec![]));
    }

    // ── Date-arithmetic sanity (independent of RNG) ──────────────────────────
    #[test]
    fn date_roundtrip_and_known_offsets() {
        // round-trip a span of dates through ordinal and back
        for (y, m, d) in [(1, 1, 1), (1990, 3, 7), (2000, 2, 29), (1999, 12, 31), (2024, 2, 29)] {
            let o = ymd_to_ordinal(y, m, d).unwrap();
            assert_eq!(ordinal_to_ymd(o), (y, m, d), "roundtrip {y}-{m}-{d}");
        }
        // March 7 1990 + 26 = April 2 1990 (the dob golden offset)
        let o = ymd_to_ordinal(1990, 3, 7).unwrap();
        assert_eq!(ordinal_to_ymd(o + 26), (1990, 4, 2));
        // Year boundary + leap-year crossing
        let o = ymd_to_ordinal(1999, 12, 31).unwrap();
        assert_eq!(ordinal_to_ymd(o + 1), (2000, 1, 1));
        // Invalid dates → None (mirrors Python date() ValueError)
        assert!(ymd_to_ordinal(2001, 2, 29).is_none()); // not a leap year
        assert!(ymd_to_ordinal(1990, 13, 1).is_none());
        assert!(ymd_to_ordinal(1990, 4, 31).is_none());
    }

    #[test]
    fn dob_identity_on_invalid_or_no_match() {
        // No recognized date → unchanged (no RNG consumed)
        let mut rng = ShakeRng::new(&seed_from_value("hello", "date_of_birth", &[0u8; 8]));
        assert_eq!(fake_date_of_birth_noise("hello", &mut rng), ("hello".into(), vec![]));
        // Chinese numeral months are unmatched → unchanged
        let mut rng = ShakeRng::new(&seed_from_value("三月七号", "date_of_birth", &[0u8; 8]));
        assert_eq!(fake_date_of_birth_noise("三月七号", &mut rng), ("三月七号".into(), vec![]));
    }

    #[test]
    fn age_identity_when_no_digit() {
        let mut rng = ShakeRng::new(&seed_from_value("no age here", "age", &[0u8; 8]));
        assert_eq!(fake_age_noise("no age here", &mut rng), ("no age here".into(), vec![]));
    }

    #[test]
    fn pool_counts_match_python() {
        // Verbatim-transcription gate: counts MUST equal the Python source pools.
        let z = zh_data();
        assert_eq!(z.reserved_person_names.len(), 13);
        assert_eq!(z.reserved_person_names_aliases.len(), 13);
        assert_eq!(z.reserved_cities.len(), 3);
        assert_eq!(z.reserved_cities.iter().map(|c| c.2.len()).sum::<usize>(), 9);
        assert_eq!(z.reserved_addresses_zh_aliases.len(), 9);
        assert_eq!(z.passport_prefixes.len(), 2);
        assert_eq!(z.plate_special_prefixes.len(), 2);
        assert_eq!(z.hkid_reserved_letter, "Z");
        assert_eq!(z.twid_reserved_letter, "W");
        assert_eq!(z.macau_reserved_lead, "9");
        assert_eq!(z.twarc_reserved_prefix, "WW");

        let e = en_data();
        assert_eq!(e.reserved_person_names_en.len(), 10);
        assert_eq!(e.reserved_person_names_en_aliases.len(), 10);
        assert_eq!(e.reserved_addresses_en.len(), 6);
        assert_eq!(e.reserved_addresses_en_aliases.len(), 6);

        let s = shared_data();
        assert_eq!(s.rfc2606_domains.len(), 3);
        assert_eq!(s.rfc5737_prefixes.len(), 3);
        assert_eq!(s.rfc7042_mac_prefix, "00:00:5E:00:53");
    }

    #[test]
    fn resolve_known_and_unknown() {
        for name in [
            "fake_phone_reserved", "fake_id_number_reserved", "fake_person_reserved",
            "fake_phone_en_reserved", "fake_person_en_reserved", "fake_email_reserved",
            "fake_ip_reserved", "fake_mac_reserved", "fake_age_noise", "fake_date_of_birth_noise",
        ] {
            assert!(resolve_faker(name).is_some(), "{name} should resolve");
        }
        assert!(resolve_faker("fake_zh_real").is_none()); // out of scope
        assert!(resolve_faker("nonexistent").is_none());
    }

    #[test]
    fn generate_unique_fake_first_roll_when_unused() {
        // With an empty `used` set, the first roll should match the per-faker golden.
        let used = std::collections::HashSet::new();
        let (fake, aliases) =
            generate_unique_fake(fake_person_reserved, "x", "person", &[0u8; 8], &used).unwrap();
        assert_eq!((fake, aliases), ("卷帘".into(), als(&["Juan Lian", "JuanLian"])));
    }

    #[test]
    fn generate_unique_fake_rerolls_on_collision() {
        // Pre-seed `used` with the first-roll value; the re-roll must differ.
        let first = run(fake_person_reserved, "x", "person").0;
        let mut used = std::collections::HashSet::new();
        used.insert(first.clone());
        let (fake, _) =
            generate_unique_fake(fake_person_reserved, "x", "person", &[0u8; 8], &used).unwrap();
        assert_ne!(fake, first);

        // The re-roll value must equal the Python re-roll: seed_input "x#0".
        let reroll_seed = seed_from_value("x#0", "person", &[0u8; 8]);
        let mut rng = ShakeRng::new(&reroll_seed);
        let expected = fake_person_reserved("x", &mut rng).0;
        assert_eq!(fake, expected);
    }

    #[test]
    fn generate_unique_fake_rejects_identity_pass() {
        // If the faker would return the input value, it must re-roll (identity guard).
        // A person fake that equals the input "卷帘" must be rejected and re-rolled.
        let used = std::collections::HashSet::new();
        let (fake, _) =
            generate_unique_fake(fake_person_reserved, "卷帘", "person", &[0u8; 8], &used).unwrap();
        assert_ne!(fake, "卷帘");
    }
}
