//! Pure Layer-1 PII validators, ported 1:1 from the Python `_validate_*` functions.
//! Each is a pure function of the matched value. Dispatched by machine key via
//! `resolve_validator`. Helpers (`luhn_check_digit`, `gb11643_check_char`, ...) stay
//! public so the binding/tests can reuse them.

use std::sync::LazyLock;
use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use fancy_regex::Regex;

// ── Luhn ──────────────────────────────────────────────────────────────────
pub fn luhn_check_digit(body: &str) -> u32 {
    let digits: Vec<u32> = body.chars().filter_map(|c| c.to_digit(10)).collect();
    let (mut doubled, mut not_doubled) = (0u32, 0u32);
    for (i, &d) in digits.iter().rev().enumerate() {
        if i % 2 == 0 {
            let x = d * 2;
            doubled += if x > 9 { x - 9 } else { x };
        } else {
            not_doubled += d;
        }
    }
    (10 - (doubled + not_doubled) % 10) % 10
}

pub fn validate_luhn(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 16 { return false; }
    let (body, last) = digits.split_at(digits.len() - 1);
    luhn_check_digit(body) == last.parse::<u32>().unwrap()
}

pub fn validate_credit_card_luhn(value: &str) -> bool {
    let digits_only: String = value.replace(['-', ' '], "");
    if digits_only.is_empty() || !digits_only.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    validate_luhn(&digits_only)
}

const BANK_BINS: &[&str] = &[
    "621700","621660","621662","621663","622202","622200","622208","621225",
    "622848","622849","620059","621282","622568","622569","625912","625911",
    "622588","622598","621483","622575","622155","622156","622157","621002",
    "622689","622688","621691","622622","622668","622669","622670","622671",
    "622630","622631","622632","622633","621283","621285","621286","621484",
    "622580","622581","622582","622583","622150","622151","622152","622153",
    "622700","622701","622690","622692",
];

pub fn validate_cn_bank_card(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 16 { return false; }
    if validate_luhn(value) { return true; }
    let prefix = &digits[..6];
    BANK_BINS.contains(&prefix)
}

// ── GB 11643 (Chinese national ID) ──────────────────────────────────────────
const GB11643_WEIGHTS: [u32; 17] = [7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2];
const GB11643_CHECK_CHARS: &[u8] = b"10X98765432";

pub fn gb11643_check_char(body17: &str) -> char {
    let total: u32 = body17.chars().take(17).zip(GB11643_WEIGHTS.iter())
        .map(|(c, w)| c.to_digit(10).unwrap_or(0) * w).sum();
    GB11643_CHECK_CHARS[(total % 11) as usize] as char
}

pub fn validate_id_number(value: &str) -> bool {
    let value: String = value.replace([' ', '-'], "").to_uppercase();
    if value.chars().count() != 18 { return false; }
    let chars: Vec<char> = value.chars().collect();
    if !chars[..17].iter().all(|c| c.is_ascii_digit()) { return false; }
    let last = chars[17];
    if !(last.is_ascii_digit() || last == 'X') { return false; }
    if chars[0] == '0' { return false; }
    let body17: String = chars[..17].iter().collect();
    gb11643_check_char(&body17) == last
}

// ── HKID ────────────────────────────────────────────────────────────────────
/// Compute the HKID check character.
///
/// # Panics
/// Panics if `digits` contains a non-decimal character. Callers must pass a
/// 6-digit string (guaranteed on the `validate_hkid` path by the regex).
pub fn hkid_check_digit(letters: &str, digits: &str) -> String {
    let pad = if letters.chars().count() == 1 { " " } else { "" };
    let body = format!("{pad}{letters}{digits}");
    let weights = [9i32, 8, 7, 6, 5, 4, 3, 2];
    let mut total = 0i32;
    for (ch, w) in body.chars().zip(weights.iter()) {
        let v = if ch == ' ' { 36 }
            else if ch.is_ascii_alphabetic() { (ch as i32) - ('A' as i32) + 1 }
            else { ch.to_digit(10).unwrap() as i32 };
        total += v * w;
    }
    let check = (11 - total % 11) % 11;
    if check == 10 { "X".into() } else { check.to_string() }
}

static HKID_BODY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Z]{1,2})(\d{6})\((\d|X)\)$").unwrap());

pub fn validate_hkid(value: &str) -> bool {
    match HKID_BODY_RE.captures(value) {
        Ok(Some(caps)) => {
            let l = caps.get(1).unwrap().as_str();
            let d = caps.get(2).unwrap().as_str();
            let c = caps.get(3).unwrap().as_str();
            hkid_check_digit(l, d) == c
        }
        _ => false,
    }
}

// ── TWID ──────────────────────────────────────────────────────────────────
fn twid_letter_code(letter: char) -> Option<u32> {
    match letter {
        'A'=>Some(10),'B'=>Some(11),'C'=>Some(12),'D'=>Some(13),'E'=>Some(14),'F'=>Some(15),
        'G'=>Some(16),'H'=>Some(17),'I'=>Some(34),'J'=>Some(18),'K'=>Some(19),'L'=>Some(20),
        'M'=>Some(21),'N'=>Some(22),'O'=>Some(35),'P'=>Some(23),'Q'=>Some(24),'R'=>Some(25),
        'S'=>Some(26),'T'=>Some(27),'U'=>Some(28),'V'=>Some(29),'W'=>Some(32),'X'=>Some(30),
        'Y'=>Some(31),'Z'=>Some(33), _=>None,
    }
}

/// Compute the TWID check digit.
///
/// # Panics
/// Panics if `letter` is not A–Z or `digits` contains a non-decimal character.
/// Callers must pre-validate (guaranteed on the `validate_twid` path).
pub fn twid_check_digit(letter: char, digits: &str) -> char {
    let code = twid_letter_code(letter).unwrap();
    let (n1, n2) = (code / 10, code % 10);
    let weights = [8u32, 7, 6, 5, 4, 3, 2, 1];
    let mut total = n1 + n2 * 9;
    for (d, w) in digits.chars().zip(weights.iter()) {
        total += d.to_digit(10).unwrap() * w;
    }
    std::char::from_digit((10 - total % 10) % 10, 10).unwrap()
}

pub fn validate_twid(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() != 10 || !chars[0].is_ascii_alphabetic()
        || !chars[1..].iter().all(|c| c.is_ascii_digit()) { return false; }
    if twid_letter_code(chars[0]).is_none() { return false; }
    let body: String = chars[1..9].iter().collect();
    twid_check_digit(chars[0], &body) == chars[9]
}

// ── Unified Social Credit Code (MOD 31) ─────────────────────────────────────
const CREDIT_CODE_CHARSET: &str = "0123456789ABCDEFGHJKLMNPQRTUWXY";
const CREDIT_CODE_WEIGHTS: [u32; 17] = [1,3,9,27,19,26,16,17,20,29,25,13,8,24,10,30,28];

fn credit_code_val(c: char) -> Option<u32> {
    CREDIT_CODE_CHARSET.chars().position(|x| x == c).map(|i| i as u32)
}

pub fn validate_credit_code(value: &str) -> bool {
    let chars: Vec<char> = value.to_uppercase().chars().collect();
    if chars.len() != 18 { return false; }
    if chars.iter().any(|&c| credit_code_val(c).is_none()) { return false; }
    let total: u32 = (0..17).map(|i| credit_code_val(chars[i]).unwrap() * CREDIT_CODE_WEIGHTS[i]).sum();
    let check = (31 - total % 31) % 31;
    credit_code_val(chars[17]).unwrap() == check
}

// ── My Number (JP) ──────────────────────────────────────────────────────────
pub fn validate_my_number(value: &str) -> bool {
    let digits: String = value.replace(' ', "");
    if digits.chars().count() != 12 || !digits.chars().all(|c| c.is_ascii_digit()) { return false; }
    let d: Vec<u32> = digits.chars().map(|c| c.to_digit(10).unwrap()).collect();
    let weights = [6u32,5,4,3,2,7,6,5,4,3,2];
    let total: u32 = (0..11).map(|i| d[i] * weights[i]).sum();
    let remainder = total % 11;
    let check = if remainder <= 1 { 0 } else { 11 - remainder };
    d[11] == check
}

// ── CPF / CNPJ (BR) ─────────────────────────────────────────────────────────
fn br_check(d: &[i32], slice_len: usize, weights: &[i32]) -> i32 {
    let total: i32 = (0..slice_len).map(|i| d[i] * weights[i]).sum();
    let rem = total % 11;
    if rem < 2 { 0 } else { 11 - rem }
}

pub fn validate_cpf(value: &str) -> bool {
    let d: Vec<i32> = value.chars().filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap() as i32).collect();
    if d.len() != 11 || d.iter().all(|&x| x == d[0]) { return false; }
    let w1: Vec<i32> = (2..=10).rev().collect();      // 10,9,...,2
    if d[9] != br_check(&d, 9, &w1) { return false; }
    let w2: Vec<i32> = (2..=11).rev().collect();      // 11,10,...,2
    d[10] == br_check(&d, 10, &w2)
}

pub fn validate_cnpj(value: &str) -> bool {
    let d: Vec<i32> = value.chars().filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap() as i32).collect();
    if d.len() != 14 || d.iter().all(|&x| x == d[0]) { return false; }
    let w1 = [5,4,3,2,9,8,7,6,5,4,3,2];
    if d[12] != br_check(&d, 12, &w1) { return false; }
    let w2 = [6,5,4,3,2,9,8,7,6,5,4,3,2];
    d[13] == br_check(&d, 13, &w2)
}

// ── IBAN (mod 97) ───────────────────────────────────────────────────────────
fn iban_expected_len(cc: &str) -> Option<usize> {
    match cc {
        "AD"=>Some(24),"AE"=>Some(23),"AL"=>Some(28),"AT"=>Some(20),"AZ"=>Some(28),"BA"=>Some(20),
        "BE"=>Some(16),"BG"=>Some(22),"BH"=>Some(22),"BR"=>Some(29),"BY"=>Some(28),"CH"=>Some(21),
        "CR"=>Some(22),"CY"=>Some(28),"CZ"=>Some(24),"DE"=>Some(22),"DK"=>Some(18),"DO"=>Some(28),
        "EE"=>Some(20),"EG"=>Some(29),"ES"=>Some(24),"FI"=>Some(18),"FO"=>Some(18),"FR"=>Some(27),
        "GB"=>Some(22),"GE"=>Some(22),"GI"=>Some(23),"GL"=>Some(18),"GR"=>Some(27),"GT"=>Some(28),
        "HR"=>Some(21),"HU"=>Some(28),"IE"=>Some(22),"IL"=>Some(23),"IQ"=>Some(23),"IS"=>Some(26),
        "IT"=>Some(27),"JO"=>Some(30),"KW"=>Some(30),"KZ"=>Some(20),"LB"=>Some(28),"LC"=>Some(32),
        "LI"=>Some(21),"LT"=>Some(20),"LU"=>Some(20),"LV"=>Some(21),"LY"=>Some(25),"MC"=>Some(27),
        "MD"=>Some(24),"ME"=>Some(22),"MK"=>Some(19),"MR"=>Some(27),"MT"=>Some(31),"MU"=>Some(30),
        "NL"=>Some(18),"NO"=>Some(15),"PK"=>Some(24),"PL"=>Some(28),"PS"=>Some(29),"PT"=>Some(25),
        "QA"=>Some(29),"RO"=>Some(24),"RS"=>Some(22),"SA"=>Some(24),"SC"=>Some(31),"SD"=>Some(18),
        "SE"=>Some(24),"SI"=>Some(19),"SK"=>Some(24),"SM"=>Some(27),"ST"=>Some(25),"SV"=>Some(28),
        "TL"=>Some(23),"TN"=>Some(24),"TR"=>Some(26),"UA"=>Some(29),"VA"=>Some(22),"VG"=>Some(24),
        "XK"=>Some(20), _=>None,
    }
}

pub fn validate_iban(value: &str) -> bool {
    let iban: String = value.replace(' ', "").to_uppercase();
    let chars: Vec<char> = iban.chars().collect();
    if chars.len() < 2 { return false; }
    let cc: String = chars[..2].iter().collect();
    match iban_expected_len(&cc) {
        Some(n) if chars.len() == n => {}
        _ => return false,
    }
    let rearranged: String = chars[4..].iter().chain(chars[..4].iter()).collect();
    let mut rem: u64 = 0;
    for c in rearranged.chars() {
        if c.is_ascii_alphabetic() {
            for d in ((c as u32) - 55).to_string().chars() {
                rem = (rem * 10 + d.to_digit(10).unwrap() as u64) % 97;
            }
        } else if let Some(d) = c.to_digit(10) {
            rem = (rem * 10 + d as u64) % 97;
        } else {
            return false;
        }
    }
    rem == 1
}

// ── Format / structural validators ──────────────────────────────────────────
pub fn validate_email(value: &str) -> bool {
    let local = if value.contains('@') { value.split('@').next().unwrap_or("") } else { "" };
    !(local.contains("..") || local.starts_with('.') || local.ends_with('.'))
}

pub(crate) static AGE_DIGITS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d+").unwrap());
pub fn validate_age(value: &str) -> bool {
    match AGE_DIGITS_RE.find(value) {
        Ok(Some(m)) => match m.as_str().parse::<u64>() {
            Ok(age) => age <= 149,
            Err(_) => false, // overflow ⇒ far above 149
        },
        _ => false,
    }
}

pub fn validate_pan(value: &str) -> bool {
    let c: Vec<char> = value.chars().collect();
    if c.len() != 10 { return false; }
    c[..5].iter().all(|x| x.is_ascii_alphabetic())
        && c[5..9].iter().all(|x| x.is_ascii_digit())
        && c[9].is_ascii_alphabetic()
        && "ABCFGHLJPT".contains(c[3])
}

pub fn validate_ssn(value: &str) -> bool {
    let digits: String = value.replace(['-', ' '], "");
    if digits.chars().count() != 9 || !digits.chars().all(|c| c.is_ascii_digit()) { return false; }
    let (area, group, serial) = (&digits[..3], &digits[3..5], &digits[5..]);
    if area == "000" || group == "00" || serial == "0000" { return false; }
    !(area == "666" || area.parse::<u32>().unwrap() >= 900)
}

pub fn validate_aadhaar(value: &str) -> bool {
    let digits: String = value.replace([' ', '-'], "");
    let c: Vec<char> = digits.chars().collect();
    if c.len() != 12 || c[0] == '0' || c[0] == '1' { return false; }
    c.iter().all(|x| x.is_ascii_digit())
}

pub fn validate_de_phone(value: &str) -> bool {
    let n = value.chars().filter(|c| c.is_ascii_digit()).count();
    (10..=15).contains(&n)
}

pub fn validate_de_tax_id(value: &str) -> bool {
    let digits: String = value.replace(' ', "");
    let c: Vec<char> = digits.chars().collect();
    if c.len() != 11 || c[0] == '0' { return false; }
    c.iter().all(|x| x.is_ascii_digit())
}

pub fn validate_jp_phone(value: &str) -> bool {
    let n = value.replace('-', "").chars().count();
    (10..=11).contains(&n)
}

// ── JWT (deferred → Rust in v0.7.7) ─────────────────────────────────────────
/// base64url engine matching Python `base64.urlsafe_b64decode` (binascii)
/// LENIENT semantics: non-canonical trailing bits are allowed and padding is
/// `Indifferent`. The default `URL_SAFE` engine is STRICT (RequireCanonical +
/// rejects trailing bits), which rejected non-canonical headers that pre-port
/// Python ACCEPTED — so a JWT with a non-canonical header that Python redacted
/// silently LEAKED unredacted under the strict validator. This engine restores
/// that parity. Canonical headers (the golden corpus) decode identically under
/// both engines, so the only behavior change is ADDING acceptance of
/// non-canonical headers — never removing a previously-accepted one.
static JWT_B64: LazyLock<GeneralPurpose> = LazyLock::new(|| {
    GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
    )
});

/// JWT format validation, ported 1:1 from `lang/shared/patterns.py::_validate_jwt`.
///
/// Splits on `.`, requires exactly 3 parts, base64url-decodes the header (part 0)
/// with Python-equal padding (`-len % 4` pad `=`) and Python-equal LENIENT
/// base64 (see `JWT_B64`), parses the bytes as JSON, and returns `true` iff the
/// result is a JSON OBJECT containing the key `"alg"`. Any decode/parse error
/// (the Python `(ValueError, UnicodeDecodeError)` branch) → `false`.
pub fn validate_jwt(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let header_b64 = parts[0];
    // Python: padded = header_b64 + "=" * (-len(header_b64) % 4)
    let pad = (4 - header_b64.len() % 4) % 4;
    let padded = format!("{header_b64}{}", "=".repeat(pad));
    let decoded = match JWT_B64.decode(padded.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    // json.loads + isinstance(header, dict) and "alg" in header
    match serde_json::from_slice::<serde_json::Value>(&decoded) {
        Ok(serde_json::Value::Object(map)) => map.contains_key("alg"),
        _ => false,
    }
}

// ── Chinese organization / school (deferred → Rust in v0.7.7) ────────────────
/// Leading verbs/particles/questions stripped from org/school candidates before
/// validation. Stripped one at a time (`has_name_before_suffix` restarts the scan
/// after each match), and the first entry that matches in array order wins.
/// ORDER IS LOAD-BEARING: entries are ordered longest-prefix-first so a specific
/// prefix shadows its own substring (e.g. "请查一下" before "请查"); reordering can
/// change results and break parity with the Python `_has_name_before_suffix`
/// (mirrors `lang/zh/patterns.py::_LEADING_NOISE`).
const LEADING_NOISE: &[&str] = &[
    "请查一下", "请查下", "请查", "查一下", "查下", "就职于", "供职于", "任职于",
    "毕业于", "就读于", "就读", "考入", "考上", "去过", "到过", "这是", "那是",
    "这个", "那个", "那里", "这里", "在", "去", "从", "到", "被", "给", "让",
    "有", "是", "的", "了", "和", "与", "把", "将", "已", "问", "看", "找", "一下",
];

const ORG_SUFFIXES: &[&str] = &[
    "股份有限公司", "有限责任公司", "有限公司", "责任公司", "集团公司", "集团",
    "公司", "企业", "工厂", "银行", "保险", "证券", "基金", "医院", "诊所", "药房",
    "事务所", "研究院", "研究所", "实验室",
];

const SCHOOL_SUFFIXES: &[&str] = &[
    "大学", "学院", "中学", "小学", "高中", "初中", "附中", "附小", "实验学校",
    "外国语学校", "师范学校", "职业学校", "技术学校", "幼儿园", "书院", "学堂", "党校",
];

/// Port of `lang/zh/patterns.py::_has_name_before_suffix`.
///
/// Repeatedly strips a single leading-noise prefix (the Python `for ... else break`
/// loop strips at most one prefix per pass, restarting from the top until none
/// matches — note: only strips when `len(stripped) > len(noise)`, never consuming
/// the whole string), then returns `true` iff the remainder ends with any suffix
/// AND is strictly longer than that suffix (so a real name char precedes it).
/// All length comparisons are in char-space (Python `len(str)` over CJK text).
fn has_name_before_suffix(value: &str, suffixes: &[&str]) -> bool {
    let mut stripped = value;
    loop {
        let mut stripped_any = false;
        for noise in LEADING_NOISE {
            if stripped.starts_with(noise)
                && stripped.chars().count() > noise.chars().count()
            {
                stripped = &stripped[noise.len()..];
                stripped_any = true;
                break;
            }
        }
        if !stripped_any {
            break;
        }
    }
    let stripped_len = stripped.chars().count();
    suffixes.iter().any(|suffix| {
        stripped.ends_with(suffix) && stripped_len > suffix.chars().count()
    })
}

pub fn validate_organization(value: &str) -> bool {
    has_name_before_suffix(value, ORG_SUFFIXES)
}

pub fn validate_school(value: &str) -> bool {
    has_name_before_suffix(value, SCHOOL_SUFFIXES)
}

// ── Dispatch ──────────────────────────────────────────────────────────────
pub fn resolve_validator(name: &str) -> Option<fn(&str) -> bool> {
    Some(match name {
        "credit_card_luhn" => validate_credit_card_luhn,
        "cn_bank_card" => validate_cn_bank_card,
        "gb11643_mod11" => validate_id_number,
        "hkid" => validate_hkid,
        "twid" => validate_twid,
        "credit_code_mod31" => validate_credit_code,
        "iban_mod97" => validate_iban,
        "aadhaar" => validate_aadhaar,
        "cpf" => validate_cpf,
        "cnpj" => validate_cnpj,
        "my_number" => validate_my_number,
        "email" => validate_email,
        "pan" => validate_pan,
        "ssn" => validate_ssn,
        "age" => validate_age,
        "de_phone" => validate_de_phone,
        "de_tax_id" => validate_de_tax_id,
        "jp_phone" => validate_jp_phone,
        "jwt" => validate_jwt,
        "organization" => validate_organization,
        "school" => validate_school,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_and_cards() {
        assert!(validate_credit_card_luhn("4111111111111111"));   // canonical Visa test
        assert!(!validate_credit_card_luhn("4111111111111112"));
        assert!(!validate_credit_card_luhn("4111-1111-11AB-1111"));
        assert!(validate_cn_bank_card("6217000000000000")); // BIN-prefix fallback path
    }

    #[test]
    fn cn_id_and_credit_code() {
        assert!(validate_id_number("11010519491231002X"));  // known valid GB11643 sample
        assert!(!validate_id_number("110105194912310021"));
        assert!(!validate_id_number("01010519491231002X")); // leading 0
    }

    #[test]
    fn hkid_twid() {
        // round-trip: a body + its computed check must validate; flipping the check must not
        let c = hkid_check_digit("A", "123456");
        assert!(validate_hkid(&format!("A123456({c})")));
        let wrong = if c == "0" { "1" } else { "0" };
        assert!(!validate_hkid(&format!("A123456({wrong})")));
        let twc = twid_check_digit('A', "12345678");
        assert!(validate_twid(&format!("A12345678{twc}")));
        let twrong = if twc == '0' { '1' } else { '0' };
        assert!(!validate_twid(&format!("A12345678{twrong}")));
    }

    #[test]
    fn iban_my_number_br() {
        assert!(validate_iban("GB82WEST12345698765432"));   // canonical IBAN test value
        assert!(!validate_iban("GB82WEST12345698765431"));
        assert!(!validate_my_number("1234567890"));   // 10 digits — wrong length
        assert!(!validate_my_number("12345678901a")); // non-digit
        assert!(validate_cpf("11144477735"));         // valid CPF check digits
        assert!(!validate_cpf("11111111111"));        // all-same rejected
        assert!(validate_cnpj("11222333000181"));     // valid CNPJ check digits
        assert!(!validate_cnpj("11111111111111"));
    }

    #[test]
    fn format_validators() {
        assert!(validate_email("a.b@example.com"));
        assert!(!validate_email("a..b@example.com"));
        assert!(validate_age("42"));
        assert!(!validate_age("200"));
        assert!(validate_pan("ABCPL1234C"));
        assert!(!validate_pan("ABCDL1234C")); // 4th char D not in ABCFGHLJPT
        assert!(validate_ssn("123-45-6789"));
        assert!(!validate_ssn("666-45-6789"));
        assert!(validate_aadhaar("234567890123"));
        assert!(!validate_aadhaar("034567890123")); // starts 0
        assert!(validate_de_phone("+49 30 1234567"));
        assert!(validate_de_tax_id("12345678901"));
        assert!(!validate_de_tax_id("01234567890"));
        assert!(validate_jp_phone("090-1234-5678"));
    }

    #[test]
    fn resolve_known_and_unknown() {
        assert!(resolve_validator("ssn").is_some());
        assert!(resolve_validator("jwt").is_some());          // ported to Rust (v0.7.7)
        assert!(resolve_validator("organization").is_some());
        assert!(resolve_validator("school").is_some());
        assert!(resolve_validator("nonexistent").is_none());
    }

    #[test]
    fn jwt_validator() {
        // header {"alg":"HS256"} → valid object with "alg" key
        assert!(validate_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"));
        // fewer than 3 parts → false
        assert!(!validate_jwt("a.b"));
        // header is valid base64 but a JSON array (not an object) → false
        // base64url("[1,2,3]") == "WzEsMiwzXQ"
        assert!(!validate_jwt("WzEsMiwzXQ.b.c"));
        // header is a JSON object but lacks "alg" → false
        // base64url('{"typ":"JWT"}') == "eyJ0eXAiOiJKV1QifQ"
        assert!(!validate_jwt("eyJ0eXAiOiJKV1QifQ.b.c"));
        // header decodes to a JSON string (not an object) → false
        // base64url('"hello"') == "ImhlbGxvIg"
        assert!(!validate_jwt("ImhlbGxvIg.b.c"));
    }

    #[test]
    fn jwt_non_canonical_header_parity() {
        // PARITY REGRESSION: a JWT whose header base64 carries NON-ZERO trailing
        // bits (len%4==3, last char '1' instead of canonical '0'). Pre-port Python
        // `base64.urlsafe_b64decode` (binascii) is LENIENT and decodes this to
        // {"alg":"none"} → a valid header → Python REDACTED it. The default strict
        // URL_SAFE engine returns InvalidLastSymbol → would REJECT → leak. With the
        // lenient JWT_B64 engine this must now ACCEPT, matching pre-port Python.
        //   base64url('{"alg":"none"}') canonical == "eyJhbGciOiJub25lIn0"
        //   non-canonical (trailing bits set) == "eyJhbGciOiJub25lIn1"
        assert!(validate_jwt("eyJhbGciOiJub25lIn1.payload.sig"));
        // The canonical form is of course still accepted (golden corpus uses these).
        assert!(validate_jwt("eyJhbGciOiJub25lIn0.payload.sig"));
        // Leniency is ONLY about trailing bits/padding — structural rejects stay
        // rejected: a JSON ARRAY header is still false even with a non-canonical
        // last char. base64url('[1,2,3]') == "WzEsMiwzXQ"; flip last char to a
        // non-canonical equivalent ('Q'=16 010000 -> 'R'=17 010001, same top4).
        assert!(!validate_jwt("WzEsMiwzXR.payload.sig"));
        // A 2-segment value is still rejected regardless of base64 leniency.
        assert!(!validate_jwt("eyJhbGciOiJub25lIn1.payload"));
    }

    #[test]
    fn organization_school_validators() {
        assert!(validate_organization("阿里巴巴有限公司"));
        assert!(!validate_organization("这是公司")); // all-noise prefix, no name before suffix
        assert!(validate_school("北京大学"));
        assert!(!validate_school("这是大学"));
        // leading-particle-prefixed values (what the regex captures) still validate
        assert!(validate_organization("在阿里巴巴有限公司"));
        assert!(validate_school("毕业于北京大学"));
    }
}
