//! Masking functions and collision resolver — ported from `pure/replacer.py`
//! (lines 346–454).
//!
//! All character-length operations use `str::chars().count()` / char Vec
//! indexing to correctly handle multi-byte CJK characters.

use std::collections::HashSet;

/// Circled digit characters ①..⑳ (U+2460..U+2473).
/// 20 entries, matching `_CIRCLED_DIGITS` in replacer.py.
const CIRCLED_DIGITS: &[char] = &[
    '①', '②', '③', '④', '⑤', '⑥', '⑦', '⑧', '⑨', '⑩', '⑪', '⑫', '⑬', '⑭', '⑮', '⑯',
    '⑰', '⑱', '⑲', '⑳',
];

/// Upper bound for the numeric collision suffix loop (exclusive).
/// Mirrors `_MAX_NUMERIC_COLLISION_SUFFIX = 10_000`.
const MAX_NUMERIC_COLLISION_SUFFIX: u32 = 10_000;

/// Apply mask strategy: show `visible_prefix` + `visible_suffix` chars, mask middle.
///
/// Mirrors `_mask_value` (replacer.py:346–380).
///
/// Email special-case: `local[0]` + at least 3 stars + `@domain`.
/// Per-type defaults: phone(3,4), bank_card(6,4), credit_card(6,4), id_number(0,4).
/// If `visible_prefix` and `visible_suffix` are both 0 the per-type default applies.
///
/// **Char-based**: all lengths are Unicode scalar values (`.chars().count()`),
/// not byte lengths.
pub fn mask_value(
    value: &str,
    entity_type: &str,
    visible_prefix: usize,
    visible_suffix: usize,
) -> String {
    if entity_type == "email" {
        // Email: find '@', show first char of local + stars + @domain.
        // Only apply the email-specific shape when a valid '@' (index > 0) is
        // present. If there's no valid '@' the value isn't a real email (a
        // mislabel reachable via `_pre_detected`, a custom pattern, or an
        // NER/L3 mislabel) — fall through to the generic char-mask below
        // instead of returning it verbatim, which would leak the value.
        if let Some(at) = value.find('@').filter(|&a| a > 0) {
            let local = &value[..at];
            let domain = &value[at..]; // includes the '@'
            let local_chars: Vec<char> = local.chars().collect();
            let visible: String = if local_chars.is_empty() {
                String::new()
            } else {
                local_chars[0].to_string()
            };
            let star_count = (local_chars.len().saturating_sub(1)).max(3);
            return format!("{}{}{}", visible, "*".repeat(star_count), domain);
        }
        // No valid '@' → fall through to generic masking (`_ => (3, 4)` default).
    }

    // Per-type defaults for (prefix, suffix)
    let (default_prefix, default_suffix) = match entity_type {
        "phone" => (3usize, 4usize),
        "bank_card" => (6, 4),
        "credit_card" => (6, 4),
        "id_number" => (0, 4),
        _ => (3, 4),
    };

    let p = if visible_prefix != 0 {
        visible_prefix
    } else {
        default_prefix
    };
    let s = if visible_suffix != 0 {
        visible_suffix
    } else {
        default_suffix
    };

    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();

    if len <= p + s {
        return "*".repeat(len);
    }

    let prefix_str: String = chars[..p].iter().collect();
    let suffix_str: String = chars[len - s..].iter().collect();
    let masked = "*".repeat(len - p - s);
    format!("{}{}{}", prefix_str, masked, suffix_str)
}

/// Chinese name mask: 张* / 李** / 欧阳**.
///
/// Mirrors `_mask_name` (replacer.py:383–391):
/// - len == 1 → `"*"`
/// - len == 2 or 3 → first char + (len-1) stars
/// - len >= 4 → first 2 chars + (len-2) stars
///
/// **Char-based** — `欧阳明` (3 chars) → `欧**` (first 1 char + 2 stars).
pub fn mask_name(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();
    match len {
        0 => String::new(),
        1 => "*".to_string(),
        2 | 3 => {
            let first: String = chars[..1].iter().collect();
            format!("{}{}", first, "*".repeat(len - 1))
        }
        _ => {
            // len >= 4: show first 2 chars
            let first_two: String = chars[..2].iter().collect();
            format!("{}{}", first_two, "*".repeat(len - 2))
        }
    }
}

/// Landline mask: keep area code + last 3 digits, star the middle.
///
/// Mirrors `_mask_landline` (replacer.py:394–413).
///
/// Splitting rules:
/// 1. Dash present → area = everything up to and including `-`; number = rest.
/// 2. Starts with `0` → area len 3 if `value[1]` is `'1'` or `'2'`, else 4.
/// 3. Otherwise → area = `""`, number = whole value.
pub fn mask_landline(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();

    let (area_chars, number_chars): (Vec<char>, Vec<char>) = if let Some(dash_pos) =
        chars.iter().position(|&c| c == '-')
    {
        // Split at the dash (inclusive)
        let area = chars[..=dash_pos].to_vec();
        let number = chars[dash_pos + 1..].to_vec();
        (area, number)
    } else if !chars.is_empty() && chars[0] == '0' {
        // Guess area code length from second digit
        let area_len = if chars.len() > 1 && (chars[1] == '1' || chars[1] == '2') {
            3usize
        } else {
            4usize
        };
        let split = area_len.min(chars.len());
        (chars[..split].to_vec(), chars[split..].to_vec())
    } else {
        (vec![], chars.clone())
    };

    let area: String = area_chars.iter().collect();
    let number = number_chars;

    if number.len() <= 3 {
        let num_str: String = number.iter().collect();
        return format!("{}{}", area, num_str);
    }

    let stars = "*".repeat(number.len() - 3);
    let last3: String = number[number.len() - 3..].iter().collect();
    format!("{}{}{}", area, stars, last3)
}

/// Phone mask with regional rules.
///
/// Mirrors `_mask_phone_regional` (replacer.py:416–438):
/// - cn / auto+11-digit: (3, 4)
/// - hk / auto+8-digit:  (2, 2)
/// - tw / auto+9-digit:  (2, 3)
/// - default:            (2, 2)
///
/// Strips dashes and spaces before masking.
pub fn mask_phone_regional(value: &str, region: &str) -> String {
    let digits: String = value.chars().filter(|c| *c != '-' && *c != ' ').collect();
    let dlen = digits.chars().count();

    let (p, s) = match region {
        "cn" => (3usize, 4usize),
        "hk" => (2, 2),
        "tw" => (2, 3),
        "auto" if dlen == 11 => (3, 4),
        "auto" if dlen == 8 => (2, 2),
        "auto" if dlen == 9 => (2, 3),
        _ => (2, 2),
    };

    let chars: Vec<char> = digits.chars().collect();
    let len = chars.len();
    if len <= p + s {
        return "*".repeat(len);
    }
    let prefix: String = chars[..p].iter().collect();
    let suffix: String = chars[len - s..].iter().collect();
    format!("{}{}{}", prefix, "*".repeat(len - p - s), suffix)
}

/// Append a circled-digit (or numeric) suffix to avoid label collisions.
///
/// Mirrors `_resolve_collision` (replacer.py:441–454):
/// 1. If `label` is not in `used` → return unchanged.
/// 2. Try `label①` .. `label⑳` (circled digits).
/// 3. Try `label(21)` .. `label(9999)`.
/// 4. Return `Err` if all are exhausted (matches Python `raise RuntimeError`).
///
/// Returning `Err` — rather than panicking — keeps a pathological input (a
/// document engineered to saturate every suffix for one label) from crossing the
/// PyO3 boundary as an uncatchable `PanicException`. The binding maps the `Err`
/// to a catchable Python `ValueError`, so saturation degrades to a normal error
/// instead of a process-level DoS.
pub fn resolve_collision(label: &str, used: &HashSet<String>) -> Result<String, String> {
    if !used.contains(label) {
        return Ok(label.to_string());
    }
    // Try circled-digit suffixes ①..⑳
    for &c in CIRCLED_DIGITS {
        let candidate = format!("{}{}", label, c);
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    // Numeric suffix (21)..(9999)
    for i in 21..MAX_NUMERIC_COLLISION_SUFFIX {
        let candidate = format!("{}({})", label, i);
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(format!("too many collisions for label {label:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- mask_value ---

    #[test]
    fn mask_value_phone_default() {
        assert_eq!(mask_value("13812345678", "phone", 0, 0), "138****5678");
    }

    #[test]
    fn mask_value_phone_short() {
        // 7 chars: 3+4 = 7 → all stars
        assert_eq!(mask_value("1234567", "phone", 0, 0), "*******");
    }

    #[test]
    fn mask_value_bank_card() {
        // 16 digits: show first 6 + last 4 = "622600******0000"
        assert_eq!(
            mask_value("6217000000000000", "bank_card", 0, 0),
            "621700******0000"
        );
    }

    #[test]
    fn mask_value_id_number() {
        // 18 chars: suffix-only default (0, 4) — leading region code stays hidden.
        assert_eq!(
            mask_value("110101199003074610", "id_number", 0, 0),
            "**************4610"
        );
    }

    #[test]
    fn id_number_default_hides_leading_region_code() {
        // 18-digit Chinese ID; default mask must NOT reveal the leading region code.
        let out = mask_value("110101199003078888", "id_number", 0, 0);
        assert!(!out.starts_with("1101"), "must not reveal the region code");
        assert!(out.ends_with("8888"));
    }

    #[test]
    fn mask_value_email_normal() {
        // "a@b.com" → local="a" (len 1) → visible="a", stars=max(0,3)=3
        assert_eq!(mask_value("a@b.com", "email", 0, 0), "a***@b.com");
    }

    #[test]
    fn mask_value_email_longer_local() {
        // "alice@example.com" → local="alice" (len 5) → visible="a", stars=max(4,3)=4
        assert_eq!(
            mask_value("alice@example.com", "email", 0, 0),
            "a****@example.com"
        );
    }

    #[test]
    fn mask_value_email_no_at() {
        // No valid '@' → fall through to generic mask, not returned verbatim.
        // "notanemail" (10 chars) > 3+4 → "not" + 3 stars + "mail".
        assert_eq!(mask_value("notanemail", "email", 0, 0), "not***mail");
    }

    #[test]
    fn mask_value_email_at_start_masked() {
        // '@' at index 0 → not a valid email; falls through to generic mask.
        // "@b.com" (6 chars) <= 3+4 → all stars.
        assert_eq!(mask_value("@b.com", "email", 0, 0), "******");
    }

    #[test]
    fn email_without_at_is_masked_not_verbatim() {
        let out = mask_value("notanemail", "email", 0, 0);
        assert_ne!(out, "notanemail");
        assert!(out.contains('*'));
    }

    #[test]
    fn mask_value_custom_prefix_suffix() {
        // explicit visible_prefix=2, visible_suffix=2 override defaults
        assert_eq!(mask_value("13812345678", "phone", 2, 2), "13*******78");
    }

    #[test]
    fn mask_value_generic_short() {
        // len <= 3+4 → all stars for unknown type
        assert_eq!(mask_value("1234567", "unknown", 0, 0), "*******");
    }

    // --- mask_name ---

    #[test]
    fn mask_name_single_char() {
        assert_eq!(mask_name("张"), "*");
    }

    #[test]
    fn mask_name_two_chars() {
        assert_eq!(mask_name("张三"), "张*");
    }

    #[test]
    fn mask_name_three_chars() {
        // "欧阳明" → 3 chars → first 1 + 2 stars
        assert_eq!(mask_name("欧阳明"), "欧**");
    }

    #[test]
    fn mask_name_four_plus() {
        // len >= 4: first 2 + (len-2) stars
        assert_eq!(mask_name("欧阳修远"), "欧阳**");
    }

    #[test]
    fn mask_name_empty() {
        assert_eq!(mask_name(""), "");
    }

    // --- mask_landline ---

    #[test]
    fn mask_landline_with_dash() {
        // "010-12345678" → area="010-", number="12345678" (8 chars)
        // masked = "*****" + "678" → "010-*****678"
        assert_eq!(mask_landline("010-12345678"), "010-*****678");
    }

    #[test]
    fn mask_landline_no_dash_short_area() {
        // "01012345678" → value[1]='1' → area_len=3 → area="010", number="12345678"
        assert_eq!(mask_landline("01012345678"), "010*****678");
    }

    #[test]
    fn mask_landline_no_dash_long_area() {
        // "075512345678" → value[1]='7' → area_len=4 → area="0755", number="12345678"
        assert_eq!(mask_landline("075512345678"), "0755*****678");
    }

    #[test]
    fn mask_landline_short_number() {
        // number.len() <= 3 → no masking of number
        assert_eq!(mask_landline("010-123"), "010-123");
    }

    // --- mask_phone_regional ---

    #[test]
    fn mask_phone_regional_cn() {
        assert_eq!(mask_phone_regional("13812345678", "cn"), "138****5678");
    }

    #[test]
    fn mask_phone_regional_hk() {
        // 8-digit HK number
        assert_eq!(mask_phone_regional("90123456", "hk"), "90****56");
    }

    #[test]
    fn mask_phone_regional_tw() {
        // 9-digit TW number
        assert_eq!(mask_phone_regional("912345678", "tw"), "91****678");
    }

    #[test]
    fn mask_phone_regional_default() {
        assert_eq!(mask_phone_regional("1234567890", "us"), "12******90");
    }

    #[test]
    fn mask_phone_regional_strips_dashes() {
        assert_eq!(mask_phone_regional("138-1234-5678", "cn"), "138****5678");
    }

    // --- resolve_collision ---

    #[test]
    fn resolve_collision_no_collision() {
        let used: HashSet<String> = HashSet::new();
        assert_eq!(resolve_collision("张*", &used).unwrap(), "张*");
    }

    #[test]
    fn resolve_collision_first_circled() {
        let mut used = HashSet::new();
        used.insert("张*".to_string());
        assert_eq!(resolve_collision("张*", &used).unwrap(), "张*①");
    }

    #[test]
    fn resolve_collision_second_circled() {
        let mut used = HashSet::new();
        used.insert("张*".to_string());
        used.insert("张*①".to_string());
        assert_eq!(resolve_collision("张*", &used).unwrap(), "张*②");
    }

    #[test]
    fn resolve_collision_all_circled_numeric() {
        let mut used = HashSet::new();
        used.insert("L*".to_string());
        for &c in CIRCLED_DIGITS {
            used.insert(format!("L*{}", c));
        }
        // Should fall through to numeric suffix (21)
        assert_eq!(resolve_collision("L*", &used).unwrap(), "L*(21)");
    }

    #[test]
    fn resolve_collision_saturated_returns_err_not_panic() {
        // Saturate the label plus every circled-digit and numeric suffix.
        // The resolver must return `Err` (a catchable error) rather than panic
        // (which would cross PyO3 as an uncatchable PanicException → DoS).
        let mut used = HashSet::new();
        used.insert("X".to_string());
        for &c in CIRCLED_DIGITS {
            used.insert(format!("X{}", c));
        }
        for i in 21..MAX_NUMERIC_COLLISION_SUFFIX {
            used.insert(format!("X({})", i));
        }
        let out = resolve_collision("X", &used);
        assert!(out.is_err(), "saturated resolve_collision must return Err, got {out:?}");
        assert!(out.unwrap_err().contains("too many collisions"));
    }
}
