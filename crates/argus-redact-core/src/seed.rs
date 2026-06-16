//! Seed derivation helpers — ported from `pure/replacer.py` (lines 77–139).
//!
//! These functions are pure deterministic transformations used by the
//! pseudonym and realistic replacement strategies.

use sha2::{Digest, Sha256};

/// Salt passed to [`pseudonym_seed_int`] and [`resolve_salt`].
#[derive(Debug, Clone)]
pub enum Salt {
    /// Signed integer salt (e.g. `salt=42`).  Stored as i64 to preserve the
    /// Python two's-complement encoding semantics (negatives → big-endian
    /// signed 8-byte representation).
    Int(i64),
    /// Raw bytes salt (e.g. `salt=b"\x00"*8`).
    Bytes(Vec<u8>),
}

// 8-byte boundary for int↔bytes back-compat seed encoding (matches Python `_SALT_INT_BYTES`).
const _SALT_INT_BYTES: usize = 8;

/// Coerce `salt` to an integer seed for `PseudonymGenerator`.
///
/// Mirrors `_pseudonym_seed_int` (replacer.py:105–116):
/// - `None`  → `None`
/// - `Int`   → pass through as u64 bit-pattern (two's-complement reinterpret)
/// - `Bytes` → first 8 bytes interpreted as big-endian u64 (right-padded with 0)
pub fn pseudonym_seed_int(salt: Option<&Salt>) -> Option<u64> {
    match salt {
        None => None,
        Some(Salt::Int(i)) => Some(*i as u64),
        Some(Salt::Bytes(b)) => {
            // Take the first 8 bytes, right-pad with zeros
            let mut buf = [0u8; 8];
            let n = b.len().min(8);
            buf[..n].copy_from_slice(&b[..n]);
            Some(u64::from_be_bytes(buf))
        }
    }
}

/// Stable per-type integer offset for seed derivation.
///
/// Mirrors `_type_seed_offset` (replacer.py:119–128):
/// `SHA256(type_.as_bytes())[:4]` interpreted as big-endian u32, then `% 10_000`.
///
/// SHA-256 is stable across processes (unlike Python's `hash()` which varies
/// with `PYTHONHASHSEED`), guaranteeing "same salt → same fake" in multi-worker
/// deployments.
pub fn type_seed_offset(type_: &str) -> u32 {
    const MOD: u32 = 10_000;
    let digest = Sha256::digest(type_.as_bytes());
    let be = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    be % MOD
}

/// Add `offset` to an optional seed, wrapping at u64 boundary.
///
/// Mirrors `_offset_seed` (replacer.py:131–139).
/// Python: `(seed + offset) % 2**64` ≡ `u64::wrapping_add`.
pub fn offset_seed(seed: Option<u64>, offset: u64) -> Option<u64> {
    seed.map(|s| s.wrapping_add(offset))
}

/// Determine the effective byte-slice salt for HMAC seeding.
///
/// Mirrors `_resolve_salt` (replacer.py:84–102):
/// 1. `Bytes`  → the bytes as-is
/// 2. `Int`    → 8-byte big-endian (signed)
/// 3. `None`   → read `ARGUS_REDACT_PSEUDONYM_SALT` env var (UTF-8)
/// 4. else     → `Err`
pub fn resolve_salt(salt: Option<&Salt>) -> Result<Vec<u8>, String> {
    match salt {
        Some(Salt::Bytes(b)) => Ok(b.clone()),
        Some(Salt::Int(i)) => {
            // Python: salt.to_bytes(8, "big", signed=salt<0)
            // For non-negative: just the u64 big-endian representation.
            // For negative: two's-complement 8-byte big-endian (i64::to_be_bytes).
            Ok(i.to_be_bytes().to_vec())
        }
        None => {
            match std::env::var("ARGUS_REDACT_PSEUDONYM_SALT") {
                Ok(v) if !v.is_empty() => Ok(v.into_bytes()),
                _ => Err(
                    "realistic strategy requires explicit salt: pass `salt=<int>`, \
                     `salt=<bytes>`, or set ARGUS_REDACT_PSEUDONYM_SALT."
                        .to_string(),
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Python-computed reference values (run once, hardcoded):
    //   _type_seed_offset('phone')     == 4357
    //   _type_seed_offset('id_number') == 548
    //   _type_seed_offset('person')    == 1959
    //   _type_seed_offset('email')     == 4807
    #[test]
    fn type_seed_offset_phone() {
        assert_eq!(type_seed_offset("phone"), 4357);
    }

    #[test]
    fn type_seed_offset_id_number() {
        assert_eq!(type_seed_offset("id_number"), 548);
    }

    #[test]
    fn type_seed_offset_ssn() {
        assert_eq!(type_seed_offset("ssn"), 3470);
    }

    #[test]
    fn type_seed_offset_person() {
        assert_eq!(type_seed_offset("person"), 1959);
    }

    #[test]
    fn type_seed_offset_email() {
        assert_eq!(type_seed_offset("email"), 4807);
    }

    #[test]
    fn offset_seed_wrap() {
        // Wrapping add: u64::MAX + 1 == 0
        assert_eq!(offset_seed(Some(u64::MAX), 1), Some(0));
    }

    #[test]
    fn offset_seed_none() {
        assert_eq!(offset_seed(None, 42), None);
    }

    #[test]
    fn offset_seed_normal() {
        assert_eq!(offset_seed(Some(100), 23), Some(123));
    }

    #[test]
    fn pseudonym_seed_int_none() {
        assert_eq!(pseudonym_seed_int(None), None);
    }

    #[test]
    fn pseudonym_seed_int_positive() {
        assert_eq!(pseudonym_seed_int(Some(&Salt::Int(42))), Some(42u64));
    }

    #[test]
    fn pseudonym_seed_int_negative() {
        // -1i64 as u64 == u64::MAX (two's-complement reinterpret)
        assert_eq!(pseudonym_seed_int(Some(&Salt::Int(-1))), Some(u64::MAX));
    }

    #[test]
    fn pseudonym_seed_int_bytes_padded() {
        // b"\x00\x00\x00\x00\x00\x00\x00\x2a" → 42
        let b = vec![0u8, 0, 0, 0, 0, 0, 0, 42];
        assert_eq!(pseudonym_seed_int(Some(&Salt::Bytes(b))), Some(42u64));
    }

    #[test]
    fn pseudonym_seed_int_bytes_short() {
        // b"\x01" right-padded to 8 bytes → 0x0100000000000000
        let b = vec![0x01u8];
        let expected = u64::from_be_bytes([0x01, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(pseudonym_seed_int(Some(&Salt::Bytes(b))), Some(expected));
    }

    #[test]
    fn resolve_salt_bytes() {
        let b = vec![1u8, 2, 3];
        assert_eq!(resolve_salt(Some(&Salt::Bytes(b.clone()))), Ok(b));
    }

    #[test]
    fn resolve_salt_int_positive() {
        // 42i64 → big-endian 8 bytes
        let expected = 42i64.to_be_bytes().to_vec();
        assert_eq!(resolve_salt(Some(&Salt::Int(42))), Ok(expected));
    }

    #[test]
    fn resolve_salt_int_negative() {
        // -1i64 → [0xff; 8] in two's complement big-endian
        let expected = (-1i64).to_be_bytes().to_vec();
        assert_eq!(resolve_salt(Some(&Salt::Int(-1))), Ok(expected));
    }

    #[test]
    fn resolve_salt_none_no_env() {
        // Clear env var to ensure we get an Err.
        // SAFETY: tests run single-threaded in the test harness; no concurrent env reads.
        unsafe { std::env::remove_var("ARGUS_REDACT_PSEUDONYM_SALT") };
        assert!(resolve_salt(None).is_err());
    }

    #[test]
    fn resolve_salt_none_env() {
        // SAFETY: tests run single-threaded in the test harness; no concurrent env reads.
        unsafe { std::env::set_var("ARGUS_REDACT_PSEUDONYM_SALT", "test-salt") };
        let result = resolve_salt(None);
        unsafe { std::env::remove_var("ARGUS_REDACT_PSEUDONYM_SALT") };
        assert_eq!(result, Ok(b"test-salt".to_vec()));
    }
}
