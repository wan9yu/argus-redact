//! `_ShakeRng` — the realistic-faker RNG, ported from `pure/replacer.py:77–193`.
//!
//! Bit-identity with Python is paramount: the realistic strategy derives fake
//! values from this stream, and a single diverging byte changes every fake.
//!
//! Two pieces:
//!
//! 1. [`seed_from_value`] — `HMAC-SHA256(salt, "{type}:{value}")` → 32-byte master
//!    key (mirrors `_seed_from_value`).
//! 2. [`ShakeRng`] — a SHAKE-256 XOF stream RNG (mirrors `_ShakeRng`).
//!
//! ## Why the XOF reader is bit-identical to Python's buffer-doubling
//!
//! Python's `_ShakeRng` pre-computes `shake_256(seed).digest(256)` and re-derives
//! `digest(new_len)` when the buffer is exhausted. SHAKE-256 is an *extendable*
//! output function: `digest(N)` is exactly the first `N` bytes of an infinite
//! squeeze, so `digest(M)[:K] == digest(N)[:K]` for `K ≤ M ≤ N`. The buffer
//! doubling is therefore a pure optimization — the byte *stream* is fixed.
//!
//! Rust's `sha3::Shake256` exposes that same squeeze via an XOF reader. Reading
//! `n` bytes sequentially yields the identical bytes Python would slice out of
//! its buffer, so we read sequentially and skip the buffer machinery entirely.
//! The KDF-replay unit tests below are the proof: they assert the Rust stream
//! reproduces sequences frozen from current Python, byte for byte.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// `HMAC-SHA256(salt, "{type}:{value}")` — the 32-byte master key.
///
/// Mirrors `_seed_from_value` (replacer.py:77–81). The message is the UTF-8
/// encoding of `"{type_}:{value}"`; the salt is the HMAC key (any length).
pub fn seed_from_value(value: &str, type_: &str, salt: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC accepts any key length");
    // Disambiguate: both `hmac::Mac` and `sha3::digest::Update` (in scope for
    // the XOF) provide an `update` method.
    Mac::update(&mut mac, format!("{type_}:{value}").as_bytes());
    mac.finalize().into_bytes().into()
}

/// SHAKE-256 XOF stream RNG (mirrors `_ShakeRng`).
///
/// Exposes only the `random.Random` subset the fakers use: [`ShakeRng::randint`],
/// [`ShakeRng::choice_index`], and [`ShakeRng::rand_digits`]. Output is uniform
/// via rejection sampling (no modulo bias).
pub struct ShakeRng {
    reader: sha3::Shake256Reader,
}

impl ShakeRng {
    /// Seed the stream. Mirrors `_ShakeRng.__init__` — the seed feeds SHAKE-256
    /// and the squeeze is read on demand.
    pub fn new(seed: &[u8]) -> Self {
        let mut h = Shake256::default();
        h.update(seed);
        Self {
            reader: h.finalize_xof(),
        }
    }

    /// Read `n` bytes from the XOF stream. Mirrors `_take` — but without the
    /// buffer doubling, because the sequential reads are byte-identical to the
    /// Python buffer slices (see module docs).
    fn take(&mut self, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        self.reader.read(&mut buf);
        buf
    }

    /// Uniform integer in `[a, b]` via rejection sampling.
    ///
    /// Mirrors `_ShakeRng.randint` (replacer.py:176–187). The byte consumption
    /// per call — including rejection-sampling re-reads — MUST match Python
    /// exactly, so the rest of the stream stays aligned. We compute
    /// `bytes_needed`, `max_unbiased`, and read big-endian identically.
    ///
    /// `u128` is used for the bound math so `bytes_needed == 8` (range up to
    /// `2^64`) cannot overflow.
    pub fn randint(&mut self, a: i64, b: i64) -> i64 {
        assert!(b >= a, "randint: empty range [{a}, {b}]");
        // rng = b - a + 1, computed in i128 to avoid i64 overflow at the extremes.
        let rng = (b as i128 - a as i128 + 1) as u128;
        // bytes_needed = max(1, ((rng - 1).bit_length() + 7) // 8)
        let bits = 128 - (rng - 1).leading_zeros(); // (rng - 1).bit_length()
        let bytes_needed = std::cmp::max(1, ((bits + 7) / 8) as usize);
        // max_unbiased = (1 << (bytes_needed*8)) - ((1 << (bytes_needed*8)) % rng)
        let space: u128 = 1u128 << (bytes_needed * 8);
        let max_unbiased = space - (space % rng);
        loop {
            let bytes = self.take(bytes_needed);
            let mut n: u128 = 0;
            for byte in &bytes {
                n = (n << 8) | (*byte as u128); // big-endian
            }
            if n < max_unbiased {
                return a + (n % rng) as i64;
            }
        }
    }

    /// Uniform index into a sequence of length `len`. Mirrors `choice`
    /// (replacer.py:189–193): `randint(0, len - 1)`.
    pub fn choice_index(&mut self, len: usize) -> usize {
        assert!(len > 0, "choice from empty sequence");
        self.randint(0, len as i64 - 1) as usize
    }

    /// `n` random ASCII digits, joined. Mirrors the benchmark generators'
    /// `_fakers_util.rand_digits` (`tests/benchmark/generators/`): `n ×`
    /// `randint(0, 9)`.
    pub fn rand_digits(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| char::from(b'0' + self.randint(0, 9) as u8))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── KDF-replay vectors ────────────────────────────────────────────────
    // FROZEN from current Python (`pure.replacer._ShakeRng` + `_seed_from_value`).
    // These are the bit-identity ground truth. If any assertion fails, the XOF
    // stream or the randint byte-consumption has diverged from Python — that is
    // a real bug, NOT a vector to "fix" to match Rust.
    //
    // Generated by:
    //   PYTHONPATH=src python3 -c "
    //   from argus_redact.pure.replacer import _ShakeRng, _seed_from_value
    //   seed = _seed_from_value('Alice', 'person', bytes(8))
    //   print(seed.hex())
    //   r = _ShakeRng(seed); print([r.randint(0,9) for _ in range(20)])
    //   ... (mixed ranges, second seed) ..."

    // Seed 1: _seed_from_value("Alice", "person", &[0u8; 8])
    const SEED1_HEX: &str = "a2e1895de10e12dc452f7e3bde7d98219e1e0ed794726117688a80cbd8b5aff6";
    const SEED1_RANDINT_0_9: [i64; 20] =
        [5, 2, 3, 2, 3, 2, 8, 7, 8, 3, 3, 3, 8, 0, 6, 7, 5, 7, 0, 8];
    // 5×randint(1960,2005) + 5×randint(0,999) + 5×randint(1,28), fresh stream
    const SEED1_RANDINT_MIXED: [i64; 15] = [
        1966, 1975, 1978, 1961, 1976, 765, 111, 591, 628, 803, 24, 4, 15, 17, 21,
    ];

    // Seed 2: _seed_from_value("测试", "phone", &42u64.to_be_bytes())
    const SEED2_HEX: &str = "cf18e5b4d4c6218f4edbb1529ab55e98efff4e32f95cd2f4c1a758017bcca4f7";
    const SEED2_RANDINT_0_9: [i64; 20] =
        [1, 5, 1, 2, 6, 8, 0, 2, 0, 6, 3, 9, 2, 7, 6, 9, 8, 3, 6, 2];
    const SEED2_RANDINT_MIXED: [i64; 15] = [
        2001, 1989, 1985, 2000, 1978, 122, 426, 177, 709, 695, 25, 6, 23, 5, 24,
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn seed_from_value_matches_python_hmac_seed1() {
        let seed = seed_from_value("Alice", "person", &[0u8; 8]);
        assert_eq!(hex(&seed), SEED1_HEX);
    }

    #[test]
    fn seed_from_value_matches_python_hmac_seed2() {
        // salt = (42).to_bytes(8, "big")
        let seed = seed_from_value("测试", "phone", &42u64.to_be_bytes());
        assert_eq!(hex(&seed), SEED2_HEX);
    }

    #[test]
    fn shake_rng_randint_0_9_seed1() {
        let seed = seed_from_value("Alice", "person", &[0u8; 8]);
        let mut r = ShakeRng::new(&seed);
        let got: Vec<i64> = (0..20).map(|_| r.randint(0, 9)).collect();
        assert_eq!(got, SEED1_RANDINT_0_9);
    }

    #[test]
    fn shake_rng_randint_mixed_seed1() {
        let seed = seed_from_value("Alice", "person", &[0u8; 8]);
        let mut r = ShakeRng::new(&seed);
        let mut got: Vec<i64> = (0..5).map(|_| r.randint(1960, 2005)).collect();
        got.extend((0..5).map(|_| r.randint(0, 999)));
        got.extend((0..5).map(|_| r.randint(1, 28)));
        assert_eq!(got, SEED1_RANDINT_MIXED);
    }

    #[test]
    fn shake_rng_randint_0_9_seed2() {
        let seed = seed_from_value("测试", "phone", &42u64.to_be_bytes());
        let mut r = ShakeRng::new(&seed);
        let got: Vec<i64> = (0..20).map(|_| r.randint(0, 9)).collect();
        assert_eq!(got, SEED2_RANDINT_0_9);
    }

    #[test]
    fn shake_rng_randint_mixed_seed2() {
        let seed = seed_from_value("测试", "phone", &42u64.to_be_bytes());
        let mut r = ShakeRng::new(&seed);
        // ranges mirror Python exactly: 1960..=2005, 0..=999, 1..=28
        let mut got: Vec<i64> = (0..5).map(|_| r.randint(1960, 2005)).collect();
        got.extend((0..5).map(|_| r.randint(0, 999)));
        got.extend((0..5).map(|_| r.randint(1, 28)));
        assert_eq!(got, SEED2_RANDINT_MIXED);
    }

    #[test]
    fn rand_digits_matches_randint_stream() {
        // rand_digits(6) == first 6 of randint(0,9) joined as ASCII.
        let seed = seed_from_value("Alice", "person", &[0u8; 8]);
        let mut r = ShakeRng::new(&seed);
        assert_eq!(r.rand_digits(6), "523232");
    }

    #[test]
    fn choice_index_is_randint_0_len_minus_1() {
        // choice_index(10) must equal randint(0, 9) on a fresh stream.
        let seed = seed_from_value("Alice", "person", &[0u8; 8]);
        let mut a = ShakeRng::new(&seed);
        let mut b = ShakeRng::new(&seed);
        for _ in 0..10 {
            assert_eq!(a.choice_index(10) as i64, b.randint(0, 9));
        }
    }
}
