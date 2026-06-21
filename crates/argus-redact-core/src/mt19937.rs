//! CPython-exact MT19937 — the seeded pseudonym RNG, ported from CPython's
//! `_randommodule.c` + `random.py` so the `P-NNNNN` code stream is byte-identical
//! with NO CPython dependency.
//!
//! This is a **precision parity port**: it reproduces `random.Random(seed)` for an
//! INTEGER seed exactly. It is the single seeded [`RandomSource`] used by BOTH the
//! PyO3 binding (replacing its former live `random.Random(seed).randint` call) AND
//! the wasm crate (replacing the SHAKE stream that produced divergent codes). One
//! implementation, one stream, true wasm↔Python parity.
//!
//! ## What is matched (and where it lives in CPython)
//!
//! - **MT19937 core** (`genrand_uint32`, `_randommodule.c`): n=624, m=397, the
//!   standard tempering / twist constants.
//! - **Integer seeding** (`random_seed`, `_randommodule.c`): a Python int is
//!   reduced via `init_by_array` over its absolute value's 32-bit little-endian
//!   words. The argus seed reaches us as a `u64`, which is always non-negative, so
//!   the abs() is a no-op here — but we take the words of the magnitude exactly as
//!   CPython does (`init_genrand(19650218)` then the `init_by_array` mixing). A
//!   seed of `0` yields the key array `[0]` (length 1), matching CPython.
//! - **`getrandbits(k)`** (`random_getrandbits`, `_randommodule.c`): pulls
//!   `ceil(k/32)` 32-bit words; for the final word, when `k % 32 != 0` the word is
//!   right-shifted by `32 - (k % 32)`; words are assembled little-endian.
//! - **`randint(a, b)`** = `randrange(a, b+1)` = `a + _randbelow(b - a + 1)`
//!   (`random.py`). `_randbelow_with_getrandbits(n)`: `k = n.bit_length()`; loop
//!   `r = getrandbits(k)` while `r >= n`; return `r`. (`n == 0` → `0`.)
//!
//! The CPython-parity oracle test (`mod tests`) pins this against captured
//! `random.Random(seed).randint(...)` / `.getrandbits(...)` sequences across a seed
//! and range sweep, so any drift from CPython fails loudly.

use crate::pseudonym::RandomSource;

const N: usize = 624;
const M: usize = 397;
const MATRIX_A: u32 = 0x9908_b0df;
const UPPER_MASK: u32 = 0x8000_0000;
const LOWER_MASK: u32 = 0x7fff_ffff;

/// MT19937 generator state — the `n=624` word vector plus the position index.
/// Mirrors CPython's `RandomObject` (`state[N]`, `index`).
#[derive(Clone)]
pub struct Mt19937 {
    state: [u32; N],
    index: usize,
}

impl Mt19937 {
    /// Seed from a Python integer, given as its 32-bit little-endian magnitude
    /// words (`init_key`). An empty slice is treated as `[0]` (the `seed == 0`
    /// case in CPython, where `bits == 0` yields a 1-element key array).
    ///
    /// Mirrors `init_by_array` (`_randommodule.c`).
    fn from_key(init_key: &[u32]) -> Self {
        let mut mt = Self::init_genrand(19_650_218);

        // CPython always passes key_length >= 1 (a 0 seed → key = [0]).
        let key: &[u32] = if init_key.is_empty() { &[0] } else { init_key };
        let key_length = key.len();

        let mut i: usize = 1;
        let mut j: usize = 0;
        let mut k = if N > key_length { N } else { key_length };

        while k > 0 {
            // mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525)) + key[j] + j
            let prev = mt.state[i - 1];
            mt.state[i] = (mt.state[i]
                ^ ((prev ^ (prev >> 30)).wrapping_mul(1_664_525)))
            .wrapping_add(key[j])
            .wrapping_add(j as u32);
            i += 1;
            j += 1;
            if i >= N {
                mt.state[0] = mt.state[N - 1];
                i = 1;
            }
            if j >= key_length {
                j = 0;
            }
            k -= 1;
        }

        k = N - 1;
        while k > 0 {
            // mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941)) - i
            let prev = mt.state[i - 1];
            mt.state[i] = (mt.state[i]
                ^ ((prev ^ (prev >> 30)).wrapping_mul(1_566_083_941)))
            .wrapping_sub(i as u32);
            i += 1;
            if i >= N {
                mt.state[0] = mt.state[N - 1];
                i = 1;
            }
            k -= 1;
        }

        // MSB is 1; assuring non-zero initial array.
        mt.state[0] = 0x8000_0000;
        mt
    }

    /// `init_genrand(s)` (`_randommodule.c`) — the linear seeding used as the base
    /// state before `init_by_array` mixing.
    fn init_genrand(s: u32) -> Self {
        let mut state = [0u32; N];
        state[0] = s;
        for i in 1..N {
            let prev = state[i - 1];
            // mt[i] = 1812433253 * (mt[i-1] ^ (mt[i-1] >> 30)) + i
            state[i] = 1_812_433_253u32
                .wrapping_mul(prev ^ (prev >> 30))
                .wrapping_add(i as u32);
        }
        Self { state, index: N }
    }

    /// `genrand_uint32` (`_randommodule.c`) — one 32-bit output word, regenerating
    /// the state vector (the twist) when exhausted.
    fn genrand_uint32(&mut self) -> u32 {
        if self.index >= N {
            // Generate N words at one time (the twist).
            for kk in 0..(N - M) {
                let y = (self.state[kk] & UPPER_MASK) | (self.state[kk + 1] & LOWER_MASK);
                self.state[kk] =
                    self.state[kk + M] ^ (y >> 1) ^ if y & 1 != 0 { MATRIX_A } else { 0 };
            }
            for kk in (N - M)..(N - 1) {
                let y = (self.state[kk] & UPPER_MASK) | (self.state[kk + 1] & LOWER_MASK);
                self.state[kk] = self.state[kk + M - N]
                    ^ (y >> 1)
                    ^ if y & 1 != 0 { MATRIX_A } else { 0 };
            }
            let y = (self.state[N - 1] & UPPER_MASK) | (self.state[0] & LOWER_MASK);
            self.state[N - 1] = self.state[M - 1] ^ (y >> 1) ^ if y & 1 != 0 { MATRIX_A } else { 0 };

            self.index = 0;
        }

        let mut y = self.state[self.index];
        self.index += 1;

        // Tempering.
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^= y >> 18;
        y
    }

    /// `random_getrandbits(k)` (`_randommodule.c`). For `k == 0` CPython returns 0
    /// (it allocates 0 words); we mirror that. Result fits a `u128` for the bit
    /// widths the pseudonym/randint path uses (k up to 64 in practice; `u128`
    /// gives headroom and exact little-endian assembly).
    pub fn getrandbits(&mut self, k: u32) -> u128 {
        if k == 0 {
            return 0;
        }
        // words = (k - 1) / 32 + 1  == ceil(k / 32)
        let words = ((k - 1) / 32 + 1) as usize;
        let mut result: u128 = 0;
        let mut shift = 0u32;
        for i in 0..words {
            let mut r = self.genrand_uint32();
            // The last (most-significant) word is right-shifted to drop the bits
            // beyond k when k is not a multiple of 32.
            if i == words - 1 {
                let rem = k % 32;
                if rem != 0 {
                    r >>= 32 - rem;
                }
            }
            result |= (r as u128) << shift;
            shift += 32;
        }
        result
    }

    /// `_randbelow_with_getrandbits(n)` (`random.py`): a uniform int in `[0, n)`
    /// via rejection sampling on `getrandbits(n.bit_length())`. `n == 0` → 0
    /// (matches the `randrange` width==0 guard the pseudonym path never hits, but
    /// kept defensive — and what the trait contract on `randint` with `lo==hi`
    /// implies: `n == 1`, bit_length 1, always returns 0).
    fn randbelow(&mut self, n: u128) -> u128 {
        if n == 0 {
            return 0;
        }
        // n.bit_length(): number of bits to represent n (n >= 1 here).
        let k = 128 - n.leading_zeros();
        loop {
            let r = self.getrandbits(k);
            if r < n {
                return r;
            }
        }
    }
}

/// A core [`RandomSource`] backed by CPython-exact MT19937 — the seeded pseudonym
/// stream. `use_secrets()` is always `false` (this is the seeded path; the
/// unseeded `secrets` path stays binding-specific). `randbelow` is implemented for
/// trait completeness but, with `use_secrets() == false`, the generator never
/// routes through it.
pub struct MtRandomSource {
    mt: Mt19937,
}

impl MtRandomSource {
    /// Seed `random.Random(seed)` for a `u64` seed. The seed is non-negative
    /// (argus threads a `u64` derived from the salt + per-type offset), so the
    /// magnitude == the value. We split it into 32-bit little-endian words (the
    /// `init_by_array` key); a `0` seed produces an empty word list, which
    /// `from_key` normalizes to `[0]` exactly as CPython's `random_seed` does.
    pub fn for_seed(seed: u64) -> Self {
        let key = u64_to_key(seed);
        Self { mt: Mt19937::from_key(&key) }
    }
}

/// Split a `u64` into its 32-bit little-endian words with no trailing-zero word
/// (matching CPython's bignum → `uint32` array conversion, which carries only the
/// significant words). `0` → empty (callers treat empty as `[0]`).
fn u64_to_key(seed: u64) -> Vec<u32> {
    if seed == 0 {
        return Vec::new();
    }
    let mut words = Vec::new();
    let mut s = seed;
    while s != 0 {
        words.push((s & 0xffff_ffff) as u32);
        s >>= 32;
    }
    words
}

impl RandomSource for MtRandomSource {
    fn randint(&mut self, lo: u32, hi: u32) -> u32 {
        // randint(lo, hi) = randrange(lo, hi+1) = lo + _randbelow(hi - lo + 1).
        let n = (hi as u128) - (lo as u128) + 1;
        (lo as u128 + self.mt.randbelow(n)) as u32
    }

    fn randbelow(&mut self, range: u32) -> u32 {
        self.mt.randbelow(range as u128) as u32
    }

    fn use_secrets(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CPython-parity oracle ────────────────────────────────────────────────
    //
    // Captured from CPython 3.11 via:
    //   python3 -c "import random; r=random.Random(SEED); print([r.randint(LO,HI) for _ in range(N)])"
    //   python3 -c "import random; r=random.Random(SEED); print([r.getrandbits(K) for _ in range(N)])"
    //
    // Seed sweep covers: 0, 1, 42, 2^32-1, 2^32 (first multi-word boundary), a
    // 128-bit multi-word int, u64::MAX (the `salt=-1` reinterpret), 2001 (a real
    // argus offset seed = 42 + person offset 1959), and 100_000_000. Ranges cover
    // small (0,9), power-of-two boundaries (0,255)/(0,256), and the P-NNNNN
    // 5-digit ranges (1,99999) and (10000,99999). N = 24 draws each.

    /// (seed, lo, hi, expected) — `random.Random(seed).randint(lo, hi)` × N.
    #[rustfmt::skip]
    const RANDINT_CASES: &[(u128, u32, u32, &[u32])] = &[
        (0, 0, 9, &[6, 6, 0, 4, 8, 7, 6, 4, 7, 5, 9, 3, 8, 2, 4, 2, 1, 9, 4, 8, 9, 2, 4, 1]),
        (0, 0, 255, &[197, 215, 20, 132, 248, 207, 155, 244, 183, 111, 71, 144, 71, 48, 128, 75, 158, 50, 37, 169, 241, 51, 181, 222]),
        (0, 0, 256, &[197, 215, 20, 132, 248, 207, 155, 244, 183, 111, 71, 144, 71, 48, 128, 75, 158, 50, 37, 169, 241, 51, 181, 222]),
        (0, 1, 99999, &[50495, 99347, 55126, 5307, 33937, 67014, 63692, 53076, 39756, 62469, 46931, 76466, 28632, 66151, 18255, 36942, 18317, 99065, 12430, 81051, 32835, 69805, 92429, 78893]),
        (0, 10000, 99999, &[60494, 65125, 15306, 43936, 77013, 73691, 63075, 49755, 72468, 56930, 86465, 38631, 76150, 28254, 46941, 28316, 22429, 91050, 42834, 79804, 88892, 29262, 50651, 22945]),
        (1, 0, 9, &[2, 9, 1, 4, 1, 7, 7, 7, 6, 3, 1, 7, 0, 6, 6, 9, 0, 7, 4, 3, 9, 1, 5, 0]),
        (1, 0, 255, &[68, 32, 130, 60, 253, 230, 241, 194, 107, 48, 249, 14, 199, 221, 1, 228, 136, 117, 52, 162, 15, 11, 13, 4]),
        (1, 0, 256, &[68, 32, 130, 60, 253, 230, 241, 194, 107, 48, 249, 14, 199, 221, 1, 228, 136, 117, 52, 162, 15, 11, 13, 4]),
        (1, 1, 99999, &[17612, 74607, 8272, 33433, 15456, 64938, 99741, 58916, 61899, 85406, 49757, 27520, 12303, 63945, 3716, 51094, 56724, 79619, 99914, 277, 91205, 58378, 34909, 94574]),
        (1, 10000, 99999, &[27611, 84606, 18271, 43432, 25455, 74937, 68915, 71898, 95405, 59756, 37519, 22302, 73944, 13715, 61093, 66723, 89618, 10276, 68377, 44908, 39984, 87483, 23399, 51606]),
        (42, 0, 9, &[1, 0, 4, 3, 3, 2, 1, 8, 1, 9, 6, 0, 0, 1, 3, 3, 8, 9, 0, 8, 3, 8, 6, 3]),
        (42, 0, 255, &[57, 12, 140, 125, 114, 71, 52, 44, 216, 16, 15, 47, 111, 119, 13, 101, 214, 112, 229, 142, 3, 81, 216, 174]),
        (42, 0, 256, &[57, 12, 140, 125, 114, 71, 52, 44, 216, 16, 15, 47, 111, 119, 13, 101, 214, 112, 229, 142, 3, 81, 216, 174]),
        (42, 1, 99999, &[83811, 14593, 3279, 97197, 36049, 32099, 29257, 18290, 96531, 13435, 88697, 97081, 71483, 11396, 77398, 55303, 4166, 3906, 12281, 28658, 30496, 66238, 78908, 3479]),
        (42, 10000, 99999, &[93810, 24592, 13278, 46048, 42098, 39256, 28289, 23434, 98696, 81482, 21395, 87397, 65302, 14165, 13905, 22280, 38657, 40495, 76237, 88907, 13478, 83563, 36062, 95181]),
        (4294967295, 0, 9, &[9, 3, 3, 9, 8, 4, 9, 5, 6, 4, 5, 7, 6, 1, 3, 9, 2, 7, 8, 5, 2, 0, 5, 0]),
        (4294967295, 0, 255, &[104, 110, 149, 174, 195, 143, 181, 254, 210, 32, 111, 70, 244, 187, 83, 31, 169, 19, 193, 224, 131, 35, 0, 230]),
        (4294967295, 0, 256, &[104, 110, 149, 174, 195, 143, 181, 254, 210, 32, 111, 70, 244, 187, 83, 31, 169, 19, 193, 224, 131, 35, 0, 230]),
        (4294967295, 1, 99999, &[83278, 81209, 26634, 28226, 79609, 68472, 38186, 79044, 44569, 49954, 88128, 90253, 36656, 46542, 65173, 53798, 8425, 28440, 80008, 18069, 62563, 66159, 47912, 21324]),
        (4294967295, 10000, 99999, &[93277, 91208, 36633, 38225, 89608, 78471, 48185, 89043, 54568, 59953, 98127, 46655, 56541, 75172, 63797, 18424, 38439, 90007, 28068, 72562, 76158, 57911, 31323, 18184]),
        (4294967296, 0, 9, &[1, 5, 6, 0, 0, 9, 5, 8, 7, 0, 2, 1, 6, 8, 5, 5, 6, 7, 7, 2, 1, 4, 2, 8]),
        (4294967296, 0, 255, &[57, 179, 213, 8, 11, 169, 231, 7, 70, 38, 221, 160, 175, 195, 245, 236, 82, 60, 159, 70, 143, 180, 77, 93]),
        (4294967296, 0, 256, &[57, 179, 213, 8, 11, 169, 231, 7, 70, 38, 221, 256, 160, 175, 195, 245, 236, 82, 60, 159, 70, 143, 180, 77]),
        (4294967296, 1, 99999, &[14811, 46048, 54766, 2186, 2992, 80180, 99921, 43452, 71514, 59221, 1835, 18100, 9932, 56776, 65679, 41178, 44918, 96607, 49980, 62803, 60587, 21123, 90655, 15477]),
        (4294967296, 10000, 99999, &[24810, 56047, 64765, 12185, 12991, 90179, 53451, 81513, 69220, 11834, 28099, 19931, 66775, 75678, 51177, 54917, 59979, 72802, 70586, 31122, 25476, 96688, 50731, 28068]),
        (24197857203266734881846307747534221840, 0, 9, &[9, 0, 2, 9, 7, 2, 4, 8, 3, 3, 4, 9, 7, 8, 9, 2, 6, 9, 8, 6, 8, 3, 9, 3]),
        (24197857203266734881846307747534221840, 0, 255, &[8, 86, 249, 95, 131, 111, 97, 142, 235, 92, 200, 212, 107, 112, 40, 173, 244, 235, 6, 56, 141, 186, 61, 144]),
        (24197857203266734881846307747534221840, 0, 256, &[8, 86, 249, 95, 131, 111, 97, 142, 235, 92, 200, 212, 107, 112, 40, 173, 244, 235, 6, 56, 141, 186, 61, 144]),
        (24197857203266734881846307747534221840, 1, 99999, &[87600, 78050, 2171, 22272, 84452, 85211, 80577, 63997, 24408, 33766, 73193, 28632, 25038, 36432, 80128, 60248, 72425, 92650, 75301, 23752, 51250, 93656, 96406, 75028]),
        (24197857203266734881846307747534221840, 10000, 99999, &[97599, 88049, 12170, 32271, 94451, 95210, 90576, 73996, 34407, 43765, 83192, 38631, 35037, 46431, 90127, 70247, 82424, 85300, 33751, 61249, 85027, 80203, 64388, 94801]),
        (18446744073709551615, 0, 9, &[0, 3, 5, 9, 3, 7, 9, 1, 5, 0, 3, 8, 7, 1, 5, 7, 4, 4, 9, 0, 5, 4, 4, 9]),
        (18446744073709551615, 0, 255, &[11, 127, 173, 108, 233, 48, 189, 27, 98, 240, 40, 168, 247, 134, 142, 18, 160, 150, 151, 148, 255, 191, 72, 181]),
        (18446744073709551615, 0, 256, &[11, 127, 173, 108, 233, 48, 189, 27, 98, 240, 40, 168, 247, 134, 142, 18, 160, 150, 151, 148, 255, 191, 72, 181]),
        (18446744073709551615, 1, 99999, &[2861, 32608, 44315, 81101, 27784, 59778, 80626, 12455, 48634, 95960, 91167, 97325, 7125, 96617, 25238, 95679, 69782, 61566, 86302, 10255, 43230, 63363, 34358, 36432]),
        (18446744073709551615, 10000, 99999, &[12860, 42607, 54314, 91100, 37783, 69777, 90625, 22454, 58633, 17124, 35237, 79781, 71565, 96301, 20254, 53229, 73362, 44357, 46431, 87288, 14807, 51173, 48613, 48826]),
        (2001, 0, 9, &[9, 0, 5, 0, 1, 9, 9, 0, 9, 2, 9, 0, 4, 7, 2, 1, 6, 1, 5, 2, 6, 7, 5, 4]),
        (2001, 0, 255, &[11, 185, 26, 44, 21, 87, 29, 129, 237, 77, 32, 221, 43, 181, 87, 223, 246, 180, 154, 192, 213, 82, 241, 194]),
        (2001, 0, 256, &[11, 185, 26, 44, 21, 87, 29, 129, 237, 77, 32, 221, 43, 181, 87, 223, 246, 180, 154, 192, 213, 82, 241, 194]),
        (2001, 1, 99999, &[76865, 2841, 47508, 6907, 11369, 85347, 78837, 77751, 5617, 74568, 97719, 92100, 82272, 22322, 81277, 7493, 33154, 60688, 19888, 8359, 84115, 56699, 11198, 46384]),
        (2001, 10000, 99999, &[86864, 12840, 57507, 16906, 21368, 95346, 88836, 87750, 15616, 84567, 92271, 32321, 91276, 17492, 43153, 70687, 29887, 18358, 94114, 66698, 21197, 56383, 32466, 67113]),
        (100000000, 0, 9, &[9, 6, 7, 2, 7, 0, 7, 7, 0, 8, 3, 0, 0, 2, 2, 8, 1, 8, 4, 1, 7, 4, 8, 2]),
        (100000000, 0, 255, &[203, 248, 94, 245, 23, 250, 253, 18, 101, 21, 11, 69, 66, 54, 129, 61, 234, 134, 84, 109, 12, 160, 114, 131]),
        (100000000, 0, 256, &[203, 248, 94, 245, 23, 250, 253, 18, 101, 21, 11, 69, 66, 54, 129, 61, 234, 134, 84, 109, 12, 160, 114, 131]),
        (100000000, 1, 99999, &[75816, 98870, 90387, 52012, 83005, 63658, 24307, 62939, 6134, 64001, 64798, 4735, 67137, 25987, 5561, 2989, 89861, 17790, 17059, 89025, 66547, 14017, 73251, 33136]),
        (100000000, 10000, 99999, &[85815, 62011, 93004, 73657, 34306, 72938, 16133, 74000, 74797, 14734, 77136, 35986, 15560, 12988, 99860, 27789, 27058, 99024, 76546, 24016, 83250, 43135, 25669, 70105]),
    ];

    /// (seed, k, expected) — `random.Random(seed).getrandbits(k)` × N. Exercises
    /// k < 32, k == 32, k > 32 (multi-word), and k not a multiple of 32 (the
    /// final-word shift). Values fit u128.
    #[rustfmt::skip]
    const GETRANDBITS_CASES: &[(u128, u32, &[u128])] = &[
        (0, 1, &[1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1]),
        (0, 7, &[108, 49, 97, 113, 53, 5, 33, 123, 65, 62, 51, 117]),
        (0, 17, &[110680, 50494, 99346, 116686, 55125, 5306, 33936, 126545, 67013, 63691, 53075, 120354]),
        (0, 32, &[3626764237, 1654615998, 3255389356, 3823568514, 1806341205, 173879092, 1112038970, 4146640122, 2195908194, 2087043557, 1739178872, 3943786419]),
        (0, 33, &[3626764237, 7550356652, 1806341205, 5407006266, 2195908194, 6034146168, 7661356601, 5597685513, 2046968324, 6800574079, 3900315155, 2167613558]),
        (0, 40, &[424533559245, 978212965548, 44756014165, 1061968961082, 534771852898, 1011056493432, 913899456057, 1062159640329, 392888992260, 981758150271, 240123516435, 152491468918]),
        (0, 64, &[7106521602475165645, 16422101724900707500, 746805015404516437, 17809683713383489082, 8963783824838420066, 16938433693753131896, 15308084094301570617, 17852758786694309641, 6604845167042249220, 16448235973081859711, 4029557120079369747, 2569146471088859254]),
        (42, 1, &[1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1]),
        (42, 7, &[81, 14, 3, 94, 35, 31, 28, 17, 94, 13, 86, 94]),
        (42, 17, &[83810, 14592, 3278, 97196, 36048, 32098, 29256, 18289, 96530, 13434, 88696, 97080]),
        (42, 32, &[2746317213, 478163327, 107420369, 3184935163, 1181241943, 1051802512, 958682846, 599310825, 3163119785, 440213415, 2906402157, 3181143731]),
        (42, 33, &[2746317213, 4402387665, 1181241943, 958682846, 3163119785, 7201369453, 8126849360, 4668366722, 1812140441, 127978094, 939042955, 6465451729]),
        (42, 40, &[123005401501, 811856239313, 267469214295, 151282538206, 114832269481, 814655221101, 600832336208, 648913461122, 36171878809, 98912225902, 254342113419, 663595448017]),
        (42, 64, &[2053695854357871005, 13679192365072849617, 4517457392071889495, 2574020394472462046, 1890702223848595625, 13662908291426823533, 10060236952204337488, 10892664235628797826, 586287033698423193, 1728372192399379054, 4291835990902352011, 11105285438068160209]),
        (18446744073709551615, 1, &[0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1]),
        (18446744073709551615, 7, &[2, 31, 43, 79, 27, 58, 78, 12, 117, 115, 47, 98]),
        (18446744073709551615, 17, &[2860, 32607, 44314, 81100, 27783, 59777, 80625, 12454, 120530, 118071, 48633, 100662]),
        (18446744073709551615, 32, &[93740670, 1068495656, 1452108352, 2657516307, 910393425, 1958779474, 2641946051, 408097150, 3949527284, 3868957638, 1593622763, 3298503726]),
        (18446744073709551615, 33, &[93740670, 5747075648, 910393425, 2641946051, 8244494580, 5888590059, 7439366323, 3189129643, 3165929296, 7430163874, 6312341588, 8068338922]),
        (18446744073709551615, 40, &[270676680318, 680056941120, 499126599761, 105721161155, 991792005364, 843407212779, 767648577715, 59023704491, 213619326800, 587250748834, 723571880020, 1047450424554]),
        (18446744073709551615, 64, &[4589153898531806846, 11413945628603804224, 8412893781816475729, 1752763915482752451, 16617046528768934132, 14166965630497767659, 12830555127327471795, 1002642564908990891, 3551897395286785872, 9820843617686605218, 12145808473019297876, 17519960284706968810]),
    ];

    // The seed sweep contains multi-word ints (2^32, 128-bit, u64::MAX). Argus
    // only ever threads a `u64` seed, so the public `MtRandomSource::for_seed`
    // takes a `u64`. To exercise the > u64 case (the 128-bit literal) against the
    // CPython oracle, the test seeds the raw `Mt19937` directly from the int's
    // little-endian 32-bit words. This is the same conversion CPython performs.
    fn key_from_u128(seed: u128) -> Vec<u32> {
        if seed == 0 {
            return Vec::new();
        }
        let mut words = Vec::new();
        let mut s = seed;
        while s != 0 {
            words.push((s & 0xffff_ffff) as u32);
            s >>= 32;
        }
        words
    }

    fn mt_for_seed_u128(seed: u128) -> Mt19937 {
        Mt19937::from_key(&key_from_u128(seed))
    }

    #[test]
    fn randint_matches_cpython() {
        for &(seed, lo, hi, expected) in RANDINT_CASES {
            let mut mt = mt_for_seed_u128(seed);
            let n = (hi as u128) - (lo as u128) + 1;
            let got: Vec<u32> = (0..expected.len())
                .map(|_| (lo as u128 + mt.randbelow(n)) as u32)
                .collect();
            assert_eq!(
                got, expected,
                "randint mismatch: seed={seed} lo={lo} hi={hi}"
            );
        }
    }

    #[test]
    fn getrandbits_matches_cpython() {
        for &(seed, k, expected) in GETRANDBITS_CASES {
            let mut mt = mt_for_seed_u128(seed);
            let got: Vec<u128> = (0..expected.len()).map(|_| mt.getrandbits(k)).collect();
            assert_eq!(got, expected, "getrandbits mismatch: seed={seed} k={k}");
        }
    }

    #[test]
    fn mt_random_source_randint_matches_cpython_for_u64_seeds() {
        // The public u64-seeded entry point must reproduce CPython for every seed
        // in the sweep that fits a u64 (the 128-bit literal is skipped).
        for &(seed, lo, hi, expected) in RANDINT_CASES {
            if seed > u64::MAX as u128 {
                continue;
            }
            let mut src = MtRandomSource::for_seed(seed as u64);
            let got: Vec<u32> = (0..expected.len()).map(|_| src.randint(lo, hi)).collect();
            assert_eq!(got, expected, "MtRandomSource mismatch: seed={seed} lo={lo} hi={hi}");
        }
    }

    #[test]
    fn use_secrets_is_false() {
        // The seeded source is always the deterministic MT path.
        let src = MtRandomSource::for_seed(42);
        assert!(!src.use_secrets());
    }

    #[test]
    fn lo_equals_hi_returns_lo() {
        // randint(x, x) → n == 1, bit_length 1, getrandbits(1) rejected until 0,
        // so always returns lo with no infinite loop.
        let mut src = MtRandomSource::for_seed(7);
        for _ in 0..50 {
            assert_eq!(src.randint(42, 42), 42);
        }
    }

    #[test]
    fn seed_zero_uses_key_array_of_zero() {
        // The seed==0 edge: CPython builds key=[0]. Our u64_to_key(0) is empty,
        // normalized to [0] in from_key. Reproduce the (0, 10000, 99999) golden.
        let mut src = MtRandomSource::for_seed(0);
        let got: Vec<u32> = (0..5).map(|_| src.randint(10000, 99999)).collect();
        assert_eq!(got, vec![60494, 65125, 15306, 43936, 77013]);
    }
}
