use std::collections::{HashMap, HashSet};

/// Abstracts the two RNG operations the generator needs. The binding implements
/// this over Python random.Random (seeded) / secrets (unseeded), preserving the
/// exact call sequence the pre-split code used.
pub trait RandomSource {
    /// Seeded path: Python random.Random.randint(lo, hi) — inclusive both ends.
    fn randint(&mut self, lo: u32, hi: u32) -> u32;
    /// Unseeded path: secrets.randbelow(range); caller adds lo.
    fn randbelow(&mut self, range: u32) -> u32;
    /// true = secrets/unseeded path, false = seeded random.Random path.
    fn use_secrets(&self) -> bool;
}

/// Stateful pseudonym generator — same entity always gets same code.
/// Generic over a [`RandomSource`] so the pure core stays free of pyo3; the
/// binding supplies a Python-backed source for seed compatibility.
pub struct PseudonymGenerator<R: RandomSource> {
    prefix: String,
    code_range: (u32, u32),
    entity_to_code: HashMap<String, String>,
    used_codes: HashSet<String>,
    rng: R,
}

impl<R: RandomSource> PseudonymGenerator<R> {
    pub fn new(
        prefix: &str,
        code_range: (u32, u32),
        rng: R,
        existing_key: Option<&HashMap<String, String>>,
    ) -> Self {
        let mut entity_to_code = HashMap::new();
        let mut used_codes = HashSet::new();

        // Load existing codes matching this prefix
        if let Some(key) = existing_key {
            let prefix_dash = format!("{}-", prefix);
            for (replacement, original) in key {
                if replacement.starts_with(&prefix_dash) {
                    entity_to_code.insert(original.clone(), replacement.clone());
                    used_codes.insert(replacement.clone());
                }
            }
        }

        Self {
            prefix: prefix.to_string(),
            code_range,
            entity_to_code,
            used_codes,
            rng,
        }
    }

    /// Get or create a pseudonym for an entity.
    pub fn get(&mut self, entity: &str) -> String {
        if let Some(code) = self.entity_to_code.get(entity) {
            return code.clone();
        }

        let code = self.generate_unique();
        self.entity_to_code.insert(entity.to_string(), code.clone());
        self.used_codes.insert(code.clone());
        code
    }

    fn generate_unique(&mut self) -> String {
        let (lo, hi) = self.code_range;

        for _ in 0..1000 {
            let num: u32 = if self.rng.use_secrets() {
                let range = hi - lo + 1;
                self.rng.randbelow(range) + lo
            } else {
                self.rng.randint(lo, hi)
            };

            let code = format!("{}-{:05}", self.prefix, num);
            if !self.used_codes.contains(&code) {
                return code;
            }
        }

        // Expand range and retry
        self.code_range = (lo, hi * 10);
        self.generate_unique()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ScriptedRng {
        values: Vec<u32>,
        idx: usize,
    }
    impl RandomSource for ScriptedRng {
        fn randint(&mut self, _lo: u32, _hi: u32) -> u32 {
            let v = self.values[self.idx];
            self.idx += 1;
            v
        }
        fn randbelow(&mut self, _range: u32) -> u32 {
            let v = self.values[self.idx];
            self.idx += 1;
            v
        }
        fn use_secrets(&self) -> bool {
            false
        }
    }

    #[test]
    fn same_entity_same_code() {
        let mut g = PseudonymGenerator::new(
            "P",
            (1, 99999),
            ScriptedRng { values: vec![1, 2, 3], idx: 0 },
            None,
        );
        let a = g.get("Alice");
        assert_eq!(a, g.get("Alice")); // cached
        assert_eq!(a, "P-00001"); // {:05} zero-pad
    }

    #[test]
    fn collision_forces_next_draw() {
        // entity "a" draws 5 → P-00005; entity "b" draws 5 (collision) then 7 → P-00007
        let mut g = PseudonymGenerator::new(
            "P",
            (1, 99999),
            ScriptedRng { values: vec![5, 5, 7], idx: 0 },
            None,
        );
        assert_eq!(g.get("a"), "P-00005");
        assert_eq!(g.get("b"), "P-00007");
    }

    #[test]
    fn existing_key_preload() {
        let mut k = HashMap::new();
        k.insert("P-00042".to_string(), "Zoe".to_string());
        let mut g = PseudonymGenerator::new(
            "P",
            (1, 99999),
            ScriptedRng { values: vec![1], idx: 0 },
            Some(&k),
        );
        assert_eq!(g.get("Zoe"), "P-00042"); // served from preload, no RNG draw
    }
}
