use std::collections::{HashMap, HashSet};
use pyo3::prelude::*;

/// Stateful pseudonym generator — same entity always gets same code.
/// Uses Python's random.Random for seed compatibility.
#[pyclass]
pub struct PseudonymGenerator {
    prefix: String,
    code_range: (u32, u32),
    entity_to_code: HashMap<String, String>,
    used_codes: HashSet<String>,
    /// Python random.Random instance (for seed compatibility) or None (use secrets)
    rng: Option<PyObject>,
    use_secrets: bool,
}

#[pymethods]
impl PseudonymGenerator {
    #[new]
    #[pyo3(signature = (*, prefix="P", code_range=(1, 99999), seed=None, existing_key=None))]
    fn new(
        py: Python<'_>,
        prefix: &str,
        code_range: (u32, u32),
        seed: Option<u64>,
        existing_key: Option<HashMap<String, String>>,
    ) -> PyResult<Self> {
        let mut entity_to_code = HashMap::new();
        let mut used_codes = HashSet::new();

        // Load existing codes matching this prefix
        if let Some(ref key) = existing_key {
            let prefix_dash = format!("{}-", prefix);
            for (replacement, original) in key {
                if replacement.starts_with(&prefix_dash) {
                    entity_to_code.insert(original.clone(), replacement.clone());
                    used_codes.insert(replacement.clone());
                }
            }
        }

        let (rng, use_secrets) = if let Some(s) = seed {
            let random_mod = py.import("random")?;
            let rng_obj = random_mod.call_method1("Random", (s,))?;
            (Some(rng_obj.into_pyobject(py)?.unbind()), false)
        } else {
            (None, true)
        };

        Ok(Self {
            prefix: prefix.to_string(),
            code_range,
            entity_to_code,
            used_codes,
            rng,
            use_secrets,
        })
    }

    /// Get or create a pseudonym for an entity.
    fn get(&mut self, py: Python<'_>, entity: &str) -> PyResult<String> {
        if let Some(code) = self.entity_to_code.get(entity) {
            return Ok(code.clone());
        }

        let code = self.generate_unique(py)?;
        self.entity_to_code.insert(entity.to_string(), code.clone());
        self.used_codes.insert(code.clone());
        Ok(code)
    }
}

impl PseudonymGenerator {
    fn generate_unique(&mut self, py: Python<'_>) -> PyResult<String> {
        let (lo, hi) = self.code_range;

        for _ in 0..1000 {
            let num: u32 = if self.use_secrets {
                let secrets = py.import("secrets")?;
                let range = hi - lo + 1;
                let val: u32 = secrets.call_method1("randbelow", (range,))?.extract()?;
                val + lo
            } else if let Some(ref rng) = self.rng {
                rng.call_method1(py, "randint", (lo, hi))?.extract(py)?
            } else {
                lo // unreachable
            };

            let code = format!("{}-{:05}", self.prefix, num);
            if !self.used_codes.contains(&code) {
                return Ok(code);
            }
        }

        // Expand range and retry
        self.code_range = (lo, hi * 10);
        self.generate_unique(py)
    }
}
