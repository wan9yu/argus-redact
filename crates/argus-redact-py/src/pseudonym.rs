use std::collections::HashMap;

use pyo3::prelude::*;

use argus_redact_core::{PseudonymGenerator, RandomSource};

/// RandomSource backed by Python: random.Random(seed).randint (seeded) or
/// secrets.randbelow (unseeded). Preserves the exact call sequence the
/// pre-split code used, so seeded bit streams reproduce.
///
/// Note: the trait methods return `u32` (not `PyResult`), so a Python-side RNG
/// failure surfaces as a Rust panic, which PyO3 converts to a Python
/// `PanicException` at the `#[pymethods]` boundary (no `panic = "abort"` in the
/// workspace, so it unwinds — not a process abort). The pre-split code raised a
/// normal `PyErr`. In practice these are stdlib calls on validated `u32` inputs
/// that do not fail; the difference is the exception *type* on the theoretical
/// error path, not behavior on the happy path.
struct PyRandomSource {
    /// random.Random instance (seeded), or None (secrets/unseeded).
    rng: Option<Py<PyAny>>,
    use_secrets: bool,
}

impl RandomSource for PyRandomSource {
    fn randint(&mut self, lo: u32, hi: u32) -> u32 {
        Python::attach(|py| {
            self.rng
                .as_ref()
                .expect("randint called without a seeded rng")
                .call_method1(py, "randint", (lo, hi))
                .expect("random.Random.randint failed")
                .extract(py)
                .expect("randint result not u32")
        })
    }

    fn randbelow(&mut self, range: u32) -> u32 {
        Python::attach(|py| {
            let secrets = py.import("secrets").expect("import secrets failed");
            secrets
                .call_method1("randbelow", (range,))
                .expect("secrets.randbelow failed")
                .extract()
                .expect("randbelow result not u32")
        })
    }

    fn use_secrets(&self) -> bool {
        self.use_secrets
    }
}

/// Stateful pseudonym generator — same entity always gets same code.
#[pyclass(name = "PseudonymGenerator")]
pub struct PyPseudonymGenerator {
    inner: PseudonymGenerator<PyRandomSource>,
}

#[pymethods]
impl PyPseudonymGenerator {
    #[new]
    #[pyo3(signature = (*, prefix="P", code_range=(1, 99999), seed=None, existing_key=None))]
    fn new(
        py: Python<'_>,
        prefix: &str,
        code_range: (u32, u32),
        seed: Option<u64>,
        existing_key: Option<HashMap<String, String>>,
    ) -> PyResult<Self> {
        let src = if let Some(s) = seed {
            let random_mod = py.import("random")?;
            let rng_obj = random_mod.call_method1("Random", (s,))?;
            PyRandomSource { rng: Some(rng_obj.unbind()), use_secrets: false }
        } else {
            PyRandomSource { rng: None, use_secrets: true }
        };
        let inner = PseudonymGenerator::new(prefix, code_range, src, existing_key.as_ref());
        Ok(Self { inner })
    }

    /// Get or create a pseudonym for an entity.
    fn get(&mut self, entity: &str) -> String {
        self.inner.get(entity)
    }
}
