use argus_redact_core::shake_rng::ShakeRng;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// `_core.seed_from_value` — `HMAC-SHA256(salt, "{type}:{value}")` → 32 bytes.
///
/// Additive `_core` export of the single KDF SSOT
/// (`argus_redact_core::shake_rng::seed_from_value`), the master key the
/// realistic strategy derives fakes from. Mirrors `pure/replacer._seed_from_value`
/// so the Python copy can migrate onto this and later be deleted.
#[pyfunction]
pub fn seed_from_value<'py>(
    py: Python<'py>,
    value: &str,
    type_: &str,
    salt: &Bound<'py, PyBytes>,
) -> Bound<'py, PyBytes> {
    let digest = argus_redact_core::shake_rng::seed_from_value(value, type_, salt.as_bytes());
    PyBytes::new(py, &digest)
}

/// `_core.ShakeRng` — PyO3 wrapper over the Rust SHAKE-256 RNG, so custom
/// `faker_reserved` callables receive the SAME deterministic stream the Rust
/// engine uses (single KDF SSOT; the Python `_ShakeRng` is retired in v0.7.4).
///
/// Mirrors the `random.Random` subset that Python `_ShakeRng` exposes
/// (`pure/replacer.py` `_ShakeRng.randint`/`choice`): the byte stream is frozen
/// by the core KDF-replay vectors, so the `randint`/`choice` sequence is
/// bit-identical to the Python reference for the same seed.
#[pyclass(name = "ShakeRng")]
pub struct PyShakeRng {
    inner: ShakeRng,
}

impl PyShakeRng {
    /// Construct directly from seed bytes — used by the engine to hand custom
    /// `faker_reserved` callables the same seeded stream (Task 8). Kept
    /// `pub(crate)` so only the binding crate can mint instances off-band.
    pub(crate) fn new_from_bytes(seed: &[u8]) -> PyShakeRng {
        PyShakeRng { inner: ShakeRng::new(seed) }
    }
}

#[pymethods]
impl PyShakeRng {
    #[new]
    fn new(seed: &Bound<'_, PyBytes>) -> Self {
        PyShakeRng { inner: ShakeRng::new(seed.as_bytes()) }
    }

    /// Uniform integer in `[a, b]`. Mirrors Python `_ShakeRng.randint`.
    ///
    /// The core RNG operates on `i64`, matching Python's arbitrary-int
    /// `randint` over the ranges the fakers use.
    fn randint(&mut self, a: i64, b: i64) -> PyResult<i64> {
        if b < a {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "randint: empty range [{a}, {b}]"
            )));
        }
        Ok(self.inner.randint(a, b))
    }

    /// Uniformly pick one element of `seq`. Empty seq raises IndexError.
    fn choice<'py>(&mut self, seq: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let len = seq.len()?;
        if len == 0 {
            return Err(pyo3::exceptions::PyIndexError::new_err(
                "Cannot choose from an empty sequence",
            ));
        }
        let idx = self.inner.choice_index(len);
        seq.get_item(idx)
    }
}
