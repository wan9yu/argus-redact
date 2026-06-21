use std::collections::HashMap;

use pyo3::prelude::*;

use argus_redact_core::{MtRandomSource, PseudonymGenerator, RandomSource};

/// RandomSource for the pseudonym generator. Two paths:
/// - **Seeded** (`salt`/`seed` given): a pure-Rust, CPython-exact MT19937
///   ([`MtRandomSource`] in the core). This reproduces `random.Random(seed)`
///   byte-for-byte WITHOUT calling into CPython's `random` module — the same
///   single implementation the wasm crate uses, so the `P-NNNNN` code stream is
///   identical across the Python wheel and wasm (SSOT).
/// - **Unseeded** (`seed == None`): non-deterministic `secrets.randbelow`. This
///   path is Python-only (there is no host entropy source in wasm) and carries no
///   cross-runtime parity concern, so it stays in the binding.
///
/// Note: the trait methods return `u32` (not `PyResult`). The seeded path is now
/// pure Rust and cannot fail. The unseeded `secrets` call, on the theoretical
/// error path, surfaces as a Rust panic → PyO3 `PanicException` at the
/// `#[pymethods]` boundary (no `panic = "abort"` in the workspace, so it unwinds —
/// not a process abort). In practice it is a stdlib call on a validated `u32` that
/// does not fail; the difference is the exception *type*, not happy-path behavior.
pub(crate) enum PyRandomSource {
    /// Seeded: CPython-exact MT19937, pure Rust, no `random` module call.
    Seeded(MtRandomSource),
    /// Unseeded: `secrets.randbelow` (non-deterministic, Python-only).
    Secrets,
}

impl PyRandomSource {
    /// Mint a source for an optional `u64` seed: the core MT19937 (CPython-exact)
    /// when `Some` (seeded), `secrets` when `None` (unseeded). Same construction
    /// the `replace` orchestrator's `PseudoFactory` relies on, so seeded bit
    /// streams reproduce identically across the standalone generator and the
    /// orchestrator.
    ///
    /// Seeded predictability caveat: with a seed/salt, the `P-NNNNN` codes are
    /// drawn from a Mersenne-Twister (MT19937) stream — CPython's `random.Random`,
    /// now reimplemented in the core. MT19937 is deterministic and not
    /// cryptographic: given enough observed outputs the stream is, in principle,
    /// recoverable, so codes are predictable and linkable across redactions that
    /// share the same seed/salt. This is a low-severity property because the code
    /// is an opaque sequence label, not derived from the original value — it
    /// carries no PII-bearing information. It is a deterministic-but-predictable
    /// label, not a cryptographic commitment. Unseeded mode draws from `secrets`
    /// instead (see `randbelow`), which is not reproducible and not subject to
    /// this caveat.
    pub(crate) fn for_seed(seed: Option<u64>) -> Self {
        match seed {
            Some(s) => PyRandomSource::Seeded(MtRandomSource::for_seed(s)),
            None => PyRandomSource::Secrets,
        }
    }
}

impl RandomSource for PyRandomSource {
    fn randint(&mut self, lo: u32, hi: u32) -> u32 {
        match self {
            PyRandomSource::Seeded(mt) => mt.randint(lo, hi),
            PyRandomSource::Secrets => panic!("randint called without a seeded rng"),
        }
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
        matches!(self, PyRandomSource::Secrets)
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
        prefix: &str,
        code_range: (u32, u32),
        seed: Option<u64>,
        existing_key: Option<HashMap<String, String>>,
    ) -> PyResult<Self> {
        // Same seeded construction the `replace` orchestrator uses (`for_seed`),
        // so the standalone generator and the orchestrator share one bit stream.
        let src = PyRandomSource::for_seed(seed);
        let inner = PseudonymGenerator::new(prefix, code_range, src, existing_key.as_ref());
        Ok(Self { inner })
    }

    /// Get or create a pseudonym for an entity.
    fn get(&mut self, entity: &str) -> String {
        self.inner.get(entity)
    }
}
