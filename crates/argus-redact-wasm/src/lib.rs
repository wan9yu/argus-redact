//! `argus-redact-wasm` — a thin wasm-bindgen wrapper exposing **fast-mode**
//! `redact` / `restore` over the pure-Rust `argus-redact-core`.
//!
//! This crate carries NO PyO3 and NO Python registry: built-in PII types only
//! ([`build_type_info`] with `registry_defaults = None`, the core's built-in
//! table being the SSOT, locked by `tests/specs/test_typeinfo_drift_guard.py`).
//! There are NO custom Python fakers — the `realistic` strategy resolves only the
//! built-in (`ShakeRng`-backed) fakers that already live in core.
//!
//! ## Pseudonym codes ARE Python-MT-compatible (true cross-runtime parity)
//!
//! The `pseudonym` strategy (and `remove`'s pseudonym fallback) mints `P-NNNNN`
//! codes from a [`RandomSource`]. Both the PyO3 path and wasm now use the SAME
//! seeded source: [`MtRandomSource`], a CPython-exact MT19937 living in the core.
//! It reproduces `random.Random(seed)` byte-for-byte with no Python dependency, so
//! the wasm codes are IDENTICAL to the Python wheel's codes for the same
//! `(text, salt)`. One implementation (SSOT), one stream, true cross-runtime
//! parity. The codes are (a) deterministic for a given salt and (b) fully
//! restorable, because `restore` keys off the returned `key` map.
//!
//! wasm only supports the seeded path (a salt is required — there is no host
//! entropy source for the unseeded `secrets` path); an absent salt is folded to a
//! fixed seed so unsalted pseudonym redaction is still deterministic in wasm.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use argus_redact_core::redact_l1::{redact_l1, RedactL1Args};
use argus_redact_core::restore::restore_full;
use argus_redact_core::seed::Salt;
use argus_redact_core::typeinfo::{build_type_info, Config, EntityConfig};
use argus_redact_core::{kinship_exact, MtRandomSource, PseudoFactory, SELF_REF_PRONOUNS};

// ── pseudonym RNG: the core's CPython-exact MT19937 (shared with PyO3) ───────

/// [`PseudoFactory`] minting a fresh [`MtRandomSource`] per (seed) — the SAME
/// CPython-exact MT19937 the PyO3 binding uses, so the `P-NNNNN` codes are
/// byte-identical to the Python wheel for the same `(text, salt)`. An absent seed
/// (`None`) would normally route core to the `secrets` path, which has no host
/// entropy source in wasm; we fold `None` to a fixed seed (`0`) so unsalted
/// pseudonym redaction is still deterministic in wasm.
struct WasmPseudoFactory;

impl PseudoFactory for WasmPseudoFactory {
    type Source = MtRandomSource;
    fn make(&self, seed: Option<u64>) -> MtRandomSource {
        MtRandomSource::for_seed(seed.unwrap_or(0))
    }
}

// ── opts deserialization ────────────────────────────────────────────────────

/// `lang` accepts either a single code (`"zh"`) or a list (`["zh","en"]`), like
/// the Python `lang: str | list[str]` parameter.
#[derive(Deserialize)]
#[serde(untagged)]
enum StringOrVec {
    One(String),
    Many(Vec<String>),
}

impl StringOrVec {
    fn into_vec(self) -> Vec<String> {
        match self {
            StringOrVec::One(s) => vec![s],
            StringOrVec::Many(v) => v,
        }
    }
}

/// `salt` accepts an integer (`42`) or a byte array (`[0,1,2,...]`), mirroring
/// the Python `salt: int | bytes | None`.
#[derive(Deserialize)]
#[serde(untagged)]
enum SaltOpt {
    Int(i64),
    Bytes(Vec<u8>),
}

/// Per-type user config entry (subset of the Python config dict relevant to
/// fast-mode replacement). All fields optional; an absent field falls back to the
/// built-in default.
#[derive(Deserialize, Default)]
struct EntityConfigOpt {
    strategy: Option<String>,
    prefix: Option<String>,
    replacement: Option<String>,
    label: Option<String>,
    visible_prefix: Option<usize>,
    visible_suffix: Option<usize>,
}

/// The full `redact` options object. Unknown fields are rejected so a typo (e.g.
/// `langs` for `lang`) surfaces loudly rather than being silently ignored.
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct RedactOpts {
    lang: Option<StringOrVec>,
    mode: Option<String>,
    salt: Option<SaltOpt>,
    config: Option<HashMap<String, EntityConfigOpt>>,
    names: Option<Vec<String>>,
    unified_prefix: Option<String>,
}

/// The `redact` return shape `{ text, key, aliases }`. `key` is `{fake: original}`
/// (for `restore`); `aliases` is `{fake: [alias, ...]}` from realistic fakers.
#[derive(Serialize)]
struct RedactResult {
    text: String,
    key: HashMap<String, String>,
    aliases: HashMap<String, Vec<String>>,
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Build the keep-strategy whitelist exactly as Python's `_KEEP_WHITELIST`:
/// `SELF_REF_PRONOUNS | _ZH_PRONOUNS | _ZH_KINSHIP`. `SELF_REF_PRONOUNS` and the
/// kinship set come from core (the SSOT, parity-gated); the 4 zh pronouns are the
/// same literal frozenset Python hardcodes in `pure/replacer.py`.
fn keep_whitelist() -> HashSet<String> {
    let mut wl: HashSet<String> = SELF_REF_PRONOUNS.iter().map(|s| s.to_string()).collect();
    for p in ["我", "我的", "我们", "我们的"] {
        wl.insert(p.to_string());
    }
    for k in kinship_exact() {
        wl.insert(k.clone());
    }
    wl
}

/// Translate the deserialized user config into the core's [`Config`] map.
fn to_core_config(opt: Option<HashMap<String, EntityConfigOpt>>) -> Option<Config> {
    opt.map(|m| {
        m.into_iter()
            .map(|(k, v)| {
                (
                    k,
                    EntityConfig {
                        strategy: v.strategy,
                        prefix: v.prefix,
                        replacement: v.replacement,
                        label: v.label,
                        visible_prefix: v.visible_prefix,
                        visible_suffix: v.visible_suffix,
                    },
                )
            })
            .collect()
    })
}

/// Resolve the per-type default `person` / `organization` prefixes from the built-in
/// `build_type_info` output (so a user `config` prefix override threads through).
fn lookup_prefix(info: &[(String, argus_redact_core::TypeInfo)], type_: &str, fallback: &str) -> String {
    info.iter()
        .find(|(k, _)| k == type_)
        .map(|(_, ti)| ti.prefix.clone())
        .unwrap_or_else(|| fallback.to_string())
}

// ── public API ──────────────────────────────────────────────────────────────

/// Set the panic hook once so wasm panics surface as readable JS console errors.
/// Feature-gated: in a size-optimized build without `console_error_panic_hook`
/// this is a no-op. Called from the wasm `start` shim AND defensively at the top
/// of each entry point (cheap; the hook install is idempotent).
fn set_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// wasm module init — installs the panic hook on instantiation.
#[wasm_bindgen(start)]
pub fn init() {
    set_panic_hook();
}

/// Fast-mode redact. `text` is the source; `opts` is a JS object deserialized
/// into [`RedactOpts`]. Returns `{ text, key, aliases }`.
///
/// Errors (as a JS `Error`):
/// - `mode` other than `"fast"` (NER / semantic layers are unavailable in wasm).
/// - a `realistic` / pseudonym strategy with NO salt (the core's `seed.rs` env
///   fallback returns `Err` on wasm — there is no environment).
/// - any core redaction error.
#[wasm_bindgen]
pub fn redact(text: &str, opts: JsValue) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let opts: RedactOpts = if opts.is_undefined() || opts.is_null() {
        RedactOpts::default()
    } else {
        serde_wasm_bindgen::from_value(opts)
            .map_err(|e| JsValue::from_str(&format!("invalid opts: {e}")))?
    };

    // Mode gate: wasm ships fast mode only (no NER / semantic adapters).
    match opts.mode.as_deref() {
        None | Some("fast") => {}
        Some(other) => {
            return Err(JsValue::from_str(&format!(
                "mode='{other}' is not supported in wasm — only mode='fast' (regex \
                 + known-names) is available; NER/semantic layers need the Python build"
            )));
        }
    }

    let langs: Vec<String> = opts
        .lang
        .map(StringOrVec::into_vec)
        .unwrap_or_else(|| vec!["zh".to_string()]);
    let names: Vec<String> = opts.names.unwrap_or_default();
    let salt: Option<Salt> = opts.salt.map(|s| match s {
        SaltOpt::Int(i) => Salt::Int(i),
        SaltOpt::Bytes(b) => Salt::Bytes(b),
    });
    let config = to_core_config(opts.config);

    // Detect first so build_type_info only resolves the types that actually
    // appear — but redact_l1 detects internally, so we re-detect for type_info.
    // Cheap relative to a network round-trip; matches the Python shim, which also
    // builds type_info over the detected entity set before calling _core.redact_l1.
    let detected = argus_redact_core::redact_l1::detect_l1(text, &langs, &names)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mut entities = detected.layer1;
    entities.extend(detected.person);

    // registry_defaults = None: built-in type table is the SSOT for wasm.
    let info_pairs = build_type_info(&entities, config.as_ref(), &langs, None);
    let person_prefix = lookup_prefix(&info_pairs, "person", "P");
    let org_prefix = lookup_prefix(&info_pairs, "organization", "O");
    let info_map: HashMap<String, argus_redact_core::TypeInfo> = info_pairs.into_iter().collect();

    let wl = keep_whitelist();
    let result = redact_l1(
        RedactL1Args {
            text,
            lang: &langs,
            names: &names,
            type_info: &info_map,
            salt: salt.as_ref(),
            key: None,
            person_prefix: &person_prefix,
            org_prefix: &org_prefix,
            unified_prefix: opts.unified_prefix.as_deref(),
            keep_whitelist: &wl,
            types: None,
            types_exclude: None,
        },
        &WasmPseudoFactory,
        None, // no custom Python fakers in wasm
    )
    .map_err(|e| JsValue::from_str(&e))?;

    let out = RedactResult {
        text: result.redacted,
        key: result.key,
        aliases: result.aliases,
    };
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsValue::from_str(&format!("failed to serialize result: {e}")))
}

/// Restore redacted text using the `key` map (`{fake: original}`) returned by
/// [`redact`]. The optional `aliases` are NOT taken here (fast-mode realistic
/// aliases are carried on the redact result); this is the core restore path used
/// for the common `(text, key)` roundtrip.
#[wasm_bindgen]
pub fn restore(text: &str, key: JsValue) -> Result<String, JsValue> {
    set_panic_hook();

    let key: HashMap<String, String> = if key.is_undefined() || key.is_null() {
        HashMap::new()
    } else {
        serde_wasm_bindgen::from_value(key)
            .map_err(|e| JsValue::from_str(&format!("invalid key: {e}")))?
    };

    restore_full(text, &key, None, None).map_err(|e| JsValue::from_str(&e.0))
}
