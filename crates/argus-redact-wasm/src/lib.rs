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

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use argus_redact_core::grammar::normalize_grammar_en;
use argus_redact_core::redact_l1::{detect_l1, redact_l1, RedactL1Args};
use argus_redact_core::replace::{replace, ReplaceArgs};
use argus_redact_core::restore::restore_full;
use argus_redact_core::seed::Salt;
use argus_redact_core::streaming::{
    DetectSpans, RedactSegment, StreamingRedactor as CoreStreamingRedactor,
};
use argus_redact_core::typeinfo::{build_type_info, Config, EntityConfig};
use argus_redact_core::{kinship_exact, MtRandomSource, PseudoFactory, SELF_REF_PRONOUNS, TypeInfo};

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

/// The full `redact` options object. Unknown keys are rejected (by
/// [`reject_unknown_opts`], called at every opts entry point) so a typo such as
/// `langs` for `lang` surfaces loudly rather than being silently ignored — a
/// silently-dropped `lang` would fall back to the `zh` default and skip the
/// detectors the caller meant to run, leaking PII with no error.
///
/// Note: serde's `deny_unknown_fields` is a NO-OP under `serde-wasm-bindgen` (its
/// Deserializer resolves fields by name and never enforces it), so the guarantee
/// is delivered by the runtime key-check in [`reject_unknown_opts`], not by serde.
/// `KNOWN_OPTS_KEYS` must stay in sync with the fields below.
#[derive(Deserialize, Default)]
#[serde(default)]
struct RedactOpts {
    lang: Option<StringOrVec>,
    mode: Option<String>,
    salt: Option<SaltOpt>,
    config: Option<HashMap<String, EntityConfigOpt>>,
    names: Option<Vec<String>>,
    unified_prefix: Option<String>,
}

/// The exact set of keys [`RedactOpts`] understands. Kept next to the struct so the
/// two stay in lockstep; [`reject_unknown_opts`] rejects any key not in this set.
const KNOWN_OPTS_KEYS: &[&str] = &["lang", "mode", "salt", "config", "names", "unified_prefix"];

/// Reject any opts key not in [`KNOWN_OPTS_KEYS`] with a clear JS `Error`. This is
/// the runtime enforcement of the documented "a typo surfaces loudly" guarantee
/// (serde's `deny_unknown_fields` does not fire under `serde-wasm-bindgen`).
///
/// A non-object `opts` (e.g. a `Map`, a string) is left for the deserializer to
/// reject; `undefined` / `null` are accepted (they mean "use defaults") and handled
/// by the callers before this is reached.
fn reject_unknown_opts(opts: &JsValue) -> Result<(), JsValue> {
    let obj: &js_sys::Object = match opts.dyn_ref::<js_sys::Object>() {
        Some(o) => o,
        // Not a plain object — let the serde deserializer produce the type error.
        None => return Ok(()),
    };
    let keys = js_sys::Object::keys(obj);
    for k in keys.iter() {
        if let Some(key) = k.as_string() {
            if !KNOWN_OPTS_KEYS.contains(&key.as_str()) {
                return Err(JsValue::from_str(&format!("unknown option key: {key}")));
            }
        }
    }
    Ok(())
}

/// A `serde_wasm_bindgen::Serializer` that emits Rust maps as PLAIN JS objects
/// rather than the default JS `Map`. A `Map` does not survive `JSON.stringify`
/// (`JSON.stringify(new Map(...)) === "{}"`), so the `key` / `aliases` fields would
/// silently lose every entry across a JSON boundary — breaking the documented
/// redact → persist key as JSON → restore roundtrip. Used at every return path.
fn to_object_serializer() -> serde_wasm_bindgen::Serializer {
    serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true)
}

/// The `redact` return shape `{ text, key, aliases, keep_downgraded,
/// mask_collisions }`. `key` is `{fake: original}` (for `restore`); `aliases` is
/// `{fake: [alias, ...]}` from realistic fakers. `keep_downgraded` /
/// `mask_collisions` are the two compliance signals the core `replace()` session
/// tracks, surfaced here ADDITIVELY — mirrors the `signals` slot the PyO3 binding
/// carries (`crates/argus-redact-py/src/replace.rs`), NOT a widening of the public
/// core [`RedactSegment`] (which stays `{ downstream_text, key, aliases }` for
/// crates.io compatibility; see [`redact_segment`]).
#[derive(Serialize)]
struct RedactResult {
    text: String,
    key: HashMap<String, String>,
    aliases: HashMap<String, Vec<String>>,
    keep_downgraded: bool,
    mask_collisions: Vec<String>,
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

/// The resolved redaction params shared by the one-shot `redact` and the streaming
/// `feed`/`flush` closures: the SAME detect → `build_type_info` → `redact_l1` path
/// with one set of langs/names/config/salt/whitelist. Holding them once keeps the
/// streaming closures byte-parity with the one-shot path (and with Python).
struct RedactParams {
    langs: Vec<String>,
    names: Vec<String>,
    salt: Option<Salt>,
    config: Option<Config>,
    unified_prefix: Option<String>,
    whitelist: HashSet<String>,
}

/// [`redact_segment`]'s full result: the public core [`RedactSegment`]
/// (`downstream_text` + `key` + `aliases`, untouched — NOT widened) plus the two
/// compliance signals the core `replace()` session tracks on `ReplaceResult`
/// (`keep_downgraded` / `mask_collisions`), read off the session result HERE
/// before they would otherwise be dropped when `RedactSegment` is built. Local to
/// this crate — never crosses the crates.io-published core boundary.
struct RedactSegmentWithSignals {
    segment: RedactSegment,
    keep_downgraded: bool,
    mask_collisions: Vec<String>,
}

/// Run the one-shot fast-mode redact path over `text`, optionally threading an
/// `existing_key` for cross-chunk collision continuity (same original reuses the
/// same fake — mirrors the Python `existing_key=` / `setdefault` merge). This is
/// the SSOT for the one-shot [`redact`] entry point: `detect_l1` →
/// `build_type_info` (`registry_defaults = None`) → `redact_l1` with the wasm
/// MT19937 pseudo-factory. Returns the segment PLUS the `keep_downgraded` /
/// `mask_collisions` signals (see [`RedactSegmentWithSignals`]).
/// The streaming path uses a separate replace-based redact closure (no re-detect).
fn redact_segment(
    params: &RedactParams,
    text: &str,
    existing_key: Option<&HashMap<String, String>>,
) -> Result<RedactSegmentWithSignals, String> {
    // Detect first so build_type_info only resolves the types that actually
    // appear — redact_l1 re-detects internally; this re-detect feeds type_info,
    // matching the Python shim's build-type-info-over-detected-entities order.
    let detected = detect_l1(text, &params.langs, &params.names).map_err(|e| e.to_string())?;
    let mut entities = detected.layer1;
    entities.extend(detected.person);
    entities.extend(detected.regions);
    entities.extend(detected.job_titles);
    entities.extend(detected.framework);

    let info_pairs = build_type_info(&entities, params.config.as_ref(), &params.langs, None);
    let person_prefix = lookup_prefix(&info_pairs, "person", "P");
    let org_prefix = lookup_prefix(&info_pairs, "organization", "O");
    let info_map: HashMap<String, TypeInfo> = info_pairs.into_iter().collect();

    let result = redact_l1(
        RedactL1Args {
            text,
            lang: &params.langs,
            names: &params.names,
            type_info: &info_map,
            salt: params.salt.as_ref(),
            key: existing_key,
            person_prefix: &person_prefix,
            org_prefix: &org_prefix,
            unified_prefix: params.unified_prefix.as_deref(),
            keep_whitelist: &params.whitelist,
            types: None,
            types_exclude: None,
        },
        &WasmPseudoFactory,
        None, // no custom Python fakers in wasm
    )?;

    Ok(RedactSegmentWithSignals {
        segment: RedactSegment {
            downstream_text: result.redacted,
            key: result.key,
            aliases: result.aliases,
        },
        keep_downgraded: result.keep_downgraded,
        mask_collisions: result.mask_collisions,
    })
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
/// into [`RedactOpts`]. Returns `{ text, key, aliases, keep_downgraded,
/// mask_collisions }` — the last two are additive compliance signals (a JS
/// caller reading only `text`/`key`/`aliases` is unaffected): `keep_downgraded`
/// is `true` if a `keep`-strategy entity failed the whitelist and was downgraded;
/// `mask_collisions` lists (one entry per collision, not deduped) the entity
/// types for which a mask-family strategy produced two originals sharing one
/// visible label, disambiguated with a trailing marker (see the core
/// `ReplaceResult::mask_collisions` doc for the LLM-normalization caveat).
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
        // Reject typo'd / unknown keys BEFORE deserializing (serde's
        // deny_unknown_fields is a no-op under serde-wasm-bindgen).
        reject_unknown_opts(&opts)?;
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

    let params = resolve_params(opts);
    let with_signals = redact_segment(&params, text, None).map_err(|e| JsValue::from_str(&e))?;

    let out = RedactResult {
        text: with_signals.segment.downstream_text,
        key: with_signals.segment.key,
        aliases: with_signals.segment.aliases,
        keep_downgraded: with_signals.keep_downgraded,
        mask_collisions: with_signals.mask_collisions,
    };
    out.serialize(&to_object_serializer())
        .map_err(|e| JsValue::from_str(&format!("failed to serialize result: {e}")))
}

/// Resolve a deserialized [`RedactOpts`] into the shared [`RedactParams`] (langs
/// default to `zh`, salt mapped to the core [`Salt`], config translated, whitelist
/// built once). Mode is validated by the caller before this is called.
fn resolve_params(opts: RedactOpts) -> RedactParams {
    let langs: Vec<String> = opts
        .lang
        .map(StringOrVec::into_vec)
        .unwrap_or_else(|| vec!["zh".to_string()]);
    let salt: Option<Salt> = opts.salt.map(|s| match s {
        SaltOpt::Int(i) => Salt::Int(i),
        SaltOpt::Bytes(b) => Salt::Bytes(b),
    });
    RedactParams {
        langs,
        names: opts.names.unwrap_or_default(),
        salt,
        config: to_core_config(opts.config),
        unified_prefix: opts.unified_prefix,
        whitelist: keep_whitelist(),
    }
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

    // No `aliases` are taken here (see the doc comment above), so
    // `alias_collisions` is always empty — discard it.
    restore_full(text, &key, None, None)
        .map(|(result, _)| result)
        .map_err(|e| JsValue::from_str(&e.0))
}

// ── streaming: feed / flush over the core carry-window engine ─────────────────

/// The boxed detect / redact closure types the concrete core `StreamingRedactor`
/// is instantiated with. `#[wasm_bindgen]` structs can't be generic, so the
/// generic core engine is monomorphized over these trait objects (the detect
/// closure for the carry-window entity-snap, the redact closure for the emit).
type BoxedDetect = Box<dyn Fn(&str) -> DetectSpans>;
type BoxedRedact = Box<dyn Fn(&str, &DetectSpans) -> Result<RedactSegment, String>>;

/// The `feed` / `flush` return shape `{ downstreamText, key, aliases }`. Mirrors
/// the fields the Python `StreamingRedactor` surfaces from its `PseudonymLLMResult`
/// (`downstream_text` → `downstreamText`); `key` is the redactor's ACCUMULATED key
/// snapshot after merging this segment (so a caller can restore the whole stream
/// with one key), and `aliases` are this segment's realistic-faker aliases.
#[derive(Serialize)]
struct EmitResultJs {
    #[serde(rename = "downstreamText")]
    downstream_text: String,
    key: HashMap<String, String>,
    aliases: HashMap<String, Vec<String>>,
}

/// Sentence-bounded incremental fast-mode redaction with cross-chunk key
/// continuity, over the core carry-window state machine (the SSOT shared with the
/// Python `StreamingRedactor` and the wasm one-shot `redact`).
///
/// Each [`feed`](StreamingRedactor::feed) detects once over the full ±W buffer,
/// emits the range up to the last safe sentence boundary (keeping the entity
/// straddling the cut whole), and redacts via `build_type_info` → `replace` +
/// en-grammar tail over the GIVEN pre-detected, range-shifted spans — no internal
/// re-detect. The segment's key is merged into the accumulated key (first-seen
/// wins). [`flush`](StreamingRedactor::flush) drains the tail at end-of-stream.
/// Returns `{ downstreamText, key, aliases }`; an empty `downstreamText` means the
/// buffer hasn't reached a cut yet.
///
/// Construct one per logical session: the accumulated key grows monotonically.
#[wasm_bindgen]
pub struct StreamingRedactor {
    inner: CoreStreamingRedactor<BoxedDetect, BoxedRedact>,
    /// Shared with the redact closure so each segment threads the accumulated key
    /// as `existing_key` (a repeated original reuses its fake — mirroring the
    /// Python `existing_key=self._accumulated_key`). Kept in sync with the core's
    /// own accumulated key after every emit.
    accumulated_key: Rc<RefCell<HashMap<String, String>>>,
}

#[wasm_bindgen]
impl StreamingRedactor {
    /// Build a streaming redactor from an `opts` object `{ lang, mode: "fast",
    /// salt (required), config, names }` — the SAME opts the one-shot `redact`
    /// takes. Errors (as a JS `Error`):
    /// - `mode` other than `"fast"` (NER / semantic layers are unavailable in wasm);
    /// - a missing `salt` (wasm has no host entropy for the unseeded pseudonym
    ///   path, so a salt is required for deterministic, restorable codes).
    #[wasm_bindgen(constructor)]
    pub fn new(opts: JsValue) -> Result<StreamingRedactor, JsValue> {
        set_panic_hook();

        let opts: RedactOpts = if opts.is_undefined() || opts.is_null() {
            RedactOpts::default()
        } else {
            // Reject typo'd / unknown keys BEFORE deserializing (serde's
            // deny_unknown_fields is a no-op under serde-wasm-bindgen).
            reject_unknown_opts(&opts)?;
            serde_wasm_bindgen::from_value(opts)
                .map_err(|e| JsValue::from_str(&format!("invalid opts: {e}")))?
        };

        // Mode gate: wasm streaming ships fast mode only.
        match opts.mode.as_deref() {
            None | Some("fast") => {}
            Some(other) => {
                return Err(JsValue::from_str(&format!(
                    "mode='{other}' is not supported in wasm — only mode='fast' (regex \
                     + known-names) is available; NER/semantic layers need the Python build"
                )));
            }
        }

        // Salt is required: there is no host entropy source for the unseeded
        // pseudonym path in wasm, so streaming demands an explicit salt for
        // deterministic, restorable codes.
        if opts.salt.is_none() {
            return Err(JsValue::from_str(
                "StreamingRedactor requires a salt — wasm has no host entropy source \
                 for the unseeded pseudonym path; pass an integer or byte-array salt",
            ));
        }

        let params = Rc::new(resolve_params(opts));
        let accumulated_key: Rc<RefCell<HashMap<String, String>>> =
            Rc::new(RefCell::new(HashMap::new()));

        // Detect closure: the RAW `layer1 ++ person` entities + L1 hints over the
        // combined buffer — the carry-window snap NORMALIZES them (merge +
        // self-reference filter) to the exact set Python's fast `_detect` produces,
        // so the cut is identical across runtimes.
        let detect_params = Rc::clone(&params);
        let detect: BoxedDetect = Box::new(move |text: &str| {
            match detect_l1(text, &detect_params.langs, &detect_params.names) {
                Ok(r) => {
                    let mut entities = r.layer1;
                    entities.extend(r.person);
                    entities.extend(r.regions);
                    entities.extend(r.job_titles);
                    entities.extend(r.framework);
                    DetectSpans {
                        entities,
                        hints: r.hints,
                    }
                }
                // A detect failure (e.g. oversize buffer) yields no spans → the
                // carry-window falls back to its non-entity-aware cut; the redact
                // closure surfaces the real error on emit.
                Err(_) => DetectSpans::default(),
            }
        });

        // Redact closure: detect-once path — redact the GIVEN pre-detected,
        // range-shifted entities over `text` via `build_type_info` → `replace` +
        // en-grammar tail. No internal re-detect (the core engine already detected
        // once over the full ±W buffer and shifted the spans into the emit range).
        // Threads the accumulated key for cross-chunk collision continuity so the
        // same original reuses its existing fake across segments.
        let redact_params = Rc::clone(&params);
        let redact_key = Rc::clone(&accumulated_key);
        let redact: BoxedRedact = Box::new(move |text: &str, spans: &DetectSpans| {
            let existing = redact_key.borrow();
            let info_pairs = build_type_info(
                &spans.entities,
                redact_params.config.as_ref(),
                &redact_params.langs,
                None,
            );
            let person_prefix = lookup_prefix(&info_pairs, "person", "P");
            let org_prefix = lookup_prefix(&info_pairs, "organization", "O");
            let info_map: HashMap<String, TypeInfo> = info_pairs.into_iter().collect();
            let result = replace(
                ReplaceArgs {
                    text,
                    entities: &spans.entities,
                    salt: redact_params.salt.as_ref(),
                    key: Some(&*existing),
                    type_info: &info_map,
                    person_prefix: &person_prefix,
                    org_prefix: &org_prefix,
                    unified_prefix: redact_params.unified_prefix.as_deref(),
                    keep_whitelist: &redact_params.whitelist,
                },
                &WasmPseudoFactory,
                None,
            )?;
            let effective_lang = redact_params.langs.first().map(String::as_str).unwrap_or("zh");
            let downstream = if effective_lang == "en" {
                let originals: Vec<String> = result.key.values().cloned().collect();
                normalize_grammar_en(&result.redacted, &originals)
            } else {
                result.redacted
            };
            Ok(RedactSegment {
                downstream_text: downstream,
                key: result.key,
                aliases: result.aliases,
            })
        });

        Ok(StreamingRedactor {
            inner: CoreStreamingRedactor::new(detect, redact),
            accumulated_key,
        })
    }

    /// Buffer until a safe cut, then redact the committed prefix. Returns
    /// `{ downstreamText, key, aliases }`; `downstreamText` is `""` when the buffer
    /// hasn't reached a cut yet (the `key` still carries the accumulated snapshot).
    #[wasm_bindgen]
    pub fn feed(&mut self, chunk: &str) -> Result<JsValue, JsValue> {
        let emit = self.inner.feed(chunk).map_err(|e| JsValue::from_str(&e))?;
        self.emit_to_js(emit)
    }

    /// End-of-stream flush — drain the pending buffer through the redact path.
    /// Returns an empty `downstreamText` when nothing is buffered.
    #[wasm_bindgen]
    pub fn flush(&mut self) -> Result<JsValue, JsValue> {
        let emit = self.inner.flush().map_err(|e| JsValue::from_str(&e))?;
        self.emit_to_js(emit)
    }

    /// Marshal a core `EmitResult` to `{ downstreamText, key, aliases }` and keep
    /// the shared accumulated-key cell in sync with the core's snapshot (so the
    /// next segment's `existing_key` reflects everything seen so far).
    fn emit_to_js(
        &self,
        emit: argus_redact_core::streaming::EmitResult,
    ) -> Result<JsValue, JsValue> {
        *self.accumulated_key.borrow_mut() = emit.accumulated_key.clone();
        let out = EmitResultJs {
            downstream_text: emit.segment.downstream_text,
            key: emit.accumulated_key,
            aliases: emit.segment.aliases,
        };
        out.serialize(&to_object_serializer())
            .map_err(|e| JsValue::from_str(&format!("failed to serialize result: {e}")))
    }
}
