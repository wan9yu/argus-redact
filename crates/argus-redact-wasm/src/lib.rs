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

use argus_redact_core::coverage::{finalize_entities, FilterScope};
use argus_redact_core::grammar::normalize_grammar_en;
use argus_redact_core::redact_l1::detect_l1;
use argus_redact_core::replace::{replace, ReplaceArgs};
use argus_redact_core::restore::restore_full;
use argus_redact_core::seed::Salt;
use argus_redact_core::{restore_full_guarded, Anchor, GuardEventKind, RestoreOutcome};
use argus_redact_core::streaming::{
    DetectSpans, RedactSegment, StreamingRedactor as CoreStreamingRedactor,
};
use argus_redact_core::typeinfo::{build_type_info, Config, EntityConfig};
use argus_redact_core::{
    detect_languages, kinship_exact, MtRandomSource, PatternMatch, PseudoFactory, SELF_REF_PRONOUNS,
    TypeInfo,
};

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

/// Serialize a result value to a plain-JS-object [`JsValue`] via
/// [`to_object_serializer`], mapping any serialization failure to the SAME
/// `failed to serialize result` JS `Error`. The single return-marshalling idiom
/// shared by every JS-object entry point (`redact`, both `restore_guarded`
/// branches, and the streaming `emit_to_js`).
fn serialize_result<T: Serialize>(out: &T) -> Result<JsValue, JsValue> {
    out.serialize(&to_object_serializer())
        .map_err(|e| JsValue::from_str(&format!("failed to serialize result: {e}")))
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

/// Resolve the per-type info map plus the `person` / `organization` prefixes from
/// a set of entities — the `build_type_info` → `lookup_prefix` → `info_map`
/// assembly shared by the one-shot [`redact_segment`] and the streaming redact
/// closure (`registry_defaults = None` on both — built-in tables are the SSOT).
/// A `config` prefix override threads through `build_type_info`, so it is picked
/// up by the `lookup_prefix` reads.
fn build_info(
    entities: &[PatternMatch],
    config: Option<&Config>,
    langs: &[String],
) -> (HashMap<String, TypeInfo>, String, String) {
    let info_pairs = build_type_info(entities, config, langs, None);
    let person_prefix = lookup_prefix(&info_pairs, "person", "P");
    let org_prefix = lookup_prefix(&info_pairs, "organization", "O");
    let info_map: HashMap<String, TypeInfo> = info_pairs.into_iter().collect();
    (info_map, person_prefix, org_prefix)
}

/// Flatten a raw [`DetectL1Result`](argus_redact_core::redact_l1::DetectL1Result)
/// into the fast-mode `{ entities, hints }` bundle both detect paths consume:
/// `layer1 ++ person ++ regions ++ job_titles ++ framework` (Python's fast
/// `_detect` extend order), carried together with the L1 `hints` as a
/// [`DetectSpans`]. Shared by [`redact_segment`] (which then finalizes + redacts)
/// and the streaming detect closure (which returns the bundle to the carry-window
/// engine). Consumes the result by value so no entity vec is cloned.
fn flatten_l1(d: argus_redact_core::redact_l1::DetectL1Result) -> DetectSpans {
    let mut entities = d.layer1;
    entities.extend(d.person);
    entities.extend(d.regions);
    entities.extend(d.job_titles);
    entities.extend(d.framework);
    DetectSpans {
        entities,
        hints: d.hints,
    }
}

/// The resolved redaction params shared by the one-shot `redact` and the streaming
/// `feed`/`flush` closures: the SAME detect → `build_info` → `finalize` → `replace`
/// path with one set of langs/names/config/salt/whitelist. Holding them once keeps
/// the streaming closures byte-parity with the one-shot path (and with Python).
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

/// The detect-once SSOT tail shared by the one-shot [`redact_segment`] and the
/// streaming redact closure: `replace` (wasm MT19937 pseudo-factory, no custom
/// fakers) → the en-only `normalize_grammar_en` tail, over an already-built
/// `type_info` + `person` / `organization` prefixes and a resolved entity set. This
/// is the ACTUALLY-duplicated part — the two copies were byte-for-byte identical.
///
/// `build_info` is DELIBERATELY NOT folded in here: each caller runs it over its OWN
/// set and threads the result in. The one-shot path resolves it over the RAW
/// pre-finalize entities (then `replace`s the finalized subset); the streaming
/// closure resolves it over `spans.entities` (the same set it `replace`s). Those two
/// sets are NOT interchangeable — `person_prefix` is the SHARED generator prefix for
/// every non-org `pseudonym`-strategy entity (e.g. `school`), so if `finalize`
/// dropped a config-prefix-overridden `person` span that a surviving `school` span
/// is seeded from, building the info over the finalized set would silently lose the
/// override and change the redacted text + key. Keeping `build_info` at the call
/// site preserves the exact a414e4a behaviour on both paths.
///
/// `existing_key` threads cross-chunk collision continuity (a repeated original
/// reuses its fake). Returns the segment PLUS the `keep_downgraded` /
/// `mask_collisions` signals — the one-shot path surfaces them, the streaming face
/// drops them.
fn replace_and_grammar(
    params: &RedactParams,
    text: &str,
    info_map: &HashMap<String, TypeInfo>,
    person_prefix: &str,
    org_prefix: &str,
    entities: &[PatternMatch],
    existing_key: Option<&HashMap<String, String>>,
) -> Result<RedactSegmentWithSignals, String> {
    let result = replace(
        ReplaceArgs {
            text,
            entities,
            salt: params.salt.as_ref(),
            key: existing_key,
            type_info: info_map,
            person_prefix,
            org_prefix,
            unified_prefix: params.unified_prefix.as_deref(),
            keep_whitelist: &params.whitelist,
        },
        &WasmPseudoFactory,
        None, // no custom Python fakers in wasm
    )?;

    // en-only grammar tail — a SEPARATE step exactly as `redact_l1` step 7 applies
    // it (`replace` never calls grammar internally). `effective_lang` = lang[0] else
    // "zh", mirroring Python.
    let effective_lang = params.langs.first().map(String::as_str).unwrap_or("zh");
    let downstream = if effective_lang == "en" {
        let originals: Vec<String> = result.key.values().cloned().collect();
        normalize_grammar_en(&result.redacted, &originals)
    } else {
        result.redacted
    };

    Ok(RedactSegmentWithSignals {
        segment: RedactSegment {
            downstream_text: downstream,
            key: result.key,
            aliases: result.aliases,
        },
        keep_downgraded: result.keep_downgraded,
        mask_collisions: result.mask_collisions,
    })
}

/// Run the one-shot fast-mode redact path over `text`, optionally threading an
/// `existing_key` for cross-chunk collision continuity (same original reuses the
/// same fake — mirrors the Python `existing_key=` / `setdefault` merge). This is
/// the SSOT for the one-shot [`redact`] entry point.
///
/// Detection runs EXACTLY ONCE (`detect_l1`), matching the Python `redact()` glue
/// (`_detect` → `_build_type_info` → `_replace_and_emit`) rather than the previous
/// detect-twice shape (an outer `detect_l1` to seed `build_type_info`, then a
/// `redact_l1` that re-detected internally). The single detection feeds BOTH
/// [`build_info`] over the RAW (pre-finalize) entities AND the post-detect pipeline:
/// `finalize_entities` (merge → self-reference filter → type filter → coverage
/// restore, `apply_type_filter = true`, no `types` scope) → the shared
/// [`replace_and_grammar`] tail (`replace` → en-grammar) over that finalized set,
/// carrying the RAW-derived `type_info` / prefixes. Byte-identical to the old
/// `redact_l1` call: the re-detect it dropped was deterministic (same raw entities),
/// and the `type_info` (resolved over the raw set, as the old outer `build_type_info`
/// did) / filter scope / grammar step are the same. Returns the segment PLUS the
/// `keep_downgraded` / `mask_collisions` signals (see [`RedactSegmentWithSignals`]).
fn redact_segment(
    params: &RedactParams,
    text: &str,
    existing_key: Option<&HashMap<String, String>>,
) -> Result<RedactSegmentWithSignals, String> {
    // ONE detection, flattened into the fast-mode { entities, hints } bundle.
    let DetectSpans { entities, hints } =
        flatten_l1(detect_l1(text, &params.langs, &params.names).map_err(|e| e.to_string())?);

    // type_info over the RAW (pre-finalize) entities — the exact set the old outer
    // `build_type_info` resolved, so the per-type info AND the shared `person` /
    // `organization` pseudonym prefixes are unchanged even when finalize later drops
    // a (prefix-overridden) person span that a surviving non-org pseudonym entity
    // (e.g. school) is seeded from. Resolving over the finalized set would lose that
    // override — a reachable byte-identity break.
    let (info_map, person_prefix, org_prefix) =
        build_info(&entities, params.config.as_ref(), &params.langs);

    // Post-detect pipeline, reproducing `redact_l1`'s steps 2-5a over this single
    // detection: merge → self-reference filter → type filter (none) → coverage
    // restore. `apply_type_filter = true` + `FilterScope::from_hints(None, None,…)`
    // are exactly the arguments `redact_l1` passed for the wasm (no-`types`) call.
    let scope = FilterScope::from_hints(None, None, &hints);
    let filtered = finalize_entities(entities, &hints, &scope, text, true);

    // Shared `replace` → en-grammar tail: replace runs over the FILTERED set with the
    // RAW-derived type_info / prefixes (a414e4a order).
    replace_and_grammar(
        params,
        text,
        &info_map,
        &person_prefix,
        &org_prefix,
        &filtered,
        existing_key,
    )
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

/// Deserialize + validate a `redact` opts object once for BOTH the one-shot
/// [`redact`] and the [`StreamingRedactor`] constructor. `undefined`/`null` yields
/// [`RedactOpts::default`] ("use defaults"); otherwise unknown keys are rejected
/// (via [`reject_unknown_opts`] — serde's `deny_unknown_fields` is a no-op under
/// `serde-wasm-bindgen`), then the object is deserialized, then the mode is gated
/// (wasm ships fast mode only — no NER / semantic adapters). Sharing this keeps the
/// `invalid opts` message AND the multi-line mode-gate error string byte-identical
/// across the two entry points.
fn parse_opts(opts: JsValue) -> Result<RedactOpts, JsValue> {
    let opts: RedactOpts = if opts.is_undefined() || opts.is_null() {
        RedactOpts::default()
    } else {
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
    Ok(opts)
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

    let opts = parse_opts(opts)?;

    let mut params = resolve_params(opts);
    // Resolve the `lang="auto"` sentinel against the actual text (Python parity —
    // `glue/redact.py`'s `if lang == "auto": lang = detect_languages(text)`) so a
    // `{lang:'auto'}` caller runs the real zh/en detectors instead of the literal
    // "auto" lang, which matches neither and silently under-redacts.
    params.langs = resolve_auto_lang(params.langs, text);
    let with_signals = redact_segment(&params, text, None).map_err(|e| JsValue::from_str(&e))?;

    let out = RedactResult {
        text: with_signals.segment.downstream_text,
        key: with_signals.segment.key,
        aliases: with_signals.segment.aliases,
        keep_downgraded: with_signals.keep_downgraded,
        mask_collisions: with_signals.mask_collisions,
    };
    serialize_result(&out)
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

/// Resolve the `lang="auto"` sentinel to concrete language codes via the core's
/// script-range [`detect_languages`] — the SAME resolver the Python `redact()`
/// shim runs (`glue/redact.py`: `if lang == "auto": lang = detect_languages(text)`).
///
/// Without this, a `{lang:'auto'}` opts object reaches `detect_l1` as the LITERAL
/// lang list `["auto"]`, which matches NEITHER `"zh"` NOR `"en"`. The lang-GATED
/// person detector (zh/en) is then skipped, so a name like 张伟 leaks silently.
/// (Language-NEUTRAL patterns — the phone / national-id regexes — still load
/// regardless of the requested lang, so those are unaffected; the leak on the
/// `"auto"` path is the person detector specifically.) A `"auto"` lang is not the
/// same code path as an OMITTED lang, which correctly defaults to `["zh"]`. Any
/// non-`"auto"` lang list passes through unchanged.
///
/// Both `{lang:'auto'}` and `{lang:['auto']}` collapse to `["auto"]` before this
/// point, so both resolve. The Python shim special-cases only the bare string, but
/// resolving the single-element list too only ever redacts MORE, never less — the
/// safe direction — so the tiny divergence cannot leak.
fn resolve_auto_lang(langs: Vec<String>, text: &str) -> Vec<String> {
    if langs.len() == 1 && langs[0] == "auto" {
        detect_languages(text)
    } else {
        langs
    }
}

/// `true` when the requested lang is (solely) the `"auto"` sentinel. The streaming
/// constructor uses this to REJECT `"auto"` loudly: a stream has no full text at
/// construction to script-detect from (unlike one-shot [`redact`], which resolves
/// it via [`resolve_auto_lang`]). This is the pre-collapse form of that check —
/// both `{lang:'auto'}` and a single-element `{lang:['auto']}` count.
fn lang_is_auto(lang: &Option<StringOrVec>) -> bool {
    match lang {
        Some(StringOrVec::One(s)) => s == "auto",
        Some(StringOrVec::Many(v)) => v.len() == 1 && v[0] == "auto",
        None => false,
    }
}

/// Deserialize the optional `aliases` JS argument shared by [`restore`] and
/// [`restore_guarded`]: `undefined`/`null` means "no aliases" (`None`);
/// otherwise the `{fake: [alternate-transliteration, ...]}` map.
fn opt_aliases(aliases: JsValue) -> Result<Option<HashMap<String, Vec<String>>>, JsValue> {
    if aliases.is_undefined() || aliases.is_null() {
        Ok(None)
    } else {
        serde_wasm_bindgen::from_value(aliases)
            .map(Some)
            .map_err(|e| JsValue::from_str(&format!("invalid aliases: {e}")))
    }
}

/// Deserialize the `key` JS argument shared by [`restore`] and
/// [`restore_guarded`] — the `{fake: original}` restore map returned by
/// [`redact`]. `undefined`/`null` means "no key" (an empty map); otherwise the
/// map is deserialized, mapping any failure to the SAME `invalid key` JS
/// `Error`. Mirrors [`opt_aliases`] (by-value `JsValue`, `Result<_, JsValue>`).
fn opt_key(key: JsValue) -> Result<HashMap<String, String>, JsValue> {
    if key.is_undefined() || key.is_null() {
        Ok(HashMap::new())
    } else {
        serde_wasm_bindgen::from_value(key)
            .map_err(|e| JsValue::from_str(&format!("invalid key: {e}")))
    }
}

/// Restore redacted text using the `key` map (`{fake: original}`) returned by
/// [`redact`]. `aliases` is an optional `{fake: [alternate-transliteration,
/// ...]}` map — mirrors the Python `restore(text, key, aliases=...)` /
/// `restore_json` / `restore_csv` faces, so a reply that rewrote a fake into
/// one of its aliases (e.g. pinyin for a Chinese name) still round-trips.
/// `undefined` / `null` means "no aliases", identical to omitting the
/// argument entirely from JS.
///
/// `aliases` is APPENDED after `key` rather than inserted before it, so
/// existing two-argument callers (`restore(text, key)`) are unaffected — a
/// JS call that does not pass a third argument gets `undefined` for it, the
/// same as every optional trailing argument on this binding.
///
/// # Security: UNGUARDED by default (a stated trade-off)
///
/// This entry point is **unguarded** — it applies the `key` (+ `aliases`) map
/// unconditionally, with NO (P)rovenance or (S)cope check. A caller who
/// restores attacker-chosen text against a key can therefore surface
/// originals for tokens that were never part of the intended exchange. This
/// is a DELIBERATE trade-off: `restore` keeps the minimal `(text, key)`
/// roundtrip the browser demo and simple integrations depend on, and (unlike
/// the Python `restore()` shim, which fails closed by default since v0.8.0)
/// this browser binding does NOT guard by default in this release.
///
/// For fail-closed, **Python-parity** behaviour use [`restore_guarded`]: it runs
/// the core (P)rovenance + (S)cope guard against a caller-supplied anchor and
/// refuses (`outcome: "blocked"`) when provenance cannot be proven. New
/// security-sensitive callers SHOULD prefer [`restore_guarded`]. (A
/// guarded-by-default flip / rename for this binding is deferred to a future
/// wasm-hardening pass.)
#[wasm_bindgen]
pub fn restore(text: &str, key: JsValue, aliases: JsValue) -> Result<String, JsValue> {
    set_panic_hook();

    let key = opt_key(key)?;

    let aliases = opt_aliases(aliases)?;

    // `alias_collisions` is discarded here — this entry point's return shape
    // is a bare `String`; a caller that needs collision detail should use
    // [`restore_guarded`], whose `events` surface an `alias_collision` guard
    // event the same way the PyO3 binding does.
    restore_full(text, &key, aliases.as_ref(), None)
        .map(|(result, _)| result)
        .map_err(|e| JsValue::from_str(&e.0))
}

// ── restore_guarded: anchor-taking (P)rovenance + (S)cope guard ───────────────

/// The `anchor` object shape `{ nonce: string, scope: string[] }` a JS caller
/// passes to [`restore_guarded`] — mirrors how `src/argus_redact/server.py`
/// reconstructs a core [`Anchor`] from a JSON `{"nonce": str, "scope": [...]}`
/// request field.
#[derive(Deserialize)]
struct AnchorSpec {
    nonce: String,
    scope: Vec<String>,
}

/// One guard check's outcome, for JS. `kind` is the guard event's stable
/// snake_case name — the SAME vocabulary the PyO3 `restore_guarded` binding
/// uses (`crates/argus-redact-py/src/restore.rs`), so a caller sees identical
/// strings regardless of which binding served the restore. `tokens` is the
/// core [`GuardEvent`](argus_redact_core::GuardEvent)'s `detail` verbatim — a
/// bare data carrier, NO prose; the demo layer owns any human-readable
/// rendering.
#[derive(Serialize)]
struct GuardEventJs {
    kind: String,
    count: usize,
    tokens: Option<Vec<String>>,
}

/// [`restore_guarded`]'s return shape `{ restored, outcome, events }` —
/// STRUCTURED-ONLY, no human-readable prose. Mirrors the PyO3
/// `restore_guarded` binding's `(restored, alias_collisions, events,
/// outcome)` tuple, minus `alias_collisions` (not part of this browser-facing
/// contract — a JS caller that needs it can still read it from `redact`'s
/// `aliases`-free `key`-only roundtrip).
#[derive(Serialize)]
struct GuardedRestoreJs {
    restored: String,
    outcome: String,
    events: Vec<GuardEventJs>,
}

/// Anchor-taking guarded restore — the browser-facing counterpart to the
/// PyO3 `restore_guarded` binding, and the **fail-closed, Python-parity**
/// counterpart to the unguarded [`restore`] (which applies the key with no
/// provenance/scope check — see its doc for that trade-off). Runs the core
/// (P)rovenance + (S)cope guard (`restore_full_guarded`) and returns a
/// STRUCTURED-ONLY `{ restored, outcome, events }` object; no human-readable
/// prose crosses this boundary (the demo layer owns any zh/en copy over these
/// codes).
///
/// `anchor` is deserialized as `{ nonce: string, scope: string[] }`
/// ([`AnchorSpec`]), mirroring `src/argus_redact/server.py`'s reconstruction
/// of an `Anchor` from a JSON request body.
///
/// `anchor` `undefined`/`null` means the caller supplied no provenance anchor
/// at all. This wasm binding is the TOP-LEVEL browser caller of the guard —
/// there is no further Python/JS shim above it — so it owns the no-anchor
/// policy itself, mirroring the Python `restore()` shim's `anchor is None`
/// branch (`src/argus_redact/pure/restore.py`): fail closed with a single
/// `guard_no_anchor` event (`count` = the key's size) rather than falling
/// through to an unguarded restore. `restored` in that case is the raw input
/// `text`, byte-for-byte UNCHANGED — not even nonce-stripped, since no anchor
/// means nothing was there to prove any nonce is ours.
///
/// `aliases` is an optional `{fake: [alternate-transliteration, ...]}` map,
/// APPENDED after `anchor` (never inserted before it — an existing
/// three-argument JS call site must keep meaning `(text, key, anchor)`, not
/// silently reinterpret its third argument as aliases). It mirrors the same
/// parameter on [`restore`]; if the caller's aliases collide (two fakes
/// claiming the same alias), that already surfaces as an `alias_collision`
/// event via `result.events` below — no extra wiring needed here.
#[wasm_bindgen]
pub fn restore_guarded(
    text: &str,
    key: JsValue,
    anchor: JsValue,
    aliases: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let key = opt_key(key)?;

    if anchor.is_undefined() || anchor.is_null() {
        let out = GuardedRestoreJs {
            restored: text.to_string(),
            outcome: RestoreOutcome::Blocked.as_str().to_string(),
            events: vec![GuardEventJs {
                kind: GuardEventKind::GuardNoAnchor.as_str().to_string(),
                count: key.len(),
                tokens: None,
            }],
        };
        return serialize_result(&out);
    }

    let spec: AnchorSpec = serde_wasm_bindgen::from_value(anchor)
        .map_err(|e| JsValue::from_str(&format!("invalid anchor: {e}")))?;
    let core_anchor = Anchor::new(spec.nonce, spec.scope.into_iter().collect());

    let aliases = opt_aliases(aliases)?;

    let result = restore_full_guarded(text, &key, aliases.as_ref(), None, Some(&core_anchor))
        .map_err(|e| JsValue::from_str(&e.0))?;

    let out = GuardedRestoreJs {
        restored: result.restored,
        outcome: result.outcome.as_str().to_string(),
        events: result
            .events
            .iter()
            .map(|ev| GuardEventJs {
                kind: ev.kind.as_str().to_string(),
                count: ev.count,
                tokens: ev.detail.clone(),
            })
            .collect(),
    };
    serialize_result(&out)
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

        let opts = parse_opts(opts)?;

        // lang="auto" needs the FULL text to script-detect (see `resolve_auto_lang`);
        // a stream has none at construction, so refuse it loudly rather than pass
        // the literal "auto" lang through and silently under-redact every chunk.
        if lang_is_auto(&opts.lang) {
            return Err(JsValue::from_str(
                "lang='auto' is not supported for the streaming redactor — \
                 auto-detection needs the full text, which a stream does not have \
                 at construction; pass a concrete lang (e.g. 'zh' or 'en')",
            ));
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
                Ok(r) => flatten_l1(r),
                // A detect failure (e.g. oversize buffer) yields no spans → the
                // carry-window falls back to its non-entity-aware cut; the redact
                // closure surfaces the real error on emit.
                Err(_) => DetectSpans::default(),
            }
        });

        // Redact closure: detect-once path — redact the GIVEN pre-detected,
        // range-shifted entities over `text`. `build_info` runs over `spans.entities`
        // (this path's own set — the same set `replace` consumes, unchanged from
        // a414e4a), then the shared `replace_and_grammar` tail (`replace` + en-grammar)
        // — the SAME tail the one-shot `redact_segment` runs. No internal re-detect
        // (the core engine already detected once over the full ±W buffer and shifted
        // the spans into the emit range). Threads the accumulated key (the
        // `Rc<RefCell>` mirror the core keeps in sync) as `existing_key` for
        // cross-chunk collision continuity so the same original reuses its existing
        // fake across segments. The segment's `keep_downgraded` / `mask_collisions`
        // signals are not part of the streaming face, so the `RedactSegmentWithSignals`
        // wrapper is unwrapped to its segment.
        let redact_params = Rc::clone(&params);
        let redact_key = Rc::clone(&accumulated_key);
        let redact: BoxedRedact = Box::new(move |text: &str, spans: &DetectSpans| {
            let existing = redact_key.borrow();
            let (info_map, person_prefix, org_prefix) = build_info(
                &spans.entities,
                redact_params.config.as_ref(),
                &redact_params.langs,
            );
            replace_and_grammar(
                &redact_params,
                text,
                &info_map,
                &person_prefix,
                &org_prefix,
                &spans.entities,
                Some(&*existing),
            )
            .map(|with_signals| with_signals.segment)
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
        serialize_result(&out)
    }
}

// ── regression: lang="auto" must resolve, not silently under-redact ───────────
//
// Pure-Rust tests over `resolve_auto_lang` + the core `detect_l1` seam, runnable
// via `cargo test -p argus-redact-wasm --lib` WITHOUT a wasm runtime (the JsValue
// public API in `tests/*.rs` still needs `wasm-pack test --node`). They pin the
// under-redaction the fix closes: a literal `"auto"` lang is NOT a real language,
// so the language-gated detectors are skipped unless `"auto"` is resolved first.
#[cfg(test)]
mod auto_lang_tests {
    use super::{lang_is_auto, resolve_auto_lang, StringOrVec};
    use argus_redact_core::redact_l1::detect_l1;

    const LEAKY: &str = "张伟的电话13800138000";

    /// Sanity: the LITERAL `"auto"` lang matches neither zh nor en, so the zh
    /// person detector never runs and 张伟 would be left in the clear — the exact
    /// mechanism the fix must close.
    #[test]
    fn literal_auto_lang_skips_the_zh_person_detector() {
        let d = detect_l1(LEAKY, &["auto".to_string()], &[]).unwrap();
        assert!(
            d.person.is_empty(),
            "the literal \"auto\" lang is expected to skip the zh person detector"
        );
    }

    /// The fix: `resolve_auto_lang` maps the `"auto"` sentinel to the
    /// script-detected langs (`["zh"]` here), so BOTH 张伟 (person) and the phone
    /// (L1 regex) are detected — neither is left unredacted.
    #[test]
    fn resolve_auto_lang_recovers_zh_person_and_phone() {
        let resolved = resolve_auto_lang(vec!["auto".to_string()], LEAKY);
        assert_eq!(resolved, vec!["zh".to_string()], "\"auto\" must resolve to zh");

        let d = detect_l1(LEAKY, &resolved, &[]).unwrap();
        assert!(!d.person.is_empty(), "张伟 must be detected as a person");
        assert!(!d.layer1.is_empty(), "the phone must be detected by the L1 regex");
    }

    /// A concrete lang list is untouched by the resolver.
    #[test]
    fn non_auto_lang_passes_through_unchanged() {
        assert_eq!(
            resolve_auto_lang(vec!["en".to_string()], LEAKY),
            vec!["en".to_string()]
        );
        assert_eq!(
            resolve_auto_lang(vec!["zh".to_string(), "en".to_string()], LEAKY),
            vec!["zh".to_string(), "en".to_string()]
        );
    }

    /// The streaming constructor REJECTS `lang="auto"` (a stream can't script-detect
    /// without the full text). `lang_is_auto` is the predicate behind that refusal —
    /// pin it so a future change can't silently re-open the per-chunk under-redaction.
    #[test]
    fn lang_is_auto_flags_only_the_solo_auto_sentinel() {
        use StringOrVec::{Many, One};
        assert!(lang_is_auto(&Some(One("auto".to_string()))));
        assert!(lang_is_auto(&Some(Many(vec!["auto".to_string()]))));
        assert!(!lang_is_auto(&Some(One("zh".to_string()))));
        assert!(!lang_is_auto(&None));
        // "auto" alongside a concrete lang is NOT the solo sentinel → not rejected.
        assert!(!lang_is_auto(&Some(Many(vec![
            "auto".to_string(),
            "zh".to_string()
        ]))));
    }
}

// ── regression: one-shot build_info must resolve over the RAW pre-finalize set ──
//
// `person_prefix` is the SHARED pseudonym-generator prefix for EVERY non-org
// `pseudonym`-strategy entity (e.g. `school`; see core `replace.rs` — a non-org
// pseudonym entity with no per-type prefix override draws from `person_prefix`).
// Resolving the one-shot `type_info` / prefixes over the FINALIZED set instead of the
// raw pre-finalize set silently drops a config `person`-prefix override whenever a
// `person` span is merge-absorbed by an overlapping surviving `school` span: the
// school's pseudonym code flips from the override "X-…" to the fallback "P-…",
// changing BOTH the redacted text AND the key. This pins `redact_segment` to the
// raw-set order (parity with the Python reference and parent a414e4a). Runs native
// via `cargo test -p argus-redact-wasm --lib`; fails against the pre-fix (finalized)
// shape, which would emit "P-83811是名校。".
#[cfg(test)]
mod raw_typeinfo_prefix_tests {
    use super::*;

    #[test]
    fn one_shot_person_prefix_override_survives_person_absorbed_into_school() {
        // 曾宪梓中 (person) overlaps 曾宪梓中学 (school). Detection surfaces BOTH in the
        // raw set; finalize absorbs the person into the surviving school. Config
        // overrides the person prefix to "X"; the school (non-org pseudonym) draws
        // from `person_prefix`, so its code must carry "X" — exactly what the Python
        // reference `redact(...)` emits for the same (text, salt, config).
        let text = "曾宪梓中学是名校。";

        let mut config: Config = HashMap::new();
        config.insert(
            "person".to_string(),
            EntityConfig {
                strategy: None,
                prefix: Some("X".to_string()),
                replacement: None,
                label: None,
                visible_prefix: None,
                visible_suffix: None,
            },
        );
        let params = RedactParams {
            langs: vec!["zh".to_string()],
            names: Vec::new(),
            salt: Some(Salt::Int(42)),
            config: Some(config),
            unified_prefix: None,
            whitelist: keep_whitelist(),
        };

        // Preconditions — fail loudly if detection drifts (never silently vacuous):
        // the raw set carries BOTH person + school; finalize keeps school, drops person.
        let DetectSpans { entities, hints } =
            flatten_l1(detect_l1(text, &params.langs, &params.names).unwrap());
        assert!(
            entities.iter().any(|e| e.type_ == "person"),
            "precondition: a person span must be detected in the raw set: {entities:?}"
        );
        assert!(
            entities.iter().any(|e| e.type_ == "school"),
            "precondition: a school span must be detected in the raw set: {entities:?}"
        );
        let scope = FilterScope::from_hints(None, None, &hints);
        let filtered = finalize_entities(entities, &hints, &scope, text, true);
        assert!(
            filtered.iter().any(|e| e.type_ == "school"),
            "precondition: school must survive finalize: {filtered:?}"
        );
        assert!(
            !filtered.iter().any(|e| e.type_ == "person"),
            "precondition: the person span must be merge-absorbed (absent from finalized): {filtered:?}"
        );

        // The guard: build_info over the RAW set keeps the person entry, so
        // `person_prefix` = the override "X" and the surviving school's code carries
        // it. Byte-identical to the Python reference for (text, salt=42, config).
        let out = redact_segment(&params, text, None).expect("redact_segment");
        assert_eq!(
            out.segment.downstream_text, "X-83811是名校。",
            "school must redact with the config person-prefix override 'X' (build_info over the \
             RAW set); a 'P-' prefix here means build_info regressed to the finalized set"
        );
        let mut expected_key: HashMap<String, String> = HashMap::new();
        expected_key.insert("X-83811".to_string(), "曾宪梓中学".to_string());
        assert_eq!(
            out.segment.key, expected_key,
            "key must map the X-prefixed school fake to the original school name"
        );
    }
}
