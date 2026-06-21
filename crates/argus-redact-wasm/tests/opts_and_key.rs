//! wasm-bindgen tests for two silent PII-path guarantees the d.ts + doc comments
//! promise but the wrapper did not deliver. Runs in Node
//! (`wasm-pack test --node crates/argus-redact-wasm`).
//!
//!   F1 — the `key` / `aliases` fields must serialize as PLAIN JS objects, not JS
//!        `Map`s, so the documented LLM roundtrip (redact → persist key as JSON →
//!        restore) survives a `JSON.stringify` / `JSON.parse` boundary. A `Map`
//!        stringifies to `{}` and the pseudonym is never reversed (silent leak of
//!        the masking — text returned unchanged with no error).
//!
//!   F2 — an unknown opts key (a typo such as `langs` for `lang`) must be REJECTED
//!        loudly. Silently ignoring it falls back to the `zh` default, EN detection
//!        never runs, and the PII LEAKS with no error.
//!
//! Both assertions cross the SAME JS boundaries a real JS caller crosses (an actual
//! `JSON.stringify`/`JSON.parse` for F1; a plain JS object built field-by-field for
//! F2) — a Rust-side `serde_wasm_bindgen` roundtrip would mask the Map-vs-object
//! bug, so these go through `js_sys::JSON` / `js_sys::Reflect` directly.

use js_sys::{Object, Reflect, JSON};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::*;

use argus_redact_wasm::{redact, restore, StreamingRedactor};

/// Build a plain JS opts object field-by-field (exactly what a JS caller passes),
/// so no serde layer hides a typo'd key behind name resolution.
fn js_opts(pairs: &[(&str, JsValue)]) -> JsValue {
    let obj = Object::new();
    for (k, v) in pairs {
        Reflect::set(&obj, &JsValue::from_str(k), v).unwrap();
    }
    obj.into()
}

/// A JS string array (for `names`).
fn js_str_array(items: &[&str]) -> JsValue {
    let arr = js_sys::Array::new();
    for s in items {
        arr.push(&JsValue::from_str(s));
    }
    arr.into()
}

/// Round-trip a JsValue through a REAL `JSON.stringify` → `JSON.parse`, returning
/// the reparsed value (what a caller gets back after persisting the key as JSON).
fn json_roundtrip(v: &JsValue) -> JsValue {
    let s = JSON::stringify(v).expect("JSON.stringify");
    let s: String = s.into();
    JSON::parse(&s).expect("JSON.parse")
}

// ── F1: key survives JSON.stringify round-trip (one-shot) ─────────────────────

#[wasm_bindgen_test]
fn key_survives_json_roundtrip_one_shot() {
    let original = "Contact Alice Johnson at the office.";
    let opts = js_opts(&[
        ("lang", JsValue::from_str("en")),
        ("mode", JsValue::from_str("fast")),
        ("salt", JsValue::from_f64(42.0)),
        ("names", js_str_array(&["Alice Johnson"])),
    ]);

    let out = redact(original, opts).expect("redact should succeed");

    // The returned `key` must be a PLAIN object, NOT a JS Map: `JSON.stringify`
    // of a Map yields `"{}"` and the entry is lost. Assert the stringified key is
    // non-empty BEFORE the restore so a regression points straight at the shape.
    let key = Reflect::get(&out, &JsValue::from_str("key")).unwrap();
    let key_json: String = JSON::stringify(&key).expect("stringify key").into();
    assert_ne!(
        key_json, "{}",
        "key serialized to an empty object — it is a JS Map, not a plain object \
         (entries lost across JSON.stringify): {key_json}"
    );

    // The documented roundtrip: persist the key as JSON, reparse it, restore with it.
    let key_reparsed = json_roundtrip(&key);
    let redacted: String = Reflect::get(&out, &JsValue::from_str("text"))
        .unwrap()
        .as_string()
        .unwrap();
    let restored = restore(&redacted, key_reparsed).expect("restore should succeed");
    assert_eq!(
        restored, original,
        "restore(text, JSON.parse(JSON.stringify(key))) must recover the original"
    );
}

// ── F1: key survives JSON.stringify round-trip (streaming flush) ──────────────

#[wasm_bindgen_test]
fn key_survives_json_roundtrip_streaming() {
    let original = "Call John Smith at the office. Email a@b.com today. From 8.8.8.8 always.";
    let opts = js_opts(&[
        ("lang", JsValue::from_str("en")),
        ("mode", JsValue::from_str("fast")),
        ("salt", JsValue::from_f64(42.0)),
        ("names", js_str_array(&["John Smith"])),
    ]);
    let mut r = StreamingRedactor::new(opts).expect("construct StreamingRedactor");

    // Feed the whole input in small chunks, accumulate the downstream, then flush.
    let chars: Vec<char> = original.chars().collect();
    let mut downstream = String::new();
    for chunk in chars.chunks(7) {
        let s: String = chunk.iter().collect();
        let emit = r.feed(&s).expect("feed");
        let ds = Reflect::get(&emit, &JsValue::from_str("downstreamText"))
            .unwrap()
            .as_string()
            .unwrap();
        downstream.push_str(&ds);
    }
    let flush = r.flush().expect("flush");
    let flush_ds = Reflect::get(&flush, &JsValue::from_str("downstreamText"))
        .unwrap()
        .as_string()
        .unwrap();
    downstream.push_str(&flush_ds);

    // The flush carries the FINAL accumulated key snapshot.
    let key = Reflect::get(&flush, &JsValue::from_str("key")).unwrap();
    let key_json: String = JSON::stringify(&key).expect("stringify key").into();
    assert_ne!(
        key_json, "{}",
        "streaming key serialized to an empty object — it is a JS Map, not a plain \
         object (entries lost across JSON.stringify): {key_json}"
    );

    let key_reparsed = json_roundtrip(&key);
    let restored = restore(&downstream, key_reparsed).expect("restore should succeed");
    assert_eq!(
        restored, original,
        "streamed restore(downstream, JSON.parse(JSON.stringify(key))) must recover the original"
    );
}

// ── F2: unknown opts key is rejected (one-shot) ───────────────────────────────

#[wasm_bindgen_test]
fn typo_opts_key_rejected_one_shot() {
    // `langs` is a typo for `lang`; silently ignoring it falls back to the zh
    // default, EN SSN detection never runs, and the SSN LEAKS. It must THROW.
    let opts = js_opts(&[
        ("salt", JsValue::from_f64(42.0)),
        ("langs", JsValue::from_str("en")),
    ]);
    let err = redact("SSN 123-45-6789", opts);
    assert!(
        err.is_err(),
        "a typo'd opts key (langs) must be rejected, not silently ignored"
    );
}

#[wasm_bindgen_test]
fn bogus_opts_key_rejected_one_shot() {
    let opts = js_opts(&[
        ("lang", JsValue::from_str("en")),
        ("salt", JsValue::from_f64(42.0)),
        ("totally_made_up", JsValue::from_bool(true)),
    ]);
    let err = redact("hello", opts);
    assert!(err.is_err(), "an unknown opts key must be rejected");
}

#[wasm_bindgen_test]
fn valid_opts_keys_accepted_one_shot() {
    // The control: a correct `lang` (plus the rest of the known set) must WORK.
    let opts = js_opts(&[
        ("lang", JsValue::from_str("en")),
        ("mode", JsValue::from_str("fast")),
        ("salt", JsValue::from_f64(42.0)),
        ("names", js_str_array(&["Alice Johnson"])),
        ("unified_prefix", JsValue::from_str("X")),
    ]);
    let out = redact("Contact Alice Johnson.", opts).expect("valid opts must succeed");
    // It is a real result object with a `text` field.
    assert!(out.is_object(), "redact must return an object for valid opts");
    let text = Reflect::get(&out, &JsValue::from_str("text"))
        .unwrap()
        .as_string()
        .unwrap();
    assert!(!text.contains("Alice Johnson"), "the name should have been redacted");
}

// ── F2: unknown opts key is rejected (streaming constructor) ──────────────────

#[wasm_bindgen_test]
fn typo_opts_key_rejected_streaming() {
    let opts = js_opts(&[
        ("salt", JsValue::from_f64(42.0)),
        ("langs", JsValue::from_str("en")),
    ]);
    let r = StreamingRedactor::new(opts);
    assert!(
        r.is_err(),
        "a typo'd opts key (langs) must be rejected by the streaming constructor"
    );
}

#[wasm_bindgen_test]
fn valid_opts_keys_accepted_streaming() {
    let opts = js_opts(&[
        ("lang", JsValue::from_str("en")),
        ("mode", JsValue::from_str("fast")),
        ("salt", JsValue::from_f64(42.0)),
    ]);
    assert!(
        StreamingRedactor::new(opts).is_ok(),
        "valid opts must construct a StreamingRedactor"
    );
}

// Silence an unused-import lint if `JsCast` ends up unreferenced in some configs.
#[allow(dead_code)]
fn _assert_jscast_in_scope(v: JsValue) -> Option<Object> {
    v.dyn_into::<Object>().ok()
}
