//! wasm-bindgen tests for the anchor-taking `restore_guarded` — the
//! browser-facing counterpart to the PyO3 `restore_guarded` binding. Runs in
//! Node (`wasm-pack test --node crates/argus-redact-wasm`).
//!
//! `restore_guarded` returns a STRUCTURED-ONLY `{ restored, outcome, events }`
//! object (no human-readable prose — the demo layer owns any zh/en copy over
//! these codes), so these tests read the shape with `js_sys::Reflect` exactly
//! as a real JS caller would, mirroring the helper pattern in
//! `opts_and_key.rs`.
//!
//! Covers the four cases in the guard's decision surface:
//!   (a) an anchor is present but its nonce is absent from the reply — the
//!       (P)rovenance check fails closed: `outcome == "blocked"`, `restored`
//!       is the raw input, unchanged.
//!   (b) a real redact -> reply -> restore roundtrip with `scope` covering
//!       every returned pseudonym: `outcome == "complete"`, the original is
//!       fully recovered, and the echoed nonce is stripped.
//!   (c) `scope` excludes one of two returned pseudonym codes: that code is
//!       withheld and reported via an `out_of_scope_pseudonym` event carrying
//!       `tokens`; `outcome == "partial"`.
//!   (d) `anchor` is `undefined`/`null` — the wasm binding is the top-level
//!       browser caller, so IT owns the no-anchor policy: fail closed with a
//!       `guard_no_anchor` event rather than falling through to an unguarded
//!       restore.

use js_sys::{Object, Reflect};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::*;

use argus_redact_wasm::{redact, restore_guarded};

/// A real 32-hex-char nonce (the shape `secrets.token_hex(16)` / `make_anchor`
/// produce) — well above the guard's `MIN_NONCE_LEN` floor.
const NONCE: &str = "0123456789abcdef0123456789abcdef";

/// Build a plain JS object field-by-field (exactly what a JS caller passes).
fn js_obj(pairs: &[(&str, JsValue)]) -> JsValue {
    let obj = Object::new();
    for (k, v) in pairs {
        Reflect::set(&obj, &JsValue::from_str(k), v).unwrap();
    }
    obj.into()
}

/// A JS string array.
fn js_str_array(items: &[&str]) -> JsValue {
    let arr = js_sys::Array::new();
    for s in items {
        arr.push(&JsValue::from_str(s));
    }
    arr.into()
}

/// Read a field off a JsValue object and unwrap it as a Rust `String`.
fn get_str(obj: &JsValue, field: &str) -> String {
    Reflect::get(obj, &JsValue::from_str(field))
        .unwrap()
        .as_string()
        .unwrap_or_else(|| panic!("field {field:?} is not a string"))
}

/// Read a field off a JsValue object, returning the raw JsValue.
fn get(obj: &JsValue, field: &str) -> JsValue {
    Reflect::get(obj, &JsValue::from_str(field)).unwrap()
}

// ── (a) provenance failure: anchor present, nonce absent from the reply ──────

#[wasm_bindgen_test]
fn provenance_failed_when_nonce_absent_blocks_and_returns_input_unchanged() {
    let key = js_obj(&[("P-1", JsValue::from_str("张三"))]);
    let anchor = js_obj(&[
        ("nonce", JsValue::from_str(NONCE)),
        ("scope", js_str_array(&["P-1"])),
    ]);
    let text = "P-1 says hello, no nonce here.";

    let out = restore_guarded(text, key, anchor, JsValue::UNDEFINED).expect("a blocked outcome is not an error");

    assert_eq!(get_str(&out, "outcome"), "blocked");
    assert_eq!(get_str(&out, "restored"), text, "raw input must come back unchanged");

    let events: js_sys::Array = get(&out, "events").dyn_into().unwrap();
    assert_eq!(events.length(), 1);
    assert_eq!(get_str(&events.get(0), "kind"), "provenance_failed");
}

// ── (b) full roundtrip: scope covers every code -> complete, nonce stripped ─

#[wasm_bindgen_test]
fn full_scope_roundtrip_recovers_original_and_strips_nonce() {
    let original = "Contact Alice Johnson at the office.";
    let opts = js_obj(&[
        ("lang", JsValue::from_str("en")),
        ("mode", JsValue::from_str("fast")),
        ("salt", JsValue::from_f64(42.0)),
        ("names", js_str_array(&["Alice Johnson"])),
    ]);
    let redacted = redact(original, opts).expect("redact should succeed");
    let redacted_text = get_str(&redacted, "text");
    let key = get(&redacted, "key");

    // scope = Object.keys(key) — every pseudonym the redact call minted.
    let key_obj: Object = key.clone().dyn_into().expect("key must be a plain object");
    let scope = Object::keys(&key_obj);
    assert!(scope.length() >= 1, "redact must have produced at least one pseudonym");

    let anchor = js_obj(&[("nonce", JsValue::from_str(NONCE)), ("scope", scope.into())]);
    let reply = format!("{redacted_text}\n{NONCE}");

    let out = restore_guarded(&reply, key, anchor, JsValue::UNDEFINED).expect("restore_guarded should succeed");

    assert_eq!(get_str(&out, "outcome"), "complete");
    assert_eq!(get_str(&out, "restored"), original);

    let events: js_sys::Array = get(&out, "events").dyn_into().unwrap();
    assert_eq!(events.length(), 0, "a full-scope happy path carries no guard events");
}

// ── (c) partial scope: one returned code excluded -> withheld + reported ────

#[wasm_bindgen_test]
fn out_of_scope_code_present_in_reply_is_partial_and_withheld() {
    let original = "Contact Alice Johnson and Bob Smith at the office.";
    let opts = js_obj(&[
        ("lang", JsValue::from_str("en")),
        ("mode", JsValue::from_str("fast")),
        ("salt", JsValue::from_f64(42.0)),
        ("names", js_str_array(&["Alice Johnson", "Bob Smith"])),
    ]);
    let redacted = redact(original, opts).expect("redact should succeed");
    let redacted_text = get_str(&redacted, "text");
    let key = get(&redacted, "key");

    let key_obj: Object = key.clone().dyn_into().expect("key must be a plain object");
    let all_codes = Object::keys(&key_obj);
    assert!(all_codes.length() >= 2, "need two distinct pseudonym codes for this test");

    // Scope covers ONLY the first code; the second is out-of-scope.
    let in_scope = js_sys::Array::new();
    in_scope.push(&all_codes.get(0));
    let excluded_code = all_codes.get(1).as_string().unwrap();

    let anchor = js_obj(&[("nonce", JsValue::from_str(NONCE)), ("scope", in_scope.into())]);
    let reply = format!("{redacted_text}\n{NONCE}");

    let out = restore_guarded(&reply, key, anchor, JsValue::UNDEFINED).expect("restore_guarded should succeed");

    assert_eq!(get_str(&out, "outcome"), "partial");

    let events: js_sys::Array = get(&out, "events").dyn_into().unwrap();
    let mut saw_out_of_scope = false;
    for i in 0..events.length() {
        let ev = events.get(i);
        if get_str(&ev, "kind") == "out_of_scope_pseudonym" {
            saw_out_of_scope = true;
            let tokens: js_sys::Array = get(&ev, "tokens")
                .dyn_into()
                .expect("out_of_scope_pseudonym must carry tokens");
            assert!(tokens.length() >= 1, "tokens must list the withheld code(s)");
        }
    }
    assert!(saw_out_of_scope, "expected an out_of_scope_pseudonym event");

    // The excluded code's original must NOT have been substituted back in.
    let restored = get_str(&out, "restored");
    assert!(
        restored.contains(&excluded_code),
        "the out-of-scope code must remain withheld verbatim: {restored}"
    );
}

// ── (d) no anchor at all -> fail closed with guard_no_anchor ─────────────────

#[wasm_bindgen_test]
fn missing_anchor_fails_closed_with_guard_no_anchor_event() {
    let text = "P-1 says hello.";
    let key_len = 1usize;

    for anchor in [JsValue::UNDEFINED, JsValue::NULL] {
        let key = js_obj(&[("P-1", JsValue::from_str("张三"))]);
        let out = restore_guarded(text, key, anchor, JsValue::UNDEFINED).expect("a blocked outcome is not an error");

        assert_eq!(get_str(&out, "outcome"), "blocked");
        assert_eq!(get_str(&out, "restored"), text, "raw input must come back unchanged");

        let events: js_sys::Array = get(&out, "events").dyn_into().unwrap();
        assert_eq!(events.length(), 1);
        let ev0 = events.get(0);
        assert_eq!(get_str(&ev0, "kind"), "guard_no_anchor");
        assert_eq!(get(&ev0, "count").as_f64().unwrap() as usize, key_len);
    }
}
