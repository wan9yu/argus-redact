//! wasm-bindgen tests for optional `aliases` forwarding on `restore` /
//! `restore_guarded`. Runs in Node (`wasm-pack test --node crates/argus-redact-wasm`).
//!
//! Parity with the Python faces (`restore(text, key, aliases=...)`,
//! `restore_json`/`restore_csv`, `StreamingRestorer`): an LLM that rewrites a
//! realistic fake into an alternate transliteration only round-trips back to
//! the original if that alias was supplied. Before this, the wasm bindings
//! took `key` only — an alias form was silently left unrestored in the
//! browser even when the Python bindings already recovered it.
//!
//! `aliases` is APPENDED as a new trailing argument on both `restore(text,
//! key, aliases)` and `restore_guarded(text, key, anchor, aliases)` —
//! deliberately never inserted before an existing positional parameter, so a
//! JS caller that omits it (as every pre-existing call site does) keeps
//! getting `undefined`, which this binding treats identically to "no
//! aliases".

use js_sys::{Object, Reflect};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

use argus_redact_wasm::{restore, restore_guarded};

const NONCE: &str = "0123456789abcdef0123456789abcdef";

fn js_obj(pairs: &[(&str, JsValue)]) -> JsValue {
    let obj = Object::new();
    for (k, v) in pairs {
        Reflect::set(&obj, &JsValue::from_str(k), v).unwrap();
    }
    obj.into()
}

fn js_str_array(items: &[&str]) -> JsValue {
    let arr = js_sys::Array::new();
    for s in items {
        arr.push(&JsValue::from_str(s));
    }
    arr.into()
}

fn get_str(obj: &JsValue, field: &str) -> String {
    Reflect::get(obj, &JsValue::from_str(field))
        .unwrap()
        .as_string()
        .unwrap_or_else(|| panic!("field {field:?} is not a string"))
}

// ── restore: aliases appended as a new trailing (optional) argument ─────────

#[wasm_bindgen_test]
fn restore_forwards_aliases_for_an_alternate_transliteration() {
    let key = js_obj(&[("王五", JsValue::from_str("王建国"))]);
    let aliases = js_obj(&[("王五", js_str_array(&["Wang Wu"]))]);

    let restored =
        restore("Wang Wu phoned", key, aliases).expect("restore with aliases should succeed");

    assert_eq!(restored, "王建国 phoned");
}

#[wasm_bindgen_test]
fn restore_without_aliases_leaves_the_alias_form_unrestored() {
    let key = js_obj(&[("王五", JsValue::from_str("王建国"))]);

    // `undefined` is exactly what a JS caller gets for an omitted trailing
    // argument — same contract as `key`/`anchor` already use elsewhere in
    // this binding.
    let restored = restore("Wang Wu phoned", key, JsValue::UNDEFINED)
        .expect("restore without aliases should still succeed");

    assert_eq!(
        restored, "Wang Wu phoned",
        "no aliases supplied -> the alternate transliteration is not restored"
    );
}

#[wasm_bindgen_test]
fn restore_treats_null_aliases_the_same_as_undefined() {
    let key = js_obj(&[("王五", JsValue::from_str("王建国"))]);

    let restored =
        restore("Wang Wu phoned", key, JsValue::NULL).expect("restore should succeed");

    assert_eq!(restored, "Wang Wu phoned");
}

// ── restore_guarded: aliases appended AFTER anchor ───────────────────────────

#[wasm_bindgen_test]
fn restore_guarded_forwards_aliases_within_a_full_scope_roundtrip() {
    let key = js_obj(&[("王五", JsValue::from_str("王建国"))]);
    let aliases = js_obj(&[("王五", js_str_array(&["Wang Wu"]))]);
    let anchor = js_obj(&[
        ("nonce", JsValue::from_str(NONCE)),
        ("scope", js_str_array(&["王五"])),
    ]);
    let reply = format!("Wang Wu phoned\n{NONCE}");

    let out = restore_guarded(&reply, key, anchor, aliases)
        .expect("restore_guarded with aliases should succeed");

    assert_eq!(get_str(&out, "outcome"), "complete");
    assert_eq!(get_str(&out, "restored"), "王建国 phoned");
}

#[wasm_bindgen_test]
fn restore_guarded_without_aliases_argument_behaves_as_before() {
    let key = js_obj(&[("王五", JsValue::from_str("王建国"))]);
    let anchor = js_obj(&[
        ("nonce", JsValue::from_str(NONCE)),
        ("scope", js_str_array(&["王五"])),
    ]);
    let reply = format!("王五\n{NONCE}");

    // Omitting the trailing `aliases` argument entirely, exactly as every
    // pre-existing JS call site does.
    let out: JsValue = restore_guarded(&reply, key, anchor, JsValue::UNDEFINED)
        .expect("restore_guarded without aliases should still succeed");

    assert_eq!(get_str(&out, "outcome"), "complete");
    assert_eq!(get_str(&out, "restored"), "王建国");
}
