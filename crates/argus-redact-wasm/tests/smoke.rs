//! wasm-bindgen smoke test for the fast-mode `redact` / `restore` wrappers.
//!
//! Runs in Node (`wasm-pack test --node crates/argus-redact-wasm`). Exercises the
//! end-to-end fast-mode roundtrip over the Rust core: a zh text carrying a phone
//! (regex L1) + a known person name (L1b person) is redacted at `salt=42`, then
//! restored. We assert (1) the raw PII is GONE from the redacted text and (2)
//! `restore(redacted, key) == original`.

use argus_redact_wasm::{redact, restore};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

/// The opts struct the wasm `redact` deserializes. Serialized here so the test
/// builds the JsValue exactly as a JS caller would.
#[derive(Serialize)]
struct Opts {
    lang: String,
    mode: String,
    salt: i64,
    names: Vec<String>,
}

/// The `{ text, key, aliases }` shape `redact` returns. We deserialize it back to
/// inspect the redacted text + key.
#[derive(Deserialize)]
struct RedactOut {
    text: String,
    key: std::collections::HashMap<String, String>,
}

#[wasm_bindgen_test]
fn redact_masks_and_restores() {
    let original = "我叫张伟，电话13800138000。";

    let opts = serde_wasm_bindgen::to_value(&Opts {
        lang: "zh".to_string(),
        mode: "fast".to_string(),
        salt: 42,
        // 张伟 is a standalone zh name; pass it explicitly so fast mode catches it.
        names: vec!["张伟".to_string()],
    })
    .unwrap();

    let result_js = redact(original, opts).expect("redact should succeed");
    let result: RedactOut = serde_wasm_bindgen::from_value(result_js).unwrap();

    // 1. The raw PII must be ABSENT from the redacted text.
    assert!(
        !result.text.contains("13800138000"),
        "phone leaked into redacted text: {}",
        result.text
    );
    assert!(
        !result.text.contains("张伟"),
        "person name leaked into redacted text: {}",
        result.text
    );
    // The redaction actually happened (text changed) and the key is non-empty.
    assert_ne!(result.text, original, "text must have changed");
    assert!(!result.key.is_empty(), "key must record the substitutions");

    // 2. restore(redacted, key) must recover the ORIGINAL input exactly.
    let key_js = serde_wasm_bindgen::to_value(&result.key).unwrap();
    let restored = restore(&result.text, key_js, JsValue::UNDEFINED).expect("restore should succeed");
    assert_eq!(restored, original, "roundtrip must recover the original");
}

/// Cross-runtime pseudonym parity: wasm now mints `P-NNNNN` codes from the SAME
/// CPython-exact MT19937 (`MtRandomSource`) the Python wheel uses, so for a fixed
/// `(text, salt)` the code is byte-identical to what the Python build produces.
///
/// The expected code below was captured from the Python wheel:
///   redact("Contact Alice Johnson at the office.", salt=42, mode="fast",
///          lang="en", names=["Alice Johnson"])  →  "Contact P-83811 at the office."
/// Before this change wasm used a divergent SHAKE stream and produced a DIFFERENT
/// code; this test pins the parity that now holds.
#[wasm_bindgen_test]
fn pseudonym_code_matches_python_wheel() {
    #[derive(Serialize)]
    struct EnOpts {
        lang: String,
        mode: String,
        salt: i64,
        names: Vec<String>,
    }
    let original = "Contact Alice Johnson at the office.";
    let opts = serde_wasm_bindgen::to_value(&EnOpts {
        lang: "en".to_string(),
        mode: "fast".to_string(),
        salt: 42,
        names: vec!["Alice Johnson".to_string()],
    })
    .unwrap();

    let result_js = redact(original, opts).expect("redact should succeed");
    let result: RedactOut = serde_wasm_bindgen::from_value(result_js).unwrap();

    // The exact code the Python wheel produces for this (text, salt) — proves the
    // wasm MT19937 stream is byte-identical to CPython's random.Random(seed).
    assert_eq!(
        result.text, "Contact P-83811 at the office.",
        "wasm pseudonym code must match the Python wheel's code"
    );
    assert_eq!(
        result.key.get("P-83811").map(String::as_str),
        Some("Alice Johnson"),
        "key must map the Python-identical code back to the original"
    );
}

#[wasm_bindgen_test]
fn non_fast_mode_rejected() {
    #[derive(Serialize)]
    struct ModeOpts {
        mode: String,
    }
    let opts = serde_wasm_bindgen::to_value(&ModeOpts { mode: "ner".to_string() }).unwrap();
    let err = redact("hello", opts);
    assert!(err.is_err(), "mode='ner' must be rejected in wasm");
}

#[wasm_bindgen_test]
fn realistic_without_salt_errors() {
    // Build the opts as a typed nested struct so serde-wasm-bindgen emits a plain
    // JS object graph (what a real JS caller passes) — NOT a nested `serde_json::Value`,
    // which serde-wasm-bindgen would serialize as a JS Map and the struct
    // deserializer would not read back.
    #[derive(Serialize)]
    struct EntityCfg {
        strategy: String,
    }
    #[derive(Serialize)]
    struct CfgOpts {
        lang: String,
        mode: String,
        // realistic strategy on phone, but NO salt → must error (no env fallback in wasm).
        config: std::collections::HashMap<String, EntityCfg>,
    }
    let mut config = std::collections::HashMap::new();
    config.insert("phone".to_string(), EntityCfg { strategy: "realistic".to_string() });
    let opts = serde_wasm_bindgen::to_value(&CfgOpts {
        lang: "zh".to_string(),
        mode: "fast".to_string(),
        config,
    })
    .unwrap();
    let err = redact("电话13800138000", opts);
    assert!(err.is_err(), "realistic strategy without salt must error");
}
