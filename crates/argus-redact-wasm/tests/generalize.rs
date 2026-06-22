//! wasm↔Python byte-parity for the lossy `generalize` location-coarsening strategy.
//!
//! Runs in Node (`wasm-pack test --node crates/argus-redact-wasm`). The oracle is
//! the Python golden `tests/core/test_generalize_strategy.py`: the SAME fixture
//! text + opts must produce the SAME coarsened `.text` through the wasm wrapper.
//!
//! `generalize` maps a detected location/address span to its city (default) or
//! province ancestor via the GB/T 2260 gazetteer in the Rust core. It is LOSSY —
//! the coarse value (杭州市) maps back to many originals — so it emits NO restore-key
//! entry. These tests assert the coarsening output is byte-identical to Python:
//!   - default level → `杭州市`, original street span `文一路100号` gone;
//!   - `level:"province"` → `浙江省`.
//!
//! The opts are modeled as typed structs (like `tests/parity.rs`) so
//! `serde_wasm_bindgen::to_value` emits a PLAIN JS object the wasm `RedactOpts`
//! deserializer reads — and so the per-type config sub-object carries the
//! `strategy` (+ `level`) keys exactly as the Python `config` dict does. The
//! `level` key exercises the wasm `EntityConfigOpt.level` → `to_core_config` thread.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use wasm_bindgen_test::*;

use argus_redact_wasm::redact;

/// Fixed salt the Python golden uses (`salt=42`).
const SALT: i64 = 42;

/// The fixture sentence whose address span (杭州西湖区文一路100号) is detected in
/// fast mode. Byte-identical to `_TEXT` in `tests/core/test_generalize_strategy.py`.
const TEXT: &str = "他住在杭州西湖区文一路100号。";

/// Per-type config entry. Carries `strategy` (+ optional `level`), mirroring the
/// Python `config` dict. `skip_serializing_if` keeps the emitted JS object minimal.
#[derive(Serialize)]
struct EntityCfg {
    strategy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<String>,
}

/// The redact opts object. Fields omitted when absent so the emitted JS object is
/// exactly what the Python kwargs carry. `mode` is always `"fast"` (wasm's only mode).
#[derive(Serialize)]
struct Opts {
    lang: Vec<String>,
    mode: String,
    salt: i64,
    config: HashMap<String, EntityCfg>,
}

/// The `{ text, key, aliases }` shape `redact` returns; we read back `text` + `key`.
#[derive(Deserialize)]
struct RedactOut {
    text: String,
    key: HashMap<String, String>,
}

/// Build opts that set `generalize` on both `location` and `address`, with an
/// optional coarsening `level` (None = default city level).
fn generalize_opts(level: Option<&str>) -> Opts {
    let mut config = HashMap::new();
    for ty in ["location", "address"] {
        config.insert(
            ty.to_string(),
            EntityCfg {
                strategy: "generalize".to_string(),
                level: level.map(|s| s.to_string()),
            },
        );
    }
    Opts {
        lang: vec!["zh".to_string()],
        mode: "fast".to_string(),
        salt: SALT,
        config,
    }
}

fn run(opts: Opts) -> RedactOut {
    let opts_js = serde_wasm_bindgen::to_value(&opts).expect("opts serialize");
    let out_js = redact(TEXT, opts_js).expect("redact should succeed");
    serde_wasm_bindgen::from_value(out_js).expect("result deserialize")
}

// ── default level → city (杭州市) ─────────────────────────────────────────────

#[wasm_bindgen_test]
fn generalize_to_city_byte_identical_to_python() {
    let out = run(generalize_opts(None));
    assert!(
        out.text.contains("杭州市"),
        "default generalize level must coarsen to the city 杭州市, got: {}",
        out.text
    );
    assert!(
        !out.text.contains("文一路100号"),
        "the street span 文一路100号 must be coarsened away, got: {}",
        out.text
    );
    // Lossy: no restore-key entry for the coarse value (matches the Python golden).
    assert!(
        !out.key.contains_key("杭州市"),
        "generalize is lossy — the coarse value must not appear as a key entry"
    );
}

// ── level:"province" → province (浙江省) ──────────────────────────────────────

#[wasm_bindgen_test]
fn generalize_to_province_byte_identical_to_python() {
    let out = run(generalize_opts(Some("province")));
    assert!(
        out.text.contains("浙江省"),
        "level:\"province\" must coarsen to 浙江省 (not the city 杭州市) — confirms \
         EntityConfigOpt.level threads through to_core_config + build_type_info, got: {}",
        out.text
    );
    assert!(
        !out.text.contains("文一路100号"),
        "the street span 文一路100号 must be coarsened away, got: {}",
        out.text
    );
    assert!(
        !out.key.contains_key("浙江省"),
        "generalize is lossy — the coarse value must not appear as a key entry"
    );
}
