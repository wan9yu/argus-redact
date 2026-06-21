//! Golden byte-parity: wasm `redact` / `restore` vs the NATIVE fast-mode suite.
//!
//! Runs in Node (`wasm-pack test --node crates/argus-redact-wasm`). The oracle is
//! the SAME frozen fixture the Python engine-parity test (`tests/core/
//! test_redact_engine_parity.py`) asserts against: `tests/core/fixtures/
//! redact_engine_v072.json`, embedded here at compile time via `include_str!`
//! (wasm can't read files at runtime).
//!
//! The fixture stores only the expected `{ redacted, key }` per case label; the
//! per-case INPUTS (text + redact options: lang, mode=fast, config, names,
//! unified_prefix, salt) live in the Python test's `CASES` list. We mirror that
//! list 1:1 here as [`Case`] values so the two suites stay in lockstep — if either
//! the inputs or the frozen outputs drift, both this test and the Python test fail.
//!
//! For EACH fast-mode case we assert, byte-for-byte:
//!   1. wasm `redact(text, opts).text` == the golden `redacted`,
//!   2. wasm `redact(...).key`        == the golden `key`,
//!   3. wasm `restore(redacted, key)` == the ORIGINAL input.
//!
//! Coverage: all 13 fixture cases are fast-mode and exercise every fast-mode
//! strategy (pseudonym / mask / name_mask / landline_mask / realistic / category /
//! keep / remove) across `zh` + `en`. NONE use NER, semantic, or custom-adapter
//! paths, so none are skipped — wasm is fast-only and these are exactly its domain.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use wasm_bindgen_test::*;

use argus_redact_wasm::{redact, restore};

/// The frozen golden snapshot, embedded at compile time. Same file the Python
/// `test_redact_engine_parity` freezes against. Keyed by case label →
/// `{ redacted, key }`.
const GOLDEN_JSON: &str = include_str!("../../../tests/core/fixtures/redact_engine_v072.json");

/// Fixed salt the Python suite uses → deterministic pseudonym + faker derivation.
/// Must match `SALT = 42` in `test_redact_engine_parity.py`.
const SALT: i64 = 42;

/// One golden expectation entry: `{ redacted, key }` as stored in the fixture.
#[derive(Deserialize)]
struct Expected {
    redacted: String,
    key: HashMap<String, String>,
}

/// The `{ text, key, aliases }` shape `redact` returns; we read back `text` + `key`.
#[derive(Deserialize)]
struct RedactOut {
    text: String,
    key: HashMap<String, String>,
}

// ── opts: typed structs mirroring the Python redact() kwargs ─────────────────
//
// IMPORTANT (serde-wasm-bindgen): opts must be a typed struct graph so it
// serializes to a PLAIN JS object. A `serde_json::Value` would serialize nested
// maps as JS `Map`s, which the wasm `RedactOpts` struct deserializer can't read.
// So we model `config` as `HashMap<String, EntityCfg>` of a typed `EntityCfg`,
// exactly like the smoke test does.

/// Per-type config entry. Only `strategy` is needed by any golden case; absent =
/// built-in default. `skip_serializing_if` keeps the emitted JS object minimal,
/// matching what the Python `config` dict carries.
#[derive(Serialize, Default)]
struct EntityCfg {
    #[serde(skip_serializing_if = "Option::is_none")]
    strategy: Option<String>,
}

impl EntityCfg {
    fn strat(s: &str) -> Self {
        EntityCfg { strategy: Some(s.to_string()) }
    }
}

/// The redact opts object. Fields are omitted when absent so the emitted JS object
/// is exactly what a JS caller (or the Python kwargs) would pass — and so the wasm
/// `deny_unknown_fields` deserializer never sees a stray `null`-shaped field it
/// would reject. `mode` is always `"fast"` (wasm's only mode).
#[derive(Serialize)]
struct Opts {
    lang: String,
    mode: String,
    salt: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<HashMap<String, EntityCfg>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unified_prefix: Option<String>,
}

/// One parity case: a label keying into the fixture + the inputs to feed wasm.
struct Case {
    label: &'static str,
    text: &'static str,
    opts: Opts,
}

fn opts(lang: &str) -> Opts {
    Opts {
        lang: lang.to_string(),
        mode: "fast".to_string(),
        salt: SALT,
        config: None,
        names: None,
        unified_prefix: None,
    }
}

fn cfg(entries: &[(&str, &str)]) -> Option<HashMap<String, EntityCfg>> {
    Some(
        entries
            .iter()
            .map(|(k, s)| (k.to_string(), EntityCfg::strat(s)))
            .collect(),
    )
}

fn names(ns: &[&str]) -> Option<Vec<String>> {
    Some(ns.iter().map(|s| s.to_string()).collect())
}

/// The 1:1 mirror of `CASES` (+ the `unified_prefix` case) in
/// `tests/core/test_redact_engine_parity.py`. All fast-mode.
fn cases() -> Vec<Case> {
    vec![
        Case {
            label: "zh_default",
            text: "张三的电话13812345678，身份证110101199003074610",
            opts: opts("zh"),
        },
        Case {
            label: "zh_realistic",
            text: "张三的电话13812345678，身份证110101199003074610",
            opts: Opts {
                config: cfg(&[
                    ("person", "realistic"),
                    ("phone", "realistic"),
                    ("id_number", "realistic"),
                ]),
                ..opts("zh")
            },
        },
        Case {
            label: "zh_mask",
            text: "电话13812345678 银行卡6217000000000000",
            opts: Opts {
                config: cfg(&[("phone", "mask"), ("bank_card", "mask")]),
                ..opts("zh")
            },
        },
        Case {
            label: "zh_landline_mask",
            text: "座机 010-12345678",
            opts: Opts {
                config: cfg(&[
                    ("phone_landline", "landline_mask"),
                    ("phone", "landline_mask"),
                ]),
                ..opts("zh")
            },
        },
        // names= required: standalone Chinese names not detected in fast mode.
        Case {
            label: "zh_name_mask",
            text: "张三和欧阳明",
            opts: Opts {
                config: cfg(&[("person", "name_mask")]),
                names: names(&["张三", "欧阳明"]),
                ..opts("zh")
            },
        },
        Case {
            label: "zh_category",
            text: "北京市朝阳区三里屯",
            opts: Opts {
                config: cfg(&[("address", "category")]),
                ..opts("zh")
            },
        },
        Case {
            label: "zh_keep",
            text: "我妈说她13812345678",
            opts: opts("zh"),
        },
        Case {
            label: "zh_collision",
            text: "张三 张三 李四 张三",
            opts: Opts {
                config: cfg(&[("person", "name_mask")]),
                names: names(&["张三", "李四"]),
                ..opts("zh")
            },
        },
        Case {
            label: "en_realistic",
            text: "John Smith SSN 123-45-6789 card 4111111111111111",
            opts: Opts {
                config: cfg(&[
                    ("person", "realistic"),
                    ("ssn", "realistic"),
                    ("credit_card", "realistic"),
                ]),
                ..opts("en")
            },
        },
        Case {
            label: "en_address",
            text: "lives at 1600 Pennsylvania Ave",
            opts: Opts {
                config: cfg(&[("address", "realistic")]),
                ..opts("en")
            },
        },
        Case {
            label: "shared_email_ip",
            text: "mail a@b.com from 8.8.8.8",
            opts: opts("en"),
        },
        Case {
            label: "unified",
            text: "张三 13812345678 110101199003074610",
            opts: opts("zh"),
        },
        // unified_prefix via the kwarg.
        Case {
            label: "unified_prefix",
            text: "张三 13812345678 110101199003074610",
            opts: Opts {
                unified_prefix: Some("R".to_string()),
                ..opts("zh")
            },
        },
    ]
}

/// Drive every fast-mode golden case through wasm and assert byte-parity on the
/// redacted text, the key map, and the restore roundtrip.
#[wasm_bindgen_test]
fn golden_fast_mode_byte_parity() {
    let golden: HashMap<String, Expected> =
        serde_json::from_str(GOLDEN_JSON).expect("fixture must parse");

    let cases = cases();

    // Guard: every fixture entry must be covered by exactly one case (and vice
    // versa) — so a new fixture case can't silently slip past wasm parity.
    assert_eq!(
        cases.len(),
        golden.len(),
        "case count ({}) must match fixture entry count ({}) — a fixture case is uncovered",
        cases.len(),
        golden.len()
    );

    for case in cases {
        let exp = golden
            .get(case.label)
            .unwrap_or_else(|| panic!("fixture missing case '{}'", case.label));

        let opts_js = serde_wasm_bindgen::to_value(&case.opts)
            .unwrap_or_else(|e| panic!("[{}] opts serialize failed: {e}", case.label));

        let out_js = redact(case.text, opts_js)
            .unwrap_or_else(|e| panic!("[{}] redact errored: {e:?}", case.label));
        let out: RedactOut = serde_wasm_bindgen::from_value(out_js)
            .unwrap_or_else(|e| panic!("[{}] result deserialize failed: {e}", case.label));

        // 1. redacted text byte-for-byte.
        assert_eq!(
            out.text, exp.redacted,
            "[{}] redacted text diverged from golden",
            case.label
        );

        // 2. key map byte-for-byte (HashMap eq is order-independent, exactly the
        //    `dict(sorted(...))` comparison the Python test does).
        assert_eq!(
            out.key, exp.key,
            "[{}] key map diverged from golden",
            case.label
        );

        // 3. restore(redacted, key) recovers the ORIGINAL input exactly.
        let key_js = serde_wasm_bindgen::to_value(&out.key)
            .unwrap_or_else(|e| panic!("[{}] key serialize failed: {e}", case.label));
        let restored = restore(&out.text, key_js)
            .unwrap_or_else(|e| panic!("[{}] restore errored: {e:?}", case.label));
        assert_eq!(
            restored, case.text,
            "[{}] restore roundtrip did not recover the original",
            case.label
        );
    }
}
