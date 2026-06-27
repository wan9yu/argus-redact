//! Streaming parity for the wasm `StreamingRedactor` (feed/flush) over the core
//! carry-window engine. Runs in Node (`wasm-pack test --node crates/argus-redact-wasm`).
//!
//! Two layers of assertion:
//!
//!   1. SAFETY (straddle / leak cases): an entity split across a force-flush cut
//!      (email/IPv4 at an internal dot, a person name across the 4096−256 window,
//!      an open-ended `cut<=0` token) is NEVER emitted half-redacted, so the raw
//!      PII is ABSENT from the concatenated `feed()`+`flush()` downstream, and the
//!      streamed output restores to the original.
//!
//!   2. CROSS-RUNTIME PARITY (the SSOT proof): for a fixed input + salt + chunking
//!      the wasm streamed downstream + accumulated key are BYTE-IDENTICAL to what
//!      the Python one-shot redact path produces when driven through the SAME
//!      core carry-window. The expected values were captured by driving the Python
//!      `_consume_to_boundary` (the core carry-window SSOT) + the one-shot
//!      `redact(mode="fast")` per emitted segment, accumulating the key with
//!      first-seen-wins — exactly the loop the wasm `StreamingRedactor` runs. This
//!      pins that the snap-parity fix makes wasm == Python streaming for the
//!      `Mary Jane` straddle and the email/IPv4 cases.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use wasm_bindgen_test::*;

use argus_redact_wasm::{restore, StreamingRedactor};

/// Fixed salt shared with the Python oracle so the MT19937 pseudonym codes
/// (`P-NNNNN` / `IP-NNNNN`) are byte-identical across runtimes.
const SALT: i64 = 42;

// ── opts: a typed struct graph so serde-wasm-bindgen emits a PLAIN JS object ──
//
// (A `serde_json::Value` would serialize nested maps as JS `Map`s the wasm opts
// deserializer can't read — same constraint the golden-parity test documents.)

/// Per-type config entry. Only `strategy` is needed by these cases.
#[derive(Serialize, Default, Clone)]
struct EntityCfg {
    #[serde(skip_serializing_if = "Option::is_none")]
    strategy: Option<String>,
}

impl EntityCfg {
    fn strat(s: &str) -> Self {
        EntityCfg {
            strategy: Some(s.to_string()),
        }
    }
}

/// The `StreamingRedactor` constructor opts. Mirrors the one-shot `redact` opts
/// (lang / mode=fast / salt / config / names); fields are omitted when absent so
/// the emitted JS object is exactly what a JS caller passes.
#[derive(Serialize)]
struct Opts {
    lang: String,
    mode: String,
    salt: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<HashMap<String, EntityCfg>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    names: Option<Vec<String>>,
}

impl Opts {
    fn new(lang: &str) -> Self {
        Opts {
            lang: lang.to_string(),
            mode: "fast".to_string(),
            salt: SALT,
            config: None,
            names: None,
        }
    }
    fn with_config(mut self, entries: &[(&str, &str)]) -> Self {
        self.config = Some(
            entries
                .iter()
                .map(|(k, s)| (k.to_string(), EntityCfg::strat(s)))
                .collect(),
        );
        self
    }
    fn with_names(mut self, ns: &[&str]) -> Self {
        self.names = Some(ns.iter().map(|s| s.to_string()).collect());
        self
    }
}

/// The `{ downstreamText, key, aliases }` shape `feed` / `flush` return.
#[derive(Deserialize)]
struct EmitOut {
    #[serde(rename = "downstreamText")]
    downstream_text: String,
    key: HashMap<String, String>,
}

/// Build a `StreamingRedactor`, feed every chunk + flush, and return the
/// concatenated downstream text + the aggregate key (the last emit's `key`, which
/// is the redactor's accumulated snapshot after merging that segment).
fn stream(chunks: &[&str], opts: &Opts) -> (String, HashMap<String, String>) {
    let opts_js = serde_wasm_bindgen::to_value(opts).expect("opts serialize");
    let mut r = StreamingRedactor::new(opts_js).expect("construct StreamingRedactor");

    let mut out = String::new();
    for c in chunks {
        let emit_js = r.feed(c).expect("feed");
        let emit: EmitOut = serde_wasm_bindgen::from_value(emit_js).expect("feed result");
        out.push_str(&emit.downstream_text);
    }
    // `flush` returns the FINAL accumulated-key snapshot (monotonic across emits),
    // so it is the aggregate key for the whole stream regardless of whether the
    // flush itself emitted any downstream text.
    let flush_js = r.flush().expect("flush");
    let flush: EmitOut = serde_wasm_bindgen::from_value(flush_js).expect("flush result");
    out.push_str(&flush.downstream_text);
    (out, flush.key)
}

/// Split `text` into `size`-char chunks (CHAR-space, like the Python oracle).
fn chunk(text: &str, size: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    chars
        .chunks(size)
        .map(|c| c.iter().collect::<String>())
        .collect()
}

fn restore_key(text: &str, key: &HashMap<String, String>) -> String {
    let key_js = serde_wasm_bindgen::to_value(key).expect("key serialize");
    restore(text, key_js).expect("restore")
}

// ── SAFETY: straddle / leak cases ────────────────────────────────────────────

/// Email straddling an internal dot at the force-flush cut: the raw email must be
/// ABSENT from the concatenated downstream (never emitted as a half-token whose
/// head no longer matches the email pattern), and the streamed output restores to
/// the original.
#[wasm_bindgen_test]
fn email_straddle_no_leak_and_restores() {
    let input = format!("{} contact user@example.com here {}", "a".repeat(3830), "b".repeat(300));
    let chunks = chunk(&input, 50);
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
    let (ds, key) = stream(&refs, &Opts::new("en"));

    assert!(
        !ds.contains("user@example.com"),
        "raw email leaked into the streamed downstream"
    );
    assert_eq!(
        restore_key(&ds, &key),
        input,
        "streamed email roundtrip must recover the original"
    );
}

/// IPv4 straddling an internal dot at the force-flush cut: same guarantee — the
/// raw IPv4 must not appear, and restore recovers the original.
#[wasm_bindgen_test]
fn ipv4_straddle_no_leak_and_restores() {
    let input = format!("{} from 203.0.113.7 ok {}", "a".repeat(3830), "b".repeat(300));
    let chunks = chunk(&input, 50);
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
    let (ds, key) = stream(&refs, &Opts::new("en"));

    assert!(
        !ds.contains("203.0.113.7"),
        "raw IPv4 leaked into the streamed downstream"
    );
    assert_eq!(
        restore_key(&ds, &key),
        input,
        "streamed IPv4 roundtrip must recover the original"
    );
}

/// The snap-parity case: a person name straddling the 4096−256 force-flush cut,
/// fed in small chunks. The carry-window must detect on the FULL combined buffer
/// and snap the cut back so the whole name is carried together — so the raw name
/// never appears in the downstream. This is the case that must match Python now.
#[wasm_bindgen_test]
fn person_name_straddle_snap_no_leak() {
    let input = format!("{} Mary Jane Watson Parker {}", "q".repeat(3829), "z".repeat(300));
    let chunks = chunk(&input, 64);
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
    let opts = Opts::new("en")
        .with_names(&["Mary Jane Watson Parker"])
        .with_config(&[("person", "realistic")]);
    let (ds, _key) = stream(&refs, &opts);

    assert!(
        !ds.contains("Mary Jane Watson Parker"),
        "person name leaked across the force-flush cut (snap failed)"
    );
}

/// The `cut<=0` open-ended entity: an email head `a@b` followed by many `.co`
/// extensions never resolves a bounded cut. The stream must stay BOUNDED (the
/// buffer drains via the trailing-window force-flush) and never hang/panic.
#[wasm_bindgen_test]
fn open_ended_token_stays_bounded() {
    let mut input = String::from("a@b");
    for _ in 0..3000 {
        input.push_str(".co");
    }
    let chunks = chunk(&input, 64);
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
    // The assertion is simply that this returns (no panic / no unbounded hang).
    let (ds, _key) = stream(&refs, &Opts::new("en"));
    // The bounded-drain emits the head; the downstream is non-empty and finite.
    assert!(!ds.is_empty(), "open-ended token must still drain a bounded prefix");
}

/// A clean multi-chunk redact → restore roundtrip with sentence boundaries: the
/// raw PII is absent from the downstream and the streamed output restores exactly.
#[wasm_bindgen_test]
fn multi_chunk_redact_restore_roundtrip() {
    let input = "Call John Smith at the office. Email a@b.com today. From 8.8.8.8 always.";
    let chunks = chunk(input, 7);
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
    let opts = Opts::new("en").with_names(&["John Smith"]);
    let (ds, key) = stream(&refs, &opts);

    for raw in ["John Smith", "a@b.com", "8.8.8.8"] {
        assert!(!ds.contains(raw), "raw PII '{raw}' leaked into the downstream");
    }
    assert_eq!(
        restore_key(&ds, &key),
        input,
        "multi-chunk streamed roundtrip must recover the original"
    );
}

/// zh evidence-gated cross-cut: a bare region (西湖区) fires ONLY because a phone
/// sits within its proximity window. A sentence boundary lands between them, so a
/// naive cut emits the phone and carries the region alone — re-detected below
/// threshold, the bare region would leak. The widened snap (SSOT `snap_cut`) must
/// carry candidate + evidence together, so the region is redacted, not leaked.
/// Proves the Bug-2 fix holds across the wasm runtime (same leak the Rust/Python
/// regression tests pin).
#[wasm_bindgen_test]
fn zh_region_evidence_cross_cut_no_leak() {
    let input = "我的电话13800138000。西湖区";
    let chunks = chunk(input, 100); // single chunk → feed + flush
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
    let (ds, _key) = stream(&refs, &Opts::new("zh"));
    assert!(!ds.contains("西湖区"), "bare region leaked in wasm streaming: {ds}");
    assert!(!ds.contains("13800138000"), "phone leaked in wasm streaming: {ds}");
}

// ── CROSS-RUNTIME PARITY (the SSOT proof) ────────────────────────────────────
//
// Expected values captured from the Python one-shot redact path driven through
// the SAME core carry-window (`_consume_to_boundary` + per-segment
// `redact(mode="fast")` with first-seen-wins key merge). If the snap or the
// MT19937 stream drifts, these byte-comparisons fail.

/// Mary Jane straddle: the Python-streamed downstream is exactly
/// `"q"*3829 + " John Roe " + "z"*300` (the `realistic` person fake) with the key
/// `{"John Roe": "Mary Jane Watson Parker"}`. wasm must reproduce it byte-for-byte.
#[wasm_bindgen_test]
fn cross_runtime_parity_person_straddle() {
    let input = format!("{} Mary Jane Watson Parker {}", "q".repeat(3829), "z".repeat(300));
    let chunks = chunk(&input, 64);
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
    let opts = Opts::new("en")
        .with_names(&["Mary Jane Watson Parker"])
        .with_config(&[("person", "realistic")]);
    let (ds, key) = stream(&refs, &opts);

    let expected_ds = format!("{} John Roe {}", "q".repeat(3829), "z".repeat(300));
    assert_eq!(ds, expected_ds, "wasm streamed downstream must match Python byte-for-byte");

    let mut expected_key = HashMap::new();
    expected_key.insert("John Roe".to_string(), "Mary Jane Watson Parker".to_string());
    assert_eq!(key, expected_key, "wasm aggregate key must match Python");
}

/// Email/IPv4 straddle: the Python-streamed key masks the email to
/// `u***@example.com` and pseudonymizes the IPv4 to `IP-94349` (the CPython-exact
/// MT19937 code at salt=42). wasm must reproduce both the key and the absence.
#[wasm_bindgen_test]
fn cross_runtime_parity_email_ipv4_keys() {
    // Email straddle.
    let email_in = format!("{} contact user@example.com here {}", "a".repeat(3830), "b".repeat(300));
    let echunks = chunk(&email_in, 50);
    let erefs: Vec<&str> = echunks.iter().map(String::as_str).collect();
    let (_eds, ekey) = stream(&erefs, &Opts::new("en"));
    assert_eq!(
        ekey.get("u***@example.com").map(String::as_str),
        Some("user@example.com"),
        "wasm email mask key must match Python"
    );

    // IPv4 straddle.
    let ip_in = format!("{} from 203.0.113.7 ok {}", "a".repeat(3830), "b".repeat(300));
    let ipchunks = chunk(&ip_in, 50);
    let iprefs: Vec<&str> = ipchunks.iter().map(String::as_str).collect();
    let (_ipds, ipkey) = stream(&iprefs, &Opts::new("en"));
    assert_eq!(
        ipkey.get("IP-94349").map(String::as_str),
        Some("203.0.113.7"),
        "wasm IPv4 pseudonym code must match Python's MT19937 code"
    );
}

/// Normal multi-chunk stream: the full downstream + key are byte-identical to the
/// Python one-shot-driven stream (proves the common boundary path, not just the
/// straddle edges, matches across runtimes).
#[wasm_bindgen_test]
fn cross_runtime_parity_normal_stream() {
    let input = "Call John Smith at the office. Email a@b.com today. From 8.8.8.8 always.";
    let chunks = chunk(input, 7);
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
    let opts = Opts::new("en").with_names(&["John Smith"]);
    let (ds, key) = stream(&refs, &opts);

    assert_eq!(
        ds, "Call P-83811 at the office. Email a***@b.com today. From IP-94349 always.",
        "wasm streamed downstream must match Python byte-for-byte"
    );
    let mut expected_key = HashMap::new();
    expected_key.insert("P-83811".to_string(), "John Smith".to_string());
    expected_key.insert("a***@b.com".to_string(), "a@b.com".to_string());
    expected_key.insert("IP-94349".to_string(), "8.8.8.8".to_string());
    assert_eq!(key, expected_key, "wasm aggregate key must match Python");
}

/// `salt` is required by the constructor (wasm has no host entropy for the
/// unseeded path) — an opts object without `salt` must error clearly.
#[wasm_bindgen_test]
fn missing_salt_errors() {
    #[derive(Serialize)]
    struct NoSalt {
        lang: String,
        mode: String,
    }
    let opts = serde_wasm_bindgen::to_value(&NoSalt {
        lang: "en".to_string(),
        mode: "fast".to_string(),
    })
    .unwrap();
    assert!(
        StreamingRedactor::new(opts).is_err(),
        "constructing without salt must error"
    );
}

/// `mode` other than `"fast"` must be rejected at construction (no NER/semantic
/// adapters in wasm).
#[wasm_bindgen_test]
fn non_fast_mode_rejected() {
    let opts = serde_wasm_bindgen::to_value(&Opts {
        mode: "ner".to_string(),
        ..Opts::new("en")
    })
    .unwrap();
    assert!(
        StreamingRedactor::new(opts).is_err(),
        "mode='ner' must be rejected in wasm streaming"
    );
}
