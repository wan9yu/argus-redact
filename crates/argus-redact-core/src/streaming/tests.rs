//! Parity tests for the streaming carry-window state machine — the v0.7.10
//! boundary-split oracle, ported from the Python streaming tests
//! (`tests/safety/test_streaming_straddle.py`, `tests/core/test_detect_partial.py`,
//! `tests/core/test_streaming.py`).
//!
//! The state machine here is generic over a `detect` / `redact` closure; the tests
//! wire those to the SAME core fast-mode path the wasm one-shot uses
//! (`detect_l1` → `build_type_info` → `redact_l1`), so the carry-window behavior is
//! exercised end-to-end against real detection — exactly as the Python tests run
//! through the public `StreamingRedactor` surface. The leaks A2 caught are real;
//! these reproduce them.

use std::collections::{HashMap, HashSet};

use super::*;
use crate::mt19937::MtRandomSource;
use crate::redact_l1::{detect_l1, redact_l1, RedactL1Args};
use crate::seed::Salt;
use crate::typeinfo::build_type_info;
use crate::{kinship_exact, PseudoFactory, TypeInfo, SELF_REF_PRONOUNS};

const SALT: i64 = 42;

/// A `PseudoFactory` minting a fresh CPython-exact MT19937 per seed — the same
/// SSOT source the wasm one-shot uses (so `P-NNNNN` codes are deterministic).
struct TestPseudoFactory;
impl PseudoFactory for TestPseudoFactory {
    type Source = MtRandomSource;
    fn make(&self, seed: Option<u64>) -> MtRandomSource {
        MtRandomSource::for_seed(seed.unwrap_or(0))
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// The keep-strategy whitelist (`SELF_REF_PRONOUNS | zh pronouns | kinship`),
/// mirroring the wasm one-shot.
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

/// A detect closure returning the RAW `(layer1 ++ person, hints)` over `text` —
/// the carry-window's entity-snap input (same detection params as the redact
/// closure). The snap normalizes these internally (merge + self-reference filter,
/// mirroring `_detect` fast), so callers may thread the RAW overlapping set and
/// still get the merged-cut behavior.
fn make_detect(lang: Vec<String>) -> impl Fn(&str) -> DetectSpans {
    move |text: &str| {
        let r = detect_l1(text, &lang, &[]).expect("detect_l1");
        // Mirror production (wasm `redact_segment` / streaming closure + Python
        // `_detect`): the snap must see the evidence-gated L1 detectors too, or a
        // region/occupation/condition/hobby candidate could be cut from its
        // corroborating evidence and leak.
        let mut entities = r.layer1.clone();
        entities.extend(r.person.clone());
        entities.extend(r.regions.clone());
        entities.extend(r.job_titles.clone());
        entities.extend(r.framework.clone());
        DetectSpans { entities, hints: r.hints }
    }
}

/// A redact closure for the detection-context-window engine: redact the GIVEN
/// FINAL entities over `text` — NO detect, NO merge, NO filter (the engine already
/// detected once over the full ±W buffer, merged + self-ref-filtered, and shifted
/// the spans into range). This is the `replace` + en-grammar tail of `redact_l1`,
/// fed the pre-detected entities (the Rust mirror of Python's
/// `redact_pseudonym_llm(_pre_detected=...)`). The `realistic` strategy is wired
/// via the pseudonym-llm-ish config so the straddle tests assert raw PII is absent.
fn make_redact(lang: Vec<String>) -> impl Fn(&str, &DetectSpans) -> Result<RedactSegment, String> {
    let wl = keep_whitelist();
    move |text: &str, spans: &DetectSpans| {
        // Realistic-strategy config for the PII types under test (phone / email /
        // ip_address / organization / person), so downstream gets reserved-range
        // fakes — the same shapes the Python downstream_text carries.
        let config = realistic_config();
        let info_pairs = build_type_info(&spans.entities, Some(&config), &lang, None);
        let info_map: HashMap<String, TypeInfo> = info_pairs.into_iter().collect();
        let result = crate::replace::replace(
            crate::replace::ReplaceArgs {
                text,
                entities: &spans.entities,
                salt: Some(&Salt::Int(SALT)),
                key: None,
                type_info: &info_map,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
            },
            &TestPseudoFactory,
            None,
        )?;
        let effective_lang: &str = lang.first().map(String::as_str).unwrap_or("zh");
        let downstream = if effective_lang == "en" {
            let originals: Vec<String> = result.key.values().cloned().collect();
            crate::grammar::normalize_grammar_en(&result.redacted, &originals)
        } else {
            result.redacted
        };
        Ok(RedactSegment {
            downstream_text: downstream,
            key: result.key,
            aliases: result.aliases,
        })
    }
}

/// The batch reference for the fuzz oracle: detect + redact the WHOLE `text` in one
/// pass via production `redact_l1` (the same realistic config + factory the stream
/// path uses). `stream(chunk_chars(text, n))` must equal this for every chunking.
fn one_shot_redact(text: &str, lang: &[&str]) -> String {
    let lang_v = s(lang);
    let detected = detect_l1(text, &lang_v, &[]).expect("detect_l1");
    let mut entities = detected.layer1;
    entities.extend(detected.person);
    entities.extend(detected.regions);
    entities.extend(detected.job_titles);
    entities.extend(detected.framework);
    let config = realistic_config();
    let info_map: HashMap<String, TypeInfo> =
        build_type_info(&entities, Some(&config), &lang_v, None)
            .into_iter()
            .collect();
    let result = redact_l1(
        RedactL1Args {
            text,
            lang: &lang_v,
            names: &[],
            type_info: &info_map,
            salt: Some(&Salt::Int(SALT)),
            key: None,
            person_prefix: "P",
            org_prefix: "O",
            unified_prefix: None,
            keep_whitelist: &keep_whitelist(),
            types: None,
            types_exclude: None,
        },
        &TestPseudoFactory,
        None,
    )
    .expect("redact_l1");
    result.redacted
}

/// Split `text` into CHAR chunks of at most `size` (the fuzz oracle's chunkings).
fn chunk_chars(text: &str, size: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    chars.chunks(size).map(|c| c.iter().collect()).collect()
}

/// A pseudonym-llm-ish realistic config for the PII types the straddle tests use.
fn realistic_config() -> crate::typeinfo::Config {
    use crate::typeinfo::EntityConfig;
    let mut c: crate::typeinfo::Config = HashMap::new();
    for t in [
        "phone",
        "email",
        "ip_address",
        "ipv4",
        "organization",
        "person",
        "id_number",
    ] {
        c.insert(
            t.to_string(),
            EntityConfig {
                strategy: Some("realistic".to_string()),
                prefix: None,
                replacement: None,
                label: None,
                visible_prefix: None,
                visible_suffix: None,
            },
        );
    }
    c
}

/// Feed chunks through a fresh redactor and return concatenated downstream text +
/// the redactor (for aggregate_key). Mirrors the Python `_stream` helper.
fn stream(chunks: &[&str], lang: &[&str]) -> (String, HashMap<String, String>) {
    let lang_v = s(lang);
    let mut r = StreamingRedactor::new(make_detect(lang_v.clone()), make_redact(lang_v));
    let mut out = String::new();
    for c in chunks {
        out.push_str(&r.feed(c).expect("feed").segment.downstream_text);
    }
    out.push_str(&r.flush().expect("flush").segment.downstream_text);
    (out, r.aggregate_key())
}

// ── last_boundary_index parity (test_detect_partial.py::TestLastBoundaryIndex) ──

#[test]
fn last_boundary_no_boundary_returns_minus_one() {
    assert_eq!(last_boundary_index("hello world"), -1);
}

#[test]
fn last_boundary_returns_index_after_boundary() {
    assert_eq!(last_boundary_index("hi. "), 3); // '.' followed by space → real end
    assert_eq!(last_boundary_index("hi.\n"), 4); // '\n' always counts
    assert_eq!(last_boundary_index("你好。"), 3); // CJK 。 always counts
}

#[test]
fn last_boundary_ascii_at_buffer_end_is_ambiguous() {
    assert_eq!(last_boundary_index("hi."), -1);
    assert_eq!(last_boundary_index("a@bcd."), -1); // intra-entity dot, not a boundary
    assert_eq!(last_boundary_index("a@bcd.com listening"), -1); // '.' before 'c'
}

#[test]
fn last_boundary_cjk_and_newline_always_count() {
    assert_eq!(last_boundary_index("你好。世界"), 3);
    assert_eq!(last_boundary_index("done\n"), 5);
    assert_eq!(last_boundary_index("结束！"), 3);
}

#[test]
fn last_boundary_normal_en_sentence_splits_at_dot_space() {
    assert_eq!(last_boundary_index("Hello. World"), 6); // after ". "
}

#[test]
fn last_boundary_picks_rightmost() {
    assert_eq!(last_boundary_index("a. b. c"), 5); // after second '. '
}

#[test]
fn last_boundary_empty_string() {
    assert_eq!(last_boundary_index(""), -1);
}


// ── snap_cut / context_cut unit rules ──────────────────────────────────────────

#[test]
fn snap_cut_is_straddle_only() {
    // A closed entity straddling the cut snaps to its start; a NON-straddling span
    // no longer widens (the evidence-gated widening is gone — the context window
    // handles cross-cut evidence).
    let spans = vec![
        (10usize, 20usize, "phone".to_string()),
        (61usize, 64usize, "location".to_string()),
    ];
    assert_eq!(snap_cut(&spans, 15), 10); // phone straddles 15 → 10
    assert_eq!(snap_cut(&spans, 30), 30); // location far from 30, NOT widened → 30
}

#[test]
fn context_cut_holds_back_w_and_respects_ctx() {
    // No entity; W=4; buffer "abcd。efghij" (len 11), boundary after 。 at idx 5.
    // safe_end = 11-4 = 7; last boundary ≤ 7 is 5 → cut 5 (≥ ctx_len 0).
    let chars: Vec<char> = "abcd。efghij".chars().collect();
    let cut = context_cut(&[], &chars, 0, DEFAULT_MAX_BUFFER, 4, false);
    assert_eq!(cut.cut, 5);
    // Tail shorter than W → nothing emittable (cut == ctx_len).
    let short: Vec<char> = "abc".chars().collect();
    let cut2 = context_cut(&[], &short, 0, DEFAULT_MAX_BUFFER, 4, false);
    assert_eq!(cut2.cut, 0);
    // force_flush drains everything past ctx_len.
    let cut3 = context_cut(&[], &chars, 2, DEFAULT_MAX_BUFFER, 4, true);
    assert_eq!(cut3.cut, 11);
}

#[test]
fn context_cut_no_boundary_under_max_buffer_holds() {
    // Boundary-less buffer below max_buffer: hold everything (cut == ctx_len), never
    // emit a half-token.
    let chars: Vec<char> = "abcdefghij".chars().collect();
    let cut = context_cut(&[], &chars, 0, DEFAULT_MAX_BUFFER, 4, false);
    assert_eq!(cut.cut, 0);
}

#[test]
fn context_cut_bounded_drain_at_max_buffer() {
    // Boundary-less buffer AT max_buffer with no straddling span → bounded drain to
    // len - CARRY_WINDOW (so the buffer can never grow without bound).
    let chars: Vec<char> = "x".repeat(DEFAULT_MAX_BUFFER).chars().collect();
    let cut = context_cut(&[], &chars, 0, DEFAULT_MAX_BUFFER, EVIDENCE_CONTEXT_WINDOW, false);
    assert_eq!(cut.cut, DEFAULT_MAX_BUFFER - CARRY_WINDOW);
}

// ── emit_possible gate parity (the detect-on-emit perf gate) ───────────────────

#[test]
fn emit_possible_is_a_superset_of_context_cut_emit() {
    // CORRECTNESS INVARIANT for the perf gate: `emit_possible` must be TRUE whenever
    // `context_cut` would EMIT (cut > ctx_len). `feed` skips the expensive
    // detect + `context_cut` when `emit_possible` is false, so an over-aggressive
    // gate (false on a real emit) is an under-redaction LEAK. Sweep a spread of
    // buffer shapes × ctx_len × max_buffer and, for the EXACT spans + params `feed`
    // passes to `context_cut`, assert the superset relation holds.
    let w = EVIDENCE_CONTEXT_WINDOW;
    let filler200 = "y".repeat(200);
    let pem_short = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n".to_string();
    let pem_long = format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{}", "b3BlbnNz\n".repeat(40));
    // (label, buffer, ctx_len, max_buffer)
    let cases: Vec<(&str, String, usize, usize)> = vec![
        ("no boundary, below max → hold", "q".repeat(60), 0, DEFAULT_MAX_BUFFER),
        ("boundary inside [ctx_len, len-w] → emit", format!("first part. {filler200}"), 0, DEFAULT_MAX_BUFFER),
        ("boundary only in the last w → hold", format!("{} end. ", "z".repeat(200)), 0, DEFAULT_MAX_BUFFER),
        ("len just below max, boundaryless → hold", "q".repeat(63), 0, 64),
        ("len == max > carry, boundaryless → drain emit", "q".repeat(300), 0, 300),
        ("len == max < carry, boundaryless → drain holds (gate conservative-true)", "q".repeat(64), 0, 64),
        ("len > max, boundaryless → drain emit", "q".repeat(400), 0, 300),
        ("PEM in-flight, short (< w) → hold", pem_short, 0, DEFAULT_MAX_BUFFER),
        ("PEM in-flight, long (> w, has \\n boundaries) → snap-to-BEGIN holds (gate conservative-true)", pem_long, 0, DEFAULT_MAX_BUFFER),
        ("boundary at/under ctx_len → hold", format!("abcdefgh. {filler200}"), 50, DEFAULT_MAX_BUFFER),
        ("boundary past ctx_len > 0 → emit", format!("{}. {}", "y".repeat(60), "z".repeat(200)), 30, DEFAULT_MAX_BUFFER),
    ];

    let mut emit_seen = 0usize;
    for (label, buffer, ctx_len, max_buffer) in cases {
        let lang_v = s(&["en"]);
        let mut r = StreamingRedactor::with_max_buffer(
            make_detect(lang_v.clone()),
            make_redact(lang_v),
            max_buffer,
        );
        // `snap_spans` + `pem_max_buffer` read `self.buffer`, so mirror `feed`'s state.
        r.buffer = buffer.clone();
        let chars: Vec<char> = buffer.chars().collect();
        // Reproduce `feed` EXACTLY: same final spans, same PEM-aware max_buffer, same W.
        let final_entities = r.detect_final(&buffer);
        let spans = r.snap_spans(&final_entities, chars.len());
        let max = r.pem_max_buffer();
        let cc = context_cut(&spans, &chars, ctx_len, max, w, false);
        let ep = emit_possible(&chars, ctx_len, max, w, false);
        if cc.cut > ctx_len {
            emit_seen += 1;
            assert!(
                ep,
                "LEAK: context_cut emits (cut={} > ctx_len={}) but emit_possible=false — case [{}]",
                cc.cut, ctx_len, label
            );
        }
    }
    // Guard against a vacuous pass: the spread must actually exercise real emits
    // (boundary cut + bounded drain + ctx_len>0), not only hold cases.
    assert!(emit_seen >= 3, "spread must exercise real emits; saw only {emit_seen}");
}

#[test]
fn feed_holds_without_emit_unchanged() {
    // The gate is behavior-preserving on a HOLD: a boundary-less, sub-max_buffer feed
    // has no possible emit, so `feed` takes the cheap gate path and returns an empty
    // result, leaving `buffer`/`ctx_len` exactly as the pre-gate detect+context_cut
    // hold path did.
    let lang_v = s(&["en"]);
    let mut r = StreamingRedactor::new(make_detect(lang_v.clone()), make_redact(lang_v));
    let filler = "no boundary here just filler text";
    let res = r.feed(filler).expect("feed");
    assert_eq!(res.segment.downstream_text, "", "boundary-less sub-max feed must hold");
    assert!(res.segment.key.is_empty(), "a held feed mints no key");
    assert_eq!(r.buffer(), filler, "held buffer is exactly the input");
    assert_eq!(r.ctx_len, 0, "ctx_len unchanged on a hold");

    // A follow-up feed adds a real boundary AND enough tail to push it past the W
    // forward hold-back, so the engine now emits the committed prefix correctly.
    let tail = format!(". {}", "x".repeat(200));
    let res2 = r.feed(&tail).expect("feed");
    assert!(
        !res2.segment.downstream_text.is_empty(),
        "a boundary past the hold-back must emit"
    );
    assert!(
        res2.segment.downstream_text.starts_with("no boundary here"),
        "emits the committed prefix: {:?}",
        res2.segment.downstream_text
    );
}

// ── A2 straddle / leak oracle (test_streaming_straddle.py) ─────────────────────

#[test]
fn phone_straddling_max_buffer_redacts() {
    // 4091 boundary-less filler + "电话138" → chunk1 hits exactly 4096 chars with
    // no sentence boundary, forcing a flush. The phone 13800138000 straddles it.
    let pad = "啊".repeat(DEFAULT_MAX_BUFFER - 5);
    let c1 = format!("{pad}电话138");
    let (out, _) = stream(&[&c1, "00138000，结束。"], &["zh"]);
    assert!(
        !out.contains("13800138000"),
        "raw phone leaked across the force-flush cut"
    );
}

#[test]
fn email_straddling_max_buffer_redacts() {
    // English filler keeps the buffer boundary-less; chunk1 hits exactly 4096
    // chars so the force-flush fires with a@bcd.com straddling the cut.
    let head = "a@bc";
    let pad = "x".repeat(DEFAULT_MAX_BUFFER - head.chars().count());
    let c1 = format!("{pad}{head}");
    assert_eq!(c1.chars().count(), DEFAULT_MAX_BUFFER); // chunk1 forces a flush
    let (out, _) = stream(&[&c1, "d.com stop."], &["en"]);
    assert!(
        !out.contains("a@bcd.com"),
        "raw email leaked across the force-flush cut"
    );
}

#[test]
fn cjk_org_straddling_max_buffer_redacts() {
    // A CJK org name straddles the force-flush cut. chunk1 hits exactly 4096 chars;
    // the distinctive head of the company name (just before the cut) must not leak.
    let org = "北京字节跳动科技有限公司";
    let prefix = "公司是";
    let org_chars: Vec<char> = org.chars().collect();
    let head: String = org_chars[..4].iter().collect(); // "北京字节" straddles the cut
    let tail: String = org_chars[4..].iter().collect();
    let pad = "啊".repeat(DEFAULT_MAX_BUFFER - prefix.chars().count() - head.chars().count());
    let c1 = format!("{pad}{prefix}{head}");
    assert_eq!(c1.chars().count(), DEFAULT_MAX_BUFFER); // chunk1 forces a flush
    let c2 = format!("{tail}。结束。");
    let (out, _) = stream(&[&c1, &c2], &["zh"]);
    assert!(
        !out.contains(&head),
        "raw org head leaked across the force-flush cut"
    );
}

#[test]
fn ipv4_split_at_internal_dot_after_force_flush_no_leak() {
    // An IPv4 (8.8.8.8) straddles the force-flush cut, split at an internal dot.
    // That dot is an ASCII boundary char; the carry-window refinement (ASCII
    // boundary counts only when followed by whitespace) keeps the entity whole.
    let pii = "8.8.8.8";
    let full = format!("server ip {pii} listening");
    let p = full.find(pii).unwrap();
    let p_chars = full[..p].chars().count();
    let full_chars: Vec<char> = full.chars().collect();
    let head: String = full_chars[..p_chars + 2].iter().collect(); // "...8."
    let tail: String = full_chars[p_chars + 2..].iter().collect();
    let pad = "x".repeat(DEFAULT_MAX_BUFFER - head.chars().count());
    let c1 = format!("{pad}{head}");
    assert_eq!(c1.chars().count(), DEFAULT_MAX_BUFFER);
    let c2 = format!("{tail}.");
    let (out, _) = stream(&[&c1, &c2], &["en"]);
    assert!(!out.contains(pii), "raw IPv4 leaked across the internal-dot cut");
}

#[test]
fn email_split_after_dot_after_force_flush_no_leak() {
    // An email a@bcd.com split right after its dot ("a@bcd." | "com"). The dot is
    // an ASCII boundary char inside the entity; the carry-window must not split it.
    let pii = "a@bcd.com";
    let full = format!("mail {pii} stop");
    let p = full.find(pii).unwrap();
    let p_chars = full[..p].chars().count();
    let full_chars: Vec<char> = full.chars().collect();
    let head: String = full_chars[..p_chars + 6].iter().collect(); // "...a@bcd."
    let tail: String = full_chars[p_chars + 6..].iter().collect();
    let pad = "x".repeat(DEFAULT_MAX_BUFFER - head.chars().count());
    let c1 = format!("{pad}{head}");
    assert_eq!(c1.chars().count(), DEFAULT_MAX_BUFFER);
    let c2 = format!("{tail}.");
    let (out, _) = stream(&[&c1, &c2], &["en"]);
    assert!(!out.contains(pii), "raw email leaked across the internal-dot cut");
}

#[test]
fn email_split_at_dot_no_force_flush_no_leak() {
    // No force-flush at all — small chunks split exactly at the email's dot. The
    // trailing dot of chunk1 is at the BUFFER END → ambiguous, must NOT count.
    let (out, _) = stream(&["contact me at a@bcd.", "com please."], &["en"]);
    assert!(!out.contains("a@bcd.com"), "raw email leaked across the dot split");
}

#[test]
fn dotted_username_email_split_after_dot_no_partial_leak() {
    // jane.doe@company.com split after the username dot ("jane." | rest). The dot
    // in the username is intra-entity; "jane." must not be emitted raw as a head.
    let (out, _) = stream(&["please email jane.", "doe@company.com today."], &["en"]);
    assert!(!out.contains("jane.doe@company.com"), "full email leaked");
    assert!(!out.contains("jane."), "dotted-username head leaked across the dot");
}

#[test]
fn cjk_full_width_boundary_still_splits() {
    // CJK full-width 。 always counts as a boundary. A stream split at 。 must still
    // flush + redact normally and round-trip via aggregate_key.
    let chunks = ["手机13912345678。", "另一个号13987654321。"];
    let (out, agg) = stream(&chunks, &["zh"]);
    assert!(!out.contains("13912345678"));
    assert!(!out.contains("13987654321"));
    let joined: String = chunks.concat();
    let restored = restore_full(&out, &agg, None, None).unwrap();
    assert_eq!(restored, joined);
}

#[test]
fn straddling_entity_round_trips_via_aggregate_key() {
    // An entity straddling the carry boundary must still restore cleanly.
    let pad = "啊".repeat(DEFAULT_MAX_BUFFER - 5);
    let c1 = format!("{pad}电话138");
    let chunks = [c1.as_str(), "00138000，结束。"];
    let (out, agg) = stream(&chunks, &["zh"]);
    let joined: String = chunks.concat();
    let restored = restore_full(&out, &agg, None, None).unwrap();
    assert_eq!(restored, joined);
}

#[test]
fn entity_before_carry_window_emitted_exactly_once() {
    // An entity wholly before the len-W cut is emitted once — not duplicated by the
    // carried residual being re-detected next round.
    let phone = "13800138000";
    let c1 = format!("电话{phone}，{}", "啊".repeat(DEFAULT_MAX_BUFFER));
    let lang_v = s(&["zh"]);
    let mut r = StreamingRedactor::new(make_detect(lang_v.clone()), make_redact(lang_v));
    let mut out = String::new();
    out.push_str(&r.feed(&c1).unwrap().segment.downstream_text);
    out.push_str(&r.flush().unwrap().segment.downstream_text);
    assert!(!out.contains(phone), "phone leaked");
    let agg = r.aggregate_key();
    let fake = agg
        .iter()
        .find(|(k, v)| v.as_str() == phone && k.starts_with("19999"))
        .map(|(k, _)| k.clone())
        .expect("realistic phone fake present");
    let count = out.matches(&fake).count();
    assert_eq!(count, 1, "the fake must appear exactly once (no double-emit)");
}


#[test]
fn region_evidence_before_cut_not_orphaned() {
    // Evidence-gated leak: a bare zh region (西湖区) fires ONLY via proximity to a
    // phone. Detection-context window: the whole buffer (phone + region, within ±W)
    // is detected as a unit and the region redacted with that detection — no
    // re-detect of a bare slice, so the region can't be emitted below threshold.
    let (out, _) = stream(&["我的电话13800138000。西湖区"], &["zh"]);
    assert!(!out.contains("西湖区"), "bare region leaked across the evidence cut: {out:?}");
    assert!(!out.contains("13800138000"), "phone leaked: {out:?}");
}

#[test]
fn region_evidence_after_cut_not_orphaned() {
    // Mirror direction: region in the prefix, its proximate phone in the residual —
    // both within ±W, so detect-on-full fires the region and the window redacts it.
    let (out, _) = stream(&["西湖区。我的电话13800138000"], &["zh"]);
    assert!(!out.contains("西湖区"), "bare region leaked across the evidence cut: {out:?}");
}

#[test]
fn hobby_cue_across_cut_not_orphaned() {
    // The cue-window variant: a hobby (攀岩) fires only because the cue 喜欢 is in
    // its window. A cue is NOT a detected entity, but the context window keeps cue +
    // term in one detect-on-full, so the hobby is detected and redacted as a unit.
    let (out, _) = stream(&["我喜欢。攀岩"], &["zh"]);
    assert!(!out.contains("攀岩"), "bare hobby leaked across the cue cut: {out:?}");
}

#[test]
fn region_evidence_at_exact_prox_boundary_not_orphaned() {
    // The region fires on a phone at EXACTLY distance 50 (the inclusive
    // REGION_PROX_NEAR boundary). W (= 128) covers dist-50, so detect-on-full sees
    // the corroborating phone and the region is redacted. (Was the old margin
    // off-by-one guard; with the widening gone the window subsumes it.)
    let filler = "啊".repeat(50);
    let input = format!("13812345678{filler}西湖区。");
    let (out, _) = stream(&[&input], &["zh"]);
    assert!(!out.contains("西湖区"), "region at exact prox distance 50 leaked: {out:?}");
    assert!(!out.contains("13812345678"), "phone leaked: {out:?}");
}

// ── Cross-sentence evidence (context window) + fuzz oracle ──────────────────────

#[test]
fn cross_sentence_forward_region_redacted() {
    // Forward: candidate (花生, a medical condition allergen) in segment 1, its cue
    // (过敏) in segment 2. The forward hold-back keeps 花生 buffered until 过敏
    // arrives, so detect-on-full fires it. Must redact ≡ batch (no bare term).
    let (out, _) = stream(&["我对花生", "过敏很严重。"], &["zh"]);
    assert!(!out.contains("花生"), "forward cross-sentence leak: {out:?}");
}

#[test]
fn cross_sentence_backward_hobby_redacted() {
    // Backward: cue (喜欢) emitted-region in segment 1, candidate (攀岩) in segment
    // 2. The retained left-context keeps 喜欢 in scope when 攀岩 arrives.
    let (out, _) = stream(&["我很喜欢。", "攀岩这项运动。"], &["zh"]);
    assert!(!out.contains("攀岩"), "backward cross-sentence leak: {out:?}");
}

#[test]
fn fuzz_stream_equals_batch_zh_gated() {
    // The zero-debt proof: for several zh texts mixing a gated candidate with its
    // evidence, every chunking of the stream must equal the batch redaction
    // byte-for-byte. This is the safety net for removing the Bug-2 widening.
    let long = "我的电话是13800138000，请尽快联系。".repeat(15); // > W → real mid-stream cuts
    let texts = [
        "我对花生过敏，电话13800138000。",
        "他住在西湖区，喜欢攀岩。",
        "我很喜欢。攀岩这项运动。",
        "电话13812345678。西湖区那边。",
        long.as_str(),
    ];
    for t in texts {
        let batch = one_shot_redact(t, &["zh"]);
        for size in [1usize, 2, 3, 5, 7] {
            let chunks = chunk_chars(t, size);
            let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
            let (streamed, _) = stream(&refs, &["zh"]);
            assert_eq!(streamed, batch, "stream≠batch on {t:?} size {size}");
        }
    }
}

#[test]
fn documented_edge_evidence_beyond_w_not_retained() {
    // Spec §3 residual edge — a BOUNDED-MEMORY limit, NOT a leak we intend to fix.
    // The detection-context window retains only the last W (EVIDENCE_CONTEXT_WINDOW)
    // chars of already-emitted text as left-context, so evidence committed MORE than
    // W chars before a cut is gone from the buffer and can no longer corroborate a
    // later candidate. This is precisely the input class `stream ≡ batch` provably
    // cannot hold for with a bounded buffer (a candidate whose sole evidence is a
    // >W-distant entity — e.g. a >W-char corroborator straddling the lookahead). Pin
    // it so the window can neither silently WIDEN (retain more than W → unbounded
    // memory) nor silently REGRESS (retain less).
    let lang_v = s(&["zh"]);
    let mut r = StreamingRedactor::new(make_detect(lang_v.clone()), make_redact(lang_v));
    // A unique ASCII evidence marker (no entity in zh mode), then > W filler, a
    // sentence boundary, then a tail long enough that the boundary sits past the
    // forward hold-back and is emitted (forcing a real cut + carry).
    let marker = "EVIDENCE-MARK";
    let input = format!("{marker}{}。{}", "啊".repeat(200), "哦".repeat(200));
    r.feed(&input).expect("feed");

    let boundary = last_boundary_index(&input);
    assert!(
        boundary > EVIDENCE_CONTEXT_WINDOW as isize,
        "precondition: the cut must land past W so the marker falls outside the window"
    );
    // The carry retains exactly the last W chars before the cut plus everything after
    // it — never more (that would be unbounded growth), never the >W-distant marker.
    let expected_retained =
        input.chars().count() - (boundary as usize - EVIDENCE_CONTEXT_WINDOW);
    assert_eq!(
        r.buffer().chars().count(),
        expected_retained,
        "left-context must be capped at exactly W"
    );
    assert!(
        !r.buffer().contains(marker),
        "evidence committed >W before the cut must NOT be retained (the §3 bound): {:?}",
        r.buffer()
    );
}

fn pem_key(body_lines: usize) -> String {
    let line = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAA";
    let body: Vec<&str> = (0..body_lines).map(|_| line).collect();
    format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----",
        body.join("\n")
    )
}

#[test]
fn ssh_private_key_streamed_line_by_line_not_leaked() {
    // A multi-line PEM key fed line-by-line: each `\n` is an always-boundary that
    // would commit the BEGIN line + body lines BEFORE END arrives (neither half
    // matches ssh_private_key alone) → plaintext leak. The opener pending span must
    // hold the cut before BEGIN so the whole key is carried + redacted on END.
    let key = pem_key(3);
    let text = format!("my key:\n{key}\ndone.");
    let chunks: Vec<String> = text.split('\n').map(|l| format!("{l}\n")).collect();
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
    let (out, _) = stream(&refs, &["en"]);
    assert!(!out.contains("-----BEGIN OPENSSH PRIVATE KEY-----"), "BEGIN line leaked: {out:?}");
    assert!(!out.contains("b3BlbnNzaC1"), "key body leaked: {out:?}");
}

#[test]
fn ssh_private_key_larger_than_buffer_not_leaked() {
    // A COMPLETE key (END present) whose total length exceeds DEFAULT_MAX_BUFFER but
    // stays within the 10000 body bound (so batch redacts it) must NOT be
    // force-flush-split. The dangerous shape is END with NO trailing boundary after
    // it: the last boundary is the '\n' INSIDE the key, so the snap lands at cut==0
    // and — once END closes the opener — the bounded drain would split the key head
    // unless the ceiling stays raised while ANY BEGIN is present. Fed line-by-line
    // (END is the final chunk, no trailing newline) AND as a single feed.
    let key = pem_key(90); // ~5400 chars > DEFAULT_MAX_BUFFER, body < 10000
    assert!(key.chars().count() > DEFAULT_MAX_BUFFER);
    let lines: Vec<String> = key.split('\n').map(String::from).collect();
    let chunks: Vec<String> = lines
        .iter()
        .enumerate()
        .map(|(i, l)| if i + 1 < lines.len() { format!("{l}\n") } else { l.clone() })
        .collect();
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
    let (out, _) = stream(&refs, &["en"]);
    assert!(!out.contains("-----BEGIN OPENSSH PRIVATE KEY-----"), "BEGIN leaked (line-by-line, no trailing boundary)");
    assert!(!out.contains("b3BlbnNzaC1"), "body leaked (line-by-line, no trailing boundary)");

    // Single feed of the whole key, then flush — same guarantee.
    let (out2, _) = stream(&[&key], &["en"]);
    assert!(!out2.contains("-----BEGIN OPENSSH PRIVATE KEY-----"), "BEGIN leaked (single feed)");
    assert!(!out2.contains("b3BlbnNzaC1"), "body leaked (single feed)");
}

#[test]
fn dense_boundaryless_forceflush_does_not_split_region() {
    // Bounded-drain split guard: a dense, boundary-less stream of region+phone
    // repeats hits the max_buffer force-flush. The evidence-widening chains the snap
    // all the way to 0, so the engine must drain — and the drain must be snapped
    // CLOSED-ONLY so it never splits a region straddling the drain point (a split
    // would recombine downstream into a verbatim leak). The region must not appear.
    let region = "上海浦东新区";
    let chunk = format!("我住在{region}，电话13800138000，");
    let big: String = chunk.repeat(500); // dense, no sentence boundary
    let (out, _) = stream(&[&big], &["zh"]);
    assert!(!out.contains(region), "region split/leaked across the bounded drain: present in output");
}

#[test]
fn open_ended_entity_does_not_grow_buffer_unbounded() {
    // REGRESSION (A2): an open-ended detected span whose span keeps growing as more
    // boundary-less chars arrive used to drive carry_cut_index to cut<=0 on EVERY
    // feed, so the buffer never drained — it grew monotonically. The carry must
    // stay bounded.
    //
    // C1 no-leak strengthening: the open email "a@b.co.co…" spans the buffer from
    // index 0; the forced bounded-drain must RE-DETECT its emit slice so the head
    // "a@b" is REDACTED, not dropped+leaked raw. Accumulate the output and assert
    // the head never appears (the single assertion that surfaces C1).
    let lang_v = s(&["en"]);
    let mut r = StreamingRedactor::new(make_detect(lang_v.clone()), make_redact(lang_v));
    let mut out = String::new();
    out.push_str(&r.feed("a@b").unwrap().segment.downstream_text);
    let seg = ".co".repeat(5000); // 15000 boundary-less chars/feed
    let mut emitted_any = false;
    for _ in 0..30 {
        let res = r.feed(&seg).expect("feed must not error");
        if !res.segment.downstream_text.is_empty() {
            emitted_any = true;
        }
        out.push_str(&res.segment.downstream_text);
        assert!(
            r.buffer().chars().count() < 3 * DEFAULT_MAX_BUFFER,
            "buffer grew unbounded: {} chars",
            r.buffer().chars().count()
        );
    }
    out.push_str(&r.flush().unwrap().segment.downstream_text);
    assert!(emitted_any, "no downstream text ever emitted — buffer never drained");
    assert!(
        !out.contains("a@b"),
        "open-ended email head leaked raw across the forced bounded drain (C1)"
    );
}

/// A boundary-less typed token whose length far exceeds `DEFAULT_MAX_BUFFER` and
/// whose PREFIX still matches the same pattern: a GitHub token `ghp_` + `n` chars.
/// No validator, no sentence boundary, so the force-flush bounded drain must split
/// it — and the split head must be re-detected + redacted, not leaked raw.
fn mega_github_token(n: usize) -> String {
    format!("ghp_{}", "A".repeat(n))
}

#[test]
fn forceflush_megabuffer_typed_entity_head_not_leaked() {
    // C1 (CRITICAL leak regression): a >max_buffer boundary-less github_token is fed
    // in small chunks. The buffer hits DEFAULT_MAX_BUFFER with the token spanning
    // [0, len); the bounded drain MUST split it. Before the fix the range-shifted
    // straddler was DROPPED (end > cut) and the ~3840-char head emitted RAW; the fix
    // re-detects the emit slice so the head (still a valid github_token prefix) is
    // redacted. Pin: the distinctive head must be ABSENT, and restore round-trips.
    let token = mega_github_token(5000); // 5004 chars > DEFAULT_MAX_BUFFER + CARRY_WINDOW
    assert!(token.chars().count() > DEFAULT_MAX_BUFFER + CARRY_WINDOW);
    let chunks: Vec<String> = chunk_chars(&token, 137); // small chunks, no boundary
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
    let (out, agg) = stream(&refs, &["en"]);

    let head = format!("ghp_{}", "A".repeat(200));
    assert!(
        !out.contains(&head),
        "github_token head leaked RAW across the forced bounded drain (C1)"
    );
    // Restore round-trips: the redacted head expands back and the documented-edge
    // raw tail is untouched, so the original is reconstructed exactly.
    let restored = restore_full(&out, &agg, None, None).unwrap();
    assert_eq!(restored, token, "restore must reconstruct the original token");
}

#[test]
fn shift_spans_clamps_left_straddler_to_in_range_tail() {
    // The clamp restore-safety fix (C1 face 3): an entity whose head reaches back
    // into the already-emitted left-context (start < lo) is clamped to start=0 AND
    // its text TRUNCATED to the in-range tail, so the minted fake maps to exactly
    // the chars the emit range covers. Without truncation key[fake] = the FULL
    // original while only the tail is spliced → restore expands the fake over the
    // already-emitted head → a round-trip corruption (duplicated head).
    let e = PatternMatch {
        text: "abcdefgh".to_string(), // buffer [2, 10)
        type_: "phone".to_string(),
        start: 2,
        end: 10,
        confidence: 1.0,
        layer: 1,
    };
    // lo=5: the head "abc" ([2,5)) is already-emitted left-context; emit range ends past end.
    let out = shift_spans(&[e], 5, 12);
    assert_eq!(out.entities.len(), 1);
    let se = &out.entities[0];
    assert_eq!(se.start, 0, "clamped to the range start");
    assert_eq!(se.end, 5, "end rebased (10 - lo 5)");
    assert_eq!(se.text, "defgh", "text truncated to the in-range tail (dropped lo-start=3 head chars)");
}

#[test]
fn fuzz_megabuffer_typed_entity_no_leak_en() {
    // Fuzz oracle extension: a >max_buffer typed entity (EN — the corpus above is
    // zh-only) fed under several chunkings. For EVERY chunking the FULL token
    // original (which batch redacts as one unit) must be ABSENT from the streamed
    // output — before the C1 fix the dropped straddler emitted the head raw and the
    // tail raw CONTIGUOUSLY, re-forming the whole token. Restore must round-trip too.
    let token = mega_github_token(6000); // 6004 chars
    for size in [89usize, 512, 1777] {
        let chunks = chunk_chars(&token, size);
        let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
        let (out, agg) = stream(&refs, &["en"]);
        assert!(
            !out.contains(&token),
            "full token re-formed (leaked) in stream output at chunk size {size}"
        );
        assert_eq!(
            restore_full(&out, &agg, None, None).unwrap(),
            token,
            "restore round-trip failed at chunk size {size}"
        );
    }
}


// ── normal stream (no force-flush) parity ──────────────────────────────────────

#[test]
fn normal_sentence_boundary_stream_unchanged() {
    // A normal stream that flushes at sentence boundaries must redact entities,
    // keep raw PII absent, and round-trip via aggregate_key.
    let chunks = [
        "请拨打 13912345678 联系老王。",
        "或拨 13987654321 找老陈。",
        "邮箱 user@company.com 已记录。",
    ];
    let (out, agg) = stream(&chunks, &["zh"]);
    assert!(!out.contains("13912345678"));
    assert!(!out.contains("13987654321"));
    assert!(!out.contains("user@company.com"));
    let joined: String = chunks.concat();
    let restored = restore_full(&out, &agg, None, None).unwrap();
    assert_eq!(restored, joined);
}

#[test]
fn cross_chunk_phone_zh() {
    // Phone split across two chunks. With the forward hold-back (W), a short
    // sentence is held until flush; the whole-stream output must still redact the
    // phone with no bare leak.
    let lang_v = s(&["zh"]);
    let mut r = StreamingRedactor::new(make_detect(lang_v.clone()), make_redact(lang_v));
    let out1 = r.feed("电话1391").unwrap(); // no complete entity → buffered
    assert_eq!(out1.segment.downstream_text, "");
    let mut out = out1.segment.downstream_text;
    out.push_str(&r.feed("2345678。").unwrap().segment.downstream_text);
    out.push_str(&r.flush().unwrap().segment.downstream_text);
    assert!(
        !out.contains("13912345678"),
        "phone should be redacted across chunks"
    );
}

#[test]
fn aggregate_key_same_fake_across_chunks() {
    // Same original repeated across the stream maps to exactly ONE realistic fake
    // (accumulated-key continuity). Each chunk carries enough boundary-less filler
    // (> W) that its sentence is pushed out of the forward hold-back window and
    // genuinely emitted in a separate redact round, so this exercises cross-round
    // reuse (deterministic per (salt, value)), not just within-call dedup.
    let filler = "啊".repeat(200);
    let chunks = [
        format!("第一次13912345678。{filler}"),
        format!("第二次13912345678。{filler}"),
    ];
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
    let (_, agg) = stream(&refs, &["zh"]);
    let fakes: HashSet<&String> = agg
        .iter()
        .filter(|(k, v)| v.as_str() == "13912345678" && k.starts_with("199"))
        .map(|(k, _)| k)
        .collect();
    assert_eq!(fakes.len(), 1, "the repeated phone must map to exactly one fake: {fakes:?}");
}

#[test]
fn flush_idempotent_on_empty() {
    let lang_v = s(&["zh"]);
    let mut r = StreamingRedactor::new(make_detect(lang_v.clone()), make_redact(lang_v));
    r.feed("电话13912345678。").unwrap(); // short sentence held by the forward hold-back
    let drained = r.flush().unwrap(); // end-of-stream drains it (phone redacted)
    assert!(
        !drained.segment.downstream_text.contains("13912345678"),
        "phone redacted at flush"
    );
    let result = r.flush().unwrap(); // nothing left → empty, idempotent
    assert_eq!(result.segment.downstream_text, "");
    assert!(result.segment.key.is_empty());
}

#[test]
fn multi_chunk_redact_restore_roundtrip() {
    // A multi-chunk redact → restore roundtrip via aggregate_key (the integration
    // oracle: the downstream stream restores to the exact concatenated input).
    let chunks = [
        "请拨打 13912345678 联系老王。",
        "或拨 13987654321 找老陈。",
        "邮箱 user@company.com 已记录。",
    ];
    let (out, agg) = stream(&chunks, &["zh"]);
    let joined: String = chunks.concat();
    assert_eq!(restore_full(&out, &agg, None, None).unwrap(), joined);
}

// ── StreamingRestorer parity (test_streaming.py::TestStreamingRestorer) ─────────

#[test]
fn restorer_restores_at_sentence_boundary() {
    let mut key = HashMap::new();
    key.insert("P-1".to_string(), "13812345678".to_string());
    let mut restorer = StreamingRestorer::new(key, RestoreStrategy::Sentence);
    let result = restorer.feed("结果是P-1。下一句").unwrap();
    assert!(result.contains("13812345678"));
}

#[test]
fn restorer_buffers_incomplete_sentence() {
    let mut key = HashMap::new();
    key.insert("P-1".to_string(), "13812345678".to_string());
    let mut restorer = StreamingRestorer::new(key, RestoreStrategy::Sentence);
    let result = restorer.feed("结果是P-1").unwrap();
    assert_eq!(result, ""); // no boundary, buffered
}

#[test]
fn restorer_flush_remaining() {
    let mut key = HashMap::new();
    key.insert("P-1".to_string(), "13812345678".to_string());
    let mut restorer = StreamingRestorer::new(key, RestoreStrategy::Sentence);
    restorer.feed("结果是P-1").unwrap();
    let result = restorer.flush().unwrap();
    assert!(result.contains("13812345678"));
}

#[test]
fn restorer_chunk_by_chunk() {
    let mut key = HashMap::new();
    key.insert("P-1".to_string(), "13812345678".to_string());
    let mut restorer = StreamingRestorer::new(key, RestoreStrategy::Sentence);
    let full: Vec<char> = "第一句话P-1。第二句话。".chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < full.len() {
        let end = (i + 5).min(full.len());
        let chunk: String = full[i..end].iter().collect();
        out.push_str(&restorer.feed(&chunk).unwrap());
        i = end;
    }
    out.push_str(&restorer.flush().unwrap());
    assert!(out.contains("13812345678"));
}

#[test]
fn restorer_empty_key() {
    let mut restorer = StreamingRestorer::new(HashMap::new(), RestoreStrategy::Sentence);
    let result = restorer.feed("hello world。").unwrap();
    assert_eq!(result, "hello world。");
}

#[test]
fn restorer_none_strategy_restores_immediately() {
    let mut key = HashMap::new();
    key.insert("P-1".to_string(), "13812345678".to_string());
    let mut restorer = StreamingRestorer::new(key, RestoreStrategy::None);
    let result = restorer.feed("结果是P-1").unwrap();
    assert!(result.contains("13812345678")); // no buffering, restored immediately
}

#[test]
fn restorer_value_split_across_chunks() {
    // A long realistic value split mid-fake must aggregate (sentence buffering)
    // before restore — the restorer's whole-code matching across chunk boundaries.
    let mut key = HashMap::new();
    key.insert("19999892122".to_string(), "13912345678".to_string());
    let downstream = "电话 19999892122 联系。";
    let fake = "19999892122";
    let ds_chars: Vec<char> = downstream.chars().collect();
    let fake_start = downstream.find(fake).unwrap();
    let fake_start_chars = downstream[..fake_start].chars().count();
    let split = fake_start_chars + fake.chars().count() / 2;
    let chunk1: String = ds_chars[..split].iter().collect();
    let chunk2: String = ds_chars[split..].iter().collect();
    // chunk1 must NOT contain a REAL sentence boundary (it would otherwise flush).
    assert_eq!(restorer_split(&chunk1), ("".to_string(), chunk1.clone()));
    let mut restorer = StreamingRestorer::new(key, RestoreStrategy::Sentence);
    let out1 = restorer.feed(&chunk1).unwrap();
    assert_eq!(out1, "", "chunk1 alone should buffer (no sentence boundary)");
    let mut out = out1;
    out.push_str(&restorer.feed(&chunk2).unwrap());
    out.push_str(&restorer.flush().unwrap());
    assert_eq!(out, "电话 13912345678 联系。");
}

// ── Restorer must NOT split a realistic fake at its internal dot ────────────────

#[test]
fn restorer_split_internal_dot_at_buffer_end_holds() {
    // REGRESSION: an ASCII `.` that is the rightmost buffer char (or not
    // followed by whitespace) is ambiguous — it could be a fake's internal dot
    // (email/IPv4). The restorer must mirror the redactor: ASCII boundary counts
    // ONLY before whitespace; never at the buffer end. So a dotted fake's internal
    // dot does not flush a half-token.
    assert_eq!(
        restorer_split("mail user16068@example."),
        ("".to_string(), "mail user16068@example.".to_string()),
        "internal dot at buffer end must NOT split"
    );
    assert_eq!(
        restorer_split("ip 192.168."),
        ("".to_string(), "ip 192.168.".to_string()),
        "IPv4 octet dot at buffer end must NOT split"
    );
    // ASCII `.` BEFORE whitespace is a real sentence end → splits right after the
    // dot (index AFTER the boundary char, mirroring last_boundary_index).
    assert_eq!(
        restorer_split("done. rest"),
        ("done.".to_string(), " rest".to_string()),
        "ASCII dot before whitespace is a real boundary"
    );
    // CJK 。 and \n always split, even at the buffer end.
    assert_eq!(
        restorer_split("结束。"),
        ("结束。".to_string(), "".to_string()),
        "CJK boundary always splits"
    );
    assert_eq!(
        restorer_split("line\n"),
        ("line\n".to_string(), "".to_string()),
        "newline always splits"
    );
}

#[test]
fn restorer_dotted_fake_email_round_trips_char_by_char() {
    // The documented round-trip: a realistic dotted fake (email) fed char-by-char
    // through the restorer must fully restore, not flush a half-token at the
    // internal dot.
    let mut key = HashMap::new();
    key.insert("user16068@example.net".to_string(), "user@test.org".to_string());
    let ds = "mail user16068@example.net ok.";
    let mut restorer = StreamingRestorer::new(key, RestoreStrategy::Sentence);
    let mut out = String::new();
    for c in ds.chars() {
        out.push_str(&restorer.feed(&c.to_string()).unwrap());
    }
    out.push_str(&restorer.flush().unwrap());
    assert_eq!(out, "mail user@test.org ok.");
}

#[test]
fn restorer_dotted_fake_ipv4_round_trips_char_by_char() {
    // Same for an IPv4 fake whose octet dots are internal.
    let mut key = HashMap::new();
    key.insert("192.0.2.50".to_string(), "10.1.2.3".to_string());
    let ds = "server 192.0.2.50 up.";
    let mut restorer = StreamingRestorer::new(key, RestoreStrategy::Sentence);
    let mut out = String::new();
    for c in ds.chars() {
        out.push_str(&restorer.feed(&c.to_string()).unwrap());
    }
    out.push_str(&restorer.flush().unwrap());
    assert_eq!(out, "server 10.1.2.3 up.");
}
