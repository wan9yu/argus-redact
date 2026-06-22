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
        let mut entities = r.layer1.clone();
        entities.extend(r.person.clone());
        DetectSpans { entities, hints: r.hints }
    }
}

/// A redact closure mirroring the wasm one-shot (`detect_l1` → `build_type_info`
/// → `redact_l1`), returning the realistic downstream segment. The `realistic`
/// strategy is wired via the pseudonym-llm-ish config so the straddle tests assert
/// raw PII is absent from the downstream text.
fn make_redact(lang: Vec<String>) -> impl Fn(&str) -> Result<RedactSegment, String> {
    let wl = keep_whitelist();
    move |text: &str| {
        let detected = detect_l1(text, &lang, &[]).map_err(|e| e.to_string())?;
        let mut entities = detected.layer1;
        entities.extend(detected.person);
        // Realistic-strategy config for the PII types under test (phone / email /
        // ip_address / organization / person), so downstream gets reserved-range
        // fakes — the same shapes the Python downstream_text carries.
        let config = realistic_config();
        let info_pairs = build_type_info(&entities, Some(&config), &lang, None);
        let info_map: HashMap<String, TypeInfo> = info_pairs.into_iter().collect();
        let result = redact_l1(
            RedactL1Args {
                text,
                lang: &lang,
                names: &[],
                type_info: &info_map,
                salt: Some(&Salt::Int(SALT)),
                key: None,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
                types: None,
                types_exclude: None,
            },
            &TestPseudoFactory,
            None,
        )?;
        Ok(RedactSegment {
            downstream_text: result.redacted,
            key: result.key,
            aliases: result.aliases,
        })
    }
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

// ── bounded_carry parity (test_streaming_straddle.py) ──────────────────────────

#[test]
fn bounded_carry_small_buffer_carries_all() {
    let combined = "x".repeat(100);
    let (emit, residual) = bounded_carry(&combined, DEFAULT_MAX_BUFFER);
    assert_eq!(emit, "");
    assert_eq!(residual, combined);
}

#[test]
fn bounded_carry_small_max_buffer_carries_all_no_panic() {
    // REGRESSION: with a max_buffer SMALLER than the carry window, a combined
    // buffer of len < CARRY_WINDOW must not compute `combined.len() - CARRY_WINDOW`
    // (usize underflow → out-of-range slice panic / wasm abort). It carries all,
    // matching the pre-port Python negative-index ('', combined). Must never panic.
    let combined = "a".repeat(100);
    let (emit, residual) = bounded_carry(&combined, 5);
    assert_eq!(emit, "");
    assert_eq!(residual, combined);
}

#[test]
fn bounded_carry_at_max_buffer_drains_to_len_minus_window() {
    let combined = "x".repeat(DEFAULT_MAX_BUFFER);
    let (emit, residual) = bounded_carry(&combined, DEFAULT_MAX_BUFFER);
    let target = DEFAULT_MAX_BUFFER - CARRY_WINDOW;
    assert_eq!(emit, "x".repeat(target));
    assert_eq!(residual, "x".repeat(CARRY_WINDOW));
    assert_eq!(residual.chars().count(), CARRY_WINDOW);
    // Above max_buffer too.
    let bigger = "y".repeat(DEFAULT_MAX_BUFFER + 500);
    let (emit2, residual2) = bounded_carry(&bigger, DEFAULT_MAX_BUFFER);
    assert_eq!(emit2, "y".repeat(DEFAULT_MAX_BUFFER + 500 - CARRY_WINDOW));
    assert_eq!(residual2.chars().count(), CARRY_WINDOW);
}

// ── Snap-parity SSOT (Rust snap == Python merged _detect snap) ──────────────────

/// The merged-`_detect`-equivalent cut oracle: the cut a SNAP over the SAME
/// entity set Python's `_detect` (fast) produces (`detect_l1` → `merge_entities_
/// with_text` → `filter_self_reference`) would pick at `target`. This is what the
/// Rust `carry_cut_index` MUST now match — regardless of whether a caller threads
/// raw or merged spans into it.
fn merged_detect_cut(combined: &str, target: usize, lang: &[&str]) -> usize {
    let lang_v = s(lang);
    let d = detect_l1(combined, &lang_v, &[]).expect("detect_l1");
    let mut entities = d.layer1.clone();
    entities.extend(d.person.clone());
    let merged = crate::merge_entities_with_text(entities, combined);
    let filtered = crate::filter_self_reference(merged, &d.hints);
    let mut cut = target;
    for e in &filtered {
        if e.start < cut && cut < e.end {
            cut = e.start;
        }
    }
    cut
}

#[test]
fn snap_parity_en_mary_jane_watson_parker() {
    // REGRESSION: RAW detect_l1 over "Mary Jane Watson Parker" yields
    // overlapping person spans [(0,16),(10,23)]; MERGED (_detect fast) yields
    // [(0,16)]. At target 16 the merged snap does NOT straddle (cut=16) but the
    // RAW snap straddles via (10,23) → cut=10, leaking "Mary Jane " raw. The core
    // snap MUST now normalize internally and match the merged cut.
    let combined = "Mary Jane Watson Parker";
    let target = 16;
    let detect = make_detect(s(&["en"]));
    let rust_cut = carry_cut_index(combined, target, &detect);
    let oracle = merged_detect_cut(combined, target, &["en"]);
    assert_eq!(rust_cut, oracle, "core snap must match merged _detect cut");
    assert_eq!(rust_cut, 16, "merged snap does not straddle at 16 → no snap-back");
}

#[test]
fn snap_parity_zh_org_run() {
    // The zh case: a contiguous CJK org/person run. The core snap (normalized)
    // must match the merged _detect cut at every interior target.
    let combined = "陈大文张三在北京字节跳动科技有限公司";
    let detect = make_detect(s(&["zh"]));
    let n = combined.chars().count();
    for target in 1..n {
        let rust_cut = carry_cut_index(combined, target, &detect);
        let oracle = merged_detect_cut(combined, target, &["zh"]);
        assert_eq!(
            rust_cut, oracle,
            "core snap must match merged _detect cut at target {target}"
        );
    }
}

#[test]
fn snap_parity_fuzz_en_and_zh() {
    // Fuzz a range of buffers/targets: the core snap must equal the merged-_detect
    // cut for every (buffer, target) — order/overlap-invariant.
    let cases: [(&str, &[&str]); 4] = [
        ("Mary Jane Watson Parker called Bob Smith Jones.", &["en"]),
        ("Email jane.doe@company.com or john@x.org now.", &["en"]),
        ("陈大文张三在北京字节跳动科技有限公司上班。", &["zh"]),
        ("电话13912345678联系王建国，地址北京市朝阳区。", &["zh"]),
    ];
    for (combined, lang) in cases {
        let lang_v = s(lang);
        let detect = make_detect(lang_v.clone());
        let n = combined.chars().count();
        for target in 0..=n {
            let rust_cut = carry_cut_index(combined, target, &detect);
            let oracle = merged_detect_cut(combined, target, lang);
            assert_eq!(
                rust_cut, oracle,
                "snap mismatch on {combined:?} at target {target}"
            );
        }
    }
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
fn unbounded_token_longer_than_window_is_the_documented_edge() {
    // Documented residual edge: a contiguous run LONGER than CARRY_WINDOW that is
    // not a single detected entity can still split at the force-flush cut. Pin the
    // known limitation: the token ends up split between emit and residual.
    let token = "9".repeat(2 * CARRY_WINDOW); // far longer than the carry window
    let total = DEFAULT_MAX_BUFFER + CARRY_WINDOW + 100;
    let target = total - CARRY_WINDOW;
    let start = target - CARRY_WINDOW; // run crosses target by a full window each side
    let pad = "x".repeat(start - "code".chars().count());
    let after = "x".repeat(total - start - token.chars().count());
    let combined = format!("{pad}code{token}{after}");
    let detect = make_detect(s(&["en"]));
    let (emit, residual) =
        consume_to_boundary_detect("", &combined, DEFAULT_MAX_BUFFER, false, &detect);
    assert!(
        !emit.contains(&token) && !residual.contains(&token),
        "expected the >window run to be split (documented limitation)"
    );
}

#[test]
fn open_ended_entity_does_not_grow_buffer_unbounded() {
    // REGRESSION (A2): an open-ended detected span whose span keeps growing as more
    // boundary-less chars arrive used to drive carry_cut_index to cut<=0 on EVERY
    // feed, so the buffer never drained — it grew monotonically. The carry must
    // stay bounded.
    let lang_v = s(&["en"]);
    let mut r = StreamingRedactor::new(make_detect(lang_v.clone()), make_redact(lang_v));
    r.feed("a@b").unwrap();
    let seg = ".co".repeat(5000); // 15000 boundary-less chars/feed
    let mut emitted_any = false;
    for _ in 0..30 {
        let res = r.feed(&seg).expect("feed must not error");
        if !res.segment.downstream_text.is_empty() {
            emitted_any = true;
        }
        assert!(
            r.buffer().chars().count() < 3 * DEFAULT_MAX_BUFFER,
            "buffer grew unbounded: {} chars",
            r.buffer().chars().count()
        );
    }
    assert!(emitted_any, "no downstream text ever emitted — buffer never drained");
}

#[test]
fn open_ended_entity_at_boundary_path_drains() {
    // The boundary path (boundary >= 0) must also drain via bounded_carry when an
    // open-ended span runs from buffer-start past the boundary (cut<=0). We force
    // carry_cut_index to 0 via a detect closure that reports one giant span.
    let combined = format!("{}stop. {}", "x".repeat(DEFAULT_MAX_BUFFER - 6), "y".repeat(100));
    assert!(last_boundary_index(&combined) >= 0); // precondition: boundary path
    let total = combined.chars().count();
    // detect reports a single span [0, total) → straddles ANY interior cut → cut=0.
    let detect = |_t: &str| DetectSpans {
        entities: vec![crate::PatternMatch {
            text: String::new(),
            type_: "person".to_string(),
            start: 0,
            end: total,
            confidence: 1.0,
            layer: 1,
        }],
        hints: Vec::new(),
    };
    let (emit, residual) =
        consume_to_boundary_detect("", &combined, DEFAULT_MAX_BUFFER, false, &detect);
    assert_ne!(residual, combined, "boundary-path cut<=0 still carries everything");
    let combined_chars: Vec<char> = combined.chars().collect();
    let expected_emit: String = combined_chars[..total - CARRY_WINDOW].iter().collect();
    assert_eq!(emit, expected_emit);
    assert_eq!(residual.chars().count(), CARRY_WINDOW);
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
    // Phone split across two chunks; first buffers, second emits redacted.
    let lang_v = s(&["zh"]);
    let mut r = StreamingRedactor::new(make_detect(lang_v.clone()), make_redact(lang_v));
    let out1 = r.feed("电话1391").unwrap(); // no boundary → buffered
    assert_eq!(out1.segment.downstream_text, "");
    let out2 = r.feed("2345678。").unwrap(); // boundary → emit
    assert!(
        !out2.segment.downstream_text.contains("13912345678"),
        "phone should be redacted across chunks"
    );
}

#[test]
fn aggregate_key_same_fake_across_chunks() {
    // Same original across chunks reuses the same fake (accumulated key continuity).
    let lang_v = s(&["zh"]);
    let mut r = StreamingRedactor::new(make_detect(lang_v.clone()), make_redact(lang_v));
    let out1 = r.feed("第一次提到13912345678。").unwrap();
    let out2 = r.feed("第二次还是13912345678。").unwrap();
    let f1: Vec<&String> = out1
        .segment
        .key
        .iter()
        .filter(|(k, v)| v.as_str() == "13912345678" && k.starts_with("199"))
        .map(|(k, _)| k)
        .collect();
    let f2: Vec<&String> = out2
        .segment
        .key
        .iter()
        .filter(|(k, v)| v.as_str() == "13912345678" && k.starts_with("199"))
        .map(|(k, _)| k)
        .collect();
    assert!(!f1.is_empty() && !f2.is_empty(), "realistic phone fake present in both");
    assert_eq!(f1[0], f2[0], "realistic fake must match across chunks");
}

#[test]
fn flush_idempotent_on_empty() {
    let lang_v = s(&["zh"]);
    let mut r = StreamingRedactor::new(make_detect(lang_v.clone()), make_redact(lang_v));
    r.feed("电话13912345678。").unwrap(); // complete sentence — buffer drains
    let result = r.flush().unwrap();
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
