//! Layer-1 detection orchestration — Rust port of the fast-mode L1 slice of
//! `glue/redact.py::_detect`.
//!
//! [`detect_l1`] reproduces the exact ordered sequence the Python `_detect` runs
//! before any merge/filter/boost, returning the **RAW** (unmerged) L1 entities +
//! the L1 hints + the near-misses. L2 (NER) and L3 (semantic) are NOT part of
//! this function — fast mode skips them, and full mode wires them in a later
//! caller step.
//!
//! ## The `_detect` → `detect_l1` mapping (fast-mode L1 portion)
//!
//! 1. `normalize_text(text)` → `(detect_text, offset_map)`. `use_normalized =
//!    offset_map.is_some()`.
//! 2. `match_patterns(detect_text, load_patterns(lang))` — `load_patterns`
//!    replicates `_load_patterns`: `builtin_patterns("shared") ++
//!    builtin_patterns(code)` for each lang (skipping a literal "shared" in the
//!    list, mirroring the Python loop). The core `match_patterns` returns ALL
//!    matches in ONE list; Python's `pure/patterns.py` splits them on confidence
//!    (`< 1.0` → near-miss, else result). We replicate that split here.
//! 3. If `use_normalized` and there are raw matches: `map_spans_to_original` the
//!    layer1 spans back to ORIGINAL-text offsets, rebuilding each match's `text`
//!    as `text[s..e]` (char-sliced) from the original — mirroring redact.py
//!    :210-228.
//! 4. `produce_hints_l1(layer1, text, near_misses)` — using the ORIGINAL `text`,
//!    not `detect_text`.
//! 5. `get_person_threshold(hints)`.
//! 6. zh person detection first (if "zh" in lang), then en (if "en" in lang) —
//!    BOTH honor `threshold` and receive `layer1` as `pii_entities` (en's
//!    bare-surname evidence gate uses the same proximity / threshold model as zh).
//!    (Matches Python's `entities.extend(zh); entities.extend(en)` order.)
//! 7. Names-only fallback (redact.py:268-283): if NEITHER "zh" NOR "en" is in
//!    lang AND `names` is non-empty, each non-empty known name's literal,
//!    non-overlapping occurrences in the ORIGINAL text are emitted as `person`
//!    entities (confidence 1.0, `text = name`). Mutually exclusive with the
//!    zh/en branches.
//! 8. layer1 + person tagged `layer = LAYER_REGEX` (= 1). RAW output: no
//!    merge/filter/boost.
//!
//! ## [`DetectL1Result`] serves both consumers
//!
//! - **Fast mode** (caller T6) needs `layer1 ++ person` (via [`DetectL1Result::entities`])
//!   plus `hints` to merge/filter/boost.
//! - **Full mode** (caller T8) consumes the same full four-kind `hints`
//!   (`pii_density` / `near_miss_format` / `text_intent` / `self_reference_tier`)
//!   that `detect_l1` already produces, and additionally needs `layer1`,
//!   `person`, and `near_misses` returned *separately* for the L2/L3 merge and
//!   the final report. Returning the four fields distinctly serves both without
//!   a re-match.

use std::collections::HashSet;

use crate::data::{all_langs, builtin_patterns};
use crate::grammar::normalize_grammar_en;
use crate::hints::{filter_self_reference, get_person_threshold, produce_hints_l1, Hint};
use crate::merger::merge_entities_with_text;
use crate::normalize::{
    finalize, map_spans_to_original, normalize_core, normalize_text_for_person,
};
use crate::occupation::detect_occupation_zh;
use crate::patterns::{match_patterns, PatternConfig, PatternError};
use crate::regions::detect_regions_zh;
use crate::replace::{replace, FakerFactory, PseudoFactory, ReplaceArgs, ReplaceResult, TypeInfo};
use crate::reserved_range::{byte_to_char_offset, char_slice};
use crate::types::PatternMatch;
use crate::{person_en, person_zh};

/// Layer = 1 (regex). Mirrors `argus_redact.layers.LAYER_REGEX`.
const LAYER_REGEX: u8 = 1;

/// The raw (pre-merge) output of L1 detection.
///
/// `layer1` and `person` are kept distinct so full mode can thread the L1a regex
/// entities and the person matches separately into the L2/L3 merge and report;
/// the full four-kind hint set is returned in `hints` (already produced here, not
/// recomputed downstream). Fast mode concatenates `layer1`/`person` via
/// [`DetectL1Result::entities`].
pub struct DetectL1Result {
    /// L1a regex matches (validator-clean), tagged `layer = 1`, spans in
    /// ORIGINAL-text offsets.
    pub layer1: Vec<PatternMatch>,
    /// L1b person-name matches (zh then en), tagged `layer = 1`.
    pub person: Vec<PatternMatch>,
    /// L1b evidence-gated Chinese admin-region matches (`type_ = "location"`),
    /// tagged `layer = 1`, spans in ORIGINAL-text offsets. Empty when `zh` is not
    /// in the requested lang.
    pub regions: Vec<PatternMatch>,
    /// L1b evidence-gated Chinese occupation matches (`type_ = "job_title"`),
    /// tagged `layer = 1`, spans in ORIGINAL-text offsets. Empty when `zh` is not
    /// in the requested lang.
    pub job_titles: Vec<PatternMatch>,
    /// L1b framework-detector matches (conditions ++ hobbies) — evidence-gated
    /// quasi-identifiers from `evidence_detector`. One combined vec so future
    /// framework detectors don't grow the result shape again.
    pub framework: Vec<PatternMatch>,
    /// L1 hints — all four kinds (`pii_density`, `near_miss_format`,
    /// `text_intent`, `self_reference_tier`) over the ORIGINAL text.
    pub hints: Vec<Hint>,
    /// Validator near-misses (regex matched, validation failed) — confidence 0.3.
    pub near_misses: Vec<PatternMatch>,
}

impl DetectL1Result {
    /// `layer1 ++ person` ONLY — **not** the full pre-merge L1 entity set. The
    /// complete fast-mode list also includes `regions`, `job_titles`, and
    /// `framework`, which the fast path (and each binding) concatenates
    /// separately; this helper exists for the tests that assert the layer1+person
    /// slice. Order mirrors Python's `entities.extend(layer1); extend(person)`.
    pub fn layer1_and_person(&self) -> Vec<PatternMatch> {
        let mut out = Vec::with_capacity(self.layer1.len() + self.person.len());
        out.extend(self.layer1.iter().cloned());
        out.extend(self.person.iter().cloned());
        out
    }
}

/// Build the L1 pattern set: `builtin_patterns("shared") ++ builtin_patterns(code)`
/// for each requested lang. Mirrors `_load_patterns` (incl. skipping a literal
/// "shared" inside the lang list). Order is preserved (RON file order per lang),
/// which the regex match precedence depends on.
fn load_patterns(lang: &[String]) -> Vec<PatternConfig> {
    let mut configs: Vec<PatternConfig> = Vec::new();
    let mut push = |p: &crate::data::PatternData| {
        configs.push(PatternConfig {
            type_: p.type_.clone(),
            pattern: p.pattern.clone(),
            check_context: p.check_context,
            group: p.group.clone(),
            validator: p.validator.clone(),
        });
    };
    for p in builtin_patterns("shared") {
        push(p);
    }
    for code in lang {
        if code == "shared" {
            continue;
        }
        for p in builtin_patterns(code) {
            push(p);
        }
    }
    // Always also load `language_neutral` patterns (CN structured numeric IDs, the
    // en card PAN) from any source lang the caller did NOT request — those digits
    // are the same regardless of surrounding script, so they must be detectable in
    // en/ja/ko/… text too. The per-pattern flag is the single source of truth:
    // scan every embedded lang, skipping "shared" (already loaded above) and any
    // requested lang (whose neutral patterns already loaded in the loop above).
    //
    // A neutral pattern that duplicates a requested lang's native one (en
    // `credit_card` vs zh `bank_card`, same PAN digits) is loaded anyway: the
    // overlap merge collapses the two matches into one entity, and the spurious
    // `near_miss_format` the loser used to raise is suppressed at the hint layer
    // (a near-miss whose span an accepted entity of another type already claims).
    for src in all_langs() {
        if src == "shared" || lang.iter().any(|l| l == src) {
            continue;
        }
        for p in builtin_patterns(src) {
            if p.language_neutral {
                push(p);
            }
        }
    }
    configs
}

/// Tag entities with `layer` if not already tagged (port of `_tag_layer`:
/// `layer if e.layer == 0 else e.layer`).
fn tag_layer(entities: &mut [PatternMatch], layer: u8) {
    for e in entities.iter_mut() {
        if e.layer == 0 {
            e.layer = layer;
        }
    }
}

/// Map matches from detect_text (normalized) coords back to ORIGINAL-text coords,
/// rebuilding each match's `text` as the original char-slice. Identity (clone) when
/// there is no offset map (text was not normalized).
///
/// ## Mutation coverage note
///
/// The `!matches.is_empty()` match guard (its `→ true` survivor) is an equivalent
/// mutant: when `matches` is empty the `Some` arm maps an empty span list and the
/// `.zip(...).map(...)` yields `[]`, exactly what the `_` arm's `matches.to_vec()`
/// returns. The guard is only a tiny shortcut (skip the `map_spans_to_original`
/// call on the empty fast path); removing it changes no output, so no test can
/// distinguish it.
fn map_matches_to_original(
    matches: &[PatternMatch],
    text: &str,
    offset_map: Option<&[usize]>,
    orig_len: usize,
) -> Vec<PatternMatch> {
    match offset_map {
        Some(map) if !matches.is_empty() => {
            let spans: Vec<(usize, usize)> =
                matches.iter().map(|m| (m.start, m.end)).collect();
            let mapped = map_spans_to_original(&spans, Some(map), orig_len);
            matches
                .iter()
                .zip(mapped.iter())
                .map(|(m, &(s, e))| PatternMatch {
                    text: char_slice(text, s, e),
                    type_: m.type_.clone(),
                    start: s,
                    end: e,
                    confidence: m.confidence,
                    layer: m.layer,
                })
                .collect()
        }
        _ => matches.to_vec(),
    }
}

/// Run the fast-mode L1 detection sequence, returning the RAW (unmerged) result.
///
/// `lang` is the resolved language list (e.g. `["zh"]`, `["zh","en"]`). `names`
/// is the known-names list. No merge/filter/boost is applied.
pub fn detect_l1(
    text: &str,
    lang: &[String],
    names: &[String],
) -> Result<DetectL1Result, PatternError> {
    if text.len() > crate::MAX_INPUT_SIZE {
        return Err(PatternError(format!(
            "input too large: {} bytes exceeds MAX_INPUT_SIZE {}",
            text.len(),
            crate::MAX_INPUT_SIZE
        )));
    }
    // 1. Normalize. The expensive steps 1–3 (invisible strip + accent fold +
    //    confusables + per-char NFKC) run ONCE via `normalize_core`; the full
    //    detect view and the person-detect view (step 7) both derive from that
    //    same intermediate, so they STRUCTURALLY share char positions + offset
    //    map (see step 7). `use_normalized` iff an offset map was produced.
    let core = normalize_core(text);
    let (normalized, offset_map) = match &core {
        Some((chars, omap)) => finalize(chars, omap, text, true),
        None => (text.to_string(), None),
    };
    let use_normalized = offset_map.is_some();
    let detect_text: &str = if use_normalized { &normalized } else { text };

    // 2. Match patterns over detect_text. The core returns ALL matches in one
    //    list; split on confidence to mirror pure/patterns.py (confidence < 1.0
    //    → near-miss at 0.3; else → result). Both sub-lists keep the core's
    //    start-sorted order, matching Python (results are re-sorted by start —
    //    already start-sorted here; near_misses keep append order = start order).
    let all_matches = match_patterns(detect_text, &load_patterns(lang))?;
    let mut layer1_raw: Vec<PatternMatch> = Vec::new();
    let mut near_misses: Vec<PatternMatch> = Vec::new();
    for m in all_matches {
        if m.confidence < 1.0 {
            near_misses.push(PatternMatch {
                text: m.text,
                type_: m.type_,
                start: m.start,
                end: m.end,
                confidence: 0.3,
                layer: m.layer,
            });
        } else {
            layer1_raw.push(m);
        }
    }

    // 3. Map normalized offsets back to original text (only on the raw results,
    //    matching Python which maps `layer1_raw` only). Rebuild each match's text
    //    as the ORIGINAL char-slice text[s..e]. `layer1_raw` stays AVAILABLE after
    //    this (the helper clones), so the zh person detector can reuse it as
    //    detect-coord pii_entities below.
    let orig_len = text.chars().count();
    let mut layer1 =
        map_matches_to_original(&layer1_raw, text, offset_map.as_deref(), orig_len);

    // 4. Tag layer1 with LAYER_REGEX.
    tag_layer(&mut layer1, LAYER_REGEX);

    // 5. Hints from the ORIGINAL text (not detect_text).
    let hints = produce_hints_l1(&layer1, text, &near_misses);

    // 6. Person threshold from the text_intent hint.
    let threshold = get_person_threshold(&hints);

    // 7. Person detection runs over a PERSON-specific normalized text — every
    //    name-preserving fold of `normalize_text` (invisible strip / accent fold /
    //    confusable / NFKC) EXCEPT the Chinese-digit-sequence step. That step turns
    //    a ≥7-char digit run into ASCII and would swallow a CJK name char that is
    //    also a digit homograph (`三`=3): `张三` next to a phone forms one digit run,
    //    so the full-normalization detect_text reads `张3` and the surname regex
    //    misses the name. Skipping ONLY that step keeps `张三` intact while still
    //    folding `Ｊohn`→`John`, `José`→`Jose`, `Ѕmith`→`Smith`. Resulting spans
    //    are in person-detect coords and map back to the ORIGINAL below (step 9),
    //    mirroring the layer1 map-back.
    //
    //    Both the full `detect_text` and this person-detect-text derive from the
    //    SAME `normalize_core` intermediate (steps 1–3 above) — they diverge only
    //    in the step-4 digit fold, which is an in-place, length-preserving value
    //    substitution. So the two views STRUCTURALLY share the SAME char positions
    //    and SAME offset map; only some char VALUES differ. Therefore `layer1_raw`
    //    (full-norm detect coords) is coordinate-correct as the zh detector's
    //    `pii_entities` (`person_norm_same_positions_as_full_norm` guards this): its
    //    `.start`/`.end` line up with the person-detect-text. (The zh detector reads
    //    only `.start`/`.end`/`.type_` of pii_entities, never `.layer`, so passing
    //    the untagged `layer1_raw` rather than the LAYER_REGEX-tagged `layer1` is
    //    behaviorally identical.) zh runs first (threshold + pii_entities), then en
    //    (SAME threshold + pii_entities — its bare-surname evidence gate mirrors
    //    zh's proximity / threshold model), matching Python's extend order.
    //
    //    Known names must match the person-detect-text, so they fold through the
    //    SAME person normalization (a plain name folds to itself). Spans map back
    //    to the original below, so an accented/fullwidth known-name still restores
    //    correctly.
    let (person_normalized, person_offset_map) = match &core {
        Some((chars, omap)) => finalize(chars, omap, text, false),
        None => (text.to_string(), None),
    };
    let person_use_normalized = person_offset_map.is_some();
    let person_detect_text: &str =
        if person_use_normalized { &person_normalized } else { text };
    let scan_names: Vec<String> = if person_use_normalized {
        names.iter().map(|n| normalize_text_for_person(n).0).collect()
    } else {
        names.to_vec()
    };

    let has_zh = lang.iter().any(|c| c == "zh");
    let has_en = lang.iter().any(|c| c == "en");

    let mut person: Vec<PatternMatch> = Vec::new();
    if has_zh {
        let mut zh = person_zh::detect_person_names(
            person_detect_text,
            &layer1_raw,
            &scan_names,
            threshold,
        );
        tag_layer(&mut zh, LAYER_REGEX);
        person.extend(zh);
    }
    if has_en {
        let mut en = person_en::detect_person_names(
            person_detect_text,
            &layer1_raw,
            &scan_names,
            threshold,
        );
        tag_layer(&mut en, LAYER_REGEX);
        person.extend(en);
    }

    // 8. Names-only fallback (redact.py:268-283): when NEITHER "zh" NOR "en" is
    //    in lang AND names is non-empty, the zh/en person detectors never run, so
    //    Python falls back to a literal scan of each known name. We scan
    //    `person_detect_text` with the person-normalized `scan_names` (parity with
    //    the detectors above), then map back in step 9. Mutually exclusive with the
    //    zh/en branches above (the condition guarantees it). Each name's
    //    NON-overlapping, case-sensitive, LITERAL occurrences
    //    (`re.finditer(re.escape(name), text)`) become person entities at
    //    confidence 1.0, with `text = name` (exactly as Python sets `text=name`,
    //    not the matched slice — equal for a literal match). Appended AFTER layer1
    //    in `.layer1_and_person()`, matching Python's `entities.append` order.
    if !has_zh && !has_en && !scan_names.is_empty() {
        for name in &scan_names {
            // Python `if not name: continue` — skip empty names.
            if name.is_empty() {
                continue;
            }
            // `re.finditer(re.escape(name), text)` is a LITERAL, case-sensitive,
            // non-overlapping scan; `str::match_indices` is exactly that (it
            // advances past each match, so non-overlapping holds) for a non-empty
            // needle — no regex compile, no per-hit fallibility. `match_indices`
            // yields a BYTE offset; convert the start once, then the end is just
            // `start + name.chars().count()` (the match equals `name`), saving the
            // second `byte_to_char_offset` O(n) scan.
            let name_chars = name.chars().count();
            for (byte_pos, _) in person_detect_text.match_indices(name.as_str()) {
                let start = byte_to_char_offset(person_detect_text, byte_pos);
                person.push(PatternMatch {
                    text: name.clone(),
                    type_: "person".to_string(),
                    start,
                    end: start + name_chars,
                    confidence: 1.0,
                    layer: LAYER_REGEX,
                });
            }
        }
    }

    // 9. Map person spans (person-detect coords) back to ORIGINAL text, like
    //    layer1. Identity-clone when the person text was not normalized, so the
    //    common path (no folds applied — e.g. `张三 13812345678 …`, which is
    //    digit-free WITHOUT the digit step) is byte-identical to the pre-change
    //    behavior. Uses the PERSON offset map (positions equal the full map, but
    //    keep them paired with the text they describe).
    let person = map_matches_to_original(
        &person,
        text,
        person_offset_map.as_deref(),
        orig_len,
    );

    // 10. Evidence-gated Chinese admin-region detection (only when "zh" is in
    //     lang). Mirrors the person block: run on the SAME person-detect-text
    //     (digit-step-skipped normalization, so a region name that shares a CJK
    //     digit homograph isn't folded away), pass `layer1_raw` as the structural
    //     PII proximity context (same detect-coord convention as the zh person
    //     detector — positions line up with the person-detect-text), tag the
    //     LAYER_REGEX layer like person does, then map the spans back to the
    //     ORIGINAL text exactly like layer1/person. Empty when "zh" is absent.
    let mut regions: Vec<PatternMatch> = Vec::new();
    if has_zh {
        let mut zh_regions = detect_regions_zh(person_detect_text, &layer1_raw);
        tag_layer(&mut zh_regions, LAYER_REGEX);
        regions = zh_regions;
    }
    let regions = map_matches_to_original(
        &regions,
        text,
        person_offset_map.as_deref(),
        orig_len,
    );

    // 11. Evidence-gated Chinese occupation detection (only when "zh" is in
    //     lang). Mirrors the region block: run on the SAME person-detect-text,
    //     pass `layer1_raw` as the structural PII proximity context (same
    //     detect-coord convention as the zh person/region detectors), tag the
    //     LAYER_REGEX layer, then map the spans back to the ORIGINAL text exactly
    //     like layer1/person/regions. Empty when "zh" is absent.
    let mut job_titles: Vec<PatternMatch> = Vec::new();
    if has_zh {
        let mut zh_jobs = detect_occupation_zh(person_detect_text, &layer1_raw);
        tag_layer(&mut zh_jobs, LAYER_REGEX);
        job_titles = zh_jobs;
    }
    let job_titles = map_matches_to_original(
        &job_titles,
        text,
        person_offset_map.as_deref(),
        orig_len,
    );

    // 12. Evidence-gated framework detectors (zh only): conditions + hobbies.
    //     Combined into one `framework` vec.
    let mut framework: Vec<PatternMatch> = Vec::new();
    if has_zh {
        framework.extend(crate::conditions::detect_conditions_zh(person_detect_text, &layer1_raw));
        framework.extend(crate::hobbies::detect_hobbies_zh(person_detect_text, &layer1_raw));
        tag_layer(&mut framework, LAYER_REGEX);
    }
    let framework = map_matches_to_original(&framework, text, person_offset_map.as_deref(), orig_len);

    Ok(DetectL1Result {
        layer1,
        person,
        regions,
        job_titles,
        framework,
        hints,
        near_misses,
    })
}

/// Fast-mode end-to-end redaction over L1 (regex + person) only — Rust port of
/// the fast-mode `redact()` post-detect path in `glue/redact.py`
/// (`_detect` lines ~329-343 + `_replace_and_emit`). Produces the SAME
/// `(redacted, key, aliases, keep_downgraded)` as the Python `redact(mode="fast")`.
///
/// The post-detect order mirrors Python EXACTLY:
///
/// 1. `detect_l1(text, lang, names)` → the RAW L1 entities (`layer1 ++ person`).
/// 2. `merge_entities(entities, text)` — priority-aware (see
///    [`merge_entities_with_text`]).
/// 3. **`boost_cross_layer` is a NO-OP in fast mode** and is SKIPPED. Python
///    runs it (`hints.boost_cross_layer(merged, pre_merge)`), but it returns
///    `merged` unchanged whenever fewer than 2 distinct layers are present in
///    `pre_merge` — and fast mode emits ONLY layer 1 (regex + person), so there
///    is exactly one layer. Skipping it is byte-identical. (The `ARGUS_ABLATION_NO_BOOST`
///    env var only ever toggles the same no-op here, so it is irrelevant too.)
/// 4. `filter_self_reference(merged, &d.hints)`.
/// 5. **Type filter** (matching `redact.py:337-343`): if `types` is given, keep
///    only entities whose type is in `types`; ELSE if `types_exclude` is given,
///    drop entities whose type is in `types_exclude`. `types` wins (Python
///    `if ... elif ...`); the caller is responsible for rejecting the both-set
///    combination, exactly as `redact()` does up front.
/// 6. `replace(...)` — value-passing the SAME `type_info` / prefixes / whitelist
///    / factories the Python `_build_type_info` resolves and threads through
///    `_core.replace` (the T7 binding adapts the Python factories to these
///    trait objects).
/// 7. **Grammar normalize** (mirror `_replace_and_emit`): if the effective lang
///    is `"en"`, run `normalize_grammar_en(redacted, key.values())`. This is a
///    SEPARATE step here AND in Python — `replace()` does NOT call grammar
///    internally (confirmed: `replace.rs` has no grammar reference), so there is
///    no double-application. `effective_lang` mirrors Python:
///    `lang[0] if lang else "zh"`.
///
/// The `key` threads through `replace` for collision continuity (the input
/// `key` is merged in, the result key is returned), matching `_replace_and_emit`.
/// `keep_downgraded` is surfaced on the result so the caller can raise the
/// `SecurityWarning` (the Python shim does, T7).
///
/// Data inputs to [`redact_l1`], grouped to keep the signature readable — mirrors
/// the sibling [`ReplaceArgs`] idiom (the two `factory` params stay trailing on
/// `redact_l1` itself, matching [`replace`]).
pub struct RedactL1Args<'a> {
    /// The source text.
    pub text: &'a str,
    /// Resolved language list (e.g. `["zh"]`, `["zh","en"]`).
    pub lang: &'a [String],
    /// Known-names list for person detection / names-only fallback.
    pub names: &'a [String],
    /// Per-type resolved info, keyed by entity type (Python `_build_type_info`).
    pub type_info: &'a std::collections::HashMap<String, TypeInfo>,
    /// Effective salt (drives pseudonym seed + realistic HMAC).
    pub salt: Option<&'a crate::seed::Salt>,
    /// Existing key to merge into (reuse + collision avoidance).
    pub key: Option<&'a std::collections::HashMap<String, String>>,
    /// Person pseudonym prefix.
    pub person_prefix: &'a str,
    /// Organization pseudonym prefix.
    pub org_prefix: &'a str,
    /// Unified-prefix mode: all reversible types collapse to one prefix.
    pub unified_prefix: Option<&'a str>,
    /// Keep-strategy whitelist (`SELF_REF_PRONOUNS` ∪ zh pronouns ∪ zh kinship).
    pub keep_whitelist: &'a HashSet<String>,
    /// Type allow-list: if set, keep only entities whose type is in it.
    pub types: Option<&'a HashSet<String>>,
    /// Type deny-list: if set (and `types` is not), drop entities whose type is
    /// in it. `types` wins (Python `if ... elif ...`); the caller guards against
    /// both being set.
    pub types_exclude: Option<&'a HashSet<String>>,
}

pub fn redact_l1<F: PseudoFactory>(
    args: RedactL1Args,
    factory: &F,
    faker_factory: Option<&dyn FakerFactory>,
) -> Result<ReplaceResult, String> {
    let RedactL1Args {
        text,
        lang,
        names,
        type_info,
        salt,
        key,
        person_prefix,
        org_prefix,
        unified_prefix,
        keep_whitelist,
        types,
        types_exclude,
    } = args;

    // 1. Raw L1 detection (layer1 ++ person) + hints. Destructure to MOVE the
    //    entity vecs (no clone — this bundled fast path discards `d` afterward).
    let DetectL1Result { layer1, person, regions, job_titles, framework, hints, .. } =
        detect_l1(text, lang, names).map_err(|e| e.to_string())?;
    let mut entities = layer1;
    entities.extend(person);
    entities.extend(regions);
    entities.extend(job_titles);
    entities.extend(framework);

    // 2. Priority-aware merge over the ORIGINAL text.
    let merged = merge_entities_with_text(entities, text);

    // 3. boost_cross_layer: NO-OP in fast mode (single layer) — skipped.

    // 4. Self-reference tier filter.
    let filtered = filter_self_reference(merged, &hints);

    // 5. Type filter (redact.py:337-343): types wins over types_exclude.
    let filtered: Vec<PatternMatch> = if let Some(keep) = types {
        filtered.into_iter().filter(|e| keep.contains(&e.type_)).collect()
    } else if let Some(drop) = types_exclude {
        filtered.into_iter().filter(|e| !drop.contains(&e.type_)).collect()
    } else {
        filtered
    };

    // 6. Replace. Both detect (above) and replace surface their error as a
    //    `String`, so the binding (T7) re-wraps a single error type into a
    //    Python exception.
    let result = replace(
        ReplaceArgs {
            text,
            entities: &filtered,
            salt,
            key,
            type_info,
            person_prefix,
            org_prefix,
            unified_prefix,
            keep_whitelist,
        },
        factory,
        faker_factory,
    )?;

    // 7. Grammar normalize (en only) — a SEPARATE step (replace() never calls it).
    let effective_lang: &str = lang.first().map(String::as_str).unwrap_or("zh");
    if effective_lang == "en" {
        // normalize_grammar_en checks key VALUES (original strings), mirroring
        // Python `normalize_grammar_en(redacted, result_key)` →
        // `_core.normalize_grammar_en(text, list(key.values()))`. The Rust core
        // `result.key` is {replacement: original}, so `.values()` are the
        // originals — exactly what grammar checks for self-ref pronouns.
        let originals: Vec<String> = result.key.values().cloned().collect();
        let normalized = normalize_grammar_en(&result.redacted, &originals);
        return Ok(ReplaceResult {
            redacted: normalized,
            key: result.key,
            aliases: result.aliases,
            keep_downgraded: result.keep_downgraded,
        });
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn en_load_includes_language_neutral_cn_numeric() {
        // CN structured numeric identifiers must be detectable even when only en
        // is requested — their digits are script-independent. The CN mobile
        // pattern lives in zh data but is flagged language_neutral.
        let configs = load_patterns(&["en".to_string()]);
        assert!(
            configs
                .iter()
                .any(|c| c.type_ == "phone" && c.pattern.contains("1[3-9]")),
            "en pattern load must include the language-neutral CN mobile pattern"
        );
    }

    #[test]
    fn zh_load_does_not_duplicate_language_neutral_patterns() {
        // When zh IS requested, the neutral patterns load via the normal zh pass;
        // the always-load step must not add a second copy.
        let configs = load_patterns(&["zh".to_string()]);
        let cn_mobile = configs
            .iter()
            .filter(|c| c.type_ == "phone" && c.pattern.contains("1[3-9]"))
            .count();
        assert_eq!(cn_mobile, 1, "CN mobile must appear exactly once for zh");
    }

    #[test]
    fn non_en_zh_langs_load_the_card_pattern() {
        // A PAN is the same digits in any script. ja/ko (and de/uk/in/br) ship no
        // card pattern of their own, so the neutral en `credit_card` must reach
        // them — otherwise a full card number passes through kana/hangul text.
        for lang in ["ja", "ko", "de", "uk", "in", "br"] {
            let configs = load_patterns(&[lang.to_string()]);
            assert_eq!(
                configs
                    .iter()
                    .filter(|c| c.type_ == "credit_card")
                    .count(),
                1,
                "{lang} must load exactly one card pattern"
            );
        }
    }

    #[test]
    fn zh_load_also_receives_the_neutral_card_pattern() {
        // zh ships its own `bank_card` AND receives the neutral en `credit_card`:
        // the two match the same PAN digits, the overlap merge collapses them to one
        // entity, and the loser's spurious near-miss is suppressed at the hint layer.
        // No denylist keeps the neutral pattern out.
        let configs = load_patterns(&["zh".to_string()]);
        assert!(configs.iter().any(|c| c.type_ == "bank_card"));
        assert!(configs.iter().any(|c| c.type_ == "credit_card"));
    }

    #[test]
    fn zh_plus_en_load_keeps_one_card_pattern_each() {
        // Requesting en alongside zh loads en's patterns natively rather than through
        // the neutral cross-load — still exactly one pattern of each type, no dupes.
        let configs = load_patterns(&["zh".to_string(), "en".to_string()]);
        assert_eq!(configs.iter().filter(|c| c.type_ == "credit_card").count(), 1);
        assert_eq!(configs.iter().filter(|c| c.type_ == "bank_card").count(), 1);
    }

    // ── Golden fixtures captured from LIVE Python ─────────────────────────────
    //
    // Each fixture is the RAW (pre-merge) `_detect` fast-mode output: the
    // entity list (layer1 ++ person, in that order) + the L1 hint summary +
    // near-misses. Captured by replaying redact.py::_detect lines ~199-264 (L1
    // portion; L2/L3 skipped in fast mode) against the live compiled core. See
    // the task notes — the values below ARE the live-Python output.

    /// (text, type, start, end, confidence, layer)
    type Ent = (&'static str, &'static str, usize, usize, f64, u8);
    /// text_intent intent, optional (tier, has_kinship)
    type HintSummary = (&'static str, Option<(u8, bool)>);

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn run(text: &str, lang: &[&str], names: &[&str]) -> DetectL1Result {
        detect_l1(text, &s(lang), &s(names)).unwrap()
    }

    fn assert_entities(got: &[PatternMatch], expected: &[Ent]) {
        let got_v: Vec<(String, String, usize, usize, f64, u8)> = got
            .iter()
            .map(|e| {
                (
                    e.text.clone(),
                    e.type_.clone(),
                    e.start,
                    e.end,
                    e.confidence,
                    e.layer,
                )
            })
            .collect();
        let exp_v: Vec<(String, String, usize, usize, f64, u8)> = expected
            .iter()
            .map(|&(t, ty, st, en, c, l)| (t.to_string(), ty.to_string(), st, en, c, l))
            .collect();
        assert_eq!(got_v, exp_v);
    }

    /// Compare the produced L1 hints against a captured summary:
    /// each expected entry is (text_intent, Option<(tier, has_kinship)>), in
    /// Python's emit order (self_reference_tier — when present — then text_intent).
    fn assert_hints(got: &[Hint], expected: &[HintSummary]) {
        use crate::hints::HintKind;
        // Reduce to the same shape Python's summary used: a flat tier (opt) + intent.
        let mut intent: Option<String> = None;
        let mut tier: Option<(u8, bool)> = None;
        for h in got {
            match &h.kind {
                HintKind::TextIntent { intent: i } => intent = Some(i.clone()),
                HintKind::SelfReferenceTier { tier: t, has_kinship: k } => {
                    tier = Some((*t, *k))
                }
                HintKind::PiiDensity { .. } | HintKind::NearMissFormat { .. } => {}
            }
        }
        // expected always has exactly one text_intent entry (last); a tier entry
        // may precede it. Fold expected the same way.
        let mut exp_intent: Option<String> = None;
        let mut exp_tier: Option<(u8, bool)> = None;
        for &(ti, tr) in expected {
            exp_intent = Some(ti.to_string());
            if let Some(t) = tr {
                exp_tier = Some(t);
            }
        }
        assert_eq!(intent, exp_intent, "text_intent mismatch");
        assert_eq!(tier, exp_tier, "self_reference_tier mismatch");
    }

    fn assert_near_misses(got: &[PatternMatch], expected: &[(&str, &str, usize, usize)]) {
        let got_v: Vec<(String, String, usize, usize)> = got
            .iter()
            .map(|e| (e.text.clone(), e.type_.clone(), e.start, e.end))
            .collect();
        let exp_v: Vec<(String, String, usize, usize)> = expected
            .iter()
            .map(|&(t, ty, st, en)| (t.to_string(), ty.to_string(), st, en))
            .collect();
        assert_eq!(got_v, exp_v);
    }

    #[test]
    fn zh_phone_id_with_normalize_and_near_misses() {
        // normalize_text changes the text (CN punctuation/digits) → map-span path.
        // id_number/credit_code fail validation → near-misses.
        let r = run("我叫张伟，电话13800138000，身份证110101199003078888。", &["zh"], &[]);
        assert_entities(
            &r.layer1_and_person(),
            &[
                ("我", "self_reference", 0, 1, 1.0, 1),
                ("13800138000", "phone", 7, 18, 1.0, 1),
                ("张伟", "person", 2, 4, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("self_reference_tier (tier=1)", Some((1, false))), ("narrative", None)]);
        assert_near_misses(
            &r.near_misses,
            &[
                ("110101199003078888", "id_number", 22, 40),
                ("110101199003078888", "credit_code", 22, 40),
            ],
        );
    }

    #[test]
    fn en_names_neutral() {
        let r = run("Contact John Smith or Mary Johnson at the office.", &["en"], &[]);
        assert_entities(
            &r.layer1_and_person(),
            &[
                ("John Smith", "person", 8, 18, 1.0, 1),
                ("Mary Johnson", "person", 22, 34, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("neutral", None)]);
        assert!(r.near_misses.is_empty());
    }

    #[test]
    fn en_known_name_exact() {
        let r = run("Reach out to Zaphod about the project.", &["en"], &["Zaphod"]);
        assert_entities(&r.layer1_and_person(), &[("Zaphod", "person", 13, 19, 1.0, 1)]);
        assert_hints(&r.hints, &[("neutral", None)]);
    }

    #[test]
    fn instruction_suppresses_threshold_tier3() {
        // "Please tell me" → instruction → person_threshold 1.2, but en ignores
        // threshold (surname-list match) so Michael Brown still appears.
        let r = run("Please tell me about Michael Brown's account.", &["en"], &[]);
        assert_entities(
            &r.layer1_and_person(),
            &[
                ("me", "self_reference", 12, 14, 1.0, 1),
                ("Michael Brown", "person", 21, 34, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("self_reference_tier (tier=3)", Some((3, false))), ("instruction", None)]);
    }

    #[test]
    fn kinship_selfref_zh_tier1() {
        let r = run("我妈的电话是13912345678", &["zh"], &[]);
        assert_entities(
            &r.layer1_and_person(),
            &[
                ("我妈", "self_reference", 0, 2, 1.0, 1),
                ("我", "self_reference", 0, 1, 1.0, 1),
                ("13912345678", "phone", 6, 17, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("self_reference_tier (tier=1,kin)", Some((1, true))), ("narrative", None)]);
    }

    #[test]
    fn emoji_multibyte_offsets() {
        // 😀 is a 2-char-wide-in-UTF16 / 4-byte char; offsets are CHAR positions.
        let r = run("联系王芳😀电话13700137000谢谢", &["zh"], &[]);
        assert_entities(
            &r.layer1_and_person(),
            &[
                ("13700137000", "phone", 7, 18, 1.0, 1),
                ("王芳", "person", 2, 4, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("narrative", None)]);
    }

    #[test]
    fn org_school_jwt_validators() {
        let r = run(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U email a@b.com",
            &["en"],
            &[],
        );
        assert_entities(
            &r.layer1_and_person(),
            &[
                (
                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                    "jwt",
                    0,
                    108,
                    1.0,
                    1,
                ),
                ("a@b.com", "email", 115, 122, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("narrative", None)]);
    }

    #[test]
    fn normalize_cn_digit_maps_back_to_original_text() {
        // detect_text becomes "...13800138000..." but the entity text is the
        // ORIGINAL "一三八零零一三八零零零" (map-span rebuilds text[s..e]).
        let r = run("电话一三八零零一三八零零零是我的号码", &["zh"], &[]);
        assert_entities(
            &r.layer1_and_person(),
            &[
                ("一三八零零一三八零零零", "phone", 2, 13, 1.0, 1),
                ("我的", "self_reference", 14, 16, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("self_reference_tier (tier=1)", Some((1, false))), ("narrative", None)]);
    }

    #[test]
    fn zh_en_combined_order_zh_then_en() {
        // Both detectors run; person order is zh (张伟) then en (John Smith).
        let r = run("张伟 and John Smith met, phone 13800138000", &["zh", "en"], &[]);
        assert_entities(
            &r.layer1_and_person(),
            &[
                ("13800138000", "phone", 29, 40, 1.0, 1),
                ("张伟", "person", 0, 2, 0.8, 1),
                ("John Smith", "person", 7, 17, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("narrative", None)]);
    }

    #[test]
    fn fullwidth_phone_nfkc_normalize() {
        // Fullwidth digits NFKC-fold in detect_text; entity text is the ORIGINAL
        // fullwidth run mapped back.
        let r = run("电话：１３８００１３８０００ 联系我", &["zh"], &[]);
        assert_entities(
            &r.layer1_and_person(),
            &[
                ("１３８００１３８０００", "phone", 3, 14, 1.0, 1),
                ("我", "self_reference", 17, 18, 1.0, 1),
            ],
        );
        assert_hints(&r.hints, &[("self_reference_tier (tier=1)", Some((1, false))), ("narrative", None)]);
    }

    // ── Names-only fallback (redact.py:268-283) ──────────────────────────────
    //
    // When NEITHER "zh" NOR "en" is in lang AND names is non-empty, the zh/en
    // person detectors never run and Python falls back to a literal scan of each
    // known name over the ORIGINAL text. Expected values below were captured from
    // LIVE Python `_detect(..., mode="fast")`:
    //   python3 -c "
    //   from argus_redact.glue.redact import _detect
    //   ents,_,_,_ = _detect('TEXT', lang=['ja'], mode='fast', names=[...],
    //                        types=None, types_exclude=None)
    //   print([(e.text,e.type,e.start,e.end,e.confidence,e.layer) for e in ents])
    //   "

    #[test]
    fn names_only_fallback_differential() {
        // The reviewer's differential case: lang=["ja"] (neither zh nor en), so
        // the fallback fires for each known name. Python _detect output:
        //   [('Zaphod','person',8,14,1.0,1), ('Trillian','person',19,27,1.0,1)]
        let r = run("Talk to Zaphod and Trillian please", &["ja"], &["Zaphod", "Trillian"]);
        assert_entities(
            &r.layer1_and_person(),
            &[
                ("Zaphod", "person", 8, 14, 1.0, 1),
                ("Trillian", "person", 19, 27, 1.0, 1),
            ],
        );
    }

    #[test]
    fn names_only_fallback_duplicate_occurrences() {
        // A name appearing twice → two non-overlapping matches. Python:
        //   [('Zaphod','person',0,6,1.0,1), ('Zaphod','person',11,17,1.0,1)]
        let r = run("Zaphod met Zaphod again", &["ja"], &["Zaphod"]);
        assert_entities(
            &r.layer1_and_person(),
            &[
                ("Zaphod", "person", 0, 6, 1.0, 1),
                ("Zaphod", "person", 11, 17, 1.0, 1),
            ],
        );
    }

    #[test]
    fn names_only_fallback_empty_name_skipped() {
        // An empty name in the list is skipped (Python `if not name: continue`):
        // no match, no panic. Python: [('Zaphod','person',0,6,1.0,1)]
        let r = run("Zaphod is here", &["ja"], &["", "Zaphod"]);
        assert_entities(&r.layer1_and_person(), &[("Zaphod", "person", 0, 6, 1.0, 1)]);
    }

    #[test]
    fn names_only_fallback_regex_special_char_literal() {
        // A name with a regex-special char ("A.") is matched LITERALLY (re.escape),
        // so it matches "A." and NOT "Ax" in "AxB". Python:
        //   [('A.','person',0,2,1.0,1)]
        let r = run("A. and AxB present", &["ja"], &["A."]);
        assert_entities(&r.layer1_and_person(), &[("A.", "person", 0, 2, 1.0, 1)]);
    }

    #[test]
    fn names_only_fallback_not_fired_for_zh() {
        // When "zh" is in lang the zh person branch handles names; the fallback is
        // suppressed. The known name is still detected (via the zh branch) at the
        // SAME (text, span, conf, layer), so the entity output is identical — what
        // matters is the fallback condition (`!has_zh && !has_en`) excludes this.
        // Python _detect(lang=["zh"]): [('Zaphod','person',0,6,1.0,1)]
        let r = run("Zaphod here", &["zh"], &["Zaphod"]);
        assert_entities(&r.layer1_and_person(), &[("Zaphod", "person", 0, 6, 1.0, 1)]);
    }

    #[test]
    fn names_only_fallback_not_fired_for_en() {
        // When "en" is in lang the en person branch handles names; the fallback is
        // suppressed. Python _detect(lang=["en"]): [('Zaphod','person',0,6,1.0,1)]
        let r = run("Zaphod here", &["en"], &["Zaphod"]);
        assert_entities(&r.layer1_and_person(), &[("Zaphod", "person", 0, 6, 1.0, 1)]);
    }

    // ── Mutation-kill guard: the oversize input boundary (detect_l1 L178) ─────
    //
    // `if text.len() > MAX_INPUT_SIZE { Err }`. A text of EXACTLY MAX_INPUT_SIZE
    // bytes must SUCCEED (the guard is strict `>`). This single boundary kills
    // both surviving mutants:
    //   - `>` → `>=`: would reject an exactly-MAX text → Err (off-by-one).
    //   - `>` → `==`: would reject an exactly-MAX text → Err (only `==` fires).
    // (A MAX+1 text errors under HEAD AND both mutants — `match_patterns` has its
    // own `> MAX` guard downstream — so the over-limit side cannot distinguish
    // them; the exactly-MAX side is the discriminating case.)
    #[test]
    fn input_at_exact_max_size_succeeds() {
        // 1 MiB of ASCII (bytes == chars), no PII, no normalization needed.
        let text = "a".repeat(crate::MAX_INPUT_SIZE);
        assert_eq!(text.len(), crate::MAX_INPUT_SIZE);
        let r = detect_l1(&text, &s(&["en"]), &[]);
        assert!(r.is_ok(), "exactly-MAX_INPUT_SIZE input must not be rejected");
    }

    #[test]
    fn input_over_max_size_errors() {
        // MAX+1 bytes is rejected (documents the over-limit side of the guard;
        // does not by itself distinguish the `==`/`>=` mutants — see above).
        let text = "a".repeat(crate::MAX_INPUT_SIZE + 1);
        assert!(detect_l1(&text, &s(&["en"]), &[]).is_err());
    }
}

#[cfg(test)]
mod redact_l1_tests {
    //! End-to-end `redact_l1` golden checks — locked against the T1 fixture
    //! `tests/core/fixtures/redact_l1_v077.json`, frozen from LIVE Python at
    //! `SALT=42`.
    //!
    //! ## Why a SUBSET of the T1 corpus
    //!
    //! The pseudonym strategies (`pseudonym`, and `remove`'s pseudonym fallback)
    //! mint `<PREFIX>-NNNNN` codes from Python's `random.Random(seed)`
    //! Mersenne-Twister stream — reproducible ONLY through the PyO3
    //! `PyPseudoFactory` (a Python-backed `RandomSource`). The CORE crate has no
    //! PyO3, so a pure-Rust test can't reproduce those codes; cases that emit
    //! them (`zh_default`'s `P-83811`, `intent_instruction_en`'s `P-83811`,
    //! `jwt_valid`'s `JWT-21680`, …) are covered by the T8 end-to-end golden
    //! through Python instead.
    //!
    //! Everything that does NOT touch the MT stream IS reproducible here and is
    //! asserted byte-for-byte against the frozen `(redacted, key)`:
    //!   - `mask` / `name_mask` / `category` (deterministic, no RNG),
    //!   - `keep` (whitelisted identity),
    //!   - empty-entity cases (instruction-suppressed / neutral / near-miss),
    //!   - `realistic` with a BUILT-IN faker (the faker stream is `ShakeRng`,
    //!     which lives in core — fully reproducible).
    //!
    //! `type_info` for each case is hardcoded from what the Python
    //! `_build_type_info` produces (captured via
    //! `python -c "from argus_redact.pure.replacer import _build_type_info; ..."`).
    //! The `keep_whitelist` for the kinship case carries `"我妈"` (a member of
    //! `_KEEP_WHITELIST` = `SELF_REF_PRONOUNS | _ZH_PRONOUNS | _ZH_KINSHIP`).

    use super::*;
    use crate::pseudonym::RandomSource;
    use crate::replace::FakerResolution;
    use crate::seed::Salt;
    use std::collections::HashMap;

    const SALT: i64 = 42; // matches the T1 fixture freeze.

    /// A `PseudoFactory` that must NEVER be exercised by these cases (none use a
    /// pseudonym / remove-fallback strategy). It panics on use so a regression
    /// that routes a code through the MT path is caught loudly rather than
    /// silently producing a wrong (un-frozen) value.
    struct UnusedFactory;
    struct PanicRng;
    impl RandomSource for PanicRng {
        fn randint(&mut self, _lo: u32, _hi: u32) -> u32 {
            panic!("pseudonym RNG must not be reached in the reproducible subset")
        }
        fn randbelow(&mut self, _range: u32) -> u32 {
            panic!("pseudonym RNG must not be reached in the reproducible subset")
        }
        fn use_secrets(&self) -> bool {
            false
        }
    }
    impl PseudoFactory for UnusedFactory {
        type Source = PanicRng;
        fn make(&self, _seed: Option<u64>) -> PanicRng {
            PanicRng
        }
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// Build one `TypeInfo` mirroring the Python `_build_type_info` dict shape.
    #[allow(clippy::too_many_arguments)]
    fn ti(
        strategy: &str,
        default_strategy: &str,
        prefix: &str,
        faker_name: Option<&str>,
        replacement: Option<&str>,
        label: Option<&str>,
        default_category_label: &str,
    ) -> TypeInfo {
        TypeInfo {
            strategy: strategy.to_string(),
            default_strategy: default_strategy.to_string(),
            prefix: prefix.to_string(),
            prefix_overridden: false,
            faker_resolution: match faker_name {
                Some(n) => FakerResolution::Builtin(n.to_string()),
                None => FakerResolution::None,
            },
            replacement: replacement.map(str::to_string),
            label: label.map(str::to_string),
            default_category_label: default_category_label.to_string(),
            visible_prefix: 0,
            visible_suffix: 0,
        }
    }

    /// Run `redact_l1` and return `(redacted, sorted key entries)` to compare
    /// against the fixture (whose key is stored sorted).
    fn run(
        text: &str,
        lang: &[&str],
        names: &[&str],
        type_info: HashMap<String, TypeInfo>,
        keep_whitelist: &[&str],
    ) -> (String, Vec<(String, String)>) {
        let wl: HashSet<String> = keep_whitelist.iter().map(|x| x.to_string()).collect();
        let lang_v = s(lang);
        let names_v = s(names);
        let r = redact_l1(
            RedactL1Args {
                text,
                lang: &lang_v,
                names: &names_v,
                type_info: &type_info,
                salt: Some(&Salt::Int(SALT)),
                key: None,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
                types: None,
                types_exclude: None,
            },
            &UnusedFactory,
            None,
        )
        .unwrap();
        let mut key: Vec<(String, String)> =
            r.key.into_iter().collect();
        key.sort();
        (r.redacted, key)
    }

    fn kv(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> =
            pairs.iter().map(|(k, val)| (k.to_string(), val.to_string())).collect();
        v.sort();
        v
    }

    // ── zh_mask: mask strategy on phone + bank_card (no pseudonym) ───────────
    #[test]
    fn golden_zh_mask() {
        let mut info = HashMap::new();
        info.insert("phone".into(), ti("mask", "mask", "PHON", None, None, None, "[phone]"));
        info.insert("bank_card".into(), ti("mask", "mask", "BANK", None, None, None, "[bank_card]"));
        let (redacted, key) =
            run("电话13812345678 银行卡6217000000000000", &["zh"], &[], info, &[]);
        assert_eq!(redacted, "电话138****5678 银行卡621700******0000");
        assert_eq!(
            key,
            kv(&[("138****5678", "13812345678"), ("621700******0000", "6217000000000000")])
        );
    }

    // ── zh_keep: kinship self_reference kept (tier 1) + phone mask ───────────
    #[test]
    fn golden_zh_keep_kinship() {
        let mut info = HashMap::new();
        // self_reference is "keep" (registry default keep); whitelisted "我妈"
        // survives, so it is NOT added to the key (Python continues past the
        // key-insert). phone masks.
        info.insert(
            "self_reference".into(),
            ti("keep", "keep", "S", None, None, None, "[self_reference]"),
        );
        info.insert("phone".into(), ti("mask", "mask", "PHON", None, None, None, "[phone]"));
        let (redacted, key) = run("我妈说她13812345678", &["zh"], &[], info, &["我妈"]);
        assert_eq!(redacted, "我妈说她138****5678");
        assert_eq!(key, kv(&[("138****5678", "13812345678")]));
    }

    // ── intent_instruction_zh: instruction suppresses the only self-ref →
    //    empty entities → text unchanged, empty key. ───────────────────────────
    #[test]
    fn golden_intent_instruction_zh_empty() {
        // No entities survive the tier filter (instruction tier 3 drops the
        // pronoun self-ref, no other PII). type_info is empty, like Python.
        let (redacted, key) =
            run("帮我查一下张三的电话号码", &["zh"], &[], HashMap::new(), &[]);
        assert_eq!(redacted, "帮我查一下张三的电话号码");
        assert!(key.is_empty());
    }

    // ── zh_category: address → category label ────────────────────────────────
    #[test]
    fn golden_zh_category() {
        let mut info = HashMap::new();
        info.insert(
            "address".into(),
            ti("category", "remove", "ADDR", None, None, None, "[address]"),
        );
        let (redacted, key) = run("北京市朝阳区三里屯", &["zh"], &[], info, &[]);
        assert_eq!(redacted, "[address]屯");
        assert_eq!(key, kv(&[("[address]", "北京市朝阳区三里")]));
    }

    // ── zh_name_mask: known_names + name_mask ────────────────────────────────
    #[test]
    fn golden_zh_name_mask() {
        let mut info = HashMap::new();
        info.insert(
            "person".into(),
            ti("name_mask", "pseudonym", "P", None, None, None, "[person]"),
        );
        let (redacted, key) =
            run("张三和欧阳明", &["zh"], &["张三", "欧阳明"], info, &[]);
        assert_eq!(redacted, "张*和欧**");
        assert_eq!(key, kv(&[("张*", "张三"), ("欧**", "欧阳明")]));
    }

    // ── zh_realistic: realistic with BUILT-IN fakers (ShakeRng — pure core).
    //    Reproduces the frozen faker outputs at SALT=42. ──────────────────────
    #[test]
    fn golden_zh_realistic() {
        let mut info = HashMap::new();
        info.insert(
            "person".into(),
            ti("realistic", "pseudonym", "P", Some("fake_person_reserved"), None, None, "[person]"),
        );
        info.insert(
            "phone".into(),
            ti("realistic", "mask", "PHON", Some("fake_phone_reserved"), None, None, "[phone]"),
        );
        info.insert(
            "id_number".into(),
            ti("realistic", "remove", "ID", Some("fake_id_number_reserved"), None, None, "[id_number]"),
        );
        let (redacted, key) = run(
            "张三的电话13812345678，身份证110101199003074610",
            &["zh"],
            &[],
            info,
            &[],
        );
        assert_eq!(redacted, "卷帘的电话19999892122，身份证999837198308135463");
        assert_eq!(
            key,
            kv(&[
                ("19999892122", "13812345678"),
                ("999837198308135463", "110101199003074610"),
                ("卷帘", "张三"),
            ])
        );
    }

    // ── en_realistic: en lang (exercises grammar-normalize gate) + realistic
    //    built-in fakers. No first-person pronoun in the key, so grammar is a
    //    no-op — but the lang=="en" branch IS taken, proving the wiring. ───────
    #[test]
    fn golden_en_realistic() {
        let mut info = HashMap::new();
        info.insert(
            "person".into(),
            ti("realistic", "pseudonym", "P", Some("fake_person_en_reserved"), None, None, "[person]"),
        );
        info.insert(
            "ssn".into(),
            ti("realistic", "remove", "SSN", Some("fake_ssn_en_reserved"), None, None, "[ssn]"),
        );
        info.insert(
            "credit_card".into(),
            ti("realistic", "mask", "CRED", Some("fake_credit_card_en_reserved"), None, None, "[credit_card]"),
        );
        let (redacted, key) = run(
            "John Smith SSN 123-45-6789 card 4111111111111111",
            &["en"],
            &[],
            info,
            &[],
        );
        assert_eq!(redacted, "Richard Roe SSN 999-47-9373 card 9999996421710008");
        assert_eq!(
            key,
            kv(&[
                ("999-47-9373", "123-45-6789"),
                ("9999996421710008", "4111111111111111"),
                ("Richard Roe", "John Smith"),
            ])
        );
    }

    // ── type-filter placement (redact.py:337-343): `types` keeps only listed
    //    types AFTER filter_self_reference. Drops the phone, keeps the masked
    //    bank_card. ──────────────────────────────────────────────────────────
    #[test]
    fn type_filter_keep_only_listed() {
        let mut info = HashMap::new();
        info.insert("phone".into(), ti("mask", "mask", "PHON", None, None, None, "[phone]"));
        info.insert("bank_card".into(), ti("mask", "mask", "BANK", None, None, None, "[bank_card]"));
        let wl: HashSet<String> = HashSet::new();
        let keep: HashSet<String> = ["bank_card"].iter().map(|x| x.to_string()).collect();
        let lang_v = s(&["zh"]);
        let r = redact_l1(
            RedactL1Args {
                text: "电话13812345678 银行卡6217000000000000",
                lang: &lang_v,
                names: &[],
                type_info: &info,
                salt: Some(&Salt::Int(SALT)),
                key: None,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
                types: Some(&keep),
                types_exclude: None,
            },
            &UnusedFactory,
            None,
        )
        .unwrap();
        // phone left intact, only bank_card masked.
        assert_eq!(r.redacted, "电话13812345678 银行卡621700******0000");
        assert_eq!(r.key.get("621700******0000"), Some(&"6217000000000000".to_string()));
        assert!(!r.key.values().any(|v| v == "13812345678"));
    }

    // ── Mutation-kill guard: the en grammar-normalize gate (redact_l1 L501) ──
    //
    // `if effective_lang == "en" { normalize_grammar_en(...) }`. The forward
    // grammar rule rewrites a pseudonym code followed by a first-person verb to
    // the third-person form (`P-7 am` → `P-7 is`), but ONLY when a key VALUE is a
    // self-ref pronoun. We arm both preconditions with the deterministic `remove`
    // strategy (fixed `replacement`, no RNG):
    //   - "John Smith" (person) → "P-7" (a `[A-Z]+-\d+` code),
    //   - "I" (self_reference)  → "X" (so "I" lands in `key.values()`, arming the
    //     grammar pass).
    // A phone (layer1 PII) is added so the self_reference tier is 1 (kept by
    // `filter_self_reference`; tier 2 would DROP the lone pronoun and leave "I"
    // un-redacted, disarming the grammar). The phone masks (no RNG, no code that
    // could disturb the verb rule). Text replaces to "P-7 am X, …"; the en gate
    // then rewrites it to "P-7 is X, …". Mutating `==` to `!=` SKIPS grammar for
    // en, leaving the un-normalized "P-7 am X, …" — an observable difference.
    #[test]
    fn en_grammar_normalize_gate_fires() {
        let mut info = HashMap::new();
        info.insert(
            "person".into(),
            ti("remove", "remove", "P", None, Some("P-7"), None, "[person]"),
        );
        info.insert(
            "self_reference".into(),
            ti("remove", "remove", "S", None, Some("X"), None, "[self_reference]"),
        );
        info.insert("phone".into(), ti("mask", "mask", "PHON", None, None, None, "[phone]"));
        let (redacted, _key) = run("John Smith am I, phone 4155551234", &["en"], &[], info, &[]);
        // en gate fires → forward verb rule rewrites "P-7 am" to "P-7 is".
        assert_eq!(redacted, "P-7 is X, phone 415***1234");
    }

    // ── types_exclude drops the listed type (mutually exclusive with `types`,
    //    which the caller guards — matching redact()'s up-front check). ────────
    #[test]
    fn type_filter_exclude_listed() {
        let mut info = HashMap::new();
        info.insert("phone".into(), ti("mask", "mask", "PHON", None, None, None, "[phone]"));
        info.insert("bank_card".into(), ti("mask", "mask", "BANK", None, None, None, "[bank_card]"));
        let wl: HashSet<String> = HashSet::new();
        let drop: HashSet<String> = ["phone"].iter().map(|x| x.to_string()).collect();
        let lang_v = s(&["zh"]);
        let r = redact_l1(
            RedactL1Args {
                text: "电话13812345678 银行卡6217000000000000",
                lang: &lang_v,
                names: &[],
                type_info: &info,
                salt: Some(&Salt::Int(SALT)),
                key: None,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
                types: None,
                types_exclude: Some(&drop),
            },
            &UnusedFactory,
            None,
        )
        .unwrap();
        assert_eq!(r.redacted, "电话13812345678 银行卡621700******0000");
    }
}

#[cfg(test)]
mod person_normalized_offset_tests {
    //! Person detection now runs on the NORMALIZED detect_text and maps the
    //! resulting spans back to the ORIGINAL text (Task 6, v0.7.9 Phase 2). These
    //! tests lock the OFFSET round-trip: a confusable / fullwidth / combining-mark
    //! name is detected after folding, and the emitted entity's `start`/`end`/`text`
    //! address the ORIGINAL substring (so restore recovers the exact obfuscated
    //! bytes). A pure-ASCII name must stay byte-identical to the pre-change path.

    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn run(text: &str, lang: &[&str], names: &[&str]) -> DetectL1Result {
        detect_l1(text, &s(lang), &s(names)).unwrap()
    }

    /// Find the single person entity, asserting there is exactly one.
    fn only_person(r: &DetectL1Result) -> &PatternMatch {
        assert_eq!(r.person.len(), 1, "expected exactly one person entity");
        &r.person[0]
    }

    /// The ORIGINAL char-substring `text[start..end]` — what restore must recover.
    fn orig_slice(text: &str, start: usize, end: usize) -> String {
        text.chars().skip(start).take(end - start).collect()
    }

    #[test]
    fn fullwidth_name_maps_to_original_substring() {
        // Ｊ (U+FF2A, fullwidth J) folds to ASCII 'J' in detect_text → "John Smith"
        // is detected there. The span/text must address the ORIGINAL fullwidth
        // substring so restore puts the exact bytes back.
        let text = "Contact \u{FF2A}ohn Smith today";
        let r = run(text, &["en"], &[]);
        let p = only_person(&r);
        assert_eq!(p.type_, "person");
        assert_eq!(p.layer, LAYER_REGEX);
        assert_eq!((p.start, p.end), (8, 18));
        // The entity text is the ORIGINAL (fullwidth-Ｊ) slice, NOT the folded one.
        assert_eq!(p.text, "\u{FF2A}ohn Smith");
        assert_eq!(p.text, orig_slice(text, p.start, p.end));
        assert!(p.text.contains('\u{FF2A}'), "must keep the original fullwidth J");
    }

    #[test]
    fn combining_mark_name_maps_to_original_substring() {
        // "José" written as Jose + U+0301 (combining acute). The mark is dropped
        // during normalization (so the surname scan sees "Jose Smith"), but it
        // shifts NO original offsets — the base 'e' keeps its source index. The
        // mapped-back span must still cover the original chars INCLUDING the mark.
        let text = "Contact Jos\u{0065}\u{0301} Smith today";
        let r = run(text, &["en"], &[]);
        let p = only_person(&r);
        assert_eq!((p.start, p.end), (8, 19));
        // Original slice still carries the combining mark.
        assert_eq!(p.text, "Jose\u{0301} Smith");
        assert_eq!(p.text, orig_slice(text, p.start, p.end));
        assert!(p.text.contains('\u{0301}'), "must keep the combining mark");
    }

    #[test]
    fn confusable_adjacent_name_maps_to_original_substring() {
        // Ѕ (U+0405, Cyrillic DZE) is a confusable that folds to ASCII 'S', so
        // "John Ѕmith" reads as the surname "Smith" after folding. The span/text
        // map back to the ORIGINAL run that still contains the Cyrillic Ѕ.
        let text = "Email John \u{0405}mith now";
        let r = run(text, &["en"], &[]);
        let p = only_person(&r);
        assert_eq!((p.start, p.end), (6, 16));
        assert_eq!(p.text, "John \u{0405}mith");
        assert_eq!(p.text, orig_slice(text, p.start, p.end));
        assert!(p.text.contains('\u{0405}'), "must keep the original Cyrillic S");
    }

    #[test]
    fn pure_ascii_name_byte_identical_to_pre_change() {
        // A pure-ASCII name does NOT normalize (offset_map is None), so detect_text
        // == text and map_matches_to_original is an identity clone. The entity must
        // be byte-identical to the pre-change behavior: same start/end/text/conf.
        let r = run("Contact John Smith today", &["en"], &[]);
        let p = only_person(&r);
        assert_eq!(p.type_, "person");
        assert_eq!(p.layer, LAYER_REGEX);
        assert_eq!((p.start, p.end), (8, 18));
        assert_eq!(p.text, "John Smith");
        assert_eq!(p.confidence, 1.0);
    }

    #[test]
    fn zh_name_with_fullwidth_digits_elsewhere_maps_back() {
        // Fullwidth digits "１２３" elsewhere force use_normalized = true, so the
        // whole person scan runs on detect_text. The zh name 张三 (no special
        // chars, identity-folds) must map back to the CORRECT original char span —
        // the fullwidth digits ahead of it must not shift its offsets.
        //   chars: １(0) ２(1) ３(2) ' '(3) 客(4) 户(5) 张(6) 三(7) 的(8) 手(9) 机(10)
        let text = "\u{FF11}\u{FF12}\u{FF13} 客户张三的手机";
        let r = run(text, &["zh"], &[]);
        let p = only_person(&r);
        assert_eq!(p.type_, "person");
        assert_eq!((p.start, p.end), (6, 8));
        assert_eq!(p.text, "张三");
        assert_eq!(p.text, orig_slice(text, p.start, p.end));
    }

    #[test]
    fn zh_digit_homograph_name_survives_digit_run() {
        // REGRESSION GUARD: `张三` (三 == the Chinese digit 3) immediately before a
        // long phone digit run. The FULL normalization folds `张三 138…` into the
        // one ≥7-char digit run `张3 138…`, which would hide the name from the
        // surname regex. Person detection uses the digit-step-SKIPPED normalization,
        // so `张三` stays a name and is detected at the correct ORIGINAL span.
        //   chars: 张(0) 三(1) ' '(2) then the phone digits…
        let text = "张三 13812345678 110101199003074610";
        let r = run(text, &["zh"], &[]);
        let p = r
            .person
            .iter()
            .find(|p| p.text == "张三")
            .expect("张三 must still be detected next to a digit run");
        assert_eq!((p.start, p.end), (0, 2));
        assert_eq!(p.text, orig_slice(text, p.start, p.end));
        // The phone is still caught by the regex layer (full-normalization path).
        assert!(r.layer1.iter().any(|e| e.type_ == "phone"));
    }

    #[test]
    fn normalized_known_name_maps_back_to_original() {
        // A known-name supplied with a precomposed accent ("José"): the scan_names
        // entry normalizes to "Jose" and matches the folded detect_text, then maps
        // back to the original "José" substring. Exercises the scan_names
        // normalization + the person map-back together.
        let text = "Email Jos\u{00E9} now";
        let r = run(text, &["en"], &["Jos\u{00E9}"]);
        // The known-name (José) is detected (confidence 1.0) and restores the
        // original precomposed accent.
        let p = r
            .person
            .iter()
            .find(|p| p.start == 6 && p.end == 10)
            .expect("known name José at 6..10");
        assert_eq!(p.text, "Jos\u{00E9}");
        assert_eq!(p.text, orig_slice(text, p.start, p.end));
        assert_eq!(p.confidence, 1.0);
    }
}
