use std::cmp::Ordering;

use crate::hints::py_strip;
use crate::reserved_range::char_slice;
use crate::types::PatternMatch;

/// Sort comparator: ascending `start`, then the LONGER span first on a tie. The
/// single source for the order both `merge_entities_text` and `merge_priority`
/// sort by, so the two dedup passes cannot drift.
fn by_start_then_longer(a: &PatternMatch, b: &PatternMatch) -> Ordering {
    a.start
        .cmp(&b.start)
        .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
}

/// Priority entity types for [`merge_entities_with_text`] — port of
/// `pure/merger._PRIORITY_TYPES`. A `self_reference` entity wins overlaps and
/// splits the loser, so it survives long enough for `filter_self_reference` to
/// decide its fate by tier.
const PRIORITY_TYPES: &[&str] = &["self_reference"];

/// Pick winner between two overlapping matches: longer span wins, then higher confidence.
fn pick_winner(a: &PatternMatch, b: &PatternMatch) -> bool {
    let len_a = a.end - a.start;
    let len_b = b.end - b.start;
    if len_a != len_b {
        return len_a >= len_b;
    }
    a.confidence >= b.confidence
}

/// Deduplicate overlapping entity spans. Longer spans win; same length → higher confidence wins.
///
/// Thin `text`-less wrapper over [`merge_entities_text`] — kept as its own pub fn
/// (rather than a default-arg shim) because it is pub-re-exported from the crate
/// root and consumed as a crates.io-stable primitive; its signature must not grow
/// a `text` parameter. Callers that don't have `text` (or don't need the
/// person-cross-layer trim, which is a no-op without one) use this directly.
pub fn merge_entities(entities: Vec<PatternMatch>) -> Vec<PatternMatch> {
    merge_entities_text(entities, "")
}

/// Same person-type on both sides, different detection layer? `Some(a.layer >
/// b.layer)` says who wins (`true` = `a`, `false` = `b`); `None` means the rule
/// does not apply (same layer, or either side is not `person`) and the caller
/// must fall back to length/confidence. Scoped to `person` ONLY — see the
/// module-level note on why this must never generalize to other types.
fn person_cross_layer_winner(a: &PatternMatch, b: &PatternMatch) -> Option<bool> {
    if a.type_ != "person" || b.type_ != "person" || a.layer == b.layer {
        return None;
    }
    Some(a.layer > b.layer)
}

/// Deduplicate overlapping entity spans, `text`-aware. Same length/confidence
/// resolution as [`merge_entities`], plus one narrow addition: a `person` span on
/// one detection layer overlapping a `person` span on another layer prefers the
/// higher layer (an NER model, layer 2+, over a Layer-1 regex candidate) instead
/// of the longer one. This is deliberately scoped to `person`-vs-`person` across
/// layers — see [`person_cross_layer_winner`] — because "higher layer wins" was
/// tried unscoped and destroyed `address` and `license_plate` recall (those types
/// have no cross-layer alternative: the NER model emits a coarser span, and
/// preferring it flips the entity type and drops the value match entirely). Names
/// are the one type where a higher-layer detector is reliably *more* correct than
/// an over-greedy regex candidate.
///
/// When the higher-layer person wins a partial overlap, the loser is not simply
/// discarded. If the winner starts at or before the loser's start, [`trim_entity`]
/// carves off whatever *tail* of the loser survives past the winner's end, so a
/// fused candidate like "李明明王" (winner "李明明" + a trailing character that was
/// really a second name) keeps that trailing character redacted. If the winner
/// instead starts strictly *inside* the loser, [`keep_prefix`] re-admits the
/// loser's exclusive *head* `[loser.start, winner.start)` (and `trim_entity` still
/// re-admits any exclusive tail past the winner's end), so the staggered partial
/// overlap no longer drops the loser's head into the clear. Every re-admitted
/// fragment keeps the loser's `person` type and its own layer, and the pieces stay
/// pairwise non-overlapping while covering all of `loser ∪ winner` — so the rule is
/// strictly recall-monotone: it never flips the winner or the type and never
/// shrinks coverage.
///
/// This head re-admission is scoped to `person`-vs-`person` cross-layer ONLY (it
/// lives in the person-only `Some(false)` arm, not the heterogeneous `_` fallback).
/// A *generic* head-preserving trim would re-redact benign cross-TYPE false-positive
/// heads that the merge is meant to absorb — e.g. the `于` head of a `person` FP
/// absorbed into an `address` (see the `coverage.rs` "never restores what the merge
/// itself trimmed" invariant) — turning a precision win into an over-redaction.
fn merge_entities_text(entities: Vec<PatternMatch>, text: &str) -> Vec<PatternMatch> {
    if entities.is_empty() {
        return vec![];
    }

    let mut sorted = entities;
    sorted.sort_by(by_start_then_longer);

    let mut merged: Vec<PatternMatch> = vec![sorted[0].clone()];

    for entity in sorted.into_iter().skip(1) {
        let last = merged.last().unwrap();
        // Check overlap: a.start < b.end && b.start < a.end
        if last.start < entity.end && entity.start < last.end {
            // The person-cross-layer rule needs `text` for its remainder trim: an
            // empty `text` makes `trim_entity` slice an empty string, `py_strip`
            // it to empty, and return `None` — which would silently DROP the tail
            // that should have been redacted. So only consult the rule when there
            // is real text to trim against; with no text, fall through to the
            // length/confidence path = the pre-existing (leak-free) behavior.
            let cross = if text.is_empty() {
                None
            } else {
                person_cross_layer_winner(last, &entity)
            };
            match cross {
                Some(false) if entity.start <= last.start => {
                    // The higher-layer `entity` wins and starts no later than
                    // `last` — no head would be dropped. Swap in the winner and
                    // push whatever tail of the loser survives past its end; that
                    // remainder re-enters the overlap test on the next iteration.
                    let loser = last.clone();
                    let len = merged.len();
                    merged[len - 1] = entity;
                    if let Some(rem) = trim_entity(&loser, merged[len - 1].end, text) {
                        merged.push(rem);
                    }
                }
                Some(false) => {
                    // The higher-layer `entity` wins but starts STRICTLY INTERIOR
                    // to `last` (the `entity.start <= last.start` case is the arm
                    // above). A naive `merged[len-1] = entity` would drop `last`'s
                    // exclusive HEAD `[last.start, entity.start)` into plaintext —
                    // the staggered partial-overlap leak this fix closes. Re-admit
                    // that head via `keep_prefix`, install the winner, and re-admit
                    // any exclusive TAIL of `last` past the winner's end too (only
                    // reachable when the higher-layer span is SHORTER and fully
                    // interior; for the confirmed longer-winner leak geometry there
                    // is no tail). The head is finalized to the left of the winner,
                    // so only the winner (or its tail remainder) re-enters the
                    // overlap test next iteration. All emitted fragments keep
                    // `last`'s `person` type + layer, stay pairwise non-overlapping,
                    // and together cover `last ∪ entity` — strictly recall-monotone,
                    // never flipping the winner or the type. Scoped to person-vs-
                    // person here so it never touches the cross-TYPE FP head that
                    // the `_` fallback deliberately absorbs.
                    let loser = last.clone();
                    let len = merged.len();
                    let winner_end = entity.end;
                    match keep_prefix(&loser, entity.start, text) {
                        Some(head) => {
                            merged[len - 1] = head;
                            merged.push(entity);
                        }
                        None => {
                            merged[len - 1] = entity;
                        }
                    }
                    if let Some(tail) = trim_entity(&loser, winner_end, text) {
                        merged.push(tail);
                    }
                }
                Some(true) => {
                    // `last` (higher-layer person) wins the overlap; keep it. The
                    // greedy sort guarantees `entity.start >= last.start`, so if
                    // the lower-layer `entity` overruns `last`'s tail, the
                    // non-overlapping region `[last.end, entity.end)` is still PII
                    // that must be redacted — mirror the `Some(false)` remainder
                    // trim (tail-only, no head-drop risk since entity starts no
                    // earlier than last). Otherwise `entity` is fully covered by
                    // `last` and is dropped.
                    if entity.end > last.end {
                        let last_end = last.end;
                        if let Some(rem) = trim_entity(&entity, last_end, text) {
                            merged.push(rem);
                        }
                    }
                }
                _ => {
                    // The person-cross-layer rule does not apply (`None`): the two
                    // spans are a different TYPE from each other, or the same layer.
                    // Both `Some(_)` cross-layer person cases are handled by the arms
                    // above, so nothing person-cross-layer reaches here. Fall back to
                    // the pre-existing length/confidence resolution — the longer span
                    // wins the overlap. This is NOT under-redaction-free in general:
                    // when the longer winner starts after the loser, the loser's
                    // exclusive head is dropped. For the cross-TYPE case that is the
                    // intended precision behavior — a benign false-positive head
                    // absorbed into a real entity (e.g. a `person` FP `于` head folded
                    // into an `address`; see the `coverage.rs` "never restores what
                    // the merge itself trimmed" invariant) MUST stay uncovered, which
                    // is exactly why the head-preserving trim is scoped to person-vs-
                    // person above and deliberately kept out of this heterogeneous arm.
                    if !pick_winner(last, &entity) {
                        let len = merged.len();
                        merged[len - 1] = entity;
                    }
                }
            }
        } else {
            merged.push(entity);
        }
    }

    merged
}

/// Is `t` a priority type (currently only `self_reference`)?
fn is_priority(t: &str) -> bool {
    PRIORITY_TYPES.contains(&t)
}

/// Trim `e` so it starts at `new_start`; `None` if nothing (or only whitespace)
/// remains. Port of `pure/merger._trim_entity` (char-sliced). The empty test uses
/// [`py_strip`] (NOT `str::trim`) so U+001C–U+001F count as whitespace, matching
/// Python `str.strip()`.
fn trim_entity(e: &PatternMatch, new_start: usize, text: &str) -> Option<PatternMatch> {
    if new_start >= e.end {
        return None;
    }
    let new_text = char_slice(text, new_start, e.end);
    if py_strip(&new_text).is_empty() {
        return None;
    }
    Some(PatternMatch {
        text: new_text,
        type_: e.type_.clone(),
        start: new_start,
        end: e.end,
        confidence: e.confidence,
        layer: e.layer,
    })
}

/// Keep only the PREFIX of `e` up to `new_end` — the span `[e.start, new_end)`;
/// `None` if nothing (or only whitespace) remains. The head-preserving mirror of
/// [`trim_entity`]: where `trim_entity` moves the START forward and keeps the end,
/// this keeps the start and moves the END back. Needed when a higher-layer person
/// winner starts strictly INTERIOR to the loser, so the loser's exclusive head
/// `[loser.start, winner.start)` would otherwise be dropped into the clear. Uses
/// the same [`py_strip`] empty-test as `trim_entity` for Python `str.strip()`
/// parity. Callers pass `new_end` in `(e.start, e.end)` (an interior boundary);
/// the guard below still returns `None` if `new_end` collapses to or before the
/// start.
fn keep_prefix(e: &PatternMatch, new_end: usize, text: &str) -> Option<PatternMatch> {
    if new_end <= e.start {
        return None;
    }
    let new_text = char_slice(text, e.start, new_end);
    if py_strip(&new_text).is_empty() {
        return None;
    }
    Some(PatternMatch {
        text: new_text,
        type_: e.type_.clone(),
        start: e.start,
        end: new_end,
        confidence: e.confidence,
        layer: e.layer,
    })
}

/// Insert priority entities into already-merged non-priority results, splitting
/// overlaps so a priority span wins. Port of `pure/merger._merge_priority`.
fn merge_priority(
    mut merged_others: Vec<PatternMatch>,
    priority: Vec<PatternMatch>,
    text: &str,
) -> Vec<PatternMatch> {
    merged_others.extend(priority);
    let mut all_entities = merged_others;
    // sort key: (start, -(end - start)) — longer span first on a tie.
    all_entities.sort_by(by_start_then_longer);
    let mut final_: Vec<PatternMatch> = vec![all_entities[0].clone()];
    for current in all_entities.into_iter().skip(1) {
        let last_end = final_.last().unwrap().end;
        if current.start >= last_end {
            final_.push(current);
            continue;
        }
        // Overlap — priority wins.
        let last_priority = is_priority(&final_.last().unwrap().type_);
        let cur_priority = is_priority(&current.type_);
        if cur_priority && !last_priority {
            let last = final_.last().unwrap();
            // A self_reference that starts strictly INTERIOR to a non-priority
            // entity (after the entity start) is part of that entity's name, not a
            // standalone pronoun: the container wins WHOLE (the full entity span is
            // redacted) and the interior self_reference is dropped. This holds
            // whether the sr is contained (自我管理咨询有限公司 with interior 我[1,2]
            // -> [ORG]) OR overruns the tail (公司我[0,3] with sr 我们[2,4] -> the
            // whole "公司我" is redacted, not replaced by the sr). Without this, the
            // overrun case would replace the container with the sr, drop the head
            // [last.start, current.start], and — once the sr is tier-filtered —
            // leak the entire name the caller asked to redact.
            //
            // The guard is strict (`>`, not `>=`): a self_reference at the entity
            // START (current.start == last.start) is NOT swallowed — that is the
            // "keep the leading pronoun" case (我在阿里巴巴有限公司 -> 我[ORG]), where
            // the sr must keep splitting the over-greedy entity so the pronoun
            // survives. Only an interior sr (a head exists to leak) yields here.
            if current.start > last.start {
                continue; // interior self_reference is part of the name; keep the container whole
            }
            let last = last.clone();
            let trimmed = trim_entity(&last, current.end, text);
            let idx = final_.len() - 1;
            final_[idx] = current;
            if let Some(t) = trimmed {
                final_.push(t);
            }
        } else if last_priority && !cur_priority {
            let last = final_.last().unwrap();
            if let Some(t) = trim_entity(&current, last.end, text) {
                final_.push(t);
            }
        } else {
            // Neither priority (or both): the longer span wins, else the higher
            // confidence. Port of `_merge_priority`'s final branch (the two
            // Python sub-conditions both replace `final[-1]`, so they fold into
            // one `||`).
            //
            // This resolver is NOT layer-aware (unlike `merge_entities_text`'s
            // `person_cross_layer_winner` check) — deliberately: `others` is
            // always pre-merged via `merge_entities_text(others, text)` before
            // `merge_priority` runs (see `merge_entities_with_text`), so every
            // non-priority entity reaching this loop is already pairwise
            // non-overlapping with its neighbors. Folding a priority entity in
            // can only shrink a survivor (trim moves its start forward, keeps
            // its end), which can only widen an existing gap, never narrow one
            // into a fresh overlap — so this branch can never actually see an
            // unresolved cross-layer person/person pair. See
            // `priority_path_person_cross_layer_seam_no_leak` and
            // `priority_path_person_cross_layer_pre_merge_boundary_holds_under_trim`
            // for the constructed reachability attempts that confirm this.
            let last = final_.last().unwrap();
            let idx = final_.len() - 1;
            let longer = (current.end - current.start) > (last.end - last.start);
            if longer || current.confidence > last.confidence {
                final_[idx] = current;
            }
        }
    }
    final_.sort_by(|a, b| a.start.cmp(&b.start));
    final_
}

/// Deduplicate overlapping entities, priority-aware — port of the Python
/// `pure/merger.merge_entities(entities, text)` (the public callable, NOT the
/// `_core.merge_entities` Rust primitive [`merge_entities`], which only handles
/// the non-priority path). When no priority (`self_reference`) entity is present
/// this is exactly [`merge_entities`]; otherwise the non-priority subset is
/// merged first and the priority entities are folded in via [`merge_priority`].
pub fn merge_entities_with_text(entities: Vec<PatternMatch>, text: &str) -> Vec<PatternMatch> {
    if entities.is_empty() {
        return vec![];
    }
    let has_priority = entities.iter().any(|e| is_priority(&e.type_));
    if !has_priority {
        // No self_reference in play — go straight to the text-aware merge so the
        // person-cross-layer rule (which needs `text` for its remainder trim) is
        // reachable. This is the path a fused-name overlap with no self_reference
        // in the input takes.
        return merge_entities_text(entities, text);
    }
    let mut others: Vec<PatternMatch> = Vec::new();
    let mut priority: Vec<PatternMatch> = Vec::new();
    for e in entities {
        if is_priority(&e.type_) {
            priority.push(e);
        } else {
            others.push(e);
        }
    }
    let merged_others = if others.is_empty() {
        Vec::new()
    } else {
        // Pre-merge the non-priority subset WITH the real text so a fused-person
        // cross-layer overlap co-present with a self_reference still gets the
        // remainder trim (passing no text here would silently drop the tail).
        merge_entities_text(others, text)
    };
    merge_priority(merged_others, priority, text)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pm(text: &str, s: usize, e: usize, conf: f64) -> PatternMatch {
        PatternMatch { text: text.into(), type_: "x".into(), start: s, end: e, confidence: conf, layer: 0 }
    }
    #[test]
    fn longer_span_wins() {
        let out = merge_entities(vec![pm("ab", 0, 2, 1.0), pm("abc", 0, 3, 1.0)]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].end, 3);
    }
    #[test]
    fn non_overlapping_kept() {
        let out = merge_entities(vec![pm("a", 0, 1, 1.0), pm("b", 5, 6, 1.0)]);
        assert_eq!(out.len(), 2);
    }

    // ── Priority-split overlap tests (merge_entities_with_text) ───────────────
    //
    // Expected outputs captured from LIVE Python:
    //   python3 -c "from argus_redact.pure.merger import merge_entities;
    //               from argus_redact._types import PatternMatch; ..."
    // These lock the self_reference priority-split permanently (it was only
    // temp-tested during code review). Each helper builds a (text, type, start,
    // end, confidence, layer) tuple comparable to the merged output.

    /// Build a typed PatternMatch for the priority tests.
    fn pmt(text: &str, type_: &str, s: usize, e: usize, conf: f64, layer: u8) -> PatternMatch {
        PatternMatch { text: text.into(), type_: type_.into(), start: s, end: e, confidence: conf, layer }
    }

    /// Reduce to the comparable tuple shape used by the priority-split assertions.
    fn tup(e: &PatternMatch) -> (String, String, usize, usize, f64, u8) {
        (e.text.clone(), e.type_.clone(), e.start, e.end, e.confidence, e.layer)
    }

    fn assert_merged(got: &[PatternMatch], expected: &[(&str, &str, usize, usize, f64, u8)]) {
        let got_v: Vec<_> = got.iter().map(tup).collect();
        let exp_v: Vec<_> = expected
            .iter()
            .map(|&(t, ty, s, e, c, l)| (t.to_string(), ty.to_string(), s, e, c, l))
            .collect();
        assert_eq!(got_v, exp_v);
    }

    #[test]
    fn interior_self_reference_does_not_split_container() {
        let text = "自我管理咨询有限公司";
        let org = pmt("自我管理咨询有限公司", "organization", 0, 10, 1.0, 0);
        let sr = pmt("我", "self_reference", 1, 2, 1.0, 0);
        let out = merge_entities_with_text(vec![org, sr], text);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].type_, "organization");
        assert_eq!((out[0].start, out[0].end), (0, 10));
    }

    #[test]
    fn priority_partial_overlap_sr_first() {
        // sr [0,3] precedes an overlapping `other` [2,6]; sr wins, other trimmed
        // to start at sr.end=3. Live Python:
        //   ('我的电','self_reference',0,3,1.0,1), ('话号码','other',3,6,1.0,1)
        let out = merge_entities_with_text(
            vec![
                pmt("我的电", "self_reference", 0, 3, 1.0, 1),
                pmt("电话号码", "other", 2, 6, 1.0, 1),
            ],
            "我的电话号码xxxx",
        );
        assert_merged(
            &out,
            &[
                ("我的电", "self_reference", 0, 3, 1.0, 1),
                ("话号码", "other", 3, 6, 1.0, 1),
            ],
        );
    }

    #[test]
    fn priority_partial_overlap_sr_second() {
        // `other` [0,4] precedes an sr [2,6] that starts INTERIOR (2>0) and
        // overruns the tail (6>4). The interior sr is part of the entity name, so
        // `other` wins WHOLE — replacing it with the sr would drop the head [0,2]
        // and leak it. The sr is dropped.
        let out = merge_entities_with_text(
            vec![
                pmt("abcd", "other", 0, 4, 1.0, 1),
                pmt("cdef", "self_reference", 2, 6, 1.0, 1),
            ],
            "abcdefghij",
        );
        assert_merged(&out, &[("abcd", "other", 0, 4, 1.0, 1)]);
    }

    #[test]
    fn priority_containment_other_wins() {
        // `other` [0,6] fully contains sr [2,4]: the sr is part of the container's
        // span (an interior pronoun inside a real entity name), so the container
        // wins INTACT and the contained sr is dropped — no whole-entity split, no
        // leading-slice [0,2] leak. (Previously this split to sr + tail [4,6],
        // dropping the leading 'ab'; that was the partial-leak defect.)
        let out = merge_entities_with_text(
            vec![
                pmt("abcdef", "other", 0, 6, 1.0, 1),
                pmt("cd", "self_reference", 2, 4, 1.0, 1),
            ],
            "abcdefghij",
        );
        assert_merged(&out, &[("abcdef", "other", 0, 6, 1.0, 1)]);
    }

    #[test]
    fn overrun_interior_self_reference_keeps_container_whole() {
        // A self_reference that starts INTERIOR to a non-priority entity (start >
        // entity.start) but overruns its tail (end > entity.end) must NOT replace
        // the container. Doing so drops the container head [entity.start,
        // sr.start] and, once the sr is later tier-filtered, leaks the whole name
        // the caller asked to redact. The container wins WHOLE (the full
        // requested name is redacted); the interior sr is dropped.
        // person "公司我"[0,3] + sr "我们"[2,4] -> person[0,3] intact.
        let text = "公司我们裁员了";
        let out = merge_entities_with_text(
            vec![
                pmt("公司我", "person", 0, 3, 1.0, 0),
                pmt("我们", "self_reference", 2, 4, 1.0, 0),
            ],
            text,
        );
        assert_merged(&out, &[("公司我", "person", 0, 3, 1.0, 0)]);
    }

    #[test]
    fn standalone_self_reference_outside_entity_kept() {
        // A self_reference [0,1] that is NOT inside any entity (a standalone
        // pronoun) is preserved after merge — the containment guard must not
        // swallow it. The phone [3,14] is disjoint; both survive, start-sorted.
        let out = merge_entities_with_text(
            vec![
                pmt("我", "self_reference", 0, 1, 1.0, 0),
                pmt("13800138000x", "phone", 3, 14, 1.0, 0),
            ],
            "我 x 13800138000x",
        );
        assert_eq!(out.len(), 2);
        assert_merged(
            &out,
            &[
                ("我", "self_reference", 0, 1, 1.0, 0),
                ("13800138000x", "phone", 3, 14, 1.0, 0),
            ],
        );
    }

    #[test]
    fn overrun_self_reference_does_not_drop_container_head() {
        // org [0,10] followed by an sr [8,12] that starts interior (8>0) and
        // extends PAST the org end. The sr must NOT win-and-trim the org to
        // nothing — that drops the org head [0,8] in plaintext. The interior sr is
        // part of the name region; the container wins WHOLE and the sr is dropped.
        let text = "organizatio我我";
        let out = merge_entities_with_text(
            vec![
                pmt("organizati", "organization", 0, 10, 1.0, 0),
                pmt("o我我", "self_reference", 8, 12, 1.0, 0),
            ],
            text,
        );
        assert_merged(&out, &[("organizati", "organization", 0, 10, 1.0, 0)]);
    }

    #[test]
    fn priority_same_span_sr_wins() {
        // sr and `other` share the exact span [0,2]; the priority entity wins.
        // Same-span is NOT interior containment (current.start == last.start, no
        // leading slice to leak), so the containment guard (current.start >
        // last.start) does not fire — the sr keeps winning the tie as before, so
        // tier-filtering can still decide its fate. Live Python:
        //   ('ab','self_reference',0,2,1.0,1)
        let out = merge_entities_with_text(
            vec![
                pmt("ab", "other", 0, 2, 1.0, 1),
                pmt("ab", "self_reference", 0, 2, 1.0, 1),
            ],
            "abcdefghij",
        );
        assert_merged(&out, &[("ab", "self_reference", 0, 2, 1.0, 1)]);
    }

    #[test]
    fn priority_trim_to_whitespace_drop() {
        // sr [0,4] overlaps `other` [3,6]; trimming `other` to start at sr.end=4
        // leaves "  " (whitespace) → dropped. Live Python:
        //   ('我的电话','self_reference',0,4,1.0,1)
        let out = merge_entities_with_text(
            vec![
                pmt("我的电话", "self_reference", 0, 4, 1.0, 1),
                pmt("话  ", "other", 3, 6, 1.0, 1),
            ],
            "我的电话  X",
        );
        assert_merged(&out, &[("我的电话", "self_reference", 0, 4, 1.0, 1)]);
    }

    #[test]
    fn priority_non_overlap_control() {
        // sr [0,1] and phone [2,13] don't overlap; both kept, start-sorted.
        // Live Python:
        //   ('我','self_reference',0,1,1.0,1), ('13800138000','phone',2,13,1.0,1)
        let out = merge_entities_with_text(
            vec![
                pmt("我", "self_reference", 0, 1, 1.0, 1),
                pmt("13800138000", "phone", 2, 13, 1.0, 1),
            ],
            "我 13800138000",
        );
        assert_merged(
            &out,
            &[
                ("我", "self_reference", 0, 1, 1.0, 1),
                ("13800138000", "phone", 2, 13, 1.0, 1),
            ],
        );
    }

    // ── Person cross-layer merge (merge_entities_text) ────────────────────────

    #[test]
    fn person_cross_layer_partial_overlap_trims_remainder() {
        // An over-greedy L1 person candidate "李明明王"[2,6] overlaps a correct L2
        // NER person span "李明明"[2,5]. Same start, so no head to drop: the
        // higher-layer (L2) span wins and the L1 loser is trimmed to its tail
        // remainder [5,6) "王" (still `person`, still layer 1) rather than
        // discarded outright — nothing that would have been redacted leaks.
        let out = merge_entities_with_text(
            vec![
                pmt("李明明王", "person", 2, 6, 1.0, 1),
                pmt("李明明", "person", 2, 5, 1.0, 2),
            ],
            "客户李明明王联系电话13800138000",
        );
        assert_merged(
            &out,
            &[
                ("李明明", "person", 2, 5, 1.0, 2),
                ("王", "person", 5, 6, 1.0, 1),
            ],
        );
    }

    #[test]
    fn person_same_layer_control_uses_length_then_confidence() {
        // Two person spans on the SAME layer must NOT trigger the cross-layer
        // rule — person_cross_layer_winner returns None for equal layers, so
        // this falls through to the existing length-then-confidence pick_winner
        // logic (longer span wins outright, no trim/remainder).
        let out = merge_entities_with_text(
            vec![
                pmt("李明明王", "person", 2, 6, 1.0, 1),
                pmt("李明明", "person", 2, 5, 1.0, 1),
            ],
            "客户李明明王联系电话13800138000",
        );
        assert_merged(&out, &[("李明明王", "person", 2, 6, 1.0, 1)]);
    }

    #[test]
    fn has_priority_path_cross_layer_person_keeps_remainder() {
        // A self_reference co-present with the fused-name person overlap forces
        // `merge_entities_with_text` down the priority path, which pre-merges the
        // non-priority subset. That pre-merge must run WITH the real text so the
        // person-cross-layer trim still carves off the "王"[5,6] tail — otherwise
        // it is silently dropped into plaintext (the leak this closes).
        let out = merge_entities_with_text(
            vec![
                pmt("我", "self_reference", 0, 1, 1.0, 0),
                pmt("李明明王", "person", 2, 6, 1.0, 1),
                pmt("李明明", "person", 2, 5, 1.0, 2),
            ],
            "我x李明明王联系电话13800138000",
        );
        assert_merged(
            &out,
            &[
                ("我", "self_reference", 0, 1, 1.0, 0),
                ("李明明", "person", 2, 5, 1.0, 2),
                ("王", "person", 5, 6, 1.0, 1),
            ],
        );
    }

    #[test]
    fn person_cross_layer_last_wins_overrun_tail_redacted() {
        // The higher-layer person span "张三"[2,4] (L2) sorts first and wins the
        // overlap over the lower-layer "三丰道"[3,6] (L1). But the loser overruns
        // last's tail: its non-overlapping region [4,6) is still PII and must be
        // redacted. The Some(true) arm mirror-trims that tail ("丰道"[4,6], layer
        // 1) instead of dropping the whole loser. Together the two spans cover
        // [2,6) with no plaintext gap.
        let out = merge_entities_with_text(
            vec![
                pmt("张三", "person", 2, 4, 1.0, 2),
                pmt("三丰道", "person", 3, 6, 1.0, 1),
            ],
            "客户张三丰道人",
        );
        assert_merged(
            &out,
            &[
                ("张三", "person", 2, 4, 1.0, 2),
                ("丰道", "person", 4, 6, 1.0, 1),
            ],
        );
    }

    #[test]
    fn bare_merge_entities_empty_text_cross_layer_falls_through() {
        // The pub `merge_entities(entities)` wrapper passes text="". The person
        // rule must NOT fire without text (its trim would slice an empty string
        // and silently drop the remainder). With the empty-text guard it falls
        // through to the length-then-confidence path = the pre-existing behavior:
        // the longer L1 span wins whole, no panic, no partial remainder.
        let out = merge_entities(vec![
            pmt("李明明王", "person", 2, 6, 1.0, 1),
            pmt("李明明", "person", 2, 5, 1.0, 2),
        ]);
        assert_merged(&out, &[("李明明王", "person", 2, 6, 1.0, 1)]);
    }

    // ── Reachability probe: merge_priority's neither-priority ELSE branch ─────
    //
    // `merge_priority`'s final `else` (neither entity is priority, or both are)
    // resolves overlaps by plain length/confidence — it does NOT consult
    // `person_cross_layer_winner`. These tests try to construct a case where
    // that branch actually sees an unresolved cross-layer person/person
    // overlap, to check whether it is a live leak site or whether the `others`
    // pre-merge (run with real `text`, see `has_priority_path_cross_layer_person_keeps_remainder`)
    // always resolves such pairs upstream. It always does: `others` is merged
    // via `merge_entities_text` before `merge_priority` ever runs, so its
    // output is already pairwise non-overlapping; folding the self_reference
    // back in only ever *trims* those survivors (start moves forward, end is
    // preserved), which can only widen an existing gap between two neighbors,
    // never narrow one into a fresh overlap. So no matter where the
    // self_reference lands relative to the cross-layer survivors, the else
    // branch's overlap gate (`current.start >= last_end`) never lets it see
    // them as overlapping. These are regression guards for that invariant, not
    // leak reproductions — kept green on purpose.

    #[test]
    fn priority_path_person_cross_layer_seam_no_leak() {
        // self_reference "明王"[4,6] straddles the seam between the two L1/L2
        // survivors of a three-way cross-layer chain (L1 person[2,6] layer1,
        // L2 person[2,5] layer2, L2 person[5,8] layer2). The `others` pre-merge
        // resolves the three down to two non-overlapping layer-2 survivors,
        // ["李明明"(2,5), "王道人"(5,8)], covering [2,8) before self_reference
        // ever enters the picture (mirrors
        // `person_cross_layer_partial_overlap_trims_remainder` chained twice).
        // Folding the self_reference in via merge_priority: it starts INTERIOR
        // to both survivors it touches, so the containment guard drops it
        // outright (its range is already covered) — no plaintext tail, and
        // the else branch is never invoked for this pair at all.
        let text = "客户李明明王道人电话";
        let out = merge_entities_with_text(
            vec![
                pmt("明王", "self_reference", 4, 6, 1.0, 0),
                pmt("李明明王", "person", 2, 6, 1.0, 1),
                pmt("李明明", "person", 2, 5, 1.0, 2),
                pmt("王道人", "person", 5, 8, 1.0, 2),
            ],
            text,
        );
        assert_merged(
            &out,
            &[
                ("李明明", "person", 2, 5, 1.0, 2),
                ("王道人", "person", 5, 8, 1.0, 2),
            ],
        );
    }

    #[test]
    fn priority_path_person_cross_layer_pre_merge_boundary_holds_under_trim() {
        // Sharper adversarial attempt: self_reference "李明"[2,4] starts AT the
        // seam's leading survivor's start (not interior), so it wins the
        // overlap and TRIMS the layer-2 survivor down (via merge_priority's
        // `cur_priority && !last_priority` branch) instead of being dropped —
        // the closest this algorithm gets to reshaping a cross-layer survivor
        // after the pre-merge already ran. The two-entity chain (L1
        // person[2,6] layer1 + L2 person[2,5] layer2) pre-merges to
        // ["李明明"(2,5) layer2, "王"(5,6) layer1] (different layers, adjacent at
        // the seam start=end=5 — see `person_cross_layer_partial_overlap_trims_remainder`).
        // Trimming the layer-2 survivor only moves ITS start forward
        // (2->4), which cannot move the seam itself (still exactly 5): the
        // layer-1 remainder's start and the trimmed layer-2 remainder's end
        // never cross, so merge_priority's overlap gate (`current.start >=
        // last_end`) still short-circuits before the else branch's
        // length/confidence resolver ever runs on this pair. Full [2,6)
        // coverage survives.
        let text = "客户李明明王联系电话";
        let out = merge_entities_with_text(
            vec![
                pmt("李明", "self_reference", 2, 4, 1.0, 0),
                pmt("李明明王", "person", 2, 6, 1.0, 1),
                pmt("李明明", "person", 2, 5, 1.0, 2),
            ],
            text,
        );
        assert_merged(
            &out,
            &[
                ("李明", "self_reference", 2, 4, 1.0, 0),
                ("明", "person", 4, 5, 1.0, 2),
                ("王", "person", 5, 6, 1.0, 1),
            ],
        );
    }

    #[test]
    fn priority_trim_drops_u001c_only_remainder() {
        // self_reference [0,1] "我" overlaps other [0,3] "我\u{1c}\u{1c}".
        // The sr starts AT the entity start (current.start == last.start), so this
        // is prefix-aligned, not interior containment — the containment guard
        // (current.start > last.start) does not fire and the sr keeps winning.
        // Trimming other to start at 1 → "\u{1c}\u{1c}" → py_strip empty → dropped
        // (Python str.strip() trims U+001C–001F; str::trim() would not, leaving a
        // garbage entity). Locks the py_strip parity fix.
        let out = merge_entities_with_text(
            vec![
                pmt("我", "self_reference", 0, 1, 1.0, 1),
                pmt("我\u{1c}\u{1c}", "other", 0, 3, 1.0, 1),
            ],
            "我\u{1c}\u{1c}",
        );
        assert_merged(&out, &[("我", "self_reference", 0, 1, 1.0, 1)]);
    }

    // ── Person cross-layer STAGGERED partial overlap (interior-start winner) ──
    //
    // Regression tests for the staggered-overlap HEAD leak: a higher-layer
    // `person` winner that starts strictly INTERIOR to a lower-layer `person`
    // loser used to fall through to the `_` length/confidence arm, which replaced
    // the loser outright and dropped the loser's exclusive head into plaintext.

    #[test]
    fn person_cross_layer_interior_start_head_not_dropped() {
        // The confirmed leak geometry. An over-greedy L1 person "李四"[0,2] (layer
        // 1) overlaps a higher-layer NER person "四德张"[1,4] (layer 2) that starts
        // INTERIOR to it (1 > 0) and is longer. The L2 span wins the overlap, but
        // the loser's exclusive head "李"[0,1] must NOT be dropped into the clear.
        // Pre-fix, the `_` arm did `merged[len-1] = entity`, leaking "李"; the new
        // person-scoped `Some(false)` arm re-admits the head via `keep_prefix`.
        // Winner and both `person` types are preserved; output is non-overlapping.
        let out = merge_entities_with_text(
            vec![
                pmt("李四", "person", 0, 2, 1.0, 1),
                pmt("四德张", "person", 1, 4, 1.0, 2),
            ],
            "李四德张",
        );
        assert_merged(
            &out,
            &[
                ("李", "person", 0, 1, 1.0, 1),
                ("四德张", "person", 1, 4, 1.0, 2),
            ],
        );
    }

    #[test]
    fn person_cross_layer_interior_contained_winner_readmits_head_and_tail() {
        // The other sub-case of an interior-start higher-layer winner: it is
        // SHORTER than the loser and fully CONTAINED in it. An over-greedy L1
        // person "四德张明"[0,4] (layer 1) around a higher-layer NER person
        // "德张"[1,3] (layer 2). The winner has both an exclusive HEAD "四"[0,1] and
        // an exclusive TAIL "明"[3,4] on the loser. An unguarded head-only re-admit
        // would drop the tail (a NEW leak); this re-admits BOTH via `keep_prefix`
        // (head) + `trim_entity` (tail). Coverage of [0,4) is preserved with no
        // plaintext gap and the three fragments are pairwise non-overlapping —
        // strictly recall-monotone (same total coverage the pre-fix `_` arm kept
        // as one span, now with the L2 authority for the interior).
        let out = merge_entities_with_text(
            vec![
                pmt("四德张明", "person", 0, 4, 1.0, 1),
                pmt("德张", "person", 1, 3, 1.0, 2),
            ],
            "四德张明",
        );
        assert_merged(
            &out,
            &[
                ("四", "person", 0, 1, 1.0, 1),
                ("德张", "person", 1, 3, 1.0, 2),
                ("明", "person", 3, 4, 1.0, 1),
            ],
        );
    }

    #[test]
    fn person_cross_layer_interior_start_head_kept_on_priority_path() {
        // Same interior-start head-leak geometry, but a co-present self_reference
        // forces `merge_entities_with_text` down the priority path, which
        // pre-merges the non-priority subset WITH the real text. The head "李"[2,3]
        // must still survive that pre-merge (this is where the leak would silently
        // re-appear if the priority path skipped the text-aware merge).
        let out = merge_entities_with_text(
            vec![
                pmt("我", "self_reference", 0, 1, 1.0, 0),
                pmt("李四", "person", 2, 4, 1.0, 1),
                pmt("四德张", "person", 3, 6, 1.0, 2),
            ],
            "我x李四德张",
        );
        assert_merged(
            &out,
            &[
                ("我", "self_reference", 0, 1, 1.0, 0),
                ("李", "person", 2, 3, 1.0, 1),
                ("四德张", "person", 3, 6, 1.0, 2),
            ],
        );
    }

    #[test]
    fn cross_type_fp_head_absorbed_not_readmitted() {
        // PRECISION guard: the head re-admission is scoped to person-vs-person, so
        // it must NOT fire for a cross-TYPE overlap. A benign `person` false
        // positive "于江苏"[0,3] overlapping a real `address` "江苏省南京"[1,6] must
        // still be absorbed WHOLE into the address — the "于"[0,1] head stays
        // UNCOVERED (a generic head-preserving trim would wrongly re-admit it as a
        // person span). Mirrors the `coverage.rs` "never restores what the merge
        // itself trimmed" invariant at the merge site. `person_cross_layer_winner`
        // returns `None` here (types differ), so this resolves in the `_` arm.
        let out = merge_entities_with_text(
            vec![
                pmt("于江苏", "person", 0, 3, 1.0, 1),
                pmt("江苏省南京", "address", 1, 6, 1.0, 2),
            ],
            "于江苏省南京",
        );
        assert_merged(&out, &[("江苏省南京", "address", 1, 6, 1.0, 2)]);
    }
}
