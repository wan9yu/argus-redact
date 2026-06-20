use crate::hints::py_strip;
use crate::reserved_range::char_slice;
use crate::types::PatternMatch;

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
pub fn merge_entities(entities: Vec<PatternMatch>) -> Vec<PatternMatch> {
    if entities.is_empty() {
        return vec![];
    }

    let mut sorted = entities;
    sorted.sort_by(|a, b| {
        a.start.cmp(&b.start)
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
    });

    let mut merged: Vec<PatternMatch> = vec![sorted[0].clone()];

    for entity in sorted.into_iter().skip(1) {
        let last = merged.last().unwrap();
        // Check overlap: a.start < b.end && b.start < a.end
        if last.start < entity.end && entity.start < last.end {
            // Overlapping — pick winner
            if !pick_winner(last, &entity) {
                let len = merged.len();
                merged[len - 1] = entity;
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
    all_entities.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
    });
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
            // A self_reference strictly INTERIOR to a non-priority entity (it starts
            // after the entity start) is part of that entity's name, not a standalone
            // pronoun: the container wins (whole-entity redaction) and the interior
            // self_reference is dropped. Prevents the leading slice
            // [last.start, current.start] from leaking
            // (自我管理咨询有限公司 with interior 我[1,2] -> [ORG], not 自我[ORG]).
            //
            // The guard is strict (`>`, not `>=`): a self_reference at the entity
            // START (current.start == last.start) is NOT swallowed — that is the
            // "keep the leading pronoun" case (我在阿里巴巴有限公司 -> 我[ORG]), where
            // the sr must keep splitting the over-greedy entity so the pronoun
            // survives. Only an interior sr (a head exists to leak) yields here.
            if current.start > last.start && current.end <= last.end {
                continue; // drop the contained self_reference; keep the container
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
        return merge_entities(entities);
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
        merge_entities(others)
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
        // `other` [0,4] precedes the overlapping sr [2,6]; sr wins. The trim of
        // `other` to start at sr.end=6 yields nothing (6 >= other.end=4), so only
        // sr remains. Live Python: ('cdef','self_reference',2,6,1.0,1)
        let out = merge_entities_with_text(
            vec![
                pmt("abcd", "other", 0, 4, 1.0, 1),
                pmt("cdef", "self_reference", 2, 6, 1.0, 1),
            ],
            "abcdefghij",
        );
        assert_merged(&out, &[("cdef", "self_reference", 2, 6, 1.0, 1)]);
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
    fn partial_overlap_sr_not_contained_keeps_split() {
        // org [0,10] is followed by an sr [8,12] that extends PAST the org end —
        // the sr is NOT fully contained, so the old priority-split behavior holds:
        // the sr wins and the org is trimmed to start at sr.end=12 (nothing left,
        // 12 >= 10), leaving the sr alone.
        let text = "organizatio我我";
        let out = merge_entities_with_text(
            vec![
                pmt("organizati", "organization", 0, 10, 1.0, 0),
                pmt("o我我", "self_reference", 8, 12, 1.0, 0),
            ],
            text,
        );
        assert_merged(&out, &[("o我我", "self_reference", 8, 12, 1.0, 0)]);
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
}
