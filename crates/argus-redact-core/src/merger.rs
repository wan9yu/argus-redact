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
/// remains. Port of `pure/merger._trim_entity` (char-sliced; `str.strip()` →
/// trim of Unicode whitespace, matching Python `.strip()` for the empty test).
fn trim_entity(e: &PatternMatch, new_start: usize, text: &str) -> Option<PatternMatch> {
    if new_start >= e.end {
        return None;
    }
    let new_text = char_slice(text, new_start, e.end);
    if new_text.trim().is_empty() {
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
            let last = final_.last().unwrap().clone();
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
    fn priority_containment_other_contains_sr() {
        // `other` [0,6] fully contains sr [2,4]; sr wins and `other` is split —
        // the trailing remainder [4,6] survives (the leading [0,2] is consumed
        // because the merged-others entity is replaced by sr in the same slot).
        // Live Python:
        //   ('cd','self_reference',2,4,1.0,1), ('ef','other',4,6,1.0,1)
        let out = merge_entities_with_text(
            vec![
                pmt("abcdef", "other", 0, 6, 1.0, 1),
                pmt("cd", "self_reference", 2, 4, 1.0, 1),
            ],
            "abcdefghij",
        );
        assert_merged(
            &out,
            &[
                ("cd", "self_reference", 2, 4, 1.0, 1),
                ("ef", "other", 4, 6, 1.0, 1),
            ],
        );
    }

    #[test]
    fn priority_same_span_sr_wins() {
        // sr and `other` share the exact span [0,2]; the priority entity wins.
        // Live Python: ('ab','self_reference',0,2,1.0,1)
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
}
