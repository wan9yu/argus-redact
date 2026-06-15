use crate::types::PatternMatch;

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
}
