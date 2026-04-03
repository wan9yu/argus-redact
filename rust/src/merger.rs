use pyo3::prelude::*;
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
#[pyfunction]
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
