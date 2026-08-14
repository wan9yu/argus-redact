//! Post-merge coverage invariant.
//!
//! Detection ends with a priority-aware merge followed by one or more DROPPING
//! filters (`filter_self_reference`, the `types`/`types_exclude` filter). The
//! merge is *absorbing*: when two spans overlap one wins and the loser is
//! discarded, which is safe because the winner covers the loser's bytes. A
//! filter that then drops a winner un-covers everything that winner absorbed,
//! leaving that PII unredacted in the output.
//!
//! This module owns the ONE predicate the filters and the restorer share, so
//! the two can never disagree about what a filter legitimately removes.
//!
//! The restorer deliberately does NOT undo the merge. An entity the merge
//! trimmed away (a false-positive `person` absorbed into an `address`, say) is
//! left alone: only entities the MERGED set still covered, and the FILTERED set
//! no longer covers, are re-admitted. Without that condition the invariant would
//! resurrect false positives on ordinary text.

use std::collections::HashSet;

use crate::hints::{filter_self_reference, get_self_reference_tier, Hint};
use crate::merger::merge_entities_with_text;
use crate::types::PatternMatch;

/// What the post-merge filters legitimately remove.
///
/// `#[non_exhaustive]`: crates.io publishes are immutable, so a bare pub struct
/// can never gain a field without a major version. Construct via [`Self::new`]
/// (or [`Self::from_hints`]) from outside this crate.
#[non_exhaustive]
pub struct FilterScope<'a> {
    /// Type allow-list: when set, only these types survive.
    pub types: Option<&'a HashSet<String>>,
    /// Type deny-list: consulted only when `types` is `None`.
    pub types_exclude: Option<&'a HashSet<String>>,
    /// True when the self-reference tier filter will drop `self_reference` spans.
    pub drop_self_reference: bool,
}

impl<'a> FilterScope<'a> {
    /// Build a `FilterScope` directly from its three components.
    /// `#[non_exhaustive]` blocks other crates from writing the struct literal,
    /// so this is the stable construction path for callers outside
    /// `argus-redact-core` — e.g. the Python binding, which resolves
    /// `types`/`types_exclude` into `HashSet`s and computes
    /// `drop_self_reference` itself rather than from `Hint`s (see
    /// [`Self::from_hints`] for the hint-driven constructor used in-crate).
    pub fn new(
        types: Option<&'a HashSet<String>>,
        types_exclude: Option<&'a HashSet<String>>,
        drop_self_reference: bool,
    ) -> Self {
        FilterScope { types, types_exclude, drop_self_reference }
    }

    /// Build the scope the way the pipeline's own filters are configured:
    /// `drop_self_reference` mirrors `filter_self_reference`, which keeps every
    /// entity at tier 1 and drops `self_reference` at any other tier — including
    /// when no tier hint was emitted at all.
    pub fn from_hints(
        types: Option<&'a HashSet<String>>,
        types_exclude: Option<&'a HashSet<String>>,
        hints: &[Hint],
    ) -> Self {
        FilterScope {
            types,
            types_exclude,
            drop_self_reference: get_self_reference_tier(hints) != Some(1),
        }
    }

    /// The single predicate. Both the filters and the restorer consult it.
    ///
    /// Precedence mirrors `redact_l1`'s step 5 exactly: `types` wins over
    /// `types_exclude` (`if ... else if ...`), so when a keep-list is present
    /// the deny-list is never consulted.
    pub fn admits(&self, e: &PatternMatch) -> bool {
        if self.drop_self_reference && e.type_ == "self_reference" {
            return false;
        }
        match (self.types, self.types_exclude) {
            (Some(keep), _) => keep.contains(&e.type_),
            (None, Some(drop)) => !drop.contains(&e.type_),
            (None, None) => true,
        }
    }

    /// True when no entity in `entities` can be dropped by the filters this
    /// scope describes. Callers use it to skip snapshotting the pre-merge set on
    /// the hot path: a merged entity's type is always some pre-merge entity's
    /// type, so "every pre-merge entity is admitted" implies "no filter drops
    /// anything", which implies no coverage can be lost.
    pub fn admits_all(&self, entities: &[PatternMatch]) -> bool {
        entities.iter().all(|e| self.admits(e))
    }
}

/// True when `[start, end)` is fully contained in some span of `set`.
fn covered(start: usize, end: usize, set: &[(usize, usize)]) -> bool {
    set.iter().any(|&(s, e)| s <= start && e >= end)
}

/// Re-admit pre-merge entities whose coverage a post-merge filter destroyed.
///
/// Returns the corrected entity list and the sorted, de-duplicated TYPES of the
/// entities restored — a PII-free signal safe for the audit ledger.
///
/// Returns `filtered` untouched (and an empty type list) whenever nothing was
/// lost, which is the overwhelmingly common case.
pub fn restore_lost_coverage(
    pre_merge: &[PatternMatch],
    merged_spans: &[(usize, usize)],
    filtered: Vec<PatternMatch>,
    scope: &FilterScope<'_>,
    text: &str,
) -> (Vec<PatternMatch>, Vec<String>) {
    let surviving: Vec<(usize, usize)> = filtered.iter().map(|e| (e.start, e.end)).collect();

    let lost: Vec<PatternMatch> = pre_merge
        .iter()
        .filter(|p| scope.admits(p))
        .filter(|p| covered(p.start, p.end, merged_spans))
        .filter(|p| !covered(p.start, p.end, &surviving))
        .cloned()
        .collect();

    if lost.is_empty() {
        return (filtered, Vec::new());
    }

    let mut types: Vec<String> = lost.iter().map(|e| e.type_.clone()).collect();
    types.sort();
    types.dedup();

    let mut all = filtered;
    all.extend(lost);
    (merge_entities_with_text(all, text), types)
}

/// Reduce a RAW detection set to the FINAL entity set — the post-merge pipeline
/// every detection path shares: merge → self-reference filter → (optional) type
/// filter → coverage restore. This is the ONE place the post-merge PII-leak
/// coverage invariant (v0.8.6) lives, so the batch (`redact_l1`) and streaming
/// (`streaming::detect_final`) faces can never drift on it.
///
/// `apply_type_filter` is the ONLY axis the two callers differ on:
/// - `redact_l1` runs the `types`/`types_exclude` filter (`true`), reading the
///   lists off `scope` — the very same lists the restorer's `admits` consults.
/// - the streaming face applies NO type filter (`false`): its caller-supplied
///   redact closure owns type selection, so its `scope` carries no lists.
///
/// Every other step — the pre-merge snapshot decision, merge order, self-ref
/// tier filter, and `restore_lost_coverage` — is identical for both.
///
/// `scope` MUST be built from the same `hints` passed here (via
/// [`FilterScope::from_hints`]): that is what keeps `scope.drop_self_reference`
/// and `filter_self_reference` in agreement, which the coverage restore relies on.
pub fn finalize_entities(
    entities: Vec<PatternMatch>,
    hints: &[Hint],
    scope: &FilterScope<'_>,
    text: &str,
    apply_type_filter: bool,
) -> Vec<PatternMatch> {
    // Snapshot the pre-merge set ONLY when a post-merge filter can actually drop
    // something — the restore step below needs it. A merged entity's type is
    // always some pre-merge entity's type, so when every pre-merge entity is
    // admitted no filter drops anything and no coverage can be lost.
    let pre_merge: Option<Vec<PatternMatch>> =
        if scope.admits_all(&entities) { None } else { Some(entities.clone()) };
    let merged = merge_entities_with_text(entities, text);
    // One Option carrying both halves — `merged` is moved into the filter below,
    // so its spans must be taken first, and the snapshot is only ever useful
    // paired with them.
    let snapshot: Option<(Vec<PatternMatch>, Vec<(usize, usize)>)> =
        pre_merge.map(|pre| (pre, merged.iter().map(|e| (e.start, e.end)).collect()));

    // Self-reference tier filter (both faces run it).
    let filtered = filter_self_reference(merged, hints);

    // Type filter (redact.py:337-343): types wins over types_exclude. Only the
    // batch path applies it; the streaming face leaves type selection to its
    // caller's redact closure. Routed through `scope.admits` — the SAME single
    // predicate `restore_lost_coverage` consults — so the two can never drift on
    // the keep-over-deny precedence. `admits` also drops `self_reference` when
    // `scope.drop_self_reference`, but `filter_self_reference` above already
    // removed every `self_reference` span in exactly that case (both key off the
    // same `get_self_reference_tier(hints)`), so that arm is a no-op here.
    let filtered: Vec<PatternMatch> = if apply_type_filter {
        filtered.into_iter().filter(|e| scope.admits(e)).collect()
    } else {
        filtered
    };

    // Post-merge coverage invariant: the filters above drop entities by type, and
    // a dropped entity may have absorbed a DIFFERENT real entity during the merge.
    // Re-admit anything whose coverage they destroyed.
    match snapshot {
        Some((pre, spans)) => restore_lost_coverage(&pre, &spans, filtered, scope, text).0,
        None => filtered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hints::HintKind;
    use std::collections::HashSet;

    fn pm(text: &str, type_: &str, start: usize, end: usize) -> PatternMatch {
        PatternMatch {
            text: text.to_string(),
            type_: type_.to_string(),
            start,
            end,
            confidence: 1.0,
            layer: 1,
        }
    }

    fn set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn spans(entities: &[PatternMatch]) -> Vec<(usize, usize)> {
        entities.iter().map(|e| (e.start, e.end)).collect()
    }

    // Built the same way `hints.rs`'s own `srt` test helper builds it.
    fn srt(tier: u8) -> Hint {
        Hint {
            kind: HintKind::SelfReferenceTier { tier, has_kinship: false },
        }
    }

    #[test]
    fn admits_everything_with_an_empty_scope() {
        let scope = FilterScope { types: None, types_exclude: None, drop_self_reference: false };
        assert!(scope.admits(&pm("x", "phone", 0, 1)));
        assert!(scope.admits(&pm("x", "self_reference", 0, 1)));
    }

    #[test]
    fn types_wins_over_types_exclude() {
        // Mirrors redact_l1.rs step 5: `if types { .. } else if types_exclude { .. }`.
        let keep = set(&["phone"]);
        let drop = set(&["phone"]);
        let scope = FilterScope {
            types: Some(&keep),
            types_exclude: Some(&drop),
            drop_self_reference: false,
        };
        assert!(scope.admits(&pm("x", "phone", 0, 1)));
        assert!(!scope.admits(&pm("x", "medical", 0, 1)));
    }

    #[test]
    fn drops_self_reference_only_when_flagged() {
        let on = FilterScope { types: None, types_exclude: None, drop_self_reference: true };
        let off = FilterScope { types: None, types_exclude: None, drop_self_reference: false };
        assert!(!on.admits(&pm("我们", "self_reference", 0, 2)));
        assert!(off.admits(&pm("我们", "self_reference", 0, 2)));
    }

    #[test]
    fn no_loss_returns_the_filtered_list_untouched() {
        let pre = vec![pm("13800138000", "phone", 15, 26)];
        let merged = pre.clone();
        let scope = FilterScope { types: None, types_exclude: None, drop_self_reference: false };
        let (out, restored) =
            restore_lost_coverage(&pre, &spans(&merged), merged.clone(), &scope, "irrelevant");
        assert_eq!(out, merged);
        assert!(restored.is_empty());
    }

    #[test]
    fn restores_a_phone_absorbed_by_a_dropped_self_reference() {
        // Variant A: an L3 self_reference span swallows the L1 phone, then the
        // tier filter drops the winner.
        let phone = pm("13800138000", "phone", 15, 26);
        let sr = pm("number 13800138000", "self_reference", 8, 26);
        let pre = vec![phone.clone(), sr.clone()];
        let merged = vec![sr];              // merge picked the priority span
        let filtered: Vec<PatternMatch> = vec![]; // tier filter dropped it
        let scope = FilterScope { types: None, types_exclude: None, drop_self_reference: true };
        let (out, restored) = restore_lost_coverage(
            &pre,
            &spans(&merged),
            filtered,
            &scope,
            "Contact number 13800138000 for details",
        );
        assert_eq!(out, vec![phone]);
        assert_eq!(restored, vec!["phone".to_string()]);
    }

    #[test]
    fn restores_a_phone_absorbed_by_a_type_filtered_winner() {
        // Variant B: a benign coarse L3 `medical` span swallows the phone, then
        // `types=["phone"]` drops the winner.
        let phone = pm("13800138000", "phone", 15, 26);
        let med = pm("number 13800138000", "medical", 8, 26);
        let pre = vec![phone.clone(), med.clone()];
        let merged = vec![med];
        let filtered: Vec<PatternMatch> = vec![];
        let keep = set(&["phone"]);
        let scope =
            FilterScope { types: Some(&keep), types_exclude: None, drop_self_reference: false };
        let (out, restored) = restore_lost_coverage(
            &pre,
            &spans(&merged),
            filtered,
            &scope,
            "Contact number 13800138000 for details",
        );
        assert_eq!(out, vec![phone]);
        assert_eq!(restored, vec!["phone".to_string()]);
    }

    #[test]
    fn never_restores_what_the_merge_itself_trimmed() {
        // A false-positive `person` the merge legitimately absorbed into an
        // `address` must NOT come back — this is the condition that keeps the
        // invariant golden-neutral on ordinary text.
        let fp = pm("于江苏省", "person", 58, 62);
        let addr = pm("江苏省南京市鼓楼区1号", "address", 59, 70);
        let pre = vec![fp, addr.clone()];
        let merged = vec![addr.clone()];   // `fp` is NOT covered by `addr` (58 < 59)
        let filtered = vec![addr.clone()];
        let scope = FilterScope { types: None, types_exclude: None, drop_self_reference: false };
        let (out, restored) =
            restore_lost_coverage(&pre, &spans(&merged), filtered, &scope, "irrelevant");
        assert_eq!(out, vec![addr]);
        assert!(restored.is_empty());
    }

    #[test]
    fn never_restores_an_entity_the_filter_itself_excludes() {
        // The self_reference filter is MEANT to drop self_reference spans;
        // re-admitting them would defeat it.
        let sr = pm("我们", "self_reference", 11, 13);
        let pre = vec![sr.clone()];
        let merged = vec![sr];
        let filtered: Vec<PatternMatch> = vec![];
        let scope = FilterScope { types: None, types_exclude: None, drop_self_reference: true };
        let (out, restored) =
            restore_lost_coverage(&pre, &spans(&merged), filtered, &scope, "irrelevant");
        assert!(out.is_empty());
        assert!(restored.is_empty());
    }

    #[test]
    fn restored_types_are_sorted_and_deduplicated() {
        let phone = pm("13800138000", "phone", 15, 26);
        let id = pm("110101199003074610", "id_number", 30, 48);
        let phone2 = pm("13900139000", "phone", 55, 66);
        let big = pm("all of it", "medical", 0, 70);
        let pre = vec![phone, id, phone2, big.clone()];
        let merged = vec![big];
        let keep = set(&["phone", "id_number"]);
        let scope =
            FilterScope { types: Some(&keep), types_exclude: None, drop_self_reference: false };
        let (out, restored) = restore_lost_coverage(
            &pre,
            &spans(&merged),
            vec![],
            &scope,
            "x".repeat(70).as_str(),
        );
        assert_eq!(restored, vec!["id_number".to_string(), "phone".to_string()]);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn from_hints_drops_self_reference_except_at_tier_1() {
        // Mirrors `filter_self_reference`: tier 1 keeps self_reference, every
        // other tier drops it, and no tier hint at all is treated as "not
        // tier 1" — drop.
        let tier1 = FilterScope::from_hints(None, None, &[srt(1)]);
        assert!(!tier1.drop_self_reference);

        for tier in [2u8, 3u8] {
            let scope = FilterScope::from_hints(None, None, &[srt(tier)]);
            assert!(scope.drop_self_reference, "tier {tier} should drop self_reference");
        }

        let no_hint = FilterScope::from_hints(None, None, &[]);
        assert!(no_hint.drop_self_reference);
    }

    #[test]
    fn from_hints_passes_types_and_types_exclude_through_unchanged() {
        let keep = set(&["phone"]);
        let scope = FilterScope::from_hints(Some(&keep), None, &[]);
        assert!(scope.admits(&pm("x", "phone", 0, 1)));
        assert!(!scope.admits(&pm("x", "medical", 0, 1)));

        let drop = set(&["medical"]);
        let scope = FilterScope::from_hints(None, Some(&drop), &[]);
        assert!(scope.admits(&pm("x", "phone", 0, 1)));
        assert!(!scope.admits(&pm("x", "medical", 0, 1)));
    }

    #[test]
    fn admits_all_is_true_only_when_every_entity_is_admitted() {
        let keep = set(&["phone"]);
        let type_scope =
            FilterScope { types: Some(&keep), types_exclude: None, drop_self_reference: false };
        assert!(type_scope.admits_all(&[pm("x", "phone", 0, 1), pm("y", "phone", 2, 3)]));
        // Type-filter reason: `medical` is not in the keep-list.
        assert!(!type_scope.admits_all(&[pm("x", "phone", 0, 1), pm("y", "medical", 2, 3)]));

        let sr_scope = FilterScope { types: None, types_exclude: None, drop_self_reference: true };
        assert!(sr_scope.admits_all(&[pm("x", "phone", 0, 1)]));
        // Self-reference reason.
        assert!(!sr_scope.admits_all(&[pm("x", "phone", 0, 1), pm("我们", "self_reference", 2, 4)]));
    }

    #[test]
    fn admits_all_true_on_pre_merge_guarantees_restore_is_a_no_op() {
        // This is the property a caller's fast path relies on: if `admits_all`
        // is true for the pre-merge set, no filter configured by that same
        // scope can drop a merge winner, so running the full restore path
        // anyway must find nothing to restore. If this ever fails, the fast
        // path is unsound: it would skip the pre-merge snapshot on inputs
        // where coverage can still be lost.
        let phone = pm("13800138000", "phone", 15, 26);
        let id = pm("110101199003074610", "id_number", 30, 48);
        let pre = vec![phone.clone(), id.clone()];
        let scope = FilterScope { types: None, types_exclude: None, drop_self_reference: false };
        assert!(scope.admits_all(&pre));

        // Nothing the filters legitimately remove, so the filtered set is
        // whatever the merge produced, untouched.
        let merged = pre.clone();
        let filtered = merged.clone();
        let (out, restored) =
            restore_lost_coverage(&pre, &spans(&merged), filtered.clone(), &scope, "irrelevant");
        assert_eq!(out, filtered);
        assert!(restored.is_empty());
    }
}
