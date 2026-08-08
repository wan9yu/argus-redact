//! Bounded, lazy fan-out candidate generator for ambiguous digit glyphs.
//!
//! `normalize_core` collapses input to one canonical char sequence, so a glyph
//! that is genuinely ambiguous — could this be part of a hidden number, or is
//! it a harmless neighbour? — gets exactly one irreversible reading. This
//! module identifies those ambiguous positions and derives a cheap, bounded set
//! of alternate ("keep") readings so detection can be run against more than one
//! view of the text. The invariant this serves: **detection recall is a
//! superset over admissible readings** — a value is detected if it is
//! detectable under ANY reading of its ambiguous characters.
//!
//! This module is the *generator* only — it does not run detection itself.
//! [`crate::redact_l1::detect_l1`] (step 3b) is the consumer: it builds each
//! candidate view from this module's primitives, runs `match_patterns` over
//! it, and unions any span the base reading did not already claim.
//!
//! ## Ambiguous position, precisely
//!
//! Scanning proceeds over maximal "digit-ish" runs — anchored by a genuine
//! (`is_plain_digit_char`) or exotic (`is_nfkc_digit_yielding_non_decimal`)
//! digit, bridged across interior separators (`is_digit_sep`), exactly the run
//! shape `normalize::suppressed_nfkc_folds` already scans. Within/around such a
//! run, a position is ambiguous when it is an **exotic digit-yielder** (`¹`,
//! `⑧`, …) inside the run, or a **CJK digit-yielder** (`cn_digit`, e.g. `三`)
//! immediately leading or trailing it — both have two readings: the original
//! glyph (KEEP) or its ASCII-digit fold (the alternate reading). A digit
//! separator only bridges the run; it is never itself ambiguous, because
//! folding one is a no-op (see [`fold_glyph_same_len`]) — its keep reading and
//! its fold reading are the same string, so flagging it would waste a fan-out
//! slot on a candidate identical to one already tried.
//!
//! A char that is a digit-yielder but has no digit run anywhere near it (a
//! lone `三` in `三月三日`, an isolated `¹` in running prose) is not ambiguous —
//! there is nothing for it to fuse with, so there is only one admissible
//! reading and no fan-out is generated.
use crate::normalize::{
    cn_digit, is_digit_sep, is_nfkc_digit_yielding_non_decimal, is_plain_digit_char,
};
use unicode_normalization::UnicodeNormalization;

/// Hard cap on how many ambiguous positions a single call will report / fan out
/// over. Real tokens carry 0–1 ambiguous positions; this bounds the pathological
/// case (an adversarial run of dozens of exotic glyphs) to at most
/// `2^MAX_FANOUT_POSITIONS` candidates downstream. Beyond the cap, the caller
/// falls back to the two all-fold / all-keep extremes (still cannot leak) —
/// that fallback is wired in the caller, not here.
pub(crate) const MAX_FANOUT_POSITIONS: usize = 4;

/// A digit-ish char for the purpose of anchoring/continuing a run: a genuine
/// digit or an exotic (No/So) digit-yielder. `cn_digit` chars are deliberately
/// EXCLUDED from this — they only ever become ambiguous as a leading/trailing
/// neighbour of a run anchored by a real or exotic digit (see module docs);
/// treating a lone CJK numeral as its own anchor would flag ordinary Chinese
/// prose (dates, counts) that has no adjacent number to fuse with.
fn is_run_anchor(c: char) -> bool {
    is_nfkc_digit_yielding_non_decimal(c) || is_plain_digit_char(c)
}

/// Indices of ambiguous positions in `chars`, ascending, capped at
/// [`MAX_FANOUT_POSITIONS`] (the first ones encountered, left to right), plus
/// whether the cap actually truncated a longer list. A caller cannot tell
/// "exactly [`MAX_FANOUT_POSITIONS`] ambiguous positions" from "more existed
/// and got cut off" from the `Vec` length alone, so the second element is the
/// real signal for that distinction.
///
/// See the module docs for exactly what counts as ambiguous. `chars` is the
/// `normalize_core` intermediate (post invisible-strip / accent-fold /
/// confusables / per-char NFKC) — the same view [`crate::normalize::normalize_core`]
/// produces, before any digit-sequence fold.
pub(crate) fn ambiguous_positions(chars: &[char]) -> (Vec<usize>, bool) {
    let n = chars.len();
    let mut positions: Vec<usize> = Vec::new();
    let mut i = 0;
    while i < n {
        if !is_run_anchor(chars[i]) {
            i += 1;
            continue;
        }
        let run_start = i;
        let mut last_anchor_idx = i;
        while i < n {
            if is_nfkc_digit_yielding_non_decimal(chars[i]) {
                positions.push(i); // exotic member of the run
                last_anchor_idx = i;
                i += 1;
            } else if is_plain_digit_char(chars[i]) {
                last_anchor_idx = i;
                i += 1;
            } else if is_digit_sep(chars[i]) {
                // A separator bridges the run (matching normalize::suppressed_nfkc_folds's
                // run shape) but is never itself ambiguous — see the module docs for why
                // flagging it would only waste a fan-out slot.
                i += 1;
            } else {
                break;
            }
        }
        // A CJK digit-yielder immediately LEADING the run (e.g. 三 in
        // 张三13800138000) is ambiguous: keep it as a name/word char, or fold
        // it into the run it is butting up against.
        if run_start > 0 && cn_digit(chars[run_start - 1]).is_some() {
            positions.push(run_start - 1);
        }
        // Symmetric TRAILING case.
        if last_anchor_idx + 1 < n && cn_digit(chars[last_anchor_idx + 1]).is_some() {
            positions.push(last_anchor_idx + 1);
        }
    }
    positions.sort_unstable();
    positions.dedup();
    let truncated = positions.len() > MAX_FANOUT_POSITIONS;
    if truncated {
        positions.truncate(MAX_FANOUT_POSITIONS);
    }
    (positions, truncated)
}

/// Best-effort SAME-LENGTH digit fold for a single ambiguous glyph: the
/// common case (superscript/subscript/circled single digits, CN digits) is
/// exactly one source char folding to exactly one ASCII digit, so it can be
/// substituted in place without touching the surrounding offsets.
///
/// A minority of the exotic table NFKC-folds to MULTIPLE chars (vulgar
/// fractions `½` → `"1⁄2"`, parenthesised digits `⑴` → `"(1)"`, CJK compat
/// month/hour/day symbols `㋀` → `"1月"`). Those cannot be represented as a
/// position-preserving substitution, so this helper returns such a glyph
/// UNCHANGED rather than corrupt or resize the buffer. This is a KNOWN,
/// currently UNADDRESSED limitation: nothing in this crate recovers a number
/// that only fuses through one of these multi-char folds — there is no
/// length-changing "fold everything" pass for this case (contrast
/// [`fusion_boundary_variant`], which does rebuild the buffer, but to
/// re-insert a stripped boundary, not to expand a multi-char digit fold).
fn fold_glyph_same_len(c: char) -> char {
    if let Some(d) = cn_digit(c) {
        return d;
    }
    if is_nfkc_digit_yielding_non_decimal(c) {
        let mut folded = c.nfkc();
        if let (Some(first), None) = (folded.next(), folded.next()) {
            return first;
        }
    }
    c
}

/// The candidate TEXT with position `pos` forced to its KEEP reading —
/// exotic/CJK-digit-yielder left as its original glyph — while every OTHER
/// ambiguous position stays at its alternate (fold) reading. One variant per
/// call: the caller iterates `ambiguous_positions`, calls this once per
/// position, uses the result, and moves to the next.
///
/// `fold_all` MUST be [`fold_all_variant`]'s output for the SAME `chars` /
/// `positions` (every ambiguous position already folded). Rather than
/// re-cloning `chars` and re-folding every OTHER position from scratch on
/// each call, this reuses that ONE buffer as scratch: it toggles the single
/// index `pos` back to its original glyph, collects the resulting `String`,
/// then restores `fold_all[pos]` to the fold-all reading before returning —
/// so the same buffer is ready for the caller's next position with no
/// re-clone and no re-fold of the positions that were already correct.
///
/// Length- and offset-preserving, same as [`fold_all_variant`]: the caller
/// reuses the base offset map unchanged for the returned text.
pub(crate) fn keep_variant_text(chars: &[char], fold_all: &mut [char], pos: usize) -> String {
    let folded = fold_all[pos];
    fold_all[pos] = chars[pos]; // toggle pos to its KEEP reading
    let text: String = fold_all.iter().collect();
    fold_all[pos] = folded; // restore the fold-all reading for the next call
    text
}

/// The intermediate with EVERY ambiguous position folded to its ASCII-digit
/// reading — the aggressive "all homographs are part of the number" candidate
/// that recovers an interior exotic (`13⑧00138000`) or a CJK homograph fused
/// into a run (`13八00138000`). Length-PRESERVING: only single-char folds are
/// applied (`fold_glyph_same_len`), so the shared offset map still addresses the
/// same source indices — multi-char and separator positions are left as-is,
/// exactly as [`keep_variant_text`] does.
///
/// `positions` is the caller's ALREADY-COMPUTED [`ambiguous_positions`] (see
/// [`keep_variant_text`] for why it is passed in rather than recomputed).
pub(crate) fn fold_all_variant(chars: &[char], positions: &[usize]) -> Vec<char> {
    let mut out: Vec<char> = chars.to_vec();
    for &idx in positions {
        out[idx] = fold_glyph_same_len(chars[idx]);
    }
    out
}

/// A digit-ish char for the fusion-gap neighbour test: a run anchor (genuine or
/// exotic digit) OR a CJK digit homograph. A stripped invisible is a "number
/// fusion" risk only when it sat directly between two such chars.
fn is_digit_ish(c: char) -> bool {
    is_run_anchor(c) || cn_digit(c).is_some()
}

/// The "keep-boundary" candidate: re-insert a boundary wherever
/// [`crate::normalize::normalize_core`] stripped one or more invisibles from
/// BETWEEN two digit-ish chars (a gap in `omap`).
///
/// The base/primary view treats a stripped invisible as noise, fusing its two
/// neighbours into one run — which can HIDE a number the reader sees as bounded
/// (`13800138000͏2024` → `138001380002024`, or two phones joined into an
/// unbounded 22-digit run). This candidate reads each such invisible as the
/// boundary it renders as, so the fused number regains its `(?<!\d)`/`(?!\d)`
/// anchors and is detected. It only ever ADDS readings (unioned by the caller),
/// so it cannot suppress the fused reading the base already provides.
///
/// Length-CHANGING, so the offset map is REBUILT: every surviving char keeps its
/// original index; each inserted boundary maps to the original index of the
/// first invisible it stands in for (so a match ending just before it maps back
/// to exactly the original digits, not the invisible). Returns `None` when there
/// is no qualifying gap — the common case, so the caller runs no extra pass.
pub(crate) fn fusion_boundary_variant(
    chars: &[char],
    omap: &[usize],
) -> Option<(Vec<char>, Vec<usize>)> {
    let n = chars.len();
    debug_assert_eq!(n, omap.len());
    // One O(n) scan collects every qualifying gap index; the rebuild below reuses
    // this list instead of re-testing the same jump/digit-ish condition per char.
    // Also doubles as the "bail with no allocation" pre-check: an empty list means
    // text that normalized with nothing stripped between digits, the common case,
    // costs one scan and no rebuild.
    let gaps: Vec<usize> = (0..n.saturating_sub(1))
        .filter(|&i| {
            omap[i + 1] > omap[i] + 1 && is_digit_ish(chars[i]) && is_digit_ish(chars[i + 1])
        })
        .collect();
    if gaps.is_empty() {
        return None;
    }
    let mut out_chars: Vec<char> = Vec::with_capacity(n + gaps.len());
    let mut out_map: Vec<usize> = Vec::with_capacity(n + gaps.len());
    let mut gaps = gaps.into_iter().peekable();
    for i in 0..n {
        out_chars.push(chars[i]);
        out_map.push(omap[i]);
        // A jump in the original index means invisibles were stripped here.
        if gaps.peek() == Some(&i) {
            gaps.next();
            out_chars.push(' '); // a pure boundary the digit regexes cannot cross
            out_map.push(omap[i] + 1); // original index of the first stripped invisible
        }
    }
    Some((out_chars, out_map))
}

#[cfg(test)]
mod tests {
    #[test]
    fn ambiguous_positions_flags_edge_exotic_and_between_digit_ignorable() {
        let chars: Vec<char> = "13800138000\u{b9}".chars().collect();
        assert_eq!(super::ambiguous_positions(&chars).0, vec![11]); // the ¹
        let chars: Vec<char> = "13\u{2467}00138000".chars().collect();
        assert_eq!(super::ambiguous_positions(&chars).0, vec![2]); // the ⑧
        let chars: Vec<char> = "abc".chars().collect();
        assert!(super::ambiguous_positions(&chars).0.is_empty()); // no fan-out in prose
    }

    #[test]
    fn fanout_is_bounded() {
        let chars: Vec<char> = "1\u{2467}2\u{2467}3\u{2467}4\u{2467}5\u{2467}6\u{2467}"
            .chars()
            .collect(); // >4 exotics
        let (positions, truncated) = super::ambiguous_positions(&chars);
        assert!(positions.len() <= super::MAX_FANOUT_POSITIONS);
        // More than MAX_FANOUT_POSITIONS ambiguous positions existed, so the flag
        // must say so — this is the case the plain length check cannot distinguish
        // from "exactly the cap, nothing truncated".
        assert!(truncated);
    }

    #[test]
    fn ambiguous_positions_ignores_separator_not_between_digits() {
        // '.' preceded by a letter — not between two digits, not ambiguous.
        let chars: Vec<char> = "abc.123".chars().collect();
        assert!(super::ambiguous_positions(&chars).0.is_empty());
        // '.' followed by a letter — same, from the other side.
        let chars: Vec<char> = "123.abc".chars().collect();
        assert!(super::ambiguous_positions(&chars).0.is_empty());
    }

    // ── Author's own tests: CJK digit-yielder leading/trailing a run ───────

    #[test]
    fn ambiguous_positions_flags_leading_cjk_homograph() {
        // 三 (idx 1) butts up against an 11-digit ASCII run: could be the
        // name char 张三, or fold into "313800138000".
        let chars: Vec<char> = "张三13800138000".chars().collect();
        assert_eq!(super::ambiguous_positions(&chars).0, vec![1]);
    }

    #[test]
    fn ambiguous_positions_flags_trailing_cjk_homograph() {
        let chars: Vec<char> = "13800138000三".chars().collect();
        assert_eq!(super::ambiguous_positions(&chars).0, vec![11]);
    }

    #[test]
    fn ambiguous_positions_flags_cjk_homograph_bridging_two_runs() {
        // 三 sits between two separate 11-digit ASCII runs — trailing to the
        // first, leading to the second; must be reported exactly once.
        let mut s = String::from("13800138000");
        s.push('三');
        s.push_str("13900139000");
        let chars: Vec<char> = s.chars().collect();
        assert_eq!(super::ambiguous_positions(&chars).0, vec![11]);
    }

    #[test]
    fn ambiguous_positions_ignores_isolated_cjk_numeral_with_no_adjacent_run() {
        // 三月三日 ("March 3rd"): each 三 is flanked by ordinary Han characters,
        // never by a real/exotic digit run — nothing to fuse with, so no
        // fan-out. Regression guard against flagging ordinary Chinese prose.
        let chars: Vec<char> = "三月三日".chars().collect();
        assert!(super::ambiguous_positions(&chars).0.is_empty());
    }

    // ── Author's own tests: keep_variant_text ───────────────────────────

    #[test]
    fn keep_variant_text_forces_pos_to_keep_and_folds_the_rest() {
        // Two ambiguous positions: the exotic ⑧ (interior) and the exotic ¹
        // (trailing).
        let chars: Vec<char> = "13\u{2467}001380\u{b9}".chars().collect();
        let (positions, _truncated) = super::ambiguous_positions(&chars);
        assert_eq!(positions.len(), 2);
        let pos = positions[0]; // the ⑧

        let mut fold_all = super::fold_all_variant(&chars, &positions);
        let text = super::keep_variant_text(&chars, &mut fold_all, pos);
        let kept: Vec<char> = text.chars().collect();

        // The forced position keeps its original (unfolded) glyph.
        assert_eq!(kept[pos], chars[pos]);
        // Every OTHER ambiguous position takes the fold reading.
        for &idx in &positions {
            if idx != pos {
                assert_ne!(kept[idx], chars[idx]);
                assert!(kept[idx].is_ascii_digit());
            }
        }
        // Non-ambiguous positions are untouched.
        assert_eq!(kept[0], chars[0]);
        assert_eq!(kept[1], chars[1]);
        // Position-preserving: same length as the source.
        assert_eq!(kept.len(), chars.len());
        // The scratch buffer is restored to the fold-all reading afterwards, so a
        // caller looping over positions can reuse it for the next one.
        assert_eq!(fold_all, super::fold_all_variant(&chars, &positions));
    }

    #[test]
    fn keep_variant_text_folds_a_cjk_homograph_when_it_is_not_the_forced_position() {
        // Leading AND trailing CJK homographs around one ASCII run.
        let mut s = String::from("三");
        s.push_str("13800138000");
        s.push('三');
        let chars: Vec<char> = s.chars().collect();
        let (positions, _truncated) = super::ambiguous_positions(&chars);
        assert_eq!(positions, vec![0, 12]);

        // Force the LEADING 三 to its keep reading; the trailing one folds.
        let mut fold_all = super::fold_all_variant(&chars, &positions);
        let text = super::keep_variant_text(&chars, &mut fold_all, 0);
        let kept: Vec<char> = text.chars().collect();
        assert_eq!(kept[0], '三'); // forced position: unchanged
        assert_eq!(kept[12], '3'); // the other ambiguous position: folded
        // The digit run itself is untouched either way.
        assert_eq!(&kept[1..12], &chars[1..12]);
    }

    #[test]
    fn keep_variant_text_is_a_noop_when_there_is_only_one_ambiguous_position() {
        let chars: Vec<char> = "13800138000\u{b9}".chars().collect();
        let (positions, _truncated) = super::ambiguous_positions(&chars);
        let mut fold_all = super::fold_all_variant(&chars, &positions);
        let text = super::keep_variant_text(&chars, &mut fold_all, 11);
        let kept: Vec<char> = text.chars().collect();
        assert_eq!(kept, chars); // nothing else to fold
    }

    // ── fold_all_variant: every homograph read into the number ─────────────

    #[test]
    fn fold_all_variant_folds_every_exotic_and_homograph() {
        // Interior exotic ⑧ → 8.
        let chars: Vec<char> = "13\u{2467}00138000".chars().collect();
        let (p, _truncated) = super::ambiguous_positions(&chars);
        let folded: String = super::fold_all_variant(&chars, &p).into_iter().collect();
        assert_eq!(folded, "13800138000");
        // Trailing CJK homograph 八 → 8.
        let chars: Vec<char> = "13八00138000".chars().collect();
        let (p, _truncated) = super::ambiguous_positions(&chars);
        let folded: String = super::fold_all_variant(&chars, &p).into_iter().collect();
        assert_eq!(folded, "13800138000");
        // No ambiguity → identity.
        let chars: Vec<char> = "13800138000".chars().collect();
        let (p, _truncated) = super::ambiguous_positions(&chars);
        assert_eq!(super::fold_all_variant(&chars, &p), chars);
    }

    // ── fusion_boundary_variant: re-insert a stripped invisible as a boundary ─

    #[test]
    fn fusion_boundary_variant_reinserts_boundary_at_a_digit_gap() {
        // chars = post-strip "13800138000" + "2024"; an invisible was stripped at
        // original index 11 (the gap in omap). The candidate re-inserts a boundary
        // so the 11-digit phone regains its trailing anchor.
        let chars: Vec<char> = "138001380002024".chars().collect();
        let omap: Vec<usize> = (0..11).chain(12..16).collect(); // gap at original 11
        let (fchars, fmap) =
            super::fusion_boundary_variant(&chars, &omap).expect("a digit gap exists");
        let s: String = fchars.iter().collect();
        assert_eq!(s, "13800138000 2024");
        assert_eq!(fmap.len(), fchars.len());
        // The inserted boundary maps to the original index of the stripped invisible.
        assert_eq!(fmap[11], 11);
        // The digit right after it keeps its original index (12).
        assert_eq!(fmap[12], 12);
    }

    #[test]
    fn fusion_boundary_variant_none_without_a_qualifying_gap() {
        // Contiguous omap → nothing stripped → no candidate.
        let chars: Vec<char> = "13800138000".chars().collect();
        let omap: Vec<usize> = (0..11).collect();
        assert!(super::fusion_boundary_variant(&chars, &omap).is_none());
        // A gap between NON-digits (an email split by an invisible) is not a
        // number-fusion risk — the base stripped view already reads it as one token.
        let chars: Vec<char> = "ab".chars().collect();
        let omap: Vec<usize> = vec![0, 2]; // gap at original 1, but neighbours are letters
        assert!(super::fusion_boundary_variant(&chars, &omap).is_none());
    }

    // ── Author's own test: the documented multi-char-fold limitation ───────

    #[test]
    fn fold_glyph_same_len_leaves_multi_char_folds_unchanged() {
        // ½ (U+00BD) NFKC-folds to the THREE-char "1⁄2" — not representable
        // as a same-length substitution, so the helper must return it as-is.
        assert_eq!(super::fold_glyph_same_len('\u{bd}'), '\u{bd}');
        // Contrast: ⑧ (single-char fold) and 三 (CN digit) DO fold.
        assert_eq!(super::fold_glyph_same_len('\u{2467}'), '8');
        assert_eq!(super::fold_glyph_same_len('三'), '3');
        // An ordinary ASCII digit or letter passes through untouched.
        assert_eq!(super::fold_glyph_same_len('5'), '5');
        assert_eq!(super::fold_glyph_same_len('a'), 'a');
    }
}
