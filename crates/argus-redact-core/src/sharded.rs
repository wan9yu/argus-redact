//! A longest-first literal-alternation matcher that stays LINEAR in the number
//! of keys.
//!
//! Every key-driven scan in this crate — restore substitution, the
//! `tokens_present` scope report, the display-marker mark/strip pair — used to
//! build ONE `fancy_regex` alternation over the whole key set. `fancy_regex`
//! compiles a backtracking program whose per-key cost grows once the alternation
//! passes a few thousand branches, so a key with tens of thousands of entries
//! (a long document redacted entity-by-entity, a bulk CSV job) paid a
//! super-linear compile before a single byte of text was scanned.
//!
//! `ShardedMatcher` splits the key set into shards of at most
//! [`MAX_KEYS_PER_SHARD`] keys, compiles one bounded alternation per shard, and
//! merges the per-shard results with the SAME rule the single alternation
//! implemented implicitly:
//!
//!   * leftmost match wins (the engine scans positions left to right), then
//!   * at an equal start, the LONGEST key wins (which is why every call site
//!     sorted longest-first before building its pattern).
//!
//! The longest-first sort now lives in [`ShardedMatcher::new`] instead of being
//! re-derived at each call site, so the ordering invariant cannot drift between
//! the mark and strip halves of the display-marker pair, or between
//! `restore_full` and `RestoreSession`.

use fancy_regex::Regex;

use crate::reserved_range::{escaped_alternation, escaped_alternation_digit_bounded};

/// Maximum literal keys compiled into a single alternation.
///
/// Sharding is a TRADE, and this constant is where it is priced. Splitting the
/// key set bounds the compile (the win) but multiplies the text scan by the
/// shard count (the cost), because every shard must be searched at each
/// position to find the leftmost match. So:
///
///   * too small → key sets that never had a compile problem pay a scan tax;
///   * too large → the compile blow-up survives inside a shard.
///
/// 4096 was picked by measuring BOTH sides on the same build. Against a
/// prefix-chained key (`P-0`…`P-59999`, the shape that actually goes quadratic),
/// a one-shot restore at 15k/30k/60k keys went 0.166/0.619/2.362 s unsharded →
/// 0.027/0.055/0.112 s here: quadratic (3.8x per doubling) to linear (2.05x),
/// 21x at 60k. Against key sets that never blew up (uniform-length codes, and a
/// 130k-char text with a mid-size key — the scan-multiplied worst case), the
/// same build stays within 6% of unsharded, where 1024 cost up to 44%.
///
/// Tests pin the BOUND (no shard may exceed the constant), not this value, so
/// re-tuning is a one-line change plus a re-measure.
pub(crate) const MAX_KEYS_PER_SHARD: usize = 4096;

/// How each key is fenced inside its alternation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Bound {
    /// Bare literals (display-marker mark/strip).
    None,
    /// All-digit keys get `(?<!\d)…(?!\d)` (restore substitution) — see
    /// `escaped_alternation_digit_bounded`.
    Digit,
    /// The whole alternation is fenced by `[A-Za-z0-9_-]` lookarounds so a
    /// pseudonym cannot match inside a longer pseudonym-shaped run
    /// (`tokens_present`).
    PseudonymToken,
}

/// A compiled, longest-first literal matcher over an arbitrary number of keys.
#[derive(Debug)]
pub(crate) struct ShardedMatcher {
    shards: Vec<Regex>,
}

/// The `Bound → alternation pattern` mapping for one shard's `chunk`. The single
/// source shared by [`ShardedMatcher::new`] and the differential-test oracle so
/// the oracle cannot drift from the production pattern it pins.
fn pattern_for(bound: Bound, chunk: &[&str]) -> String {
    match bound {
        Bound::None => escaped_alternation(chunk),
        Bound::Digit => escaped_alternation_digit_bounded(chunk),
        Bound::PseudonymToken => {
            let alt = escaped_alternation(chunk);
            format!(r"(?<![A-Za-z0-9_-])(?:{alt})(?![A-Za-z0-9_-])")
        }
    }
}

impl ShardedMatcher {
    /// Compile `keys` (any order, duplicates tolerated) into shards.
    ///
    /// Sorting happens HERE: keys are ordered longest-first before sharding, so
    /// a longer key always sits earlier in its own shard's alternation, and the
    /// cross-shard merge in [`ShardedMatcher::find_iter`] restores the same
    /// preference between shards.
    pub(crate) fn new<S: AsRef<str>>(keys: &[S], bound: Bound) -> Result<Self, String> {
        let mut ordered: Vec<&str> = keys.iter().map(|k| k.as_ref()).collect();
        // `sort_by` (stable) on descending byte length — identical to the
        // `sort_by(|a, b| b.len().cmp(&a.len()))` every call site ran itself.
        ordered.sort_by(|a, b| b.len().cmp(&a.len()));

        let mut shards = Vec::with_capacity(ordered.len().div_ceil(MAX_KEYS_PER_SHARD).max(1));
        for chunk in ordered.chunks(MAX_KEYS_PER_SHARD) {
            let pattern = pattern_for(bound, chunk);
            shards.push(Regex::new(&pattern).map_err(|e| e.to_string())?);
        }
        Ok(ShardedMatcher { shards })
    }

    /// True when there is nothing to match (empty key set).
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }

    /// The first match at or after byte offset `pos`, as `(start, end)`.
    ///
    /// Merge rule — exactly the single alternation's implicit one:
    /// smallest `start` wins; at an equal `start` the largest `end` wins.
    ///
    /// A match-time error in any shard (backtrack/size limit) stops the search
    /// and reports "no match", mirroring the `Err(_) => break` every one of the
    /// pre-sharding scan loops already used.
    ///
    /// This scans EVERY shard from `pos` on each call; [`ShardedMatcher::find_iter`]
    /// used to drive it in a loop and paid for that quadratically. The lazy
    /// per-shard cursor merge in `find_iter` replaced it in production, so this
    /// method is retained only as the differential-test oracle that pins the
    /// merge rule the cursor merge must reproduce byte-for-byte.
    #[cfg(test)]
    pub(crate) fn find_from_pos(&self, text: &str, pos: usize) -> Option<(usize, usize)> {
        let mut best: Option<(usize, usize)> = None;
        for shard in &self.shards {
            match shard.find_from_pos(text, pos) {
                Ok(Some(m)) => {
                    let cand = (m.start(), m.end());
                    best = Some(match best {
                        None => cand,
                        Some(cur) => {
                            if cand.0 < cur.0 {
                                cand
                            } else {
                                cur
                            }
                        }
                    });
                }
                Ok(None) => {}
                Err(_) => return None,
            }
        }
        best
    }

    /// Iterate every non-overlapping match, left to right.
    ///
    /// The iteration is a lazy K-way merge over one cursor per shard, LINEAR in
    /// the total regex work (O(total per-shard matches + shards)) rather than
    /// the O(shards · matches · text) the old `find_from_pos`-per-position loop
    /// paid: a shard with no further match now reports that ONCE (its cursor
    /// goes `Exhausted`) instead of re-scanning the whole remaining text at
    /// every step, and a shard whose next match lies far ahead is scanned to
    /// that match ONCE and cached until the merge consumes past it. The emitted
    /// `(start, end)` sequence is byte-identical to the old loop — see the
    /// differential test `linear_iter_matches_find_from_pos_driven_loop_*`.
    pub(crate) fn find_iter<'a>(&'a self, text: &'a str) -> ShardedMatches<'a> {
        ShardedMatches {
            matcher: self,
            text,
            pos: 0,
            fronts: vec![ShardFront::Uninit; self.shards.len()],
            done: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn shard_count(&self) -> usize {
        self.shards.len()
    }
}

/// One shard's cached leftmost match at or after the position it was last
/// scanned from — the cursor the merge advances lazily.
#[derive(Clone, Copy)]
enum ShardFront {
    /// Never scanned yet (freshly built iterator).
    Uninit,
    /// The shard's leftmost match `(start, end)` at or after its last scan
    /// position. Kept until the merge's global `pos` passes `start`, then
    /// re-scanned from the new `pos`.
    Match(usize, usize),
    /// The shard returned `Ok(None)` — no match at or after its scan position,
    /// which (scan positions only ever advance) means no match ever again.
    /// Never re-scanned: this is precisely the shard that made the old loop
    /// quadratic by re-scanning the tail at every step.
    Exhausted,
}

/// Iterator over [`ShardedMatcher::find_iter`].
///
/// K-way merge: each shard keeps a lazily-advanced `ShardFront` cursor; each
/// `next` refreshes only the cursors the last emission consumed past, then
/// emits the front with the SMALLEST start (ties resolved to the earliest
/// shard — which, under the longest-first sharding, is the longest key: the
/// exact rule the pre-cursor `find_from_pos` merge applied).
///
/// The emitted `(start, end)` sequence is byte-identical to the old
/// `find_from_pos`-driven loop, in two legs proven by different means:
///
///   * MATCH-PICKING — which spans are emitted and in what order — is exercised
///     DIRECTLY by the randomized multi-shard differential test
///     (`linear_iter_matches_find_from_pos_driven_loop_*`).
///   * ERROR-EARLY-STOP — a shard that errors (backtrack/size limit) when
///     scanned from the current `pos` ends the whole iteration, mirroring the
///     old `find_from_pos`'s `Err(_) => return None`. The MECHANISM is exercised
///     by `linear_iter_error_stop_is_identical_to_find_from_pos_driven_loop`,
///     which lowers a shard's `backtrack_limit` to force a real `Err`. That it
///     can never DIVERGE from the old loop — a cached front is not re-checked
///     for errors — rests on the argument below, NOT on the test.
///
/// Why a cached front need not be re-checked: a shard could only have cached a
/// match/exhaustion by scanning (without error) from an EARLIER position through
/// at least the current `pos` (its cached match starts at or after `pos`, or it
/// found nothing in the whole suffix). Re-scanning it from the later `pos` then
/// repeats a strict SUBSET of that already-error-free work, so it cannot newly
/// exceed the limit. This monotonicity holds specifically because fancy-regex
/// (workspace pin `= "0.17"`) counts backtracking with a single cumulative
/// per-call counter over a left-to-right search — a shorter scan span can only
/// count fewer steps. A future bump that changed that counting could invalidate
/// this leg: the targeted error test guards the mechanism; this note guards the
/// dependency assumption it rests on.
pub(crate) struct ShardedMatches<'a> {
    matcher: &'a ShardedMatcher,
    text: &'a str,
    /// Global merge position: the next emitted match starts at or after here.
    pos: usize,
    /// One cursor per shard, index-aligned with `matcher.shards`.
    fronts: Vec<ShardFront>,
    /// Set once the iteration has ended (no match, or a shard errored) so
    /// further `next` calls stay `None` without re-scanning — the old loop
    /// stayed `None` too, since `pos` never advanced past a `None`.
    done: bool,
}

impl Iterator for ShardedMatches<'_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<(usize, usize)> {
        if self.done || self.pos > self.text.len() {
            return None;
        }

        // Refresh every cursor the previous emission consumed past (start <
        // pos), plus any not yet scanned. Exhausted cursors and cursors whose
        // cached match still starts at or after `pos` are left untouched — the
        // linear win. Iterating the shards in order and returning `None` on the
        // first error reproduces the old `find_from_pos`'s behaviour: any shard
        // erroring at this position ended the search regardless of other
        // shards' matches.
        for (i, shard) in self.matcher.shards.iter().enumerate() {
            let needs_rescan = match self.fronts[i] {
                ShardFront::Exhausted => false,
                ShardFront::Match(start, _) => start < self.pos,
                ShardFront::Uninit => true,
            };
            if needs_rescan {
                match shard.find_from_pos(self.text, self.pos) {
                    Ok(Some(m)) => self.fronts[i] = ShardFront::Match(m.start(), m.end()),
                    Ok(None) => self.fronts[i] = ShardFront::Exhausted,
                    Err(_) => {
                        self.done = true;
                        return None;
                    }
                }
            }
        }

        // Merge rule, identical to `find_from_pos`: smallest start wins; on an
        // equal start keep the EARLIER shard (longest key under the sort). The
        // in-order scan with a strict `<` keeps the earlier shard on a tie.
        let mut best: Option<(usize, usize)> = None;
        for front in &self.fronts {
            if let ShardFront::Match(start, end) = *front {
                best = Some(match best {
                    None => (start, end),
                    Some(cur) => {
                        if start < cur.0 {
                            (start, end)
                        } else {
                            cur
                        }
                    }
                });
            }
        }

        match best {
            None => {
                self.done = true;
                None
            }
            Some((start, end)) => {
                self.pos = if end > start { end } else { start + 1 };
                Some((start, end))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pre-sharding implementation, kept as a test-only ORACLE: one
    /// alternation over every key, longest-first. Every sharded result must
    /// equal what this produces.
    fn single_alternation(keys: &[String], bound: Bound) -> Regex {
        let mut ordered: Vec<&str> = keys.iter().map(|k| k.as_str()).collect();
        ordered.sort_by(|a, b| b.len().cmp(&a.len()));
        let pattern = pattern_for(bound, &ordered);
        Regex::new(&pattern).unwrap()
    }

    fn oracle_matches(re: &Regex, text: &str) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos <= text.len() {
            match re.find_from_pos(text, pos) {
                Ok(Some(m)) => {
                    out.push((m.start(), m.end()));
                    pos = if m.end() > m.start() { m.end() } else { m.start() + 1 };
                }
                _ => break,
            }
        }
        out
    }

    #[test]
    fn sharded_matcher_equals_single_alternation() {
        // Enough keys to force several shards, in all three bound styles.
        let keys: Vec<String> = (0..3000).map(|i| format!("P-{i}")).collect();
        let text: String = (0..3000)
            .step_by(7)
            .map(|i| format!("x P-{i} y "))
            .collect::<Vec<_>>()
            .join("");
        for bound in [Bound::None, Bound::Digit, Bound::PseudonymToken] {
            let sharded = ShardedMatcher::new(&keys, bound).unwrap();
            let oracle = single_alternation(&keys, bound);
            assert_eq!(
                sharded.find_iter(&text).collect::<Vec<_>>(),
                oracle_matches(&oracle, &text),
                "bound = {bound:?}"
            );
        }
    }

    #[test]
    fn longest_key_wins_across_shard_boundaries() {
        // "P-1" and "P-10" land in DIFFERENT shards (2 keys, shard size 1 would
        // be needed to force that generically, so instead pad the set until the
        // two provably split). The merge must still prefer the longer.
        let mut keys: Vec<String> = (0..MAX_KEYS_PER_SHARD + 5).map(|i| format!("K{i:09}")).collect();
        keys.push("P-1".to_string());
        keys.push("P-10".to_string());
        let m = ShardedMatcher::new(&keys, Bound::None).unwrap();
        assert!(m.shard_count() > 1, "test needs more than one shard");
        let text = "see P-10 here";
        assert_eq!(m.find_iter(text).collect::<Vec<_>>(), vec![(4, 8)]);
    }

    #[test]
    fn competing_keys_forced_into_different_shards_still_resolve_leftmost_longest() {
        // The test above ("longest_key_wins_across_shard_boundaries") does NOT
        // actually exercise the cross-shard merge for its two competing keys:
        // with MAX_KEYS_PER_SHARD + 5 filler keys of length 10 ahead of "P-10"
        // (len 4) and "P-1" (len 3), both of the short keys land in the SAME
        // trailing shard (shard 1 holds the last 5 fillers + "P-10" + "P-1"),
        // so the within-shard longest-first alternation order alone already
        // picks "P-10" — the cross-shard `find_from_pos` merge (the tie-break
        // at equal `start`) is never exercised by two DIFFERENT shards' results
        // actually competing for the same position.
        //
        // Force a genuine split: exactly MAX_KEYS_PER_SHARD - 1 filler keys
        // (length 10, sorting ahead of everything else) plus the long
        // competitor "abbbb" (length 5) fill shard 0 to EXACTLY its capacity
        // (MAX_KEYS_PER_SHARD), landing "abbbb" as the LAST key of shard 0. The
        // short competitor "a" (length 1, a strict prefix of "abbbb") is then
        // the very next key in sorted order, landing as the FIRST key of shard
        // 1 — a different shard from "abbbb".
        let mut keys: Vec<String> =
            (0..MAX_KEYS_PER_SHARD - 1).map(|i| format!("Q{i:09}")).collect();
        keys.push("abbbb".to_string());
        keys.push("a".to_string());
        assert_eq!(keys.len(), MAX_KEYS_PER_SHARD + 1);

        let m = ShardedMatcher::new(&keys, Bound::None).unwrap();
        assert_eq!(m.shard_count(), 2, "test setup must force exactly 2 shards");

        // Both "abbbb" (shard 0) and "a" (shard 1) start at position 0 of the
        // text below. A single unsharded alternation (longest-first) picks
        // "abbbb"; the sharded merge must reproduce that across the shard
        // boundary instead of taking whichever shard's candidate it saw last.
        let text = "abbbb";
        assert_eq!(m.find_iter(text).collect::<Vec<_>>(), vec![(0, 5)]);
    }

    #[test]
    fn leftmost_match_wins_across_shards() {
        // A later shard holding an EARLIER match must win over an earlier
        // shard's later match.
        let mut keys: Vec<String> = (0..MAX_KEYS_PER_SHARD).map(|i| format!("Z{i:09}")).collect();
        keys.push("bbbb".to_string()); // long → sorts into the first shard
        keys.push("a".to_string()); // short → sorts last
        let m = ShardedMatcher::new(&keys, Bound::None).unwrap();
        assert!(m.shard_count() > 1);
        let text = "a bbbb";
        assert_eq!(m.find_iter(text).collect::<Vec<_>>(), vec![(0, 1), (2, 6)]);
    }

    #[test]
    fn every_shard_respects_the_bound() {
        let keys: Vec<String> = (0..(MAX_KEYS_PER_SHARD * 3 + 1)).map(|i| format!("P-{i}")).collect();
        let m = ShardedMatcher::new(&keys, Bound::Digit).unwrap();
        assert_eq!(m.shard_count(), keys.len().div_ceil(MAX_KEYS_PER_SHARD));
    }

    #[test]
    fn empty_key_set_matches_nothing() {
        let m = ShardedMatcher::new::<String>(&[], Bound::None).unwrap();
        assert!(m.is_empty());
        assert_eq!(m.find_iter("anything").count(), 0);
    }

    #[test]
    fn digit_bound_still_fences_numeric_keys_after_sharding() {
        let mut keys: Vec<String> = (0..MAX_KEYS_PER_SHARD).map(|i| format!("Q{i:09}")).collect();
        keys.push("19999123456".to_string());
        let m = ShardedMatcher::new(&keys, Bound::Digit).unwrap();
        assert!(m.shard_count() > 1);
        // Inside a longer digit run the numeric key must NOT match.
        assert_eq!(m.find_iter("199991234560").count(), 0);
        assert_eq!(m.find_iter("call 19999123456 now").collect::<Vec<_>>(), vec![(5, 16)]);
    }

    // ── differential oracle: the find_from_pos-driven loop ──────────────────
    //
    // `find_iter` is a lazy K-way merge over per-shard cursors; this oracle is
    // the ORIGINAL iterator body, which re-invoked `find_from_pos` from every
    // advanced position (quadratic when a shard had no further match and
    // re-scanned the whole tail each step). `find_from_pos` is retained
    // verbatim, so this loop reproduces exactly what `ShardedMatches::next`
    // computed before the cursor rewrite — the merge order, the equal-start
    // tie-break, the empty-match `start + 1` step, and the
    // `find_from_pos` early-stop all flow through it. Every `find_iter` result
    // must be byte-identical to what this returns.
    fn find_from_pos_driven(m: &ShardedMatcher, text: &str) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos <= text.len() {
            match m.find_from_pos(text, pos) {
                Some((start, end)) => {
                    out.push((start, end));
                    pos = if end > start { end } else { start + 1 };
                }
                None => break,
            }
        }
        out
    }

    #[test]
    fn linear_iter_matches_find_from_pos_driven_loop_on_boundary_cases() {
        // Hand-picked edges: match at the very start / at the very end, adjacent
        // matches, competing prefixes across the longest-first order, digit
        // boundaries, empty text, no-match text, whole-text-is-a-key, CJK.
        struct Case {
            keys: &'static [&'static str],
            text: &'static str,
        }
        let cases = [
            Case { keys: &["P-1"], text: "" },                     // empty text
            Case { keys: &[], text: "P-1 here" },                  // empty key set
            Case { keys: &["P-1"], text: "P-1" },                  // whole text is the key
            Case { keys: &["P-1"], text: "P-1 tail" },             // match at start
            Case { keys: &["P-1"], text: "head P-1" },             // match at end
            Case { keys: &["P-1", "P-2"], text: "P-1P-2" },        // adjacent matches
            Case { keys: &["P-1", "P-10"], text: "P-10 and P-1" }, // longest-first prefix
            Case { keys: &["P-1", "P-10"], text: "P-1 and P-10" }, // reversed occurrence order
            Case { keys: &["a", "abbbb"], text: "abbbb a ab" },    // prefix competition
            Case { keys: &["19999123456"], text: "199991234560 19999123456" }, // digit bound
            Case { keys: &["P-1"], text: "nothing matches here" }, // no match at all
            Case { keys: &["张三", "李明"], text: "张三和李明张三" }, // CJK, repeated
        ];
        for bound in [Bound::None, Bound::Digit, Bound::PseudonymToken] {
            for c in &cases {
                let m = ShardedMatcher::new(c.keys, bound).unwrap();
                assert_eq!(
                    m.find_iter(c.text).collect::<Vec<_>>(),
                    find_from_pos_driven(&m, c.text),
                    "bound={bound:?} keys={:?} text={:?}",
                    c.keys,
                    c.text,
                );
            }
        }
    }

    #[test]
    fn linear_iter_matches_find_from_pos_driven_loop_over_randomized_multishard_inputs() {
        // Thousands of deterministic random texts, run against matchers that
        // span MORE THAN ONE shard so the cross-shard cursor merge is exactly
        // what is being differentially checked. The matcher is compiled ONCE per
        // bound (compiling a >MAX_KEYS_PER_SHARD alternation thousands of times
        // would dominate the run); the randomness lives in the TEXT, which is
        // what actually drives the per-shard cursor advance / re-scan decisions.
        let keys: Vec<String> =
            (0..(MAX_KEYS_PER_SHARD * 2 + 25)).map(|i| format!("P-{i}")).collect();
        // Short tokens whose concatenations frequently form whole keys, partial
        // keys, and digit-run neighbours — matches, misses, ties and boundary
        // rejections all in one stream.
        let alphabet =
            ["P", "-", "0", "1", "2", "5", "9", "a", " ", "P-", "P-1", "P-12", "张", "P-10"];

        // 64-bit LCG (deterministic; fixed seed) — no external rng dependency.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next_u32 = || -> u32 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };

        for bound in [Bound::None, Bound::Digit, Bound::PseudonymToken] {
            let m = ShardedMatcher::new(&keys, bound).unwrap();
            assert!(m.shard_count() >= 2, "test must span multiple shards");
            for _ in 0..3000 {
                let n_tokens = (next_u32() % 40) as usize;
                let mut text = String::new();
                for _ in 0..n_tokens {
                    text.push_str(alphabet[(next_u32() as usize) % alphabet.len()]);
                }
                assert_eq!(
                    m.find_iter(&text).collect::<Vec<_>>(),
                    find_from_pos_driven(&m, &text),
                    "bound={bound:?} text={text:?}",
                );
            }
        }
    }

    #[test]
    fn linear_iter_error_stop_is_identical_to_find_from_pos_driven_loop() {
        use fancy_regex::RegexBuilder;

        // The literal-alternation shards `ShardedMatcher::new` compiles never
        // trip fancy-regex's backtrack limit in practice, so the error-early-stop
        // leg is otherwise argued but never EXECUTED. Force a real
        // `Err(BacktrackLimitExceeded)` inside a shard by hand-building the
        // matcher (bypassing `new`, only to inject a tiny `backtrack_limit` on a
        // catastrophic pattern — the merge/iteration logic under test is
        // untouched) and assert the linear merge stops at exactly the point, and
        // with exactly the prefix, the retained `find_from_pos` oracle does.
        let cheap = Regex::new("M").unwrap(); // literal; never errors
        // `M | (a+)+z`: matches a bare "M" cheaply, but on an "a"-run with no
        // trailing 'z' the `(a+)+z` branch backtracks catastrophically and blows
        // the tiny budget — a real Err, reached fast (the limit stops it long
        // before the 2^n exploration would).
        let boom = RegexBuilder::new(r"M|(a+)+z").backtrack_limit(1000).build().unwrap();

        // Case 1 — NON-EMPTY prefix, then error-stop. Both shards match "M" at 0
        // cheaply, the merge emits (0,1) and advances to pos 1; RE-SCANNING the
        // boom shard from pos 1 enters the "a"-run and errors. The consumed-then-
        // rescanned shard is the interesting path: the merge must both emit the
        // (0,1) prefix AND stop at pos 1, identically to the oracle.
        let m = ShardedMatcher { shards: vec![cheap.clone(), boom.clone()] };
        let text = format!("M{}", "a".repeat(40)); // 40 a's, no 'z'
        assert_eq!(m.find_iter(&text).collect::<Vec<_>>(), vec![(0, 1)]);
        assert_eq!(find_from_pos_driven(&m, &text), vec![(0, 1)]);
        assert_eq!(m.find_iter(&text).collect::<Vec<_>>(), find_from_pos_driven(&m, &text));

        // Case 2 — error on the FIRST scan (empty prefix). No "M", so the boom
        // shard errors at pos 0; both loop forms stop immediately, emitting
        // nothing.
        let m = ShardedMatcher { shards: vec![cheap, boom] };
        let text = "a".repeat(40);
        let empty: Vec<(usize, usize)> = Vec::new();
        assert_eq!(m.find_iter(&text).collect::<Vec<_>>(), empty);
        assert_eq!(find_from_pos_driven(&m, &text), empty);
    }
}
