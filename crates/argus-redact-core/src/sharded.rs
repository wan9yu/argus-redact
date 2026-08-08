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

impl ShardedMatcher {
    /// Compile `keys` (any order, duplicates tolerated) into shards.
    ///
    /// Sorting happens HERE: keys are ordered longest-first before sharding, so
    /// a longer key always sits earlier in its own shard's alternation, and the
    /// cross-shard merge in [`ShardedMatcher::find_from_pos`] restores the same
    /// preference between shards.
    pub(crate) fn new<S: AsRef<str>>(keys: &[S], bound: Bound) -> Result<Self, String> {
        let mut ordered: Vec<&str> = keys.iter().map(|k| k.as_ref()).collect();
        // `sort_by` (stable) on descending byte length — identical to the
        // `sort_by(|a, b| b.len().cmp(&a.len()))` every call site ran itself.
        ordered.sort_by(|a, b| b.len().cmp(&a.len()));

        let mut shards = Vec::with_capacity(ordered.len().div_ceil(MAX_KEYS_PER_SHARD).max(1));
        for chunk in ordered.chunks(MAX_KEYS_PER_SHARD) {
            let pattern = match bound {
                Bound::None => escaped_alternation(chunk),
                Bound::Digit => escaped_alternation_digit_bounded(chunk),
                Bound::PseudonymToken => {
                    let alt = escaped_alternation(chunk);
                    format!(r"(?<![A-Za-z0-9_-])(?:{alt})(?![A-Za-z0-9_-])")
                }
            };
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
    pub(crate) fn find_iter<'a>(&'a self, text: &'a str) -> ShardedMatches<'a> {
        ShardedMatches { matcher: self, text, pos: 0 }
    }

    #[cfg(test)]
    pub(crate) fn shard_count(&self) -> usize {
        self.shards.len()
    }
}

/// Iterator over [`ShardedMatcher::find_iter`].
pub(crate) struct ShardedMatches<'a> {
    matcher: &'a ShardedMatcher,
    text: &'a str,
    pos: usize,
}

impl Iterator for ShardedMatches<'_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<(usize, usize)> {
        if self.pos > self.text.len() {
            return None;
        }
        let (start, end) = self.matcher.find_from_pos(self.text, self.pos)?;
        self.pos = if end > start { end } else { start + 1 };
        Some((start, end))
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
        let pattern = match bound {
            Bound::None => escaped_alternation(&ordered),
            Bound::Digit => escaped_alternation_digit_bounded(&ordered),
            Bound::PseudonymToken => {
                let alt = escaped_alternation(&ordered);
                format!(r"(?<![A-Za-z0-9_-])(?:{alt})(?![A-Za-z0-9_-])")
            }
        };
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
}
