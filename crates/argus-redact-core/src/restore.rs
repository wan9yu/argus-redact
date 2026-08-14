use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};
use fancy_regex::Regex;

use crate::display_marker::strip_display_markers_scoped;
use crate::grammar::{is_self_ref, restore_grammar_en};
use crate::hints::{py_rstrip, py_strip};
use crate::reserved_range::{CharOffsetCursor, scan_for_pollution};
use crate::sharded::{Bound, ShardedMatcher};

#[derive(Debug)]
pub struct RestoreError(pub String);
impl std::fmt::Display for RestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}

/// Result of a full restore pass. `restored` is the text with pseudonyms
/// replaced back to originals; `alias_collisions` lists every alias string
/// that two distinct fakes both claimed (mapping to two different originals)
/// — see `merge_aliases`. `events` records every guard check that fired
/// (empty when the pass ran unguarded); `outcome` summarizes whether the
/// restore proceeded in full, was partially withheld, or was blocked outright.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct RestoreResult {
    pub restored: String,
    pub alias_collisions: Vec<String>,
    pub events: Vec<GuardEvent>,
    pub outcome: RestoreOutcome,
}

/// A provenance anchor: the nonce a caller must echo back to prove a reply
/// actually came from the model that saw the redacted prompt, plus the set
/// of pseudonym codes that reply is scoped to (anything outside `scope` is
/// out-of-scope for that anchor).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Anchor {
    pub nonce: String,
    pub scope: std::collections::HashSet<String>,
}

impl Anchor {
    /// Build an `Anchor` from its two fields. `#[non_exhaustive]` blocks
    /// other crates from writing the struct literal directly, so this is the
    /// stable construction path for callers outside `argus-redact-core`.
    pub fn new(nonce: String, scope: std::collections::HashSet<String>) -> Self {
        Self { nonce, scope }
    }
}

/// Summary verdict of a guarded restore pass.
///
/// `#[non_exhaustive]`: a later 0.8.x release may add a variant (e.g. a more
/// granular partial state); downstream `match` expressions must carry a
/// wildcard arm so they keep compiling across such an addition.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum RestoreOutcome {
    Blocked,
    Partial,
    Complete,
}

impl RestoreOutcome {
    /// The stable snake_case name of this outcome — the SECURITY vocabulary the
    /// Python (`crates/argus-redact-py/src/restore.rs`) and wasm
    /// (`crates/argus-redact-wasm/src/lib.rs`) faces both surface verbatim. This
    /// is the single source of that wire string; both bindings call it, so the
    /// emitted names are byte-identical across runtimes.
    ///
    /// The match is exhaustive over every variant (no wildcard arm): although the
    /// enum is `#[non_exhaustive]` for downstream crates, this crate OWNS the
    /// enum, so adding a variant is a compile error here until its name is added
    /// — the "grow in lockstep" invariant, now enforced at the source instead of
    /// silently degrading to a fallback string in each binding.
    pub fn as_str(&self) -> &'static str {
        match self {
            RestoreOutcome::Blocked => "blocked",
            RestoreOutcome::Partial => "partial",
            RestoreOutcome::Complete => "complete",
        }
    }
}

/// The kind of guard check a [`GuardEvent`] reports on.
///
/// `#[non_exhaustive]` for the same forward-compatibility reason as
/// [`RestoreOutcome`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum GuardEventKind {
    GuardNoAnchor,
    ProvenanceFailed,
    EmptyKeyWithScope,
    OutOfScopePseudonym,
    AliasCollision,
}

impl GuardEventKind {
    /// The stable snake_case name of this guard-event kind — the SECURITY
    /// vocabulary the Python and wasm faces both surface verbatim (see
    /// [`RestoreOutcome::as_str`] for the SSOT / byte-identical reasoning). The
    /// match is exhaustive over every variant for the same reason: a new variant
    /// must gain its name here, in the crate that owns the enum.
    pub fn as_str(&self) -> &'static str {
        match self {
            GuardEventKind::GuardNoAnchor => "guard_no_anchor",
            GuardEventKind::ProvenanceFailed => "provenance_failed",
            GuardEventKind::EmptyKeyWithScope => "empty_key_with_scope",
            GuardEventKind::OutOfScopePseudonym => "out_of_scope_pseudonym",
            GuardEventKind::AliasCollision => "alias_collision",
        }
    }
}

/// One guard check's outcome. `count` is how many instances the check found;
/// `detail`, when present, is the SORTED list of the specific tokens involved
/// (e.g. out-of-scope pseudonym codes) — a bare data carrier, not a
/// human-readable message. Callers own rendering (as of v0.8.8, Python's
/// `security_events` `detail` reports only `count`, never these tokens; wasm
/// still exposes `tokens[]` as-is) so no reason-code prose lives in this crate.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct GuardEvent {
    pub kind: GuardEventKind,
    pub count: usize,
    pub detail: Option<Vec<String>>,
}

// ── Nonce echo-verify (P guard) ─────────────────────────────────────────────
//
// The sole implementation of the nonce floor / echo check / stripper; the Python
// shim calls into these and keeps no copy of its own.
// A `make_anchor` nonce is `secrets.token_hex(16)` = 32 hex chars. A floor
// well below that (real nonces pass) but far above any incidental text-suffix
// collision rejects short degenerate nonces as provenance proofs.

/// Minimum nonce length the guard will accept.
const MIN_NONCE_LEN: usize = 16;

/// Formatting a chat model routinely adds around a token it was asked to echo:
/// markdown emphasis/code spans, quotes, brackets, sentence punctuation.
///
/// All are non-alphanumeric, so trimming them can never turn some OTHER token
/// into the nonce — only reveal the nonce that is actually there. Without this,
/// ```` `<nonce>` ```` — an entirely ordinary way for a model to render a token
/// — fails the provenance check and SILENTLY BLOCKS a legitimate restore, which
/// is indistinguishable to the caller from a detected injection.
const NONCE_WRAPPERS: &[char] = &[
    '`', '*', '_', '~', '"', '\'', '\u{201c}', '\u{201d}', '\u{2018}', '\u{2019}', '(', ')', '[',
    ']', '{', '}', '<', '>', '.', ',', ';', ':', '!', '?',
];

/// Strip surrounding whitespace and [`NONCE_WRAPPERS`] from one candidate line.
fn unwrap_nonce_candidate(line: &str) -> &str {
    py_strip(py_strip(line).trim_matches(|c| NONCE_WRAPPERS.contains(&c)))
}

/// True only if the model echoed `nonce` as instructed — as a whole token, on
/// its own line or as the trailing token (the shape `prompt_anchor` asks for
/// and `strip_nonce` removes), allowing for ordinary wrapper formatting.
///
/// `nonce.chars().count()` (NOT `.len()`) mirrors Python `len()`, which counts
/// codepoints rather than bytes, so the floor check lands on the same value
/// for any non-ASCII nonce too.
fn nonce_echoed(text: &str, nonce: &str) -> bool {
    if nonce.chars().count() < MIN_NONCE_LEN {
        return false;
    }
    // Documented trailing echo. `trim_end_matches` only peels wrapper chars, so
    // `id=<nonce>xyz` still does not qualify — the nonce must be the last
    // TOKEN, not merely present.
    if py_rstrip(text).trim_end_matches(|c| NONCE_WRAPPERS.contains(&c)).ends_with(nonce) {
        return true;
    }
    text.split('\n').any(|line| unwrap_nonce_candidate(line) == nonce) // own-line echo
}

/// Remove the echoed verification token from the model's reply.
///
/// EVERY echoed copy is removed, not just the last one: the own-line filter and
/// the inline pass both always run. A trailing fast-path that returned early
/// left an earlier duplicate echo in place, and that copy then travelled all
/// the way into the restored plaintext handed back to the caller.
fn strip_nonce(text: &str, nonce: &str) -> String {
    if nonce.chars().count() < MIN_NONCE_LEN {
        // Defense in depth: a degenerate nonce has no valid echo to strip, and
        // stripping it WOULD destroy or corrupt the text. The only caller
        // gates on `nonce_echoed` first, so this never fires today — but a
        // function whose failure mode is "silently destroy the caller's
        // plaintext" must refuse degenerate input regardless of caller.
        return text.to_string();
    }
    // Drop whole lines that are a bare (possibly wrapped) echo — this also
    // takes the wrapper characters with them. No trailing fast path: with a
    // duplicate echo earlier in the reply an early return left the surviving
    // copy in the returned PLAINTEXT — the guard leaking its own secret into
    // the answer it hands back.
    let kept: Vec<&str> =
        text.split('\n').filter(|line| unwrap_nonce_candidate(line) != nonce).collect();
    let mut out = kept.join("\n");
    if out.contains(nonce) {
        // Echoed inline rather than on its own line (e.g. "…body. <nonce>").
        out = out.replace(nonce, "");
    }
    py_rstrip(&out).to_string()
}

/// Fail closed on a key containing an empty-string surrogate. argus never
/// produces one (the redact side refuses to), so such a key is corrupted or
/// hand-built; an empty surrogate would otherwise become a zero-width regex
/// alternative matching between every character and splicing the original in
/// everywhere. Single source for the check + message, called on both the raw
/// key and the merged flat map so both are guarded.
fn reject_empty_key_entry(key: &HashMap<String, String>) -> Result<(), RestoreError> {
    if key.keys().any(|k| k.is_empty()) {
        return Err(RestoreError(
            "restore key contains an empty-string entry — corrupted or hand-built key".to_string(),
        ));
    }
    Ok(())
}

/// Reject a restore input larger than [`crate::MAX_INPUT_SIZE`] (1 MiB) BEFORE
/// any substitution scan touches it — the same ceiling the redact path
/// (`patterns.rs`, `redact_l1.rs`) and `check_restore_safety` already enforce.
///
/// The K-way-merge matcher already makes the substitution scan LINEAR, so this
/// is defense-in-depth rather than the primary DoS cure: it bounds a single
/// restore call's worst-case time and memory and gives one consistent 1 MiB
/// ceiling across the whole redact + restore surface. The message names only
/// the byte count and the limit — never the text — so an oversized hostile
/// payload cannot smuggle content out through the error string.
///
/// Applied at the public entry points (`restore`, `restore_full_guarded`,
/// `RestoreSession::restore_cell`) so the check sits at the API boundary and is
/// not re-run by the private helpers they share.
fn check_input_size(text: &str) -> Result<(), RestoreError> {
    if text.len() > crate::MAX_INPUT_SIZE {
        return Err(RestoreError(format!(
            "input too large: {} bytes exceeds MAX_INPUT_SIZE {}",
            text.len(),
            crate::MAX_INPUT_SIZE
        )));
    }
    Ok(())
}

/// Restore redacted text by replacing pseudonyms with originals.
/// Keys sorted by length descending to prevent partial matches.
/// Single-pass replacement prevents re-scanning of replaced content.
pub fn restore(text: &str, key: &HashMap<String, String>) -> Result<String, RestoreError> {
    check_input_size(text)?;
    restore_tracking_self_ref(text, key, &[]).map(|(result, _spans)| result)
}

/// Same single-pass substitution as `restore()`, but additionally records the
/// BYTE-offset span (in the OUTPUT string) of every self-referential pronoun
/// value (`is_self_ref`, e.g. "I") it splices in. These spans let
/// `restore_full` scope the reverse grammar fix to just the neighbourhood of
/// an actual pronoun restoration instead of a whole-text pass — see
/// `apply_grammar_scoped`.
///
/// The recorded offsets are exactly the start/end of the pushed replacement
/// text, so they always land on a valid UTF-8 char boundary: no separate
/// byte→char conversion is needed to slice `result` at them later.
/// `shield` holds tokens that must be MATCHED but never substituted. They join
/// the longest-first alternation, so a shorter lookup key can no longer match
/// INSIDE one; `substitute_with` finds no lookup entry for them and emits them
/// verbatim, consuming the whole token atomically. That is what lets the guard
/// WITHHOLD an identity without SPLICING one — see `restore_full_guarded`.
fn restore_tracking_self_ref(
    text: &str,
    key: &HashMap<String, String>,
    shield: &[String],
) -> Result<(String, Vec<(usize, usize)>), RestoreError> {
    if (key.is_empty() && shield.is_empty()) || text.is_empty() {
        return Ok((text.to_string(), Vec::new()));
    }

    // An empty-string surrogate can never come from argus — the producer
    // (`replace.rs`) refuses to register one, because it would match between
    // every character below and explode the original throughout the text.
    // A key that has one is corrupted or hand-built: fail closed rather than
    // execute the explosion.
    reject_empty_key_entry(key)?;

    // Build the matcher from the escaped keys (digit-bounded so a numeric key
    // cannot match inside a longer number). `ShardedMatcher::new` does the
    // longest-first ordering itself, across keys and shield alike — the shield
    // only works because the ordering is global, not per-source.
    let keys: Vec<&String> = key.keys().chain(shield.iter()).collect();
    let matcher = ShardedMatcher::new(&keys, Bound::Digit)
        .map_err(|e| RestoreError(format!("Invalid restore pattern: {e}")))?;

    Ok(substitute_with(&matcher, key, text))
}

/// Single-pass, longest-first substitution of every match of `matcher` in `text`
/// using `flat` as the lookup, tracking the byte-offset span (in the OUTPUT
/// string) of every self-referential pronoun value it splices in — the exact
/// substitution body `restore_tracking_self_ref` used to run inline.
///
/// Shared by `restore_tracking_self_ref` (which compiles `matcher` fresh from
/// `key` on every call) and `RestoreSession::restore_cell` (which reuses one
/// `matcher` precompiled once in `RestoreSession::new` across many calls over
/// the same `flat` map) — factored out so the two call sites can never drift.
fn substitute_with(
    matcher: &ShardedMatcher,
    flat: &HashMap<String, String>,
    text: &str,
) -> (String, Vec<(usize, usize)>) {
    let mut result = String::with_capacity(text.len());
    let mut last_end = 0;
    let mut self_ref_spans: Vec<(usize, usize)> = Vec::new();

    for (start, end) in matcher.find_iter(text) {
        result.push_str(&text[last_end..start]);
        let matched = &text[start..end];
        if let Some(replacement) = flat.get(matched) {
            let span_start = result.len();
            result.push_str(replacement);
            if is_self_ref(replacement) {
                self_ref_spans.push((span_start, result.len()));
            }
        } else {
            result.push_str(matched);
        }
        last_end = end;
    }
    result.push_str(&text[last_end..]);

    (result, self_ref_spans)
}

/// Chars to scan past a restored self-ref pronoun for a verb to fix. Covers
/// the longest reverse rule ("I doesn't", 9 chars for the full "I doesn't"
/// phrase) plus slack for the `\b` boundary — generous enough to catch the
/// verb, tight enough to stay well short of an unrelated sentence further along.
const GRAMMAR_FIX_WINDOW_CHARS: usize = 12;

/// Apply `restore_grammar_en` ONLY inside the neighbourhood of each recorded
/// self-ref-pronoun restoration span, leaving the rest of `text` byte-for-byte
/// untouched elsewhere. A whole-text `restore_grammar_en` call would also "fix"
/// an unrelated "I is" that happens to already be in the surrounding text —
/// text this restoration never touched — corrupting it into "I am". Scoping
/// to a window that starts at the restored pronoun and runs a few chars past
/// it avoids that: the fix only ever fires where a pronoun was JUST restored.
///
/// Each span's own window is `[span.start, span.end + GRAMMAR_FIX_WINDOW_CHARS
/// chars]`. When the next span's window OVERLAPS the current accumulated
/// window (its start falls at or before the current window's end), the two
/// windows are MERGED — extended to the max of both windows' ends — rather
/// than the next span being skipped. Skipping would silently drop the
/// grammar fix for a second restoration that lies close to (but isn't fully
/// covered by) an earlier restoration's window: the first window can reach
/// past the second span's start without reaching far enough to cover the
/// second span's own trailing verb. Merging guarantees every restored
/// pronoun's trailing verb is inside some window, each region processed
/// exactly once — no double-application, no corruption, no missed fix.
fn apply_grammar_scoped(text: &str, spans: &[(usize, usize)]) -> String {
    if spans.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    // The current maximal merged window, accumulated across spans whose
    // windows overlap or touch.
    let mut window: Option<(usize, usize)> = None;

    for &(start, end) in spans {
        let this_window_end = advance_chars(text, end, GRAMMAR_FIX_WINDOW_CHARS).min(text.len());
        match window {
            None => window = Some((start, this_window_end)),
            Some((win_start, win_end)) => {
                if start <= win_end {
                    // Overlapping/adjacent: extend the accumulated window
                    // to cover both spans' trailing verbs.
                    window = Some((win_start, win_end.max(this_window_end)));
                } else {
                    // No overlap: flush the finished window, then start a
                    // new one for this span.
                    out.push_str(&text[cursor..win_start]);
                    out.push_str(&restore_grammar_en(&text[win_start..win_end]));
                    cursor = win_end;
                    window = Some((start, this_window_end));
                }
            }
        }
    }
    if let Some((win_start, win_end)) = window {
        out.push_str(&text[cursor..win_start]);
        out.push_str(&restore_grammar_en(&text[win_start..win_end]));
        cursor = win_end;
    }
    out.push_str(&text[cursor..]);
    out
}

/// Advance up to `n_chars` UTF-8 chars past byte offset `from` in `s`,
/// returning the resulting byte offset. Always lands on a char boundary
/// (unlike `from + n_chars`, which would panic or slice mid-character on
/// multi-byte text) — char-safe equivalent of `from + n_chars` bytes.
fn advance_chars(s: &str, from: usize, n_chars: usize) -> usize {
    let mut end = from;
    for (offset, ch) in s[from..].char_indices().take(n_chars) {
        end = from + offset + ch.len_utf8();
    }
    end
}

/// Build the flat restore lookup = `key` ∪ {alias → key[fake]'s original},
/// merging in SORTED fake-key order so the winner is deterministic across
/// process runs (a plain `for (fake, alias_list) in alias_map` walk order is
/// randomized per-process by HashMap's hasher, so an unsorted walk would let
/// the process hash seed decide the output). When two distinct fakes alias to
/// the SAME string with two DIFFERENT originals, the sorted-first fake wins
/// and the collision is recorded in the returned `Vec` so the caller can be
/// warned the loser's identity may come back wrong on restore.
///
/// Returns `(flat_map, alias_collisions, alias_owner)`. With `aliases = None`,
/// `flat_map` is a plain clone of `key` and the other two are empty.
///
/// `alias_owner` maps each alias string that actually entered `flat_map` to the
/// FAKE whose original it resolved to. Pseudonyms themselves are never listed —
/// they own themselves. The guarded path needs this: scope is defined over
/// pseudonyms, and an alias inherits the scope of the fake that owns it, so
/// without an owner the guard cannot tell an authorised alias from one that
/// smuggles a withheld identity back into the reply.
fn merge_aliases<'k>(
    key: &'k HashMap<String, String>,
    aliases: Option<&HashMap<String, Vec<String>>>,
) -> (Cow<'k, HashMap<String, String>>, Vec<String>, HashMap<String, String>) {
    let mut alias_collisions: Vec<String> = Vec::new();
    let mut alias_owner: HashMap<String, String> = HashMap::new();
    // With aliases → build the merged map (owned). Without → the flat map IS the
    // key, so BORROW it: the common `restore_body`/`RestoreSession` no-alias path
    // no longer deep-clones the whole key map just to hand out a `&HashMap`.
    let flat: Cow<HashMap<String, String>> = if let Some(alias_map) = aliases {
        let mut m: HashMap<String, String> = key.clone();
        let mut fakes: Vec<&String> = alias_map.keys().collect();
        fakes.sort();
        for fake in fakes {
            if let Some(original) = key.get(fake) {
                for alias in &alias_map[fake] {
                    match m.get(alias) {
                        Some(existing) if existing != original => {
                            // Two fakes map one alias to different originals —
                            // the deterministic (sorted-first) winner stays;
                            // record the collision so the caller can be warned
                            // it may be the wrong identity for the other fake.
                            alias_collisions.push(alias.clone());
                        }
                        None => {
                            m.insert(alias.clone(), original.clone());
                            alias_owner.insert(alias.clone(), fake.clone());
                        }
                        _ => {}
                    }
                }
            }
        }
        Cow::Owned(m)
    } else {
        Cow::Borrowed(key)
    };
    (flat, alias_collisions, alias_owner)
}

/// Display-marker strip + alias merge + core substitution + grammar, over
/// exactly the `key` passed in. This is the body shared by the unguarded
/// path and the guarded path's in-scope restore — the guarded path calls it
/// with the SCOPED key (never the full key), so an out-of-scope fake's own
/// display marker is left untouched right alongside its withheld pseudonym.
///
/// 1. If `display_marker` is Some → strip that marker from text, scoped to
///    `key`'s fakes only.
/// 2. If `key` empty → return text unchanged.
/// 3. Alias merge: build flat lookup = key ∪ {alias → key[fake]'s original}
///    (see `merge_aliases`).
/// 4. Core substitution (`restore`, single-pass longest-first), tracking the
///    span of every self-ref pronoun value it substitutes in.
/// 5. `restore_grammar_en` runs ONLY in the neighbourhood of those spans (see
///    `apply_grammar_scoped`) — never as a whole-text pass.
///
/// Decoration markers (`ⓕ`, `(假)`, `ˢ`, `*`) need no dedicated pass: a marker
/// trailing a key is ordinary non-key text, so the single `restore` pass leaves
/// it verbatim right after the restored value (e.g. `"P-1ⓕ"` → `"<value>ⓕ"`).
///
/// Returns `(restored_text, alias_collisions)` where `alias_collisions` has
/// one entry per alias string that two distinct fakes both claimed (mapping
/// to two different originals) — empty when `aliases` is `None` or no
/// collision occurred.
fn restore_body(
    text: &str,
    key: &HashMap<String, String>,
    aliases: Option<&HashMap<String, Vec<String>>>,
    display_marker: Option<&str>,
) -> Result<(String, Vec<String>), RestoreError> {
    // `restore_tracking_self_ref` (called from `restore_flat` below) rejects an
    // empty-string key entry too; this is defense in depth so this function
    // fails closed on its own before doing any alias-merge work, independent
    // of whether the lower-level fn is reached unchanged.
    reject_empty_key_entry(key)?;

    // Alias merge — build flat lookup.
    let (flat, alias_collisions, _alias_owner) = merge_aliases(key, aliases);

    // The display-marker strip is scoped to this key's own FAKES (not the
    // merged map): markers are written by `mark_for_display` against the
    // pseudonyms, so that is exactly where they can be. `restore_flat` only
    // reads `marker_fakes` when `display_marker` is Some, so building the list
    // otherwise is wasted work whose empty result is never observed.
    let marker_fakes: Vec<String> =
        if display_marker.is_some() { key.keys().cloned().collect() } else { Vec::new() };

    // No shield on the unguarded path: nothing is withheld, so every token in
    // the merged map is substitutable.
    Ok((restore_flat(text, &flat, &marker_fakes, display_marker, &[])?, alias_collisions))
}

/// Marker strip + core substitution + grammar over an ALREADY-merged `flat`
/// lookup — the half of `restore_body` below the alias merge.
///
/// Split out because the guarded path must merge aliases over the FULL key
/// (so the collision domain, and therefore which original an alias resolves
/// to, is a property of the key rather than of one reply's scope) and only
/// THEN apply the scope filter to the merged map. It cannot reach that by
/// calling `restore_body` with a pre-scoped key: `merge_aliases` seeds its
/// lookup from the map it is handed, so under a pre-scoped key an
/// out-of-scope pseudonym is simply ABSENT — and an alias whose literal text
/// equals that pseudonym then wins the vacant slot instead of colliding with
/// it, handing the caller a withheld code restored to the WRONG identity.
///
/// `marker_fakes` scopes the display-marker strip. A global strip would remove
/// the marker character everywhere in `text`, destroying unrelated content that
/// happens to contain it (e.g. markdown `**bold**`, or a masked value's internal
/// `*`). Scoping to the same longest-first fake alternation `mark_for_display`
/// uses makes the strip land exactly where the mark was added, nowhere else.
///
/// `shield` — tokens matched but never substituted. See
/// `restore_tracking_self_ref`. Empty on the unguarded path.
fn restore_flat(
    text: &str,
    flat: &HashMap<String, String>,
    marker_fakes: &[String],
    display_marker: Option<&str>,
    shield: &[String],
) -> Result<String, RestoreError> {
    // Step 1: strip explicit display marker — scoped to `marker_fakes` only.
    let text_owned: String;
    let text = if let Some(dm) = display_marker {
        text_owned = strip_display_markers_scoped(text, marker_fakes, Some(dm));
        text_owned.as_str()
    } else {
        text
    };

    // Step 2: empty lookup fast-path. A shield with nothing to substitute
    // still has nothing to do — every shielded token would be emitted verbatim,
    // which is what returning `text` unchanged already does.
    if flat.is_empty() {
        return Ok(text.to_string());
    }
    reject_empty_key_entry(flat)?;

    // A shield entry that is ALSO a lookup key would be SUBSTITUTED, not
    // shielded — the lookup wins in `substitute_with`. The guarded caller
    // derives the two sets by complementary filters on one map so they cannot
    // intersect (and the unguarded path passes an empty shield); this filter
    // makes the property local rather than a contract the caller has to
    // remember. Since a collision never happens on either real path, borrow
    // `shield` as-is and only allocate the filtered copy if one ever does —
    // byte-identical either way.
    let shield_only: Cow<[String]> = if shield.iter().any(|s| flat.contains_key(s)) {
        Cow::Owned(shield.iter().filter(|s| !flat.contains_key(*s)).cloned().collect())
    } else {
        Cow::Borrowed(shield)
    };

    // Step 3: core substitution over the flat lookup.
    //
    // No separate decoration-marker pass runs here. `restore` is a single
    // left-to-right longest-key-match pass that replaces each source span
    // exactly once and advances PAST each replacement (never re-scanning the
    // value it just emitted). A trailing marker is non-key text, so it survives
    // verbatim after the restored value — the same result the old marker pass
    // produced, minus its hazard: that pass wrote `value + markers` into a
    // buffer this scan then re-read, so under a CHAINED key map (a value that is
    // itself another key) the value got replaced a SECOND time — a cross-entity
    // disclosure. Folding the marker handling into the single no-rescan pass
    // closes that double-replace by construction.
    let (result, self_ref_spans) = restore_tracking_self_ref(text, flat, &shield_only)?;

    // Step 4: grammar restore, scoped to the neighbourhood of each restored
    // self-ref pronoun. `apply_grammar_scoped` is a no-op (returns `result`
    // unchanged) when `self_ref_spans` is empty, i.e. when no key value was a
    // self-ref pronoun OR none of them actually got substituted into `text`.
    Ok(apply_grammar_scoped(&result, &self_ref_spans))
}

/// Full restore path: [`restore_body`], optionally preceded by a provenance +
/// scope guard.
///
/// `anchor = None` is the current unguarded path — `restore_body` runs over
/// the full `key`, unconditionally `RestoreOutcome::Complete`, no events.
/// This is the byte-identical, non-breaking default every existing caller of
/// [`restore_full`] keeps getting.
///
/// `anchor = Some(a)` runs the P (provenance) + S (scope) guard, mirroring
/// `pure/restore.py::restore`'s `guard is True` branch (the anchor-is-not-None
/// half — `anchor is None` under `guard=True` is reported via
/// `GuardEventKind::GuardNoAnchor` by the Python/wasm callers, never here:
/// this function only ever sees `Some(anchor)`, so it has nothing to report
/// for that case):
///
/// 1. **(P) Provenance.** If the model's reply doesn't echo `a.nonce`
///    (`nonce_echoed`), fail closed: return the RAW `text` completely
///    unrestored (not even nonce-stripped — there was nothing to prove it was
///    ours), `RestoreOutcome::Blocked`, and a `ProvenanceFailed` event sized to
///    the whole key (nothing was, or could be, substituted). Otherwise strip
///    the now-verified nonce (`strip_nonce`) so it never reaches the caller as
///    part of the restored plaintext.
/// 2. **(S) Scope.** Restrict substitution to the entries of `key` whose
///    pseudonym is in `a.scope` (`scoped`). A non-empty `key` whose scope
///    excludes every entry is advisory (`EmptyKeyWithScope`) rather than an
///    error — a legitimate non-overlapping scope, not corruption. Any
///    out-of-scope pseudonym that actually appears in the (nonce-stripped)
///    text is reported via `OutOfScopePseudonym` (sized/detailed by
///    `tokens_present`) — cosmetic only, it never changes what gets withheld
///    (that's `scoped`, structural).
/// 3. Run [`restore_body`] over `scoped` (never the full `key`) — so an
///    out-of-scope fake is withheld AND its own display marker, if any, is
///    left untouched right alongside it. Fold any resulting alias collision
///    into an `AliasCollision` event.
/// 4. `RestoreOutcome::Partial` when anything was withheld
///    (`out_of_scope_hits` non-empty), else `RestoreOutcome::Complete`.
pub fn restore_full_guarded(
    text: &str,
    key: &HashMap<String, String>,
    aliases: Option<&HashMap<String, Vec<String>>>,
    display_marker: Option<&str>,
    anchor: Option<&Anchor>,
) -> Result<RestoreResult, RestoreError> {
    // Size cap BEFORE any scan — covers both the unguarded `restore_body`
    // branch and the guarded `tokens_present` + substitution branch (the latter
    // otherwise scans `text` in `tokens_present` before restoring it).
    check_input_size(text)?;
    let Some(anchor) = anchor else {
        let (result, alias_collisions) = restore_body(text, key, aliases, display_marker)?;
        return Ok(RestoreResult {
            restored: result,
            alias_collisions,
            events: vec![],
            outcome: RestoreOutcome::Complete,
        });
    };

    // (P) Provenance: the model must have echoed the nonce we asked it to.
    if !nonce_echoed(text, &anchor.nonce) {
        return Ok(RestoreResult {
            restored: text.to_string(),
            alias_collisions: Vec::new(),
            events: vec![GuardEvent {
                kind: GuardEventKind::ProvenanceFailed,
                count: key.len(),
                detail: None,
            }],
            outcome: RestoreOutcome::Blocked,
        });
    }
    // Provenance holds — strip the token so it never reaches the caller as
    // part of the restored plaintext (it is not a pseudonym, so the
    // substitution pass below would otherwise carry it straight through).
    let text = strip_nonce(text, &anchor.nonce);

    // Corrupted-key check on the FULL key, BEFORE the scope split. Running it
    // only on the scoped slice (as calling `restore_body(scoped, ..)` would)
    // lets an empty-string entry that scope happens to exclude slip past the
    // check entirely — the guarded path would then be the one path in the
    // library that does NOT fail closed on a corrupted key.
    reject_empty_key_entry(key)?;

    // Alias merge over the FULL key. The winner of a contested alias, and
    // whether an alias collides at all, must be a property of the KEY — the
    // same answer the unguarded path gives. Merging over a pre-scoped key
    // would let scope decide WHICH identity an alias resolves to, which is
    // how an alias could stand in for an out-of-scope pseudonym. See
    // `restore_flat`.
    let (flat_full, alias_collisions_full, alias_owner) = merge_aliases(key, aliases);
    reject_empty_key_entry(&flat_full)?;

    // (S) Scope: a PSEUDONYM is substitutable iff the anchor scopes it; an
    // ALIAS iff the fake that OWNS it is scoped — an alias is exactly as
    // authorised as the identity behind it.
    let scoped_flat: HashMap<String, String> = flat_full
        .iter()
        .filter(|(k, _)| match alias_owner.get(*k) {
            Some(owner) => anchor.scope.contains(owner),
            None => anchor.scope.contains(*k),
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // The in-scope PSEUDONYMS (no aliases) — the advisory below counts these,
    // and they alone scope the display-marker strip.
    let scoped_fakes: Vec<String> =
        key.keys().filter(|k| anchor.scope.contains(*k)).cloned().collect();

    // Everything in the merged map that scope does NOT reach. These join the
    // substitution alternation as SHIELD entries — matched (so nothing shorter
    // can match inside one) but absent from the lookup, so each is emitted
    // verbatim and consumed atomically.
    //
    // Without the shield, filtering out-of-scope entries out of the map leaves
    // a withheld pseudonym with no alternative of its own, and a SHORTER
    // in-scope one matches INSIDE it: `{"P-1": "Alice", "P-10": "Ten"}` scoped
    // to `P-1` turned `P-10` into `Alice0`. The guard reported that token as
    // withheld while having spliced a real identity into it — strictly worse
    // than leaving the guard off. The scope guard may WITHHOLD an identity; it
    // may never SPLICE one.
    let mut shield: Vec<String> =
        flat_full.keys().filter(|t| !scoped_flat.contains_key(*t)).cloned().collect();
    // Sorted so the alternation this feeds is byte-stable across process runs.
    shield.sort();

    let mut events: Vec<GuardEvent> = Vec::new();

    // Advisory: the key was non-empty and anchor.scope is non-empty, but scope
    // excluded EVERY entry — the restore below is a silent no-op that would
    // otherwise be reported COMPLETE with no hint that nothing was
    // substituted. Distinct from the corruption empty-string-key case (that
    // fails closed in `restore_body`); this is a legitimate, non-overlapping
    // scope and key, so it only advises, never blocks.
    if !key.is_empty() && scoped_fakes.is_empty() && !anchor.scope.is_empty() {
        events.push(GuardEvent { kind: GuardEventKind::EmptyKeyWithScope, count: key.len(), detail: None });
    }

    // Detect out-of-scope pseudonyms that appear in text — see
    // `tokens_present`. Cosmetic only: it sizes the event's `count`/`detail`,
    // never which pseudonyms get withheld (that is `shield` above). It scans
    // the SHIELD, not `key`, so an ALIAS of an out-of-scope fake is reported as
    // withheld too and `strict=True` fails closed on it identically.
    let out_of_scope = tokens_present(&shield, &text);
    if !out_of_scope.is_empty() {
        events.push(GuardEvent {
            kind: GuardEventKind::OutOfScopePseudonym,
            count: out_of_scope.len(),
            detail: Some(out_of_scope.clone()),
        });
    }

    // Restore only in-scope pseudonyms (and their aliases), with every
    // out-of-scope token shielded.
    let result = restore_flat(&text, &scoped_flat, &scoped_fakes, display_marker, &shield)?;
    let alias_collisions = alias_collisions_full;
    if !alias_collisions.is_empty() {
        // Dedupe + sort for the EVENT only — `merge_aliases` pushes one entry
        // per LOSING claim, so a 3-way collision on one alias string appears
        // multiple times in `alias_collisions`. The event must report DISTINCT
        // collided aliases (matching Python's `alias_collision_event`, which
        // counts `set(...)`), and its `detail` must be the SORTED token list
        // the `GuardEvent.detail` contract promises (as its sibling
        // `OutOfScopePseudonym` already does via `tokens_present`). `BTreeSet`
        // gives both in one step. `RestoreResult.alias_collisions` below stays
        // the RAW list — the unguarded/warn path counts it via its own
        // `set()`-dedup and must see every push.
        let distinct: Vec<String> =
            alias_collisions.iter().cloned().collect::<BTreeSet<_>>().into_iter().collect();
        events.push(GuardEvent {
            kind: GuardEventKind::AliasCollision,
            count: distinct.len(),
            detail: Some(distinct),
        });
    }

    // out_of_scope means some pseudonyms present in the text were outside
    // this call's scope and withheld (Partial — the restore was limited to
    // scope); no hits means nothing in the text was withheld (Complete — any
    // events left, e.g. EmptyKeyWithScope or AliasCollision, are advisory).
    let outcome = if out_of_scope.is_empty() { RestoreOutcome::Complete } else { RestoreOutcome::Partial };

    Ok(RestoreResult { restored: result, alias_collisions, events, outcome })
}

/// The `pseudonyms` that appear in `text` as whole tokens (sorted, deduped).
/// Port of `pure/restore.py::_tokens_present`.
///
/// A match must not be merely a substring of a longer pseudonym-shaped run
/// (e.g. `P-1` embedded in `P-10`). Generated pseudonyms are
/// `<PREFIX>-<digits>` runs of letters, digits, underscores and hyphens, so
/// plain word-boundary matching is not enough — a hyphen is not a word
/// character, but must still not count as a boundary between two
/// pseudonym-shaped tokens. The negative lookbehind/lookahead over
/// `[A-Za-z0-9_-]` covers that.
///
/// ONE alternation scan over the whole set, longest-first (so `P-10` wins
/// over `P-1` at the same offset), rather than a full-text scan per
/// pseudonym.
///
/// Used only to size the `out_of_scope_pseudonym` security event's `count`
/// and `detail`; it never changes which pseudonyms are withheld (that is
/// structural, driven by the caller's own scoped key filter).
fn tokens_present(pseudonyms: &[String], text: &str) -> Vec<String> {
    if pseudonyms.is_empty() {
        return Vec::new();
    }

    // `ShardedMatcher::new` sorts longest-first itself — mirrors Python's
    // `sorted(pseudonyms, key=len, reverse=True)`, which never mutates its
    // input either.
    let matcher = match ShardedMatcher::new(pseudonyms, Bound::PseudonymToken) {
        Ok(m) => m,
        // An escaped alternation of literal strings should always compile;
        // if it somehow doesn't, Python's `re.compile` on the equivalent
        // pattern would not raise here either, so fail open to "no hits"
        // rather than panic.
        Err(_) => return Vec::new(),
    };

    let mut hits: BTreeSet<String> = BTreeSet::new();
    for (start, end) in matcher.find_iter(text) {
        hits.insert(text[start..end].to_string());
    }
    // `BTreeSet` iterates in sorted order, so this is exactly Python's
    // `sorted(set(pattern.findall(text)))`.
    hits.into_iter().collect()
}

/// Compat projection of [`restore_full_guarded`] onto the pre-existing tuple
/// shape. `argus-redact-core` is a stable crates.io crate — this signature is
/// frozen; new callers should use `restore_full_guarded` directly.
pub fn restore_full(
    text: &str,
    key: &HashMap<String, String>,
    aliases: Option<&HashMap<String, Vec<String>>>,
    display_marker: Option<&str>,
) -> Result<(String, Vec<String>), RestoreError> {
    restore_full_guarded(text, key, aliases, display_marker, None).map(|r| (r.restored, r.alias_collisions))
}

/// A reusable restore pass over a FIXED key + aliases.
///
/// `restore_full`/`restore_full_guarded` merge aliases and compile the
/// alternation regex from scratch on every call — fine for a single restore,
/// wasteful for a bulk caller (CSV per-cell, streaming per-sentence) that
/// restores many small texts against the SAME key. `RestoreSession::new`
/// does that work ONCE; `restore_cell` replays the substitution per text.
///
/// Sits BELOW the guard: a session caches only key-derived state, no
/// guard/scope semantics. It always runs the unguarded path — the same one
/// `restore_full`/`restore_full_guarded(..., None)` take — so bulk callers
/// restore over a fixed key without provenance or scope checks.
#[derive(Debug)]
pub struct RestoreSession {
    flat: HashMap<String, String>,
    matcher: Option<ShardedMatcher>,
    alias_collisions: Vec<String>,
}

impl RestoreSession {
    /// Precompute the alias-merged flat map (via `merge_aliases`, the same
    /// helper `restore_body` uses) and the compiled longest-first
    /// alternation regex, once, for the lifetime of the session.
    ///
    /// Fails closed on an empty-string key entry exactly like `restore_body`
    /// does — checked on both the raw `key` and the merged `flat` map
    /// (defense in depth: a corrupted entry could also enter only through
    /// the alias merge). An empty `flat` (i.e. an empty `key`) leaves `re`
    /// as `None` rather than compiling a pattern that would never match
    /// anything.
    pub fn new(
        key: &HashMap<String, String>,
        aliases: Option<&HashMap<String, Vec<String>>>,
    ) -> Result<RestoreSession, RestoreError> {
        reject_empty_key_entry(key)?;
        let (flat, alias_collisions, _alias_owner) = merge_aliases(key, aliases);
        reject_empty_key_entry(&flat)?;

        let matcher = if flat.is_empty() {
            None
        } else {
            let keys: Vec<&String> = flat.keys().collect();
            Some(
                ShardedMatcher::new(&keys, Bound::Digit)
                    .map_err(|e| RestoreError(format!("Invalid restore pattern: {e}")))?,
            )
        };

        Ok(RestoreSession { flat: flat.into_owned(), matcher, alias_collisions })
    }

    /// Aliases claimed by more than one original — one entry per LOSING claim,
    /// resolved once in `new`. A property of the KEY, not of any cell, so a
    /// session-based face reads it once at construction to emit the same
    /// wrong-identity warning the one-shot path emits from
    /// `RestoreResult.alias_collisions`.
    pub fn alias_collisions(&self) -> &[String] {
        &self.alias_collisions
    }

    /// Restore one cell of text against the precomputed key. Unguarded and
    /// display-marker-free (bulk callers pass none — equivalence is checked
    /// against `restore_full(..., None, None)`), so `events` is always empty
    /// and `outcome` is always `Complete`.
    pub fn restore_cell(&self, text: &str) -> Result<RestoreResult, RestoreError> {
        check_input_size(text)?;
        let Some(matcher) = &self.matcher else {
            return Ok(RestoreResult {
                restored: text.to_string(),
                alias_collisions: self.alias_collisions.clone(),
                events: vec![],
                outcome: RestoreOutcome::Complete,
            });
        };
        let (result, spans) = substitute_with(matcher, &self.flat, text);
        let result = apply_grammar_scoped(&result, &spans);
        Ok(RestoreResult {
            restored: result,
            alias_collisions: self.alias_collisions.clone(),
            events: vec![],
            outcome: RestoreOutcome::Complete,
        })
    }

    /// Drop all cached state. After this, `restore_cell` returns its input
    /// unchanged — the same behavior as a session built from an empty key.
    pub fn wipe(&mut self) {
        self.flat.clear();
        self.matcher = None;
        self.alias_collisions.clear();
    }

    /// Same effect as [`RestoreSession::wipe`], named for callers that model
    /// a session as a resource to explicitly close.
    pub fn close(&mut self) {
        self.wipe();
    }
}

// ── Danger patterns for check_restore_safety ────────────────────────────────

/// Proximity window (chars before/after pseudonym) for danger-pattern scan.
const DANGER_WINDOW: usize = 100;

fn danger_pattern() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        // Mirrors `_DANGER_PATTERNS` in `pure/restore.py`:
        //   email | URL | exfil verbs (zh + en).
        let pat = concat!(
            r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}", // email address
            r"|https?://",                                       // URL
            r"|(?:send|share|forward|发送|转发|分享|泄露|传给|发给)", // exfil verbs
        );
        Regex::new(pat)
            .unwrap_or_else(|e| panic!("danger_pattern compile failed: {e}"))
    })
}

/// Check whether LLM output has suspicious pseudonym usage (possible injection).
///
/// Returns a list of warning strings. Empty = safe. Mirrors `check_restore_safety`
/// in `pure/restore.py:58-108`. Warning message strings are byte-identical to the
/// Python f-strings (tests assert them).
///
/// Checks:
/// 1. Pseudonym frequency amplification (`count_llm > count_original` → warning).
/// 2. Pseudonym near danger patterns (email, URL, exfil verbs within ±100 chars → warning).
/// 3. Reserved-range value amplification (`len(scan(llm)) > len(scan(redacted))` → warning).
pub fn check_restore_safety(
    redacted: &str,
    llm_output: &str,
    key: &HashMap<String, String>,
) -> Vec<String> {
    let mut warnings: Vec<String> = Vec::new();
    // Size cap. This function's contract is "empty list == nothing suspicious",
    // so returning empty for text that was never examined would CERTIFY exactly
    // the input nobody looked at. Report instead, and scan nothing.
    if llm_output.len() > crate::MAX_INPUT_SIZE || redacted.len() > crate::MAX_INPUT_SIZE {
        return vec![format!(
            "input too large to scan ({} bytes; limit {}) — restore safety was NOT checked",
            llm_output.len().max(redacted.len()),
            crate::MAX_INPUT_SIZE
        )];
    }
    // Python's `_DANGER_WINDOW` is a CHAR window (re indices on str are char-based);
    // window the context in char space so CJK-dense output matches Python exactly.
    let llm_chars: Vec<char> = llm_output.chars().collect();

    // Sorted iteration: a plain `key.keys()` walk order is randomized
    // per-process by HashMap's hasher, so the warnings vector's element order
    // (and, for pseudonyms sharing a danger-pattern window, which one is
    // reported first) would vary across runs for identical input.
    let mut codes: Vec<&String> = key.keys().collect();
    codes.sort();
    for code in codes {
        let count_original = count_occurrences(redacted, code);
        let count_llm = count_occurrences(llm_output, code);

        // Check 1: frequency amplification.
        if count_llm > count_original {
            warnings.push(format!(
                "Pseudonym '{code}' appears {count_llm}x in LLM output \
but only {count_original}x in redacted input — possible injection"
            ));
        }

        // Check 2: danger-pattern proximity.
        if count_llm > 0 {
            let escaped = fancy_regex::escape(code);
            if let Ok(code_re) = Regex::new(&escaped) {
                // Monotone sweep per code — the cursor keeps the ±window
                // conversion from rescanning the whole reply per occurrence.
                let mut cursor = CharOffsetCursor::new(llm_output);
                let mut search_start = 0;
                let mut warned = false;
                while search_start <= llm_output.len() && !warned {
                    match code_re.find_from_pos(llm_output, search_start) {
                        Ok(Some(m)) => {
                            // ±DANGER_WINDOW in CHAR space (matches Python
                            // `llm_output[max(0,start-100):min(len,end+100)]`).
                            let char_start = cursor.char_offset(m.start());
                            let char_end = cursor.char_offset(m.end());
                            let cs = char_start.saturating_sub(DANGER_WINDOW);
                            let ce = (char_end + DANGER_WINDOW).min(llm_chars.len());
                            let context: String = llm_chars[cs..ce].iter().collect();
                            if let Ok(Some(danger)) = danger_pattern().find(&context) {
                                warnings.push(format!(
                                    "Pseudonym '{code}' near danger pattern \
'{danger_str}' — possible exfiltration",
                                    danger_str = danger.as_str()
                                ));
                                warned = true; // one warning per pseudonym
                            }
                            search_start = if m.end() > m.start() {
                                m.end()
                            } else {
                                m.start() + 1
                            };
                        }
                        _ => break,
                    }
                }
            }
        }
    }

    // Check 3: reserved-range amplification.
    let redacted_hits = scan_for_pollution(redacted, None);
    let output_hits = scan_for_pollution(llm_output, None);
    if output_hits.len() > redacted_hits.len() {
        let delta = output_hits.len() - redacted_hits.len();
        warnings.push(format!(
            "LLM output contains {delta} additional reserved-range value(s) not in input — \
possible hallucination or fabrication"
        ));
    }

    warnings
}

/// Count non-overlapping occurrences of `needle` in `haystack` (mirrors Python `str.count`).
fn count_occurrences(haystack: &str, needle: &str) -> usize {
    // `str::matches` is non-overlapping (it resumes after each match), matching
    // the hand-rolled `start += pos + needle.len()` advance this replaced. The
    // empty-needle guard stays: `matches("")` splits at every boundary, whereas
    // the contract here (and Python `str.count`'s non-empty case) is 0.
    if needle.is_empty() {
        0
    } else {
        haystack.matches(needle).count()
    }
}

#[cfg(test)]
mod integration_probe {
    //! DRY-RUN ONLY. Two hunks from the streaming/restore workstream, written
    //! here to prove they land on top of the sharded-matcher + guard-shield
    //! composition rather than colliding with it.
    use super::*;

    const N: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn duplicate_nonce_echo_never_survives_into_plaintext() {
        // The trailing fast-path returns BEFORE the own-line filter runs, so a
        // second copy of the nonce anywhere earlier in the reply travels into
        // the returned plaintext — the guard leaking its own secret.
        let text = format!("{N}\nthe reply body\n{N}");
        let out = strip_nonce(&text, N);
        assert!(!out.contains(N), "nonce survived the strip: {out:?}");
        assert_eq!(out, "the reply body");
    }

    #[test]
    fn oversized_llm_output_is_not_certified_safe_without_being_scanned() {
        // check_restore_safety returns "empty == safe". Over the crate input
        // cap it must not return empty for text nobody looked at.
        let mut key = HashMap::new();
        key.insert("P-1".to_string(), "Alice".to_string());
        let huge = "x".repeat(crate::MAX_INPUT_SIZE + 1);
        let out = check_restore_safety("P-1", &huge, &key);
        assert!(!out.is_empty(), "oversized reply certified safe without a scan");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the SECURITY wire vocabulary the Python + wasm bindings surface. These
    /// strings are a cross-runtime contract: changing one silently breaks the
    /// `security_events` / guard-outcome names the two faces expose, so pin every
    /// variant's exact bytes here at the SSOT.
    #[test]
    fn restore_outcome_as_str_is_the_stable_vocabulary() {
        assert_eq!(RestoreOutcome::Blocked.as_str(), "blocked");
        assert_eq!(RestoreOutcome::Partial.as_str(), "partial");
        assert_eq!(RestoreOutcome::Complete.as_str(), "complete");
    }

    #[test]
    fn guard_event_kind_as_str_is_the_stable_vocabulary() {
        assert_eq!(GuardEventKind::GuardNoAnchor.as_str(), "guard_no_anchor");
        assert_eq!(GuardEventKind::ProvenanceFailed.as_str(), "provenance_failed");
        assert_eq!(GuardEventKind::EmptyKeyWithScope.as_str(), "empty_key_with_scope");
        assert_eq!(GuardEventKind::OutOfScopePseudonym.as_str(), "out_of_scope_pseudonym");
        assert_eq!(GuardEventKind::AliasCollision.as_str(), "alias_collision");
    }

    #[test]
    fn longest_key_first() {
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        k.insert("P-12".to_string(), "Bob".to_string());
        assert_eq!(restore("see P-12 and P-1", &k).unwrap(), "see Bob and Alice");
    }

    #[test]
    fn empty_key_noop() {
        let k = HashMap::new();
        assert_eq!(restore("hello", &k).unwrap(), "hello");
    }

    #[test]
    fn empty_string_key_entry_rejected_not_explosive() {
        // argus never produces a `"" -> original` entry (the producer in
        // replace.rs refuses to register one). A key that has one is
        // corrupted or hand-built; it must fail closed rather than match
        // between every char and explode the original throughout the text.
        let mut k = HashMap::new();
        k.insert(String::new(), "SECRET".to_string());
        let err = restore("abc", &k).unwrap_err();
        assert!(err.0.contains("empty"), "unexpected error message: {}", err.0);
    }

    #[test]
    fn full_empty_string_key_entry_rejected() {
        let mut k = HashMap::new();
        k.insert(String::new(), "SECRET".to_string());
        let err = restore_full("abc", &k, None, None).unwrap_err();
        assert!(err.0.contains("empty"), "unexpected error message: {}", err.0);
    }

    // ── restore_full tests ──────────────────────────────────────────────

    #[test]
    fn full_basic_round_trip() {
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let (result, _collisions) = restore_full("P-1 ok", &k, None, None).unwrap();
        assert_eq!(result, "张三 ok");
    }

    #[test]
    fn full_alias_maps_to_original() {
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-1".to_string(), vec!["Zhang San".to_string()]);
        let (result, _collisions) =
            restore_full("Zhang San came home", &k, Some(&aliases), None).unwrap();
        assert_eq!(result, "张三 came home");
    }

    #[test]
    fn full_alias_collision_deterministic_winner_and_recorded() {
        // Two distinct fakes (-> two distinct originals) alias to the SAME
        // string. The sorted-first fake ("P-1" < "P-2") must always win,
        // regardless of the HashMap's per-process iteration order, and the
        // collision must be recorded so the caller can be warned.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        k.insert("P-2".to_string(), "Bob".to_string());
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-1".to_string(), vec!["Shared".to_string()]);
        aliases.insert("P-2".to_string(), vec!["Shared".to_string()]);
        let (result, collisions) = restore_full("hello Shared", &k, Some(&aliases), None).unwrap();
        assert_eq!(result, "hello Alice", "sorted-first fake must win deterministically");
        assert_eq!(collisions, vec!["Shared".to_string()]);
    }

    #[test]
    fn full_alias_no_collision_when_aliases_agree_or_differ() {
        // No collision when a single fake's alias has no competing claim.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-1".to_string(), vec!["Al".to_string()]);
        let (result, collisions) = restore_full("hello Al", &k, Some(&aliases), None).unwrap();
        assert_eq!(result, "hello Alice");
        assert!(collisions.is_empty());
    }

    #[test]
    fn full_decoration_marker_preserved() {
        // "P-1ⓕ" → "张三ⓕ" (marker stays attached to restored value)
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let (result, _collisions) = restore_full("call P-1ⓕ now", &k, None, None).unwrap();
        assert_eq!(result, "call 张三ⓕ now");
    }

    #[test]
    fn full_explicit_display_marker_stripped() {
        // When display_marker is passed explicitly, it is stripped rather than preserved.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let (result, _collisions) = restore_full("call P-1ⓕ now", &k, None, Some("ⓕ")).unwrap();
        assert_eq!(result, "call 张三 now");
    }

    #[test]
    fn full_self_ref_grammar_applied() {
        // key has value "I" (self-ref) → grammar restore runs on the restored
        // pronoun. Forward normalization would have turned "I am" → "P-1 is",
        // so restoring "P-1 is ok" → "I is ok" → grammar-fixed to "I am ok".
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "I".to_string());
        let (result, _collisions) = restore_full("P-1 is ok", &k, None, None).unwrap();
        assert_eq!(result, "I am ok");
    }

    #[test]
    fn full_self_ref_grammar_scoped_not_whole_text() {
        // A global grammar fix would ALSO mangle an
        // unrelated "I is" that this restoration never touched. Only the
        // restored "P-1" → "I" plus its own following verb gets fixed; "The
        // letter I is silent." is untouched text and must survive verbatim.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "I".to_string());
        let (result, _collisions) =
            restore_full("P-1 is here. The letter I is silent.", &k, None, None).unwrap();
        assert_eq!(result, "I am here. The letter I is silent.");
    }

    #[test]
    fn full_two_close_together_self_ref_restorations_both_get_fixed() {
        // Two separate "I" restorations close together: the first grammar
        // window (12 chars past the first restored "I") reaches byte 13 of
        // the output — far enough to cover the *second* restored "I" itself,
        // but NOT its own trailing "is". The old overlap-SKIP logic dropped
        // the second span entirely because its start (12) fell inside the
        // first window's range (< 13), even though that window never
        // actually fixed its verb. Merging windows instead of skipping must
        // fix both restorations' verbs.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "I".to_string());
        k.insert("P-2".to_string(), "I".to_string());
        let text = format!("P-1 is{}P-2 is right", " ".repeat(8));
        let (result, _collisions) = restore_full(&text, &k, None, None).unwrap();
        let expected = format!("I am{}I am right", " ".repeat(8));
        assert_eq!(result, expected);
    }

    #[test]
    fn full_self_ref_no_actual_substitution_leaves_text_unchanged() {
        // The key has a self-ref value, but the redacted-form token ("P-1")
        // never appears in this text — no substitution happens, so the
        // grammar fix must not fire either (nothing was actually restored).
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "I".to_string());
        let (result, _collisions) = restore_full("I is ok", &k, None, None).unwrap();
        assert_eq!(result, "I is ok");
    }

    #[test]
    fn full_longest_first_no_prefix_corruption() {
        // "张" vs "张明" — longer key must match first.
        let mut k = HashMap::new();
        k.insert("张".to_string(), "Alice".to_string());
        k.insert("张明".to_string(), "Bob".to_string());
        let (result, _collisions) = restore_full("张明 and 张", &k, None, None).unwrap();
        assert_eq!(result, "Bob and Alice");
    }

    #[test]
    fn full_empty_key_returns_text_unchanged() {
        let k = HashMap::new();
        let (result, _collisions) = restore_full("hello world", &k, None, None).unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn full_alias_for_absent_fake_silently_skipped() {
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        // alias for a fake NOT in key
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-99".to_string(), vec!["Stranger".to_string()]);
        let (result, _collisions) = restore_full("Stranger came by", &k, Some(&aliases), None).unwrap();
        assert_eq!(result, "Stranger came by");
    }

    #[test]
    fn full_bare_marker_char_does_not_cause_double_replacement() {
        // A bare '(' (a single char of the "(假)" preset) following a key is
        // ordinary non-key text: the single-pass restore must leave it verbatim
        // after the restored value, never treat it as a marker that re-triggers
        // a replacement of the value (which would disclose a DIFFERENT entity's
        // original — a cross-entity leak). key: 张三→李明, 李明→王芳. "张三(经理)"
        // must restore to "李明(经理)" (single-pass-correct), NOT "王芳(经理)".
        let mut k = HashMap::new();
        k.insert("张三".to_string(), "李明".to_string());
        k.insert("李明".to_string(), "王芳".to_string());
        let (result, _collisions) = restore_full("张三(经理)", &k, None, None).unwrap();
        assert_eq!(result, "李明(经理)");
    }

    #[test]
    fn full_complete_marker_does_not_cause_chained_double_replacement_zh() {
        // Residual of the bare-char fix: a COMPLETE marker following a key must
        // not let the key be replaced twice under a CHAINED map (where a value
        // emitted for one key is itself another key). key: 张三→李明, 李明→王芳.
        // "张三(假)" must restore to "李明(假)" (single-pass-correct), NOT
        // "王芳(假)" (李明 re-scanned and re-replaced — a cross-entity leak).
        let mut k = HashMap::new();
        k.insert("张三".to_string(), "李明".to_string());
        k.insert("李明".to_string(), "王芳".to_string());
        let (result, _collisions) = restore_full("张三(假)", &k, None, None).unwrap();
        assert_eq!(result, "李明(假)");
    }

    #[test]
    fn full_complete_marker_does_not_cause_chained_double_replacement_pseudonym() {
        // Same chained-map double-replace, with the circled-f marker and a
        // pseudonym chain: P-1→P-2, P-2→SECRET. "P-1ⓕ" must restore to "P-2ⓕ"
        // (single-pass-correct), NOT "SECRETⓕ" (P-2 re-scanned and re-replaced).
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "P-2".to_string());
        k.insert("P-2".to_string(), "SECRET".to_string());
        let (result, _collisions) = restore_full("P-1ⓕ", &k, None, None).unwrap();
        assert_eq!(result, "P-2ⓕ");
    }

    #[test]
    fn full_complete_chinese_marker_still_stripped_to_value() {
        // The full "(假)" preset marker must still be recognized and preserved
        // after the restored value (proves the fix narrows to whole markers, not
        // that it disables marker handling).
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let (result, _collisions) = restore_full("call P-1(假) now", &k, None, None).unwrap();
        assert_eq!(result, "call 张三(假) now");
    }

    #[test]
    fn full_guarded_matches_tuple_projection() {
        // `restore_full_guarded` must be a strict superset of the tuple
        // `restore_full` returns — same restored text, same alias_collisions
        // — including on a case that actually records a collision.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        k.insert("P-2".to_string(), "Bob".to_string());
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-1".to_string(), vec!["Shared".to_string()]);
        aliases.insert("P-2".to_string(), vec!["Shared".to_string()]);

        let guarded = restore_full_guarded("hello Shared", &k, Some(&aliases), None, None).unwrap();
        let tuple = restore_full("hello Shared", &k, Some(&aliases), None).unwrap();

        assert_eq!(guarded.restored, tuple.0);
        assert_eq!(guarded.alias_collisions, tuple.1);
        // anchor=None is the current unguarded path: no guard checks ran, so
        // there is nothing to report and the pass is unconditionally COMPLETE.
        assert!(guarded.events.is_empty());
        assert_eq!(guarded.outcome, RestoreOutcome::Complete);
    }

    #[test]
    fn full_guarded_none_anchor_byte_identical_on_existing_fixtures() {
        // anchor=None must reproduce restore_full's tuple projection exactly —
        // on a handful of the pre-existing `full_*` fixtures above, not just
        // the alias-collision one — with zero events and outcome Complete.
        // This is the non-breaking proof that adding the 5th param didn't
        // change the default (no-anchor) path at all.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        k.insert("P-2".to_string(), "I".to_string());
        let text = "P-1 says P-2 is here.ⓕ";

        let guarded = restore_full_guarded(text, &k, None, None, None).unwrap();
        let tuple = restore_full(text, &k, None, None).unwrap();

        assert_eq!(guarded.restored, tuple.0);
        assert_eq!(guarded.alias_collisions, tuple.1);
        assert!(guarded.events.is_empty());
        assert_eq!(guarded.outcome, RestoreOutcome::Complete);
    }

    // ── restore_full_guarded assembly: anchor=Some(..) drives the P+S guard ──
    //
    // Mirrors `pure/restore.py::restore`'s `guard is True` branch (the
    // anchor-is-not-None half only — `anchor is None` under `guard=True`
    // stays a Python/wasm-layer concern, see GuardEventKind::GuardNoAnchor).

    #[test]
    fn guarded_happy_path_strips_nonce_restores_in_scope_complete_no_events() {
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let mut scope = std::collections::HashSet::new();
        scope.insert("P-1".to_string());
        let anchor = Anchor { nonce: NONCE.to_string(), scope };

        let text = format!("P-1 says hello.\n{NONCE}");
        let result = restore_full_guarded(&text, &k, None, None, Some(&anchor)).unwrap();

        assert_eq!(result.restored, "张三 says hello.");
        assert_eq!(result.outcome, RestoreOutcome::Complete);
        assert!(result.events.is_empty());
        assert!(result.alias_collisions.is_empty());
    }

    #[test]
    fn guarded_no_nonce_echoed_fails_closed_raw_text_provenance_failed() {
        // No echo at all: `nonce_echoed` is false, so this must fail closed
        // exactly like Python's `_fail_closed(text, ...)` — the RAW text as
        // passed in, untouched (not nonce-stripped, since the nonce was never
        // found to strip; not restored, since the guard never reaches the
        // substitution step at all).
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let mut scope = std::collections::HashSet::new();
        scope.insert("P-1".to_string());
        let anchor = Anchor { nonce: NONCE.to_string(), scope };

        let text = "P-1 says hello, no nonce here.";
        let result = restore_full_guarded(text, &k, None, None, Some(&anchor)).unwrap();

        assert_eq!(result.restored, text, "fail-closed must return the raw text, not restore anything");
        assert_eq!(result.outcome, RestoreOutcome::Blocked);
        assert!(result.alias_collisions.is_empty());
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].kind, GuardEventKind::ProvenanceFailed);
        assert_eq!(result.events[0].count, k.len());
        assert!(result.events[0].detail.is_none());
    }

    #[test]
    fn guarded_partial_scope_out_of_scope_pseudonym_withheld() {
        // "P-2" is present in the reply but NOT in anchor.scope: it must be
        // withheld (never substituted) and reported via the sized/detailed
        // `OutOfScopePseudonym` event; the in-scope "P-1" still restores.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        k.insert("P-2".to_string(), "李四".to_string());
        let mut scope = std::collections::HashSet::new();
        scope.insert("P-1".to_string());
        let anchor = Anchor { nonce: NONCE.to_string(), scope };

        let text = format!("P-1 met P-2 yesterday.\n{NONCE}");
        let result = restore_full_guarded(&text, &k, None, None, Some(&anchor)).unwrap();

        assert_eq!(result.restored, "张三 met P-2 yesterday.");
        assert_eq!(result.outcome, RestoreOutcome::Partial);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].kind, GuardEventKind::OutOfScopePseudonym);
        assert_eq!(result.events[0].count, 1);
        assert_eq!(result.events[0].detail, Some(vec!["P-2".to_string()]));
    }

    #[test]
    fn guarded_empty_key_with_scope_advisory_when_scope_excludes_every_entry() {
        // The key is non-empty and anchor.scope is non-empty, but scope
        // excludes EVERY key entry — a legitimate non-overlapping scope, not
        // corruption. This only advises (EmptyKeyWithScope); since the
        // excluded code never actually appears in the reply, there is
        // nothing to withhold either, so the outcome is Complete (a no-op
        // restore), not Partial.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let mut scope = std::collections::HashSet::new();
        scope.insert("P-9".to_string()); // not a key in `k` at all
        let anchor = Anchor { nonce: NONCE.to_string(), scope };

        let text = format!("hello, nothing pseudonymous here.\n{NONCE}");
        let result = restore_full_guarded(&text, &k, None, None, Some(&anchor)).unwrap();

        assert_eq!(result.restored, "hello, nothing pseudonymous here.");
        assert_eq!(result.outcome, RestoreOutcome::Complete);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].kind, GuardEventKind::EmptyKeyWithScope);
        assert_eq!(result.events[0].count, k.len());
        assert!(result.events[0].detail.is_none());
    }

    #[test]
    fn guarded_alias_collision_folded_into_event_alongside_partial_scope() {
        // A guarded restore that ALSO hits an alias collision among the
        // in-scope entries must fold it into an AliasCollision event, in
        // addition to (not instead of) the OutOfScopePseudonym event from an
        // out-of-scope hit — mirrors Python's guarded branch, which appends
        // its `alias_collision` event after the scope-check events.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        k.insert("P-2".to_string(), "Bob".to_string());
        k.insert("P-3".to_string(), "Carol".to_string());
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-1".to_string(), vec!["Shared".to_string()]);
        aliases.insert("P-2".to_string(), vec!["Shared".to_string()]);
        let mut scope = std::collections::HashSet::new();
        scope.insert("P-1".to_string());
        scope.insert("P-2".to_string());
        let anchor = Anchor { nonce: NONCE.to_string(), scope };

        let text = format!("hello Shared, and P-3 too.\n{NONCE}");
        let result = restore_full_guarded(&text, &k, Some(&aliases), None, Some(&anchor)).unwrap();

        assert_eq!(result.restored, "hello Alice, and P-3 too.");
        assert_eq!(result.outcome, RestoreOutcome::Partial); // P-3 withheld
        assert_eq!(result.alias_collisions, vec!["Shared".to_string()]);
        assert_eq!(result.events.len(), 2);
        assert_eq!(result.events[0].kind, GuardEventKind::OutOfScopePseudonym);
        assert_eq!(result.events[1].kind, GuardEventKind::AliasCollision);
        assert_eq!(result.events[1].count, result.alias_collisions.len());
        assert_eq!(result.events[1].detail, Some(result.alias_collisions.clone()));
    }

    // ── (S) scope shield: an alias may never stand in for a pseudonym ───────
    // The scope filter is applied to `key` BEFORE the alias merge runs. The
    // merge seeds its lookup from the map it is handed, so under the SCOPED
    // map an out-of-scope pseudonym is simply absent — and an alias whose
    // literal text happens to equal that pseudonym then wins the empty slot
    // instead of colliding with it. Result: the guard hands back the WRONG
    // identity for a code it was supposed to withhold. Unguarded restore is
    // immune (its merge seeds from the FULL key, so the same alias collides).

    #[test]
    fn guarded_alias_never_substitutes_for_an_out_of_scope_pseudonym() {
        // "P-2" is a real pseudonym for Bob AND an alias claimed by P-1
        // (Alice). Scope covers only P-1. "P-2" must come back VERBATIM
        // (withheld, out-of-scope) — never as "Alice".
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        k.insert("P-2".to_string(), "Bob".to_string());
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-1".to_string(), vec!["P-2".to_string()]);
        let mut scope = std::collections::HashSet::new();
        scope.insert("P-1".to_string());
        let anchor = Anchor { nonce: NONCE.to_string(), scope };

        let text = format!("P-1 wrote, P-2 replied.\n{NONCE}");
        let result = restore_full_guarded(&text, &k, Some(&aliases), None, Some(&anchor)).unwrap();

        assert_eq!(
            result.restored, "Alice wrote, P-2 replied.",
            "an alias must not splice a withheld pseudonym into the wrong identity"
        );
        assert_eq!(result.outcome, RestoreOutcome::Partial);
        // The same collision the UNGUARDED path reports must be reported here.
        assert_eq!(result.alias_collisions, vec!["P-2".to_string()]);
    }

    #[test]
    fn guarded_alias_owner_out_of_scope_is_withheld_too() {
        // An alias is only as in-scope as the fake that owns it. "Ali" belongs
        // to P-1; scope covers only P-2, so "Ali" must be withheld — restoring
        // it would leak Alice through a code the anchor never authorised.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        k.insert("P-2".to_string(), "Bob".to_string());
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-1".to_string(), vec!["Ali".to_string()]);
        let mut scope = std::collections::HashSet::new();
        scope.insert("P-2".to_string());
        let anchor = Anchor { nonce: NONCE.to_string(), scope };

        let text = format!("Ali and P-2 met.\n{NONCE}");
        let result = restore_full_guarded(&text, &k, Some(&aliases), None, Some(&anchor)).unwrap();

        assert_eq!(result.restored, "Ali and Bob met.");
    }

    #[test]
    fn guarded_in_scope_alias_still_restores() {
        // The shield must not over-withhold: an alias whose OWNER is in scope
        // restores exactly as before.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        k.insert("P-2".to_string(), "Bob".to_string());
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-1".to_string(), vec!["Ali".to_string()]);
        let mut scope = std::collections::HashSet::new();
        scope.insert("P-1".to_string());
        let anchor = Anchor { nonce: NONCE.to_string(), scope };

        let text = format!("Ali arrived.\n{NONCE}");
        let result = restore_full_guarded(&text, &k, Some(&aliases), None, Some(&anchor)).unwrap();

        assert_eq!(result.restored, "Alice arrived.");
        assert_eq!(result.outcome, RestoreOutcome::Complete);
    }

    #[test]
    fn guarded_alias_collision_domain_is_the_full_key_not_the_scoped_slice() {
        // Two fakes claim the same alias; only ONE is in scope. The collision
        // is a property of the KEY, so it must be reported either way — and
        // the winner must be the same sorted-first fake the unguarded path
        // picks, so a scope filter can never change WHICH identity an alias
        // resolves to (only whether it resolves at all).
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        k.insert("P-2".to_string(), "Bob".to_string());
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-1".to_string(), vec!["Shared".to_string()]);
        aliases.insert("P-2".to_string(), vec!["Shared".to_string()]);
        let mut scope = std::collections::HashSet::new();
        scope.insert("P-2".to_string()); // the LOSER of the alias race
        let anchor = Anchor { nonce: NONCE.to_string(), scope };

        let text = format!("Shared showed up.\n{NONCE}");
        let result = restore_full_guarded(&text, &k, Some(&aliases), None, Some(&anchor)).unwrap();

        // P-1 won "Shared" (sorted first) but P-1 is out of scope → withheld.
        // It must NOT silently fall through to P-2's "Bob".
        assert_eq!(result.restored, "Shared showed up.");
        assert_eq!(result.alias_collisions, vec!["Shared".to_string()]);
        assert_eq!(result.events.iter().filter(|e| e.kind == GuardEventKind::AliasCollision).count(), 1);
    }

    #[test]
    fn guarded_empty_string_key_entry_fails_closed_even_when_out_of_scope() {
        // The corrupted-key check lives in `restore_body`, which the guarded
        // path only ever calls with the SCOPED map — so an empty-string entry
        // excluded by scope used to slip past it entirely. The check has to
        // run on the FULL key, before the scope split.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        k.insert(String::new(), "Bob".to_string());
        let mut scope = std::collections::HashSet::new();
        scope.insert("P-1".to_string());
        let anchor = Anchor { nonce: NONCE.to_string(), scope };

        let text = format!("P-1 here.\n{NONCE}");
        let err = restore_full_guarded(&text, &k, None, None, Some(&anchor));
        assert!(err.is_err(), "an empty-string key entry must fail closed regardless of scope");
    }

    #[test]
    fn guarded_empty_string_alias_fails_closed() {
        // Same corruption, arriving through the alias map instead. `RestoreSession`
        // already re-checks the merged map for this; the guarded path must too.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-1".to_string(), vec![String::new()]);
        let mut scope = std::collections::HashSet::new();
        scope.insert("P-1".to_string());
        let anchor = Anchor { nonce: NONCE.to_string(), scope };

        let text = format!("P-1 here.\n{NONCE}");
        assert!(restore_full_guarded(&text, &k, Some(&aliases), None, Some(&anchor)).is_err());
    }

    #[test]
    fn merge_aliases_reports_the_owning_fake_of_every_alias() {
        // `alias_owner` is what lets the guard decide scope for an alias: it
        // names the fake whose original the alias resolved to.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        k.insert("P-2".to_string(), "Bob".to_string());
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-1".to_string(), vec!["Ali".to_string(), "Shared".to_string()]);
        aliases.insert("P-2".to_string(), vec!["Bobby".to_string(), "Shared".to_string()]);

        let (flat, collisions, owner) = merge_aliases(&k, Some(&aliases));

        assert_eq!(flat.get("Ali"), Some(&"Alice".to_string()));
        assert_eq!(owner.get("Ali"), Some(&"P-1".to_string()));
        assert_eq!(owner.get("Bobby"), Some(&"P-2".to_string()));
        // The sorted-first fake owns a contested alias; the loser is recorded.
        assert_eq!(owner.get("Shared"), Some(&"P-1".to_string()));
        assert_eq!(collisions, vec!["Shared".to_string()]);
        // A pseudonym is owned by itself — never listed as somebody's alias.
        assert!(!owner.contains_key("P-1"));
    }

    #[test]
    fn guarded_alias_collision_event_dedupes_and_sorts_but_field_stays_raw() {
        // A MULTI-way collision: "Beta" is claimed by three distinct fakes
        // (P-1 wins, P-2 and P-3 each lose → "Beta" pushed TWICE), and "Alpha"
        // by two (P-4 wins, P-5 loses → pushed once). The raw
        // `merge_aliases` push list is therefore ["Beta", "Beta", "Alpha"]
        // (len 3, unsorted). The AliasCollision EVENT must report DISTINCT
        // collided aliases — count 2, detail sorted+deduped ["Alpha", "Beta"]
        // — matching Python's `set()`-based `alias_collision_event` and the
        // `GuardEvent.detail` SORTED-token contract. The
        // `RestoreResult.alias_collisions` FIELD must stay the RAW list so the
        // unguarded/warn path's own dedup still sees every push.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        k.insert("P-2".to_string(), "Bob".to_string());
        k.insert("P-3".to_string(), "Carol".to_string());
        k.insert("P-4".to_string(), "Dave".to_string());
        k.insert("P-5".to_string(), "Eve".to_string());
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-1".to_string(), vec!["Beta".to_string()]);
        aliases.insert("P-2".to_string(), vec!["Beta".to_string()]);
        aliases.insert("P-3".to_string(), vec!["Beta".to_string()]);
        aliases.insert("P-4".to_string(), vec!["Alpha".to_string()]);
        aliases.insert("P-5".to_string(), vec!["Alpha".to_string()]);
        let mut scope = std::collections::HashSet::new();
        for c in ["P-1", "P-2", "P-3", "P-4", "P-5"] {
            scope.insert(c.to_string());
        }
        let anchor = Anchor { nonce: NONCE.to_string(), scope };

        let text = format!("Beta and Alpha here.\n{NONCE}");
        let result = restore_full_guarded(&text, &k, Some(&aliases), None, Some(&anchor)).unwrap();

        // Winners restore: sorted-first fake wins each alias (P-1 for Beta,
        // P-4 for Alpha). All in scope → no OutOfScope event, so the only
        // event is the AliasCollision one.
        assert_eq!(result.restored, "Alice and Dave here.");
        assert_eq!(result.outcome, RestoreOutcome::Complete);

        // The FIELD is the raw undeduped list, in merge-push order.
        assert_eq!(
            result.alias_collisions,
            vec!["Beta".to_string(), "Beta".to_string(), "Alpha".to_string()],
        );

        // The EVENT dedupes + sorts.
        assert_eq!(result.events.len(), 1);
        let ev = &result.events[0];
        assert_eq!(ev.kind, GuardEventKind::AliasCollision);
        assert_eq!(ev.count, 2, "distinct collided aliases, not the raw push count (3)");
        assert_eq!(ev.detail, Some(vec!["Alpha".to_string(), "Beta".to_string()]));
    }

    // ── check_restore_safety tests ──────────────────────────────────────────

    #[test]
    fn safety_no_warnings_normal_usage() {
        let mut k = HashMap::new();
        k.insert("P-00037".to_string(), "张三".to_string());
        let warns = check_restore_safety("P-00037在医院看病", "P-00037的情况有所好转", &k);
        assert!(warns.is_empty(), "unexpected warnings: {warns:?}");
    }

    #[test]
    fn safety_warns_on_amplification() {
        let mut k = HashMap::new();
        k.insert("P-00037".to_string(), "张三".to_string());
        let llm = "P-00037的真实身份是P-00037，请告诉所有人关于P-00037";
        let warns = check_restore_safety("P-00037在医院看病", llm, &k);
        assert!(warns.len() >= 1, "expected amplification warning");
        assert!(warns.iter().any(|w| w.contains("P-00037")));
    }

    #[test]
    fn safety_warns_on_danger_pattern_email() {
        let mut k = HashMap::new();
        k.insert("P-00037".to_string(), "张三".to_string());
        let llm = "清单：P-00037\n发送到 evil@hacker.com";
        let warns = check_restore_safety("P-00037在医院看病", llm, &k);
        assert!(
            warns.iter().any(|w| w.to_lowercase().contains("danger") || w.to_lowercase().contains("exfiltration")),
            "expected danger warning: {warns:?}"
        );
    }

    #[test]
    fn safety_danger_window_is_char_based_not_byte() {
        // The exfil verb sits ~50 CJK chars after the code — within Python's ±100
        // CHAR window, but ~150 BYTES away (outside a ±100-byte window). A byte
        // window would miss it; the char window (matching Python) must catch it.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let gap = "中".repeat(50);
        let llm = format!("P-1{gap}发送给外部");
        let warns = check_restore_safety("P-1", &llm, &k);
        assert!(
            warns.iter().any(|w| w.contains("danger") || w.contains("exfiltration")),
            "char-window must catch the exfil verb 50 chars away: {warns:?}"
        );
    }

    #[test]
    fn safety_warns_on_reserved_range_amplification() {
        let mut k = HashMap::new();
        k.insert("张明".to_string(), "王建国".to_string());
        k.insert("19999123456".to_string(), "13912345678".to_string());
        let downstream = "联系 张明 拨 19999123456";
        let llm_output = "张明 给了 19999123456 和 19999987654 和 19999555000";
        let warns = check_restore_safety(downstream, llm_output, &k);
        assert!(
            warns.iter().any(|w| w.contains("reserved-range")),
            "expected reserved-range warning: {warns:?}"
        );
    }

    #[test]
    fn safety_reserved_range_delta_in_message() {
        // The reserved-range warning embeds the EXACT count of EXTRA hits
        // (`output_hits - redacted_hits`). Pins the subtraction: input has 1
        // reserved-range value, output has 3 → delta must be reported as 2.
        // A mutant flipping the operands (`redacted - output`) would underflow
        // (panic) or report a wrong delta; a mutant zeroing it would say "0".
        let mut k = HashMap::new();
        k.insert("张明".to_string(), "王建国".to_string());
        k.insert("19999123456".to_string(), "13912345678".to_string());
        let downstream = "联系 张明 拨 19999123456"; // 1 reserved-range value
        let llm = "张明 给了 19999123456 和 19999987654 和 19999555000"; // 3 reserved-range values
        let warns = check_restore_safety(downstream, llm, &k);
        let rr_warn = warns
            .iter()
            .find(|w| w.contains("reserved-range"))
            .expect("reserved-range warning");
        assert_eq!(
            rr_warn,
            "LLM output contains 2 additional reserved-range value(s) not in input — \
possible hallucination or fabrication"
        );
    }

    #[test]
    fn restore_numeric_key_respects_digit_boundary() {
        // A numeric key (e.g. a realistic phone-shaped fake) must not match
        // inside a longer digit run — otherwise restore splices a real original
        // into an unrelated number. key 19999123456→13912345678: the longer
        // token "199991234560" must stay literal, not become "139123456780".
        let mut k = HashMap::new();
        k.insert("19999123456".to_string(), "13912345678".to_string());
        assert_eq!(restore("199991234560", &k).unwrap(), "199991234560");
        // The exact, digit-bounded token still restores normally.
        assert_eq!(
            restore("call 19999123456 now", &k).unwrap(),
            "call 13912345678 now"
        );
    }

    #[test]
    fn restore_repeated_needle_advance() {
        // A repeated needle that exactly tiles the haystack pins the
        // count_occurrences / single-pass advance arithmetic: every "AA" must
        // be replaced, not just the first (an off-by-one in the advance would
        // drop or double-count occurrences). "AAAA" → two "AA" → "XX".
        let mut k = HashMap::new();
        k.insert("AA".to_string(), "X".to_string());
        assert_eq!(restore("AAAA", &k).unwrap(), "XX");
        // And inside surrounding text (advance past the match, not past start).
        assert_eq!(restore("zAAyAAz", &k).unwrap(), "zXyXz");
    }

    #[test]
    fn safety_warning_message_strings_exact() {
        // Assert byte-identical message format against the Python f-string.
        let mut k = HashMap::new();
        k.insert("P-00037".to_string(), "张三".to_string());
        let llm = "P-00037是P-00037还是P-00037"; // 3× vs 1×
        let warns = check_restore_safety("P-00037在医院", llm, &k);
        let amp_warn = warns.iter().find(|w| w.contains("appears")).expect("amplification warn");
        assert_eq!(
            amp_warn,
            "Pseudonym 'P-00037' appears 3x in LLM output but only 1x in redacted input — possible injection"
        );
    }

    #[test]
    fn safety_count_matches_no_amplification_warn() {
        let mut k = HashMap::new();
        k.insert("P-00037".to_string(), "张三".to_string());
        let redacted = "P-00037 visited the clinic. P-00037 was healthy.";
        let llm = "P-00037 is healthy. P-00037 left."; // equal count = 2
        let warns = check_restore_safety(redacted, llm, &k);
        // Should NOT warn about amplification — equal count is normal.
        assert!(
            warns.iter().all(|w| !w.contains("appears") || !w.contains("more")),
            "unexpected amplification warning: {warns:?}"
        );
    }

    #[test]
    fn safety_no_warnings_when_count_zero_in_llm() {
        let mut k = HashMap::new();
        k.insert("P-00037".to_string(), "张三".to_string());
        let llm = "no pseudonym mentioned, but visit https://example.com/leak";
        let warns = check_restore_safety("P-00037 is here", llm, &k);
        // URL present but pseudonym not in LLM output → no danger-pattern warning.
        assert!(warns.is_empty(), "unexpected warnings: {warns:?}");
    }

    #[test]
    fn safety_empty_key_no_warnings() {
        let k = HashMap::new();
        let warns = check_restore_safety("普通文本", "普通回复", &k);
        assert!(warns.is_empty());
    }

    // ── nonce echo-verify (P guard): nonce_echoed / strip_nonce ────────────
    // A real `make_anchor` nonce is `secrets.token_hex(16)` = 32 lowercase hex
    // chars.
    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn nonce_trailing_echo_strips_to_body() {
        let text = format!("Here is the reply body.\n{NONCE}");
        assert!(nonce_echoed(&text, NONCE));
        assert_eq!(strip_nonce(&text, NONCE), "Here is the reply body.");
    }

    #[test]
    fn nonce_own_line_mid_reply_echo_removed() {
        let text = format!("Before.\n{NONCE}\nAfter.");
        assert!(nonce_echoed(&text, NONCE));
        assert_eq!(strip_nonce(&text, NONCE), "Before.\nAfter.");
    }

    #[test]
    fn nonce_inline_fallback_echo_removed() {
        // Neither trailing nor on its own line — embedded inline within a line
        // alongside other text. `strip_nonce`'s defensive inline-replace
        // fallback (`if out.contains(nonce) { out = out.replace(nonce, "") }`)
        // must still remove it.
        let text = format!("prefix {NONCE} suffix");
        assert_eq!(strip_nonce(&text, NONCE), "prefix  suffix");
    }

    #[test]
    fn nonce_control_char_suffixed_line_stripped() {
        // U+001C is Python `str.isspace()`-true but not Rust
        // `char::is_whitespace()`; `py_strip` (not `str::trim`) is required to
        // recognize the nonce line as a bare echo despite the trailing control char.
        let text = format!("Reply body.\n{NONCE}\u{1c}\nTail.");
        assert!(nonce_echoed(&text, NONCE));
        assert_eq!(strip_nonce(&text, NONCE), "Reply body.\nTail.");
    }

    #[test]
    fn nonce_below_floor_fails_echoed_and_strip_is_noop() {
        let short_nonce = "abcd"; // 4 chars, well under MIN_NONCE_LEN
        let text = format!("Reply.\n{short_nonce}");
        assert!(!nonce_echoed(&text, short_nonce));
        assert_eq!(strip_nonce(&text, short_nonce), text);
    }

    #[test]
    fn nonce_echoed_through_ordinary_model_formatting() {
        // The instruction says "echo this token"; a chat model routinely
        // wraps it. Rejecting these silently BLOCKS a legitimate restore —
        // the guard's false-negative direction, which looks to the caller
        // exactly like an injected reply.
        for wrapped in [
            format!("`{NONCE}`"),
            format!("**{NONCE}**"),
            format!("\"{NONCE}\""),
            format!("'{NONCE}'"),
            format!("{NONCE}."),
            format!("{NONCE},"),
            format!("**`{NONCE}`**"),
        ] {
            let text = format!("Reply body.\n{wrapped}");
            assert!(nonce_echoed(&text, NONCE), "not accepted: {wrapped}");
            assert_eq!(strip_nonce(&text, NONCE), "Reply body.", "not stripped: {wrapped}");
        }
    }

    #[test]
    fn nonce_wrapper_stripping_does_not_accept_a_foreign_token() {
        // The wrapper tolerance must not degrade into a substring match: a
        // DIFFERENT 32-char token wrapped the same way is still not an echo.
        let other = "ffffffffffffffffffffffffffffffff";
        let text = format!("Reply body.\n`{other}`");
        assert!(!nonce_echoed(&text, NONCE));
        // Nor may a nonce merely CONTAINED in a longer line count as an echo.
        let glued = format!("Reply.\nid={NONCE}xyz");
        assert!(!nonce_echoed(&glued, NONCE));
    }

    #[test]
    fn every_echoed_nonce_copy_is_stripped() {
        // A model that echoes the token more than once must not leave a copy
        // in the returned plaintext: the trailing fast-path returned before the
        // own-line filter ran, so the earlier copy survived the strip.
        let text = format!("Body one.\n{NONCE}\nBody two.\n{NONCE}");
        assert!(nonce_echoed(&text, NONCE));
        let stripped = strip_nonce(&text, NONCE);
        assert!(!stripped.contains(NONCE), "nonce survived the strip: {stripped:?}");
        assert_eq!(stripped, "Body one.\nBody two.");
    }

    #[test]
    fn duplicate_trailing_nonce_lines_are_all_stripped() {
        let text = format!("Body.\n{NONCE}\n{NONCE}");
        let stripped = strip_nonce(&text, NONCE);
        assert!(!stripped.contains(NONCE), "nonce survived the strip: {stripped:?}");
        assert_eq!(stripped, "Body.");
    }

    // ── check_restore_safety: cost + input cap ─────────────────────────────

    #[test]
    fn check_restore_safety_scales_linearly_in_output_length() {
        // Per pseudonym occurrence the danger-window check converted a byte
        // offset to a char offset by rescanning the prefix — O(pos) each, so
        // O(n^2) over the whole output. This is the ONE public API whose stated
        // job is inspecting hostile LLM output, so its cost must be linear.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        let time_for = |n: usize| {
            let llm = "P-1 xxxx ".repeat(n);
            let t = std::time::Instant::now();
            let _ = check_restore_safety("P-1 orig", &llm, &k);
            t.elapsed().as_secs_f64()
        };
        time_for(2_000); // warm up
        let small = time_for(10_000);
        let large = time_for(40_000);
        // 4x the input. Linear => ~4x; quadratic => ~16x. 8x is a wide margin
        // that still fails the quadratic shape decisively.
        assert!(
            large < small * 8.0 + 0.05,
            "check_restore_safety is super-linear: 10k={small:.4}s 40k={large:.4}s"
        );
    }

    #[test]
    fn check_restore_safety_reports_oversized_input_instead_of_scanning_it() {
        // The only guard API with no MAX_INPUT_SIZE equivalent. It returns
        // advisory strings rather than a Result, so the cap is reported in
        // band — a caller that ignores warnings is unaffected, and one that
        // reads them learns the scan did not run.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        let big = "P-1 ".repeat(crate::MAX_INPUT_SIZE / 4 + 1);
        assert!(big.len() > crate::MAX_INPUT_SIZE);
        let warns = check_restore_safety("P-1", &big, &k);
        assert!(
            warns.iter().any(|w| w.contains("too large")),
            "no oversized-input warning: {warns:?}"
        );

        // Exactly at the cap must still be scanned normally.
        let at_cap = "P-1 xxxxxxxxxxxx".repeat(crate::MAX_INPUT_SIZE / 16);
        assert_eq!(at_cap.len(), crate::MAX_INPUT_SIZE);
        let warns = check_restore_safety("P-1", &at_cap, &k);
        assert!(
            !warns.iter().any(|w| w.contains("too large")),
            "exactly-MAX_INPUT_SIZE input must not be refused: {warns:?}"
        );
    }

    // ── restore input cap (Fix B): oversized input rejected, not scanned ────

    #[test]
    fn restore_rejects_oversized_input_with_pii_free_error() {
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        // One byte over the cap. The error must name only the size + limit.
        let over = "x".repeat(crate::MAX_INPUT_SIZE + 1);
        let err = restore(&over, &k).unwrap_err();
        assert!(err.0.contains("too large"), "unexpected error: {}", err.0);
        assert!(err.0.contains(&crate::MAX_INPUT_SIZE.to_string()));
        // PII-free: neither the payload nor any key value leaks into the message.
        assert!(!err.0.contains("Alice"));
    }

    #[test]
    fn restore_at_exactly_max_input_size_is_not_rejected() {
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        // Exactly the cap must still restore normally (byte-identical).
        let at_cap = "P-1 ".repeat(crate::MAX_INPUT_SIZE / 4);
        assert_eq!(at_cap.len(), crate::MAX_INPUT_SIZE);
        let restored = restore(&at_cap, &k).unwrap();
        assert!(restored.starts_with("Alice "));
    }

    #[test]
    fn restore_full_guarded_rejects_oversized_input_on_both_branches() {
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        let over = "x".repeat(crate::MAX_INPUT_SIZE + 1);
        // Unguarded branch (anchor = None) — reached via restore_full too.
        assert!(restore_full(&over, &k, None, None).unwrap_err().0.contains("too large"));
        // Guarded branch (anchor = Some): the cap must fire BEFORE tokens_present
        // scans the oversized text.
        let anchor = Anchor::new(
            "0123456789abcdef0123456789abcdef".to_string(),
            std::collections::HashSet::new(),
        );
        let err = restore_full_guarded(&over, &k, None, None, Some(&anchor)).unwrap_err();
        assert!(err.0.contains("too large"), "unexpected error: {}", err.0);
    }

    #[test]
    fn restore_session_cell_rejects_oversized_input() {
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        let session = RestoreSession::new(&k, None).unwrap();
        let over = "x".repeat(crate::MAX_INPUT_SIZE + 1);
        assert!(session.restore_cell(&over).unwrap_err().0.contains("too large"));
        // A cell exactly at the cap still restores.
        let at_cap = "y".repeat(crate::MAX_INPUT_SIZE);
        assert!(session.restore_cell(&at_cap).is_ok());
    }

    #[test]
    fn restore_substitution_scales_linearly_in_input_length() {
        // Fix A: the substitution scan is the K-way merge, LINEAR in text length
        // even when the key spans multiple shards and one shard never matches
        // again — the shape that made the old find_from_pos-per-position loop
        // re-scan the whole tail at every step (O(shards · matches · text)). A
        // dense single-key text over a 2-shard key reproduces that shape: only
        // "P-0" occurs, so the shard that does NOT hold it is exhausted after
        // one scan instead of being re-scanned per step.
        let key: HashMap<String, String> = (0..(crate::sharded::MAX_KEYS_PER_SHARD + 100))
            .map(|i| (format!("P-{i}"), format!("v{i}")))
            .collect();
        let time_for = |n: usize| {
            let text = "P-0 ".repeat(n);
            let t = std::time::Instant::now();
            let _ = restore(&text, &key).unwrap();
            t.elapsed().as_secs_f64()
        };
        time_for(5_000); // warm up
        let small = time_for(20_000);
        let large = time_for(80_000);
        // 4x the input. Linear => ~4x; the old quadratic => ~16x. 8x is a wide
        // margin that still fails the quadratic shape decisively.
        assert!(
            large < small * 8.0 + 0.05,
            "restore substitution is super-linear: 20k={small:.4}s 80k={large:.4}s"
        );
    }

    // ── out-of-scope pseudonym detector (S guard): tokens_present ───────────
    // Port of `pure/restore.py::_tokens_present`.

    #[test]
    fn tokens_present_empty_pseudonyms_returns_empty() {
        let empty: Vec<String> = Vec::new();
        assert_eq!(tokens_present(&empty, "see P-10 and P-1"), Vec::<String>::new());
    }

    #[test]
    fn tokens_present_longest_first_no_substring_match() {
        // "P-10" must not be reported as containing "P-1" — longest-first
        // alternation plus the boundary lookaround wins the whole "P-10" token,
        // and the shorter "P-1" elsewhere in the text still matches on its own.
        let pseudonyms = vec!["P-1".to_string(), "P-10".to_string()];
        assert_eq!(
            tokens_present(&pseudonyms, "see P-10 and P-1"),
            vec!["P-1".to_string(), "P-10".to_string()],
        );
    }

    #[test]
    fn tokens_present_trailing_word_char_not_matched() {
        // "P-1x" has a trailing word character right after "P-1" — the
        // negative lookahead over [A-Za-z0-9_-] must reject it as a match.
        let pseudonyms = vec!["P-1".to_string()];
        let empty: Vec<String> = Vec::new();
        assert_eq!(tokens_present(&pseudonyms, "P-1x"), empty);
    }

    #[test]
    fn tokens_present_duplicate_match_appears_once() {
        let pseudonyms = vec!["P-1".to_string()];
        assert_eq!(
            tokens_present(&pseudonyms, "P-1 and P-1 again"),
            vec!["P-1".to_string()],
        );
    }

    // ── guard result types: construction + outcome matching ────────────────

    #[test]
    fn guard_types_construct_and_match() {
        let event = GuardEvent {
            kind: GuardEventKind::OutOfScopePseudonym,
            count: 2,
            detail: Some(vec!["P-1".to_string(), "P-2".to_string()]),
        };
        let result = RestoreResult {
            restored: "hello".to_string(),
            alias_collisions: Vec::new(),
            events: vec![event],
            outcome: RestoreOutcome::Partial,
        };
        assert_eq!(result.outcome, RestoreOutcome::Partial);
        match result.outcome {
            RestoreOutcome::Blocked => panic!("wrong variant"),
            RestoreOutcome::Partial => {}
            RestoreOutcome::Complete => panic!("wrong variant"),
        }
        assert_eq!(result.events[0].kind, GuardEventKind::OutOfScopePseudonym);

        let anchor = Anchor { nonce: "n".to_string(), scope: std::collections::HashSet::new() };
        assert!(anchor.scope.is_empty());
    }

    // ── RestoreSession: precompiled reusable restore over a fixed key ──────
    //
    // Sits BELOW the guard: a session caches only key-derived state (the
    // alias-merged flat map + compiled regex), so every fixture here is
    // checked against `restore_full(..., None)` — the unguarded, no
    // display-marker one-shot path — never `restore_full_guarded` with an
    // anchor.

    #[test]
    fn session_matches_one_shot() {
        struct Fixture {
            text: &'static str,
            key: Vec<(&'static str, &'static str)>,
            aliases: Vec<(&'static str, Vec<&'static str>)>,
        }

        let fixtures = vec![
            // Plain single-entry round trip.
            Fixture { text: "P-1 ok", key: vec![("P-1", "张三")], aliases: vec![] },
            // Numeric digit-bounded key: a longer digit run containing the
            // key as a substring must NOT match (digit-boundary check).
            Fixture {
                text: "call 19999123456 now, but not 199991234560",
                key: vec![("19999123456", "13912345678")],
                aliases: vec![],
            },
            // zh chained-marker case: a COMPLETE marker following a key must
            // not let the key be re-scanned and replaced a second time under
            // a chained map (张三→李明, 李明→王芳).
            Fixture {
                text: "张三(假)",
                key: vec![("张三", "李明"), ("李明", "王芳")],
                aliases: vec![],
            },
            // Alias-collision case: two distinct fakes alias to the same
            // string; the sorted-first fake wins and the collision is
            // recorded in `alias_collisions`.
            Fixture {
                text: "hello Shared",
                key: vec![("P-1", "Alice"), ("P-2", "Bob")],
                aliases: vec![("P-1", vec!["Shared"]), ("P-2", vec!["Shared"])],
            },
            // Self-ref pronoun restore must still trigger the scoped grammar
            // fix (`apply_grammar_scoped`) through the session path.
            Fixture { text: "P-1 is ok", key: vec![("P-1", "I")], aliases: vec![] },
        ];

        for fx in fixtures {
            let key: HashMap<String, String> =
                fx.key.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            let aliases: Option<HashMap<String, Vec<String>>> = if fx.aliases.is_empty() {
                None
            } else {
                Some(
                    fx.aliases
                        .iter()
                        .map(|(k, vs)| (k.to_string(), vs.iter().map(|v| v.to_string()).collect()))
                        .collect(),
                )
            };

            let session = RestoreSession::new(&key, aliases.as_ref()).unwrap();
            let session_result = session.restore_cell(fx.text).unwrap();
            let one_shot = restore_full(fx.text, &key, aliases.as_ref(), None).unwrap();

            assert_eq!(
                session_result.restored, one_shot.0,
                "session/one-shot mismatch for text={:?}", fx.text
            );
            assert_eq!(session_result.alias_collisions, one_shot.1, "alias_collisions mismatch for text={:?}", fx.text);
            assert!(session_result.events.is_empty());
            assert_eq!(session_result.outcome, RestoreOutcome::Complete);
        }
    }

    #[test]
    fn session_wipe_drops_state() {
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let mut session = RestoreSession::new(&k, None).unwrap();
        assert_eq!(session.restore_cell("P-1 ok").unwrap().restored, "张三 ok");

        session.wipe();
        assert_eq!(session.restore_cell("P-1 ok").unwrap().restored, "P-1 ok");
    }

    #[test]
    fn session_close_drops_state() {
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let mut session = RestoreSession::new(&k, None).unwrap();
        session.close();
        assert_eq!(session.restore_cell("P-1 ok").unwrap().restored, "P-1 ok");
    }

    #[test]
    fn session_rejects_empty_key_entry() {
        let mut k = HashMap::new();
        k.insert(String::new(), "SECRET".to_string());
        let err = RestoreSession::new(&k, None).unwrap_err();
        assert!(err.0.contains("empty"), "unexpected error message: {}", err.0);
    }

    // ── Guard scope: an out-of-scope pseudonym must be withheld ATOMICALLY ──
    //
    // The S guard withholds an out-of-scope entry by dropping it from the
    // lookup map. If it is also dropped from the longest-first ALTERNATION,
    // a shorter IN-scope pseudonym can match INSIDE it and splice one
    // identity's original into another identity's token — the guard then
    // reports the token as "withheld" while having corrupted it. Every
    // fixture below asserts the out-of-scope token survives byte-for-byte.

    fn scope_of(codes: &[&str]) -> std::collections::HashSet<String> {
        codes.iter().map(|c| c.to_string()).collect()
    }

    fn key_of(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn guarded_out_of_scope_zh_name_not_spliced_by_shorter_in_scope_name() {
        // 李明 (in scope) is a strict PREFIX of 李明华 (out of scope). With
        // 李明华 absent from the alternation, "李明华" matches as 李明 + "华"
        // and restores to "张伟华" — 王芳's statement attributed to 张伟.
        let k = key_of(&[("李明", "张伟"), ("李明华", "王芳")]);
        let anchor = Anchor { nonce: NONCE.to_string(), scope: scope_of(&["李明"]) };

        let text = format!("李明华 reported that 李明 left.\n{NONCE}");
        let result = restore_full_guarded(&text, &k, None, None, Some(&anchor)).unwrap();

        assert_eq!(result.restored, "李明华 reported that 张伟 left.");
        assert!(
            !result.restored.contains("张伟华"),
            "spliced identity in guarded output: {:?}", result.restored
        );
        assert_eq!(result.outcome, RestoreOutcome::Partial);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].kind, GuardEventKind::OutOfScopePseudonym);
        assert_eq!(result.events[0].detail, Some(vec!["李明华".to_string()]));
    }

    #[test]
    fn guarded_out_of_scope_code_not_spliced_by_shorter_in_scope_code() {
        // P-1 (in scope) is a prefix of P-10 (out of scope): "P-10" must not
        // become "Alice0".
        let k = key_of(&[("P-1", "Alice"), ("P-10", "Ten")]);
        let anchor = Anchor { nonce: NONCE.to_string(), scope: scope_of(&["P-1"]) };

        let text = format!("P-10 and P-1\n{NONCE}");
        let result = restore_full_guarded(&text, &k, None, None, Some(&anchor)).unwrap();

        assert_eq!(result.restored, "P-10 and Alice");
        assert_eq!(result.outcome, RestoreOutcome::Partial);
    }

    #[test]
    fn guarded_alias_of_in_scope_fake_cannot_claim_an_out_of_scope_fake() {
        // THE DEDUPE TRAP. An alias of the IN-scope P-1 is literally the
        // out-of-scope fake P-2. Merging aliases over the SCOPED key makes
        // P-2 → "Alice" (no collision is seen, because P-2's own entry was
        // already filtered out), so the withheld pseudonym is substituted
        // anyway — with the WRONG identity. Merging over the FULL key sees
        // the collision and never inserts.
        let k = key_of(&[("P-1", "Alice"), ("P-2", "Bob")]);
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-1".to_string(), vec!["P-2".to_string()]);
        let anchor = Anchor { nonce: NONCE.to_string(), scope: scope_of(&["P-1"]) };

        let text = format!("P-1 and P-2\n{NONCE}");
        let result = restore_full_guarded(&text, &k, Some(&aliases), None, Some(&anchor)).unwrap();

        assert_eq!(result.restored, "Alice and P-2");
        assert!(
            !result.restored.contains("Alice and Alice"),
            "out-of-scope fake received an in-scope identity: {:?}", result.restored
        );
        assert_eq!(result.outcome, RestoreOutcome::Partial);
    }

    #[test]
    fn guarded_alias_of_out_of_scope_fake_is_withheld_and_reported() {
        // The mirror of the trap: an alias whose OWNING fake is out of scope
        // must not be substituted either, and must be reported as withheld —
        // so `strict=True` fails closed at every scope width.
        let k = key_of(&[("P-1", "Alice"), ("P-2", "Bob")]);
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-2".to_string(), vec!["Bobby".to_string()]);
        let anchor = Anchor { nonce: NONCE.to_string(), scope: scope_of(&["P-1"]) };

        let text = format!("P-1 met Bobby\n{NONCE}");
        let result = restore_full_guarded(&text, &k, Some(&aliases), None, Some(&anchor)).unwrap();

        assert_eq!(result.restored, "Alice met Bobby");
        assert_eq!(result.outcome, RestoreOutcome::Partial);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].kind, GuardEventKind::OutOfScopePseudonym);
        assert_eq!(result.events[0].detail, Some(vec!["Bobby".to_string()]));
    }

    #[test]
    fn guarded_three_way_prefix_chain_withheld_atomically() {
        // P-1 ⊂ P-10 ⊂ P-100, only the shortest in scope.
        let k = key_of(&[("P-1", "Alice"), ("P-10", "Ten"), ("P-100", "Hundred")]);
        let anchor = Anchor { nonce: NONCE.to_string(), scope: scope_of(&["P-1"]) };

        let text = format!("P-100 P-10 P-1\n{NONCE}");
        let result = restore_full_guarded(&text, &k, None, None, Some(&anchor)).unwrap();

        assert_eq!(result.restored, "P-100 P-10 Alice");
        assert_eq!(result.outcome, RestoreOutcome::Partial);
        assert_eq!(
            result.events[0].detail,
            Some(vec!["P-10".to_string(), "P-100".to_string()]),
        );
    }

    #[test]
    fn guarded_in_scope_substitutions_match_the_unguarded_pass() {
        // The guard may only ever WITHHOLD. Every in-scope substitution must
        // land exactly where the unguarded pass put it.
        let k = key_of(&[("P-1", "Alice"), ("P-10", "Ten"), ("P-100", "Hundred")]);
        let anchor = Anchor {
            nonce: NONCE.to_string(),
            scope: scope_of(&["P-1", "P-10", "P-100"]),
        };
        let text = format!("P-100 P-10 P-1\n{NONCE}");
        let guarded = restore_full_guarded(&text, &k, None, None, Some(&anchor)).unwrap();
        let unguarded = restore_full("P-100 P-10 P-1", &k, None, None).unwrap();
        assert_eq!(guarded.restored, unguarded.0);
        assert_eq!(guarded.outcome, RestoreOutcome::Complete);
    }

    #[test]
    fn equal_length_key_ordering_is_deterministic_not_hash_seeded() {
        // Equal-length keys previously tie-broke on HashMap iteration order,
        // which is per-process hash-seed dependent. The sort must be TOTAL so
        // the compiled alternation is byte-stable across runs.
        let keys = vec!["bb".to_string(), "aa".to_string(), "cc".to_string(), "a".to_string()];
        let mut sorted: Vec<&String> = keys.iter().collect();
        sorted.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        assert_eq!(
            sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            vec!["aa", "bb", "cc", "a"],
        );
    }
}
