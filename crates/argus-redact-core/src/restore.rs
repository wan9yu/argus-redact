use std::collections::{BTreeSet, HashMap};
use fancy_regex::Regex;

use crate::display_marker::strip_display_markers_scoped;
use crate::grammar::{is_self_ref, restore_grammar_en};
use crate::hints::{py_rstrip, py_strip};
use crate::reserved_range::{
    byte_to_char_offset, escaped_alternation, escaped_alternation_digit_bounded, scan_for_pollution,
};

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

/// One guard check's outcome. `count` is how many instances the check found;
/// `detail`, when present, is the SORTED list of the specific tokens involved
/// (e.g. out-of-scope pseudonym codes) — a bare data carrier, not a
/// human-readable message. Callers own rendering (Python builds its
/// `"withheld: {join}"` string, wasm exposes `tokens[]`) so no reason-code
/// prose lives in this crate.
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

/// True only if the model echoed `nonce` as instructed — as a whole token, on
/// its own line or as the trailing token (the shape `prompt_anchor` asks for
/// and `strip_nonce` removes).
///
/// `nonce.chars().count()` (NOT `.len()`) mirrors Python `len()`, which counts
/// codepoints rather than bytes, so the floor check lands on the same value
/// for any non-ASCII nonce too.
fn nonce_echoed(text: &str, nonce: &str) -> bool {
    if nonce.chars().count() < MIN_NONCE_LEN {
        return false;
    }
    if py_rstrip(text).ends_with(nonce) {
        return true; // documented trailing echo
    }
    text.split('\n').any(|line| py_strip(line) == nonce) // own-line echo
}

/// Remove the echoed verification token from the model's reply.
///
/// The documented shape (token last) is handled in one pass; the fallbacks
/// cover a model that puts it on its own line mid-reply or echoes it inline.
fn strip_nonce(text: &str, nonce: &str) -> String {
    if nonce.chars().count() < MIN_NONCE_LEN {
        // Defense in depth: a degenerate nonce has no valid echo to strip, and
        // stripping it WOULD destroy or corrupt the text. The only caller
        // gates on `nonce_echoed` first, so this never fires today — but a
        // function whose failure mode is "silently destroy the caller's
        // plaintext" must refuse degenerate input regardless of caller.
        return text.to_string();
    }
    let trimmed = py_rstrip(text);
    if trimmed.ends_with(nonce) {
        // the documented case — no full-text rebuild needed
        return py_rstrip(&trimmed[..trimmed.len() - nonce.len()]).to_string();
    }
    let kept: Vec<&str> = text.split('\n').filter(|line| py_strip(line) != nonce).collect();
    let mut out = kept.join("\n");
    if out.contains(nonce) {
        // defensive: echoed inline rather than on its own line
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

/// Restore redacted text by replacing pseudonyms with originals.
/// Keys sorted by length descending to prevent partial matches.
/// Single-pass replacement prevents re-scanning of replaced content.
pub fn restore(text: &str, key: &HashMap<String, String>) -> Result<String, RestoreError> {
    restore_tracking_self_ref(text, key).map(|(result, _spans)| result)
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
fn restore_tracking_self_ref(
    text: &str,
    key: &HashMap<String, String>,
) -> Result<(String, Vec<(usize, usize)>), RestoreError> {
    if key.is_empty() || text.is_empty() {
        return Ok((text.to_string(), Vec::new()));
    }

    // An empty-string surrogate can never come from argus — the producer
    // (`replace.rs`) refuses to register one, because it would match between
    // every character below and explode the original throughout the text.
    // A key that has one is corrupted or hand-built: fail closed rather than
    // execute the explosion.
    reject_empty_key_entry(key)?;

    // Sort keys by length descending (longest first)
    let mut keys: Vec<&String> = key.keys().collect();
    keys.sort_by(|a, b| b.len().cmp(&a.len()));

    // Build alternation pattern from escaped keys (digit-bounded so a numeric
    // key cannot match inside a longer number).
    let pattern_str = escaped_alternation_digit_bounded(&keys);

    let re = Regex::new(&pattern_str)
        .map_err(|e| RestoreError(format!("Invalid restore pattern: {e}")))?;

    Ok(substitute_with(&re, key, text))
}

/// Single-pass, longest-first substitution of every match of `re` in `text`
/// using `flat` as the lookup, tracking the byte-offset span (in the OUTPUT
/// string) of every self-referential pronoun value it splices in — the exact
/// substitution body `restore_tracking_self_ref` used to run inline.
///
/// Shared by `restore_tracking_self_ref` (which compiles `re` fresh from
/// `key` on every call) and `RestoreSession::restore_cell` (which reuses one
/// `re` precompiled once in `RestoreSession::new` across many calls over the
/// same `flat` map) — factored out so the two call sites can never drift.
fn substitute_with(re: &Regex, flat: &HashMap<String, String>, text: &str) -> (String, Vec<(usize, usize)>) {
    let mut result = String::with_capacity(text.len());
    let mut last_end = 0;
    let mut self_ref_spans: Vec<(usize, usize)> = Vec::new();

    let mut search_start = 0;
    while search_start <= text.len() {
        let m = match re.find_from_pos(text, search_start) {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(_) => break,
        };

        result.push_str(&text[last_end..m.start()]);
        if let Some(replacement) = flat.get(m.as_str()) {
            let span_start = result.len();
            result.push_str(replacement);
            if is_self_ref(replacement) {
                self_ref_spans.push((span_start, result.len()));
            }
        } else {
            result.push_str(m.as_str());
        }
        last_end = m.end();
        search_start = if m.end() > m.start() { m.end() } else { m.start() + 1 };
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
/// Returns `(flat_map, alias_collisions)`. With `aliases = None`, `flat_map`
/// is a plain clone of `key` and `alias_collisions` is empty.
fn merge_aliases(
    key: &HashMap<String, String>,
    aliases: Option<&HashMap<String, Vec<String>>>,
) -> (HashMap<String, String>, Vec<String>) {
    let mut alias_collisions: Vec<String> = Vec::new();
    let flat: HashMap<String, String> = if let Some(alias_map) = aliases {
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
                        }
                        _ => {}
                    }
                }
            }
        }
        m
    } else {
        key.clone()
    };
    (flat, alias_collisions)
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
    // Step 1: strip explicit display marker — scoped to this key's fakes
    // only. A global strip would remove the marker character everywhere in
    // `text`, destroying unrelated content that happens to contain it (e.g.
    // markdown `**bold**`, or a masked value's internal `*`). Scoping to the
    // same longest-first fake alternation `mark_for_display` uses makes the
    // strip land exactly where the mark was added, nowhere else.
    let text_owned: String;
    let text = if let Some(dm) = display_marker {
        let key_fakes: Vec<String> = key.keys().cloned().collect();
        text_owned = strip_display_markers_scoped(text, &key_fakes, Some(dm));
        text_owned.as_str()
    } else {
        text
    };

    // Step 2: empty key fast-path.
    if key.is_empty() {
        return Ok((text.to_string(), Vec::new()));
    }

    // `restore_tracking_self_ref` (called below at Step 4) rejects an
    // empty-string key entry too; this is defense in depth so this function
    // fails closed on its own before doing any alias-merge work, independent
    // of whether the lower-level fn is reached unchanged.
    reject_empty_key_entry(key)?;

    // Step 3: alias merge — build flat lookup.
    let (flat, alias_collisions) = merge_aliases(key, aliases);

    // Step 4: core substitution over the flat lookup.
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
    let (result, self_ref_spans) = restore_tracking_self_ref(text, &flat)?;

    // Step 5: grammar restore, scoped to the neighbourhood of each restored
    // self-ref pronoun. `apply_grammar_scoped` is a no-op (returns `result`
    // unchanged) when `self_ref_spans` is empty, i.e. when no key value was a
    // self-ref pronoun OR none of them actually got substituted into `text`.
    let result = apply_grammar_scoped(&result, &self_ref_spans);

    Ok((result, alias_collisions))
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

    // (S) Scope: restrict substitution to pseudonyms this reply is scoped to.
    let scoped: HashMap<String, String> = key
        .iter()
        .filter(|(k, _)| anchor.scope.contains(*k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let mut events: Vec<GuardEvent> = Vec::new();

    // Advisory: the key was non-empty and anchor.scope is non-empty, but scope
    // excluded EVERY entry — the restore below is a silent no-op that would
    // otherwise be reported COMPLETE with no hint that nothing was
    // substituted. Distinct from the corruption empty-string-key case (that
    // fails closed in `restore_body`); this is a legitimate, non-overlapping
    // scope and key, so it only advises, never blocks.
    if !key.is_empty() && scoped.is_empty() && !anchor.scope.is_empty() {
        events.push(GuardEvent { kind: GuardEventKind::EmptyKeyWithScope, count: key.len(), detail: None });
    }

    // Detect out-of-scope pseudonyms that appear in text — see
    // `tokens_present`. Cosmetic only: it sizes the event's `count`/`detail`,
    // never which pseudonyms get withheld (that is `scoped` above).
    let out_of_scope_codes: Vec<String> =
        key.keys().filter(|k| !anchor.scope.contains(*k)).cloned().collect();
    let out_of_scope = tokens_present(&out_of_scope_codes, &text);
    if !out_of_scope.is_empty() {
        events.push(GuardEvent {
            kind: GuardEventKind::OutOfScopePseudonym,
            count: out_of_scope.len(),
            detail: Some(out_of_scope.clone()),
        });
    }

    // Restore only in-scope pseudonyms.
    let (result, alias_collisions) = restore_body(&text, &scoped, aliases, display_marker)?;
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

    // Sort a COPY by length descending — mirrors Python's
    // `sorted(pseudonyms, key=len, reverse=True)`, which never mutates its
    // input either.
    let mut sorted: Vec<String> = pseudonyms.to_vec();
    sorted.sort_by(|a, b| b.len().cmp(&a.len()));
    let alternation = escaped_alternation(&sorted);
    let pattern_str = format!(r"(?<![A-Za-z0-9_-])(?:{alternation})(?![A-Za-z0-9_-])");

    let re = match Regex::new(&pattern_str) {
        Ok(re) => re,
        // An escaped alternation of literal strings should always compile;
        // if it somehow doesn't, Python's `re.compile` on the equivalent
        // pattern would not raise here either, so fail open to "no hits"
        // rather than panic.
        Err(_) => return Vec::new(),
    };

    let mut hits: BTreeSet<String> = BTreeSet::new();
    let mut search_start = 0;
    while search_start <= text.len() {
        match re.find_from_pos(text, search_start) {
            Ok(Some(m)) => {
                hits.insert(m.as_str().to_string());
                search_start = if m.end() > m.start() { m.end() } else { m.start() + 1 };
            }
            Ok(None) => break,
            // A match-time error (e.g. a backtrack/overflow limit) stops the
            // scan rather than panicking — mirrors `check_restore_safety`'s
            // `_ => break` on this same `find_from_pos` idiom in this file.
            Err(_) => break,
        }
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
    re: Option<Regex>,
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
        let (flat, alias_collisions) = merge_aliases(key, aliases);
        reject_empty_key_entry(&flat)?;

        let re = if flat.is_empty() {
            None
        } else {
            let mut keys: Vec<&String> = flat.keys().collect();
            keys.sort_by(|a, b| b.len().cmp(&a.len()));
            let pattern_str = escaped_alternation_digit_bounded(&keys);
            Some(
                Regex::new(&pattern_str)
                    .map_err(|e| RestoreError(format!("Invalid restore pattern: {e}")))?,
            )
        };

        Ok(RestoreSession { flat, re, alias_collisions })
    }

    /// Restore one cell of text against the precomputed key. Unguarded and
    /// display-marker-free (bulk callers pass none — equivalence is checked
    /// against `restore_full(..., None, None)`), so `events` is always empty
    /// and `outcome` is always `Complete`.
    pub fn restore_cell(&self, text: &str) -> Result<RestoreResult, RestoreError> {
        let Some(re) = &self.re else {
            return Ok(RestoreResult {
                restored: text.to_string(),
                alias_collisions: self.alias_collisions.clone(),
                events: vec![],
                outcome: RestoreOutcome::Complete,
            });
        };
        let (result, spans) = substitute_with(re, &self.flat, text);
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
        self.re = None;
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
                let mut search_start = 0;
                let mut warned = false;
                while search_start <= llm_output.len() && !warned {
                    match code_re.find_from_pos(llm_output, search_start) {
                        Ok(Some(m)) => {
                            // ±DANGER_WINDOW in CHAR space (matches Python
                            // `llm_output[max(0,start-100):min(len,end+100)]`).
                            let char_start = byte_to_char_offset(llm_output, m.start());
                            let char_end = byte_to_char_offset(llm_output, m.end());
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
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(needle) {
        count += 1;
        start += pos + needle.len();
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
