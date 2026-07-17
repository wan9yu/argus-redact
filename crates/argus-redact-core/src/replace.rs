//! `replace()` single-pass orchestrator — ported from `pure/replacer.py:457–644`.
//!
//! Ties together masks / seed derivation / fakers / `PseudonymGenerator` /
//! collision resolution into one pass over the detected entities. This is the
//! engine the whole redact() pipeline routes through; its output MUST reproduce
//! the frozen v0.7.2 Python output byte-for-byte (the master golden is the gate).
//!
//! ## Why a [`PseudoFactory`] trait instead of a concrete generator
//!
//! Pseudonym codes (`P-NNNNN`) are derived from Python's `random.Random(seed)`
//! Mersenne-Twister stream — the existing core [`crate::PseudonymGenerator`] is
//! generic over a [`crate::RandomSource`] precisely so the binding can supply a
//! Python-backed source that reproduces that stream bit-for-bit. The core can't
//! depend on PyO3, so `replace()` is generic over a factory that mints a fresh
//! `RandomSource` for a given seed. The binding implements it over
//! `random.Random` (seeded) / `secrets` (unseeded), exactly as the standalone
//! `PyPseudonymGenerator` does. This is a per-generator construction callback,
//! NOT a mid-loop per-entity callback — it preserves seed compatibility without
//! threading Python through the strategy dispatch.

use std::collections::{HashMap, HashSet};

use crate::fakers::{resolve_faker, try_generate_unique_fake};
use crate::masks::{mask_landline, mask_name, mask_value, resolve_collision};
use crate::pseudonym::{PseudonymGenerator, RandomSource};
use crate::seed::{offset_seed, pseudonym_seed_int, resolve_salt, type_seed_offset, Salt};
use crate::types::PatternMatch;

const DEFAULT_REDACT_LABEL: &str = "[REDACTED]";
const PSEUDONYM_CODE_RANGE: (u32, u32) = (1, 99999);

/// Mints a fresh [`RandomSource`] for a given optional u64 seed.
///
/// The binding implements this over Python `random.Random(seed)` (seeded) or
/// `secrets` (unseeded), matching `PyPseudonymGenerator`'s construction so the
/// `P-NNNNN` codes reproduce the frozen Python stream.
pub trait PseudoFactory {
    /// The concrete [`RandomSource`] this factory produces.
    type Source: RandomSource;
    /// Create a source seeded by `seed` (`None` → unseeded / secrets path).
    fn make(&self, seed: Option<u64>) -> Self::Source;
}

/// Invoke a custom (Python) `faker_reserved` for one entity, given the HMAC
/// `master_key` for this attempt. The re-roll loop lives in core
/// (`generate_unique_fake_with`); this only produces one `(fake, aliases)`.
pub trait FakerFactory {
    fn call_faker(&self, type_: &str, value: &str, master_key: &[u8])
        -> Result<(String, Vec<String>), String>;
}

/// How the realistic strategy resolves a faker for a type.
///
/// Unifies the old `faker_name: Option<String>` + `custom_faker: bool` pair into
/// a single closed set, so the realistic branch is a `match` instead of an
/// if/else chain. The Python binding folds the existing `faker_name` /
/// `custom_faker` dict fields into this enum (`faker_name` wins, then
/// `custom_faker`, then `None`) — the Python dict shape is unchanged.
#[derive(Debug, Clone)]
pub enum FakerResolution {
    /// Built-in faker function name (resolved via [`resolve_faker`]).
    Builtin(String),
    /// Custom Python callable, invoked through the [`FakerFactory`] callback.
    Custom,
    /// No faker → pseudonym fallback (organization → org_gen, else per-type gen).
    None,
}

impl Default for FakerResolution {
    fn default() -> Self {
        FakerResolution::None
    }
}

/// Per-type resolved replacement info, built in Python from the registry +
/// user config and passed into `replace()`. Mirrors the data
/// `pure/replacer.py` reaches for via `_resolve_default_strategy`,
/// `_find_faker_reserved`, `DEFAULT_PREFIXES`, and the per-type config dict.
#[derive(Debug, Clone, Default)]
pub struct TypeInfo {
    /// Effective strategy (user config strategy, else the registry default).
    pub strategy: String,
    /// The registry default strategy (ignoring user config). A `keep` entity
    /// that fails the whitelist downgrades to THIS — matching the Python
    /// original's `_resolve_default_strategy(type)` call in the keep branch.
    pub default_strategy: String,
    /// Pseudonym/remove prefix (`DEFAULT_PREFIXES[type]` or config `prefix`,
    /// falling back to `type.upper()[:4]` on the Python side before it gets here).
    pub prefix: String,
    /// Whether the user explicitly set `prefix` in config (drives the per-call
    /// person/org generator rebuild in the Python original).
    pub prefix_overridden: bool,
    /// How the realistic strategy resolves a faker for this type: a built-in
    /// faker name (→ [`resolve_faker`]), a custom Python callable (→ the
    /// supplied [`FakerFactory`]), or none (→ pseudonym fallback). Defaults to
    /// [`FakerResolution::None`].
    pub faker_resolution: FakerResolution,
    /// `config[type]["replacement"]` for the `remove` strategy, if set.
    pub replacement: Option<String>,
    /// `config[type]["label"]` for the `category` strategy, if set.
    pub label: Option<String>,
    /// Default `category` label (`DEFAULT_CATEGORY_LABEL[type]` or `[type]`),
    /// resolved on the Python side.
    pub default_category_label: String,
    /// `config[type]["visible_prefix"]` for `mask` (0 = use per-type default).
    pub visible_prefix: usize,
    /// `config[type]["visible_suffix"]` for `mask` (0 = use per-type default).
    pub visible_suffix: usize,
}

/// Result of a `replace()` call.
pub struct ReplaceResult {
    /// The redacted text.
    pub redacted: String,
    /// The replacement → original key map.
    pub key: HashMap<String, String>,
    /// `{fake: aliases}` for realistic fakers that emitted aliases.
    pub aliases: HashMap<String, Vec<String>>,
    /// `true` if a `keep`-strategy entity was downgraded (the Python original
    /// emits a `SecurityWarning` here; the binding/wrapper surfaces it).
    pub keep_downgraded: bool,
    /// Entity types for which a mask-family strategy (`mask` / `name_mask` /
    /// `landline_mask` / `category`) produced a REAL collision — two different
    /// originals wanting the same visible label — that `resolve_collision`
    /// disambiguated with a trailing circled-digit (or numeric) suffix. One
    /// entry per collided entity (not deduped), so `.len()` is the count the
    /// Python wrapper warns/reports with.
    ///
    /// The collided entry STAYS in `key` (a direct in-process restore still
    /// works) — this field only SIGNALS that the disambiguator is fragile: an
    /// LLM that normalizes away `①` collapses the two key entries and a later
    /// restore silently returns the wrong original for one of them. See
    /// `resolve_collision` in `masks.rs`.
    pub mask_collisions: Vec<String>,
}

/// Inputs to [`replace`], grouped to keep the signature readable.
pub struct ReplaceArgs<'a> {
    /// The source text.
    pub text: &'a str,
    /// Detected entities (in detection order).
    pub entities: &'a [PatternMatch],
    /// Effective salt (drives pseudonym seed + realistic HMAC).
    pub salt: Option<&'a Salt>,
    /// Existing key to merge into (reuse + collision avoidance).
    pub key: Option<&'a HashMap<String, String>>,
    /// Per-type resolved info, keyed by entity type.
    pub type_info: &'a HashMap<String, TypeInfo>,
    /// Person pseudonym prefix (config override of `DEFAULT_PREFIXES["person"]`).
    pub person_prefix: &'a str,
    /// Organization pseudonym prefix.
    pub org_prefix: &'a str,
    /// Unified-prefix mode: all reversible types collapse to one prefix.
    pub unified_prefix: Option<&'a str>,
    /// Keep-strategy whitelist (`SELF_REF_PRONOUNS` ∪ zh pronouns ∪ zh kinship),
    /// passed from Python (single SSOT — no parallel list to drift).
    pub keep_whitelist: &'a HashSet<String>,
}

/// Replace detected entities in `text`, producing `(redacted, key, aliases)`.
///
/// Faithful port of `replace()` (`pure/replacer.py:483–644`). `factory` mints
/// the Python-backed RNG for pseudonym generators (see [`PseudoFactory`]).
///
/// Thin wrapper over [`ReplaceSession`]: build a session over the initial key,
/// process the single cell, return its accumulated result. The per-entity
/// strategy dispatch lives ONLY in [`ReplaceSession::process`] — this one-shot
/// entry and the multi-cell structured path share it (no duplicated logic).
///
/// The `realistic` strategy dispatches on the type's [`FakerResolution`]:
/// [`FakerResolution::Builtin`] resolves a built-in faker via [`resolve_faker`];
/// [`FakerResolution::Custom`] (a custom Python `faker_reserved` callable) routes
/// through `faker_factory` (a [`FakerFactory`] callback) using the same core
/// re-roll loop as the built-in path; [`FakerResolution::None`] falls back to a
/// pseudonym code (organization → org_gen, else the per-type generator).
pub fn replace<F: PseudoFactory>(
    args: ReplaceArgs<'_>,
    factory: &F,
    faker_factory: Option<&dyn FakerFactory>,
) -> Result<ReplaceResult, String> {
    let ReplaceArgs {
        text,
        entities,
        salt,
        key,
        type_info,
        person_prefix,
        org_prefix,
        unified_prefix,
        keep_whitelist,
    } = args;

    let mut session = ReplaceSession::new(
        factory,
        salt,
        person_prefix,
        org_prefix,
        unified_prefix,
        key,
    );
    let redacted = session.process(text, entities, type_info, keep_whitelist, faker_factory)?;
    Ok(ReplaceResult {
        redacted,
        key: session.result_key,
        aliases: session.aliases,
        keep_downgraded: session.keep_downgraded,
        mask_collisions: session.mask_collisions,
    })
}

/// Stateful multi-cell replace engine.
///
/// Owns the accumulation key, the reverse index, the reserved-label set, and the
/// pseudonym generators so a caller that redacts many small cells (structured
/// CSV / JSON) pays O(cell) per cell — instead of the stateless per-cell
/// `replace()` re-cloning + re-preloading the whole growing key on every cell
/// (the O(N²) blow-up). One-shot [`replace`] is just a session that processes a
/// single cell, so the two paths run the *same* per-entity logic in
/// [`process`](Self::process).
///
/// ## Byte-identity with the stateless per-cell path
///
/// A pseudonym generator that PERSISTS its RNG across cells is provably
/// identical to one re-seeded per cell and pre-loaded from the growing key:
/// every stream value drawn before the current index is already a used code
/// (it was either accepted, or it collided against an accepted code) — so a
/// re-seeded generator collides through exactly those and lands on the same
/// next value. This holds while each prefix namespace is owned by ONE generator
/// (non-unified mode). The session is only driven multi-cell by structured
/// redaction, which never sets `unified_prefix`; the one-shot [`replace`] (which
/// the general `redact()` uses, including unified mode) processes a single cell,
/// so its behaviour is unchanged.
///
/// The per-cell reserved set is reconstructed exactly: `used_labels` is kept as
/// {key replacements} ∪ {key originals} incrementally, and each cell's entity
/// texts are added for the pass then reverted (kept only if they became a key
/// original) — matching the stateless
/// `used_labels = key.keys() ∪ entities.texts ∪ key.values()`.
///
/// One theoretical exception: once a persisted generator exhausts its code
/// range and permanently widens it (the `hi * 10` expansion in
/// `pseudonym.rs`), its subsequent draws are governed by the wider range for
/// the rest of the session, whereas a stateless per-cell reference would only
/// see that widened range within the single cell that triggered it — the two
/// paths can then diverge. This is reachable only around 99,000 entities
/// sharing one prefix in a single document, a scale at which the stateless
/// reference itself is already degenerate.
pub struct ReplaceSession<'f, F: PseudoFactory> {
    factory: &'f F,
    salt: Option<Salt>,
    pseudo_seed_int: Option<u64>,
    /// Salt resolved for built-in realistic fakers. Cached lazily on first use;
    /// the salt is constant for the session so the resolve is shared across cells.
    resolved_salt: Option<Vec<u8>>,
    person_prefix: String,
    org_prefix: String,
    unified_prefix: Option<String>,
    result_key: HashMap<String, String>,
    /// original → replacement, for existing-mapping reuse across cells.
    reverse_index: HashMap<String, String>,
    /// {key replacements} ∪ {key originals}, maintained incrementally.
    used_labels: HashSet<String>,
    aliases: HashMap<String, Vec<String>>,
    keep_downgraded: bool,
    /// One entry (the entity type) per mask-family collision `resolve_collision`
    /// actually disambiguated this session. See [`ReplaceResult::mask_collisions`].
    mask_collisions: Vec<String>,
    /// Person / organization pseudonym generators — built lazily on first use and
    /// persisted (RNG continues) across cells. Lazy build means an all-mask
    /// workload never touches the key here, keeping per-cell cost flat.
    pseudo_gen: Option<PseudonymGenerator<F::Source>>,
    org_gen: Option<PseudonymGenerator<F::Source>>,
    /// Per-type pseudonym generators for the remove / realistic-fallback paths.
    type_gens: HashMap<String, PseudonymGenerator<F::Source>>,
}

impl<'f, F: PseudoFactory> ReplaceSession<'f, F> {
    /// Build a session over an optional initial key. The reverse index and the
    /// reserved-label set are derived from that key ONCE here, then maintained
    /// incrementally per cell.
    pub fn new(
        factory: &'f F,
        salt: Option<&Salt>,
        person_prefix: &str,
        org_prefix: &str,
        unified_prefix: Option<&str>,
        initial_key: Option<&HashMap<String, String>>,
    ) -> Self {
        let result_key: HashMap<String, String> = initial_key.cloned().unwrap_or_default();
        let mut used_labels: HashSet<String> = HashSet::with_capacity(result_key.len() * 2);
        let mut reverse_index: HashMap<String, String> =
            HashMap::with_capacity(result_key.len());
        for (replacement, original) in &result_key {
            used_labels.insert(replacement.clone());
            used_labels.insert(original.clone());
            reverse_index.insert(original.clone(), replacement.clone());
        }
        let pseudo_seed_int = pseudonym_seed_int(salt);
        Self {
            factory,
            salt: salt.cloned(),
            pseudo_seed_int,
            resolved_salt: None,
            person_prefix: person_prefix.to_string(),
            org_prefix: org_prefix.to_string(),
            unified_prefix: unified_prefix.map(str::to_string),
            result_key,
            reverse_index,
            used_labels,
            aliases: HashMap::new(),
            keep_downgraded: false,
            mask_collisions: Vec::new(),
            pseudo_gen: None,
            org_gen: None,
            type_gens: HashMap::new(),
        }
    }

    /// Whether a `keep`-strategy entity has been downgraded so far this session.
    pub fn keep_downgraded(&self) -> bool {
        self.keep_downgraded
    }

    /// Entity types for mask-family collisions disambiguated so far this session.
    /// See [`ReplaceResult::mask_collisions`].
    pub fn mask_collisions(&self) -> &[String] {
        &self.mask_collisions
    }

    /// Borrow the accumulated `{fake: aliases}` map.
    pub fn aliases(&self) -> &HashMap<String, Vec<String>> {
        &self.aliases
    }

    /// Borrow the accumulated replacement → original key.
    pub fn key(&self) -> &HashMap<String, String> {
        &self.result_key
    }

    /// Consume the session, returning the accumulated replacement → original key.
    pub fn into_key(self) -> HashMap<String, String> {
        self.result_key
    }

    /// `resolve_collision` for a mask-family label, recording the collision (by
    /// entity type) when a real disambiguation happened. The mask / name_mask /
    /// landline_mask / category arms all need this exact pair.
    fn resolve_collision_tracked(
        &mut self,
        label: &str,
        entity_type: &str,
    ) -> Result<String, String> {
        let resolved = resolve_collision(label, &self.used_labels)?;
        if resolved != label {
            self.mask_collisions.push(entity_type.to_string());
        }
        Ok(resolved)
    }

    /// Redact one cell over the persistent session state, returning its redacted
    /// text. The key, reverse index, reserved set, aliases, and `keep_downgraded`
    /// flag all accumulate on `self`.
    pub fn process(
        &mut self,
        text: &str,
        entities: &[PatternMatch],
        type_info: &HashMap<String, TypeInfo>,
        keep_whitelist: &HashSet<String>,
        faker_factory: Option<&dyn FakerFactory>,
    ) -> Result<String, String> {
        // No-entities early return (Python: `return text, key or {}, aliases`).
        if entities.is_empty() {
            return Ok(text.to_string());
        }

        // Reserve this cell's entity texts so a generated fake can never equal
        // another entity's real value (a cross-entity leak). This is transient:
        // the stateless path folds ONLY the current cell's entity texts into
        // used_labels, so we track the ones we newly added and revert them at the
        // end — except those that became a key original (which stay reserved via
        // the {key originals} invariant). Reverting keeps the per-cell reserved
        // set byte-identical to the stateless single-call set.
        let mut cell_added: Vec<String> = Vec::new();
        for e in entities {
            if self.used_labels.insert(e.text.clone()) {
                cell_added.push(e.text.clone());
            }
        }

        let mut entity_replacements: HashMap<String, String> = HashMap::new();

        for entity in entities {
            if entity_replacements.contains_key(&entity.text) {
                continue;
            }
            if let Some(existing) = self.reverse_index.get(&entity.text) {
                entity_replacements.insert(entity.text.clone(), existing.clone());
                continue;
            }

            let info = type_info.get(&entity.type_);
            // Strategy: config strategy, else the registry default (already folded
            // into TypeInfo.strategy on the Python side). Fallback "remove" matches
            // `_resolve_default_strategy`'s unknown-type fallback.
            let mut strategy = info
                .map(|i| i.strategy.clone())
                .unwrap_or_else(|| "remove".to_string());

            if strategy == "keep" {
                // `keep` survives only for self_reference pronouns / kinship in the
                // whitelist; anything else downgrades to the type default (guards
                // against Layer-3 misclassifying sensitive PII as self_reference).
                if entity.type_ == "self_reference" && keep_whitelist.contains(&entity.text) {
                    entity_replacements.insert(entity.text.clone(), entity.text.clone());
                    continue;
                }
                self.keep_downgraded = true;
                // The Python original calls `_resolve_default_strategy(type)` again
                // here — the registry default. We carry it explicitly in
                // `default_strategy` so a user config of `{strategy: "keep"}`
                // downgrades to the registry default (not back to "keep"). Fallback
                // "remove" matches the unknown-type case.
                strategy = info
                    .map(|i| i.default_strategy.clone())
                    .unwrap_or_else(|| "remove".to_string());
                // fall through to strategy dispatch
            }

            let replacement: String = if strategy == "pseudonym" {
                if entity.type_ == "organization" {
                    if info.map(|i| i.prefix_overridden).unwrap_or(false) {
                        // Python rebuilds the org generator with the CONFIG prefix
                        // (NOT unified_prefix) and the LIVE result_key — re-seeding
                        // redraws the first number, but the up-to-date key forces a
                        // fresh code on collision. (replacer.py:578–583)
                        let prefix = info.map(|i| i.prefix.as_str()).unwrap_or("O");
                        let live = if self.result_key.is_empty() {
                            None
                        } else {
                            Some(&self.result_key)
                        };
                        self.org_gen = Some(PseudonymGenerator::new(
                            prefix,
                            PSEUDONYM_CODE_RANGE,
                            self.factory.make(offset_seed(self.pseudo_seed_int, 1)),
                            live,
                        ));
                    }
                    let org_prefix = self
                        .unified_prefix
                        .as_deref()
                        .unwrap_or(self.org_prefix.as_str());
                    let pg = lazy_gen(
                        &mut self.org_gen,
                        org_prefix,
                        offset_seed(self.pseudo_seed_int, 1),
                        &self.result_key,
                        self.factory,
                    );
                    pg.get_reserved(&entity.text, &mut self.used_labels)
                } else {
                    if info.map(|i| i.prefix_overridden).unwrap_or(false) {
                        // Same rebuild semantics for the person generator
                        // (replacer.py:586–591): config prefix + live result_key.
                        let prefix = info.map(|i| i.prefix.as_str()).unwrap_or("P");
                        let live = if self.result_key.is_empty() {
                            None
                        } else {
                            Some(&self.result_key)
                        };
                        self.pseudo_gen = Some(PseudonymGenerator::new(
                            prefix,
                            PSEUDONYM_CODE_RANGE,
                            self.factory.make(self.pseudo_seed_int),
                            live,
                        ));
                    }
                    let person_prefix = self
                        .unified_prefix
                        .as_deref()
                        .unwrap_or(self.person_prefix.as_str());
                    let pg = lazy_gen(
                        &mut self.pseudo_gen,
                        person_prefix,
                        self.pseudo_seed_int,
                        &self.result_key,
                        self.factory,
                    );
                    pg.get_reserved(&entity.text, &mut self.used_labels)
                }
            } else if strategy == "realistic" {
                // Default to None when info is absent (no TypeInfo for this type).
                let resolution = info
                    .map(|i| &i.faker_resolution)
                    .unwrap_or(&FakerResolution::None);
                // Resolve a fake via the configured faker. `None` means either "no
                // faker configured" or "the faker exhausted its re-rolls" (it could
                // only ever produce the input itself or an already-used value) —
                // both fall back to the pseudonym path below. A genuine faker error
                // (custom Python callable raised, unknown built-in) still `?`-aborts.
                let produced: Option<(String, Vec<String>)> = match resolution {
                    FakerResolution::Builtin(name) => {
                        // Built-in faker resolvable in Rust.
                        let faker = resolve_faker(name).ok_or_else(|| {
                            format!(
                                "realistic strategy: unknown faker '{name}' for type '{}'",
                                entity.type_
                            )
                        })?;
                        if self.resolved_salt.is_none() {
                            self.resolved_salt = Some(resolve_salt(self.salt.as_ref())?);
                        }
                        let salt_bytes =
                            self.resolved_salt.as_deref().expect("resolved_salt set above");
                        try_generate_unique_fake(
                            faker,
                            &entity.text,
                            &entity.type_,
                            salt_bytes,
                            &self.used_labels,
                        )?
                    }
                    FakerResolution::Custom => {
                        // Custom Python `faker_reserved`. Route through the
                        // FakerFactory callback, reusing the shared re-roll loop so
                        // seeding/collision is identical to the built-in path.
                        let ff = faker_factory.ok_or_else(|| {
                            format!(
                                "realistic strategy: custom faker for '{}' but no FakerFactory provided",
                                entity.type_
                            )
                        })?;
                        if self.resolved_salt.is_none() {
                            self.resolved_salt = Some(resolve_salt(self.salt.as_ref())?);
                        }
                        let salt_bytes =
                            self.resolved_salt.as_deref().expect("resolved_salt set above");
                        crate::fakers::generate_unique_fake_with(
                            |mk| ff.call_faker(&entity.type_, &entity.text, mk),
                            &entity.text,
                            &entity.type_,
                            salt_bytes,
                            &self.used_labels,
                        )?
                    }
                    FakerResolution::None => None,
                };
                match produced {
                    Some((fake, alias_list)) => {
                        if !alias_list.is_empty() {
                            self.aliases.insert(fake.clone(), alias_list);
                        }
                        fake
                    }
                    None => {
                        // No faker, or the faker could not produce a unique
                        // non-identity fake → fail closed to a pseudonym
                        // (organization → org_gen, else the per-type generator).
                        if entity.type_ == "organization" {
                            let org_prefix = self
                                .unified_prefix
                                .as_deref()
                                .unwrap_or(self.org_prefix.as_str());
                            let pg = lazy_gen(
                                &mut self.org_gen,
                                org_prefix,
                                offset_seed(self.pseudo_seed_int, 1),
                                &self.result_key,
                                self.factory,
                            );
                            pg.get_reserved(&entity.text, &mut self.used_labels)
                        } else {
                            let pg = get_type_gen(
                                &mut self.type_gens,
                                &entity.type_,
                                info,
                                self.unified_prefix.as_deref(),
                                self.pseudo_seed_int,
                                &self.result_key,
                                self.factory,
                            );
                            pg.get_reserved(&entity.text, &mut self.used_labels)
                        }
                    }
                }
            } else if strategy == "mask" {
                let (vp, vs) = info.map(|i| (i.visible_prefix, i.visible_suffix)).unwrap_or((0, 0));
                let masked = mask_value(&entity.text, &entity.type_, vp, vs);
                self.resolve_collision_tracked(&masked, &entity.type_)?
            } else if strategy == "name_mask" {
                let masked = mask_name(&entity.text);
                self.resolve_collision_tracked(&masked, &entity.type_)?
            } else if strategy == "landline_mask" {
                let masked = mask_landline(&entity.text);
                self.resolve_collision_tracked(&masked, &entity.type_)?
            } else if strategy == "remove" {
                if let Some(repl) = info.and_then(|i| i.replacement.as_deref()) {
                    resolve_collision(repl, &self.used_labels)?
                } else {
                    let pg = get_type_gen(
                        &mut self.type_gens,
                        &entity.type_,
                        info,
                        self.unified_prefix.as_deref(),
                        self.pseudo_seed_int,
                        &self.result_key,
                        self.factory,
                    );
                    pg.get_reserved(&entity.text, &mut self.used_labels)
                }
            } else if strategy == "category" {
                let label = info
                    .and_then(|i| i.label.clone())
                    .or_else(|| info.map(|i| i.default_category_label.clone()))
                    .unwrap_or_else(|| format!("[{}]", entity.type_));
                self.resolve_collision_tracked(&label, &entity.type_)?
            } else {
                resolve_collision(DEFAULT_REDACT_LABEL, &self.used_labels)?
            };

            entity_replacements.insert(entity.text.clone(), replacement.clone());
            self.reverse_index
                .insert(entity.text.clone(), replacement.clone());
            if !replacement.is_empty() {
                // An empty replacement (remove strategy, `replacement: ""`) means
                // "delete" — the value is already gone from `entity_replacements` /
                // the redacted output below. Registering `"" -> original` in
                // `result_key` would create a surrogate that matches between every
                // character of the text on restore, exploding/duplicating the
                // original throughout it. So an empty resolved label gets NO
                // restorable key entry (and isn't reserved in `used_labels` either
                // — collision resolution is meaningless for "nothing").
                self.used_labels.insert(replacement.clone());
                self.result_key.insert(replacement, entity.text.clone());
            }
        }

        // Revert the transient per-cell entity-text reservations that did NOT
        // become a key original (e.g. a whitelisted keep entity). Replaced
        // originals are now in reverse_index and stay reserved (the {key
        // originals} invariant), so we keep them.
        for t in cell_added {
            if !self.reverse_index.contains_key(&t) {
                self.used_labels.remove(&t);
            }
        }

        // Replace right-to-left, dedup by (start, end). Char-based slicing to match
        // Python string indexing (code points, not bytes).
        let chars: Vec<char> = text.chars().collect();
        let mut sorted: Vec<&PatternMatch> = entities.iter().collect();
        sorted.sort_by(|a, b| b.start.cmp(&a.start));

        let mut result_chars = chars;
        let mut seen_positions: HashSet<(usize, usize)> = HashSet::new();
        for entity in sorted {
            let pos = (entity.start, entity.end);
            if seen_positions.contains(&pos) {
                continue;
            }
            seen_positions.insert(pos);
            let replacement = entity_replacements
                .get(&entity.text)
                .expect("entity.text must have a replacement");
            let repl_chars: Vec<char> = replacement.chars().collect();
            // result = result[:start] + replacement + result[end:]
            //
            // Python slicing silently clamps out-of-range indices: `s[:start]` with
            // `start > len(s)` yields the whole string, `s[end:]` with `end > len(s)`
            // yields "". The Presidio bridge feeds stale offsets into a string that
            // the prior (right-to-left) replacements already shortened, relying on
            // exactly this leniency — so we clamp to the current length to stay
            // byte-identical to `_replace_python` (a hard slice would panic).
            let cur_len = result_chars.len();
            let lo = entity.start.min(cur_len);
            let hi = entity.end.min(cur_len);
            let mut new_chars =
                Vec::with_capacity(lo + repl_chars.len() + cur_len.saturating_sub(hi));
            new_chars.extend_from_slice(&result_chars[..lo]);
            new_chars.extend_from_slice(&repl_chars);
            if hi < cur_len {
                new_chars.extend_from_slice(&result_chars[hi..]);
            }
            result_chars = new_chars;
        }

        Ok(result_chars.into_iter().collect())
    }
}

/// Lazily build (or fetch) a person/organization pseudonym generator, preloading
/// codes of its prefix from the live key on first construction and persisting its
/// RNG thereafter. The caller passes `&mut self.used_labels` separately to
/// `get_reserved` (disjoint field borrow).
fn lazy_gen<'a, F: PseudoFactory>(
    slot: &'a mut Option<PseudonymGenerator<F::Source>>,
    prefix: &str,
    seed: Option<u64>,
    result_key: &HashMap<String, String>,
    factory: &F,
) -> &'a mut PseudonymGenerator<F::Source> {
    slot.get_or_insert_with(|| {
        let existing = if result_key.is_empty() { None } else { Some(result_key) };
        PseudonymGenerator::new(prefix, PSEUDONYM_CODE_RANGE, factory.make(seed), existing)
    })
}

/// Lazily build (or fetch) the per-type pseudonym generator for the remove /
/// realistic-fallback strategies. Mirrors `_get_type_gen` (replacer.py:525–533).
/// Preloads from the live `result_key` on first construction and persists across
/// cells (the matching-prefix subset it preloads is exactly the codes it minted,
/// so a persisted generator stays byte-identical to a per-cell rebuild).
#[allow(clippy::too_many_arguments)]
fn get_type_gen<'a, F: PseudoFactory>(
    type_gens: &'a mut HashMap<String, PseudonymGenerator<F::Source>>,
    entity_type: &str,
    info: Option<&TypeInfo>,
    unified_prefix: Option<&str>,
    pseudo_seed_int: Option<u64>,
    result_key: &HashMap<String, String>,
    factory: &F,
) -> &'a mut PseudonymGenerator<F::Source> {
    type_gens.entry(entity_type.to_string()).or_insert_with(|| {
        // Prefix: unified_prefix, else DEFAULT_PREFIXES[type] (resolved on the
        // Python side into TypeInfo.prefix, with the type.upper()[:4] fallback).
        let prefix = unified_prefix.unwrap_or_else(|| info.map(|i| i.prefix.as_str()).unwrap_or(""));
        let seed = offset_seed(pseudo_seed_int, type_seed_offset(entity_type) as u64);
        let existing = if result_key.is_empty() { None } else { Some(result_key) };
        PseudonymGenerator::new(prefix, PSEUDONYM_CODE_RANGE, factory.make(seed), existing)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A deterministic RandomSource that returns a fixed sequence (cycling).
    struct SeqRng {
        values: Vec<u32>,
        idx: usize,
    }
    impl RandomSource for SeqRng {
        fn randint(&mut self, _lo: u32, _hi: u32) -> u32 {
            let v = self.values[self.idx % self.values.len()];
            self.idx += 1;
            v
        }
        fn randbelow(&mut self, _range: u32) -> u32 {
            let v = self.values[self.idx % self.values.len()];
            self.idx += 1;
            v
        }
        fn use_secrets(&self) -> bool {
            false
        }
    }

    // Factory whose stream depends on the seed (so different prefixes/seeds
    // produce different codes, mirroring random.Random(seed)).
    struct SeqFactory;
    impl PseudoFactory for SeqFactory {
        type Source = SeqRng;
        fn make(&self, seed: Option<u64>) -> SeqRng {
            // Derive a small deterministic sequence from the seed.
            let base = (seed.unwrap_or(0) % 1000) as u32 + 1;
            SeqRng { values: vec![base, base + 1, base + 2, base + 3], idx: 0 }
        }
    }

    fn pm(text: &str, type_: &str, start: usize, end: usize) -> PatternMatch {
        PatternMatch {
            text: text.to_string(),
            type_: type_.to_string(),
            start,
            end,
            confidence: 1.0,
            layer: 0,
        }
    }

    fn info(strategy: &str, prefix: &str) -> TypeInfo {
        TypeInfo {
            strategy: strategy.to_string(),
            default_strategy: strategy.to_string(),
            prefix: prefix.to_string(),
            ..Default::default()
        }
    }

    fn empty_whitelist() -> HashSet<String> {
        HashSet::new()
    }

    #[test]
    fn no_entities_early_return() {
        let info_map = HashMap::new();
        let wl = empty_whitelist();
        let r = replace(
            ReplaceArgs {
                text: "hello world",
                entities: &[],
                salt: Some(&Salt::Int(42)),
                key: None,
                type_info: &info_map,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
            },
            &SeqFactory,
            None,
        )
        .unwrap();
        assert_eq!(r.redacted, "hello world");
        assert!(r.key.is_empty());
        assert!(r.aliases.is_empty());
    }

    #[test]
    fn mask_strategy_chars() {
        let mut info_map = HashMap::new();
        info_map.insert("phone".to_string(), info("mask", "P"));
        let wl = empty_whitelist();
        // "电话13812345678" → phone span chars [2..13]
        let text = "电话13812345678";
        let ents = vec![pm("13812345678", "phone", 2, 13)];
        let r = replace(
            ReplaceArgs {
                text,
                entities: &ents,
                salt: Some(&Salt::Int(42)),
                key: None,
                type_info: &info_map,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
            },
            &SeqFactory,
            None,
        )
        .unwrap();
        assert_eq!(r.redacted, "电话138****5678");
        assert_eq!(r.key.get("138****5678"), Some(&"13812345678".to_string()));
    }

    #[test]
    fn keep_whitelisted_self_reference_survives() {
        let mut info_map = HashMap::new();
        info_map.insert("self_reference".to_string(), {
            let mut i = info("keep", "S");
            i.default_strategy = "remove".to_string();
            i
        });
        let mut wl = HashSet::new();
        wl.insert("我".to_string());
        let text = "我是张三";
        let ents = vec![pm("我", "self_reference", 0, 1)];
        let r = replace(
            ReplaceArgs {
                text,
                entities: &ents,
                salt: Some(&Salt::Int(42)),
                key: None,
                type_info: &info_map,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
            },
            &SeqFactory,
            None,
        )
        .unwrap();
        assert_eq!(r.redacted, "我是张三");
        assert!(!r.keep_downgraded);
        // Whitelisted keep entities are NOT added to the key (Python continues
        // before the `result_key[...] = ...` line — only entity_replacements
        // records the identity mapping).
        assert!(!r.key.contains_key("我"));
    }

    #[test]
    fn keep_non_whitelisted_downgrades_and_signals() {
        let mut info_map = HashMap::new();
        info_map.insert("self_reference".to_string(), {
            let mut i = info("keep", "S");
            i.default_strategy = "remove".to_string();
            i
        });
        let wl = empty_whitelist(); // "我" NOT whitelisted
        let text = "我";
        let ents = vec![pm("我", "self_reference", 0, 1)];
        let r = replace(
            ReplaceArgs {
                text,
                entities: &ents,
                salt: Some(&Salt::Int(42)),
                key: None,
                type_info: &info_map,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
            },
            &SeqFactory,
            None,
        )
        .unwrap();
        assert!(r.keep_downgraded);
        // Downgraded to "remove" → a per-type pseudonym code, not "我".
        assert_ne!(r.redacted, "我");
    }

    struct StubFakerFactory;
    impl FakerFactory for StubFakerFactory {
        fn call_faker(&self, _type_: &str, value: &str, master_key: &[u8])
            -> Result<(String, Vec<String>), String> {
            let mut rng = crate::shake_rng::ShakeRng::new(master_key);
            let n = rng.randint(0, 9999);
            Ok((format!("CUST-{value}-{n}"), vec![]))
        }
    }

    #[test]
    fn realistic_custom_faker_routes_to_factory() {
        let mut info_map = HashMap::new();
        info_map.insert("widget".to_string(), {
            let mut i = info("realistic", "W");
            i.faker_resolution = FakerResolution::Custom; // no built-in → custom
            i
        });
        let wl = empty_whitelist();
        let ents = vec![pm("acme", "widget", 0, 4)];
        let r = replace(
            ReplaceArgs { text: "acme", entities: &ents, salt: Some(&Salt::Int(42)),
                key: None, type_info: &info_map, person_prefix: "P", org_prefix: "O",
                unified_prefix: None, keep_whitelist: &wl },
            &SeqFactory, Some(&StubFakerFactory),
        ).unwrap();
        assert!(r.redacted.starts_with("CUST-acme-"));
        assert_eq!(r.key.get(&r.redacted), Some(&"acme".to_string()));
        // The stub faker returns an EMPTY alias list, so the `if
        // !alias_list.is_empty()` guard must skip the insert — no alias entry.
        // Pins that guard (a mutant inverting it would insert an empty vec).
        assert!(r.aliases.is_empty(), "empty alias list must not be inserted: {:?}", r.aliases);
    }

    #[test]
    fn realistic_builtin_faker_routes_to_resolve_faker() {
        // Builtin(name) → resolve_faker(name) + generate_unique_fake. Uses a real
        // built-in faker name so resolve_faker resolves it (not the pseudonym
        // fallback, not the custom FakerFactory path).
        let mut info_map = HashMap::new();
        info_map.insert("phone".to_string(), {
            let mut i = info("realistic", "P");
            i.faker_resolution = FakerResolution::Builtin("fake_phone_reserved".to_string());
            i
        });
        let wl = empty_whitelist();
        let text = "call 13812345678";
        let ents = vec![pm("13812345678", "phone", 5, 16)];
        let r = replace(
            ReplaceArgs { text, entities: &ents, salt: Some(&Salt::Int(42)),
                key: None, type_info: &info_map, person_prefix: "P", org_prefix: "O",
                unified_prefix: None, keep_whitelist: &wl },
            &SeqFactory, None,
        )
        .unwrap();
        // A built-in fake phone replaces the original (not a P-/pseudonym code,
        // not a CUST- factory string). The value maps back in the key.
        let fake = r.key.iter().find(|(_, v)| *v == "13812345678").map(|(k, _)| k.clone());
        assert!(fake.is_some(), "built-in faker should emit a replacement keyed to the original");
        let fake = fake.unwrap();
        assert_ne!(fake, "13812345678");
        assert!(!fake.starts_with("CUST-"));
        assert!(r.redacted.contains(&fake));
    }

    #[test]
    fn realistic_none_falls_back_to_pseudonym() {
        // FakerResolution::None (no built-in name, no custom flag) → pseudonym
        // fallback (organization → org_gen, else per-type gen). A non-org type
        // routes through the per-type pseudonym generator.
        let mut info_map = HashMap::new();
        info_map.insert("widget".to_string(), {
            let i = info("realistic", "W");
            // default faker_resolution == None (no built-in, no custom)
            assert!(matches!(i.faker_resolution, FakerResolution::None));
            i
        });
        let wl = empty_whitelist();
        let ents = vec![pm("acme", "widget", 0, 4)];
        let r = replace(
            ReplaceArgs { text: "acme", entities: &ents, salt: Some(&Salt::Int(42)),
                key: None, type_info: &info_map, person_prefix: "P", org_prefix: "O",
                unified_prefix: None, keep_whitelist: &wl },
            &SeqFactory, None,
        )
        .unwrap();
        // Per-type pseudonym code with the "W" prefix, not a built-in fake or a
        // CUST- factory string.
        assert!(r.redacted.starts_with("W-"));
        assert!(!r.redacted.starts_with("CUST-"));
        assert_eq!(r.key.get(&r.redacted), Some(&"acme".to_string()));
    }

    #[test]
    fn realistic_builtin_faker_emits_aliases() {
        // `fake_person_reserved` returns a reserved name PLUS its pinyin aliases.
        // The `if !alias_list.is_empty()` guard on the built-in path must then
        // record `{fake: aliases}` in the result. Pins that guard: a mutant
        // deleting the `!` would skip the insert and leave aliases empty.
        let mut info_map = HashMap::new();
        info_map.insert("person".to_string(), {
            let mut i = info("realistic", "P");
            i.faker_resolution = FakerResolution::Builtin("fake_person_reserved".to_string());
            i
        });
        let wl = empty_whitelist();
        let text = "张三来了";
        let ents = vec![pm("张三", "person", 0, 2)];
        let r = replace(
            ReplaceArgs {
                text,
                entities: &ents,
                salt: Some(&Salt::Int(42)),
                key: None,
                type_info: &info_map,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
            },
            &SeqFactory,
            None,
        )
        .unwrap();
        // The reserved person faker emits pinyin aliases, so the alias map must
        // carry an entry keyed by the chosen fake name, with a non-empty list.
        assert!(!r.aliases.is_empty(), "person faker must emit aliases");
        let fake = r
            .key
            .iter()
            .find(|(_, v)| *v == "张三")
            .map(|(k, _)| k.clone())
            .expect("person must have a replacement");
        let alias_list = r.aliases.get(&fake).expect("fake must have aliases recorded");
        assert!(!alias_list.is_empty(), "recorded alias list must be non-empty");
    }

    #[test]
    fn pseudonym_organization_uses_org_generator() {
        // An `organization` entity routed through the `pseudonym` strategy must
        // mint its code from the ORG generator (org_prefix "O"), not the person
        // generator (person_prefix "P"). Pins the `entity.type_ ==
        // "organization"` branch: a mutant inverting it would emit a "P-" code.
        let mut info_map = HashMap::new();
        info_map.insert("organization".to_string(), info("pseudonym", "O"));
        let wl = empty_whitelist();
        let text = "在阿里巴巴工作";
        let ents = vec![pm("阿里巴巴", "organization", 1, 5)];
        let r = replace(
            ReplaceArgs {
                text,
                entities: &ents,
                salt: Some(&Salt::Int(42)),
                key: None,
                type_info: &info_map,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
            },
            &SeqFactory,
            None,
        )
        .unwrap();
        let code = r
            .key
            .iter()
            .find(|(_, v)| *v == "阿里巴巴")
            .map(|(k, _)| k.clone())
            .expect("organization must have a pseudonym code");
        assert!(code.starts_with("O-"), "org must use org_prefix, got {code}");
        assert!(!code.starts_with("P-"), "org must NOT use person generator");
        assert!(r.redacted.contains(&code));
    }

    #[test]
    fn pseudonym_person_uses_person_generator() {
        // The contrast partner: a non-org entity through `pseudonym` uses the
        // PERSON generator (person_prefix "P"). Together with the org test this
        // pins both sides of the `entity.type_ == "organization"` branch.
        let mut info_map = HashMap::new();
        info_map.insert("person".to_string(), info("pseudonym", "P"));
        let wl = empty_whitelist();
        let text = "张三来了";
        let ents = vec![pm("张三", "person", 0, 2)];
        let r = replace(
            ReplaceArgs {
                text,
                entities: &ents,
                salt: Some(&Salt::Int(42)),
                key: None,
                type_info: &info_map,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
            },
            &SeqFactory,
            None,
        )
        .unwrap();
        let code = r
            .key
            .iter()
            .find(|(_, v)| *v == "张三")
            .map(|(k, _)| k.clone())
            .expect("person must have a pseudonym code");
        assert!(code.starts_with("P-"), "person must use person_prefix, got {code}");
        assert!(!code.starts_with("O-"), "person must NOT use org generator");
    }

    #[test]
    fn entity_span_ends_at_end_of_text() {
        // An entity whose span ends EXACTLY at text length exercises the
        // `hi < cur_len` slice-clamp boundary: with hi == cur_len, the tail
        // slice must be skipped (no out-of-range copy) and the replacement must
        // land at the very end. Pins the `if hi < cur_len` guard.
        let mut info_map = HashMap::new();
        info_map.insert("phone".to_string(), info("mask", "P"));
        let wl = empty_whitelist();
        // "call 13812345678" — phone occupies chars [5..16], end == len (16).
        let text = "call 13812345678";
        assert_eq!(text.chars().count(), 16);
        let ents = vec![pm("13812345678", "phone", 5, 16)];
        let r = replace(
            ReplaceArgs {
                text,
                entities: &ents,
                salt: Some(&Salt::Int(42)),
                key: None,
                type_info: &info_map,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
            },
            &SeqFactory,
            None,
        )
        .unwrap();
        assert_eq!(r.redacted, "call 138****5678");
    }

    // Factory whose stream is INDEPENDENT of the seed: every generator it mints
    // draws 7, 7, 8, ... So two sibling generators sharing one (unified) prefix
    // would both want `U-00007` first — exactly the R1 collision condition.
    struct ConstFactory;
    impl PseudoFactory for ConstFactory {
        type Source = SeqRng;
        fn make(&self, _seed: Option<u64>) -> SeqRng {
            SeqRng { values: vec![7, 7, 8], idx: 0 }
        }
    }

    #[test]
    fn unified_prefix_cross_generator_no_collision() {
        // A person (pseudo_gen) and a remove-strategy type (a type_gen) both
        // collapse to unified_prefix "U". With every generator drawing the same
        // first number, the pre-fix code minted `U-00007` for BOTH, so the second
        // `result_key.insert` silently overwrote the first mapping. The shared
        // reserved set must now force the second generator to a distinct code, so
        // the key keeps BOTH originals.
        let mut info_map = HashMap::new();
        info_map.insert("person".to_string(), info("pseudonym", "P"));
        info_map.insert("phone".to_string(), info("remove", ""));
        let wl = empty_whitelist();
        let text = "王 138";
        let ents = vec![
            pm("王", "person", 0, 1),
            pm("138", "phone", 2, 5),
        ];
        let r = replace(
            ReplaceArgs {
                text,
                entities: &ents,
                salt: Some(&Salt::Int(42)),
                key: None,
                type_info: &info_map,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: Some("U"),
                keep_whitelist: &wl,
            },
            &ConstFactory,
            None,
        )
        .unwrap();
        // Both originals survive in the key under DISTINCT codes.
        assert_eq!(r.key.len(), 2, "both entities must be keyed: {:?}", r.key);
        let codes: HashSet<&String> = r.key.keys().collect();
        assert_eq!(codes.len(), 2, "codes must be distinct (no overwrite): {:?}", r.key);
        assert_eq!(r.key.get("U-00007"), Some(&"王".to_string()));
        assert_eq!(r.key.get("U-00008"), Some(&"138".to_string()));
        // Round-trip: both codes appear in the redacted text.
        assert!(r.redacted.contains("U-00007") && r.redacted.contains("U-00008"));
    }

    #[test]
    fn right_to_left_assembly_two_entities() {
        let mut info_map = HashMap::new();
        info_map.insert("phone".to_string(), info("mask", "P"));
        let wl = empty_whitelist();
        // "a 13812345678 b 13900000000" two phones
        let text = "a 13812345678 b 13900000000";
        let ents = vec![
            pm("13812345678", "phone", 2, 13),
            pm("13900000000", "phone", 16, 27),
        ];
        let r = replace(
            ReplaceArgs {
                text,
                entities: &ents,
                salt: Some(&Salt::Int(42)),
                key: None,
                type_info: &info_map,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
            },
            &SeqFactory,
            None,
        )
        .unwrap();
        assert_eq!(r.redacted, "a 138****5678 b 139****0000");
    }

    #[test]
    fn mask_collision_recorded_when_two_originals_share_a_masked_label() {
        // "13812345678" and "13800005678" both mask to "138****5678" (mask only
        // shows the first 3 + last 4 chars) — a REAL collision that
        // resolve_collision disambiguates with a trailing circled digit. The
        // session must record it in `mask_collisions`.
        let mut info_map = HashMap::new();
        info_map.insert("phone".to_string(), info("mask", "P"));
        let wl = empty_whitelist();
        let text = "电话13812345678 和 13800005678";
        let ents = vec![
            pm("13812345678", "phone", 2, 13),
            pm("13800005678", "phone", 16, 27),
        ];
        let r = replace(
            ReplaceArgs {
                text,
                entities: &ents,
                salt: Some(&Salt::Int(42)),
                key: None,
                type_info: &info_map,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
            },
            &SeqFactory,
            None,
        )
        .unwrap();
        assert_eq!(r.mask_collisions, vec!["phone".to_string()]);
        // The collided entry is NOT dropped — both originals stay in the key
        // (direct in-process restore still works); only the signal is added.
        assert_eq!(r.key.len(), 2, "both originals must stay keyed: {:?}", r.key);
        assert_eq!(r.key.get("138****5678"), Some(&"13812345678".to_string()));
        assert_eq!(r.key.get("138****5678①"), Some(&"13800005678".to_string()));
    }

    #[test]
    fn no_mask_collision_when_labels_differ() {
        // The existing two-phone fixture masks to two DISTINCT labels — no
        // collision, so `mask_collisions` must stay empty.
        let mut info_map = HashMap::new();
        info_map.insert("phone".to_string(), info("mask", "P"));
        let wl = empty_whitelist();
        let text = "a 13812345678 b 13900000000";
        let ents = vec![
            pm("13812345678", "phone", 2, 13),
            pm("13900000000", "phone", 16, 27),
        ];
        let r = replace(
            ReplaceArgs {
                text,
                entities: &ents,
                salt: Some(&Salt::Int(42)),
                key: None,
                type_info: &info_map,
                person_prefix: "P",
                org_prefix: "O",
                unified_prefix: None,
                keep_whitelist: &wl,
            },
            &SeqFactory,
            None,
        )
        .unwrap();
        assert!(r.mask_collisions.is_empty(), "no collision expected: {:?}", r.mask_collisions);
    }
}
