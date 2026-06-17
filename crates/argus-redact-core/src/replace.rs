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

use crate::fakers::{generate_unique_fake, resolve_faker};
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
    /// Resolved built-in faker function name (e.g. `"fake_phone_reserved"`),
    /// or `None` when no built-in faker resolves for this `(type, langs)`.
    pub faker_name: Option<String>,
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
/// The `realistic` strategy resolves built-in fakers by `faker_name` via
/// [`resolve_faker`]; a type whose `faker_name` is `None` (a custom Python
/// `faker_reserved` callable) is NOT handled here — the Python wrapper detects
/// that case up front and routes the whole call to `_replace_python` instead.
pub fn replace<F: PseudoFactory>(
    args: ReplaceArgs<'_>,
    factory: &F,
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

    let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
    let mut keep_downgraded = false;

    // No-entities early return (Python: `return text, key or {}, aliases`).
    if entities.is_empty() {
        return Ok(ReplaceResult {
            redacted: text.to_string(),
            key: key.cloned().unwrap_or_default(),
            aliases,
            keep_downgraded,
        });
    }

    let mut result_key: HashMap<String, String> = key.cloned().unwrap_or_default();
    let mut used_labels: HashSet<String> = result_key.keys().cloned().collect();

    // reverse_index: original → replacement (for existing-key reuse).
    let mut reverse_index: HashMap<String, String> = HashMap::new();
    for (replacement, original) in &result_key {
        reverse_index.insert(original.clone(), replacement.clone());
    }

    let pseudo_seed_int = pseudonym_seed_int(salt);
    let existing_for_gen = if result_key.is_empty() {
        None
    } else {
        Some(result_key.clone())
    };

    // Person + organization pseudonym generators.
    let mut pseudo_gen = PseudonymGenerator::new(
        unified_prefix.unwrap_or(person_prefix),
        PSEUDONYM_CODE_RANGE,
        factory.make(pseudo_seed_int),
        existing_for_gen.as_ref(),
    );
    let mut org_gen = PseudonymGenerator::new(
        unified_prefix.unwrap_or(org_prefix),
        PSEUDONYM_CODE_RANGE,
        factory.make(offset_seed(pseudo_seed_int, 1)),
        existing_for_gen.as_ref(),
    );
    // Per-type pseudonym generators for the remove strategy (LLM survival).
    let mut type_gens: HashMap<String, PseudonymGenerator<F::Source>> = HashMap::new();

    // Salt is immutable for the whole call; resolve it once, lazily — only when
    // a built-in realistic faker actually needs it. Deferring the resolve keeps
    // the original error surface (a `None` salt with no env var errors only when
    // a realistic faker is reached, not for calls without any realistic entity).
    let mut resolved_salt: Option<Vec<u8>> = None;

    let mut entity_replacements: HashMap<String, String> = HashMap::new();

    for entity in entities {
        if entity_replacements.contains_key(&entity.text) {
            continue;
        }
        if let Some(existing) = reverse_index.get(&entity.text) {
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
            keep_downgraded = true;
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
                    let live = if result_key.is_empty() { None } else { Some(&result_key) };
                    org_gen = PseudonymGenerator::new(
                        prefix,
                        PSEUDONYM_CODE_RANGE,
                        factory.make(offset_seed(pseudo_seed_int, 1)),
                        live,
                    );
                }
                org_gen.get(&entity.text)
            } else {
                if info.map(|i| i.prefix_overridden).unwrap_or(false) {
                    // Same rebuild semantics for the person generator
                    // (replacer.py:586–591): config prefix + live result_key.
                    let prefix = info.map(|i| i.prefix.as_str()).unwrap_or("P");
                    let live = if result_key.is_empty() { None } else { Some(&result_key) };
                    pseudo_gen = PseudonymGenerator::new(
                        prefix,
                        PSEUDONYM_CODE_RANGE,
                        factory.make(pseudo_seed_int),
                        live,
                    );
                }
                pseudo_gen.get(&entity.text)
            }
        } else if strategy == "realistic" {
            let faker_name = info.and_then(|i| i.faker_name.as_deref());
            if let Some(name) = faker_name {
                // Built-in faker resolvable in Rust. (A custom faker_reserved
                // has no faker_name and would have routed to _replace_python.)
                let faker = resolve_faker(name).ok_or_else(|| {
                    format!("realistic strategy: unknown faker '{name}' for type '{}'", entity.type_)
                })?;
                if resolved_salt.is_none() {
                    resolved_salt = Some(resolve_salt(salt)?);
                }
                let salt_bytes = resolved_salt.as_deref().expect("resolved_salt set above");
                let (fake, alias_list) =
                    generate_unique_fake(faker, &entity.text, &entity.type_, salt_bytes, &used_labels)?;
                if !alias_list.is_empty() {
                    aliases.insert(fake.clone(), alias_list);
                }
                fake
            } else if entity.type_ == "organization" {
                org_gen.get(&entity.text)
            } else {
                let type_gen = get_type_gen(
                    &mut type_gens,
                    &entity.type_,
                    info,
                    unified_prefix,
                    pseudo_seed_int,
                    existing_for_gen.as_ref(),
                    factory,
                );
                type_gen.get(&entity.text)
            }
        } else if strategy == "mask" {
            let (vp, vs) = info.map(|i| (i.visible_prefix, i.visible_suffix)).unwrap_or((0, 0));
            let masked = mask_value(&entity.text, &entity.type_, vp, vs);
            resolve_collision(&masked, &used_labels)
        } else if strategy == "name_mask" {
            resolve_collision(&mask_name(&entity.text), &used_labels)
        } else if strategy == "landline_mask" {
            resolve_collision(&mask_landline(&entity.text), &used_labels)
        } else if strategy == "remove" {
            if let Some(repl) = info.and_then(|i| i.replacement.as_deref()) {
                resolve_collision(repl, &used_labels)
            } else {
                let type_gen = get_type_gen(
                    &mut type_gens,
                    &entity.type_,
                    info,
                    unified_prefix,
                    pseudo_seed_int,
                    existing_for_gen.as_ref(),
                    factory,
                );
                type_gen.get(&entity.text)
            }
        } else if strategy == "category" {
            let label = info
                .and_then(|i| i.label.clone())
                .or_else(|| info.map(|i| i.default_category_label.clone()))
                .unwrap_or_else(|| format!("[{}]", entity.type_));
            resolve_collision(&label, &used_labels)
        } else {
            resolve_collision(DEFAULT_REDACT_LABEL, &used_labels)
        };

        entity_replacements.insert(entity.text.clone(), replacement.clone());
        used_labels.insert(replacement.clone());
        result_key.insert(replacement, entity.text.clone());
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
        let mut new_chars = Vec::with_capacity(lo + repl_chars.len() + cur_len.saturating_sub(hi));
        new_chars.extend_from_slice(&result_chars[..lo]);
        new_chars.extend_from_slice(&repl_chars);
        if hi < cur_len {
            new_chars.extend_from_slice(&result_chars[hi..]);
        }
        result_chars = new_chars;
    }

    Ok(ReplaceResult {
        redacted: result_chars.into_iter().collect(),
        key: result_key,
        aliases,
        keep_downgraded,
    })
}

/// Lazily build (or fetch) the per-type pseudonym generator for the remove /
/// realistic-fallback strategies. Mirrors `_get_type_gen` (replacer.py:525–533).
#[allow(clippy::too_many_arguments)]
fn get_type_gen<'a, F: PseudoFactory>(
    type_gens: &'a mut HashMap<String, PseudonymGenerator<F::Source>>,
    entity_type: &str,
    info: Option<&TypeInfo>,
    unified_prefix: Option<&str>,
    pseudo_seed_int: Option<u64>,
    existing: Option<&HashMap<String, String>>,
    factory: &F,
) -> &'a mut PseudonymGenerator<F::Source> {
    type_gens.entry(entity_type.to_string()).or_insert_with(|| {
        // Prefix: unified_prefix, else DEFAULT_PREFIXES[type] (resolved on the
        // Python side into TypeInfo.prefix, with the type.upper()[:4] fallback).
        let prefix = unified_prefix.unwrap_or_else(|| info.map(|i| i.prefix.as_str()).unwrap_or(""));
        let seed = offset_seed(pseudo_seed_int, type_seed_offset(entity_type) as u64);
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
        )
        .unwrap();
        assert!(r.keep_downgraded);
        // Downgraded to "remove" → a per-type pseudonym code, not "我".
        assert_ne!(r.redacted, "我");
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
        )
        .unwrap();
        assert_eq!(r.redacted, "a 138****5678 b 139****0000");
    }
}
