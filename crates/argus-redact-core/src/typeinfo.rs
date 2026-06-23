//! Built-in `TypeInfo` assembly — the SSOT port of `pure/replacer._build_type_info`.
//!
//! Folds the per-type default strategy + user config + prefix / category label +
//! the built-in faker name into the per-type [`TypeInfo`] the core `replace()`
//! consumes. Moving this out of Python lets the PyO3 binding AND a future wasm
//! crate share one implementation; the only piece that stays in Python is the
//! custom-adapter `faker_reserved` callable overlay (resolved via
//! `PyFakerFactory`), which the caller layers on top of the info this module
//! produces.
//!
//! **Per-type defaults SSOT.** The authoritative default strategy / prefix /
//! category-label for a type lives in the Python registry (`specs/{zh,en,shared}`
//! plus any runtime-registered adapter type), which is the SSOT and is the ONLY
//! place a runtime adapter type can be seen. The PyO3 caller therefore threads
//! the registry-resolved values in per type (`registry_defaults`); this module
//! uses the passed value when present and falls back to its built-in tables only
//! when no value is passed — the wasm path, which has built-in types only and no
//! Python registry. The built-in tables are kept in lockstep with the registry
//! by the drift-guard sweep in `tests/specs/test_typeinfo_drift_guard.py`.
//!
//! Bit-identity with the Python original is the gate: `build_type_info` must
//! reproduce `_build_type_info`'s built-in `info` dict field-for-field (the
//! custom-faker map is the caller's responsibility), for built-in AND custom
//! adapter types.

use std::collections::HashMap;

use crate::fakers::builtin_faker_name;
use crate::replace::{FakerResolution, TypeInfo};
use crate::types::PatternMatch;

/// Lang registration order across the built-in specs (`specs/{zh,en,shared}.py`
/// import order in `specs/__init__.py`). Drives the realistic faker's
/// "any registered lang" fallback so it matches Python's `by_lang.values()`
/// iteration (registration order) — every multi-lang built-in faker type
/// registers zh before en before shared, so iterating this list and taking the
/// first lang with a built-in faker reproduces `_resolve_realistic_faker`'s
/// final fallback step.
const LANG_REGISTRATION_ORDER: [&str; 3] = ["zh", "en", "shared"];

/// `DEFAULT_PREFIXES` — transcribed verbatim from `pure/replacer.py`. Pseudonym /
/// remove prefixes per type; a type not listed falls back to `type.upper()[:4]`.
fn default_prefix(type_: &str) -> Option<&'static str> {
    Some(match type_ {
        "person" => "P",
        "organization" => "O",
        // Pseudonym prefixes for remove-as-pseudonym (improves LLM survival rate)
        "id_number" => "ID",
        "passport" => "PASS",
        "license_plate" => "PLATE",
        "address" => "ADDR",
        "ssn" => "SSN",
        "military_id" => "MIL",
        "social_security" => "SOC",
        "credit_code" => "BIZ",
        "date_of_birth" => "DOB",
        "us_passport" => "PASS",
        "job_title" => "TITLE",
        "school" => "SCH",
        "ethnicity" => "ETH",
        "workplace" => "WORK",
        "hobby" => "HOBBY",
        "criminal_record" => "CRIM",
        "financial" => "FIN",
        "biometric" => "BIO",
        "medical" => "MED",
        "religion" => "REL",
        "political" => "POL",
        "sexual_orientation" => "ORI",
        "ip_address" => "IP",
        "mac_address" => "MAC",
        "imei" => "IMEI",
        "url_token" => "URL",
        "age" => "AGE",
        "gender" => "GEN",
        "self_reference" => "S",
        // Quasi-identifiers referenced by integrations (Presidio, profiles)
        "phone_landline" => "LL",
        "date" => "DATE",
        "url" => "URL",
        // Credentials / secrets
        "openai_api_key" => "OAI-KEY",
        "anthropic_api_key" => "ANT-KEY",
        "aws_access_key" => "AWS-KEY",
        "github_token" => "GH-TOKEN",
        "jwt" => "JWT",
        "ssh_private_key" => "SSH-KEY",
        _ => return None,
    })
}

/// `DEFAULT_CATEGORY_LABEL` — transcribed verbatim from `pure/replacer.py`.
/// A type not listed falls back to `[type]`.
fn default_category_label(type_: &str) -> Option<&'static str> {
    match type_ {
        "location" => Some("[LOCATION]"),
        _ => None,
    }
}

/// BUILT-IN fallback table for the per-type default strategy, used ONLY when the
/// caller passes no `registry_defaults` entry for the type (the wasm path — no
/// Python registry). On the PyO3 path the Python shim threads the live-registry
/// `_resolve_default_strategy(type)` (= `lookup(name)[0].strategy`) value in, so
/// runtime adapter types honor their declared strategy regardless of this table.
///
/// Transcribed from the per-type `strategy=` declarations in
/// `specs/{zh,en,shared}.py` (the only built-in types whose default is not
/// `remove`); an unknown type falls back to `remove`. This table is kept in
/// lockstep with the live registry by the drift-guard sweep
/// (`tests/specs/test_typeinfo_drift_guard.py`), which iterates every
/// `list_types()` and re-derives `lookup(name)[0].strategy`.
fn default_strategy(type_: &str) -> &'static str {
    match type_ {
        "person" => "pseudonym",
        "organization" => "pseudonym",
        "school" => "pseudonym",
        "self_reference" => "keep",
        "phone" => "mask",
        "phone_landline" => "mask",
        "email" => "mask",
        "bank_card" => "mask",
        "credit_card" => "mask",
        _ => "remove",
    }
}

/// Unified lang-preference resolution for the `realistic` strategy, mirroring
/// `_resolve_realistic_faker` for BUILT-IN fakers only. Returns the built-in
/// faker name (a key into [`crate::fakers::resolve_faker`]) for the first lang in
/// preference order that has a built-in association, or `None`.
///
/// Built-in resolution order (`_resolve_realistic_faker_cached`):
///   1. detected `langs`, in caller order
///   2. the cross-language `"shared"` fallback
///   3. any registered lang in registration order ([`LANG_REGISTRATION_ORDER`])
///
/// Custom (`faker_reserved`) callables are NOT resolved here — they live outside
/// the built-in modules and are overlaid by the caller (`PyFakerFactory`). A
/// type+lang with a custom callable in Python would short-circuit before the
/// built-in lookup; the PyO3 shim re-creates that precedence by overlaying its
/// custom-faker map after this returns (the only place a custom faker can appear
/// is a registered adapter type, which has no built-in name regardless).
fn resolve_builtin_faker(type_: &str, langs: &[String]) -> Option<&'static str> {
    // 1. detected langs, in caller order
    for lang in langs {
        if let Some(name) = builtin_faker_name(type_, lang) {
            return Some(name);
        }
    }
    // 2. cross-language 'shared' fallback
    if let Some(name) = builtin_faker_name(type_, "shared") {
        return Some(name);
    }
    // 3. any registered lang, in registration order
    for lang in LANG_REGISTRATION_ORDER {
        if let Some(name) = builtin_faker_name(type_, lang) {
            return Some(name);
        }
    }
    None
}

/// User config for one entity type. Mirrors the per-type dict
/// `pure/replacer._get_entity_config` returns: each field is optional and
/// overrides the registry/`DEFAULT_*` default. `prefix.is_some()` reproduces the
/// Python `"prefix" in ec` check that drives `prefix_overridden`.
#[derive(Debug, Clone, Default)]
pub struct EntityConfig {
    /// `config[type]["strategy"]` — overrides the registry default when set.
    pub strategy: Option<String>,
    /// `config[type]["prefix"]` — `Some` iff the user set `prefix` (sets
    /// `prefix_overridden`).
    pub prefix: Option<String>,
    /// `config[type]["replacement"]` for the `remove` strategy.
    pub replacement: Option<String>,
    /// `config[type]["label"]` for the `category` strategy.
    pub label: Option<String>,
    /// `config[type]["visible_prefix"]` for `mask` (`None`/`0` → per-type default).
    pub visible_prefix: Option<usize>,
    /// `config[type]["visible_suffix"]` for `mask` (`None`/`0` → per-type default).
    pub visible_suffix: Option<usize>,
}

/// User config: `{type_name: EntityConfig}`. The full `config` dict passed to
/// `replace()`; only the per-type entries matter for `build_type_info`.
pub type Config = HashMap<String, EntityConfig>;

/// Registry-resolved per-type defaults, threaded from the Python SSOT. For every
/// detected type the PyO3 shim resolves the live-registry default strategy
/// (`_resolve_default_strategy`) plus the `DEFAULT_PREFIXES` / `DEFAULT_CATEGORY_LABEL`
/// lookups and hands them in here so runtime adapter types — invisible to this
/// crate's built-in tables — get their declared defaults. Any field left `None`
/// falls back to this module's built-in table for that type.
#[derive(Debug, Clone, Default)]
pub struct RegistryDefault {
    /// `_resolve_default_strategy(type)` — the registry's declared strategy.
    pub strategy: Option<String>,
    /// `DEFAULT_PREFIXES.get(type, type.upper()[:4])` — the resolved prefix.
    pub prefix: Option<String>,
    /// `DEFAULT_CATEGORY_LABEL.get(type, f"[{type}]")` — the resolved label.
    pub category_label: Option<String>,
}

/// `{type_name: RegistryDefault}` — the authoritative per-type defaults from the
/// Python registry. `None` (the wasm path) → the built-in fallback tables drive
/// every type.
pub type RegistryDefaults = HashMap<String, RegistryDefault>;

/// Build the per-type `(type_name, TypeInfo)` pairs for the BUILT-IN replacement
/// info `replace()` needs, in first-occurrence order (dedup by type — the second
/// and later entities of a type are skipped, matching `_build_type_info`'s
/// `if etype in info: continue`).
///
/// Folds the registry default strategy + user `config` + `DEFAULT_PREFIXES` /
/// `DEFAULT_CATEGORY_LABEL` + the built-in faker name into each [`TypeInfo`],
/// faithfully reproducing `pure/replacer._build_type_info`'s `info` dict. The
/// custom-adapter faker overlay (the `custom_fakers` map) is NOT produced here —
/// the caller (PyO3 / wasm) overlays its custom callables, which only ever apply
/// to registered adapter types that have no built-in faker name.
///
/// A type whose effective strategy is `realistic` resolves to
/// [`FakerResolution::Builtin`] when a built-in faker exists, else
/// [`FakerResolution::None`] (the caller may upgrade `None` to
/// [`FakerResolution::Custom`] for adapter types). Any non-`realistic` strategy
/// leaves [`FakerResolution::None`].
///
/// `registry_defaults` carries the authoritative per-type default strategy /
/// prefix / category-label from the Python registry (the SSOT, including runtime
/// adapter types). For each detected type, a present field wins; an absent field
/// (or `registry_defaults == None`, the wasm path) falls back to this module's
/// built-in tables. This is the same threading pattern as the built-in faker
/// name and preserves byte-identity with `_build_type_info` for built-in AND
/// custom adapter types.
pub fn build_type_info(
    entities: &[PatternMatch],
    config: Option<&Config>,
    langs: &[String],
    registry_defaults: Option<&RegistryDefaults>,
) -> Vec<(String, TypeInfo)> {
    let mut info: Vec<(String, TypeInfo)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entity in entities {
        let etype = entity.type_.as_str();
        if !seen.insert(etype.to_string()) {
            continue; // dedup: first occurrence wins
        }
        let ec = config.and_then(|c| c.get(etype));
        let rd = registry_defaults.and_then(|r| r.get(etype));

        // Default strategy: registry value (SSOT, sees adapter types) when
        // threaded in, else the built-in fallback table (wasm path).
        let default_strat: String = rd
            .and_then(|r| r.strategy.clone())
            .unwrap_or_else(|| default_strategy(etype).to_string());
        // strategy precedence: `ec.get("strategy") or default` — a falsy ("")
        // config strategy falls through to default, matching Python `or`.
        let strategy = ec
            .and_then(|e| e.strategy.as_deref())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| default_strat.clone());

        let prefix_overridden = ec.map(|e| e.prefix.is_some()).unwrap_or(false);
        let prefix = ec
            .and_then(|e| e.prefix.clone())
            // registry-threaded prefix (SSOT) wins over the built-in table.
            .or_else(|| rd.and_then(|r| r.prefix.clone()))
            .or_else(|| default_prefix(etype).map(str::to_string))
            // `type.upper()[:4]` fallback for types absent from DEFAULT_PREFIXES.
            .unwrap_or_else(|| etype.to_uppercase().chars().take(4).collect());

        // Realistic strategy → built-in faker name (else None; the caller may
        // overlay a custom faker for adapter types).
        let faker_resolution = if strategy == "realistic" {
            match resolve_builtin_faker(etype, langs) {
                Some(name) => FakerResolution::Builtin(name.to_string()),
                None => FakerResolution::None,
            }
        } else {
            FakerResolution::None
        };

        let dcl = rd
            .and_then(|r| r.category_label.clone())
            .or_else(|| default_category_label(etype).map(str::to_string))
            .unwrap_or_else(|| format!("[{etype}]"));

        info.push((
            etype.to_string(),
            TypeInfo {
                strategy,
                default_strategy: default_strat,
                prefix,
                prefix_overridden,
                faker_resolution,
                replacement: ec.and_then(|e| e.replacement.clone()),
                label: ec.and_then(|e| e.label.clone()),
                default_category_label: dcl,
                visible_prefix: ec.and_then(|e| e.visible_prefix).unwrap_or(0),
                visible_suffix: ec.and_then(|e| e.visible_suffix).unwrap_or(0),
            },
        ));
    }
    info
}

#[cfg(test)]
mod tests {
    //! Parity tests for [`build_type_info`]. Each expectation is captured VERBATIM
    //! from live Python:
    //!   `PYTHONPATH=src python3 -c "from argus_redact._types import PatternMatch;
    //!    from argus_redact.pure.replacer import _build_type_info;
    //!    print(_build_type_info([PatternMatch(...)], <config>, [<langs>]))"`
    //! and asserted field-for-field against the produced [`TypeInfo`].

    use super::*;

    fn pm(text: &str, type_: &str) -> PatternMatch {
        PatternMatch {
            text: text.to_string(),
            type_: type_.to_string(),
            start: 0,
            end: text.len(),
            confidence: 1.0,
            layer: 0,
        }
    }

    fn langs(ls: &[&str]) -> Vec<String> {
        ls.iter().map(|s| s.to_string()).collect()
    }

    fn cfg(entries: &[(&str, EntityConfig)]) -> Config {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    /// Look up the produced TypeInfo for `type_` (panics if absent).
    fn get<'a>(info: &'a [(String, TypeInfo)], type_: &str) -> &'a TypeInfo {
        &info
            .iter()
            .find(|(k, _)| k == type_)
            .unwrap_or_else(|| panic!("type {type_} not in info"))
            .1
    }

    // Compare a TypeInfo against the captured Python fields. `faker` is the
    // expected built-in faker name (None = no faker / non-builtin).
    #[allow(clippy::too_many_arguments)]
    fn assert_info(
        ti: &TypeInfo,
        strategy: &str,
        default_strategy: &str,
        prefix: &str,
        prefix_overridden: bool,
        faker: Option<&str>,
        replacement: Option<&str>,
        label: Option<&str>,
        default_category_label: &str,
        visible_prefix: usize,
        visible_suffix: usize,
    ) {
        assert_eq!(ti.strategy, strategy, "strategy");
        assert_eq!(ti.default_strategy, default_strategy, "default_strategy");
        assert_eq!(ti.prefix, prefix, "prefix");
        assert_eq!(ti.prefix_overridden, prefix_overridden, "prefix_overridden");
        let got_faker = match &ti.faker_resolution {
            FakerResolution::Builtin(n) => Some(n.as_str()),
            FakerResolution::Custom => Some("<custom>"),
            FakerResolution::None => None,
        };
        assert_eq!(got_faker, faker, "faker_resolution");
        assert_eq!(ti.replacement.as_deref(), replacement, "replacement");
        assert_eq!(ti.label.as_deref(), label, "label");
        assert_eq!(
            ti.default_category_label, default_category_label,
            "default_category_label"
        );
        assert_eq!(ti.visible_prefix, visible_prefix, "visible_prefix");
        assert_eq!(ti.visible_suffix, visible_suffix, "visible_suffix");
    }

    #[test]
    fn pseudonym_person() {
        // _build_type_info([pm('Alice','person')], None, ['en'])
        let info = build_type_info(&[pm("Alice", "person")], None, &langs(&["en"]), None);
        assert_info(
            get(&info, "person"),
            "pseudonym",
            "pseudonym",
            "P",
            false,
            None,
            None,
            None,
            "[person]",
            0,
            0,
        );
    }

    #[test]
    fn mask_phone() {
        // _build_type_info([pm('13800138000','phone')], None, ['zh'])
        let info = build_type_info(&[pm("13800138000", "phone")], None, &langs(&["zh"]), None);
        assert_info(
            get(&info, "phone"),
            "mask",
            "mask",
            "PHON", // not in DEFAULT_PREFIXES -> type.upper()[:4]
            false,
            None,
            None,
            None,
            "[phone]",
            0,
            0,
        );
    }

    #[test]
    fn realistic_builtin_phone_zh() {
        // _build_type_info([pm('13800138000','phone')], {'phone':{'strategy':'realistic'}}, ['zh'])
        let info = build_type_info(
            &[pm("13800138000", "phone")],
            Some(&cfg(&[(
                "phone",
                EntityConfig {
                    strategy: Some("realistic".to_string()),
                    ..Default::default()
                },
            )])),
            &langs(&["zh"]),
            None,
        );
        assert_info(
            get(&info, "phone"),
            "realistic",
            "mask",
            "PHON",
            false,
            Some("fake_phone_reserved"),
            None,
            None,
            "[phone]",
            0,
            0,
        );
    }

    #[test]
    fn realistic_builtin_phone_en() {
        // detected lang en -> the en faker, not the zh one
        let info = build_type_info(
            &[pm("555-1234", "phone")],
            Some(&cfg(&[(
                "phone",
                EntityConfig {
                    strategy: Some("realistic".to_string()),
                    ..Default::default()
                },
            )])),
            &langs(&["en"]),
            None,
        );
        assert_eq!(
            match &get(&info, "phone").faker_resolution {
                FakerResolution::Builtin(n) => n.as_str(),
                _ => "<none>",
            },
            "fake_phone_en_reserved"
        );
    }

    #[test]
    fn realistic_builtin_email_shared() {
        // email registered only for 'shared'; detected lang en -> 'shared' fallback
        let info = build_type_info(
            &[pm("a@b.com", "email")],
            Some(&cfg(&[(
                "email",
                EntityConfig {
                    strategy: Some("realistic".to_string()),
                    ..Default::default()
                },
            )])),
            &langs(&["en"]),
            None,
        );
        assert_info(
            get(&info, "email"),
            "realistic",
            "mask",
            "EMAI",
            false,
            Some("fake_email_reserved"),
            None,
            None,
            "[email]",
            0,
            0,
        );
    }

    #[test]
    fn realistic_any_registered_lang_fallback() {
        // id_number registered only for zh; detected lang en + no 'shared' -> the
        // 'any registered lang' fallback picks the zh faker.
        let info = build_type_info(
            &[pm("x", "id_number")],
            Some(&cfg(&[(
                "id_number",
                EntityConfig {
                    strategy: Some("realistic".to_string()),
                    ..Default::default()
                },
            )])),
            &langs(&["en"]),
            None,
        );
        assert_info(
            get(&info, "id_number"),
            "realistic",
            "remove",
            "ID",
            false,
            Some("fake_id_number_reserved"),
            None,
            None,
            "[id_number]",
            0,
            0,
        );
    }

    #[test]
    fn keep_self_reference() {
        // _build_type_info([pm('I','self_reference')], None, ['en'])
        let info = build_type_info(&[pm("I", "self_reference")], None, &langs(&["en"]), None);
        assert_info(
            get(&info, "self_reference"),
            "keep",
            "keep",
            "S",
            false,
            None,
            None,
            None,
            "[self_reference]",
            0,
            0,
        );
    }

    #[test]
    fn config_overrides_strategy_and_prefix() {
        // {'phone':{'strategy':'remove','prefix':'TEL'}} -> prefix_overridden=true
        let info = build_type_info(
            &[pm("13800138000", "phone")],
            Some(&cfg(&[(
                "phone",
                EntityConfig {
                    strategy: Some("remove".to_string()),
                    prefix: Some("TEL".to_string()),
                    ..Default::default()
                },
            )])),
            &langs(&["zh"]),
            None,
        );
        assert_info(
            get(&info, "phone"),
            "remove",
            "mask",
            "TEL",
            true,
            None,
            None,
            None,
            "[phone]",
            0,
            0,
        );
    }

    #[test]
    fn config_category_label_and_visible() {
        // {'phone':{'strategy':'category','label':'[TEL]','visible_prefix':3,'visible_suffix':4}}
        let info = build_type_info(
            &[pm("13800138000", "phone")],
            Some(&cfg(&[(
                "phone",
                EntityConfig {
                    strategy: Some("category".to_string()),
                    label: Some("[TEL]".to_string()),
                    visible_prefix: Some(3),
                    visible_suffix: Some(4),
                    ..Default::default()
                },
            )])),
            &langs(&["zh"]),
            None,
        );
        assert_info(
            get(&info, "phone"),
            "category",
            "mask",
            "PHON",
            false,
            None,
            None,
            Some("[TEL]"),
            "[phone]",
            3,
            4,
        );
    }

    #[test]
    fn location_category_default_label() {
        // _build_type_info([pm('Paris','location')], None, ['en'])
        let info = build_type_info(&[pm("Paris", "location")], None, &langs(&["en"]), None);
        assert_info(
            get(&info, "location"),
            "remove",
            "remove",
            "LOCA",
            false,
            None,
            None,
            None,
            "[LOCATION]", // DEFAULT_CATEGORY_LABEL
            0,
            0,
        );
    }

    #[test]
    fn unknown_type_no_faker() {
        // _build_type_info([pm('xyz','mystery_type')], None, ['en'])
        let info = build_type_info(&[pm("xyz", "mystery_type")], None, &langs(&["en"]), None);
        assert_info(
            get(&info, "mystery_type"),
            "remove",
            "remove",
            "MYST", // type.upper()[:4]
            false,
            None,
            None,
            None,
            "[mystery_type]",
            0,
            0,
        );
    }

    #[test]
    fn dedup_first_occurrence() {
        // [person, person, email] -> person once (first), email once; order preserved
        let info = build_type_info(
            &[
                pm("Alice", "person"),
                pm("Bob", "person"),
                pm("x@y.com", "email"),
            ],
            None,
            &langs(&["en"]),
            None,
        );
        let keys: Vec<&str> = info.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["person", "email"]);
        assert_eq!(get(&info, "person").strategy, "pseudonym");
        assert_eq!(get(&info, "email").strategy, "mask");
    }

    #[test]
    fn realistic_no_builtin_falls_to_none() {
        // a realistic type with NO built-in faker -> FakerResolution::None
        let info = build_type_info(
            &[pm("x", "mystery_type")],
            Some(&cfg(&[(
                "mystery_type",
                EntityConfig {
                    strategy: Some("realistic".to_string()),
                    ..Default::default()
                },
            )])),
            &langs(&["en"]),
            None,
        );
        assert!(matches!(
            get(&info, "mystery_type").faker_resolution,
            FakerResolution::None
        ));
    }

    fn rdefs(entries: &[(&str, RegistryDefault)]) -> RegistryDefaults {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn wasm_fallback_no_registry_defaults_uses_builtin_table() {
        // The wasm path passes NO registry_defaults — built-in tables must drive
        // strategy / prefix / category-label for built-in types.
        let info = build_type_info(
            &[
                pm("Alice", "person"),
                pm("13800138000", "phone"),
                pm("Paris", "location"),
            ],
            None,
            &langs(&["en"]),
            None,
        );
        // person: built-in default_strategy=pseudonym, prefix=P
        assert_eq!(get(&info, "person").strategy, "pseudonym");
        assert_eq!(get(&info, "person").default_strategy, "pseudonym");
        assert_eq!(get(&info, "person").prefix, "P");
        // phone: built-in default_strategy=mask, prefix=PHON (type.upper()[:4])
        assert_eq!(get(&info, "phone").strategy, "mask");
        assert_eq!(get(&info, "phone").prefix, "PHON");
        // location: built-in DEFAULT_CATEGORY_LABEL
        assert_eq!(get(&info, "location").default_category_label, "[LOCATION]");
    }

    #[test]
    fn registry_default_strategy_wins_over_builtin_for_adapter_type() {
        // An adapter type unknown to the built-in table (`vehicle_vin`) gets its
        // declared 'realistic' strategy + prefix + label from registry_defaults,
        // instead of the built-in fallback 'remove' / type.upper()[:4] / [type].
        let info = build_type_info(
            &[pm("1HGCM", "vehicle_vin")],
            None,
            &langs(&["en"]),
            Some(&rdefs(&[(
                "vehicle_vin",
                RegistryDefault {
                    strategy: Some("realistic".to_string()),
                    prefix: Some("VIN".to_string()),
                    category_label: Some("[VIN]".to_string()),
                },
            )])),
        );
        let ti = get(&info, "vehicle_vin");
        assert_eq!(ti.strategy, "realistic", "registry strategy must win");
        assert_eq!(ti.default_strategy, "realistic");
        assert_eq!(ti.prefix, "VIN", "registry prefix must win");
        assert_eq!(ti.default_category_label, "[VIN]");
        // No built-in faker for an adapter type → None (caller overlays Custom).
        assert!(matches!(ti.faker_resolution, FakerResolution::None));
    }

    #[test]
    fn registry_default_overrides_builtin_strategy_for_known_type() {
        // The registry value wins even for a type the built-in table knows: if
        // the registry says `phone` defaults to 'remove', that beats the built-in
        // 'mask'. (Locks "registry is SSOT", not "registry only fills gaps".)
        let info = build_type_info(
            &[pm("13800138000", "phone")],
            None,
            &langs(&["zh"]),
            Some(&rdefs(&[(
                "phone",
                RegistryDefault {
                    strategy: Some("remove".to_string()),
                    prefix: None,        // absent → built-in fallback (PHON)
                    category_label: None,
                },
            )])),
        );
        let ti = get(&info, "phone");
        assert_eq!(ti.strategy, "remove");
        assert_eq!(ti.default_strategy, "remove");
        // prefix absent in registry_defaults → built-in table → type.upper()[:4].
        assert_eq!(ti.prefix, "PHON");
    }

    #[test]
    fn config_strategy_still_overrides_registry_default() {
        // User config strategy beats the registry default (the precedence the
        // Python `ec.get("strategy") or default` preserves).
        let info = build_type_info(
            &[pm("x", "vehicle_vin")],
            Some(&cfg(&[(
                "vehicle_vin",
                EntityConfig {
                    strategy: Some("remove".to_string()),
                    ..Default::default()
                },
            )])),
            &langs(&["en"]),
            Some(&rdefs(&[(
                "vehicle_vin",
                RegistryDefault {
                    strategy: Some("realistic".to_string()),
                    prefix: Some("VIN".to_string()),
                    category_label: None,
                },
            )])),
        );
        let ti = get(&info, "vehicle_vin");
        assert_eq!(ti.strategy, "remove", "config strategy wins over registry");
        // default_strategy still reflects the registry default.
        assert_eq!(ti.default_strategy, "realistic");
        // config has no prefix → registry prefix.
        assert_eq!(ti.prefix, "VIN");
    }
}
