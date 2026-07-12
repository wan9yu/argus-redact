//! Embedded per-language pattern data (SSOT), parsed once.
use std::collections::HashMap;
use std::sync::OnceLock;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PatternData {
    pub type_: String,
    #[serde(default)]
    pub label: String,
    pub pattern: String,
    #[serde(default)]
    pub validator: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub check_context: bool,
    #[serde(default)]
    pub description: String,
    /// Load this pattern regardless of the requested/detected language. Used for
    /// CN structured numeric identifiers (phone/ID/bank) whose digits are the
    /// same in any surrounding script, so they must be detectable in en/ja/ko/…
    /// text too — not only when zh is requested. Default false (language-gated).
    #[serde(default)]
    pub language_neutral: bool,
}

macro_rules! lang_ron {
    ($lang:literal) => { ($lang, include_str!(concat!("../data/", $lang, ".ron"))) };
}

static RAW: &[(&str, &str)] = &[
    lang_ron!("shared"), lang_ron!("zh"), lang_ron!("en"), lang_ron!("ja"),
    lang_ron!("ko"), lang_ron!("de"), lang_ron!("uk"), lang_ron!("in"), lang_ron!("br"),
];

static PARSED: OnceLock<HashMap<String, Vec<PatternData>>> = OnceLock::new();

fn parsed() -> &'static HashMap<String, Vec<PatternData>> {
    PARSED.get_or_init(|| {
        let mut m = HashMap::new();
        for (lang, raw) in RAW {
            let pats: Vec<PatternData> = ron::from_str(raw)
                .unwrap_or_else(|e| panic!("RON parse error in {lang}.ron: {e}"));
            m.insert(lang.to_string(), pats);
        }
        m
    })
}

/// Built-in patterns for a language code (empty slice if unknown).
pub fn builtin_patterns(lang: &str) -> &'static [PatternData] {
    parsed().get(lang).map(|v| v.as_slice()).unwrap_or(&[])
}

/// All embedded language codes in deterministic file order (incl. "shared").
pub(crate) fn all_langs() -> impl Iterator<Item = &'static str> {
    RAW.iter().map(|(lang, _)| *lang)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_parses_and_has_email() {
        let pats = builtin_patterns("shared");
        assert!(pats.iter().any(|p| p.type_ == "email" && p.validator.as_deref() == Some("email")));
    }
    #[test]
    fn all_langs_parse() {
        for lang in ["shared","zh","en","ja","ko","de","uk","in","br"] {
            let _ = builtin_patterns(lang); // panics on RON error via parsed()
        }
    }
}
