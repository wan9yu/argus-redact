//! Script-range language detection (port of pure/lang_detect.py).
const LATIN_LETTER_THRESHOLD: usize = 3;

pub fn detect_languages(text: &str) -> Vec<String> {
    if text.is_empty() {
        return vec!["zh".into()];
    }
    if text.is_ascii() {
        let mut letters = 0;
        for ch in text.chars() {
            if ch.is_ascii_alphabetic() {
                letters += 1;
                if letters >= LATIN_LETTER_THRESHOLD {
                    return vec!["en".into()];
                }
            }
        }
        return vec!["zh".into()];
    }
    let (mut has_ja, mut has_hangul, mut has_cjk, mut latin) = (false, false, false, 0usize);
    for ch in text.chars() {
        let cp = ch as u32;
        if (0x3040..=0x30FF).contains(&cp) {
            has_ja = true;
        } else if (0xAC00..=0xD7A3).contains(&cp) {
            has_hangul = true;
        } else if (0x4E00..=0x9FFF).contains(&cp) {
            has_cjk = true;
        } else if ch.is_ascii_alphabetic() {
            latin += 1;
        }
    }
    let mut langs = Vec::new();
    if has_ja { langs.push("ja".into()); }
    if has_hangul { langs.push("ko".into()); }
    if has_cjk && !has_ja && !has_hangul { langs.push("zh".into()); }
    if latin >= LATIN_LETTER_THRESHOLD { langs.push("en".into()); }
    if langs.is_empty() { vec!["zh".into()] } else { langs }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scripts() {
        assert_eq!(detect_languages(""), vec!["zh"]);
        assert_eq!(detect_languages("hello world"), vec!["en"]);
        assert_eq!(detect_languages("ab"), vec!["zh"]);             // <3 latin
        assert_eq!(detect_languages("中文测试"), vec!["zh"]);
        assert_eq!(detect_languages("日本語"), vec!["zh"]);         // all kanji → zh
        assert_eq!(detect_languages("こんにちは"), vec!["ja"]);     // hiragana → ja
        assert_eq!(detect_languages("カタカナ"), vec!["ja"]);       // katakana → ja
        assert_eq!(detect_languages("한국어"), vec!["ko"]);
        assert_eq!(detect_languages("中文 and english"), vec!["zh", "en"]);
    }
}
