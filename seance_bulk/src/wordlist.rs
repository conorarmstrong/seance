//! Build a password-attack wordlist from the evidence.
//!
//! bulk_extractor's `scan_wordlist` harvests candidate words from an image. On
//! its own it is modest; as the *input to the password cracker* (`seance_crack`)
//! it is what makes a targeted dictionary attack tractable — a user's password is
//! usually already somewhere on their own disk or in their own RAM. This module
//! extracts printable tokens from both ASCII and UTF-16LE regions (Windows stores
//! most strings as UTF-16LE), deduplicates them, and ranks by frequency so the
//! most-seen candidates are tried first.

use std::collections::HashMap;

/// One wordlist entry: the word and how often it appeared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    pub text: String,
    pub count: u32,
}

/// Configuration for wordlist extraction.
#[derive(Debug, Clone, Copy)]
pub struct WordlistConfig {
    /// Minimum token length to keep (short tokens are noise).
    pub min_len: usize,
    /// Maximum token length to keep (very long runs are rarely passwords).
    pub max_len: usize,
}

impl Default for WordlistConfig {
    fn default() -> Self {
        Self {
            min_len: 4,
            max_len: 64,
        }
    }
}

/// Whether a byte is part of a candidate word: printable ASCII that plausibly
/// appears in a password (letters, digits, common punctuation), excluding
/// whitespace which is the token separator.
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_graphic()
}

/// Extract ASCII tokens from a buffer.
fn ascii_tokens(buf: &[u8], cfg: &WordlistConfig, out: &mut HashMap<String, u32>) {
    let mut start = None;
    for (i, &b) in buf.iter().enumerate() {
        if is_word_byte(b) {
            start.get_or_insert(i);
        } else if let Some(s) = start.take() {
            add_token(&buf[s..i], cfg, out);
        }
    }
    if let Some(s) = start {
        add_token(&buf[s..], cfg, out);
    }
}

/// Extract UTF-16LE tokens: runs of `<ascii> 00 <ascii> 00 …`. This is how
/// Windows holds most strings, so an ASCII-only scan misses them.
fn utf16le_tokens(buf: &[u8], cfg: &WordlistConfig, out: &mut HashMap<String, u32>) {
    let mut current = Vec::new();
    let mut i = 0;
    while i + 1 < buf.len() {
        let (lo, hi) = (buf[i], buf[i + 1]);
        if hi == 0 && is_word_byte(lo) {
            current.push(lo);
            i += 2;
        } else {
            if !current.is_empty() {
                add_token(&current, cfg, out);
                current.clear();
            }
            i += 1;
        }
    }
    if !current.is_empty() {
        add_token(&current, cfg, out);
    }
}

fn add_token(bytes: &[u8], cfg: &WordlistConfig, out: &mut HashMap<String, u32>) {
    if bytes.len() < cfg.min_len || bytes.len() > cfg.max_len {
        return;
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        *out.entry(s.to_string()).or_insert(0) += 1;
    }
}

/// Build a frequency-ranked, deduplicated wordlist from a buffer, scanning both
/// ASCII and UTF-16LE. Output is sorted by descending count, then the word, so
/// it is deterministic.
pub fn build_wordlist(buf: &[u8], cfg: &WordlistConfig) -> Vec<Word> {
    let mut counts = HashMap::new();
    ascii_tokens(buf, cfg, &mut counts);
    utf16le_tokens(buf, cfg, &mut counts);
    let mut words: Vec<Word> = counts
        .into_iter()
        .map(|(text, count)| Word { text, count })
        .collect();
    words.sort_by(|a, b| b.count.cmp(&a.count).then(a.text.cmp(&b.text)));
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ascii_words_over_min_length() {
        let buf = b"the quick hunter2 \x00\x01 password swordfish a bb";
        let words = build_wordlist(buf, &WordlistConfig::default());
        let texts: Vec<&str> = words.iter().map(|w| w.text.as_str()).collect();
        assert!(texts.contains(&"hunter2"));
        assert!(texts.contains(&"password"));
        assert!(texts.contains(&"swordfish"));
        // "a" and "bb" are below min_len 4.
        assert!(!texts.contains(&"a"));
        assert!(!texts.contains(&"bb"));
    }

    #[test]
    fn frequency_ranking_puts_common_words_first() {
        let buf = b"secret secret secret rare filler filler";
        let words = build_wordlist(buf, &WordlistConfig::default());
        assert_eq!(words[0].text, "secret");
        assert_eq!(words[0].count, 3);
        // "filler" (2) before "rare" (1).
        let filler = words.iter().find(|w| w.text == "filler").unwrap();
        let rare = words.iter().find(|w| w.text == "rare").unwrap();
        assert!(filler.count > rare.count);
    }

    #[test]
    fn extracts_utf16le_windows_strings() {
        // "P\0a\0s\0s\0w\0d\0" — a UTF-16LE token an ASCII scan would miss.
        let mut buf = vec![0u8; 4];
        for c in b"Passwd1" {
            buf.push(*c);
            buf.push(0);
        }
        buf.extend_from_slice(&[0xff, 0xfe]);
        let words = build_wordlist(&buf, &WordlistConfig::default());
        assert!(words.iter().any(|w| w.text == "Passwd1"));
    }

    #[test]
    fn respects_max_len() {
        let long = "x".repeat(200);
        let buf = format!("short {long} end");
        let cfg = WordlistConfig {
            min_len: 4,
            max_len: 64,
        };
        let words = build_wordlist(buf.as_bytes(), &cfg);
        assert!(words.iter().all(|w| w.text.len() <= 64));
        assert!(words.iter().any(|w| w.text == "short"));
    }

    #[test]
    fn deterministic_and_deduplicated() {
        let buf = b"alpha beta alpha beta gamma";
        let a = build_wordlist(buf, &WordlistConfig::default());
        let b = build_wordlist(buf, &WordlistConfig::default());
        assert_eq!(a, b, "must be deterministic");
        // Each word appears once.
        assert_eq!(a.iter().filter(|w| w.text == "alpha").count(), 1);
    }

    #[test]
    fn empty_buffer_yields_empty_list() {
        assert!(build_wordlist(b"", &WordlistConfig::default()).is_empty());
    }
}
