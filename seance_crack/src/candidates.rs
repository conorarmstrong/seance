//! Candidate password generators: dictionary, mask, and rule mutations.
//!
//! Each generator is an [`Iterator`] over `String`, so the engine streams
//! candidates without materialising the whole space — a mask over eight
//! lower-case letters is 2×10¹¹ candidates and must never be collected.

/// A dictionary generator: yields each word once, in order. The words come from
/// `seance_bulk`'s wordlist (the suspect's own disk/RAM) or an external list.
pub struct Dictionary {
    words: std::vec::IntoIter<String>,
}

impl Dictionary {
    pub fn new(words: Vec<String>) -> Self {
        Self {
            words: words.into_iter(),
        }
    }
}

impl Iterator for Dictionary {
    type Item = String;
    fn next(&mut self) -> Option<String> {
        self.words.next()
    }
}

/// A character-class in a mask position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Digit,   // ?d
    Lower,   // ?l
    Upper,   // ?u
    Special, // ?s
    All,     // ?a
    Literal(char),
}

impl Class {
    fn chars(self) -> Vec<char> {
        match self {
            Class::Digit => ('0'..='9').collect(),
            Class::Lower => ('a'..='z').collect(),
            Class::Upper => ('A'..='Z').collect(),
            Class::Special => "!@#$%^&*()-_=+".chars().collect(),
            Class::All => {
                let mut v: Vec<char> = ('0'..='9').collect();
                v.extend('a'..='z');
                v.extend('A'..='Z');
                v.extend("!@#$%^&*()-_=+".chars());
                v
            }
            Class::Literal(c) => vec![c],
        }
    }
}

/// A mask generator: `?d?d?d?d` enumerates all four-digit strings, `?u?l?l?l99`
/// mixes classes and literals. This is how a real cracker targets a known
/// password *shape* (a name + year, a PIN) instead of brute-forcing blind.
pub struct Mask {
    positions: Vec<Vec<char>>,
    // Odometer state: current index into each position's char vector.
    counters: Vec<usize>,
    done: bool,
}

impl Mask {
    /// Parse a mask string. `?` introduces a class (`d l u s a`); `??` is a
    /// literal `?`; any other char is a literal. Returns `None` on a dangling or
    /// unknown `?x`.
    pub fn parse(mask: &str) -> Option<Self> {
        let mut positions: Vec<Vec<char>> = Vec::new();
        let mut chars = mask.chars().peekable();
        while let Some(c) = chars.next() {
            let class = if c == '?' {
                match chars.next()? {
                    'd' => Class::Digit,
                    'l' => Class::Lower,
                    'u' => Class::Upper,
                    's' => Class::Special,
                    'a' => Class::All,
                    '?' => Class::Literal('?'),
                    _ => return None,
                }
            } else {
                Class::Literal(c)
            };
            positions.push(class.chars());
        }
        if positions.is_empty() {
            return None;
        }
        let counters = vec![0; positions.len()];
        Some(Self {
            positions,
            counters,
            done: false,
        })
    }

    /// Total size of the space, saturating — used to warn before an infeasible run.
    pub fn space_size(&self) -> u128 {
        self.positions
            .iter()
            .map(|p| p.len() as u128)
            .try_fold(1u128, |acc, n| acc.checked_mul(n))
            .unwrap_or(u128::MAX)
    }
}

impl Iterator for Mask {
    type Item = String;
    fn next(&mut self) -> Option<String> {
        if self.done {
            return None;
        }
        // Read the current odometer position.
        let s: String = self
            .counters
            .iter()
            .zip(&self.positions)
            .map(|(&i, chars)| chars[i])
            .collect();
        // Advance the odometer from the last position.
        let mut pos = self.counters.len();
        loop {
            if pos == 0 {
                self.done = true;
                break;
            }
            pos -= 1;
            self.counters[pos] += 1;
            if self.counters[pos] < self.positions[pos].len() {
                break;
            }
            self.counters[pos] = 0;
            if pos == 0 {
                self.done = true;
            }
        }
        Some(s)
    }
}

/// Expand one base word into common mutations: as-is, capitalised, with a few
/// trailing digits/years, and simple leet. This is the "rules" layer that turns
/// a wordlist into the passwords people actually choose (`Password` → `Password1`,
/// `Password2024`, `P@ssword`).
pub fn rule_mutations(word: &str) -> Vec<String> {
    let mut out = vec![word.to_string()];
    // Capitalise first letter.
    let mut chars: Vec<char> = word.chars().collect();
    if let Some(first) = chars.first_mut() {
        let up: String = first.to_uppercase().collect();
        if !up.starts_with(*first) {
            let mut cap = up;
            cap.extend(&chars[1..]);
            out.push(cap);
        }
    }
    // Append a small set of common suffixes to every base so far.
    let bases: Vec<String> = out.clone();
    for base in &bases {
        for suffix in ["1", "12", "123", "!", "2023", "2024", "2025"] {
            out.push(format!("{base}{suffix}"));
        }
    }
    // Simple leet on the original.
    let leet: String = word
        .chars()
        .map(|c| match c.to_ascii_lowercase() {
            'a' => '@',
            'e' => '3',
            'i' => '1',
            'o' => '0',
            's' => '$',
            _ => c,
        })
        .collect();
    if leet != word {
        out.push(leet);
    }
    // Deduplicate while preserving order.
    let mut seen = std::collections::HashSet::new();
    out.retain(|w| seen.insert(w.clone()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dictionary_yields_each_word_in_order() {
        let d = Dictionary::new(vec!["alpha".into(), "beta".into()]);
        assert_eq!(d.collect::<Vec<_>>(), vec!["alpha", "beta"]);
    }

    #[test]
    fn mask_enumerates_all_two_digit_pins() {
        let m = Mask::parse("?d?d").unwrap();
        assert_eq!(m.space_size(), 100);
        let all: Vec<String> = m.collect();
        assert_eq!(all.len(), 100);
        assert_eq!(all[0], "00");
        assert_eq!(all[99], "99");
        assert!(all.contains(&"42".to_string()));
    }

    #[test]
    fn mask_mixes_classes_and_literals() {
        // ?u then literal "9": A9, B9, ... Z9.
        let m = Mask::parse("?u9").unwrap();
        let all: Vec<String> = m.collect();
        assert_eq!(all.len(), 26);
        assert_eq!(all[0], "A9");
        assert_eq!(all[25], "Z9");
    }

    #[test]
    fn mask_literal_question_mark() {
        let m = Mask::parse("??d").unwrap(); // literal '?' then digit? No: ?? = literal ?
                                             // "??" -> literal '?', then 'd' literal.
        let all: Vec<String> = m.collect();
        assert_eq!(all, vec!["?d"]);
    }

    #[test]
    fn mask_rejects_bad_input() {
        assert!(Mask::parse("?z").is_none()); // unknown class
        assert!(Mask::parse("?").is_none()); // dangling
        assert!(Mask::parse("").is_none()); // empty
    }

    #[test]
    fn mask_space_size_saturates() {
        // Eight ?a positions is huge but must not overflow/panic.
        let m = Mask::parse("?a?a?a?a?a?a?a?a").unwrap();
        assert!(m.space_size() > 1_000_000_000_000);
    }

    #[test]
    fn rule_mutations_cover_common_password_shapes() {
        let muts = rule_mutations("password");
        assert!(muts.contains(&"password".to_string()));
        assert!(muts.contains(&"Password".to_string()));
        assert!(muts.contains(&"password1".to_string()));
        assert!(muts.contains(&"Password2024".to_string()));
        assert!(muts.contains(&"p@$$w0rd".to_string()));
        // No duplicates.
        let mut sorted = muts.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), muts.len());
    }

    #[test]
    fn rule_mutations_on_all_digits_word_has_no_capitalisation_dupe() {
        // A word with no alpha first char should not add a bogus capitalised dupe.
        let muts = rule_mutations("1234");
        assert!(muts.contains(&"1234".to_string()));
        assert!(muts.contains(&"1234!".to_string()));
    }
}
