//! The platform's name rule, held here as well as in the platform
//! (services/src/shared/naming-slug.ts).
//!
//! SPEC-NAMING §2 lets a name be almost anything, dots included, and a person
//! who signs in here directly may claim any such name. A claim that arrives
//! through a partner's delegated session is narrower: the partner proposes
//! names on its users' behalf, and a proposal has to read aloud, type back,
//! and split one way only. So a delegated claim must be lowercase letters,
//! digits and hyphens, 1 to 32 characters, starting and ending with a letter
//! or digit. Both copies of the rule are tested against one list of cases,
//! naming/slug-vectors.json.

pub const NAME_SLUG_MAX: usize = 32;

/// Accented Latin letters folded to plain ones first, so "José" becomes
/// "jose". The same table is in naming-slug.ts.
fn fold(c: char) -> Option<&'static str> {
    Some(match c {
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => "a",
        'æ' => "ae",
        'ç' => "c",
        'è' | 'é' | 'ê' | 'ë' => "e",
        'ì' | 'í' | 'î' | 'ï' => "i",
        'ñ' => "n",
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' => "o",
        'œ' => "oe",
        'ù' | 'ú' | 'û' | 'ü' => "u",
        'ý' | 'ÿ' => "y",
        'ß' => "ss",
        _ => return None,
    })
}

/// The slug a name becomes: folded, lowercased, every run of anything that is
/// not a letter or digit turned into one hyphen, trimmed, cut to 32.
pub fn name_slug(raw: &str) -> String {
    let mut out = String::new();
    let push = |d: char, out: &mut String| {
        if d.is_ascii_lowercase() || d.is_ascii_digit() {
            out.push(d);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    };
    for ch in raw.chars().flat_map(|c| c.to_lowercase()) {
        match fold(ch) {
            Some(s) => {
                for d in s.chars() {
                    push(d, &mut out);
                }
            }
            None => push(ch, &mut out),
        }
    }
    let trimmed: String = out.trim_start_matches('-').chars().take(NAME_SLUG_MAX).collect();
    trimmed.trim_end_matches('-').to_string()
}

/// Whether a string already is a name a partner may claim.
pub fn is_name_slug(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > NAME_SLUG_MAX {
        return false;
    }
    let ok = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    ok(b[0]) && ok(b[b.len() - 1]) && b.iter().all(|&c| ok(c) || c == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_shared_cases() {
        let raw = include_str!("../slug-vectors.json");
        let doc: serde_json::Value = serde_json::from_str(raw).expect("slug-vectors.json parses");
        let cases = doc["cases"].as_array().expect("cases");
        assert!(cases.len() > 10);
        for c in cases {
            let input = c["in"].as_str().unwrap();
            assert_eq!(name_slug(input), c["slug"].as_str().unwrap(), "slug of {input:?}");
            assert_eq!(is_name_slug(input), c["valid"].as_bool().unwrap(), "validity of {input:?}");
        }
    }
}
