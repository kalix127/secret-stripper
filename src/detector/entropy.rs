use std::collections::HashMap;

pub fn shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in data.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    let len = data.chars().count() as f64;
    freq.values().fold(0.0f64, |ent, &count| {
        let p = count as f64 / len;
        if p > 0.0 {
            ent - p * p.log2()
        } else {
            ent
        }
    })
}

pub fn find_high_entropy_strings(
    text: &str,
    min_len: usize,
    max_len: usize,
    threshold: f64,
) -> Vec<(String, f64)> {
    fn is_tok(c: char) -> bool {
        c.is_alphanumeric() || c == '_' || c == '-' || c == '.'
    }

    let mut results = Vec::new();
    let mut it = text.char_indices().peekable();
    while let Some(&(start, c)) = it.peek() {
        if !is_tok(c) {
            it.next();
            continue;
        }
        let mut end = start;
        while let Some(&(idx, ch)) = it.peek() {
            if !is_tok(ch) {
                break;
            }
            end = idx + ch.len_utf8();
            it.next();
        }
        // token_len stays a *byte* length (String::len was bytes) so the
        // min/max thresholds behave exactly as before for non-ASCII tokens.
        let token = &text[start..end];
        let token_len = token.len();
        if token_len >= min_len && token_len <= max_len {
            let ent = shannon_entropy(token);
            if ent >= threshold {
                results.push((token.to_string(), ent));
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_shannon_entropy_low() {
        let e = shannon_entropy("aaaaaaa");
        assert!(e < 0.5);
    }

    #[test]
    fn test_shannon_entropy_high() {
        let e = shannon_entropy("aB3$kL9#xQ2!zP7&vR5");
        assert!(e > 3.0);
    }

    #[test]
    fn test_shannon_entropy_known() {
        let e = shannon_entropy("abcdefghijklmnopqrstuvwxyz");
        assert!((e - 4.7).abs() < 0.3);
    }

    #[test]
    fn test_find_high_entropy_strings_short() {
        let results = find_high_entropy_strings("no secrets here", 10, 100, 3.5);
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_high_entropy_strings_respects_min_len() {
        let results = find_high_entropy_strings("short", 10, 100, 1.0);
        assert!(results.is_empty());
    }
}
