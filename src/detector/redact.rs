use super::patterns::SecretPattern;

pub fn redact_text(
    text: &str,
    patterns: &[&SecretPattern],
    entropy_tokens: &[&str],
    deep_spans: &[(usize, usize)],
    pattern: &str,
) -> String {
    redact_text_with_allowlist(text, patterns, entropy_tokens, deep_spans, &[], pattern)
}

/// Same as `redact_text` but drops any span fully covered by an allowlist
/// regex before merging, so documented-safe values are not redacted.
///
/// Pattern-taking wrapper: re-runs each pattern to derive its spans. The
/// trigger/preview/corpus paths instead reuse the spans `Detector::scan`
/// already computed and call `redact_with_spans` directly.
pub fn redact_text_with_allowlist(
    text: &str,
    patterns: &[&SecretPattern],
    entropy_tokens: &[&str],
    deep_spans: &[(usize, usize)],
    allowlist: &[regex::Regex],
    pattern: &str,
) -> String {
    let mut pattern_spans: Vec<(usize, usize)> = Vec::new();
    for p in patterns {
        for m in p.regex.find_iter(text) {
            pattern_spans.push((m.start(), m.end()));
        }
    }
    redact_with_spans(
        text,
        &pattern_spans,
        entropy_tokens,
        deep_spans,
        allowlist,
        pattern,
    )
}

/// Redaction core. `pattern_spans` are already-located secret byte ranges in
/// `text` (from `Detector::scan`); no regex is re-run here.
pub fn redact_with_spans(
    text: &str,
    pattern_spans: &[(usize, usize)],
    entropy_tokens: &[&str],
    deep_spans: &[(usize, usize)],
    allowlist: &[regex::Regex],
    pattern: &str,
) -> String {
    let mut spans: Vec<(usize, usize)> = pattern_spans.to_vec();

    // Entropy hits arrive as substrings, not regex objects. We need every
    // byte span where the literal token appears so the redactor merges them
    // with the regex hits. Using `str::match_indices` skips the per-token
    // regex compile and avoids regex-engine overhead for what is just a
    // literal substring search.
    for token in entropy_tokens {
        if token.is_empty() {
            continue;
        }
        for (s, t) in text.match_indices(token) {
            spans.push((s, s + t.len()));
        }
    }

    // Deep-scan findings that pinpointed a token (BIP39 run, vendor-host
    // token) arrive as absolute byte ranges. Guard against a stale/out-of-
    // range span before merging it with the rest.
    for &(s, e) in deep_spans {
        if s < e && e <= text.len() {
            spans.push((s, e));
        }
    }

    if !allowlist.is_empty() {
        spans.retain(|&(s, e)| {
            !allowlist
                .iter()
                .any(|re| re.find_iter(text).any(|m| m.start() <= s && e <= m.end()))
        });
    }

    if spans.is_empty() {
        return text.to_string();
    }

    spans.sort_by_key(|&(s, _)| s);
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (s, e) in spans {
        match merged.last_mut() {
            Some(last) if s <= last.1 => {
                if e > last.1 {
                    last.1 = e;
                }
            }
            _ => merged.push((s, e)),
        }
    }

    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (s, e) in merged {
        out.push_str(&text[cursor..s]);
        // Preserve line structure: if the span straddles newlines (a token a
        // human soft-wrapped, or a multi-line block pattern), emit one marker
        // per newline-free fragment and copy the \n/\r runs verbatim, so a
        // 2-line secret redacts to "[R]\n[R]" instead of collapsing the lines.
        let span = &text[s..e];
        let sb = span.as_bytes();
        let mut k = 0;
        let mut frag_start = 0;
        while k < sb.len() {
            if sb[k] == b'\n' || sb[k] == b'\r' {
                if k > frag_start {
                    out.push_str(pattern);
                }
                let run = k;
                while k < sb.len() && (sb[k] == b'\n' || sb[k] == b'\r') {
                    k += 1;
                }
                out.push_str(&span[run..k]);
                frag_start = k;
            } else {
                k += 1;
            }
        }
        if k > frag_start {
            out.push_str(pattern);
        }
        cursor = e;
    }
    out.push_str(&text[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::patterns;
    use crate::detector::Severity;

    fn pat(name: &'static str, regex: &str) -> patterns::SecretPattern {
        patterns::SecretPattern {
            name,
            category: "test",
            severity: Severity::High,
            regex: regex::Regex::new(regex).unwrap(),
        }
    }

    #[test]
    fn redact_full_replacement() {
        let p = pat("test", "secret");
        let result = redact_text("my secret here", &[&p], &[], &[], "[R]");
        assert_eq!(result, "my [R] here");
    }

    #[test]
    fn redact_no_match_returns_original() {
        let p = pat("test", "secret");
        let result = redact_text("nothing to see here", &[&p], &[], &[], "*");
        assert_eq!(result, "nothing to see here");
    }

    #[test]
    fn redact_aws_key_single_marker() {
        let pats = patterns::all_patterns();
        let aws = pats.iter().find(|p| p.name == "AWS Access Key ID").unwrap();
        let result = redact_text(
            "prefix AKIAIOSFODNN7EXAMPLE suffix",
            &[aws],
            &[],
            &[],
            "[REDACTED]",
        );
        assert_eq!(result, "prefix [REDACTED] suffix");
        assert!(!result.contains("AKIA"));
        assert_eq!(result.matches("[REDACTED]").count(), 1);
    }

    #[test]
    fn redact_two_distinct_secrets_two_markers() {
        let pats = patterns::all_patterns();
        let aws = pats.iter().find(|p| p.name == "AWS Access Key ID").unwrap();
        let email = pats.iter().find(|p| p.name == "Email Address").unwrap();
        let input = "email user@example.com and AKIAIOSFODNN7EXAMPLE";
        let result = redact_text(input, &[aws, email], &[], &[], "[REDACTED]");
        assert_eq!(result, "email [REDACTED] and [REDACTED]");
        assert_eq!(result.matches("[REDACTED]").count(), 2);
    }

    #[test]
    fn redact_overlapping_patterns_merge_to_single_marker() {
        // Two patterns whose matches overlap on the same span. The merge logic
        // must collapse them so the output has exactly one marker, never a
        // cascade-redacted [REDACTED].
        let p1 = pat("outer", "abcdef");
        let p2 = pat("inner", "cde");
        let result = redact_text("xx abcdef yy", &[&p1, &p2], &[], &[], "[R]");
        assert_eq!(result, "xx [R] yy");
        assert_eq!(result.matches("[R]").count(), 1);
    }

    #[test]
    fn redact_adjacent_patterns_merge() {
        let p1 = pat("a", "foo");
        let p2 = pat("b", "bar");
        let result = redact_text("foobar tail", &[&p1, &p2], &[], &[], "[R]");
        // foo and bar share a boundary (positions 0..3 and 3..6). Adjacent
        // spans are merged into one marker.
        assert_eq!(result, "[R] tail");
    }

    #[test]
    fn redact_entropy_token_substring() {
        let token = "xyzaB3kL9xQ2zP7vR5";
        let input = format!("token={} end", token);
        let result = redact_text(&input, &[], &[token], &[], "[R]");
        assert_eq!(result, "token=[R] end");
    }

    #[test]
    fn redact_entropy_token_overlap_with_pattern() {
        let pats = patterns::all_patterns();
        let aws = pats.iter().find(|p| p.name == "AWS Access Key ID").unwrap();
        let key = "AKIAIOSFODNN7EXAMPLE";
        let result = redact_text(key, &[aws], &[key], &[], "[REDACTED]");
        assert_eq!(result, "[REDACTED]");
        assert_eq!(result.matches("[REDACTED]").count(), 1);
    }

    #[test]
    fn redact_full_private_key_block_line_preserving() {
        let pats = patterns::all_patterns();
        let key_pats: Vec<&patterns::SecretPattern> = pats
            .iter()
            .filter(|p| {
                p.name == "Private Key Block"
                    || p.name == "Private Key (RSA/DSA/EC)"
                    || p.name == "SSH Private Key inline"
                    || p.name == "PGP Private Key Block"
            })
            .collect();
        let input = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Oc8ikxqR5q8vNnC7VzLhJ0=\n-----END RSA PRIVATE KEY-----";
        let result = redact_text(input, &key_pats, &[], &[], "[REDACTED]");
        // The whole block is redacted but its 3 lines are kept distinct.
        assert_eq!(result, "[REDACTED]\n[REDACTED]\n[REDACTED]");
        assert!(!result.contains("BEGIN"));
        assert!(!result.contains("END"));
        assert!(!result.contains("MIIEp"));
    }

    #[test]
    fn redact_pgp_block_line_preserving() {
        let pats = patterns::all_patterns();
        let key_pats: Vec<&patterns::SecretPattern> = pats
            .iter()
            .filter(|p| p.name == "Private Key Block" || p.name == "PGP Private Key Block")
            .collect();
        let input = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBGTbody==\n-----END PGP PRIVATE KEY BLOCK-----";
        let result = redact_text(input, &key_pats, &[], &[], "[REDACTED]");
        assert_eq!(result, "[REDACTED]\n[REDACTED]\n[REDACTED]");
        assert!(!result.contains("lQOYBG"));
    }

    #[test]
    fn redact_softwrap_span_keeps_the_newline() {
        // A deep-style span covering a token split across one newline must
        // redact each line-fragment and keep the line break.
        let input = "key AKIAIOSFOD\nNN7EXAMPLE end";
        let s = input.find("AKIA").unwrap();
        let e = input.find(" end").unwrap();
        let result = redact_text(input, &[], &[], &[(s, e)], "[R]");
        assert_eq!(result, "key [R]\n[R] end");
    }

    #[test]
    fn redact_truncated_private_key_falls_back_to_begin_line() {
        let pats = patterns::all_patterns();
        let key_pats: Vec<&patterns::SecretPattern> = pats
            .iter()
            .filter(|p| p.name == "Private Key Block" || p.name == "Private Key (RSA/DSA/EC)")
            .collect();
        let input = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ";
        let result = redact_text(input, &key_pats, &[], &[], "[REDACTED]");
        // Block regex won't match (no END), so the BEGIN-line fallback fires
        // and at least the header gets redacted.
        assert!(result.starts_with("[REDACTED]"));
        assert!(!result.contains("BEGIN"));
    }

    #[test]
    fn redact_multiple_passes_no_cascade() {
        // Reproduces the historical bug: a single AWS key produced 20 copies
        // of [REDACTED]. Lock the count to exactly one.
        let pats = patterns::all_patterns();
        let aws = pats.iter().find(|p| p.name == "AWS Access Key ID").unwrap();
        let result = redact_text("AKIAIOSFODNN7EXAMPLE", &[aws], &[], &[], "[REDACTED]");
        assert_eq!(result, "[REDACTED]");
    }

    #[test]
    fn redact_deep_span_removes_run() {
        let input = "seed: legal winner thank year done";
        // Byte range covering "legal winner thank year".
        let start = input.find("legal").unwrap();
        let end = input.find(" done").unwrap();
        let result = redact_text(input, &[], &[], &[(start, end)], "[R]");
        assert_eq!(result, "seed: [R] done");
    }

    #[test]
    fn redact_deep_span_out_of_range_ignored() {
        let input = "short";
        let result = redact_text(input, &[], &[], &[(2, 999)], "[R]");
        assert_eq!(result, "short");
    }
}
