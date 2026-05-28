use crate::config::RedactStyle;

use super::patterns::SecretPattern;

const ENTROPY_NAME: &str = "High Entropy";

pub fn redact_text(
    text: &str,
    patterns: &[&SecretPattern],
    entropy_tokens: &[&str],
    deep_spans: &[(usize, usize, &str)],
    style: RedactStyle,
    marker: &str,
) -> String {
    redact_text_with_allowlist(
        text,
        patterns,
        entropy_tokens,
        deep_spans,
        &[],
        style,
        marker,
    )
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
    deep_spans: &[(usize, usize, &str)],
    allowlist: &[regex::Regex],
    style: RedactStyle,
    marker: &str,
) -> String {
    let mut pattern_spans: Vec<(usize, usize, &str)> = Vec::new();
    for p in patterns {
        for m in p.regex.find_iter(text) {
            pattern_spans.push((m.start(), m.end(), p.name));
        }
    }
    redact_with_spans(
        text,
        &pattern_spans,
        entropy_tokens,
        deep_spans,
        allowlist,
        style,
        marker,
    )
}

/// Redaction core. `pattern_spans` are already-located secret byte ranges in
/// `text` (from `Detector::scan`); no regex is re-run here. The third tuple
/// element on each span is the originating pattern's name, consumed only when
/// `style == RedactStyle::Typed`.
pub fn redact_with_spans(
    text: &str,
    pattern_spans: &[(usize, usize, &str)],
    entropy_tokens: &[&str],
    deep_spans: &[(usize, usize, &str)],
    allowlist: &[regex::Regex],
    style: RedactStyle,
    marker: &str,
) -> String {
    let mut spans: Vec<(usize, usize, &str)> = pattern_spans.to_vec();

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
            spans.push((s, s + t.len(), ENTROPY_NAME));
        }
    }

    // Deep-scan findings that pinpointed a token (BIP39 run, vendor-host
    // token) arrive as absolute byte ranges. Guard against a stale/out-of-
    // range span before merging it with the rest.
    for &(s, e, name) in deep_spans {
        if s < e && e <= text.len() {
            spans.push((s, e, name));
        }
    }

    if !allowlist.is_empty() {
        spans.retain(|&(s, e, _)| {
            !allowlist
                .iter()
                .any(|re| re.find_iter(text).any(|m| m.start() <= s && e <= m.end()))
        });
    }

    if spans.is_empty() {
        return text.to_string();
    }

    spans.sort_by_key(|&(s, _, _)| s);
    let mut merged: Vec<(usize, usize, &str)> = Vec::with_capacity(spans.len());
    for (s, e, name) in spans {
        match merged.last_mut() {
            // Typed mode keeps spans with different names distinct so each
            // gets its own marker; Marker / Drop merge unconditionally as
            // before.
            Some(last) if s <= last.1 && (style != RedactStyle::Typed || last.2 == name) => {
                if e > last.1 {
                    last.1 = e;
                }
            }
            _ => merged.push((s, e, name)),
        }
    }

    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (s, e, name) in merged {
        out.push_str(&text[cursor..s]);
        let emit = match style {
            RedactStyle::Marker => marker.to_string(),
            RedactStyle::Drop => String::new(),
            RedactStyle::Typed => name_to_tag(name),
        };
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
                    out.push_str(&emit);
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
            out.push_str(&emit);
        }
        cursor = e;
    }
    out.push_str(&text[cursor..]);
    out
}

/// Map a pattern name to its typed-marker form. Uppercases the name and
/// collapses any run of non-alphanumeric characters into a single underscore,
/// then wraps in brackets. `"AWS Access Key ID"` -> `"[AWS_ACCESS_KEY_ID]"`.
/// Empty / all-punctuation names fall back to `"[SECRET]"` so a malformed
/// input still produces a readable marker.
pub fn name_to_tag(name: &str) -> String {
    let mut buf = String::with_capacity(name.len() + 2);
    let mut last_was_underscore = true;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            for u in ch.to_uppercase() {
                buf.push(u);
            }
            last_was_underscore = false;
        } else if !last_was_underscore {
            buf.push('_');
            last_was_underscore = true;
        }
    }
    while buf.ends_with('_') {
        buf.pop();
    }
    if buf.is_empty() {
        return "[SECRET]".to_string();
    }
    format!("[{}]", buf)
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
        let result = redact_text(
            "my secret here",
            &[&p],
            &[],
            &[],
            RedactStyle::Marker,
            "[R]",
        );
        assert_eq!(result, "my [R] here");
    }

    #[test]
    fn redact_no_match_returns_original() {
        let p = pat("test", "secret");
        let result = redact_text(
            "nothing to see here",
            &[&p],
            &[],
            &[],
            RedactStyle::Marker,
            "*",
        );
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
            RedactStyle::Marker,
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
        let result = redact_text(
            input,
            &[aws, email],
            &[],
            &[],
            RedactStyle::Marker,
            "[REDACTED]",
        );
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
        let result = redact_text(
            "xx abcdef yy",
            &[&p1, &p2],
            &[],
            &[],
            RedactStyle::Marker,
            "[R]",
        );
        assert_eq!(result, "xx [R] yy");
        assert_eq!(result.matches("[R]").count(), 1);
    }

    #[test]
    fn redact_adjacent_patterns_merge() {
        let p1 = pat("a", "foo");
        let p2 = pat("b", "bar");
        let result = redact_text(
            "foobar tail",
            &[&p1, &p2],
            &[],
            &[],
            RedactStyle::Marker,
            "[R]",
        );
        // foo and bar share a boundary (positions 0..3 and 3..6). Adjacent
        // spans are merged into one marker.
        assert_eq!(result, "[R] tail");
    }

    #[test]
    fn redact_entropy_token_substring() {
        let token = "xyzaB3kL9xQ2zP7vR5";
        let input = format!("token={} end", token);
        let result = redact_text(&input, &[], &[token], &[], RedactStyle::Marker, "[R]");
        assert_eq!(result, "token=[R] end");
    }

    #[test]
    fn redact_entropy_token_overlap_with_pattern() {
        let pats = patterns::all_patterns();
        let aws = pats.iter().find(|p| p.name == "AWS Access Key ID").unwrap();
        let key = "AKIAIOSFODNN7EXAMPLE";
        let result = redact_text(key, &[aws], &[key], &[], RedactStyle::Marker, "[REDACTED]");
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
        let result = redact_text(
            input,
            &key_pats,
            &[],
            &[],
            RedactStyle::Marker,
            "[REDACTED]",
        );
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
        let result = redact_text(
            input,
            &key_pats,
            &[],
            &[],
            RedactStyle::Marker,
            "[REDACTED]",
        );
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
        let result = redact_text(
            input,
            &[],
            &[],
            &[(s, e, "test")],
            RedactStyle::Marker,
            "[R]",
        );
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
        let result = redact_text(
            input,
            &key_pats,
            &[],
            &[],
            RedactStyle::Marker,
            "[REDACTED]",
        );
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
        let result = redact_text(
            "AKIAIOSFODNN7EXAMPLE",
            &[aws],
            &[],
            &[],
            RedactStyle::Marker,
            "[REDACTED]",
        );
        assert_eq!(result, "[REDACTED]");
    }

    #[test]
    fn redact_deep_span_removes_run() {
        let input = "seed: legal winner thank year done";
        // Byte range covering "legal winner thank year".
        let start = input.find("legal").unwrap();
        let end = input.find(" done").unwrap();
        let result = redact_text(
            input,
            &[],
            &[],
            &[(start, end, "BIP39 Mnemonic")],
            RedactStyle::Marker,
            "[R]",
        );
        assert_eq!(result, "seed: [R] done");
    }

    #[test]
    fn redact_deep_span_out_of_range_ignored() {
        let input = "short";
        let result = redact_text(
            input,
            &[],
            &[],
            &[(2, 999, "BIP39 Mnemonic")],
            RedactStyle::Marker,
            "[R]",
        );
        assert_eq!(result, "short");
    }

    #[test]
    fn drop_style_removes_marker() {
        let pats = patterns::all_patterns();
        let aws = pats.iter().find(|p| p.name == "AWS Access Key ID").unwrap();
        let result = redact_text(
            "prefix AKIAIOSFODNN7EXAMPLE suffix",
            &[aws],
            &[],
            &[],
            RedactStyle::Drop,
            "[REDACTED]",
        );
        assert_eq!(result, "prefix  suffix");
        assert!(!result.contains("AKIA"));
        assert!(!result.contains("REDACTED"));
    }

    #[test]
    fn typed_style_uses_pattern_name() {
        let pats = patterns::all_patterns();
        let aws = pats.iter().find(|p| p.name == "AWS Access Key ID").unwrap();
        let result = redact_text(
            "key AKIAIOSFODNN7EXAMPLE end",
            &[aws],
            &[],
            &[],
            RedactStyle::Typed,
            "",
        );
        assert_eq!(result, "key [AWS_ACCESS_KEY_ID] end");
    }

    #[test]
    fn typed_style_no_merge_different_names() {
        let p1 = pat("Email Address", "EMAIL");
        let p2 = pat("AWS Access Key ID", "AWS");
        let result = redact_text(
            "EMAILAWS tail",
            &[&p1, &p2],
            &[],
            &[],
            RedactStyle::Typed,
            "",
        );
        // Adjacent spans of different names must not merge under Typed.
        assert_eq!(result, "[EMAIL_ADDRESS][AWS_ACCESS_KEY_ID] tail");
    }

    #[test]
    fn typed_style_merges_same_name() {
        // Two patterns with the same name whose hits overlap should still
        // collapse to one marker - the historical no-cascade invariant.
        let p1 = pat("Email Address", "abc");
        let p2 = pat("Email Address", "bc");
        let result = redact_text("xx abc yy", &[&p1, &p2], &[], &[], RedactStyle::Typed, "");
        assert_eq!(result, "xx [EMAIL_ADDRESS] yy");
        assert_eq!(result.matches("[EMAIL_ADDRESS]").count(), 1);
    }

    #[test]
    fn typed_style_entropy_marker() {
        let token = "xyzaB3kL9xQ2zP7vR5";
        let input = format!("t={} end", token);
        let result = redact_text(&input, &[], &[token], &[], RedactStyle::Typed, "");
        assert_eq!(result, "t=[HIGH_ENTROPY] end");
    }

    #[test]
    fn drop_style_round_trip_zero_findings() {
        // After Drop redaction the output must scan cleanly. Locks the
        // round-trip invariant the corpus harness enforces for Marker mode.
        let cfg = crate::config::Config::default();
        let det = crate::detector::Detector::from_config(&cfg);
        let input = "key AKIAIOSFODNN7EXAMPLE end";
        let r = det.scan(input);
        let entropy: Vec<&str> = r
            .high_entropy_tokens
            .iter()
            .map(|(t, _)| t.as_str())
            .collect();
        let mut deep: Vec<(usize, usize, &str)> = r
            .deep_findings
            .iter()
            .filter_map(|f| f.span.map(|(s, e)| (s, e, f.finding_type)))
            .collect();
        deep.extend(r.extra_spans.iter().copied());
        let out = redact_with_spans(
            input,
            &r.matched_spans,
            &entropy,
            &deep,
            det.allowlist(),
            RedactStyle::Drop,
            "",
        );
        assert_eq!(out, "key  end");
        let r2 = det.scan(&out);
        assert!(!r2.has_secrets);
    }

    #[test]
    fn typed_style_marker_does_not_self_match() {
        // The typed marker for an AWS access key must not itself match the
        // AWS access key pattern; otherwise Typed mode round-trips into a
        // cascade-redaction loop.
        let cfg = crate::config::Config::default();
        let det = crate::detector::Detector::from_config(&cfg);
        let r = det.scan("[AWS_ACCESS_KEY_ID]");
        assert!(!r.has_secrets);
    }

    #[test]
    fn name_to_tag_basic() {
        assert_eq!(name_to_tag("AWS Access Key ID"), "[AWS_ACCESS_KEY_ID]");
        assert_eq!(name_to_tag("Email Address"), "[EMAIL_ADDRESS]");
        assert_eq!(
            name_to_tag("Private Key (RSA/DSA/EC)"),
            "[PRIVATE_KEY_RSA_DSA_EC]"
        );
        assert_eq!(name_to_tag("IP Address"), "[IP_ADDRESS]");
        assert_eq!(name_to_tag("High Entropy"), "[HIGH_ENTROPY]");
    }

    #[test]
    fn name_to_tag_edge_cases() {
        assert_eq!(name_to_tag(""), "[SECRET]");
        assert_eq!(name_to_tag("---"), "[SECRET]");
        assert_eq!(name_to_tag("__hello__"), "[HELLO]");
        assert_eq!(name_to_tag("a"), "[A]");
    }
}
