pub mod custom;
pub mod deep_scan;
pub mod entropy;
pub mod patterns;
pub mod presets;
pub mod redact;
pub mod validators;
pub mod wordlists;

use patterns::Severity;
use std::collections::HashSet;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub matched_patterns: Vec<(&'static str, &'static str, Severity)>,
    /// Byte spans (in the original text) of every pattern hit that survived
    /// allowlist + validator, so the redactor never has to re-run the
    /// catalog. Soft-wrap-only hits travel via `extra_spans` as before.
    pub matched_spans: Vec<(usize, usize)>,
    pub high_entropy_tokens: Vec<(String, f64)>,
    pub deep_findings: Vec<deep_scan::DeepFinding>,
    /// Byte spans (in the original text) for secrets only found once their
    /// soft-wrapped newline was removed. They carry no regex of their own, so
    /// the redactor cannot re-derive them; callers must pass these through to
    /// the redaction span list the same way deep-scan spans are.
    pub extra_spans: Vec<(usize, usize)>,
    pub has_secrets: bool,
}

pub struct Detector {
    patterns: Vec<patterns::SecretPattern>,
    /// Combined automaton over every pattern source string, index-aligned with
    /// `patterns`. One pass tells us which patterns *can* match so the
    /// per-pattern `find_iter` only runs for those. `None` if the set exceeds
    /// the regex size limit - then every pattern is scanned (same result,
    /// no speedup). Built once per `Detector`.
    prefilter: Option<regex::RegexSet>,
    /// Indices into `patterns` of regexes that are not line-anchored / DOTALL.
    /// Only these run in the soft-wrap second pass, where newlines have been
    /// removed (a `(?m)`/`(?s)`/`\n` pattern there would misbehave).
    single_line_patterns: Vec<usize>,
    allowlist: Vec<regex::Regex>,
    entropy_threshold: f64,
    entropy_min_len: usize,
    entropy_max_len: usize,
    enable_deep_scan: bool,
    enable_entropy: bool,
}

/// Secret-body byte class: the characters a wrapped token is made of.
fn is_secret_body(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'.' | b'-')
}

/// Compile every entry of `BUILTIN_ALLOWLIST` exactly once per process. These
/// strings are constant and the compile cost (~tens of microseconds per regex,
/// ~13 entries = ~hundreds of microseconds) was previously paid by every
/// `Detector::from_config` / `Detector::for_preview` call - i.e. every TUI
/// preview repaint and every `secret-stripper trigger` invocation. Returning
/// a slice of clones is sub-microsecond (`Regex` is Arc-backed).
fn builtin_allowlist_compiled() -> &'static [regex::Regex] {
    static CACHE: OnceLock<Vec<regex::Regex>> = OnceLock::new();
    CACHE.get_or_init(|| {
        BUILTIN_ALLOWLIST
            .iter()
            .filter_map(|r| custom::validate_regex(r).ok())
            .collect()
    })
}

/// A regex is safe to run in the soft-wrap pass only if it does not depend on
/// real newlines: no literal `\n`, no `(?m)`/`(?s)` (alone or combined).
fn is_single_line_regex(src: &str) -> bool {
    if src.contains('\n') || src.contains("\\n") {
        return false;
    }
    let b = src.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == b'(' && b[i + 1] == b'?' {
            // Inline flags are the maximal run of [imsxUuR-] right after "(?";
            // stop at the first non-flag byte so "(?P<password>" / "(?:" / "(?="
            // are not mis-scanned.
            let mut j = i + 2;
            while j < b.len()
                && matches!(b[j], b'i' | b'm' | b's' | b'x' | b'U' | b'u' | b'R' | b'-')
            {
                if b[j] == b'm' || b[j] == b's' {
                    return false;
                }
                j += 1;
            }
        }
        i += 1;
    }
    true
}

/// `is_softwrap_join(b, i)` (with `b[i] == b'\n'`): true when this newline
/// looks like a terminal/editor hard-wrap inside one token - both sides are
/// directly adjacent secret-body characters (no space/tab/blank line), the
/// left run is >= 6 and the right run >= 2. Prose ("...end.\nNew sentence")
/// fails because `.`/space/capital are not adjacent secret-body chars.
fn is_softwrap_join(b: &[u8], i: usize) -> bool {
    // Tolerate one CR glued to the LF (CRLF or, rarely, LFCR).
    let left_end = if i > 0 && b[i - 1] == b'\r' { i - 1 } else { i };
    if left_end == 0 {
        return false;
    }
    let mut l = left_end;
    let mut lrun = 0usize;
    while l > 0 && is_secret_body(b[l - 1]) {
        l -= 1;
        lrun += 1;
    }
    if lrun < 6 {
        return false;
    }
    let mut r = i + 1;
    if r < b.len() && b[r] == b'\r' {
        r += 1;
    }
    if r >= b.len() {
        return false;
    }
    let mut rr = r;
    let mut rrun = 0usize;
    while rr < b.len() && is_secret_body(b[rr]) {
        rr += 1;
        rrun += 1;
    }
    if rrun < 2 {
        return false;
    }
    // A wrapped token's continuation is just more token bytes. If the next
    // line is instead a new `IDENT=value` / `Header: value` (an identifier,
    // then '='/':' , then a non-empty value), keep the newline so ordinary
    // env / header dumps are never fused. Trailing base64 '=' padding does
    // NOT count (nothing but '='/space follows it to end-of-line).
    let mut j = r;
    while j < b.len() && (b[j].is_ascii_alphanumeric() || matches!(b[j], b'_' | b'-')) {
        j += 1;
    }
    if j < b.len() && matches!(b[j], b'=' | b':') {
        let mut k = j + 1;
        while k < b.len() && b[k] == b'=' {
            k += 1;
        }
        while k < b.len() && matches!(b[k], b' ' | b'\t') {
            k += 1;
        }
        if k < b.len() && !matches!(b[k], b'\n' | b'\r') {
            return false;
        }
    }
    true
}

/// Build a copy of `text` with only soft-wrap newlines removed, plus a
/// `map` where `map[k]` is the original byte offset of dewrapped byte `k`
/// and `map[dw.len()]` is `text.len()`. Only ASCII `\n`/`\r` are ever
/// dropped, so the result stays valid UTF-8.
fn build_dewrapped(text: &str) -> (String, Vec<usize>) {
    let b = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut map: Vec<usize> = Vec::with_capacity(b.len() + 1);
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\n' && is_softwrap_join(b, i) {
            // A CR we already copied belongs to this wrap; drop it too.
            if i > 0 && b[i - 1] == b'\r' {
                out.pop();
                map.pop();
            }
            i += 1;
            if i < b.len() && b[i] == b'\r' {
                i += 1;
            }
            continue;
        }
        out.push(b[i]);
        map.push(i);
        i += 1;
    }
    map.push(b.len());
    (
        String::from_utf8(out).expect("only ASCII newlines removed; still valid UTF-8"),
        map,
    )
}

/// Built-in do-NOT-redact allowlist: anti-CSRF / OAuth-public / device-flow
/// tokens and signature-on-wire headers. These are not secrets (or are
/// public verifiers); redacting them would break auth flows and they are
/// false positives, so any detection fully inside one of these spans is
/// suppressed. User `allowlist_regex` is applied in addition to this.
pub(crate) const BUILTIN_ALLOWLIST: &[&str] = &[
    r"(?i)\bcsrf[_-]?token\s*[=:]\s*\S+",
    r"(?i)\bxsrf-token\s*[=:]\s*\S+",
    r"(?i)\bX-CSRF-Token:\s*\S+",
    r"(?i)\b__RequestVerificationToken\s*[=:]\s*\S+",
    r"(?i)\b_wpnonce\s*[=:]\s*\S+",
    r"(?i)\b(?:state|nonce|code_challenge|user_code)=[A-Za-z0-9._~-]+",
    r#"(?i)"(?:state|nonce|code_challenge|user_code)"\s*:\s*"[^"]+""#,
    r"(?i)\bWWW-Authenticate:\s*\S[^\n]*",
    r"(?i)\bX-Hub-Signature(?:-256)?:\s*\S+",
    r"(?i)\bStripe-Signature:\s*\S[^\n]*",
    r"(?i)\bX-Slack-Signature:\s*\S+",
    r"(?i)\bX-Shopify-Hmac-Sha256:\s*\S+",
    r"(?i)\bwebhook-signature:\s*\S+",
];

/// True if `[s, e)` is fully contained in some allowlist match in `text`.
pub(crate) fn span_allowlisted(allowlist: &[regex::Regex], text: &str, s: usize, e: usize) -> bool {
    allowlist
        .iter()
        .any(|re| re.find_iter(text).any(|m| m.start() <= s && e <= m.end()))
}

impl Detector {
    pub fn from_config(cfg: &crate::config::Config) -> Self {
        Self::from_config_verbose(cfg).0
    }

    /// Like `from_config` but also returns custom-pattern load errors for the
    /// settings UI to surface. `from_config` discards them.
    pub fn from_config_verbose(cfg: &crate::config::Config) -> (Self, Vec<String>) {
        Self::build(cfg, true)
    }

    /// Detector for the TUI live-preview only: built-ins + allowlist, NO
    /// custom patterns. Custom loading leaks strings to `'static` (fine once
    /// per process), so it must not run on the preview's per-keystroke
    /// rebuild path.
    pub fn for_preview(cfg: &crate::config::Config) -> Self {
        Self::build(cfg, false).0
    }

    fn build(cfg: &crate::config::Config, with_custom: bool) -> (Self, Vec<String>) {
        let sens_threshold = match cfg.sensitivity {
            1 => 5.0,
            2 => 4.5,
            3 => 3.8,
            4 => 3.2,
            5 => 2.5,
            _ => 3.8,
        };
        let sens_min_len = match cfg.sensitivity {
            1 => 32,
            2 => 24,
            3 => 20,
            4 => 14,
            5 => 8,
            _ => 20,
        };
        // The Option<> overrides only let the user be stricter than the dial,
        // never looser, hence the .min() against the sensitivity-derived value.
        // Floor of 2.0 prevents pathological "match anything" configs.
        let threshold = cfg
            .entropy_threshold
            .map(|t| t.min(sens_threshold).max(2.0))
            .unwrap_or(sens_threshold);
        let min_len = cfg.entropy_min_len.unwrap_or(sens_min_len);

        let disabled: HashSet<&str> = cfg.disabled_categories.iter().map(|s| s.as_str()).collect();
        let mut all = patterns::builtin_patterns_filtered(&disabled);
        let errs = if with_custom {
            let (custom, errs) = custom::load();
            all.extend(
                custom
                    .into_iter()
                    .filter(|p| !disabled.contains(p.category)),
            );
            errs
        } else {
            Vec::new()
        };
        // Allowlist regexes are bounded by validate_regex (same 1 MiB size
        // limit as custom patterns) so a hand-edited / migrated config can't
        // stall Detector construction with a pathological pattern. Built-ins
        // are compiled once per process via OnceLock; only the user portion
        // is recompiled per call. `regex::Regex` clone is Arc-backed (cheap).
        let mut allowlist: Vec<regex::Regex> = builtin_allowlist_compiled().to_vec();
        allowlist.extend(
            cfg.allowlist_regex
                .iter()
                .filter_map(|r| custom::validate_regex(r).ok()),
        );

        // The soft-wrap pass joins across a newline, so it must only run
        // *precise* patterns: an accidental cross-line join trivially
        // fabricates a format-only token (a bare base58/hex run), so Low/
        // Medium hints without a validator are excluded - only Critical/High
        // (prefix/keyword-anchored) or validator-gated patterns qualify.
        //
        // NOTE: this filter is the ONLY place `Severity` changes behavior.
        // Everywhere else it is classification/label metadata (it does not
        // decide what is redacted - every match is). Here Critical/High is
        // used as a proxy for "anchored enough to rejoin safely"; a checksum
        // validator is the other accepted proof of precision.
        let single_line_patterns: Vec<usize> = all
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                is_single_line_regex(p.regex.as_str())
                    && (matches!(p.severity, Severity::Critical | Severity::High)
                        || validators::validator_for(p.regex.as_str()).is_some())
            })
            .map(|(i, _)| i)
            .collect();

        let prefilter = regex::RegexSet::new(all.iter().map(|p| p.regex.as_str())).ok();

        (
            Self {
                patterns: all,
                prefilter,
                single_line_patterns,
                allowlist,
                entropy_threshold: threshold,
                entropy_min_len: min_len,
                entropy_max_len: 256,
                enable_deep_scan: cfg.enable_deep_scan,
                enable_entropy: cfg.enable_entropy,
            },
            errs,
        )
    }

    pub fn allowlist(&self) -> &[regex::Regex] {
        &self.allowlist
    }

    pub fn scan(&self, text: &str) -> DetectionResult {
        let mut matched = Vec::new();
        let mut matched_spans: Vec<(usize, usize)> = Vec::new();
        let mut seen: HashSet<(usize, usize)> = HashSet::new();

        // One combined-automaton pass picks the patterns that can match;
        // fall back to scanning all of them if the set was too large to
        // compile. Ascending index order preserves detection precedence.
        let candidates: Vec<usize> = match &self.prefilter {
            Some(set) => set.matches(text).into_iter().collect(),
            None => (0..self.patterns.len()).collect(),
        };
        for pi in candidates {
            let pattern = &self.patterns[pi];
            for m in pattern.regex.find_iter(text) {
                if span_allowlisted(&self.allowlist, text, m.start(), m.end()) {
                    continue;
                }
                if let Some(validate) = validators::validator_for(pattern.regex.as_str()) {
                    if !validate(m.as_str()) {
                        continue;
                    }
                }
                if seen.insert((pi, m.start())) {
                    matched.push((pattern.name, pattern.category, pattern.severity.clone()));
                    matched_spans.push((m.start(), m.end()));
                }
            }
        }

        let mut high_entropy_tokens = if self.enable_entropy {
            entropy::find_high_entropy_strings(
                text,
                self.entropy_min_len,
                self.entropy_max_len,
                self.entropy_threshold,
            )
        } else {
            Vec::new()
        };

        let mut deep_findings = if self.enable_deep_scan {
            deep_scan::deep_scan(text)
        } else {
            Vec::new()
        };
        if !self.allowlist.is_empty() {
            deep_findings.retain(|fd| {
                fd.span
                    .map(|(s, e)| !span_allowlisted(&self.allowlist, text, s, e))
                    .unwrap_or(true)
            });
        }

        // Soft-wrap second pass: catch a secret a human split mid-token across
        // one newline that no single pattern spans. Additive and gated on the
        // span actually containing a '\n', so input with no soft-wrap is
        // unaffected; the joined value is what validators (Luhn/IBAN/...) see.
        let mut extra_spans: Vec<(usize, usize)> = Vec::new();
        let (dw, map) = build_dewrapped(text);
        if dw.len() != text.len() {
            for &pi in &self.single_line_patterns {
                let pattern = &self.patterns[pi];
                for m in pattern.regex.find_iter(&dw) {
                    let (ms, me) = (m.start(), m.end());
                    if me == 0 {
                        continue;
                    }
                    let os = map[ms];
                    let oe = map[me - 1] + 1;
                    if !text[os..oe].contains('\n') {
                        continue;
                    }
                    if span_allowlisted(&self.allowlist, text, os, oe) {
                        continue;
                    }
                    if let Some(validate) = validators::validator_for(pattern.regex.as_str()) {
                        if !validate(m.as_str()) {
                            continue;
                        }
                    }
                    if seen.insert((pi, os)) {
                        matched.push((pattern.name, pattern.category, pattern.severity.clone()));
                    }
                    extra_spans.push((os, oe));
                }
            }

            // Entropy-across-wrap: a prefixless high-entropy secret split by
            // one newline. Strictly additive - only emit when the *joined*
            // token clears the bar AND no newline-split fragment was already
            // an entropy hit on the original text, so existing detections are
            // unchanged and the FP surface is just the genuinely-missed case.
            let wrap_tokens = if self.enable_entropy {
                entropy::find_high_entropy_strings(
                    &dw,
                    self.entropy_min_len,
                    self.entropy_max_len,
                    self.entropy_threshold,
                )
            } else {
                Vec::new()
            };
            for (tok, ent) in wrap_tokens {
                if high_entropy_tokens.iter().any(|(t, _)| *t == tok) {
                    continue;
                }
                if tok.is_empty() {
                    continue;
                }
                // Literal substring search; cheaper than building a regex per
                // token. See the entropy-token loop in redact_with_spans for
                // the same shape.
                for (ms, mt) in dw.match_indices(tok.as_str()) {
                    let me = ms + mt.len();
                    if me == 0 {
                        continue;
                    }
                    let os = map[ms];
                    let oe = map[me - 1] + 1;
                    if !text[os..oe].contains('\n') {
                        continue;
                    }
                    if span_allowlisted(&self.allowlist, text, os, oe) {
                        continue;
                    }
                    let additive = text[os..oe]
                        .split(['\n', '\r'])
                        .filter(|s| !s.is_empty())
                        .all(|frag| !high_entropy_tokens.iter().any(|(t, _)| t.as_str() == frag));
                    if !additive {
                        continue;
                    }
                    if seen.insert((usize::MAX, os)) {
                        high_entropy_tokens.push((tok.clone(), ent));
                    }
                    extra_spans.push((os, oe));
                }
            }
        }

        let has_secrets = !matched.is_empty()
            || !high_entropy_tokens.is_empty()
            || !deep_findings.is_empty()
            || !extra_spans.is_empty();

        DetectionResult {
            matched_patterns: matched,
            matched_spans,
            high_entropy_tokens,
            deep_findings,
            extra_spans,
            has_secrets,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> crate::config::Config {
        crate::config::Config {
            sensitivity: 3,
            entropy_threshold: Some(3.8),
            entropy_min_len: Some(20),
            enable_deep_scan: true,
            ..crate::config::Config::default()
        }
    }

    #[test]
    fn test_detector_detects_aws_key() {
        let d = Detector::from_config(&test_config());
        let r = d.scan("AKIAIOSFODNN7EXAMPLE");
        assert!(r.has_secrets);
        assert!(r
            .matched_patterns
            .iter()
            .any(|(n, _, _)| *n == "AWS Access Key ID"));
    }

    #[test]
    fn test_detector_detects_ssn() {
        let d = Detector::from_config(&test_config());
        let r = d.scan("My SSN is 123-45-6789");
        assert!(r.has_secrets);
    }

    #[test]
    fn test_detector_detects_credit_card() {
        let d = Detector::from_config(&test_config());
        let r = d.scan("4111-1111-1111-1111");
        assert!(r.has_secrets);
    }

    #[test]
    fn test_detector_clean_text() {
        let d = Detector::from_config(&test_config());
        let r = d.scan("hello world this is just normal text");
        assert!(!r.has_secrets);
    }

    #[test]
    fn test_detector_multiple_patterns() {
        let d = Detector::from_config(&test_config());
        let r = d.scan("email: user@test.com\nkey: AKIAIOSFODNN7EXAMPLE\ncc: 4111-1111-1111-1111");
        assert!(r.has_secrets);
        assert!(r.matched_patterns.len() >= 2);
    }

    #[test]
    fn test_detector_high_entropy() {
        let d = Detector::from_config(&crate::config::Config {
            sensitivity: 5,
            entropy_threshold: Some(2.5),
            entropy_min_len: Some(8),
            enable_deep_scan: true,
            ..test_config()
        });
        let r = d.scan("token=xyzaB3$kL9#xQ2!zP7&vR5mN4wS8abcdefgh");
        assert!(r.has_secrets);
    }

    #[test]
    fn preset_gates_pattern_buckets_through_detector() {
        use crate::detector::presets::Preset;

        let scan_for = |preset: Preset| {
            let mut cfg = test_config();
            preset.apply(&mut cfg);
            let names: Vec<&'static str> = Detector::from_config(&cfg)
                .scan("contact user@test.com and aws AKIAIOSFODNN7EXAMPLE")
                .matched_patterns
                .into_iter()
                .map(|(n, _, _)| n)
                .collect();
            names
        };

        // pii_contact is in Minimal; legacy (AWS key) is excluded from it.
        let minimal = scan_for(Preset::Minimal);
        assert!(minimal.contains(&"Email Address"));
        assert!(!minimal.contains(&"AWS Access Key ID"));

        // Full re-enables every bucket, so the AWS key is detected again.
        let full = scan_for(Preset::Full);
        assert!(full.contains(&"Email Address"));
        assert!(full.contains(&"AWS Access Key ID"));
    }

    #[test]
    fn test_detector_deep_scan_disabled() {
        let d = Detector::from_config(&crate::config::Config {
            enable_deep_scan: false,
            ..test_config()
        });
        let r = d.scan(r#"{"password": "s3cretV@lue!"}"#);
        // deep scan would catch this, but without it only regex patterns apply
        assert!(!r.has_secrets || !r.deep_findings.is_empty());
    }

    #[test]
    fn test_detector_entropy_toggle() {
        // sensitivity 5 -> entropy floor 8 chars / threshold 2.5, so this bare
        // random token clears the bar. Toggling enable_entropy must be the
        // only thing that decides whether it shows up as an entropy hit.
        let token = "aB3xK9zQ7mWp2RtY";
        // No Option overrides, so sensitivity 5 (floor 8 / threshold 2.5)
        // governs and this token clears the bar.
        let base = crate::config::Config {
            sensitivity: 5,
            entropy_threshold: None,
            entropy_min_len: None,
            ..crate::config::Config::default()
        };
        let on = Detector::from_config(&crate::config::Config {
            enable_entropy: true,
            ..base.clone()
        });
        let off = Detector::from_config(&crate::config::Config {
            enable_entropy: false,
            ..base
        });
        assert!(!on.scan(token).high_entropy_tokens.is_empty());
        assert!(off.scan(token).high_entropy_tokens.is_empty());
    }

    #[test]
    fn scan_records_pattern_spans() {
        let d = Detector::from_config(&test_config());
        let r = d.scan("AKIAIOSFODNN7EXAMPLE");
        assert!(!r.matched_spans.is_empty());
        let (s, e) = r.matched_spans[0];
        assert_eq!(&"AKIAIOSFODNN7EXAMPLE"[s..e], "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_detector_severity_counts() {
        let d = Detector::from_config(&test_config());
        let input = format!("-----BEGIN RSA PRIVATE KEY-----\nAKIAIOSFODNN7EXAMPLE\n{}oxb-123456789012-1234567890123-abcABC123def456", "x");
        let r = d.scan(&input);
        let critical_count = r
            .matched_patterns
            .iter()
            .filter(|(_, _, s)| *s == patterns::Severity::Critical)
            .count();
        assert!(critical_count >= 2);
    }

    #[test]
    fn dewrap_joins_softwrapped_token() {
        let text = "AKIAIOSFOD\nNN7EXAMPLE";
        let (dw, map) = build_dewrapped(text);
        assert_eq!(dw, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(map.len(), dw.len() + 1);
        // dewrapped byte 10 ('N') maps back to just past the dropped '\n'.
        assert_eq!(&text[map[10]..=map[10]], "N");
        assert_eq!(map[dw.len()], text.len());
    }

    #[test]
    fn dewrap_strips_crlf_wrap() {
        let (dw, _) = build_dewrapped("abcdefgh\r\nIJKL");
        assert_eq!(dw, "abcdefghIJKL");
    }

    #[test]
    fn dewrap_leaves_prose_and_guarded_cases_untouched() {
        for t in [
            "This is the first line.\nThis is the second line.",
            "abcdef \nghijkl",    // space before the break
            "abcdefgh\n ghijkl",  // space after the break
            "abcdefgh\n\nghijkl", // blank line
            "ab\ncdefgh",         // left run shorter than 6
            "single line no break here",
            "PASSWORD=hunter2longvalue\nNEXTKEY=value", // next line is a new key=
            "sometokenabcdef\nAuthorization: Bearer xyz", // next line is a Header:
        ] {
            let (dw, _) = build_dewrapped(t);
            assert_eq!(dw, *t, "must be unchanged: {t:?}");
        }
    }

    #[test]
    fn scan_detects_softwrapped_aws_key() {
        let d = Detector::from_config(&test_config());
        let r = d.scan("server log line\ntoken AKIAIOSFOD\nNN7EXAMPLE trailing");
        assert!(r.has_secrets);
        assert!(r
            .matched_patterns
            .iter()
            .any(|(n, _, _)| *n == "AWS Access Key ID"));
        assert!(!r.extra_spans.is_empty());
    }

    #[test]
    fn scan_softwrap_does_not_fuse_prose() {
        let d = Detector::from_config(&test_config());
        let r = d.scan("This is the first line.\nThis is the second line.");
        assert!(!r.has_secrets);
        assert!(r.extra_spans.is_empty());
    }

    #[test]
    fn scan_detects_softwrapped_high_entropy_secret() {
        // sensitivity 5 -> entropy floor 8 chars. Each 7-char half is below
        // the floor so the normal per-line pass misses both; only the joined
        // token clears the bar (the strict additive case).
        let cfg = crate::config::Config {
            sensitivity: 5,
            entropy_threshold: None,
            entropy_min_len: None,
            enable_deep_scan: true,
            ..crate::config::Config::default()
        };
        let d = Detector::from_config(&cfg);
        let r = d.scan("log dump start\naB3xK9z\nQ7mWp2R");
        assert!(r.has_secrets);
        assert!(!r.extra_spans.is_empty());
    }

    #[test]
    fn is_single_line_regex_classification() {
        assert!(is_single_line_regex(r"(?i)AKIA[0-9A-Z]{16}"));
        assert!(is_single_line_regex(r"(?:ghp|gho)_[A-Za-z0-9_.]{36,600}"));
        assert!(is_single_line_regex(r"(?P<password>\w+)"));
        assert!(!is_single_line_regex(r"(?m)^secret=.+$"));
        assert!(!is_single_line_regex(r"(?s)BEGIN.*END"));
        assert!(!is_single_line_regex(r"(?is)A.*B"));
        assert!(!is_single_line_regex(r"line1\nline2"));
    }

    #[test]
    fn test_detector_sensitivity_levels() {
        for sens in 1..=5 {
            let cfg = crate::config::Config {
                sensitivity: sens,
                ..test_config()
            };
            let d = Detector::from_config(&cfg);
            // all configs should detect basic patterns
            let r = d.scan("AKIAIOSFODNN7EXAMPLE");
            assert!(r.has_secrets, "sensitivity {} should detect AWS key", sens);
        }
    }
}
