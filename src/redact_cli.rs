use std::io::{self, Read, Write};

use crate::config::{Config, RedactStyle};
use crate::detector::{self, Detector};

/// One-shot redaction pass over a string. Shared between the `redact`
/// subcommand (stdin -> stdout) and the `paste-guard` wrapper (per-paste
/// payload). Returns the redacted text and the list of pattern names that
/// matched, in matched order, deduplicated.
pub fn redact_with(detector: &Detector, cfg: &Config, text: &str) -> (String, Vec<String>) {
    let result = detector.scan(text);
    if !result.has_secrets {
        return (text.to_string(), Vec::new());
    }

    let entropy_tokens: Vec<&str> = result
        .high_entropy_tokens
        .iter()
        .map(|(t, _)| t.as_str())
        .collect();
    let mut deep_spans: Vec<(usize, usize, &'static str)> = result
        .deep_findings
        .iter()
        .filter_map(|f| f.span.map(|(s, e)| (s, e, f.finding_type)))
        .collect();
    deep_spans.extend(result.extra_spans.iter().copied());

    let redacted = detector::redact::redact_with_spans(
        text,
        &result.matched_spans,
        &entropy_tokens,
        &deep_spans,
        detector.allowlist(),
        cfg.redact_style,
        &cfg.redact_pattern,
    );

    let mut names: Vec<String> = Vec::new();
    for (name, _category, _sev) in &result.matched_patterns {
        if !names.iter().any(|n| n.as_str() == *name) {
            names.push((*name).to_string());
        }
    }
    for f in &result.deep_findings {
        if !names.iter().any(|x| x == f.finding_type) {
            names.push(f.finding_type.to_string());
        }
    }
    if !result.high_entropy_tokens.is_empty() && !names.iter().any(|n| n == "entropy") {
        names.push("entropy".to_string());
    }

    // Fallback: deep-scan caught it but the redactor produced an identical
    // string. For Marker/Typed/Drop that means no span was located, so replace
    // the whole input to fail closed. Placeholder sample values can equal the
    // original secret (a fixed point), so for that style only fail closed when
    // there was genuinely no span to redact. Mirrors main.rs::run_trigger.
    let had_spans =
        !result.matched_spans.is_empty() || !entropy_tokens.is_empty() || !deep_spans.is_empty();
    let redaction_noop =
        redacted == text && !(matches!(cfg.redact_style, RedactStyle::Placeholder) && had_spans);
    let final_text = if redaction_noop {
        match cfg.redact_style {
            RedactStyle::Marker => cfg.redact_pattern.clone(),
            RedactStyle::Typed => "[SECRET]".to_string(),
            RedactStyle::Drop => String::new(),
            RedactStyle::Placeholder => detector::placeholders::GENERIC.to_string(),
        }
    } else {
        redacted
    };

    (final_text, names)
}

pub fn run_redact() -> anyhow::Result<()> {
    let cfg = Config::load();
    let detector = Detector::from_config(&cfg);

    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    let (redacted, _names) = redact_with(&detector, &cfg, &input);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    out.write_all(redacted.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholder_detector() -> (Config, Detector) {
        let cfg = Config {
            redact_style: RedactStyle::Placeholder,
            ..Config::default()
        };
        let det = Detector::from_config(&cfg);
        (cfg, det)
    }

    #[test]
    fn placeholder_round_trip_is_a_stable_fixed_point() {
        // A Placeholder sample can equal the original secret, so the redactor
        // returns text unchanged on a second pass. The fail-closed fallback must
        // not mistake that for a no-op and clobber the whole input.
        let (cfg, det) = placeholder_detector();
        let input = "aws AKIA1234567890ABCDEF email jane.doe@corp.com";
        let (once, _) = redact_with(&det, &cfg, input);
        assert_eq!(once, "aws AKIAIOSFODNN7EXAMPLE email user@example.com");
        let (twice, _) = redact_with(&det, &cfg, &once);
        assert_eq!(twice, once);
        assert_ne!(twice, detector::placeholders::GENERIC);
    }
}
