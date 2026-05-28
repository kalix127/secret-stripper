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
    // string (no span info). Replace the whole input so the secret cannot
    // survive the round-trip. Style-aware: Marker uses the configured marker,
    // Typed uses [SECRET] (the originating name is unrecoverable here), Drop
    // empties the output. Mirrors the trigger flow in main.rs::run_trigger.
    let final_text = if redacted == text {
        match cfg.redact_style {
            RedactStyle::Marker => cfg.redact_pattern.clone(),
            RedactStyle::Typed => "[SECRET]".to_string(),
            RedactStyle::Drop => String::new(),
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
