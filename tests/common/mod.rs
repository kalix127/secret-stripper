// Shared corpus-test machinery. One fixture file per bucket under
// tests/fixtures/corpus/<bucket>.txt drives detection + redaction round-trip
// assertions. Grammar is documented in tests/fixtures/README.md.

// Each integration-test binary that does `mod common;` uses only a subset of
// these helpers, so unused-in-this-binary is expected and not a defect.
#![allow(dead_code)]

use std::path::PathBuf;

use secret_stripper::config::Config;
use secret_stripper::detector::redact::redact_with_spans;
use secret_stripper::Detector;

pub struct Section {
    pub name: String,
    pub expected: Vec<String>,
    pub body: String,
}

pub fn corpus_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push("corpus");
    p
}

pub fn default_test_config() -> Config {
    // Default is sensitivity 3 with deep-scan enabled, which is the profile
    // the corpus is calibrated against.
    Config::default()
}

fn load(file: &str) -> String {
    let path = corpus_dir().join(file);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read corpus fixture {}: {e}", path.display()))
}

pub fn parse_sections(text: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();

        if let Some(rest) = trimmed.strip_prefix("# === ") {
            let name = rest.trim_end().trim_end_matches('=').trim().to_string();
            sections.push(Section {
                name,
                expected: Vec::new(),
                body: String::new(),
            });
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("# expect:") {
            let val = rest.trim();
            let sec = sections
                .last_mut()
                .expect("# expect: line before any # === section header");
            if val != "(none)" && !val.is_empty() {
                sec.expected.push(val.to_string());
            }
            continue;
        }

        // Any other comment line is documentation, not corpus body.
        if trimmed.starts_with('#') {
            continue;
        }

        if let Some(sec) = sections.last_mut() {
            sec.body.push_str(line);
            sec.body.push('\n');
        }
    }
    sections
}

fn fired_names(d: &Detector, body: &str) -> Vec<String> {
    let r = d.scan(body);
    let mut names: Vec<String> = r
        .matched_patterns
        .into_iter()
        .map(|(name, _, _)| name.to_string())
        .collect();
    names.extend(
        r.deep_findings
            .into_iter()
            .map(|f| f.finding_type.to_string()),
    );
    names
}

/// Assert every `# expect:` pattern in every section actually fires.
pub fn run_bucket(file: &str) {
    let text = load(file);
    let d = Detector::from_config(&default_test_config());
    let sections = parse_sections(&text);
    assert!(
        !sections.is_empty(),
        "{file}: no sections parsed (missing '# === ... ===' headers?)"
    );
    for sec in &sections {
        if sec.expected.is_empty() {
            continue;
        }
        let fired = fired_names(&d, &sec.body);
        for want in &sec.expected {
            assert!(
                fired.iter().any(|n| n == want),
                "{file} / section [{}]: expected pattern '{}' did not fire.\nFired: {:?}\nBody:\n{}",
                sec.name,
                want,
                fired,
                sec.body
            );
        }
    }
}

/// Redact each section the way the trigger flow does, then re-scan and assert
/// no pattern or deep finding survives. high_entropy_tokens are intentionally
/// NOT asserted: a high-entropy substring can legitimately remain inside
/// surrounding prose after pattern redaction.
pub fn run_bucket_roundtrip(file: &str) {
    let text = load(file);
    let cfg = default_test_config();
    let d = Detector::from_config(&cfg);
    for sec in parse_sections(&text) {
        if sec.expected.is_empty() {
            continue;
        }
        let r = d.scan(&sec.body);
        let entropy_tokens: Vec<&str> = r
            .high_entropy_tokens
            .iter()
            .map(|(t, _)| t.as_str())
            .collect();
        let mut deep_spans: Vec<(usize, usize)> =
            r.deep_findings.iter().filter_map(|f| f.span).collect();
        deep_spans.extend(r.extra_spans.iter().copied());
        let redacted = redact_with_spans(
            &sec.body,
            &r.matched_spans,
            &entropy_tokens,
            &deep_spans,
            &[],
            &cfg.redact_pattern,
        );
        let r2 = d.scan(&redacted);
        assert!(
            r2.matched_patterns.is_empty() && r2.deep_findings.is_empty(),
            "{file} / section [{}]: secret survived redaction round-trip.\nPatterns: {:?}\nDeep: {:?}\nRedacted:\n{}",
            sec.name,
            r2.matched_patterns,
            r2.deep_findings,
            redacted
        );
    }
}

/// Assert every section produces zero pattern matches and zero deep findings.
pub fn run_negatives(file: &str) {
    let text = load(file);
    let d = Detector::from_config(&default_test_config());
    for sec in parse_sections(&text) {
        let r = d.scan(&sec.body);
        assert!(
            r.matched_patterns.is_empty() && r.deep_findings.is_empty(),
            "negatives / section [{}]: false positive.\nPatterns: {:?}\nDeep: {:?}\nBody:\n{}",
            sec.name,
            r.matched_patterns,
            r.deep_findings,
            sec.body
        );
    }
}
