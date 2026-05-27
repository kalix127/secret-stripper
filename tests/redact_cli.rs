use secret_stripper::config::Config;
use secret_stripper::detector::Detector;
use secret_stripper::redact_cli::redact_with;

fn fresh_cfg() -> Config {
    let mut c = Config {
        onboarding_done: true,
        ..Config::default()
    };
    secret_stripper::detector::presets::Preset::Balanced.apply(&mut c);
    c
}

#[test]
fn pipe_redacts_openai_key() {
    let cfg = fresh_cfg();
    let det = Detector::from_config(&cfg);
    let input = "API key for testing: sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij\nend\n";
    let (out, names) = redact_with(&det, &cfg, input);
    assert_ne!(out, input, "expected the secret to be redacted");
    assert!(
        !out.contains("sk-proj-abcdefghijklmnopqrstuvwxyz"),
        "raw key leaked: {}",
        out
    );
    assert!(!names.is_empty(), "expected at least one matched pattern");
}

#[test]
fn pipe_passes_clean_text_through_unchanged() {
    let cfg = fresh_cfg();
    let det = Detector::from_config(&cfg);
    let input = "this is just a comment about the weather today\n";
    let (out, names) = redact_with(&det, &cfg, input);
    assert_eq!(out, input);
    assert!(names.is_empty());
}
