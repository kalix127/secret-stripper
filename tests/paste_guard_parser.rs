use secret_stripper::config::Config;
use secret_stripper::detector::Detector;
use secret_stripper::redact_cli::redact_with;

// The parser type lives in the binary crate and is unit-tested next to its
// source. From the lib we exercise the redact pipeline the parser feeds
// payloads through, with a realistic AWS-shaped paste.
#[test]
fn paste_payload_with_aws_key_is_redacted() {
    let mut cfg = Config {
        onboarding_done: true,
        ..Config::default()
    };
    secret_stripper::detector::presets::Preset::Balanced.apply(&mut cfg);
    let det = Detector::from_config(&cfg);

    let payload = "Here are my creds: AKIAIOSFODNN7EXAMPLE and a secret = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let (out, names) = redact_with(&det, &cfg, payload);
    assert_ne!(out, payload);
    assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "key leaked: {}", out);
    assert!(!names.is_empty());
}
