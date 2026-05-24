use secret_stripper::lang::Lang;
use secret_stripper::Severity;

#[test]
fn active_returns_a_known_variant() {
    // active() may read a config file or fall back to env detection; either
    // way it must yield one of the four supported languages.
    let l = Lang::active();
    assert!(Lang::all().contains(&l));
}

#[test]
fn severity_label_is_defined_for_every_pair() {
    let sevs = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ];
    for l in Lang::all() {
        for s in &sevs {
            assert!(!l.severity_label(s).is_empty());
        }
    }
    assert_eq!(Lang::EN.severity_label(&Severity::Critical), "Critical");
    assert_eq!(Lang::FR.severity_label(&Severity::Low), "Faible");
}

#[test]
fn translations_do_not_leak_english() {
    // Strings that must read differently per language. Guards against an
    // arm being filled with the English text as a placeholder.
    assert_ne!(Lang::EN.cli_no_secrets(), Lang::FR.cli_no_secrets());
    assert_ne!(Lang::EN.cli_no_secrets(), Lang::IT.cli_no_secrets());
    assert_ne!(Lang::EN.cli_no_secrets(), Lang::ES.cli_no_secrets());
    // A non-empty guard too: an arm left as "" would pass assert_ne! against
    // a different-language non-empty string but is still a missing translation.
    for l in Lang::all() {
        assert!(!l.cli_no_secrets().is_empty());
        assert!(!l.menu_exit().is_empty());
    }
    assert_ne!(Lang::EN.menu_exit(), Lang::FR.menu_exit());
    assert_ne!(Lang::EN.up_updated("v1"), Lang::ES.up_updated("v1"));
}

#[test]
fn parameterized_strings_interpolate_arguments() {
    for l in Lang::all() {
        assert!(l.cli_redacted(7).contains('7'));
        assert!(l.up_latest("v9.9.9").contains("v9.9.9"));
        assert!(l.update_available_body("1.0.0", "2.0.0").contains("2.0.0"));
    }
}

#[test]
fn endonyms_are_unique_and_stable() {
    assert_eq!(Lang::EN.endonym(), "English");
    let names: Vec<&str> = Lang::all().iter().map(|l| l.endonym()).collect();
    let mut dedup = names.clone();
    dedup.sort_unstable();
    dedup.dedup();
    assert_eq!(names.len(), dedup.len());
}
