use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "US NPI (labeled)",
            category: "Healthcare",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::US_NPI_RE),
        },
        SecretPattern {
            name: "US NPI Card Number",
            category: "Healthcare",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::US_NPI_CARD_RE),
        },
        SecretPattern {
            name: "US DEA Number",
            category: "Healthcare",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::US_DEA_RE),
        },
        SecretPattern {
            name: "UK NHS Number (labeled)",
            category: "Healthcare",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::UK_NHS_RE),
        },
        SecretPattern {
            name: "FHIR Patient Resource ID",
            category: "Healthcare",
            severity: Severity::Medium,
            regex: re(r"\bPatient/[A-Za-z0-9\-]{1,64}\b"),
        },
        SecretPattern {
            name: "Doximity API Token",
            category: "Healthcare",
            severity: Severity::High,
            regex: re(r"\bdx_live_[A-Za-z0-9]{20,40}\b"),
        },
    ]
}
