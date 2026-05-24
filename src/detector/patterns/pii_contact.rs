use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Email Address",
            category: "PII / Contact",
            severity: Severity::Low,
            regex: re(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        },
        SecretPattern {
            name: "Phone Number (US)",
            category: "PII / Contact",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::PHONE_US_RE),
        },
        SecretPattern {
            name: "International Phone (E.164)",
            category: "PII / Contact",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::E164_RE),
        },
        SecretPattern {
            name: "Phone Number (UK)",
            category: "PII / Contact",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::PHONE_UK_RE),
        },
        SecretPattern {
            name: "Phone Number (Italy)",
            category: "PII / Contact",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::PHONE_IT_RE),
        },
        SecretPattern {
            name: "Phone Number (France)",
            category: "PII / Contact",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::PHONE_FR_RE),
        },
        SecretPattern {
            name: "Phone Number (Germany)",
            category: "PII / Contact",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::PHONE_DE_RE),
        },
        SecretPattern {
            name: "Phone Number (Spain)",
            category: "PII / Contact",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::PHONE_ES_RE),
        },
        SecretPattern {
            name: "Phone Number (Brazil)",
            category: "PII / Contact",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::PHONE_BR_RE),
        },
        SecretPattern {
            name: "Phone Number (India)",
            category: "PII / Contact",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::PHONE_IN_RE),
        },
        SecretPattern {
            name: "Date of Birth (labeled)",
            category: "PII / Contact",
            severity: Severity::Medium,
            regex: re(
                r"(?i)\b(?:dob|date[_\s-]?of[_\s-]?birth|birth[_\s-]?date)\s*[:=]?\s*(?:19|20)[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])\b",
            ),
        },
    ]
}
