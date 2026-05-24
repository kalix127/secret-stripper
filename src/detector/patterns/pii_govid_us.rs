use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "US ITIN",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b9\d{2}[-\s]?(?:5\d|6[0-5]|7\d|8[0-8]|9[0-2]|9[4-9])[-\s]?\d{4}\b"),
        },
        SecretPattern {
            name: "US EIN (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"(?i)\bEIN[:#\s]+\d{2}-\d{7}\b"),
        },
        SecretPattern {
            name: "US PTIN",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\bP\d{8}\b"),
        },
        SecretPattern {
            name: "US Medicare MBI",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(
                r"\b[1-9][ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY0-9]\d[ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY0-9]\d[ACDEFGHJKMNPQRTUVWXY]{2}\d{2}\b",
            ),
        },
        SecretPattern {
            name: "US DEA Number",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::US_DEA_RE),
        },
        SecretPattern {
            name: "Canada SIN (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"(?i)\bSIN[:#\s]+\d{3}[-\s]?\d{3}[-\s]?\d{3}\b"),
        },
        SecretPattern {
            name: "Canada Quebec RAMQ",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[A-Z]{4}\d{8}\b"),
        },
        SecretPattern {
            name: "Canada Ontario OHIP",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b\d{4}-\d{3}-\d{3}-[A-Z]{2}\b"),
        },
        SecretPattern {
            name: "Canadian Passport",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[A-Z]{2}\d{6}\b"),
        },
        SecretPattern {
            name: "Mexico CURP",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b"),
        },
        SecretPattern {
            name: "Mexico RFC",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[A-Z]{4}\d{6}[A-Z0-9]{3}\b"),
        },
        SecretPattern {
            name: "US Driver's License (distinctive state format)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b(?:[A-Z]\d{12,14}|\d{2}[A-Z]{3}\d{5}|[A-Z]{3}\d{6})\b"),
        },
    ]
}
