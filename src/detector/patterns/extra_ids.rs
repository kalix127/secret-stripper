use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "ORCID iD",
            category: "PII / Academic",
            severity: Severity::Low,
            regex: re(crate::detector::validators::ORCID_RE),
        },
        SecretPattern {
            name: "ISIN",
            category: "Financial",
            severity: Severity::Low,
            regex: re(crate::detector::validators::ISIN_RE),
        },
        SecretPattern {
            name: "otpauth TOTP/HOTP URI",
            category: "Secret",
            severity: Severity::Critical,
            regex: re(r"otpauth://[a-z]+/[^\s?]+\?[^\s]*secret=[A-Za-z2-7]{8,}"),
        },
        SecretPattern {
            name: "BitLocker Recovery Key",
            category: "Secret",
            severity: Severity::Critical,
            regex: re(r"\b\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}\b"),
        },
        SecretPattern {
            name: "EU Digital COVID Certificate",
            category: "PII / Health",
            severity: Severity::High,
            regex: re(r"\bHC1:[A-Z0-9$%*+./:\-]{40,}"),
        },
        SecretPattern {
            name: "Credential-bearing URL",
            category: "Secret",
            severity: Severity::Critical,
            // Scheme-whitelisted: a generic `scheme://` matched things like
            // `file://user:pass@/path` in shell snippets. Only network
            // schemes that actually carry transit credentials qualify.
            regex: re(
                r"\b(?:https?|ftps?|sftp|ssh|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|smtps?|ldaps?)://[^\s/:@]+:[^\s/:@]+@[^\s/]+",
            ),
        },
        SecretPattern {
            name: "Classification Banner",
            category: "Sensitive",
            severity: Severity::Medium,
            regex: re(
                r"(?i)(?:TOP SECRET//|SECRET//[A-Z]|TS//SCI|//NOFORN|\bCUI//|UNCLASSIFIED//(?:FOUO|CUI))",
            ),
        },
    ]
}
