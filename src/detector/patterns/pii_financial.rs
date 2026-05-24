use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        // Brand-anchored + Luhn-gated (validators registry). The old generic
        // "(?:\d{4}[-\s]?){3}\d{4}" any-16-digits rule is gone: it matched
        // every order/tracking number. Each brand below needs shape + issuer
        // BIN + Mod-10 to agree. UnionPay is the lone exception - real
        // UnionPay PANs are not all Luhn-valid, so it stays prefix-only.
        SecretPattern {
            name: "Visa Card",
            category: "PII / Financial",
            severity: Severity::Critical,
            regex: re(crate::detector::validators::CARD_VISA_RE),
        },
        SecretPattern {
            name: "Mastercard Card",
            category: "PII / Financial",
            severity: Severity::Critical,
            regex: re(crate::detector::validators::CARD_MASTERCARD_RE),
        },
        SecretPattern {
            name: "American Express Card",
            category: "PII / Financial",
            severity: Severity::Critical,
            regex: re(crate::detector::validators::CARD_AMEX_RE),
        },
        SecretPattern {
            name: "Discover Card",
            category: "PII / Financial",
            severity: Severity::Critical,
            regex: re(crate::detector::validators::CARD_DISCOVER_RE),
        },
        SecretPattern {
            name: "Diners Club Card",
            category: "PII / Financial",
            severity: Severity::Critical,
            regex: re(crate::detector::validators::CARD_DINERS_RE),
        },
        SecretPattern {
            name: "JCB Card",
            category: "PII / Financial",
            severity: Severity::Critical,
            regex: re(crate::detector::validators::CARD_JCB_RE),
        },
        SecretPattern {
            name: "UnionPay Card",
            category: "PII / Financial",
            severity: Severity::Critical,
            regex: re(r"\b62\d{14,17}\b"),
        },
        SecretPattern {
            name: "Maestro Card",
            category: "PII / Financial",
            severity: Severity::Critical,
            regex: re(crate::detector::validators::CARD_MAESTRO_RE),
        },
        SecretPattern {
            name: "Dankort Card",
            category: "PII / Financial",
            severity: Severity::Critical,
            regex: re(crate::detector::validators::CARD_DANKORT_RE),
        },
        SecretPattern {
            name: "Mir Card",
            category: "PII / Financial",
            severity: Severity::Critical,
            regex: re(crate::detector::validators::CARD_MIR_RE),
        },
        SecretPattern {
            name: "UATP Card (labeled)",
            category: "PII / Financial",
            severity: Severity::Critical,
            regex: re(r"(?i)\buatp\b[:#=\s]+1\d{14}\b"),
        },
        SecretPattern {
            name: "IBAN",
            category: "PII / Financial",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::IBAN_RE),
        },
        SecretPattern {
            name: "IBAN (Germany)",
            category: "PII / Financial",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::IBAN_DE_RE),
        },
        SecretPattern {
            name: "IBAN (United Kingdom)",
            category: "PII / Financial",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::IBAN_GB_RE),
        },
        SecretPattern {
            name: "IBAN (France)",
            category: "PII / Financial",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::IBAN_FR_RE),
        },
        SecretPattern {
            name: "IBAN (Italy)",
            category: "PII / Financial",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::IBAN_IT_RE),
        },
        SecretPattern {
            name: "IBAN (Spain)",
            category: "PII / Financial",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::IBAN_ES_RE),
        },
        SecretPattern {
            name: "BIC / SWIFT (labeled)",
            category: "PII / Financial",
            severity: Severity::Low,
            regex: re(r"(?i)\b(?:bic|swift)\b[:=\s]+[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),
        },
        SecretPattern {
            name: "US Bank Routing Number (labeled)",
            category: "PII / Financial",
            severity: Severity::Medium,
            regex: re(r"(?i)routing(?:\s*number)?[:#=\s]+\d{9}\b"),
        },
        SecretPattern {
            name: "US Bank Account Number (labeled)",
            category: "PII / Financial",
            severity: Severity::Medium,
            regex: re(r"(?i)account(?:\s*(?:number|no))?[:#=\s]+\d{6,17}\b"),
        },
        SecretPattern {
            name: "UK Sort Code (labeled)",
            category: "PII / Financial",
            severity: Severity::Medium,
            regex: re(r"(?i)sort\s*code[:\s]+\d{2}-\d{2}-\d{2}\b"),
        },
        SecretPattern {
            name: "SEPA Creditor Identifier (labeled)",
            category: "PII / Financial",
            severity: Severity::Medium,
            regex: re(
                r"(?i)\b(?:creditor[\s_-]?id|sepa[\s_-]?ci)\b[:=\s]+[A-Z]{2}\d{2}[A-Z0-9]{3}[A-Z0-9]{1,28}\b",
            ),
        },
    ]
}
