use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "SWIFT MT Message Block Header",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(r"\{1:F01[A-Z]{6}[A-Z0-9]{2}[A-Z0-9]{4}\d{4}\d{6}\}\{2:[IO]\d{3}"),
        },
        SecretPattern {
            name: "SWIFT Transaction Reference (:20: tag)",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(r"(?m)^:20:[A-Z0-9/\-?:().,'+ ]{1,16}$"),
        },
        SecretPattern {
            name: "SWIFT Ordering Customer with IBAN (:50K:)",
            category: "Banking",
            severity: Severity::Critical,
            regex: re(r"(?m)^:50K:/[A-Z]{2}\d{2}[A-Z0-9]{10,30}$"),
        },
        SecretPattern {
            name: "SWIFT Beneficiary Customer with IBAN (:59:)",
            category: "Banking",
            severity: Severity::Critical,
            regex: re(r"(?m)^:59:/[A-Z]{2}\d{2}[A-Z0-9]{10,30}$"),
        },
        SecretPattern {
            name: "SWIFT Block-3 UETR Tag 121",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(
                r"\{121:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\}",
            ),
        },
        SecretPattern {
            name: "SWIFT GPI UETR (labeled)",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(
                r"(?i)\buetr\b[:=\s]+[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
            ),
        },
        SecretPattern {
            name: "ISO 20022 Message Identifier",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(r"\b(?:pacs|pain|camt)\.\d{3}\.\d{3}\.\d{2}\b"),
        },
        SecretPattern {
            name: "Legal Entity Identifier (labeled)",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(r"(?i)\blei\b[:=\s]+[A-Z0-9]{18}\d{2}\b"),
        },
        SecretPattern {
            name: "Fedwire IMAD (labeled)",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(r"(?i)\bimad\b[:=\s]+\d{8}[A-Z0-9]{4}\d{2}\d{6}\b"),
        },
        SecretPattern {
            name: "Fedwire OMAD (labeled)",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(r"(?i)\bomad\b[:=\s]+\d{8}[A-Z0-9]{4}\d{2}\d{6}\b"),
        },
        SecretPattern {
            name: "CHIPS UID (labeled)",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(r"(?i)\bchips\s*(?:uid|participant)\b[:=\s]+\d{6}\b"),
        },
        SecretPattern {
            name: "Russia Correspondent Account",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(r"\b30101810\d{12}\b"),
        },
        SecretPattern {
            name: "India IFSC Code",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        },
        SecretPattern {
            name: "India UPI VPA",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(
                r"\b[A-Za-z0-9._-]{2,64}@(?:okhdfcbank|oksbi|okicici|okaxis|paytm|ybl|upi)\b",
            ),
        },
        SecretPattern {
            name: "Brazil PIX Key (labeled)",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(r"(?i)\bpix\b[:=\s]+\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
        },
        SecretPattern {
            name: "Card Track 1 Magstripe",
            category: "Banking",
            severity: Severity::Critical,
            regex: re(r"%B\d{12,19}\^[^^]{2,26}\^\d{4}\d{3}\d*\?"),
        },
        SecretPattern {
            name: "Card Track 2 Magstripe",
            category: "Banking",
            severity: Severity::Critical,
            regex: re(r";\d{12,19}=\d{4}\d{3}\d*\?"),
        },
        SecretPattern {
            name: "Card PAN with CVV (labeled)",
            category: "Banking",
            severity: Severity::Critical,
            regex: re(
                r"(?i)\b\d{13,19}\b[^\n]{0,40}\b(?:cvv2?|cvc2?|cid|security[\s_-]?code)\b[:=\s]+\d{3,4}\b",
            ),
        },
        SecretPattern {
            name: "FATCA GIIN",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(r"\b[A-Z0-9]{6}\.[A-Z0-9]{5}\.(?:LE|SL|ME|BR|SP|SF|SD|SS)\.\d{3}\b"),
        },
        SecretPattern {
            name: "Open Banking X-Request-ID (labeled)",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(
                r"(?i)X-Request-ID[:=\s]+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            ),
        },
        SecretPattern {
            name: "New Zealand Bank Account Number",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(r"\b\d{2}-\d{4}-\d{7}-\d{2,3}\b"),
        },
        SecretPattern {
            name: "Mexico CLABE (labeled)",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(r"(?i)\bclabe\b[:#=\s]+\d{18}\b"),
        },
        SecretPattern {
            name: "Canada Bank Transit (labeled)",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(r"(?i)\btransit(?:\s*(?:number|no\.?))?[:#=\s]+\d{5}\b"),
        },
        SecretPattern {
            name: "Australia BSB (labeled)",
            category: "Banking",
            severity: Severity::Medium,
            regex: re(r"(?i)\bBSB\b[:#=\s]+\d{3}-?\d{3}\b"),
        },
    ]
}
