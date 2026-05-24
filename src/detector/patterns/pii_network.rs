use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "IPv6 Address",
            category: "PII / Network",
            severity: Severity::Low,
            regex: re(r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b"),
        },
        SecretPattern {
            name: "IPv6 Address (compressed)",
            category: "PII / Network",
            severity: Severity::Low,
            regex: re(r"(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,5}"),
        },
        SecretPattern {
            name: "IPv6 Address (link-local)",
            category: "PII / Network",
            severity: Severity::Low,
            regex: re(r"(?i)\bfe80::[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,3}\b"),
        },
        SecretPattern {
            name: "CIDR Block (IPv4)",
            category: "PII / Network",
            severity: Severity::Low,
            regex: re(
                r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)/(?:3[0-2]|[12]?\d)\b",
            ),
        },
        SecretPattern {
            name: "CIDR Block (IPv6)",
            category: "PII / Network",
            severity: Severity::Low,
            regex: re(
                r"(?:[0-9A-Fa-f]{1,4}:){1,7}:?(?:[0-9A-Fa-f]{1,4})?/(?:12[0-8]|1[01]\d|\d{1,2})\b",
            ),
        },
        SecretPattern {
            name: "UUID/GUID",
            category: "PII / Network",
            severity: Severity::Low,
            regex: re(
                r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
            ),
        },
        SecretPattern {
            name: "IMEI",
            category: "PII / Network",
            severity: Severity::Low,
            regex: re(crate::detector::validators::IMEI_RE),
        },
        SecretPattern {
            name: "IMSI",
            category: "PII / Network",
            severity: Severity::Low,
            regex: re(r"(?i)\bimsi\s*[:=]?\s*\d{14,15}\b"),
        },
        SecretPattern {
            name: "ICCID",
            category: "PII / Network",
            severity: Severity::Low,
            regex: re(crate::detector::validators::ICCID_RE),
        },
        SecretPattern {
            name: "MEID",
            category: "PII / Network",
            severity: Severity::Low,
            regex: re(r"(?i)\bmeid\s*[:=]?\s*[0-9A-Fa-f]{14}\b"),
        },
        SecretPattern {
            name: "BSSID (labeled)",
            category: "PII / Network",
            severity: Severity::Low,
            regex: re(r"(?i)\bbssid\s*[:=]?\s*(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
        },
        SecretPattern {
            name: "FCM Registration Token",
            category: "PII / Network",
            severity: Severity::Medium,
            regex: re(r"\b[\w-]{8,22}:APA91b[\w-]{100,}\b"),
        },
        SecretPattern {
            name: "TLS SHA-256 Fingerprint",
            category: "Crypto",
            severity: Severity::Low,
            regex: re(r"\b(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}\b"),
        },
        SecretPattern {
            name: "TLS SHA-1 Fingerprint",
            category: "Crypto",
            severity: Severity::Low,
            regex: re(r"\b(?:[0-9A-Fa-f]{2}:){19}[0-9A-Fa-f]{2}\b"),
        },
        SecretPattern {
            name: "SSH Key Fingerprint (SHA256)",
            category: "Crypto",
            severity: Severity::Low,
            regex: re(r"\bSHA256:[A-Za-z0-9+/]{43}\b"),
        },
        SecretPattern {
            name: "HPKP Pin (pin-sha256)",
            category: "Crypto",
            severity: Severity::Low,
            regex: re(r#"pin-sha256="[A-Za-z0-9+/]{43}=""#),
        },
        SecretPattern {
            name: "Google Analytics Cookie",
            category: "PII / Network",
            severity: Severity::Low,
            regex: re(r"\bGA1\.\d\.\d{6,12}\.\d{9,10}\b"),
        },
        SecretPattern {
            name: "Facebook Pixel Cookie",
            category: "PII / Network",
            severity: Severity::Low,
            regex: re(r"\bfb\.\d\.\d{13}\.\d{5,}\b"),
        },
        SecretPattern {
            name: "Adobe Experience Cloud ID",
            category: "PII / Network",
            severity: Severity::Low,
            regex: re(r"\b[0-9A-F]{24}@AdobeOrg\b"),
        },
    ]
}
