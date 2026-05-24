use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "UK NINO",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[ABCEGHJ-PRSTW-Z][ABEHJ-NPRSTW-Z]\d{6}[A-D]\b"),
        },
        SecretPattern {
            name: "UK NHS Number (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::UK_NHS_RE),
        },
        SecretPattern {
            name: "Ireland PPSN",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b\d{7}[A-W][AHWTX]?\b"),
        },
        SecretPattern {
            name: "Ireland Eircode",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[A-Z]\d{2}\s?[A-Z0-9]{4}\b"),
        },
        SecretPattern {
            name: "France NIR (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(
                r"(?i)\b(?:NIR|INSEE)[:#\s]+[12]\d{2}(?:0[1-9]|1[0-2])\d{2}\d{3}\d{3}\d{2}\b",
            ),
        },
        SecretPattern {
            name: "Germany Steuer-ID (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"(?i)\b(?:Steuer-?ID|Steuernummer|tax[\s-]?ID)[:#\s]+\d{11}\b"),
        },
        SecretPattern {
            name: "Germany Steuernummer",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b\d{2,3}/\d{3,4}/\d{4,5}\b"),
        },
        SecretPattern {
            name: "Italy Codice Fiscale",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b"),
        },
        SecretPattern {
            name: "Italy Partita IVA (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"(?i)\b(?:Partita\s?IVA|P\.?IVA|VAT)[:#\s]+IT?\d{11}\b"),
        },
        SecretPattern {
            name: "Italy Passport",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[A-Z]{2}\d{7}\b"),
        },
        SecretPattern {
            name: "Spain DNI/NIE (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::SPAIN_DNI_RE),
        },
        SecretPattern {
            name: "Spain NIE",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[XYZ]\d{7}[A-Z]\b"),
        },
        SecretPattern {
            name: "Spain NIF (business)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[A-HJ-NP-SUVW]\d{7}[0-9A-J]\b"),
        },
        SecretPattern {
            name: "Spain SSN",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b\d{2}/\d{8}/\d{2}\b"),
        },
        SecretPattern {
            name: "Netherlands BSN (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"(?i)\bBSN[:#\s]+\d{8,9}\b"),
        },
        SecretPattern {
            name: "Belgium Rijksregisternummer",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b\d{2}\.\d{2}\.\d{2}-\d{3}\.\d{2}\b"),
        },
        SecretPattern {
            name: "Sweden Personnummer",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b(?:19|20)?\d{6}[-+]\d{4}\b"),
        },
        SecretPattern {
            name: "Finland HETU",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b\d{6}[-+ABCDEFUVWXY]\d{3}[0-9A-Y]\b"),
        },
        SecretPattern {
            name: "Estonia Isikukood",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::EE_ISIKUKOOD_RE),
        },
        SecretPattern {
            name: "Czech/Slovak Rodne cislo",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::CZ_RC_RE),
        },
        SecretPattern {
            name: "Romania CNP",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::RO_CNP_RE),
        },
        SecretPattern {
            name: "Russia SNILS",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b\d{3}-\d{3}-\d{3}\s\d{2}\b"),
        },
        SecretPattern {
            name: "Poland PESEL (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::PESEL_RE),
        },
        SecretPattern {
            name: "Netherlands BSN (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::BSN_RE),
        },
        SecretPattern {
            name: "Belgium Rijksregisternummer (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::BE_RRN_RE),
        },
        SecretPattern {
            name: "France NIR (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::FR_NIR_RE),
        },
    ]
}
