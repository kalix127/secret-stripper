use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "India PAN",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
        },
        SecretPattern {
            name: "India GSTIN",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z0-9]Z[A-Z0-9]\b"),
        },
        SecretPattern {
            name: "India IFSC",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        },
        SecretPattern {
            name: "India Aadhaar (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"(?i)\baadhaar[:#\s]+[2-9]\d{3}\s?\d{4}\s?\d{4}\b"),
        },
        SecretPattern {
            name: "Brazil CPF",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::BR_CPF_RE),
        },
        SecretPattern {
            name: "Brazil CNPJ",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::BR_CNPJ_RE),
        },
        SecretPattern {
            name: "Chile RUT",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b\d{1,2}\.\d{3}\.\d{3}-[\dkK]\b"),
        },
        SecretPattern {
            name: "Argentina CUIL/CUIT",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b(?:20|23|24|27|30|33|34)-\d{8}-\d\b"),
        },
        SecretPattern {
            name: "China Resident ID",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::CN_RID_RE),
        },
        SecretPattern {
            name: "China Passport",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[GE]\d{8}\b"),
        },
        SecretPattern {
            name: "Taiwan National ID",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[A-Z][12]\d{8}\b"),
        },
        SecretPattern {
            name: "Korea RRN",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b\d{6}-[1-8]\d{6}\b"),
        },
        SecretPattern {
            name: "Pakistan CNIC",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[1-7]\d{4}-\d{7}-\d\b"),
        },
        SecretPattern {
            name: "Sri Lanka NIC (old)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b\d{9}[VvXx]\b"),
        },
        SecretPattern {
            name: "Singapore NRIC/FIN",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[STFGM]\d{7}[A-Z]\b"),
        },
        SecretPattern {
            name: "Malaysia MyKad",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b\d{6}-\d{2}-\d{4}\b"),
        },
        SecretPattern {
            name: "Indonesia NPWP",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b\d{2}\.\d{3}\.\d{3}\.\d-\d{3}\.\d{3}\b"),
        },
        SecretPattern {
            name: "Indonesia NIK (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"(?i)\bnik[:#\s]+\d{16}\b"),
        },
        SecretPattern {
            name: "UAE Emirates ID",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b784-\d{4}-\d{7}-\d\b"),
        },
        SecretPattern {
            name: "Egypt National ID",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[23]\d{13}\b"),
        },
        SecretPattern {
            name: "Ghana Card PIN",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\bGHA-\d{9}-\d\b"),
        },
        SecretPattern {
            name: "South Africa ID (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"(?i)\bsouth africa id[:#\s]+\d{13}\b"),
        },
        SecretPattern {
            name: "Turkey TC Kimlik No",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::TR_TCKN_RE),
        },
        SecretPattern {
            name: "Israel Teudat Zehut (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::IL_TZ_RE),
        },
        SecretPattern {
            name: "Australia TFN (labeled)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"(?i)\btfn[:#\s]+\d{3}\s?\d{3}\s?\d{2,3}\b"),
        },
        SecretPattern {
            name: "New Zealand NHI",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b[A-HJ-NP-Z]{3}\d{4}\b"),
        },
        SecretPattern {
            name: "Passport MRZ (TD3)",
            category: "PII / Gov ID",
            severity: Severity::Critical,
            regex: re(crate::detector::validators::MRZ_TD3_RE),
        },
        SecretPattern {
            name: "Canada Driver's License (distinctive province format)",
            category: "PII / Gov ID",
            severity: Severity::Medium,
            regex: re(r"\b(?:[A-Z]\d{4}-?\d{5}\d[0156]\d[0123]\d|[A-Z]\d{12}|[A-Z]{5}\d{9})\b"),
        },
    ]
}
