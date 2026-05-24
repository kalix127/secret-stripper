use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Consumer DNA Raw Data Header",
            category: "PII / Biometric",
            severity: Severity::High,
            regex: re(r"(?i)(?:#\s*)?\brsid\s+chromosome\s+position\s+genotype\b"),
        },
        SecretPattern {
            name: "VCF Genomic File Header",
            category: "PII / Biometric",
            severity: Severity::High,
            regex: re(r"##fileformat=VCFv4"),
        },
        SecretPattern {
            name: "FASTQ Sequence Record",
            category: "PII / Biometric",
            severity: Severity::High,
            regex: re(r"(?m)^@[^\n]{1,80}\r?\n[ACGTNacgtn]{15,}\r?\n\+"),
        },
        SecretPattern {
            name: "FASTA Sequence Record",
            category: "PII / Biometric",
            severity: Severity::High,
            regex: re(r"(?m)^>[^\n]{1,80}\r?\n[ACDEFGHIKLMNPQRSTVWYacgtn*]{25,}"),
        },
    ]
}
