use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "OpenCTI API Token (new format)",
            category: "Threat Intel",
            severity: Severity::Critical,
            regex: re(r"\bflgrn_octi_tkn_[A-Za-z0-9]{60,}"),
        },
        SecretPattern {
            name: "GitGuardian API Key",
            category: "Threat Intel",
            severity: Severity::Critical,
            regex: re(r"\bgg[a-z]{1,3}_[A-Za-z0-9]{25,}"),
        },
        SecretPattern {
            name: "Snyk Service Account Token",
            category: "Threat Intel",
            severity: Severity::Critical,
            regex: re(r"\bsnyk_st_[A-Za-z0-9]{40,}"),
        },
        SecretPattern {
            name: "Snyk API Token",
            category: "Threat Intel",
            severity: Severity::Critical,
            regex: re(
                r"(?i)Authorization:\s*token\s+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            ),
        },
        SecretPattern {
            name: "Bugcrowd API Token",
            category: "Threat Intel",
            severity: Severity::Critical,
            regex: re(r"(?i)Authorization:\s*Token\s+[A-Za-z0-9]+:[A-Za-z0-9_-]{40,}"),
        },
        SecretPattern {
            name: "HackerOne API Token",
            category: "Threat Intel",
            severity: Severity::Critical,
            regex: re(r"(?i)X-H1-Token:\s*[A-Za-z0-9_]+:[A-Za-z0-9+/=]{20,}"),
        },
        SecretPattern {
            name: "MaxMind Account License Key",
            category: "Threat Intel",
            severity: Severity::High,
            regex: re(r"\b\d{4,7}:[A-Za-z0-9_]{40}\b"),
        },
        SecretPattern {
            name: "AbuseIPDB API Key",
            category: "Threat Intel",
            severity: Severity::High,
            regex: re(r"(?i)Key:\s*[a-f0-9]{80}\b"),
        },
        SecretPattern {
            name: "VirusTotal API Key",
            category: "Threat Intel",
            severity: Severity::High,
            regex: re(r"(?i)x-apikey:\s*[a-f0-9]{64}\b"),
        },
        SecretPattern {
            name: "AlienVault OTX API Key",
            category: "Threat Intel",
            severity: Severity::High,
            regex: re(r"(?i)X-OTX-API-KEY:\s*[a-f0-9]{64}\b"),
        },
        SecretPattern {
            name: "Shodan API Key",
            category: "Threat Intel",
            severity: Severity::High,
            regex: re(r"(?i)SHODAN_API_KEY=[A-Za-z0-9]{32}\b"),
        },
        SecretPattern {
            name: "MISP Authkey",
            category: "Threat Intel",
            severity: Severity::Critical,
            regex: re(r"(?i)Authorization:\s*[A-Za-z0-9]{40}\b"),
        },
        SecretPattern {
            name: "urlscan.io API Key",
            category: "Threat Intel",
            severity: Severity::High,
            regex: re(
                r"(?i)API-Key:\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            ),
        },
        SecretPattern {
            name: "SecurityTrails API Key",
            category: "Threat Intel",
            severity: Severity::High,
            regex: re(r"(?i)APIKEY:\s*[A-Za-z0-9]{32}\b"),
        },
        SecretPattern {
            name: "Tenable.io API Keys Header",
            category: "Threat Intel",
            severity: Severity::Critical,
            regex: re(r"(?i)X-ApiKeys:\s*accessKey=[a-f0-9]{64};secretKey=[a-f0-9]{64}"),
        },
        SecretPattern {
            name: "TheHive API Key",
            category: "Threat Intel",
            severity: Severity::Critical,
            regex: re(r"\bthehive_[A-Za-z0-9]{32,}"),
        },
        SecretPattern {
            name: "SpyCloud API Key",
            category: "Threat Intel",
            severity: Severity::Critical,
            regex: re(r"(?i)x-api-key:\s*sc_[A-Za-z0-9]{32,}"),
        },
        SecretPattern {
            name: "Lacework Underscore Secret",
            category: "Threat Intel",
            severity: Severity::Critical,
            regex: re(r#""secret"\s*:\s*"_[A-Za-z0-9]{40,80}""#),
        },
    ]
}
