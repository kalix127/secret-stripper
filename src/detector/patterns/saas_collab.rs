use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "ClickUp Personal Access Token",
            category: "SaaS / Collab",
            severity: Severity::High,
            regex: re(r"\bpk_[0-9]{4,}_[A-Z0-9]{32,}\b"),
        },
        SecretPattern {
            name: "Airtable Personal Access Token",
            category: "SaaS / Collab",
            severity: Severity::High,
            regex: re(r"\bpat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64}\b"),
        },
        SecretPattern {
            // The bare `key<14>` shape collided with arbitrary identifiers
            // starting with `key`. Real legacy keys only appear under an
            // Airtable-context label or in the API URL.
            name: "Airtable Legacy API Key",
            category: "SaaS / Collab",
            severity: Severity::High,
            regex: re(
                r#"(?i)(?:airtable[^\n]{0,80}|authorization:\s*bearer\s+|x-api-key:\s*|airtable[._-]?api[._-]?key\s*[:=]\s*['"]?)key[A-Za-z0-9]{14}\b"#,
            ),
        },
        SecretPattern {
            name: "Contentful Content Management PAT",
            category: "SaaS / Collab",
            severity: Severity::Critical,
            regex: re(r"\bCFPAT-[A-Za-z0-9_-]{40,}\b"),
        },
        SecretPattern {
            name: "Dropbox Short-Lived OAuth Token",
            category: "SaaS / Collab",
            severity: Severity::Critical,
            regex: re(r"\bsl\.[A-Za-z0-9_-]{130,}\b"),
        },
        SecretPattern {
            name: "ServiceNow Instance URL",
            category: "SaaS / Collab",
            severity: Severity::Medium,
            regex: re(r"https://[a-z0-9-]+\.service-now\.com"),
        },
        SecretPattern {
            name: "Zendesk API Token (email/token)",
            category: "SaaS / Collab",
            severity: Severity::Critical,
            regex: re(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+/token:[A-Za-z0-9]{40}\b"),
        },
        SecretPattern {
            name: "Notion Integration Token",
            category: "SaaS / Collab",
            severity: Severity::Critical,
            regex: re(r"\b(?:secret_|ntn_)[A-Za-z0-9]{40,}\b"),
        },
        SecretPattern {
            name: "Linear API Key",
            category: "SaaS / Collab",
            severity: Severity::Critical,
            regex: re(r"\blin_api_[A-Za-z0-9]{40,}\b"),
        },
        SecretPattern {
            name: "Asana Personal Access Token",
            category: "SaaS / Collab",
            severity: Severity::Critical,
            regex: re(r"\b[12]/[0-9]{16}:[A-Za-z0-9]{32}\b"),
        },
        SecretPattern {
            name: "Dropbox Refresh Token",
            category: "SaaS / Collab",
            severity: Severity::Critical,
            regex: re(r"\b[a-z0-9]{11}AAAAAAAAAA[A-Za-z0-9=_-]{43}\b"),
        },
    ]
}
