use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Okta API Token (SSWS)",
            category: "SaaS / IAM",
            severity: Severity::Critical,
            regex: re(r"(?i)\bSSWS [A-Za-z0-9_-]{40,}\b"),
        },
        SecretPattern {
            name: "Auth0 Management API Token",
            category: "SaaS / IAM",
            severity: Severity::Critical,
            regex: re(
                r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]*?aud[A-Za-z0-9_-]*?\.[A-Za-z0-9_-]{10,}",
            ),
        },
        SecretPattern {
            // `DI<18 upper/digit>` collides with any UPPER_SNAKE constant of
            // that shape. Real IKs always appear paired with a duo / ikey /
            // integration_key label in Duo's own docs and SDK examples.
            name: "Duo Security Integration Key",
            category: "SaaS / IAM",
            severity: Severity::High,
            regex: re(
                r#"(?i)(?:duo[^\n]{0,50}|integration[_-]?key\s*[:=]\s*['"]?|\bikey\b\s*[:=]?\s*['"]?)\bDI[A-Z0-9]{18}\b"#,
            ),
        },
        SecretPattern {
            name: "Duo Security API Hostname",
            category: "SaaS / IAM",
            severity: Severity::Low,
            regex: re(r"\bapi-[a-f0-9]{8}\.duosecurity\.com\b"),
        },
        SecretPattern {
            name: "1Password Service Account Token",
            category: "SaaS / IAM",
            severity: Severity::Critical,
            regex: re(r"\bops_eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        },
        SecretPattern {
            name: "1Password Secret Reference URI",
            category: "SaaS / IAM",
            severity: Severity::Low,
            regex: re(r"op://[A-Za-z0-9_ -]+/[A-Za-z0-9_ -]+/[A-Za-z0-9_ -]+"),
        },
        SecretPattern {
            name: "Bitwarden Secrets Manager Access Token",
            category: "SaaS / IAM",
            severity: Severity::Critical,
            regex: re(
                r"\b0\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[A-Za-z0-9+/=_-]{20,}:[A-Za-z0-9+/=_-]{20,}",
            ),
        },
        SecretPattern {
            name: "Microsoft Entra ID Refresh Token",
            category: "SaaS / IAM",
            severity: Severity::Critical,
            regex: re(r"\b0\.[A-Za-z0-9_-]{200,}"),
        },
        SecretPattern {
            name: "SAML Certificate (PEM)",
            category: "SaaS / IAM",
            severity: Severity::Medium,
            regex: re(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----"),
        },
        SecretPattern {
            name: "Salesforce Session ID",
            category: "SaaS / IAM",
            severity: Severity::Critical,
            regex: re(r"\b00D[A-Za-z0-9]{12,15}![A-Za-z0-9._]{80,200}\b"),
        },
        SecretPattern {
            name: "Salesforce Refresh Token",
            category: "SaaS / IAM",
            severity: Severity::Critical,
            regex: re(r"\b5Aep[A-Za-z0-9._=-]{40,}\b"),
        },
        SecretPattern {
            name: "Stytch Secret",
            category: "SaaS / IAM",
            severity: Severity::Critical,
            regex: re(r"\bsecret-(?:test|live)-[0-9a-zA-Z=_-]{36}\b"),
        },
        SecretPattern {
            name: "Stytch Project ID",
            category: "SaaS / IAM",
            severity: Severity::Low,
            regex: re(r"\bproject-(?:test|live)-[0-9a-f-]{36}\b"),
        },
        SecretPattern {
            name: "Ory API Key",
            category: "SaaS / IAM",
            severity: Severity::Critical,
            regex: re(r"\bory_(?:pat|wak|apikey|st|at|rt|ac)_[A-Za-z0-9._-]{20,}\b"),
        },
        SecretPattern {
            name: "Ramp API Credential",
            category: "SaaS / IAM",
            severity: Severity::Critical,
            regex: re(r"\bramp_(?:id|sec)_[A-Za-z0-9]{20,}\b"),
        },
        SecretPattern {
            name: "Hex API Token",
            category: "SaaS / IAM",
            severity: Severity::Critical,
            regex: re(r"\bhxt[pw]_[0-9a-f]{96}\b"),
        },
        SecretPattern {
            name: "Prefect API Key",
            category: "SaaS / IAM",
            severity: Severity::Critical,
            regex: re(r"\bpn[ub]_[A-Za-z0-9]{36}\b"),
        },
    ]
}
