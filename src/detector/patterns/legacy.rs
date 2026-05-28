use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "AWS Access Key ID",
            category: "Cloud Secret",
            severity: Severity::Critical,
            regex: re(r"(?i)AKIA[0-9A-Z]{16}"),
        },
        SecretPattern {
            name: "GitHub Personal Access Token",
            category: "VCS Token",
            severity: Severity::Critical,
            regex: re(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_.]{36,600}"),
        },
        SecretPattern {
            name: "GitLab Personal Access Token",
            category: "VCS Token",
            severity: Severity::Critical,
            regex: re(r"glpat-[A-Za-z0-9\-_]{20,40}"),
        },
        SecretPattern {
            name: "GitLab Personal Access Token (routable)",
            category: "VCS Token",
            severity: Severity::Critical,
            regex: re(r"\bglpat-[0-9A-Za-z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b"),
        },
        SecretPattern {
            name: "Slack Bot Token",
            category: "Messaging Token",
            severity: Severity::Critical,
            regex: re(&format!("{}oxb-[0-9A-Za-z\\-]{{10,80}}", "x")),
        },
        SecretPattern {
            name: "Slack Webhook URL",
            category: "Messaging Token",
            severity: Severity::Critical,
            regex: re(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        },
        SecretPattern {
            name: "Generic API Key",
            category: "API Secret",
            severity: Severity::High,
            regex: re(
                r#"(?i)(api[_-]?key|apikey|api[_-]?secret|app[_-]?secret)['"]?\s*[:=]\s*['"][A-Za-z0-9_\-]{16,64}['"]"#,
            ),
        },
        SecretPattern {
            name: "Bearer Token",
            category: "Auth Token",
            severity: Severity::High,
            regex: re(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,200}"),
        },
        SecretPattern {
            // Full PEM block: BEGIN..END inclusive. Lazy body match so two keys
            // in the same input form two spans, not one giant span. Covers
            // optional " BLOCK" suffix used by PGP. The BEGIN-line patterns
            // below stay as fallbacks for truncated input where END is absent.
            name: "Private Key Block",
            category: "Crypto Key",
            severity: Severity::Critical,
            regex: re(
                r"(?s)-----BEGIN[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----",
            ),
        },
        SecretPattern {
            name: "Private Key (RSA/DSA/EC)",
            category: "Crypto Key",
            severity: Severity::Critical,
            regex: re(r"-----BEGIN\s?(RSA|DSA|EC|OPENSSH|PGP)?\s?PRIVATE KEY-----"),
        },
        SecretPattern {
            name: "JWT Token",
            category: "Auth Token",
            severity: Severity::High,
            regex: re(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
        },
        SecretPattern {
            name: "JWE Token",
            category: "Auth Token",
            severity: Severity::High,
            regex: re(
                r"\beyJ[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{8,}",
            ),
        },
        SecretPattern {
            name: "Google OAuth Client Secret",
            category: "OAuth Secret",
            severity: Severity::Critical,
            regex: re(r"(?i)GOCSPX-[A-Za-z0-9_\-]{20,40}"),
        },
        SecretPattern {
            // The bare `24.6.27` length triple collides with arbitrary
            // dot-separated identifiers of those exact lengths (commit
            // hashes, version strings). Real Discord tokens always sit
            // behind one of these labels in Discord's docs and SDKs.
            name: "Discord Bot Token",
            category: "Messaging Token",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)(?:authorization:\s*(?:bot|bearer)\s+|discord[_-]?(?:bot[_-]?)?token\s*[:=]\s*['"]?|client\.login\(['"])[A-Za-z0-9_\-]{24,28}\.[A-Za-z0-9_\-]{6,7}\.[A-Za-z0-9_\-]{27,38}"#,
            ),
        },
        SecretPattern {
            name: "Stripe API Key",
            category: "Payment Secret",
            severity: Severity::Critical,
            regex: re(&format!(
                "(?:{}k_live|pk_live|{}k_test|pk_test)_[A-Za-z0-9]{{24,40}}",
                "s", "s"
            )),
        },
        SecretPattern {
            name: "Twilio API Key",
            category: "Cloud Secret",
            severity: Severity::High,
            regex: re(r"SK[A-Za-z0-9]{32}"),
        },
        SecretPattern {
            name: "Docker Registry Auth",
            category: "Cloud Secret",
            severity: Severity::High,
            // Was a bare `auth=` keyword which fired on any OAuth callback URL
            // or config line. Real Docker registry auths leak as the `"auth"`
            // JSON field inside `~/.docker/config.json` dumps, so anchor on
            // that JSON-key form.
            regex: re(r#"(?i)"auth"\s*:\s*"[A-Za-z0-9+/=]{40,200}""#),
        },
        SecretPattern {
            name: "Social Security Number",
            category: "PII - Government ID",
            severity: Severity::Critical,
            regex: re(crate::detector::validators::US_SSN_RE),
        },
        SecretPattern {
            name: "US Passport Number",
            category: "PII - Government ID",
            severity: Severity::High,
            // Was a bare `\b\d{9}\b` - it redacted every 9-digit order/zip/
            // tracking number. A US passport book number only has meaning
            // when labeled, so require the keyword.
            regex: re(r"(?i)\bpassports?\s*(?:no\.?|number|#|:)?\s*[:#]?\s*(\d{9})\b"),
        },
        SecretPattern {
            // The optional :port suffix uses {1,5} digits. A 5-digit value above
            // 65535 (e.g. :99999) still matches; we accept the over-redaction
            // because the bug being fixed is "port survived in the clipboard".
            name: "IPv4 Address",
            category: "PII - Network",
            severity: Severity::Low,
            regex: re(
                r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)(?::\d{1,5})?\b",
            ),
        },
        SecretPattern {
            // Colon or dash separated: aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff
            name: "MAC Address",
            category: "PII - Network",
            severity: Severity::Low,
            regex: re(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
        },
        SecretPattern {
            // Cisco dot notation: aabb.ccdd.eeff
            name: "MAC Address",
            category: "PII - Network",
            severity: Severity::Low,
            regex: re(r"\b(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b"),
        },
        // Bare 12-hex (aabbccddeeff) MAC form removed: with no separators it
        // is indistinguishable from a 12-char git short hash, a hex id, or a
        // UUID's last group, so it redacted ordinary clipboard text. A real
        // MAC almost always carries `:`/`-`/`.` separators, which the two
        // patterns above still catch.
        SecretPattern {
            name: "Database Connection String",
            category: "Database Secret",
            severity: Severity::Critical,
            regex: re(
                r"(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss)://[A-Za-z0-9_%]+:[^@\s]+@",
            ),
        },
        SecretPattern {
            name: "Slack Token (xapp)",
            category: "Messaging Token",
            severity: Severity::Critical,
            regex: re(r"xapp-[0-9A-Za-z\-]{10,80}"),
        },
        SecretPattern {
            name: "NPM Token",
            category: "Package Registry",
            severity: Severity::Critical,
            regex: re(r"(?i)npm_[A-Za-z0-9]{36}"),
        },
        SecretPattern {
            name: "SSH Private Key inline",
            category: "Crypto Key",
            severity: Severity::Critical,
            regex: re(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        },
        SecretPattern {
            name: "OpenAI API Key",
            category: "AI Secret",
            severity: Severity::Critical,
            regex: re(r"\bsk-(?:[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{48})\b"),
        },
        SecretPattern {
            name: "Google API Key",
            category: "Cloud Secret",
            severity: Severity::Critical,
            regex: re(r"AIza[0-9A-Za-z\-_]{35}"),
        },
        SecretPattern {
            name: "Google OAuth Access Token",
            category: "OAuth Token",
            severity: Severity::Critical,
            regex: re(r"ya29\.[0-9A-Za-z\-_]{50,200}"),
        },
        SecretPattern {
            name: "Azure Storage Account Key",
            category: "Cloud Secret",
            severity: Severity::Critical,
            regex: re(r"(?i)AccountKey=[A-Za-z0-9+/=]{80,100}"),
        },
        SecretPattern {
            name: "Azure Service Principal",
            category: "Cloud Secret",
            severity: Severity::Critical,
            regex: re(r"(?i)AZURE_.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
        },
        SecretPattern {
            name: "Telegram Bot Token",
            category: "Messaging Token",
            severity: Severity::Critical,
            regex: re(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35,45}\b"),
        },
        SecretPattern {
            name: "Kubernetes Service Account Token",
            category: "Container Secret",
            severity: Severity::Critical,
            regex: re(
                r"eyJhbGciOiJSUzI1NiIsImtpZCI6[A-Za-z0-9_\-]{50,500}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
            ),
        },
        SecretPattern {
            name: "PGP Private Key Block",
            category: "Crypto Key",
            severity: Severity::Critical,
            regex: re(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        },
        SecretPattern {
            name: "DigitalOcean Personal Access Token",
            category: "Cloud Secret",
            severity: Severity::Critical,
            regex: re(r"(?i)dop_v1_[0-9a-f]{40}"),
        },
    ]
}
