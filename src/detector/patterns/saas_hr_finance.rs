use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Workday Web Services Endpoint URL",
            category: "SaaS / HR",
            severity: Severity::Medium,
            regex: re(
                r"https://[a-z0-9-]+\.workday\.com/ccx/service/[a-z0-9_]+/[A-Za-z_]+/v[0-9]+(?:\.[0-9]+)?",
            ),
        },
        SecretPattern {
            name: "ADP API Credentials",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)[a-z0-9.-]*\.api\.adp\.com[^\n]{0,40}?client_secret[\s:="']+[A-Za-z0-9_-]{20,}\b"#,
            ),
        },
        SecretPattern {
            name: "Gusto API Bearer Token",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)api\.gusto(?:-demo)?\.com[^\n]{0,40}?bearer[\s:="']+[A-Za-z0-9_-]{20,}\b"#,
            ),
        },
        SecretPattern {
            name: "Rippling API Bearer Token",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)[a-z0-9.-]*rippling\.com[^\n]{0,40}?bearer[\s:="']+[A-Za-z0-9_-]{20,}\b"#,
            ),
        },
        SecretPattern {
            name: "Deel API Bearer Token",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)(?:api\.deel\.com|[a-z0-9.-]*letsdeel\.com)[^\n]{0,40}?bearer[\s:="']+[A-Za-z0-9_-]{20,}\b"#,
            ),
        },
        SecretPattern {
            name: "BambooHR API Key (Basic Auth)",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(r"\bhttps://[A-Za-z0-9]{40}:x@[a-z0-9-]+\.bamboohr\.com\b"),
        },
        SecretPattern {
            name: "Greenhouse Harvest API Key",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)harvest\.greenhouse\.io[^\n]{0,40}?(?:api[_-]?key|token)[\s:="']+[a-z0-9]{40}\b"#,
            ),
        },
        SecretPattern {
            name: "Lever API Key",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)api(?:\.sandbox)?\.lever\.co[^\n]{0,40}?(?:api[_-]?key|key)[\s:="']+[A-Za-z0-9_-]{20,}\b"#,
            ),
        },
        SecretPattern {
            name: "Personio API Credentials",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)api\.personio\.de[^\n]{0,40}?client_secret[\s:="']+[A-Za-z0-9_-]{20,}\b"#,
            ),
        },
        SecretPattern {
            name: "Langfuse Public Key",
            category: "SaaS / HR",
            severity: Severity::High,
            regex: re(r"\bpk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
        },
        SecretPattern {
            name: "Langfuse Secret Key",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(r"\bsk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
        },
        SecretPattern {
            name: "Weights & Biases API Key",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(r#"(?i)WANDB_API_KEY[\s:="']+[a-f0-9]{40}\b"#),
        },
        SecretPattern {
            name: "Voyage AI API Key",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(r"\bpa-[A-Za-z0-9_-]{40,}\b"),
        },
        SecretPattern {
            name: "Comet ML API Key",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(r#"(?i)COMET_API_KEY[\s:="']+[A-Za-z0-9]{32,}\b"#),
        },
        SecretPattern {
            name: "Looker API3 Credentials",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)client_id[\s:="']+[A-Za-z0-9]{20}[\s,;]+[^\n]{0,30}?client_secret[\s:="']+[A-Za-z0-9]{24}\b"#,
            ),
        },
        SecretPattern {
            name: "Tableau Personal Access Token",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)tableau[^\n]{0,40}?(?:pat[_-]?secret|personal[_-]?access[_-]?token)[\s:="']+[A-Za-z0-9=]{18,}\b"#,
            ),
        },
        SecretPattern {
            name: "Metabase API Key",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(r#"(?i)X-API-KEY[\s:="']+mb_[A-Za-z0-9+/=_-]{20,}\b"#),
        },
        SecretPattern {
            name: "Fivetran API Credentials",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)api\.fivetran\.com[^\n]{0,40}?(?:api[_-]?secret|secret)[\s:="']+[A-Za-z0-9]{20,}\b"#,
            ),
        },
        SecretPattern {
            name: "dbt Cloud Service Token",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)cloud\.getdbt\.com[^\n]{0,40}?(?:service[_-]?token|token)[\s:="']+[a-zA-Z0-9]{36,}\b"#,
            ),
        },
        SecretPattern {
            name: "Hightouch API Key",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)api\.hightouch\.com[^\n]{0,40}?(?:api[_-]?key|bearer)[\s:="']+[A-Za-z0-9_-]{20,}\b"#,
            ),
        },
        SecretPattern {
            name: "Census API Key",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(r"\bsecret-token:[A-Za-z0-9+/=_-]{20,}\b"),
        },
        SecretPattern {
            name: "Airbyte Cloud Workspace Token",
            category: "SaaS / HR",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)[a-z0-9.-]*airbyte\.com[^\n]{0,40}?(?:access[_-]?token|bearer)[\s:="']+[A-Za-z0-9_.-]{20,}\b"#,
            ),
        },
    ]
}
