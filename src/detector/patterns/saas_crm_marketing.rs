use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "HubSpot Private App Token",
            category: "SaaS / CRM",
            severity: Severity::Critical,
            regex: re(
                r"\bpat-(?:na1|na2|na3|eu1|ap1)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            ),
        },
        SecretPattern {
            name: "Salesforce Session ID Access Token",
            category: "SaaS / CRM",
            severity: Severity::Critical,
            regex: re(r"\b00D[A-Za-z0-9]{12,15}![A-Za-z0-9._]{80,200}\b"),
        },
        SecretPattern {
            name: "Salesforce OAuth Refresh Token",
            category: "SaaS / CRM",
            severity: Severity::Critical,
            regex: re(r"\b5Aep[A-Za-z0-9._=-]{40,}"),
        },
        SecretPattern {
            name: "Salesforce Connected App Consumer Key",
            category: "SaaS / CRM",
            severity: Severity::High,
            regex: re(r"\b3MVG9[A-Za-z0-9._]{50,}"),
        },
        SecretPattern {
            name: "Pipedrive API Token",
            category: "SaaS / CRM",
            severity: Severity::Critical,
            regex: re(r#"(?i)pipedrive[^\n]{0,40}?api[_-]?token[\s:="']+[a-f0-9]{40}\b"#),
        },
        SecretPattern {
            name: "Close CRM API Key",
            category: "SaaS / CRM",
            severity: Severity::Critical,
            regex: re(r"\bapi_[A-Za-z0-9]{40,}\b"),
        },
        SecretPattern {
            name: "Zoho Self-Client API Key",
            category: "SaaS / CRM",
            severity: Severity::Critical,
            regex: re(r"\b1000\.[a-f0-9]{32}\.[a-f0-9]{32}\b"),
        },
        SecretPattern {
            name: "Zoho OAuth Refresh Token",
            category: "SaaS / CRM",
            severity: Severity::Critical,
            regex: re(r"\b1000\.[A-Za-z0-9]{40,}\.[A-Za-z0-9]{40,}\b"),
        },
        SecretPattern {
            name: "Marketo REST Endpoint URL",
            category: "SaaS / CRM",
            severity: Severity::Medium,
            regex: re(r"https://[0-9]{3}-[A-Z]{3}-[0-9]{3}\.mktorest\.com/[^\s]*"),
        },
        SecretPattern {
            name: "Marketo Munchkin ID",
            category: "SaaS / CRM",
            severity: Severity::Low,
            regex: re(r#"(?i)munchkin[\s:="']+[0-9]{3}-[A-Z]{3}-[0-9]{3}\b"#),
        },
        SecretPattern {
            name: "Mandrill API Key",
            category: "SaaS / CRM",
            severity: Severity::Critical,
            regex: re(r#"(?i)mandrill[^\n]{0,40}?api[_-]?key[\s:="']+[A-Za-z0-9_-]{22}\b"#),
        },
        SecretPattern {
            name: "Klaviyo Private API Key",
            category: "SaaS / CRM",
            severity: Severity::Critical,
            regex: re(r"\bpk_[A-Za-z0-9]{34}\b"),
        },
        SecretPattern {
            name: "Iterable API Key",
            category: "SaaS / CRM",
            severity: Severity::Critical,
            regex: re(r#"(?i)iterable[^\n]{0,40}?api[_-]?key[\s:="']+[a-f0-9]{32}\b"#),
        },
        SecretPattern {
            name: "Braze REST API Key",
            category: "SaaS / CRM",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)braze[^\n]{0,40}?api[_-]?key[\s:="']+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"#,
            ),
        },
        SecretPattern {
            name: "Webflow Site API Token",
            category: "SaaS / CRM",
            severity: Severity::High,
            regex: re(r#"(?i)webflow[^\n]{0,40}?(?:api[_-]?token|token)[\s:="']+[a-f0-9]{64}\b"#),
        },
        SecretPattern {
            name: "Customer.io Track API Credentials",
            category: "SaaS / CRM",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)site_id[\s:="']+[A-Za-z0-9]{20}[\s,;]+[^\n]{0,30}?(?:api[_-]?key|track[_-]?key)[\s:="']+[A-Za-z0-9]{20}\b"#,
            ),
        },
        SecretPattern {
            name: "ActiveCampaign API Credentials",
            category: "SaaS / CRM",
            severity: Severity::Critical,
            regex: re(r"https://[a-z0-9-]+\.api-us[0-9]\.com[^\s]*[?&]api_key=[a-f0-9]{40,}"),
        },
        SecretPattern {
            name: "ConvertKit API Secret",
            category: "SaaS / CRM",
            severity: Severity::Critical,
            regex: re(r#"(?i)convertkit[^\n]{0,40}?api[_-]?secret[\s:="']+[A-Za-z0-9_-]{20,}\b"#),
        },
        SecretPattern {
            name: "Drip API Token",
            category: "SaaS / CRM",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)getdrip[^\n]{0,40}?(?:api[_-]?token|token)[\s:="']+[A-Za-z0-9]{20,}\b"#,
            ),
        },
        SecretPattern {
            name: "Zapier Catch Webhook URL",
            category: "SaaS / CRM",
            severity: Severity::High,
            regex: re(r"https://hooks\.zapier\.com/hooks/catch/[0-9]+/[A-Za-z0-9]+/?"),
        },
    ]
}
