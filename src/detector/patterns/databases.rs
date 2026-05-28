use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "JDBC Connection String with Password",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"jdbc:[a-z0-9]+://[^\s?]+\?(?:[^\s&]+&)*[Pp]assword=[^\s&]+"),
        },
        SecretPattern {
            name: "ODBC/SQLServer Connection String",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"(?i)(?:Server|Data Source)=[^;\s]+;[^\n]*?Password=[^;\s]+"),
        },
        SecretPattern {
            name: "AMQP Connection String with Credentials",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"amqps?://[A-Za-z0-9_%.+-]+:[^@\s]+@[A-Za-z0-9.-]+"),
        },
        SecretPattern {
            name: "Kafka SASL Connection String",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"SASL_(?:PLAINTEXT|SSL)://[A-Za-z0-9_%.+-]+:[^@\s]+@[A-Za-z0-9.-]+:\d{2,5}"),
        },
        SecretPattern {
            name: "ClickHouse Cloud URL with Credentials",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"https://[A-Za-z0-9_%.+-]+:[^@\s]+@[a-z0-9-]+\.clickhouse\.cloud"),
        },
        SecretPattern {
            name: "Elasticsearch URL with Credentials",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(
                r"https?://[A-Za-z0-9_%.+-]+:[^@\s]+@[A-Za-z0-9.-]+(?:\.elastic-cloud\.com|:9200)",
            ),
        },
        SecretPattern {
            name: "MongoDB Atlas SRV Host",
            category: "Databases",
            severity: Severity::Medium,
            regex: re(r"\b[a-z0-9-]+\.[a-z0-9]{5}\.mongodb\.net\b"),
        },
        SecretPattern {
            name: "Databricks OAuth Token",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"\bdose[A-Za-z0-9]{32,}\b"),
        },
        SecretPattern {
            name: "PlanetScale Database Password",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"\bpscale_pw_[A-Za-z0-9_.-]{20,}"),
        },
        SecretPattern {
            name: "Neon Project API Key",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"\bnapi_[A-Za-z0-9_-]{40,}"),
        },
        SecretPattern {
            name: "CockroachDB Cloud API Key",
            category: "Databases",
            severity: Severity::High,
            regex: re(r"\bCCDB1_[A-Za-z0-9]{8,}_[A-Za-z0-9]{8,}\b"),
        },
        SecretPattern {
            name: "FaunaDB Server Key",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"\bfnAA[A-Za-z0-9_-]{40,}\b"),
        },
        SecretPattern {
            name: "Firebase Cloud Messaging Server Key (legacy)",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{130,}"),
        },
        SecretPattern {
            name: "Firebase Database URL with Secret",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"https://[a-z0-9-]+\.firebaseio\.com/[^\s]*\.json\?auth=[A-Za-z0-9_-]{10,}"),
        },
        SecretPattern {
            name: "MotherDuck Service Token",
            category: "Databases",
            severity: Severity::High,
            regex: re(r"motherduck_token=eyJ[A-Za-z0-9_.-]{20,}"),
        },
        SecretPattern {
            name: "Convex Deploy Key",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"\bprod:[a-z0-9-]+:[A-Za-z0-9_-]{40,}"),
        },
        SecretPattern {
            name: "Xata API Key",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"\bxau_[A-Za-z0-9]{32,}\b"),
        },
        SecretPattern {
            name: "Upstash Redis REST Token",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"UPSTASH_REDIS_REST_TOKEN[=:\s]+[A-Za-z0-9_.-]{40,}"),
        },
        SecretPattern {
            name: "Supabase Secret Key",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"\bsb_secret_[A-Za-z0-9_-]{20,}\b"),
        },
        SecretPattern {
            name: "Supabase Publishable Key",
            category: "Databases",
            severity: Severity::Low,
            regex: re(r"\bsb_publishable_[A-Za-z0-9_-]{20,}\b"),
        },
        SecretPattern {
            name: "Supabase Service Key (legacy sbp_)",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"\bsbp_[a-z0-9]{40}\b"),
        },
        SecretPattern {
            name: "PlanetScale Database Token",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"\bpscale_tkn_[A-Za-z0-9_=.-]{32,}\b"),
        },
        SecretPattern {
            name: "PlanetScale OAuth Token",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"\bpscale_oauth_[A-Za-z0-9_=.-]{32,}\b"),
        },
        SecretPattern {
            name: "InfluxDB v3 API Token",
            category: "Databases",
            severity: Severity::Critical,
            regex: re(r"\bapiv3_[A-Za-z0-9_-]{40,}\b"),
        },
    ]
}
