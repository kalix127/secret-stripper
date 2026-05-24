use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Oracle Cloud Tenancy OCID",
            category: "Cloud / Other",
            severity: Severity::Medium,
            regex: re(r"\bocid1\.tenancy\.oc1\.\.[a-z0-9]{20,}\b"),
        },
        SecretPattern {
            name: "Oracle Cloud User OCID",
            category: "Cloud / Other",
            severity: Severity::Medium,
            regex: re(r"\bocid1\.user\.oc1\.\.[a-z0-9]{20,}\b"),
        },
        SecretPattern {
            name: "Oracle Cloud Compartment OCID",
            category: "Cloud / Other",
            severity: Severity::Low,
            regex: re(r"\bocid1\.compartment\.oc1\.\.[a-z0-9]{20,}\b"),
        },
        SecretPattern {
            name: "Oracle Cloud Vault/Secret OCID",
            category: "Cloud / Other",
            severity: Severity::Medium,
            regex: re(r"\bocid1\.(?:vault|secret)\.oc1\.[a-z0-9-]+\.[a-z0-9]{20,}\b"),
        },
        SecretPattern {
            name: "Oracle Cloud Object Storage Endpoint",
            category: "Cloud / Other",
            severity: Severity::Low,
            regex: re(r"\bobjectstorage\.[a-z0-9-]+\.oraclecloud\.com\b"),
        },
        SecretPattern {
            name: "Alibaba RAM AccessKey ID",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"\bLTAI[A-Za-z0-9]{12,20}\b"),
        },
        SecretPattern {
            name: "Alibaba OSS Signed URL",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"[?&]OSSAccessKeyId=LTAI[A-Za-z0-9]+&Signature=[^&\s]+&Expires=\d+"),
        },
        SecretPattern {
            name: "Tencent Cloud SecretId",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"\bAKID[A-Za-z0-9]{32}\b"),
        },
        SecretPattern {
            name: "Tencent COS Signed URL",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"[?&]q-ak=AKID[A-Za-z0-9]+&[^\s]*q-signature=[a-f0-9]{40}"),
        },
        SecretPattern {
            name: "DigitalOcean OAuth Refresh Token",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"(?i)\bdor_v1_[a-f0-9]{64}\b"),
        },
        SecretPattern {
            name: "DigitalOcean OAuth Access Token",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"(?i)\bdoo_v1_[a-f0-9]{64}\b"),
        },
        SecretPattern {
            name: "DigitalOcean Spaces Access Key",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"\bDO[A-Z0-9]{18}\b"),
        },
        SecretPattern {
            name: "DigitalOcean Spaces Endpoint",
            category: "Cloud / Other",
            severity: Severity::Low,
            regex: re(r"\b[a-z0-9.-]+\.digitaloceanspaces\.com\b"),
        },
        SecretPattern {
            name: "Linode Object Storage Endpoint",
            category: "Cloud / Other",
            severity: Severity::Low,
            regex: re(r"\b[a-z0-9.-]+\.linodeobjects\.com\b"),
        },
        SecretPattern {
            name: "Scaleway Access Key",
            category: "Cloud / Other",
            severity: Severity::High,
            regex: re(r"\bSCW[A-Z0-9]{17}\b"),
        },
        SecretPattern {
            name: "Exoscale API Key",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"\bEXO[A-Za-z0-9]{16,}\b"),
        },
        SecretPattern {
            name: "Fly.io API Token (fo1)",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"\bfo1_[A-Za-z0-9_-]{40,}"),
        },
        SecretPattern {
            name: "Fly.io API Token (macaroon)",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"FlyV1 fm2_[A-Za-z0-9_-]+"),
        },
        SecretPattern {
            name: "Render API Key",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"\brnd_[A-Za-z0-9]{20,}\b"),
        },
        SecretPattern {
            name: "Heroku API Key (HRKU)",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"\bHRKU-[A-Za-z0-9_-]{20,}"),
        },
        SecretPattern {
            name: "Northflank API Token",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"\bnf_[A-Za-z0-9]{40,}"),
        },
        SecretPattern {
            name: "Snowflake Account Endpoint",
            category: "Cloud / Other",
            severity: Severity::Medium,
            regex: re(r"\b[a-z0-9-]+\.[a-z0-9-]+\.snowflakecomputing\.com\b"),
        },
        SecretPattern {
            name: "Databricks PAT",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"\bdapi[a-f0-9]{32}\b"),
        },
        SecretPattern {
            name: "PlanetScale Service Token",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"\bpscale_tkn_[A-Za-z0-9_-]{40,}"),
        },
        SecretPattern {
            name: "PlanetScale OAuth Token",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"\bpscale_oauth_[A-Za-z0-9_-]{20,}"),
        },
        SecretPattern {
            name: "Cloudflare R2 S3 Endpoint",
            category: "Cloud / Other",
            severity: Severity::Low,
            regex: re(r"\b[a-z0-9-]+\.r2\.cloudflarestorage\.com\b"),
        },
        SecretPattern {
            name: "Vercel Access Token",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"\b(?:vc[piark]|cl)_[A-Za-z0-9]{20,68}\b"),
        },
        SecretPattern {
            name: "DigitalOcean GenAI Key",
            category: "Cloud / Other",
            severity: Severity::Critical,
            regex: re(r"\bsk-do-[A-Za-z0-9_-]{20,}\b"),
        },
    ]
}
