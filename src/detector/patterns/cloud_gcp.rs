use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "GCP OAuth Client ID",
            category: "Cloud / GCP",
            severity: Severity::Medium,
            regex: re(r"\b\d+-[a-z0-9]{32}\.apps\.googleusercontent\.com\b"),
        },
        SecretPattern {
            name: "GCP OAuth Refresh Token",
            category: "Cloud / GCP",
            severity: Severity::Critical,
            regex: re(r"\b1//[A-Za-z0-9_-]{20,}"),
        },
        SecretPattern {
            name: "GCP Service Account client_email",
            category: "Cloud / GCP",
            severity: Severity::Medium,
            regex: re(r"\b[A-Za-z0-9-]+@[A-Za-z0-9-]+\.iam\.gserviceaccount\.com\b"),
        },
        SecretPattern {
            name: "GCP Service Account JSON Type",
            category: "Cloud / GCP",
            severity: Severity::Critical,
            regex: re(r#"(?i)"type"\s*:\s*"service_account""#),
        },
        SecretPattern {
            name: "GCS HMAC Access ID",
            category: "Cloud / GCP",
            severity: Severity::Critical,
            regex: re(r"\bGOOG1[A-Z0-9]{50,70}\b"),
        },
        SecretPattern {
            name: "GCP FCM Legacy Server Key",
            category: "Cloud / GCP",
            severity: Severity::Critical,
            regex: re(r"\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{100,}"),
        },
        SecretPattern {
            name: "GCP Firebase Database URL",
            category: "Cloud / GCP",
            severity: Severity::Low,
            regex: re(r"https://[A-Za-z0-9-]+\.firebaseio\.com/?"),
        },
        SecretPattern {
            name: "GCP reCAPTCHA Key",
            category: "Cloud / GCP",
            severity: Severity::High,
            regex: re(r"\b6L[A-Za-z0-9_-]{38}\b"),
        },
        SecretPattern {
            name: "GCP Cloud Run Service URL",
            category: "Cloud / GCP",
            severity: Severity::Medium,
            regex: re(r"https://[A-Za-z0-9-]+\.[a-z]\.run\.app/?"),
        },
        SecretPattern {
            name: "Yandex Cloud API Key",
            category: "Cloud / GCP",
            severity: Severity::High,
            regex: re(r"\bAQVN[A-Za-z0-9_-]{35,}\b"),
        },
        SecretPattern {
            name: "Yandex Cloud IAM Token",
            category: "Cloud / GCP",
            severity: Severity::High,
            regex: re(r"\bt1\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
        },
    ]
}
