use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            // Real Apple merchant IDs are reverse-DNS with at least three
            // dot-separated segments after `merchant.`. The previous form
            // `merchant\.[A-Za-z0-9.-]{3,}` fired on `merchant.identifier`
            // / `merchant.example` in unrelated docs.
            name: "Apple Pay Merchant ID",
            category: "Mobile",
            severity: Severity::Low,
            regex: re(r"\bmerchant\.[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*){2,}\b"),
        },
        SecretPattern {
            name: "AdMob Ad Unit ID",
            category: "Mobile",
            severity: Severity::Low,
            regex: re(r"\bca-app-pub-[0-9]{16}/[0-9]{10}\b"),
        },
        SecretPattern {
            name: "AdMob App ID",
            category: "Mobile",
            severity: Severity::Low,
            regex: re(r"\bca-app-pub-[0-9]{16}~[0-9]{10}\b"),
        },
        SecretPattern {
            name: "Google Sign-In OAuth Client ID",
            category: "Mobile",
            severity: Severity::Medium,
            regex: re(r"\b[0-9]{6,}-[a-z0-9]{32}\.apps\.googleusercontent\.com\b"),
        },
        SecretPattern {
            name: "Branch.io Live Key",
            category: "Mobile",
            severity: Severity::Medium,
            regex: re(r"\bkey_live_[A-Za-z0-9]{32}\b"),
        },
        SecretPattern {
            name: "Branch.io Test Key",
            category: "Mobile",
            severity: Severity::Low,
            regex: re(r"\bkey_test_[A-Za-z0-9]{32}\b"),
        },
        SecretPattern {
            name: "Branch.io Live Secret",
            category: "Mobile",
            severity: Severity::Critical,
            regex: re(r"\bsecret_live_[A-Za-z0-9]{32}\b"),
        },
        SecretPattern {
            name: "Branch.io Test Secret",
            category: "Mobile",
            severity: Severity::Medium,
            regex: re(r"\bsecret_test_[A-Za-z0-9]{32}\b"),
        },
        SecretPattern {
            name: "OneSignal REST API Key",
            category: "Mobile",
            severity: Severity::Critical,
            regex: re(r"\bos_v2_app_[a-z0-9_]{20,}"),
        },
        SecretPattern {
            name: "Kochava App GUID",
            category: "Mobile",
            severity: Severity::Medium,
            regex: re(r"\bkokochava[a-z0-9]{10,}\b"),
        },
        SecretPattern {
            name: "Expo Push Token",
            category: "Mobile",
            severity: Severity::Medium,
            regex: re(r"ExponentPushToken\[[A-Za-z0-9_-]{22}\]"),
        },
        SecretPattern {
            name: "Expo EAS Access Token",
            category: "Mobile",
            severity: Severity::Critical,
            regex: re(r"\bexpo_[A-Za-z0-9]{24,}\b"),
        },
    ]
}
