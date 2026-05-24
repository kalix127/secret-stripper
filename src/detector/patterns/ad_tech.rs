use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Meta Legacy Access Token",
            category: "Ad Tech",
            severity: Severity::Critical,
            regex: re(r"\b\d{15,16}\|[0-9a-zA-Z_-]{27,40}\b"),
        },
        SecretPattern {
            name: "Meta Ad Account ID",
            category: "Ad Tech",
            severity: Severity::Low,
            regex: re(r"\bact_\d{6,16}\b"),
        },
        SecretPattern {
            name: "TikTok User Access Token",
            category: "Ad Tech",
            severity: Severity::High,
            regex: re(r"\bact\.[A-Za-z0-9]{20,}\b"),
        },
        SecretPattern {
            name: "TikTok Client Access Token",
            category: "Ad Tech",
            severity: Severity::High,
            regex: re(r"\bclt\.[A-Za-z0-9]{20,}\b"),
        },
        SecretPattern {
            name: "Twitter/X Bearer Token",
            category: "Ad Tech",
            severity: Severity::Critical,
            regex: re(r"(?i)bearer\s+AAAA[A-Za-z0-9%+/=]{80,140}"),
        },
        SecretPattern {
            name: "Twitter/X OAuth 1 Access Token",
            category: "Ad Tech",
            severity: Severity::High,
            regex: re(r"\b\d{15,25}-[A-Za-z0-9]{20,40}\b"),
        },
        SecretPattern {
            name: "LinkedIn URN",
            category: "Ad Tech",
            severity: Severity::Low,
            regex: re(r"\burn:li:(?:person|organization|sponsoredAccount):[A-Za-z0-9_-]{1,}"),
        },
        SecretPattern {
            name: "Snapchat OAuth Access Token",
            category: "Ad Tech",
            severity: Severity::Critical,
            regex: re(r"\b0\.MGQ[A-Za-z0-9_-]{15,}"),
        },
        SecretPattern {
            name: "Pinterest API Access Token",
            category: "Ad Tech",
            severity: Severity::Critical,
            regex: re(r"\bpina_[A-Z0-9_-]{10,}\b"),
        },
        SecretPattern {
            name: "Google Ads Developer Token",
            category: "Ad Tech",
            severity: Severity::Critical,
            regex: re(r"(?i)developer[_-]?token['\x22]?\s*[:=]\s*['\x22]?[A-Za-z0-9_-]{22}\b"),
        },
        SecretPattern {
            name: "Google Ads OAuth Refresh Token",
            category: "Ad Tech",
            severity: Severity::Critical,
            regex: re(r"\b1//[A-Za-z0-9_-]{40,}"),
        },
        SecretPattern {
            name: "TikTok App Secret (labeled)",
            category: "Ad Tech",
            severity: Severity::Critical,
            regex: re(
                r"(?i)tiktok[A-Za-z0-9_]*(?:client|app)_secret['\x22]?\s*[:=]\s*['\x22]?[0-9a-f]{40}\b",
            ),
        },
        SecretPattern {
            name: "Meta App Secret (labeled)",
            category: "Ad Tech",
            severity: Severity::Critical,
            regex: re(
                r"(?i)(?:facebook|meta|fb)[A-Za-z0-9_]*app_secret['\x22]?\s*[:=]\s*['\x22]?[0-9a-f]{32}\b",
            ),
        },
        SecretPattern {
            name: "The Trade Desk Auth Token",
            category: "Ad Tech",
            severity: Severity::Critical,
            regex: re(r"(?i)TTD-Auth:\s*[A-Za-z0-9]{20,}"),
        },
        SecretPattern {
            name: "Beeswax Instance Host",
            category: "Ad Tech",
            severity: Severity::Low,
            regex: re(r"\b[a-z0-9][a-z0-9-]{1,30}\.api\.beeswax\.com\b"),
        },
        SecretPattern {
            name: "AppLovin MAX SDK Key (labeled)",
            category: "Ad Tech",
            severity: Severity::Low,
            regex: re(
                r"(?i)applovin[A-Za-z0-9_]*sdk_key['\x22]?\s*[:=]\s*['\x22]?[A-Za-z0-9_-]{86}\b",
            ),
        },
        SecretPattern {
            name: "LiveRamp RampID (maintained individual)",
            category: "Ad Tech",
            severity: Severity::Medium,
            regex: re(r"\bXY[A-Z0-9]{47}\b"),
        },
        SecretPattern {
            name: "LiveRamp RampID (maintained household)",
            category: "Ad Tech",
            severity: Severity::Medium,
            regex: re(r"\bHY[A-Z0-9]{47}\b"),
        },
        SecretPattern {
            name: "UID2 Operator API Key",
            category: "Ad Tech",
            severity: Severity::Critical,
            regex: re(r"\bUID2-O-L-\d{1,}-[A-Za-z0-9+/=_-]{16,}"),
        },
        SecretPattern {
            name: "UID2 Advertising-Token Header",
            category: "Ad Tech",
            severity: Severity::High,
            regex: re(r"(?i)Advertising-Token:\s*[A-Za-z0-9+/=_-]{20,}"),
        },
        SecretPattern {
            name: "Treasure Data API Key",
            category: "Ad Tech",
            severity: Severity::Critical,
            regex: re(r"\b\d{1,}/[a-f0-9]{40}\b"),
        },
    ]
}
