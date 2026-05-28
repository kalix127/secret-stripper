use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Cloudflare Origin CA Key",
            category: "Edge / CDN",
            severity: Severity::Critical,
            regex: re(r"\bv1\.0-[A-Za-z0-9_-]{160,}"),
        },
        SecretPattern {
            name: "Fastly API Token",
            category: "Edge / CDN",
            severity: Severity::High,
            regex: re(r"(?i)Fastly-Key:\s*[A-Za-z0-9_-]{32,}"),
        },
        SecretPattern {
            name: "Bunny.net API Key",
            category: "Edge / CDN",
            severity: Severity::High,
            regex: re(
                r"(?i)AccessKey:\s*[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
            ),
        },
        SecretPattern {
            name: "Netlify Personal Access Token",
            category: "Edge / CDN",
            severity: Severity::Critical,
            regex: re(r"\bnfp_[A-Za-z0-9]{36,}"),
        },
        SecretPattern {
            name: "Deno Deploy Token",
            category: "Edge / CDN",
            severity: Severity::High,
            regex: re(r"\bdd[pw]_[A-Za-z0-9]{36}\b"),
        },
        SecretPattern {
            name: "Shopify Access Token",
            category: "Edge / CDN",
            severity: Severity::Critical,
            regex: re(r"\bshpat_[A-Fa-f0-9]{32}\b"),
        },
        SecretPattern {
            name: "Shopify Custom App Access Token",
            category: "Edge / CDN",
            severity: Severity::Critical,
            regex: re(r"\bshpca_[A-Fa-f0-9]{32}\b"),
        },
        SecretPattern {
            name: "Shopify Private App Token",
            category: "Edge / CDN",
            severity: Severity::Critical,
            regex: re(r"\bshppa_[A-Fa-f0-9]{32}\b"),
        },
        SecretPattern {
            name: "Shopify Shared Secret",
            category: "Edge / CDN",
            severity: Severity::Critical,
            regex: re(r"\bshpss_[A-Fa-f0-9]{32}\b"),
        },
        SecretPattern {
            name: "Apple App Store Connect Key File",
            category: "Edge / CDN",
            severity: Severity::Critical,
            regex: re(r"\bAuthKey_[A-Z0-9]{10}\.p8\b"),
        },
        SecretPattern {
            name: "Cloudinary URL",
            category: "Edge / CDN",
            severity: Severity::Critical,
            regex: re(r"\bcloudinary://[0-9]{15}:[A-Za-z0-9_-]{20,}@[a-z0-9-]+"),
        },
        SecretPattern {
            name: "RevenueCat Secret Key",
            category: "Edge / CDN",
            severity: Severity::Critical,
            regex: re(r"\bsk_(?:appl|goog|amzn|mac|strp|rcb)_[A-Za-z0-9]{20,}\b"),
        },
    ]
}
