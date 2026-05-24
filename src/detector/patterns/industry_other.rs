use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Vehicle Identification Number (VIN)",
            category: "Industry",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::VIN_LABELED_RE),
        },
        SecretPattern {
            name: "Vehicle Identification Number (NA check digit)",
            category: "Industry",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::VIN_NA_RE),
        },
        SecretPattern {
            name: "IMO Ship Number",
            category: "Industry",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::IMO_RE),
        },
        SecretPattern {
            name: "USPS S10 Tracking",
            category: "Industry",
            severity: Severity::Low,
            regex: re(crate::detector::validators::USPS_S10_RE),
        },
        SecretPattern {
            name: "UPS Tracking Number",
            category: "Industry",
            severity: Severity::Low,
            regex: re(r"\b1Z[A-Z0-9]{16}\b"),
        },
        SecretPattern {
            name: "Amazon Order ID",
            category: "Industry",
            severity: Severity::Low,
            regex: re(r"\b\d{3}-\d{7}-\d{7}\b"),
        },
        SecretPattern {
            name: "Tesla Owner API Legacy Token",
            category: "Industry",
            severity: Severity::Critical,
            regex: re(r"(?i)owner-api\.teslamotors\.com[^\n]*?\b[a-f0-9]{64}\b"),
        },
        SecretPattern {
            name: "WooCommerce Consumer Key",
            category: "Industry",
            severity: Severity::Critical,
            regex: re(r"\bck_[a-f0-9]{40}\b"),
        },
        SecretPattern {
            name: "WooCommerce Consumer Secret",
            category: "Industry",
            severity: Severity::Critical,
            regex: re(r"\bcs_[a-f0-9]{40}\b"),
        },
        SecretPattern {
            name: "BigCommerce X-Auth-Token",
            category: "Industry",
            severity: Severity::Critical,
            regex: re(r"(?i)X-Auth-Token:\s*[a-z0-9]{31,64}\b"),
        },
        SecretPattern {
            name: "Algolia Admin API Key",
            category: "Industry",
            severity: Severity::Critical,
            regex: re(r"(?i)X-Algolia-API-Key:\s*[a-f0-9]{32}\b"),
        },
        SecretPattern {
            name: "Sabre OAuth2 Access Token",
            category: "Industry",
            severity: Severity::Critical,
            regex: re(r"\bT1RK[A-Za-z0-9+/=]{20,}"),
        },
        SecretPattern {
            name: "Travelport Universal API Credential",
            category: "Industry",
            severity: Severity::Critical,
            regex: re(r"Universal API/uAPI\d+-\d+"),
        },
        SecretPattern {
            name: "Airline PNR Record Locator",
            category: "Industry",
            severity: Severity::Medium,
            regex: re(r"(?i)(?:PNR|record locator|confirmation):\s*[A-Z0-9]{6}\b"),
        },
        SecretPattern {
            name: "ICAO 24-bit Aircraft Address",
            category: "Industry",
            severity: Severity::Medium,
            regex: re(r"(?i)(?:ICAO24|Mode S|hex):\s*[0-9A-F]{6}\b"),
        },
        SecretPattern {
            name: "ISO 6346 Container Number",
            category: "Industry",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::ISO6346_RE),
        },
        SecretPattern {
            name: "Shippo Live API Token",
            category: "Industry",
            severity: Severity::Critical,
            regex: re(r"\bshippo_live_[a-fA-F0-9]{40}\b"),
        },
        SecretPattern {
            name: "Shippo Test API Token",
            category: "Industry",
            severity: Severity::High,
            regex: re(r"\bshippo_test_[a-fA-F0-9]{40}\b"),
        },
        SecretPattern {
            name: "FedEx OAuth Client ID",
            category: "Industry",
            severity: Severity::Critical,
            regex: re(r"(?i)apis\.fedex\.com[^\n]*?\bl[0-9a-z]{31}\b"),
        },
        SecretPattern {
            name: "DHL MyDHL REST API Key",
            category: "Industry",
            severity: Severity::Critical,
            regex: re(r"(?i)api-eu\.dhl\.com[^\n]*?\b[A-Za-z0-9]{40}\b"),
        },
        SecretPattern {
            name: "USPS Web Tools UserID",
            category: "Industry",
            severity: Severity::Medium,
            regex: re(r"\b\d{3}[A-Z]{4,6}\d{4}\b"),
        },
        SecretPattern {
            name: "Octopus Energy API Key",
            category: "Industry",
            severity: Severity::Critical,
            regex: re(r"\bsk_live_[A-Za-z0-9]{32,}"),
        },
        SecretPattern {
            name: "Enphase Enlighten API Key",
            category: "Industry",
            severity: Severity::High,
            regex: re(r"(?i)api\.enphaseenergy\.com[^\s]*[?&]key=[A-Za-z0-9]{32}\b"),
        },
        SecretPattern {
            name: "Canvas LMS Access Token",
            category: "Industry",
            severity: Severity::Critical,
            regex: re(r"\b\d{4,6}~[A-Za-z0-9]{40,}"),
        },
    ]
}
