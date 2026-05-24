use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "PyPI Upload Token",
            category: "Packages",
            severity: Severity::Critical,
            regex: re(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b"),
        },
        SecretPattern {
            name: "TestPyPI Upload Token",
            category: "Packages",
            severity: Severity::Critical,
            regex: re(r"\bpypi-AgENdGVzdC5weXBpLm9yZ[A-Za-z0-9_-]{50,}\b"),
        },
        SecretPattern {
            name: "RubyGems API Key",
            category: "Packages",
            severity: Severity::Critical,
            regex: re(r"\brubygems_[a-f0-9]{48}\b"),
        },
        SecretPattern {
            name: "crates.io API Token",
            category: "Packages",
            severity: Severity::Critical,
            regex: re(r"\bcio[A-Za-z0-9]{32}\b"),
        },
        SecretPattern {
            name: "NuGet API Key",
            category: "Packages",
            severity: Severity::Critical,
            regex: re(r"\boy2[a-z0-9]{43}\b"),
        },
        SecretPattern {
            name: "JFrog Artifactory API Key",
            category: "Packages",
            severity: Severity::Critical,
            regex: re(r"\bAKCp[A-Za-z0-9]{60,}\b"),
        },
        SecretPattern {
            name: "Artifactory Reference Token",
            category: "Packages",
            severity: Severity::Critical,
            regex: re(r"\bcmVmdGtu[A-Za-z0-9+/=]{50,}\b"),
        },
        SecretPattern {
            name: "Clojars Deploy Token",
            category: "Packages",
            severity: Severity::Critical,
            regex: re(r"\bCLOJARS_[a-f0-9]{60}\b"),
        },
        SecretPattern {
            name: "Packagist API Token",
            category: "Packages",
            severity: Severity::Critical,
            regex: re(r"\bpackagist_[a-z]{3,4}_[a-f0-9]{64,}\b"),
        },
        SecretPattern {
            name: "Endor Labs Token",
            category: "Packages",
            severity: Severity::Critical,
            regex: re(r"\bendr\+[A-Za-z0-9]{20,}\b"),
        },
        SecretPattern {
            name: "Socket.dev Token",
            category: "Packages",
            severity: Severity::Critical,
            regex: re(r"\bsktsec_[A-Za-z0-9_-]{20,}\b"),
        },
        SecretPattern {
            name: "Duffel Access Token",
            category: "Packages",
            severity: Severity::Critical,
            regex: re(r"\bduffel_(?:test|live)_[A-Za-z0-9_-]{43}\b"),
        },
    ]
}
