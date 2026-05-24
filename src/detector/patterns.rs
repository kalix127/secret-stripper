use regex::Regex;
use std::sync::OnceLock;

mod ad_tech;
mod ai;
mod auth_tokens;
mod banking;
mod cloud_aws;
mod cloud_azure;
mod cloud_gcp;
mod cloud_other;
mod crypto_keys;
mod databases;
mod edge;
mod exchanges;
mod extra_ids;
mod gaming;
mod hashes;
mod healthcare;
mod industry_other;
mod infra;
mod iot;
mod legacy;
mod messaging;
mod mobile;
mod monitoring;
mod networking;
mod packages;
mod payments;
mod pii_biometric;
mod pii_contact;
mod pii_financial;
mod pii_geo;
mod pii_govid_eu;
mod pii_govid_intl;
mod pii_govid_us;
mod pii_network;
mod rpc_chain;
mod saas_collab;
mod saas_crm_marketing;
mod saas_hr_finance;
mod saas_iam;
mod structured;
mod threat_intel;
mod vcs_ci;
mod wallets;

#[derive(Debug, Clone)]
pub struct SecretPattern {
    pub name: &'static str,
    pub category: &'static str,
    pub severity: Severity,
    pub regex: Regex,
}

/// Severity classification policy, applied uniformly across every bucket.
///
/// - `Critical`: live credential granting write/admin, or full private key
///   material (access+secret pairs, `sk_live_`, PATs, refresh tokens, private
///   key PEM, connection strings with embedded creds, webhook signing secrets).
/// - `High`: scoped/unclear-scope tokens and hashed credentials (bare bearer
///   tokens, JWT shape, password hashes, test-mode payment keys, Stripe
///   `pk_live_`). Hashes are High because their leak signals a credential dump.
/// - `Medium`: direct PII or identifiers tied to a person/account (phone,
///   isolated email-as-PII, card numbers, SSN/IBAN/passport, account/tenant
///   IDs, OCIDs).
/// - `Low`: network/device identifiers and public key material (RFC1918 IPv4,
///   IPv6, CIDR, MAC, public keys, measurement/container IDs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    /// Single source of truth for the lowercase wire form (config /
    /// `patterns.toml`). Exhaustive match - a new variant fails to compile
    /// here until it is given a serialization, mirroring the i18n drift
    /// guard. Localized display text is the separate concern of
    /// `Lang::severity_label`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }

    /// Parse the wire form. Unknown / "medium" both map to `Medium` (the
    /// historical lenient default for user-supplied custom patterns).
    pub fn from_wire(s: &str) -> Severity {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "low" => Severity::Low,
            _ => Severity::Medium,
        }
    }
}

pub(crate) fn re(p: &str) -> Regex {
    Regex::new(p).unwrap_or_else(|e| panic!("invalid regex pattern {p:?}: {e}"))
}

type BucketFn = fn() -> Vec<SecretPattern>;

/// Bucket stem -> pattern constructor. The stem is the module file name and
/// is the stable key used by config `disabled_categories`. This is the single
/// place that maps a stem to its `patterns()`; order is detection precedence
/// and must match the historical `all_patterns()` order.
pub(crate) const BUCKETS: &[(&str, BucketFn)] = &[
    ("legacy", legacy::patterns),
    ("cloud_aws", cloud_aws::patterns),
    ("cloud_gcp", cloud_gcp::patterns),
    ("cloud_azure", cloud_azure::patterns),
    ("cloud_other", cloud_other::patterns),
    ("infra", infra::patterns),
    ("networking", networking::patterns),
    ("payments", payments::patterns),
    ("messaging", messaging::patterns),
    ("vcs_ci", vcs_ci::patterns),
    ("ai", ai::patterns),
    ("monitoring", monitoring::patterns),
    ("databases", databases::patterns),
    ("edge", edge::patterns),
    ("crypto_keys", crypto_keys::patterns),
    ("auth_tokens", auth_tokens::patterns),
    ("packages", packages::patterns),
    ("healthcare", healthcare::patterns),
    ("pii_contact", pii_contact::patterns),
    ("pii_financial", pii_financial::patterns),
    ("pii_govid_us", pii_govid_us::patterns),
    ("pii_govid_eu", pii_govid_eu::patterns),
    ("pii_govid_intl", pii_govid_intl::patterns),
    ("pii_geo", pii_geo::patterns),
    ("pii_biometric", pii_biometric::patterns),
    ("pii_network", pii_network::patterns),
    ("hashes", hashes::patterns),
    ("structured", structured::patterns),
    ("wallets", wallets::patterns),
    ("exchanges", exchanges::patterns),
    ("rpc_chain", rpc_chain::patterns),
    ("mobile", mobile::patterns),
    ("gaming", gaming::patterns),
    ("iot", iot::patterns),
    ("saas_iam", saas_iam::patterns),
    ("saas_collab", saas_collab::patterns),
    ("saas_crm_marketing", saas_crm_marketing::patterns),
    ("saas_hr_finance", saas_hr_finance::patterns),
    ("ad_tech", ad_tech::patterns),
    ("banking", banking::patterns),
    ("threat_intel", threat_intel::patterns),
    ("industry_other", industry_other::patterns),
    ("extra_ids", extra_ids::patterns),
];

static ALL: OnceLock<Vec<SecretPattern>> = OnceLock::new();
static CATALOG: OnceLock<Vec<(&'static str, Vec<SecretPattern>)>> = OnceLock::new();

/// Per-bucket compiled patterns, built (regexes compiled) exactly once. Every
/// other accessor clones from this; `Regex` clone is Arc-backed so filtering
/// the catalog per config change is cheap (no recompilation).
fn catalog() -> &'static [(&'static str, Vec<SecretPattern>)] {
    CATALOG.get_or_init(|| BUCKETS.iter().map(|&(s, f)| (s, f())).collect())
}

pub fn all_patterns() -> &'static [SecretPattern] {
    ALL.get_or_init(|| {
        let mut v = Vec::with_capacity(768);
        for (_stem, pats) in catalog() {
            v.extend(pats.iter().cloned());
        }
        v
    })
}

/// `(bucket_stem, pattern_count)` for every built-in bucket. For the TUI
/// category list.
pub fn bucket_catalog() -> Vec<(&'static str, usize)> {
    catalog().iter().map(|(s, v)| (*s, v.len())).collect()
}

/// Full per-bucket pattern catalog. Powers the DETECTION_COVERAGE.md
/// generator; not used by the TUI hot path.
pub fn bucket_patterns() -> &'static [(&'static str, Vec<SecretPattern>)] {
    catalog()
}

/// Built-in patterns with every bucket whose stem is in `disabled` removed.
/// Clones from the compiled catalog - no regex recompilation.
pub fn builtin_patterns_filtered(disabled: &std::collections::HashSet<&str>) -> Vec<SecretPattern> {
    let mut v = Vec::with_capacity(768);
    for (stem, pats) in catalog() {
        if disabled.contains(stem) {
            continue;
        }
        v.extend(pats.iter().cloned());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_wire_round_trips() {
        for s in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ] {
            assert_eq!(Severity::from_wire(s.as_str()), s);
        }
        // Lenient parse: case-insensitive, trimmed, unknown -> Medium.
        assert_eq!(Severity::from_wire("  CRITICAL "), Severity::Critical);
        assert_eq!(Severity::from_wire("bogus"), Severity::Medium);
        assert_eq!(Severity::from_wire(""), Severity::Medium);
    }

    #[test]
    fn test_aws_access_key() {
        let pats = all_patterns();
        let aws = pats.iter().find(|p| p.name == "AWS Access Key ID").unwrap();
        assert!(aws.regex.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(aws.regex.is_match("akiaiosfodnn7example"));
        assert!(!aws.regex.is_match("AKIAIOSFODNN7"));
    }

    #[test]
    fn test_github_pat() {
        let pats = all_patterns();
        let gh = pats
            .iter()
            .find(|p| p.name == "GitHub Personal Access Token")
            .unwrap();
        assert!(gh
            .regex
            .is_match("ghp_abcdefghijklmnopqrstuvwxyz0123456789abc"));
        assert!(!gh.regex.is_match("ghx_notarealtoken"));
    }

    #[test]
    fn test_slack_bot_token() {
        let pats = all_patterns();
        let slack = pats.iter().find(|p| p.name == "Slack Bot Token").unwrap();
        let token = format!("{}oxb-123456789012-1234567890123-abcABC123def456", "x");
        assert!(slack.regex.is_match(&token));
    }

    #[test]
    fn test_stripe_key() {
        let pats = all_patterns();
        let stripe = pats.iter().find(|p| p.name == "Stripe API Key").unwrap();
        let sk_live = format!("{}k_live_abcdefghijklmnopqrstuvwxyz012345", "s");
        let pk_live = format!("p{}_live_abcdefghijklmnopqrstuvwxyz012345", "k");
        let sk_test = format!("{}k_test_abcdefghijklmnopqrstuvwxyz012345", "s");
        let pk_test = format!("p{}_test_abcdefghijklmnopqrstuvwxyz012345", "k");
        assert!(stripe.regex.is_match(&sk_live));
        assert!(stripe.regex.is_match(&pk_live));
        assert!(stripe.regex.is_match(&sk_test));
        assert!(stripe.regex.is_match(&pk_test));
    }

    #[test]
    fn test_credit_card() {
        let pats = all_patterns();
        // The generic "any 16 digits" rule was removed - it redacted every
        // order/tracking number. Cards are now brand-anchored + Luhn-gated.
        assert!(
            pats.iter().all(|p| p.name != "Credit Card Number"),
            "generic Credit Card Number pattern must stay removed"
        );
        let visa = pats.iter().find(|p| p.name == "Visa Card").unwrap();
        assert!(visa.regex.is_match("4111-1111-1111-1111"));
        assert!(visa.regex.is_match("4111 1111 1111 1111"));
        assert!(visa.regex.is_match("4111111111111111"));
        // Luhn gate is wired: same shape, bad checksum must be rejected.
        let luhn = crate::detector::validators::validator_for(visa.regex.as_str())
            .expect("Visa Card must be Luhn-gated in the validator registry");
        assert!(luhn("4111111111111111"));
        assert!(!luhn("4111111111111112"));
    }

    #[test]
    fn test_ssn() {
        let pats = all_patterns();
        let ssn = pats
            .iter()
            .find(|p| p.name == "Social Security Number")
            .unwrap();
        assert!(ssn.regex.is_match("123-45-6789"));
        assert!(!ssn.regex.is_match("123456789"));
    }

    #[test]
    fn test_email() {
        let pats = all_patterns();
        let email = pats.iter().find(|p| p.name == "Email Address").unwrap();
        assert!(email.regex.is_match("test@example.com"));
        assert!(!email.regex.is_match("notanemail"));
    }

    #[test]
    fn test_jwt() {
        let pats = all_patterns();
        let jwt = pats.iter().find(|p| p.name == "JWT Token").unwrap();
        assert!(jwt.regex.is_match("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqPnd9iywLhVF3UxwBI9PgMv7YGf7bRZR3n1gA"));
    }

    #[test]
    fn test_private_key() {
        let pats = all_patterns();
        let pk = pats
            .iter()
            .find(|p| p.name == "Private Key (RSA/DSA/EC)")
            .unwrap();
        assert!(pk.regex.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(pk.regex.is_match("-----BEGIN EC PRIVATE KEY-----"));
        assert!(pk.regex.is_match("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn test_db_connection_string() {
        let pats = all_patterns();
        let db = pats
            .iter()
            .find(|p| p.name == "Database Connection String")
            .unwrap();
        assert!(db
            .regex
            .is_match("postgresql://user:password@localhost:5432/db"));
        assert!(db.regex.is_match("mysql://user:pass@host/db"));
    }

    #[test]
    fn test_openai_api_key() {
        let pats = all_patterns();
        let oai = pats.iter().find(|p| p.name == "OpenAI API Key").unwrap();
        // Modern project key carries the T3BlbkFJ infix anchor.
        assert!(oai.regex.is_match(&format!(
            "sk-proj-{}T3BlbkFJ{}",
            "a".repeat(30),
            "b".repeat(30)
        )));
        // Classic 48-char key.
        assert!(oai.regex.is_match(&format!("sk-{}", "a".repeat(48))));
        // The old over-broad shape (no anchor, wrong length) must not match.
        assert!(!oai
            .regex
            .is_match("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"));
    }

    #[test]
    fn test_google_api_key() {
        let pats = all_patterns();
        let g = pats.iter().find(|p| p.name == "Google API Key").unwrap();
        assert!(g.regex.is_match("AIzaSyAa8yy0GdcGPHdtA0830d4aREzXgBo38a4"));
    }

    #[test]
    fn test_telegram_bot_token() {
        let pats = all_patterns();
        let tg = pats
            .iter()
            .find(|p| p.name == "Telegram Bot Token")
            .unwrap();
        assert!(tg
            .regex
            .is_match("1234567890:ABCdefGHIjklmNOPqrSTUvwxYZ-abcdEfghIj"));
    }

    #[test]
    fn test_severity_trait() {
        assert_ne!(Severity::Critical, Severity::Low);
        assert_eq!(Severity::High, Severity::High);
    }

    fn ipv4_pat() -> SecretPattern {
        all_patterns()
            .iter()
            .find(|p| p.name == "IPv4 Address")
            .cloned()
            .unwrap()
    }

    fn mac_pats() -> Vec<SecretPattern> {
        all_patterns()
            .iter()
            .filter(|p| p.name == "MAC Address")
            .cloned()
            .collect()
    }

    fn first_match_span(pats: &[SecretPattern], text: &str) -> Option<(usize, usize)> {
        for p in pats {
            if let Some(m) = p.regex.find(text) {
                return Some((m.start(), m.end()));
            }
        }
        None
    }

    #[test]
    fn ipv4_with_port_match() {
        let p = ipv4_pat();
        let m = p.regex.find("192.168.1.1:8080").unwrap();
        assert_eq!(m.start(), 0);
        assert_eq!(m.end(), 16);
    }

    #[test]
    fn ipv4_without_port_still_matches() {
        let p = ipv4_pat();
        assert!(p.regex.is_match("192.168.1.1"));
    }

    #[test]
    fn ipv4_port_5_digit_loose() {
        // Documented loose case: 5-digit ports above 65535 still match. We
        // accept the over-redaction.
        let p = ipv4_pat();
        let m = p.regex.find("10.0.0.1:65535").unwrap();
        assert_eq!(&"10.0.0.1:65535"[m.start()..m.end()], "10.0.0.1:65535");
        let m2 = p.regex.find("10.0.0.1:99999").unwrap();
        assert_eq!(&"10.0.0.1:99999"[m2.start()..m2.end()], "10.0.0.1:99999");
    }

    #[test]
    fn mac_colon_full_match() {
        let pats = mac_pats();
        let span = first_match_span(&pats, "aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(span, (0, 17));
    }

    #[test]
    fn mac_dash_full_match() {
        let pats = mac_pats();
        let span = first_match_span(&pats, "aa-bb-cc-dd-ee-ff").unwrap();
        assert_eq!(span, (0, 17));
    }

    #[test]
    fn mac_cisco_dot_match() {
        let pats = mac_pats();
        let span = first_match_span(&pats, "aabb.ccdd.eeff").unwrap();
        assert_eq!(span, (0, 14));
    }

    #[test]
    fn mac_bare_12hex_is_not_matched() {
        // The separator-less 12-hex MAC form was removed: it was
        // indistinguishable from a git short hash / hex id / UUID tail and
        // redacted ordinary clipboard text. Only separator forms match now.
        let pats = mac_pats();
        assert!(first_match_span(&pats, "aabbccddeeff").is_none());
    }

    #[test]
    fn mac_too_short_does_not_match() {
        let pats = mac_pats();
        assert!(first_match_span(&pats, "aabbccddeef").is_none());
    }
}
