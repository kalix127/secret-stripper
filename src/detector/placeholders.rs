use std::collections::HashMap;
use std::sync::OnceLock;

use super::patterns;
use super::redact::name_to_tag;

// Sample values for the `Placeholder` redaction style. Resolution is exact
// pattern name, then the pattern's category, then the typed tag. The mapping is
// static and deterministic: the same name always yields the same value.
//
// Idempotency is a fixed point, not the absence of a match. Card and IBAN
// samples are chosen to fail their checksum validator, so a re-scan does not
// detect them at all. Provider keys, email and IP samples re-match their own
// pattern but map back to themselves, so a second pass never changes the text.
// Private-key blocks and deep-scan findings have no realistic single-line form
// (a multi-line value would be repeated once per newline fragment), so they are
// left uncurated and fall through to the typed tag.

/// Fail-closed value for the path where a secret was detected but no span is
/// known (a deep-scan-only hit). Inert: it matches no pattern on a re-scan.
pub const GENERIC: &str = "example-redacted-value";

/// Exact pattern name -> sample value.
pub(crate) const CURATED: &[(&str, &str)] = &[
    ("AWS Access Key ID", "AKIAIOSFODNN7EXAMPLE"),
    (
        "GitHub Personal Access Token",
        "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
    ),
    ("GitLab Personal Access Token", "glpat-0123456789abcdefghij"),
    ("Stripe API Key", "sk_test_4eC39HqLyjWDarjtT1zdp7dc"),
    (
        "OpenAI API Key",
        "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV",
    ),
    ("Slack Bot Token", "xoxb-0000000000-0000000000-abcdABCD1234"),
    ("Google API Key", "AIzaSyDaGkExAmpLe0123456789abcdefghijkl"),
    (
        "JWT Token",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ),
    ("Email Address", "user@example.com"),
    ("IPv4 Address", "192.0.2.1"),
    ("IPv6 Address", "2001:db8::1"),
    ("IPv6 Address (compressed)", "2001:db8::1"),
    ("Visa Card", "4111 1111 1111 1112"),
    ("Mastercard Card", "5555 5555 5555 4445"),
    ("American Express Card", "3782 822463 10006"),
    ("IBAN", "DE00370400440532013000"),
    ("IBAN (Germany)", "DE00370400440532013000"),
    ("Phone Number (US)", "(555) 555-0123"),
    ("International Phone (E.164)", "+41 44 668 18 00"),
];

/// Pattern category -> generic family value for the uncurated long tail. Values
/// are low-entropy and carry no provider prefix or checksum, so they re-match
/// nothing. PII families are intentionally absent: a category cannot tell an
/// email apart from a phone, so PII is curated by name above.
pub(crate) const CATEGORY: &[(&str, &str)] = &[
    ("API Secret", "example-api-key-value"),
    ("Auth Token", "example-auth-token-value"),
    ("OAuth Token", "example-oauth-token-value"),
    ("OAuth Secret", "example-oauth-secret-value"),
    ("Cloud Secret", "example-cloud-key-value"),
    ("Payment Secret", "example-payment-key-value"),
    ("Messaging Token", "example-messaging-token-value"),
    ("VCS Token", "example-vcs-token-value"),
];

fn category_index() -> &'static HashMap<&'static str, &'static str> {
    static IDX: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    IDX.get_or_init(|| {
        patterns::all_patterns()
            .iter()
            .map(|p| (p.name, p.category))
            .collect()
    })
}

pub(crate) fn placeholder_for(name: &str) -> String {
    if let Some(&(_, value)) = CURATED.iter().find(|&&(n, _)| n == name) {
        return value.to_string();
    }
    if let Some(category) = category_index().get(name) {
        if let Some(&(_, value)) = CATEGORY.iter().find(|&&(c, _)| c == *category) {
            return value.to_string();
        }
    }
    name_to_tag(name)
}
