use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Stripe Restricted Key (live)",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(r"\brk_live_[A-Za-z0-9]{24,99}\b"),
        },
        SecretPattern {
            name: "Stripe Restricted Key (test)",
            category: "Payments",
            severity: Severity::High,
            regex: re(r"\brk_test_[A-Za-z0-9]{24,99}\b"),
        },
        SecretPattern {
            name: "Stripe Org Secret Key",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(r"\bsk_org_[A-Za-z0-9]{20,99}\b"),
        },
        SecretPattern {
            name: "Stripe Webhook Signing Secret",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(r"\bwhsec_[A-Za-z0-9]{32,99}\b"),
        },
        SecretPattern {
            name: "Stripe OAuth Refresh Token",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(r"\brt_(?:test_)?[A-Za-z0-9]{24,99}\b"),
        },
        SecretPattern {
            name: "Braintree Access Token (production)",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(r"access_token\$production\$[a-z0-9]+\$[a-f0-9]{32}"),
        },
        SecretPattern {
            name: "Braintree Access Token (sandbox)",
            category: "Payments",
            severity: Severity::High,
            regex: re(r"access_token\$sandbox\$[a-z0-9]+\$[a-f0-9]{32}"),
        },
        SecretPattern {
            name: "Square Access Token (legacy)",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(r"\bsq0atp-[A-Za-z0-9_-]{22}\b"),
        },
        SecretPattern {
            name: "Square OAuth Secret",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(r"\bsq0csp-[A-Za-z0-9_-]{43}\b"),
        },
        SecretPattern {
            name: "Square Personal Access Token",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(r"\bEAAA[A-Za-z0-9_-]{60,}\b"),
        },
        SecretPattern {
            name: "Adyen API Key",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(r"\bAQE[A-Za-z0-9]{170,}\b"),
        },
        SecretPattern {
            name: "Razorpay Key ID",
            category: "Payments",
            severity: Severity::High,
            regex: re(r"\brzp_(?:test|live)_[A-Za-z0-9]{14}\b"),
        },
        SecretPattern {
            name: "Mollie API Key",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(r"\b(?:live|test)_[A-Za-z0-9]{30}\b"),
        },
        SecretPattern {
            name: "GoCardless API Token",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(r"\b(?:live|sandbox)_[A-Za-z0-9_-]{40,}\b"),
        },
        SecretPattern {
            name: "EasyPost API Token",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(r"\bEZAK[A-Za-z0-9]{54}\b"),
        },
        SecretPattern {
            name: "EasyPost Test API Token",
            category: "Payments",
            severity: Severity::High,
            regex: re(r"\bEZTK[A-Za-z0-9]{54}\b"),
        },
        SecretPattern {
            name: "Stripe Ephemeral Key",
            category: "Payments",
            severity: Severity::High,
            regex: re(r"\bek_(?:test|live)_[A-Za-z0-9]{20,}\b"),
        },
        SecretPattern {
            name: "Paddle API Key",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(r"\bpdl_(?:live|sdbx)_apikey_[a-z0-9]{26}_[A-Za-z0-9]{22}_[A-Za-z0-9]{3}\b"),
        },
        SecretPattern {
            name: "Plaid Access Token",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(
                r"\baccess-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            ),
        },
        SecretPattern {
            name: "PayPal OAuth Access Token",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(r"\bA21AA[A-Za-z0-9_-]{80,}\b"),
        },
        SecretPattern {
            name: "Mercado Pago Access Token",
            category: "Payments",
            severity: Severity::Critical,
            regex: re(r"\b(?:APP_USR|TEST)-\d{8,}-[0-9a-f]{6}-[0-9A-Za-z]{20,}-\d{6,}\b"),
        },
    ]
}
