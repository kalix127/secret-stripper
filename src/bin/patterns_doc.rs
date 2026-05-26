use secret_stripper::{bucket_patterns, Severity};
use std::fmt::Write as _;

const BUCKET_DESCRIPTIONS: &[(&str, &str)] = &[
    ("legacy", "Legacy patterns preserved for backward compatibility."),
    (
        "cloud_aws",
        "AWS access keys, secret keys, STS session tokens, ABIA/AIDA/AROA IDs, signed URLs.",
    ),
    (
        "cloud_gcp",
        "GCP service-account keys, OAuth client secrets, API keys, OAuth refresh tokens.",
    ),
    (
        "cloud_azure",
        "Azure Storage / Service Bus / Cosmos connection strings, AAD client secrets, SAS tokens.",
    ),
    (
        "cloud_other",
        "Cloudflare, Heroku, DigitalOcean, Linode, Vultr, Render, Fly, and other PaaS credentials.",
    ),
    (
        "infra",
        "Terraform Cloud, Vault, Consul, Nomad, etcd, and other infra-tool tokens.",
    ),
    (
        "networking",
        "VPN preshared keys, BGP secrets, SNMP communities, RADIUS / TACACS secrets.",
    ),
    (
        "payments",
        "Stripe, Square, PayPal, Plaid, Adyen, Coinbase Commerce, Razorpay keys.",
    ),
    (
        "messaging",
        "Slack, Discord, Telegram, Twilio, SendGrid, Mailgun, Postmark tokens and webhook secrets.",
    ),
    (
        "vcs_ci",
        "GitHub / GitLab / Bitbucket PATs and deploy tokens, CircleCI / Travis / Jenkins / Buildkite tokens.",
    ),
    (
        "ai",
        "OpenAI, Anthropic, Cohere, HuggingFace, Replicate, Mistral, Perplexity API keys.",
    ),
    (
        "monitoring",
        "Datadog, New Relic, Sentry, PagerDuty, Honeycomb, Grafana / Loki / Tempo API keys.",
    ),
    (
        "databases",
        "Postgres / MySQL / MongoDB / Redis / MSSQL connection URLs, plus DBaaS API keys (Supabase, PlanetScale, Neon, Turso).",
    ),
    (
        "edge",
        "Cloudflare Workers, Fastly, Vercel, Netlify, Akamai, Bunny CDN API tokens.",
    ),
    (
        "crypto_keys",
        "PEM-encoded RSA / EC / DSA / OpenSSH / PGP private key blocks.",
    ),
    (
        "auth_tokens",
        "JWTs, OAuth bearer tokens, basic-auth URLs, refresh tokens, session IDs.",
    ),
    (
        "packages",
        "NPM, PyPI, RubyGems, Cargo (crates.io), Maven Central, NuGet publish tokens.",
    ),
    (
        "healthcare",
        "NHS, NPI, DEA, Medicaid IDs and other healthcare identifiers.",
    ),
    (
        "pii_contact",
        "Email addresses, phone numbers (E.164 with separator tolerance), full names.",
    ),
    (
        "pii_financial",
        "Credit / debit cards (Luhn-validated), IBAN, BIC / SWIFT, ABA routing numbers.",
    ),
    (
        "pii_govid_us",
        "US Social Security Number, ITIN, EIN, US passport, driver's license formats.",
    ),
    (
        "pii_govid_eu",
        "EU national IDs (codice fiscale, NIE, DNI, BSN, etc.), EU passport, MRZ.",
    ),
    (
        "pii_govid_intl",
        "International passports, MRZ formats, ABN / CPF / Aadhaar / MyKad and similar.",
    ),
    (
        "pii_geo",
        "Postal addresses, postal / ZIP codes, geographic coordinates.",
    ),
    (
        "pii_biometric",
        "Biometric identifiers, fingerprint hashes, biometric template tokens.",
    ),
    (
        "pii_network",
        "IPv4 (including with port), IPv6, MAC addresses, CIDR blocks, hostnames.",
    ),
    (
        "hashes",
        "bcrypt, scrypt, argon2, MD5, SHA, NTLM password hashes.",
    ),
    (
        "structured",
        "Secrets embedded in JSON values, dotenv lines, k=v shapes, YAML scalars.",
    ),
    (
        "wallets",
        "BTC / ETH / SOL and other wallet addresses, BIP39 seed phrases, keystore JSON.",
    ),
    (
        "exchanges",
        "Binance, Coinbase, Kraken, Bitfinex, KuCoin and other exchange API keys.",
    ),
    (
        "rpc_chain",
        "Infura, Alchemy, QuickNode, Moralis, Ankr RPC URLs and project IDs.",
    ),
    (
        "mobile",
        "Firebase / FCM / APNS tokens, Android / iOS platform API keys.",
    ),
    (
        "gaming",
        "Steam, Epic, PSN, Xbox Live, Riot Games and other gaming-platform tokens.",
    ),
    (
        "iot",
        "AWS IoT certs, MQTT broker credentials, device-specific provisioning keys.",
    ),
    (
        "saas_iam",
        "Okta, Auth0, OneLogin, Ping, Azure AD tenant secrets and management tokens.",
    ),
    (
        "saas_collab",
        "Notion, Linear, Jira, Asana, Trello, Confluence integration tokens.",
    ),
    (
        "saas_crm_marketing",
        "HubSpot, Salesforce, Mailchimp, Intercom, Segment, Customer.io keys.",
    ),
    (
        "saas_hr_finance",
        "Workday, BambooHR, Gusto, ADP, NetSuite, QuickBooks API tokens.",
    ),
    (
        "ad_tech",
        "Google Ads, Facebook Ads, AppNexus / Xandr, MoPub, Criteo API credentials.",
    ),
    (
        "banking",
        "Bank routing / SWIFT / IBAN composite shapes and banking-API client secrets.",
    ),
    (
        "threat_intel",
        "VirusTotal, AbuseIPDB, GreyNoise, MISP, AlienVault OTX API tokens.",
    ),
    (
        "industry_other",
        "Niche vertical APIs (logistics, hospitality, education) not covered by another bucket.",
    ),
    (
        "extra_ids",
        "Miscellaneous ID shapes, asset tags, and internal account formats.",
    ),
];

fn description_for(stem: &str) -> &'static str {
    BUCKET_DESCRIPTIONS
        .iter()
        .find(|(s, _)| *s == stem)
        .map(|(_, d)| *d)
        .unwrap_or_else(|| {
            panic!(
                "bucket {stem:?} has no description in BUCKET_DESCRIPTIONS - add one in src/bin/patterns_doc.rs",
            )
        })
}

fn severity_label(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
    }
}

fn escape_cell(s: &str) -> String {
    s.replace('|', "\\|")
}

fn main() {
    let catalog = bucket_patterns();
    let total: usize = catalog.iter().map(|(_, p)| p.len()).sum();
    let mut out = String::new();

    writeln!(out, "# Detection Coverage").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "{} built-in patterns across {} buckets. Toggle individual buckets in `secret-stripper menu -> Detection Settings -> Categories`, or switch presets under `Presets`.",
        total,
        catalog.len()
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "This file is auto-generated by `just patterns-doc`. Do not edit by hand."
    )
    .unwrap();
    writeln!(out).unwrap();

    writeln!(out, "## Presets").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "Detection buckets are grouped into three cumulative presets, switchable from `menu -> Detection Settings -> Presets`. Manual per-bucket toggles show as `Custom`.").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "- **Minimal** - popular PII only: emails, phones, dates of birth, credit cards, IBANs, and IP / host addresses. Lowest noise; no credential scanning.").unwrap();
    writeln!(out, "- **Balanced** (default for new installs) - Minimal plus the developer and credential buckets (cloud, auth, payments, messaging, VCS / CI, AI, databases, crypto keys, SaaS, and more). Excludes regional government IDs, threat intel, banking, healthcare, password-hash artifacts, crypto wallets / exchanges / RPC, and other niche or high-false-positive buckets. Tuned for near-zero false positives on everyday clipboard text.").unwrap();
    writeln!(out, "- **Full** - Balanced plus every remaining bucket, including password hashes, crypto wallets / exchanges / RPC, regional government IDs, biometric, geo, gaming, IoT, ad-tech and other niche verticals.").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "Existing installs keep Full (all buckets) until you pick a different preset."
    )
    .unwrap();
    writeln!(out).unwrap();

    writeln!(out, "## Severity tiers").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "Every built-in pattern and every custom rule carries a severity tier. The tier does NOT change what gets redacted - if a secret matches, it is redacted regardless of tier. The one functional job of severity is the soft-wrap rejoin pass: when a secret is split across a line break (e.g. an API key wrapped mid-token), the scanner glues the halves back together before re-scanning. Re-joining can fabricate false matches, so only `Critical` / `High` patterns (prefix-anchored shapes like `AKIA...`, `ghp_...`, `sk_live_...`) and patterns with a checksum validator (Luhn, IBAN, passport MRZ, ...) are admitted into the rejoin pass. Format-only `Low` / `Medium` patterns are not.").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "**Practical guidance for custom rules:** pick `critical` or `high` if your pattern is distinctive / anchored and you want it recovered even when soft-wrapped; pick `medium` / `low` for loose, format-only shapes where a cross-line rejoin would be risky. The tier never makes your rule redact more or less in the normal (single-line) case.").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "**Tiering policy for built-ins:** `Critical` = live credential / private key (plus Luhn-checked payment cards and passport MRZ); `High` = scoped or hashed token; `Medium` = direct PII (most government IDs, emails-as-PII); `Low` = network / device identifiers.").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "## Buckets").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "| Bucket | Patterns | What it covers |").unwrap();
    writeln!(out, "|---|---|---|").unwrap();
    for (stem, pats) in catalog {
        writeln!(
            out,
            "| `{}` | {} | {} |",
            stem,
            pats.len(),
            description_for(stem)
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    writeln!(out, "## Patterns").unwrap();
    writeln!(out).unwrap();
    for (stem, pats) in catalog {
        writeln!(out, "### `{}`", stem).unwrap();
        writeln!(out).unwrap();
        writeln!(out, "{}", description_for(stem)).unwrap();
        writeln!(out).unwrap();
        writeln!(out, "| Name | Severity | Regex |").unwrap();
        writeln!(out, "|---|---|---|").unwrap();
        for p in pats {
            writeln!(
                out,
                "| {} | {} | `{}` |",
                escape_cell(p.name),
                severity_label(&p.severity),
                escape_cell(p.regex.as_str())
            )
            .unwrap();
        }
        writeln!(out).unwrap();
    }

    writeln!(out, "## Heuristic layer").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "Two scanners run alongside the regex catalog and catch secrets the named patterns miss:"
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(out, "- **Entropy scan** - a Shannon-entropy catch-all that flags long, random-looking strings even when no named pattern recognizes them. Runs on the whole clipboard text independently of which buckets are enabled, so disabling a category does not stop an entropy-looking value in that category from being redacted. Toggle off by setting `enable_entropy = false` in `config.toml` for strictly pattern-only behavior.").unwrap();
    writeln!(out, "- **Deep scan** - heuristic scanners for key=value pairs, dotenv blocks, base64-encoded blobs, JSON `password` / `secret` / `token` fields, SSH-key blobs, connection strings, BIP39 mnemonics, and vendor-host proximity. Recursive with `MAX_DEPTH = 3`. Toggle off by setting `enable_deep_scan = false` in `config.toml`.").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "Both scanners are tuned by `Config.sensitivity` (1 = strict, 5 = loose). The dial maps to concrete entropy and length thresholds in `Detector::from_config`.").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "## Validators").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "Several patterns are gated by a checksum validator on top of the regex match - the regex shape alone is not enough to trigger redaction:").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "- **Luhn** - payment cards (Visa, Mastercard, Amex, Discover, JCB, Diners, UnionPay)."
    )
    .unwrap();
    writeln!(
        out,
        "- **IBAN mod-97** - international bank account numbers."
    )
    .unwrap();
    writeln!(
        out,
        "- **Passport MRZ check digits** - ICAO 9303 machine-readable zone shapes."
    )
    .unwrap();
    writeln!(out, "- **Mod-10 / mod-11** - select national ID and tax-number schemes (codice fiscale, CPF, EIN, SSN composite, NHS, NPI).").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "`Medium`-severity patterns WITHOUT a validator are filtered out before redaction, which keeps the format-only PII layer from over-redacting on adjacent text (order numbers, tracking IDs, etc.).").unwrap();

    print!("{out}");
}
