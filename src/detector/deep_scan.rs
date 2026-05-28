use super::entropy;
use std::collections::HashSet;
use std::sync::OnceLock;

const MAX_DEPTH: u32 = 3;

// description/severity are consumed by the binary's notification path; under the
// lib test build only finding_type is read, so the allow keeps clippy quiet
// without dropping data the other consumers need.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DeepFinding {
    pub finding_type: &'static str,
    pub description: String,
    pub severity: &'static str,
    // Byte range of the offending token in the scanned text, when the scanner
    // can pinpoint it (BIP39 run, vendor-host token). None means the finding
    // is not redactable in place and falls back to the whole-clipboard wipe.
    pub span: Option<(usize, usize)>,
}

const SECRET_KEY_INDICATORS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api_secret",
    "apisecret",
    "auth_token",
    "authtoken",
    "access_key",
    "accesskey",
    "secret_key",
    "secretkey",
    "private_key",
    "privatekey",
    "client_secret",
    "clientsecret",
    "consumer_secret",
    "consumersecret",
    "refresh_token",
    "refreshtoken",
    "session_key",
    "sessionkey",
    "auth_key",
    "authkey",
    "app_secret",
    "appsecret",
    "app_key",
    "appkey",
    "db_password",
    "dbpassword",
    "database_password",
    "ssh_key",
    "sshkey",
    "pwd",
    "passphrase",
    "cert_key",
    "certkey",
    "oci_key",
    "oci_api_key",
    "pem_key",
    "pat",
    "personal_access_token",
    "oauth",
    "bearer",
    "jwt",
    "auth",
    "credential",
    "credentials",
    "s3_key",
    "s3_secret",
    "slack_token",
    "discord_token",
    "github_token",
    "gitlab_token",
    "twilio",
    "stripe",
    "payment_key",
    "secret_key",
    "publishable_key",
    "private_key",
    "encryption_key",
    "master_key",
    "root_key",
    "admin_key",
    "service_key",
    "service_account",
    "sa_key",
];

const HIGH_VALUE_KEY_INDICATORS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api_secret",
    "auth",
    "oauth",
    "bearer",
    "jwt",
    "credential",
    "pem",
    "cert",
    "private_key",
];

pub fn deep_scan(text: &str) -> Vec<DeepFinding> {
    deep_scan_with_depth(text, 0)
}

fn deep_scan_with_depth(text: &str, depth: u32) -> Vec<DeepFinding> {
    if depth > MAX_DEPTH {
        return Vec::new();
    }

    let mut findings = Vec::new();

    findings.extend(scan_key_value_pairs(text));
    findings.extend(scan_env_format(text));
    findings.extend(scan_connection_strings(text));
    findings.extend(scan_base64_content(text, depth));
    findings.extend(scan_ssh_keys(text));
    findings.extend(scan_credential_composites(text));
    findings.extend(scan_card_pan_expiry(text));
    findings.extend(scan_json_secrets(text));
    findings.extend(scan_proximity_analysis(text));
    findings.extend(scan_vendor_host_secrets(text));
    findings.extend(scan_bip39_mnemonic(text));

    findings
}

fn bip39_set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| super::wordlists::bip39_en::WORDS.iter().copied().collect())
}

fn nonspace_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\S+").unwrap())
}

// A BIP39 seed phrase is 12/15/18/21/24 words drawn from a fixed 2048-word
// list. Twelve consecutive whitespace-separated tokens that are ALL in that
// list essentially never occur in prose (common words like "the"/"is"/"and"
// are not in the list), so a run of 12+ is a high-confidence wallet-seed leak.
fn scan_bip39_mnemonic(text: &str) -> Vec<DeepFinding> {
    let set = bip39_set();
    let mut findings = Vec::new();
    let mut run = 0usize;
    let mut run_start = 0usize;
    let mut run_end = 0usize;

    let flush = |run: usize, start: usize, end: usize, findings: &mut Vec<DeepFinding>| {
        if run >= 12 {
            findings.push(DeepFinding {
                finding_type: "BIP39 mnemonic",
                description: format!(
                    "{run} consecutive BIP39 wordlist words (likely wallet seed phrase)"
                ),
                severity: "Critical",
                span: Some((start, end)),
            });
        }
    };

    for m in nonspace_re().find_iter(text) {
        let word = m
            .as_str()
            .trim_matches(|c: char| !c.is_ascii_alphabetic())
            .to_ascii_lowercase();
        if !word.is_empty() && set.contains(word.as_str()) {
            if run == 0 {
                run_start = m.start();
            }
            run_end = m.end();
            run += 1;
        } else {
            flush(run, run_start, run_end, &mut findings);
            run = 0;
        }
    }
    flush(run, run_start, run_end, &mut findings);

    findings
}

struct VendorEntry {
    finding_type: &'static str,
    severity: &'static str,
    // A vendor host or a labelled-key prefix. Bare-shape tokens are only
    // flagged when one of these sits in the same small window.
    anchor: regex::Regex,
    // The opaque token shape (hex/uuid/base64) that has no literal anchor of
    // its own and would otherwise be a deferred catalog row.
    shape: regex::Regex,
}

fn vendor_table() -> &'static Vec<VendorEntry> {
    static TABLE: OnceLock<Vec<VendorEntry>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let hex32 = r"[a-fA-F0-9]{32}";
        let hex64 = r"[a-fA-F0-9]{64}";
        let uuid =
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}";
        let b64 = r"[A-Za-z0-9+/]{40,}={0,2}";
        let mk = |finding_type, severity, anchor: &str, shape: &str| VendorEntry {
            finding_type,
            severity,
            anchor: regex::Regex::new(anchor)
                .unwrap_or_else(|e| panic!("invalid vendor anchor {anchor:?}: {e}")),
            shape: regex::Regex::new(shape)
                .unwrap_or_else(|e| panic!("invalid vendor shape {shape:?}: {e}")),
        };
        vec![
            mk(
                "Azure Cognitive Services Key (host-gated)",
                "Critical",
                r"[a-z0-9-]{1,40}\.cognitiveservices\.azure\.com",
                hex32,
            ),
            mk(
                "Linode API Token (host-gated)",
                "Critical",
                r"\bapi\.linode\.com\b",
                hex64,
            ),
            mk(
                "Neon Database Token (host-gated)",
                "Critical",
                r"\bconsole\.neon\.tech\b",
                r"[A-Za-z0-9_-]{40,}",
            ),
            mk(
                "Hetzner Cloud Token (host-gated)",
                "Critical",
                r"\bapi\.hetzner\.cloud\b",
                r"[A-Za-z0-9]{64}",
            ),
            mk(
                "Cloudant Credential (host-gated)",
                "Critical",
                r"[a-z0-9-]{1,60}\.cloudant\.com",
                r"[A-Za-z0-9]{64}",
            ),
            mk(
                "Cloudflare R2 Access Key (host-gated)",
                "Critical",
                r"[a-z0-9]{1,40}\.r2\.cloudflarestorage\.com",
                r"[a-fA-F0-9]{32,64}",
            ),
            mk(
                "Generic API Key Header",
                "High",
                r"(?i)X-Api-Key:\s*",
                r"[A-Za-z0-9_\-./+=]{16,}",
            ),
            mk(
                "Authorization Bearer Token",
                "High",
                r"(?i)Authorization:\s*Bearer\s+",
                r"[A-Za-z0-9_\-./+=]{20,}",
            ),
            mk(
                "Authorization Basic Credential",
                "High",
                r"(?i)Authorization:\s*Basic\s+",
                r"[A-Za-z0-9+/]{16,}={0,2}",
            ),
            mk(
                "Datadog API Key (host-gated)",
                "Critical",
                r"(?i)(?:DD-API-KEY:\s*|\bapi\.datadoghq\.(?:com|eu)\b)",
                hex32,
            ),
            mk(
                "New Relic License Key (host-gated)",
                "Critical",
                r"(?i)(?:X-License-Key:\s*|\bapi\.newrelic\.com\b)",
                r"[A-Fa-f0-9x]{40}",
            ),
            mk(
                "Civo API Key (host-gated)",
                "Critical",
                r"\bapi\.civo\.com\b",
                r"[A-Za-z0-9]{40,}",
            ),
            mk(
                "Railway Token (host-gated)",
                "Critical",
                r"\bbackboard\.railway\.app\b",
                uuid,
            ),
            mk(
                "Porter Token (host-gated)",
                "Critical",
                r"\bdashboard\.porter\.run\b",
                r"[A-Za-z0-9_-]{40,}",
            ),
            mk(
                "Vultr API Key (host-gated)",
                "Critical",
                r"\bapi\.vultr\.com\b",
                r"[A-Z0-9]{36}",
            ),
            mk(
                "OVH Application Secret (host-gated)",
                "Critical",
                r"\b(?:eu|ca)\.api\.ovh\.com\b",
                r"[A-Za-z0-9]{32}",
            ),
            mk(
                "Postmark Server Token (host-gated)",
                "Critical",
                r"(?i)X-Postmark-Server-Token:\s*",
                uuid,
            ),
            mk(
                "Scaleway Secret Key (host-gated)",
                "Critical",
                r"\bapi\.scaleway\.com\b",
                uuid,
            ),
            mk(
                "Maven Central Token (host-gated)",
                "Critical",
                r"(?i)(?:central\.sonatype\.com|s01\.oss\.sonatype\.org)",
                b64,
            ),
            mk(
                "Hex.pm API Key (host-gated)",
                "Critical",
                r"\bhex\.pm\b",
                r"[A-Za-z0-9]{32,}",
            ),
            mk(
                "UpCloud API Credential (host-gated)",
                "Critical",
                r"\bapi\.upcloud\.com\b",
                r"[A-Za-z0-9+/]{16,}={0,2}",
            ),
            mk(
                "Coolify API Token (labeled)",
                "Critical",
                r#"(?i)\bcoolify[_-]?(?:api[_-]?)?token['"]?\s*[:=]\s*['"]?"#,
                r"[A-Za-z0-9]{40,}",
            ),
            mk(
                "Criteo API Token (host-gated)",
                "Critical",
                r"\bapi\.criteo\.com\b",
                b64,
            ),
            mk(
                "Xandr Token (host-gated)",
                "Critical",
                r"\b[a-z0-9-]{1,40}\.adnxs\.com\b",
                r"[A-Za-z0-9]{32,}",
            ),
            mk(
                "Twilio Auth Token (paired with Account SID)",
                "Critical",
                r"\bAC[a-f0-9]{32}\b",
                hex32,
            ),
            mk(
                "Wiz Service Account Token (host-gated)",
                "Critical",
                r"\b(?:auth\.app|api)\.wiz\.io\b",
                r"[A-Za-z0-9_-]{40,}",
            ),
            mk(
                "Censys API Secret (host-gated)",
                "Critical",
                r"\b(?:search|api)\.censys\.io\b",
                r"[A-Za-z0-9]{32,}",
            ),
            mk(
                "Tatum API Key (host-gated)",
                "Critical",
                r"\bapi\.tatum\.io\b",
                uuid,
            ),
            mk(
                "Particle Access Token (host-gated)",
                "Critical",
                r"\bapi\.particle\.io\b",
                r"[a-f0-9]{40}",
            ),
        ]
    })
}

// Flag a bare-shape token (hex/UUID/base64) only when a vendor host or a
// labelled-key prefix sits in the same window (the anchor's line plus the
// line after it). This is the home for the large tail of catalog rows whose
// token has no literal anchor of its own; requiring the anchor keeps the
// false-positive rate low. The emitted span is the token only, so redaction
// removes the secret while leaving the host/label in place.
fn scan_vendor_host_secrets(text: &str) -> Vec<DeepFinding> {
    let mut findings = Vec::new();

    for entry in vendor_table() {
        for a in entry.anchor.find_iter(text) {
            let line_start = text[..a.start()].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let eol = text[a.end()..].find('\n').map(|i| a.end() + i);
            let win_end = match eol {
                Some(p) => text[p + 1..]
                    .find('\n')
                    .map(|i| p + 1 + i)
                    .unwrap_or(text.len()),
                None => text.len(),
            };
            let window = &text[line_start..win_end];

            for s in entry.shape.find_iter(window) {
                // Cannot realistically overflow (clipboard is capped at 1 MB
                // in run_trigger); saturating_add removes the latent UB under
                // panic="abort" if that invariant ever changes.
                let abs_start = line_start.saturating_add(s.start());
                let abs_end = line_start.saturating_add(s.end());
                // Skip a shape that is actually (part of) the anchor itself,
                // e.g. the "Authorization" label word.
                if abs_start < a.end() && abs_end > a.start() {
                    continue;
                }
                findings.push(DeepFinding {
                    finding_type: entry.finding_type,
                    description: format!(
                        "{} token found next to its vendor host/label anchor",
                        entry.finding_type
                    ),
                    severity: entry.severity,
                    span: Some((abs_start, abs_end)),
                });
                break;
            }
        }
    }

    findings
}

/// Do-NOT-redact keys: anti-CSRF / OAuth-public / device-flow params are
/// not secrets even though the key contains "token"/"nonce" and the value
/// is high-entropy. Mirrors `detector::BUILTIN_ALLOWLIST` for the
/// span-less key-value / env heuristics. `key` is already lowercased.
fn is_do_not_redact_key(key: &str) -> bool {
    const MARKERS: &[&str] = &[
        "csrf",
        "xsrf",
        "verificationtoken",
        "wpnonce",
        "code_challenge",
        "user_code",
        "stripe-signature",
        "x-hub-signature",
        "x-slack-signature",
        "x-shopify-hmac",
        "webhook-signature",
    ];
    MARKERS.iter().any(|m| key.contains(m)) || key == "state" || key == "nonce"
}

fn kv_pattern_set() -> &'static [regex::Regex] {
    static RE: OnceLock<Vec<regex::Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        [
            r#""([^"]+)":\s*"([^"]{8,})""#,
            r#"'([^']+)'\s*[:=]\s*'([^']{8,})'"#,
            r"([A-Za-z_][A-Za-z0-9_-]*)\s*[:=]\s*([A-Za-z0-9_\-\.\/+=]{8,})",
        ]
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect()
    })
}

fn scan_key_value_pairs(text: &str) -> Vec<DeepFinding> {
    let mut findings = Vec::new();

    for re in kv_pattern_set() {
        for cap in re.captures_iter(text) {
            let key = cap
                .get(1)
                .map(|m| m.as_str().to_lowercase())
                .unwrap_or_default();
            let value_m = match cap.get(2) {
                Some(m) => m,
                None => continue,
            };
            let value = value_m.as_str();

            if !is_secret_key_match(&key) || is_do_not_redact_key(&key) {
                continue;
            }

            if value.len() < 8 {
                continue;
            }

            let entropy = entropy::shannon_entropy(value);
            let severity = if entropy > 4.0 || value.len() > 20 {
                "Critical"
            } else if entropy > 3.0 {
                "High"
            } else {
                "Medium"
            };

            findings.push(DeepFinding {
                finding_type: "Secret Key-Value Pair",
                description: format!(
                    "Key '{}' suggests a secret with entropy {:.2}",
                    key, entropy
                ),
                severity,
                span: Some((value_m.start(), value_m.end())),
            });
        }
    }

    findings
}

// Word-boundary match against SECRET_KEY_INDICATORS. A plain `.contains()` lets
// "pat" trigger on "pattern", "auth" trigger on "authenticate", and similar
// substring collisions across the 70-entry keyword list. We treat `_` as the
// only safe separator inside config keys.
fn is_secret_key_match(key: &str) -> bool {
    SECRET_KEY_INDICATORS.iter().any(|k| {
        key == *k
            || key.starts_with(&format!("{}_", k))
            || key.ends_with(&format!("_{}", k))
            || key.contains(&format!("_{}_", k))
    })
}

fn env_format_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r#"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['"]?([A-Za-z0-9_\-\.\/\+%=]{8,})['"]?\s*$"#,
        )
        .expect("static env-format regex must compile")
    })
}

fn scan_env_format(text: &str) -> Vec<DeepFinding> {
    let mut findings = Vec::new();
    let re = env_format_re();

    for cap in re.captures_iter(text) {
        let key = cap
            .get(1)
            .map(|m| m.as_str().to_lowercase())
            .unwrap_or_default();
        let value_m = match cap.get(2) {
            Some(m) => m,
            None => continue,
        };
        let value = value_m.as_str();

        if !is_secret_key_match(&key) || is_do_not_redact_key(&key) {
            continue;
        }

        if value.len() < 8 {
            continue;
        }

        let entropy = entropy::shannon_entropy(value);
        findings.push(DeepFinding {
            finding_type: "Environment Variable Secret",
            description: format!(
                ".env style: '{}' contains a potential secret (entropy {:.2})",
                key, entropy
            ),
            severity: if entropy > 4.0 || value.len() > 20 {
                "Critical"
            } else {
                "High"
            },
            span: Some((value_m.start(), value_m.end())),
        });
    }

    findings
}

fn conn_string_patterns() -> &'static [(regex::Regex, &'static str)] {
    static RE: OnceLock<Vec<(regex::Regex, &'static str)>> = OnceLock::new();
    RE.get_or_init(|| {
        let raw: &[(&str, &str)] = &[
            (
                r"(?i)(?:postgres(?:ql)?|mysql|mariadb)://([^:]+):([^@]+)@",
                "Database",
            ),
            (r"(?i)mongodb(?:\+srv)?://([^:]+):([^@]+)@", "MongoDB"),
            (r"(?i)redis://[^:]+:([^@]+)@", "Redis"),
            (r"(?i)rediss://[^:]+:([^@]+)@", "Redis TLS"),
            (
                r"jdbc:(?i)(mysql|postgresql|oracle|sqlserver)://[^:]+:([^:]+)@",
                "JDBC",
            ),
            (r"(?i)sqlite:///(.+\.db)", "SQLite Path"),
        ];
        raw.iter()
            .filter_map(|(p, l)| regex::Regex::new(p).ok().map(|r| (r, *l)))
            .collect()
    })
}

fn scan_connection_strings(text: &str) -> Vec<DeepFinding> {
    let mut findings = Vec::new();

    for (re, label) in conn_string_patterns() {
        if re.is_match(text) {
            findings.push(DeepFinding {
                finding_type: "Connection String",
                description: format!("{} connection string with embedded credentials", label),
                severity: "Critical",
                span: None,
            });
        }
    }

    findings
}

fn base64_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").expect("static base64 regex must compile")
    })
}

fn scan_base64_content(text: &str, depth: u32) -> Vec<DeepFinding> {
    let mut findings = Vec::new();

    let re = base64_re();

    for m in re.find_iter(text) {
        let candidate = m.as_str();
        let entropy_val = entropy::shannon_entropy(candidate);

        if entropy_val < 4.5 {
            continue;
        }

        let decoded = match base64_decode(candidate) {
            Some(d) => d,
            None => continue,
        };

        let printable_ratio = decoded
            .chars()
            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            .count() as f64
            / decoded.len().max(1) as f64;

        if printable_ratio > 0.7 && decoded.len() > 10 {
            let sub_findings = deep_scan_with_depth(&decoded, depth + 1);
            if !sub_findings.is_empty() {
                findings.push(DeepFinding {
                    finding_type: "Base64 Encoded Secret",
                    description: format!(
                        "Base64 content contains {} nested secret(s)",
                        sub_findings.len()
                    ),
                    severity: "Critical",
                    span: None,
                });
                // Sub-finding spans are offsets into the decoded string, which
                // does not exist in the original clipboard text; drop them so
                // redaction never uses a bogus range (the whole-clipboard
                // fail-closed wipe still covers the nested case).
                findings.extend(sub_findings.into_iter().map(|mut f| {
                    f.span = None;
                    f
                }));
            }
        }

        if decoded.len() >= 32 && decoded.len() <= 4096 && printable_ratio < 0.3 {
            findings.push(DeepFinding {
                finding_type: "Base64 (Binary/Key Material)",
                description: format!(
                    "Base64-encoded binary likely a key or certificate ({:.2} entropy)",
                    entropy_val
                ),
                severity: "Critical",
                span: None,
            });
        }
    }

    findings
}

fn base64_decode(s: &str) -> Option<String> {
    let padded = match s.len() % 4 {
        0 => s.to_string(),
        r => {
            let mut p = s.to_string();
            for _ in 0..(4 - r) {
                p.push('=');
            }
            p
        }
    };

    let bytes = base64_engine(&padded)?;

    String::from_utf8(bytes).ok()
}

fn base64_engine(s: &str) -> Option<Vec<u8>> {
    let chars: Vec<char> = s.chars().collect();
    let mut result = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    for &c in &chars {
        let val = match c {
            'A'..='Z' => (c as u8 - b'A') as u32,
            'a'..='z' => (c as u8 - b'a' + 26) as u32,
            '0'..='9' => (c as u8 - b'0' + 52) as u32,
            '+' => 62,
            '/' => 63,
            '=' => break,
            _ => return None,
        };
        buffer = (buffer << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Some(result)
}

fn ssh_header_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"-----BEGIN\s?(RSA|DSA|EC|OPENSSH|PGP)?\s?PRIVATE KEY-----")
            .expect("static SSH header regex must compile")
    })
}

fn ssh_footer_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"-----END\s?(RSA|DSA|EC|OPENSSH|PGP)?\s?PRIVATE KEY-----")
            .expect("static SSH footer regex must compile")
    })
}

fn ssh_pub_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp256)\s+[A-Za-z0-9+/=]{50,}",
        )
        .expect("static SSH pubkey regex must compile")
    })
}

fn scan_ssh_keys(text: &str) -> Vec<DeepFinding> {
    let mut findings = Vec::new();

    let header_re = ssh_header_re();
    let footer_re = ssh_footer_re();

    if let Some(start) = header_re.find(text) {
        if let Some(end) = footer_re.find(text) {
            let body = &text[start.end()..end.start()];
            let body_clean: String = body.chars().filter(|c| !c.is_whitespace()).collect();

            if !body_clean.is_empty() {
                let decoded = base64_decode(&body_clean);
                let is_valid = decoded.is_some();

                findings.push(DeepFinding {
                    finding_type: "Private Key",
                    description: format!(
                        "Complete private key block ({} chars body, valid base64: {})",
                        body_clean.len(),
                        if is_valid { "yes" } else { "no" }
                    ),
                    severity: "Critical",
                    span: None,
                });
            }
        } else {
            findings.push(DeepFinding {
                finding_type: "Private Key (Incomplete)",
                description:
                    "Private key header found but no footer - possible clipboard truncated"
                        .to_string(),
                severity: "High",
                span: None,
            });
        }
    }

    if ssh_pub_re().is_match(text) {
        findings.push(DeepFinding {
            finding_type: "SSH Public Key",
            description: "SSH public key material exposed".to_string(),
            severity: "Medium",
            span: None,
        });
    }

    findings
}

fn scan_credential_composites(text: &str) -> Vec<DeepFinding> {
    let mut findings = Vec::new();

    for (re, label) in credential_composite_patterns() {
        for m in re.find_iter(text) {
            findings.push(DeepFinding {
                finding_type: label,
                description: format!("{} detected in clipboard", label),
                severity: "Critical",
                span: Some((m.start(), m.end())),
            });
        }
    }

    findings
}

fn credential_composite_patterns() -> &'static [(regex::Regex, &'static str)] {
    static RE: OnceLock<Vec<(regex::Regex, &'static str)>> = OnceLock::new();
    RE.get_or_init(|| {
        let raw: &[(&str, &str)] = &[
            (
                r#"(?i)(?:login|user|username)\s*[=:]\s*['"]?\S+['"]?\s+(?:password|pass|pwd)\s*[=:]\s*['"]?\S+['"]?"#,
                "Credential Pair",
            ),
            (
                r#"(?i)(?:password|pass|pwd)\s*[=:]\s*['"]?\S+['"]?\s+(?:login|user|username)\s*[=:]\s*['"]?\S+['"]?"#,
                "Credential Pair (reversed)",
            ),
            (
                r"\b[A-Za-z0-9._%+-]+:[A-Za-z0-9!@#$%^&*()_+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                "URL Embedded Credentials",
            ),
            (
                r"http[s]?://[A-Za-z0-9_%]+:[A-Za-z0-9_%!@#$^&*()+-]+@",
                "HTTP Basic Auth",
            ),
        ];
        raw.iter()
            .filter_map(|(p, l)| regex::Regex::new(p).ok().map(|r| (r, *l)))
            .collect()
    })
}

/// Card PAN co-located with an expiry or CVV/CVC label, PAN Luhn-validated.
/// Higher confidence than a bare PAN; span covers the PAN so redaction
/// removes the number (the surviving expiry alone cannot re-trigger).
fn scan_card_pan_expiry(text: &str) -> Vec<DeepFinding> {
    static PAN: OnceLock<regex::Regex> = OnceLock::new();
    static CTX: OnceLock<regex::Regex> = OnceLock::new();
    let pan = PAN.get_or_init(|| regex::Regex::new(r"\b(?:\d[ -]?){12,18}\d\b").unwrap());
    let ctx = CTX.get_or_init(|| {
        regex::Regex::new(
            r"(?i)(?:\b(?:0[1-9]|1[0-2])[/-](?:\d{2}|\d{4})\b)|(?:\b(?:cvv2?|cvc|security\s*code)\b\D{0,4}\d{3,4})",
        )
        .unwrap()
    });

    let mut findings = Vec::new();
    for m in pan.find_iter(text) {
        let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() < 13 || digits.len() > 19 {
            continue;
        }
        if !crate::detector::validators::luhn(&digits) {
            continue;
        }
        let line_start = text[..m.start()].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let eol = text[m.end()..].find('\n').map(|i| m.end() + i);
        let win_end = match eol {
            Some(p) => text[p + 1..]
                .find('\n')
                .map(|i| p + 1 + i)
                .unwrap_or(text.len()),
            None => text.len(),
        };
        let window = &text[line_start..win_end];
        if ctx.is_match(window) {
            findings.push(DeepFinding {
                finding_type: "Card PAN with Expiry/CVV",
                description: "Luhn-valid card number co-located with expiry or CVV".to_string(),
                severity: "Critical",
                span: Some((m.start(), m.end())),
            });
        }
    }
    findings
}

fn scan_json_secrets(text: &str) -> Vec<DeepFinding> {
    let mut findings = Vec::new();

    let mut depth = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut start = None;
    let mut brace_count = 0;

    for (i, c) in text.char_indices() {
        match c {
            '{' if !in_string => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
                brace_count += 1;
            }
            '}' if !in_string => {
                depth -= 1;
                brace_count += 1;
                if depth == 0 {
                    if let Some(s) = start {
                        if brace_count > 2 {
                            let slice = &text[s..=i];
                            let has_secret_key = SECRET_KEY_INDICATORS.iter().any(|k| {
                                let search = &format!("\"{}\"", k);
                                slice.to_lowercase().contains(search)
                            });

                            if has_secret_key {
                                let values = extract_string_values(slice);
                                for (val, off) in values {
                                    if val.len() >= 8 {
                                        let ent = entropy::shannon_entropy(&val);
                                        if ent > 3.5 {
                                            let abs = s + off;
                                            findings.push(DeepFinding {
                                                finding_type: "JSON Secret",
                                                description: format!("JSON contains secret-like value (entropy {:.2})", ent),
                                                severity: if ent > 4.5 { "Critical" } else { "High" },
                                                span: Some((abs, abs + val.len())),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                    brace_count = 0;
                    start = None;
                }
            }
            '"' if !escaped => in_string = !in_string,
            '\\' if in_string => escaped = !escaped,
            _ => escaped = false,
        }
    }

    findings
}

fn string_value_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r#""([A-Za-z0-9_\-\./+]{8,})""#)
            .expect("static string-value regex must compile")
    })
}

fn extract_string_values(text: &str) -> Vec<(String, usize)> {
    let mut values = Vec::new();
    for cap in string_value_re().captures_iter(text) {
        if let Some(m) = cap.get(1) {
            values.push((m.as_str().to_string(), m.start()));
        }
    }
    values
}

fn high_value_indicator_res() -> &'static [regex::Regex] {
    static RE: OnceLock<Vec<regex::Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        HIGH_VALUE_KEY_INDICATORS
            .iter()
            .filter_map(|k| regex::Regex::new(&format!(r"(?i)\b{}\b", regex::escape(k))).ok())
            .collect()
    })
}

fn scan_proximity_analysis(text: &str) -> Vec<DeepFinding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    // Precompiled once per process; the previous code compiled
    // HIGH_VALUE_KEY_INDICATORS.len() * lines.len() regexes per call.
    let indicator_res = high_value_indicator_res();

    for (i, line) in lines.iter().enumerate() {
        let has_keyword = indicator_res.iter().any(|re| re.is_match(line));
        if !has_keyword {
            continue;
        }

        let window_start = i.saturating_sub(1);
        let window_end = (i + 2).min(lines.len());

        for (j, neighbor) in lines[window_start..window_end].iter().enumerate() {
            let j = window_start + j;
            if j == i {
                continue;
            }
            let tokens: Vec<&str> = neighbor
                .split_whitespace()
                .filter(|t| {
                    t.len() >= 16
                        && t.chars()
                            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
                })
                .collect();

            for token in &tokens {
                let ent = entropy::shannon_entropy(token);
                if ent > 3.8 {
                    let preview: String = token.chars().take(30).collect();
                    // Both `text` and `token` live in the same allocation
                    // (`token` is a &str from split_whitespace on a &str from
                    // text.lines()), so the pointer difference is the byte
                    // offset of the token within text.
                    let abs = (token.as_ptr() as usize) - (text.as_ptr() as usize);
                    findings.push(DeepFinding {
                        finding_type: "Proximity Secret",
                        description: format!(
                            "High-entropy string '{}' found near keyword on line {}",
                            preview,
                            i + 1
                        ),
                        severity: if ent > 4.5 { "Critical" } else { "High" },
                        span: Some((abs, abs + token.len())),
                    });
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_key_value_pairs_secret() {
        let findings = scan_key_value_pairs(r#"{"password": "s3cretV@lue!"}"#);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_key_value_pairs_innocuous() {
        let findings = scan_key_value_pairs(r#"{"name": "John"}"#);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_env_format() {
        let text = "DATABASE_PASSWORD=supersecret123\nAPI_KEY=abcdefghijklmnop";
        let findings = scan_env_format(text);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_connection_strings_pg() {
        let findings = scan_connection_strings("postgresql://user:pass@localhost:5432/db");
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_connection_strings_redis() {
        let findings = scan_connection_strings("redis://user:pass@localhost:6379");
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_ssh_keys_rsa() {
        let text =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
        let findings = scan_ssh_keys(text);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_credential_composites() {
        let findings = scan_credential_composites("login=admin password=hunter2");
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_card_pan_expiry() {
        // Luhn-valid PAN co-located with an expiry -> fires, span = PAN.
        let hit = scan_card_pan_expiry("pay 4111 1111 1111 1111 exp 12/25");
        assert_eq!(hit.len(), 1);
        assert!(hit[0].span.is_some());
        // CVV label form.
        assert!(!scan_card_pan_expiry("card 4111111111111111 cvv 123").is_empty());
        // Luhn-invalid PAN -> no composite.
        assert!(scan_card_pan_expiry("4111111111111112 exp 12/25").is_empty());
        // PAN with no expiry/CVV context -> no composite.
        assert!(scan_card_pan_expiry("number 4111111111111111 only").is_empty());
    }

    #[test]
    fn test_deep_scan_empty() {
        let findings = deep_scan("");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_deep_scan_no_secrets() {
        let findings = deep_scan("hello world, how are you today?");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_base64_decode() {
        let result = base64_decode("dGVzdCBzdHJpbmc=");
        assert_eq!(result, Some("test string".to_string()));
    }

    #[test]
    fn test_base64_decode_invalid() {
        let result = base64_decode("!!!invalid!!!");
        assert_eq!(result, None);
    }

    #[test]
    fn test_scan_json_secrets() {
        let text = r#"{"data": {"password": "abcdefghijklmnopqrstuvwxyz"}}"#;
        let findings = scan_json_secrets(text);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_bip39_span_covers_run() {
        // Numeric breakers normalize to empty and bound the run; the span must
        // be exactly the wordlist run, not the surrounding tokens.
        let text =
            "0000 legal winner thank year wave sausage worth useful legal winner thank yellow 9999";
        let f = scan_bip39_mnemonic(text);
        assert_eq!(f.len(), 1);
        let (s, e) = f[0].span.expect("mnemonic must carry a span");
        assert_eq!(
            &text[s..e],
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        );
    }

    #[test]
    fn test_vendor_host_requires_both_anchor_and_token() {
        // Host alone: no token in window -> nothing.
        assert!(scan_vendor_host_secrets("see api.linode.com for the docs").is_empty());
        // Token alone: no anchor -> nothing.
        assert!(scan_vendor_host_secrets(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .is_empty());
        // Both present -> a finding whose span is the token only.
        let text =
            "host api.linode.com\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let f = scan_vendor_host_secrets(text);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].finding_type, "Linode API Token (host-gated)");
        let (s, e) = f[0].span.unwrap();
        assert_eq!(e - s, 64);
    }
}
