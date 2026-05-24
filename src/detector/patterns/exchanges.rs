use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Coinbase CDP API Key Name",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(r"organizations/[0-9a-f-]{36}/apiKeys/[0-9a-f-]{36}"),
        },
        SecretPattern {
            name: "Coinbase Pro API Secret",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)(?:cb-access|coinbase)[a-z_-]*(?:secret|key)['"]?\s*[:=]\s*['"]?[A-Za-z0-9+/]{86,88}={0,2}"#,
            ),
        },
        SecretPattern {
            name: "Kraken API Key",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(r#"(?i)kraken[a-z_-]*(?:key|secret)['"]?\s*[:=]\s*['"]?[A-Za-z0-9+/]{56}"#),
        },
        SecretPattern {
            name: "Binance API Key",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)binance[a-z_-]*(?:api[_-]?key|secret(?:[_-]?key)?)['"]?\s*[:=]\s*['"]?[A-Za-z0-9]{64}"#,
            ),
        },
        SecretPattern {
            name: "Gemini API Key (master)",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(r"\bmaster-[A-Za-z0-9]{20,30}\b"),
        },
        SecretPattern {
            name: "Gemini API Key (account)",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(r"\baccount-[A-Za-z0-9]{20,30}\b"),
        },
        SecretPattern {
            name: "KuCoin Passphrase",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)kucoin[a-z_-]*pass(?:phrase)?['"]?\s*[:=]\s*['"]?[A-Za-z0-9!@#$%^&*_-]{6,32}"#,
            ),
        },
        SecretPattern {
            name: "OKX Secret Key",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(r#"(?i)okx[a-z_-]*(?:secret|api[_-]?key)['"]?\s*[:=]\s*['"]?[A-F0-9]{32}"#),
        },
        SecretPattern {
            name: "Bybit API Secret",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)bybit[a-z_-]*(?:api[_-]?key|secret)['"]?\s*[:=]\s*['"]?[A-Za-z0-9]{18,36}"#,
            ),
        },
        SecretPattern {
            name: "Bitget API Key",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)bitget[a-z_-]*(?:api[_-]?key|secret|pass(?:phrase)?)['"]?\s*[:=]\s*['"]?[A-Za-z0-9!@#$%^&*_-]{16,64}"#,
            ),
        },
        SecretPattern {
            name: "Gate.io API Key",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)gate(?:io|\.io)?[a-z_-]*(?:api[_-]?key|secret)['"]?\s*[:=]\s*['"]?[A-Za-z0-9]{32}"#,
            ),
        },
        SecretPattern {
            name: "MEXC API Key",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(r"\bmx0[A-Za-z0-9]{30,40}\b"),
        },
        SecretPattern {
            name: "HTX (Huobi) API Key",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)(?:htx|huobi)[a-z_-]*(?:api[_-]?key|secret)['"]?\s*[:=]\s*['"]?[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{6}"#,
            ),
        },
        SecretPattern {
            name: "Crypto.com Exchange API Key",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)crypto[_.]?com[a-z_-]*(?:api[_-]?key|secret)['"]?\s*[:=]\s*['"]?[A-Za-z0-9]{20,40}"#,
            ),
        },
        SecretPattern {
            name: "dYdX StarkEx Stark Key",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(r#"(?i)(?:dydx|stark)[a-z_-]*key['"]?\s*[:=]\s*['"]?0x[a-fA-F0-9]{63,64}"#),
        },
        SecretPattern {
            name: "Fireblocks API Key",
            category: "Exchange",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)fireblocks[a-z_-]*(?:api[_-]?key|key)['"]?\s*[:=]\s*['"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#,
            ),
        },
        SecretPattern {
            name: "Robinhood Crypto API Key",
            category: "Exchange",
            severity: Severity::High,
            regex: re(r"\brh-api-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
        },
    ]
}
