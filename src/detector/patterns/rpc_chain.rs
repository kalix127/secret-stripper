use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Infura Endpoint URL with Project ID",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(r"[a-z0-9-]+\.infura\.io/v3/[0-9a-f]{32}"),
        },
        SecretPattern {
            name: "Infura Endpoint URL with Project Secret",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(r"https://:[0-9a-f]{32}@[a-z0-9-]+\.infura\.io/v3/[0-9a-f]{32}"),
        },
        SecretPattern {
            name: "Alchemy Endpoint URL with API Key",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(r"[a-z0-9-]+\.g\.alchemy\.com/v2/[A-Za-z0-9_-]{32}"),
        },
        SecretPattern {
            name: "Alchemy Webhook Signing Key",
            category: "RPC / Chain",
            severity: Severity::High,
            regex: re(r"\bwhsec_[A-Za-z0-9]{20,40}\b"),
        },
        SecretPattern {
            name: "QuickNode Endpoint URL with Key",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(r"[a-z0-9-]+\.quiknode\.pro/[0-9a-f]{40}"),
        },
        SecretPattern {
            name: "Ankr Multichain Endpoint URL with Token",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(r"rpc\.ankr\.com/multichain/[0-9a-f]{64}"),
        },
        SecretPattern {
            name: "Helius Endpoint URL with API Key",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(r"[a-z0-9-]+\.helius-rpc\.com/\?api-key=[0-9a-f-]{36}"),
        },
        SecretPattern {
            name: "Chainstack Endpoint URL with Key",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(r"[a-z0-9-]+\.p2pify\.com/[0-9a-f]{32}"),
        },
        SecretPattern {
            name: "Etherscan Family API Key",
            category: "RPC / Chain",
            severity: Severity::High,
            regex: re(
                r#"(?i)(?:etherscan|bscscan|polygonscan|arbiscan|snowtrace|basescan|ftmscan|gnosisscan)[a-z_-]*(?:api[_-]?key)['"]?\s*[:=]\s*['"]?[A-Z0-9]{34}"#,
            ),
        },
        SecretPattern {
            name: "The Graph Gateway API Key",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(r"gateway\.thegraph\.com/api/[0-9a-f]{32}"),
        },
        SecretPattern {
            name: "Covalent / GoldRush API Key",
            category: "RPC / Chain",
            severity: Severity::High,
            regex: re(r"\bcqt_[A-Za-z0-9]{26,40}\b"),
        },
        SecretPattern {
            name: "Bitquery OAuth Token",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(r"\bory_at_[A-Za-z0-9._-]{20,}"),
        },
        SecretPattern {
            name: "dRPC Endpoint URL with Key",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(r"\.drpc\.org/\?dkey=[A-Za-z0-9_-]{20,}"),
        },
        SecretPattern {
            name: "WalletConnect / Reown Project ID",
            category: "RPC / Chain",
            severity: Severity::High,
            regex: re(
                r#"(?i)(?:walletconnect|reown|appkit|rainbowkit)[a-z_-]*project[_-]?id['"]?\s*[:=]\s*['"]?[a-f0-9]{32}"#,
            ),
        },
        SecretPattern {
            name: "Pinata API Key",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(
                r#"(?i)pinata[a-z_-]*(?:api[_-]?key|secret)['"]?\s*[:=]\s*['"]?[A-Za-z0-9]{32,80}"#,
            ),
        },
        SecretPattern {
            name: "Web3.Storage DID Key",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(r"\bdid:key:z[1-9A-HJ-NP-Za-km-z]{40,}"),
        },
        SecretPattern {
            name: "Pimlico Endpoint URL with API Key",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(r"api\.pimlico\.io/v\d+/[a-z0-9]+/rpc\?apikey=[A-Za-z0-9_-]{20,}"),
        },
        SecretPattern {
            name: "ZeroDev Endpoint URL with Project ID",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(
                r"rpc\.zerodev\.app/api/v\d+/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            ),
        },
        SecretPattern {
            name: "Biconomy Paymaster URL with API Key",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(r"paymaster\.biconomy\.io/api/v\d+/\d+/[A-Za-z0-9_-]{32,}"),
        },
        SecretPattern {
            name: "Stackup Paymaster URL with API Key",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(r"api\.stackup\.sh/v\d+/[a-z0-9]+/[A-Za-z0-9]{32,}"),
        },
        SecretPattern {
            name: "1inch API Key",
            category: "RPC / Chain",
            severity: Severity::High,
            regex: re(r"(?:api|portal)\.1inch\.dev/[^\s?]*[?&]apiKey=[A-Za-z0-9]{22}"),
        },
        SecretPattern {
            name: "0x API Key Header",
            category: "RPC / Chain",
            severity: Severity::High,
            regex: re(r#"(?i)0x-api-key['"]?\s*[:=]\s*['"]?[A-Za-z0-9-]{32,40}"#),
        },
        SecretPattern {
            name: "Etherspot Bundler URL with API Key",
            category: "RPC / Chain",
            severity: Severity::Critical,
            regex: re(r"[a-z]+\.etherspot\.io/api/v\d+\?apikey=[A-Za-z0-9_-]{20,}"),
        },
    ]
}
