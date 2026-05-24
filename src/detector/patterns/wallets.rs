use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Bitcoin BIP32 Extended Private Key (xprv)",
            category: "Crypto Wallet",
            severity: Severity::Critical,
            regex: re(r"\bxprv[1-9A-HJ-NP-Za-km-z]{107,112}\b"),
        },
        SecretPattern {
            name: "Bitcoin BIP49 Extended Private Key (yprv)",
            category: "Crypto Wallet",
            severity: Severity::Critical,
            regex: re(r"\b[yY]prv[1-9A-HJ-NP-Za-km-z]{107,112}\b"),
        },
        SecretPattern {
            name: "Bitcoin BIP84 Extended Private Key (zprv)",
            category: "Crypto Wallet",
            severity: Severity::Critical,
            regex: re(r"\b[zZ]prv[1-9A-HJ-NP-Za-km-z]{107,112}\b"),
        },
        SecretPattern {
            name: "Bitcoin BIP32 Extended Public Key (xpub)",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\bxpub[1-9A-HJ-NP-Za-km-z]{107,112}\b"),
        },
        SecretPattern {
            name: "Bitcoin BIP49/84 Extended Public Key (ypub/zpub)",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\b[yYzZ]pub[1-9A-HJ-NP-Za-km-z]{107,112}\b"),
        },
        SecretPattern {
            name: "Bitcoin WIF Private Key",
            category: "Crypto Wallet",
            severity: Severity::Critical,
            regex: re(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"),
        },
        SecretPattern {
            name: "Bitcoin P2PKH Address",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\b1[1-9A-HJ-NP-Za-km-z]{25,34}\b"),
        },
        SecretPattern {
            name: "Bitcoin P2SH Address",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\b3[1-9A-HJ-NP-Za-km-z]{25,34}\b"),
        },
        SecretPattern {
            name: "Bitcoin Bech32 Address",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\bbc1[02-9ac-hj-np-z]{11,71}\b"),
        },
        SecretPattern {
            name: "Bitcoin Taproot Address (P2TR)",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\bbc1p[02-9ac-hj-np-z]{58}\b"),
        },
        SecretPattern {
            name: "Litecoin Address",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\b(?:ltc1[02-9ac-hj-np-z]{11,71}|[LM][1-9A-HJ-NP-Za-km-z]{25,34})\b"),
        },
        SecretPattern {
            name: "EVM Private Key (labeled)",
            category: "Crypto Wallet",
            severity: Severity::Critical,
            regex: re(r"(?i)\b(?:private[_ ]?key|privkey)\b\W{0,3}(?:0x)?[a-fA-F0-9]{64}\b"),
        },
        SecretPattern {
            name: "EVM Address",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\b0x[a-fA-F0-9]{40}\b"),
        },
        SecretPattern {
            name: "Solana Keypair Byte Array",
            category: "Crypto Wallet",
            severity: Severity::Critical,
            regex: re(r"\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]"),
        },
        SecretPattern {
            name: "Solana Address",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b"),
        },
        SecretPattern {
            name: "Cardano Shelley Address",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\baddr1[02-9ac-hj-np-z]{50,}\b"),
        },
        SecretPattern {
            name: "Cardano Stake Address",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\bstake1[02-9ac-hj-np-z]{50,}\b"),
        },
        SecretPattern {
            name: "Cosmos Ecosystem Address",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(
                r"\b(?:cosmos|osmo|juno|stars|akash|kava|secret|inj|sei|celestia|dydx|terra|regen|band|kujira|evmos|axelar|stride|chihuahua|comdex|migaloo|noble|persistence|umee|agoric|gravity)1[02-9ac-hj-np-z]{38,}\b",
            ),
        },
        SecretPattern {
            name: "Tezos Address",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\b(?:tz1|tz2|tz3|KT1)[1-9A-HJ-NP-Za-km-z]{33}\b"),
        },
        SecretPattern {
            name: "Tezos edsk Private Key",
            category: "Crypto Wallet",
            severity: Severity::Critical,
            regex: re(r"\bedsk[1-9A-HJ-NP-Za-km-z]{50,}\b"),
        },
        SecretPattern {
            name: "XRP Ledger Address",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\br[1-9A-HJ-NP-Za-km-z]{24,34}\b"),
        },
        SecretPattern {
            name: "Stellar Public Key",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\bG[A-Z2-7]{55}\b"),
        },
        SecretPattern {
            name: "Stellar Secret Seed",
            category: "Crypto Wallet",
            severity: Severity::Critical,
            regex: re(r"\bS[A-Z2-7]{55}\b"),
        },
        SecretPattern {
            name: "Tron Address",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b"),
        },
        SecretPattern {
            name: "Monero Address",
            category: "Crypto Wallet",
            severity: Severity::Low,
            regex: re(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
        },
        SecretPattern {
            name: "Ethereum v3 Keystore JSON",
            category: "Crypto Wallet",
            severity: Severity::Critical,
            regex: re(r#"(?i)"crypto"\s*:\s*\{[^}]*"ciphertext""#),
        },
        SecretPattern {
            name: "MetaMask Vault",
            category: "Crypto Wallet",
            severity: Severity::Critical,
            regex: re(
                r#"\{"data":"[A-Za-z0-9+/=]+","iv":"[A-Za-z0-9+/=]+","salt":"[A-Za-z0-9+/=]+"\}"#,
            ),
        },
        SecretPattern {
            name: "Sui Private Key",
            category: "Crypto Wallet",
            severity: Severity::Critical,
            regex: re(r"\bsuiprivkey1[02-9ac-hj-np-z]{59}\b"),
        },
        SecretPattern {
            name: "Aptos Private Key (AIP-80)",
            category: "Crypto Wallet",
            severity: Severity::Critical,
            regex: re(r"\b(?:ed25519|secp256k1)-priv-0x[0-9a-fA-F]{64}\b"),
        },
    ]
}
