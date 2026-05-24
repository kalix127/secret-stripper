use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "SSH Public Key (RSA)",
            category: "Crypto Keys",
            severity: Severity::Low,
            regex: re(r"\bssh-rsa AAAAB3NzaC1yc2[A-Za-z0-9+/]{50,}={0,3}"),
        },
        SecretPattern {
            name: "SSH Public Key (Ed25519)",
            category: "Crypto Keys",
            severity: Severity::Low,
            regex: re(r"\bssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA[A-Za-z0-9+/]{40,}={0,3}"),
        },
        SecretPattern {
            name: "SSH Public Key (DSS)",
            category: "Crypto Keys",
            severity: Severity::Low,
            regex: re(r"\bssh-dss AAAAB3NzaC1kc3[A-Za-z0-9+/]{50,}={0,3}"),
        },
        SecretPattern {
            name: "SSH Public Key (ECDSA)",
            category: "Crypto Keys",
            severity: Severity::Low,
            regex: re(
                r"\becdsa-sha2-nistp(?:256|384|521) AAAAE2VjZHNhLXNoYTItbmlzdHA[A-Za-z0-9+/]{40,}={0,3}",
            ),
        },
        SecretPattern {
            name: "SSH Public Key (FIDO Ed25519)",
            category: "Crypto Keys",
            severity: Severity::Low,
            regex: re(r"\bsk-ssh-ed25519@openssh\.com AAAA[A-Za-z0-9+/]{40,}={0,3}"),
        },
        SecretPattern {
            name: "SSH Public Key (FIDO ECDSA)",
            category: "Crypto Keys",
            severity: Severity::Low,
            regex: re(r"\bsk-ecdsa-sha2-nistp256@openssh\.com AAAA[A-Za-z0-9+/]{40,}={0,3}"),
        },
        SecretPattern {
            name: "SSH2 Public Key Block",
            category: "Crypto Keys",
            severity: Severity::Low,
            regex: re(r"---- BEGIN SSH2 PUBLIC KEY ----"),
        },
        SecretPattern {
            name: "PuTTY Private Key File",
            category: "Crypto Keys",
            severity: Severity::Critical,
            regex: re(
                r"PuTTY-User-Key-File-[23]: (?:ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(?:256|384|521))",
            ),
        },
        SecretPattern {
            name: "Encrypted PKCS#8 Private Key",
            category: "Crypto Keys",
            severity: Severity::Critical,
            regex: re(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
        },
        SecretPattern {
            name: "PEM Encrypted Header",
            category: "Crypto Keys",
            severity: Severity::Critical,
            regex: re(r"Proc-Type: 4,ENCRYPTED"),
        },
        SecretPattern {
            name: "OpenVPN Static Key",
            category: "Crypto Keys",
            severity: Severity::Critical,
            regex: re(r"-----BEGIN OpenVPN Static key V1-----"),
        },
        SecretPattern {
            name: "X.509 Certificate",
            category: "Crypto Keys",
            severity: Severity::Low,
            regex: re(r"-----BEGIN CERTIFICATE-----"),
        },
        SecretPattern {
            name: "X.509 Certificate Request",
            category: "Crypto Keys",
            severity: Severity::Low,
            regex: re(r"-----BEGIN CERTIFICATE REQUEST-----"),
        },
        SecretPattern {
            name: "PGP Public Key Block",
            category: "Crypto Keys",
            severity: Severity::Low,
            regex: re(r"-----BEGIN PGP PUBLIC KEY BLOCK-----"),
        },
        SecretPattern {
            name: "DKIM Private Key Record",
            category: "Crypto Keys",
            severity: Severity::High,
            regex: re(r"(?i)v=DKIM1;\s*(?:k=rsa;\s*)?p=[A-Za-z0-9+/]{60,}={0,3}"),
        },
    ]
}
