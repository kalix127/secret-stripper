use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "HashiCorp Vault Service Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\bhvs\.[A-Za-z0-9_-]{24,}\b"),
        },
        SecretPattern {
            name: "HashiCorp Vault Batch Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\bhvb\.[A-Za-z0-9_-]{24,}\b"),
        },
        SecretPattern {
            name: "HashiCorp Vault Recovery Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\bhvr\.[A-Za-z0-9_-]{24,}\b"),
        },
        SecretPattern {
            name: "HashiCorp Vault Transit Ciphertext",
            category: "Infra / IaC",
            severity: Severity::High,
            regex: re(r"\bvault:v[0-9]+:[A-Za-z0-9+/=_-]{20,}"),
        },
        SecretPattern {
            name: "HashiCorp Terraform Cloud Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,200}\b"),
        },
        SecretPattern {
            name: "Pulumi Access Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\bpul-[a-f0-9]{40}\b"),
        },
        SecretPattern {
            name: "Ansible Vault Encrypted Blob",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\$ANSIBLE_VAULT;1\.[12];AES256"),
        },
        SecretPattern {
            name: "Doppler Service Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\bdp\.pt\.[A-Za-z0-9]{40,}"),
        },
        SecretPattern {
            name: "Doppler CLI Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\bdp\.ct\.[A-Za-z0-9]{40,}"),
        },
        SecretPattern {
            name: "Doppler Service Account Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\bdp\.sa\.[A-Za-z0-9]{40,}"),
        },
        SecretPattern {
            name: "Doppler Personal Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\bdp\.pa\.[A-Za-z0-9]{40,}"),
        },
        SecretPattern {
            name: "Docker Hub Personal Access Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\bdckr_pat_[A-Za-z0-9_-]{27,}"),
        },
        SecretPattern {
            name: "Proxmox API Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(
                r"\b[A-Za-z0-9._-]+@[a-z]+![A-Za-z0-9_-]+=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            ),
        },
        SecretPattern {
            name: "SettleMint Personal Access Token",
            category: "Infra / IaC",
            severity: Severity::High,
            regex: re(r"\bsm_pat_[A-Za-z0-9]{16,}"),
        },
        SecretPattern {
            name: "SettleMint Application Access Token",
            category: "Infra / IaC",
            severity: Severity::High,
            regex: re(r"\bsm_aat_[A-Za-z0-9]{16,}"),
        },
        SecretPattern {
            name: "SettleMint Service Access Token",
            category: "Infra / IaC",
            severity: Severity::High,
            regex: re(r"\bsm_sat_[A-Za-z0-9]{16,}"),
        },
        SecretPattern {
            name: "Infisical Service Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\bst\.[A-Za-z0-9._-]{50,}"),
        },
        SecretPattern {
            name: "Akeyless Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\bt-[A-Za-z0-9]{40,}"),
        },
        SecretPattern {
            name: "1Password Secret Key",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(
                r"\bA3-[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b",
            ),
        },
        SecretPattern {
            name: "1Password Service Account Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\bops_[A-Za-z0-9_-]{40,}"),
        },
        SecretPattern {
            name: "Age Secret Key",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"AGE-SECRET-KEY-1[A-Z0-9]{58}"),
        },
        SecretPattern {
            name: "Doppler SCIM/Audit/Service-Account Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\bdp\.(?:said|scim|audit)\.[A-Za-z0-9]{40,44}\b"),
        },
        SecretPattern {
            name: "Bitwarden Secrets Manager Machine Token",
            category: "Infra / IaC",
            severity: Severity::Critical,
            regex: re(r"\b0\.[0-9a-fA-F-]{36}\.[A-Za-z0-9_-]{20,}:[A-Za-z0-9+/]{20,}={0,2}"),
        },
        SecretPattern {
            name: "Keeper KSM One-Time Token",
            category: "Infra / IaC",
            severity: Severity::High,
            regex: re(r"\b(?:US|EU|AU|GOV|JP|CA):[A-Za-z0-9_-]{40,50}\b"),
        },
    ]
}
