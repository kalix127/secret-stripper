use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "GitHub Fine-grained PAT",
            category: "VCS / CI",
            severity: Severity::Critical,
            regex: re(r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b"),
        },
        SecretPattern {
            name: "GitLab Pipeline Trigger Token",
            category: "VCS / CI",
            severity: Severity::High,
            regex: re(r"\bglptt-[A-Fa-f0-9]{40}\b"),
        },
        SecretPattern {
            name: "GitLab Runner Authentication Token",
            category: "VCS / CI",
            severity: Severity::High,
            regex: re(r"\bglrt-[A-Za-z0-9_-]{20}\b"),
        },
        SecretPattern {
            name: "GitLab Runner Registration Token",
            category: "VCS / CI",
            severity: Severity::High,
            regex: re(r"\bGR1348941[A-Za-z0-9_-]{20}\b"),
        },
        SecretPattern {
            name: "GitLab Deploy Token",
            category: "VCS / CI",
            severity: Severity::High,
            regex: re(r"\bgldt-[A-Za-z0-9_-]{20}\b"),
        },
        SecretPattern {
            name: "GitLab CI/CD Job Token",
            category: "VCS / CI",
            severity: Severity::High,
            regex: re(r"\bglcbt-[A-Za-z0-9_-]{20,}\b"),
        },
        SecretPattern {
            name: "GitLab Feed Token",
            category: "VCS / CI",
            severity: Severity::Medium,
            regex: re(r"\bglft-[A-Za-z0-9_-]{20,}\b"),
        },
        SecretPattern {
            name: "GitLab Feature Flag Client Token",
            category: "VCS / CI",
            severity: Severity::Medium,
            regex: re(r"\bglffct-[A-Za-z0-9_-]{20,}\b"),
        },
        SecretPattern {
            name: "GitLab Incoming Mail Token",
            category: "VCS / CI",
            severity: Severity::Medium,
            regex: re(r"\bglimt-[A-Za-z0-9_-]{25,}\b"),
        },
        SecretPattern {
            name: "GitLab Kubernetes Agent Token",
            category: "VCS / CI",
            severity: Severity::High,
            regex: re(r"\bglagent-[A-Za-z0-9_-]{50,}\b"),
        },
        SecretPattern {
            name: "GitLab OAuth Application Secret",
            category: "VCS / CI",
            severity: Severity::Critical,
            regex: re(r"\bgloas-[A-Za-z0-9_-]{64}\b"),
        },
        SecretPattern {
            name: "GitLab SCIM Token",
            category: "VCS / CI",
            severity: Severity::High,
            regex: re(r"\bglsoat-[A-Za-z0-9_-]{20}\b"),
        },
        SecretPattern {
            name: "GitLab Session Cookie",
            category: "VCS / CI",
            severity: Severity::High,
            regex: re(r"_gitlab_session=[A-Za-z0-9%]{20,}"),
        },
        SecretPattern {
            name: "Bitbucket App Password",
            category: "VCS / CI",
            severity: Severity::Critical,
            regex: re(r"\bATBB[A-Z0-9]{24,32}\b"),
        },
        SecretPattern {
            name: "Atlassian API Token (modern)",
            category: "VCS / CI",
            severity: Severity::Critical,
            regex: re(r"\b(?:ATATT|ATCTT)3xFfG[A-Za-z0-9\-_=]{170,}"),
        },
        SecretPattern {
            name: "Sourcegraph Access Token",
            category: "VCS / CI",
            severity: Severity::High,
            regex: re(r"\bsgp_(?:[a-f0-9]{16}_)?[A-Fa-f0-9]{40}\b"),
        },
        SecretPattern {
            name: "CircleCI Personal API Token",
            category: "VCS / CI",
            severity: Severity::High,
            regex: re(r"\bCCIPAT_[A-Za-z0-9]+_[a-f0-9]{40}\b"),
        },
        SecretPattern {
            name: "Buildkite Agent Token",
            category: "VCS / CI",
            severity: Severity::High,
            regex: re(r"\bbkua_[a-f0-9]{40,}\b"),
        },
        SecretPattern {
            name: "Buildkite API Access Token",
            category: "VCS / CI",
            severity: Severity::High,
            regex: re(r"\bbkaa_[A-Za-z0-9]{40,}\b"),
        },
        SecretPattern {
            name: "Octopus Deploy API Key",
            category: "VCS / CI",
            severity: Severity::Critical,
            regex: re(r"\bAPI-[A-Z0-9]{26}\b"),
        },
        SecretPattern {
            name: "Harness Personal Access Token",
            category: "VCS / CI",
            severity: Severity::High,
            regex: re(r"\bpat\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+\b"),
        },
        SecretPattern {
            name: "Harness Service Account Token",
            category: "VCS / CI",
            severity: Severity::High,
            regex: re(r"\bsat\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+\b"),
        },
        SecretPattern {
            name: "TravisCI Repo Encrypt Key",
            category: "VCS / CI",
            severity: Severity::High,
            regex: re(r#"(?i)secure:\s*"[A-Za-z0-9+/]{40,}={0,2}""#),
        },
    ]
}
