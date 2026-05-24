use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Slack User Token",
            category: "Messaging",
            severity: Severity::Critical,
            regex: re(r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}\b"),
        },
        SecretPattern {
            name: "Slack Workflow Token",
            category: "Messaging",
            severity: Severity::High,
            regex: re(r"\bxwfp-[A-Za-z0-9-]{40,}\b"),
        },
        SecretPattern {
            name: "Slack Configuration Access Token",
            category: "Messaging",
            severity: Severity::Critical,
            regex: re(r"\bxoxe\.xox[bp]-[0-9]+-[A-Za-z0-9]+\b"),
        },
        SecretPattern {
            name: "Slack Configuration Refresh Token",
            category: "Messaging",
            severity: Severity::Critical,
            regex: re(r"\bxoxe-[0-9]+-[A-Za-z0-9-]+\b"),
        },
        SecretPattern {
            name: "Slack Legacy Token",
            category: "Messaging",
            severity: Severity::Critical,
            regex: re(r"\bxox[so]-[A-Za-z0-9-]{20,}\b"),
        },
        SecretPattern {
            name: "Slack Legacy Workspace Token",
            category: "Messaging",
            severity: Severity::High,
            regex: re(r"\bxox[ar]-[A-Za-z0-9-]{20,}\b"),
        },
        SecretPattern {
            name: "Slack Session Cookie Token",
            category: "Messaging",
            severity: Severity::High,
            regex: re(r"\bxoxc-[A-Za-z0-9-]{20,}\b"),
        },
        SecretPattern {
            name: "Discord Webhook URL",
            category: "Messaging",
            severity: Severity::High,
            regex: re(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"),
        },
        SecretPattern {
            name: "Microsoft Teams Webhook URL",
            category: "Messaging",
            severity: Severity::High,
            regex: re(
                r"https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[a-f0-9-]+@[a-f0-9-]+/IncomingWebhook/[a-f0-9]+/[a-f0-9-]+",
            ),
        },
        SecretPattern {
            name: "Twilio Account SID",
            category: "Messaging",
            severity: Severity::Medium,
            regex: re(r"\bAC[a-f0-9]{32}\b"),
        },
        SecretPattern {
            name: "SendGrid API Key",
            category: "Messaging",
            severity: Severity::Critical,
            regex: re(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
        },
        SecretPattern {
            name: "Mailgun Private API Key",
            category: "Messaging",
            severity: Severity::Critical,
            regex: re(r"\bkey-[a-f0-9]{32}\b"),
        },
        SecretPattern {
            name: "Mailgun Public Validation Key",
            category: "Messaging",
            severity: Severity::Medium,
            regex: re(r"\bpubkey-[a-f0-9]{32}\b"),
        },
        SecretPattern {
            name: "Mailchimp API Key",
            category: "Messaging",
            severity: Severity::Critical,
            regex: re(r"\b[a-f0-9]{32}-us[0-9]{1,2}\b"),
        },
        SecretPattern {
            name: "Brevo API Key",
            category: "Messaging",
            severity: Severity::Critical,
            regex: re(r"\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b"),
        },
        SecretPattern {
            name: "Resend API Key",
            category: "Messaging",
            severity: Severity::Critical,
            regex: re(r"\bre_[A-Za-z0-9_]{32,}\b"),
        },
        SecretPattern {
            name: "WhatsApp Business Cloud API Token",
            category: "Messaging",
            severity: Severity::Critical,
            regex: re(r"\bEAA[A-Za-z0-9]{60,}\b"),
        },
        SecretPattern {
            name: "Meta Graph API Page Access Token",
            category: "Messaging",
            severity: Severity::Critical,
            regex: re(r"\bEAA[MC][A-Za-z0-9]{30,}\b"),
        },
        SecretPattern {
            name: "Plivo Auth ID",
            category: "Messaging",
            severity: Severity::Medium,
            regex: re(r"\bMA[A-Z0-9]{18}\b"),
        },
        SecretPattern {
            name: "Pushbullet Access Token",
            category: "Messaging",
            severity: Severity::High,
            regex: re(r"\bo\.[A-Za-z0-9]{32}\b"),
        },
        SecretPattern {
            name: "Notion API Token",
            category: "Messaging",
            severity: Severity::High,
            regex: re(r"\bntn_[A-Za-z0-9]{40,}\b"),
        },
        SecretPattern {
            name: "Notion Internal Integration Token (legacy)",
            category: "Messaging",
            severity: Severity::High,
            regex: re(r"\bsecret_[A-Za-z0-9]{43}\b"),
        },
        SecretPattern {
            name: "Intercom API Token",
            category: "Messaging",
            severity: Severity::High,
            regex: re(r"\bdG9rOg==[A-Za-z0-9+/=]{40,}\b"),
        },
        SecretPattern {
            name: "Asana Personal Access Token",
            category: "Messaging",
            severity: Severity::High,
            regex: re(r"\b1/[0-9]+:[A-Za-z0-9]{32}\b"),
        },
        SecretPattern {
            name: "Telnyx API Key",
            category: "Messaging",
            severity: Severity::Critical,
            regex: re(r"\bKEY[0-9A-Za-z_-]{55}\b"),
        },
    ]
}
