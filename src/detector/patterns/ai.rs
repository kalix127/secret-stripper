use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "OpenAI Service Account Key",
            category: "AI / ML",
            severity: Severity::Critical,
            regex: re(r"\bsk-svcacct-[A-Za-z0-9_-]{40,}\b"),
        },
        SecretPattern {
            name: "OpenAI Admin API Key",
            category: "AI / ML",
            severity: Severity::Critical,
            regex: re(r"\bsk-admin-[A-Za-z0-9_-]{40,}\b"),
        },
        SecretPattern {
            name: "OpenAI User Key (no project)",
            category: "AI / ML",
            severity: Severity::Critical,
            regex: re(r"\bsk-None-[A-Za-z0-9_-]{40,}\b"),
        },
        SecretPattern {
            name: "OpenAI Project API Key",
            category: "AI / ML",
            severity: Severity::Critical,
            regex: re(r"\bsk-proj-[A-Za-z0-9_-]{40,}\b"),
        },
        SecretPattern {
            name: "OpenAI Organization ID",
            category: "AI / ML",
            severity: Severity::Medium,
            regex: re(r"\borg-[A-Za-z0-9]{24}\b"),
        },
        SecretPattern {
            name: "Anthropic API Key",
            category: "AI / ML",
            severity: Severity::Critical,
            regex: re(r"\bsk-ant-api03-[A-Za-z0-9_-]{93,108}\b"),
        },
        SecretPattern {
            name: "Anthropic Admin API Key",
            category: "AI / ML",
            severity: Severity::Critical,
            regex: re(r"\bsk-ant-admin01-[A-Za-z0-9_-]{93,108}\b"),
        },
        SecretPattern {
            name: "Groq API Key",
            category: "AI / ML",
            severity: Severity::Critical,
            regex: re(r"\bgsk_[A-Za-z0-9]{52}\b"),
        },
        SecretPattern {
            name: "Replicate API Token",
            category: "AI / ML",
            severity: Severity::Critical,
            regex: re(r"\br8_[A-Za-z0-9]{37}\b"),
        },
        SecretPattern {
            name: "HuggingFace User Access Token",
            category: "AI / ML",
            severity: Severity::Critical,
            regex: re(r"\bhf_[A-Za-z0-9]{34,40}\b"),
        },
        SecretPattern {
            name: "HuggingFace Organization API Token",
            category: "AI / ML",
            severity: Severity::Critical,
            regex: re(r"\bapi_org_[A-Za-z0-9]{34}\b"),
        },
        SecretPattern {
            name: "OpenRouter API Key",
            category: "AI / ML",
            severity: Severity::Critical,
            regex: re(r"\bsk-or-v1-[A-Fa-f0-9]{64}\b"),
        },
        SecretPattern {
            name: "Perplexity API Key",
            category: "AI / ML",
            severity: Severity::Critical,
            regex: re(r"\bpplx-[A-Za-z0-9]{48,56}\b"),
        },
        SecretPattern {
            name: "Fireworks AI API Key",
            category: "AI / ML",
            severity: Severity::Critical,
            regex: re(r"\bfw_[A-Za-z0-9]{24,}\b"),
        },
        SecretPattern {
            name: "Anyscale Endpoints API Key",
            category: "AI / ML",
            severity: Severity::Critical,
            regex: re(r"\besecret_[A-Za-z0-9]{20,}\b"),
        },
        SecretPattern {
            name: "LangSmith API Key",
            category: "AI / ML",
            severity: Severity::High,
            regex: re(r"\bls__[a-f0-9]{32}\b"),
        },
        SecretPattern {
            name: "LangChain API Key",
            category: "AI / ML",
            severity: Severity::High,
            regex: re(r"\blsv2_pt_[A-Za-z0-9_-]{20,}\b"),
        },
        SecretPattern {
            name: "Helicone API Key",
            category: "AI / ML",
            severity: Severity::High,
            regex: re(r"\bsk-helicone-[A-Za-z0-9_-]{30,}\b"),
        },
        SecretPattern {
            name: "LlamaIndex Cloud Key",
            category: "AI / ML",
            severity: Severity::High,
            regex: re(r"\bllx-[A-Za-z0-9]{40,}\b"),
        },
        SecretPattern {
            name: "Deepgram API Key",
            category: "AI / ML",
            severity: Severity::High,
            regex: re(r"\bdg_[a-f0-9]{40}\b"),
        },
        SecretPattern {
            name: "OpenAI Realtime Ephemeral Key",
            category: "AI / ML",
            severity: Severity::High,
            regex: re(r"\bek_[A-Za-z0-9_-]{40,}\b"),
        },
        SecretPattern {
            name: "Firecrawl API Key",
            category: "AI / ML",
            severity: Severity::High,
            regex: re(r"\bfc-[0-9a-f]{32}\b"),
        },
        SecretPattern {
            name: "LangSmith API Key",
            category: "AI / ML",
            severity: Severity::Critical,
            regex: re(r"\blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}\b"),
        },
        SecretPattern {
            name: "Pinecone API Key",
            category: "AI / ML",
            severity: Severity::High,
            regex: re(r"\bpcsk_[A-Za-z0-9]{5,6}_[A-Za-z0-9]{63}\b"),
        },
        SecretPattern {
            name: "ElevenLabs API Key",
            category: "AI / ML",
            severity: Severity::High,
            regex: re(r"\bsk_[a-f0-9]{48}\b"),
        },
    ]
}
