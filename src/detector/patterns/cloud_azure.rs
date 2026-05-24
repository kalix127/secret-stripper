use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Azure Storage Connection String",
            category: "Cloud / Azure",
            severity: Severity::Critical,
            regex: re(
                r"DefaultEndpointsProtocol=https;AccountName=[a-z0-9]{3,24};AccountKey=[A-Za-z0-9+/]{86}==",
            ),
        },
        SecretPattern {
            name: "Azure Storage SAS Token",
            category: "Cloud / Azure",
            severity: Severity::Critical,
            regex: re(r"[?&]sv=\d{4}-\d{2}-\d{2}&[^\s]*sig=[A-Za-z0-9%/+=]{20,}"),
        },
        SecretPattern {
            name: "Azure Service Bus Connection String",
            category: "Cloud / Azure",
            severity: Severity::Critical,
            regex: re(
                r"Endpoint=sb://[^;\s]+\.servicebus\.windows\.net/;SharedAccessKeyName=[^;\s]+;SharedAccessKey=[A-Za-z0-9+/=]{20,}",
            ),
        },
        SecretPattern {
            name: "Azure Cosmos DB Connection String",
            category: "Cloud / Azure",
            severity: Severity::Critical,
            regex: re(
                r"AccountEndpoint=https://[a-z0-9-]+\.documents\.azure\.com:443/;AccountKey=[A-Za-z0-9+/]{86}==",
            ),
        },
        SecretPattern {
            name: "Azure Cosmos DB Account Endpoint",
            category: "Cloud / Azure",
            severity: Severity::Low,
            regex: re(r"https://[a-z0-9-]+\.documents\.azure\.com:443/?"),
        },
        SecretPattern {
            name: "Azure Key Vault Secret URI",
            category: "Cloud / Azure",
            severity: Severity::High,
            regex: re(r"https://[a-z0-9-]+\.vault\.azure\.net/secrets/[A-Za-z0-9-]+/[0-9a-f]{32}"),
        },
        SecretPattern {
            name: "Azure App Configuration Connection String",
            category: "Cloud / Azure",
            severity: Severity::Critical,
            regex: re(
                r"Endpoint=https://[^.\s]+\.azconfig\.io;Id=[^;\s]+;Secret=[A-Za-z0-9+/=]{20,}",
            ),
        },
        SecretPattern {
            name: "Azure Functions URL with Code",
            category: "Cloud / Azure",
            severity: Severity::Critical,
            regex: re(
                r"https://[^/\s]+\.azurewebsites\.net/api/[^?\s]+\?code=[A-Za-z0-9_/=-]{20,}",
            ),
        },
        SecretPattern {
            name: "Azure SQL Connection String",
            category: "Cloud / Azure",
            severity: Severity::Critical,
            regex: re(r"Server=tcp:[^,\s]+\.database\.windows\.net,1433;[^\s]*Password=[^;\s]+"),
        },
        SecretPattern {
            name: "Azure App Service Publish Profile Password",
            category: "Cloud / Azure",
            severity: Severity::Critical,
            regex: re(r#"(?i)<publishProfile[^>]*userPWD="[A-Za-z0-9]+""#),
        },
        SecretPattern {
            name: "Azure Application Insights Connection String",
            category: "Cloud / Azure",
            severity: Severity::Medium,
            regex: re(r"InstrumentationKey=[0-9a-f-]{36};IngestionEndpoint=https://[^;\s]+"),
        },
        SecretPattern {
            name: "Azure Application Insights Instrumentation Key",
            category: "Cloud / Azure",
            severity: Severity::Medium,
            regex: re(
                r"InstrumentationKey=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            ),
        },
        SecretPattern {
            name: "Azure Entra App Client Secret",
            category: "Cloud / Azure",
            severity: Severity::Critical,
            regex: re(r"\b[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}\b"),
        },
        SecretPattern {
            name: "Azure Tenant via login.microsoftonline.com",
            category: "Cloud / Azure",
            severity: Severity::Medium,
            regex: re(
                r"https://login\.microsoftonline\.com/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            ),
        },
        SecretPattern {
            name: "Azure Managed Identity Issuer",
            category: "Cloud / Azure",
            severity: Severity::Medium,
            regex: re(
                r"https://sts\.windows\.net/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            ),
        },
    ]
}
