use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Dotenv Secret Line",
            category: "Structured",
            severity: Severity::Critical,
            regex: re(
                r"(?im)^\s*[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*\s*=\s*\S{6,}",
            ),
        },
        SecretPattern {
            name: "npmrc Auth Token",
            category: "Structured",
            severity: Severity::Critical,
            regex: re(r"//[^/\s]+/:_authToken=\S+"),
        },
        SecretPattern {
            name: "pypirc Password",
            category: "Structured",
            severity: Severity::Critical,
            regex: re(r"(?im)^\s*password\s*=\s*\S{6,}"),
        },
        SecretPattern {
            name: "Git Credentials URL",
            category: "Structured",
            severity: Severity::Critical,
            regex: re(r"https://[^:/\s]+:[^@/\s]+@[^/\s]+"),
        },
        SecretPattern {
            name: "Netrc Credentials",
            category: "Structured",
            severity: Severity::Critical,
            regex: re(r"(?i)machine\s+\S+\s+login\s+\S+\s+password\s+\S+"),
        },
        SecretPattern {
            name: "Docker Config Auth",
            category: "Structured",
            severity: Severity::Critical,
            regex: re(r#""auth"\s*:\s*"[A-Za-z0-9+/=]{16,}""#),
        },
        SecretPattern {
            name: "Sidekiq Sensitive URL",
            category: "Structured",
            severity: Severity::Critical,
            regex: re(r"https?://[^:/\s]+:[^@/\s]+@(?:gems|enterprise)\.contribsys\.com"),
        },
        SecretPattern {
            name: "Bundler Enterprise Creds",
            category: "Structured",
            severity: Severity::Critical,
            regex: re(r"BUNDLE_(?:ENTERPRISE|GEMS)__CONTRIBSYS__COM=[A-Za-z0-9:_-]+"),
        },
        SecretPattern {
            name: "NuGet ClearText Password",
            category: "Structured",
            severity: Severity::Critical,
            regex: re(r#"(?i)<add key="ClearTextPassword" value="[^"]+"\s*/>"#),
        },
        SecretPattern {
            name: "OAuth2 access_token Param",
            category: "Structured",
            severity: Severity::Critical,
            regex: re(r"(?i)[?&#]access_token=[A-Za-z0-9._-]{20,}"),
        },
        SecretPattern {
            name: "OAuth2 id_token Param",
            category: "Structured",
            severity: Severity::High,
            regex: re(r"(?i)[?&#]id_token=eyJ[A-Za-z0-9_-]+"),
        },
        SecretPattern {
            name: "OAuth2 code Param",
            category: "Structured",
            severity: Severity::High,
            regex: re(r"(?i)[?&]code=[A-Za-z0-9_-]{20,}"),
        },
        SecretPattern {
            name: "Password Manager Export Header",
            category: "Structured",
            severity: Severity::Critical,
            regex: re(
                r#"(?im)^(?:name,url,username,password|folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp|url,username,password,totp,extra,name,grouping,fav|"Account","Login Name","Password","Web Site")"#,
            ),
        },
        SecretPattern {
            name: "1Password 1PIF Concealed Field",
            category: "Structured",
            severity: Severity::Critical,
            regex: re(r#""k"\s*:\s*"concealed""#),
        },
        SecretPattern {
            name: "PostgreSQL .pgpass Line",
            category: "Structured",
            severity: Severity::Critical,
            regex: re(
                r"(?m)^(?:\*|[A-Za-z0-9_.-]+):(?:\*|\d{1,5}):(?:\*|[A-Za-z0-9_.-]*):[^:\n]+:\S{4,}$",
            ),
        },
        SecretPattern {
            name: "AWS Secret Access Key (labeled)",
            category: "Structured",
            severity: Severity::Critical,
            regex: re(r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}"),
        },
        SecretPattern {
            name: "kubeconfig client-key-data",
            category: "Structured",
            severity: Severity::Critical,
            regex: re(r"client-key-data:\s*[A-Za-z0-9+/=]{100,}"),
        },
    ]
}
