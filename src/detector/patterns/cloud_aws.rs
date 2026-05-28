use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "AWS STS Temporary Access Key",
            category: "Cloud / AWS",
            severity: Severity::Critical,
            regex: re(r"\bASIA[0-9A-Z]{16}\b"),
        },
        SecretPattern {
            name: "AWS STS Bearer Token Unique ID",
            category: "Cloud / AWS",
            severity: Severity::High,
            regex: re(r"\bABIA[0-9A-Z]{16}\b"),
        },
        SecretPattern {
            name: "AWS Context-Specific Credential ID",
            category: "Cloud / AWS",
            severity: Severity::Low,
            regex: re(r"\bACCA[0-9A-Z]{16}\b"),
        },
        SecretPattern {
            name: "AWS IAM User Unique ID",
            category: "Cloud / AWS",
            severity: Severity::Low,
            regex: re(r"\bAIDA[0-9A-Z]{16}\b"),
        },
        SecretPattern {
            name: "AWS EC2 Instance Profile ID",
            category: "Cloud / AWS",
            severity: Severity::Low,
            regex: re(r"\bAIPA[0-9A-Z]{16}\b"),
        },
        SecretPattern {
            name: "AWS IAM Role Unique ID",
            category: "Cloud / AWS",
            severity: Severity::Low,
            regex: re(r"\bAROA[0-9A-Z]{16}\b"),
        },
        SecretPattern {
            name: "AWS Server Certificate ID",
            category: "Cloud / AWS",
            severity: Severity::Low,
            regex: re(r"\bASCA[0-9A-Z]{16}\b"),
        },
        SecretPattern {
            name: "AWS Public Key ID",
            category: "Cloud / AWS",
            severity: Severity::Low,
            regex: re(r"\bAPKA[0-9A-Z]{16}\b"),
        },
        SecretPattern {
            name: "AWS IAM User Group ID",
            category: "Cloud / AWS",
            severity: Severity::Low,
            regex: re(r"\bAGPA[0-9A-Z]{16}\b"),
        },
        SecretPattern {
            name: "AWS Managed Policy ID",
            category: "Cloud / AWS",
            severity: Severity::Low,
            regex: re(r"\bANPA[0-9A-Z]{16}\b"),
        },
        SecretPattern {
            name: "AWS Managed Policy Version ID",
            category: "Cloud / AWS",
            severity: Severity::Low,
            regex: re(r"\bANVA[0-9A-Z]{16}\b"),
        },
        SecretPattern {
            name: "AWS IAM ARN",
            category: "Cloud / AWS",
            severity: Severity::Medium,
            regex: re(
                r"arn:aws:iam::\d{12}:(?:user|role|group|policy|instance-profile)/[A-Za-z0-9+=,.@_/-]+",
            ),
        },
        SecretPattern {
            name: "AWS STS Assumed-Role ARN",
            category: "Cloud / AWS",
            severity: Severity::High,
            regex: re(r"arn:aws:sts::\d{12}:assumed-role/[A-Za-z0-9+=,.@_-]+/[A-Za-z0-9+=,.@_-]+"),
        },
        SecretPattern {
            name: "AWS KMS Key ARN",
            category: "Cloud / AWS",
            severity: Severity::Medium,
            regex: re(r"arn:aws:kms:[a-z0-9-]+:\d{12}:key/[0-9a-f-]{36}"),
        },
        SecretPattern {
            name: "AWS Secrets Manager ARN",
            category: "Cloud / AWS",
            severity: Severity::High,
            regex: re(
                r"arn:aws:secretsmanager:[a-z0-9-]+:\d{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}",
            ),
        },
        SecretPattern {
            name: "AWS DynamoDB Stream ARN",
            category: "Cloud / AWS",
            severity: Severity::Medium,
            regex: re(
                r"arn:aws:dynamodb:[a-z0-9-]+:\d{12}:table/[^/\s]+/stream/\d{4}-\d{2}-\d{2}T[0-9:.]+",
            ),
        },
        SecretPattern {
            name: "AWS IoT Thing ARN",
            category: "Cloud / AWS",
            severity: Severity::Medium,
            regex: re(r"arn:aws:iot:[a-z0-9-]+:\d{12}:thing/[A-Za-z0-9_-]+"),
        },
        SecretPattern {
            name: "AWS AppSync API Key",
            category: "Cloud / AWS",
            severity: Severity::High,
            regex: re(r"\bda2-[a-z0-9]{26}\b"),
        },
        SecretPattern {
            name: "AWS S3 Presigned URL",
            category: "Cloud / AWS",
            severity: Severity::Critical,
            regex: re(r"https://[^/\s]+\.s3[.-][^/\s]+/[^\s]*[?&]X-Amz-Signature=[0-9a-f]{64}"),
        },
        SecretPattern {
            name: "AWS S3 Presigned URL (legacy v2)",
            category: "Cloud / AWS",
            severity: Severity::Critical,
            regex: re(
                r"[?&]AWSAccessKeyId=(?:AKIA|ASIA)[0-9A-Z]{16}&[^\s]*Signature=[A-Za-z0-9%/+=]+",
            ),
        },
        SecretPattern {
            name: "AWS CloudFront Signed URL",
            category: "Cloud / AWS",
            severity: Severity::Critical,
            regex: re(r"[?&]Signature=[A-Za-z0-9~_-]+&Key-Pair-Id=APKA[0-9A-Z]{16}"),
        },
        SecretPattern {
            name: "AWS EKS aws-auth Bearer Token",
            category: "Cloud / AWS",
            severity: Severity::Critical,
            regex: re(r"\bk8s-aws-v1\.[A-Za-z0-9_-]{20,}"),
        },
        SecretPattern {
            name: "AWS SigV4 Authorization Header",
            category: "Cloud / AWS",
            severity: Severity::Critical,
            regex: re(r"AWS4-HMAC-SHA256 Credential=(?:AKIA|ASIA)[0-9A-Z]{16}/[0-9A-Za-z/_-]+"),
        },
        SecretPattern {
            name: "AWS MWS Auth Token",
            category: "Cloud / AWS",
            severity: Severity::Critical,
            regex: re(
                r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-zA-Z]{12}",
            ),
        },
        SecretPattern {
            name: "AWS SP-API LWA Refresh Token",
            category: "Cloud / AWS",
            severity: Severity::Critical,
            regex: re(r"Atzr\|[A-Za-z0-9_-]{20,}"),
        },
        SecretPattern {
            name: "AWS SP-API LWA Access Token",
            category: "Cloud / AWS",
            severity: Severity::Critical,
            regex: re(r"Atza\|[A-Za-z0-9_-]{20,}"),
        },
        SecretPattern {
            name: "AWS Bedrock API Key (long-lived)",
            category: "Cloud / AWS",
            severity: Severity::Critical,
            regex: re(r"\bABSK[A-Za-z0-9+/]{109,269}={0,2}"),
        },
        SecretPattern {
            name: "AWS Bedrock API Key (short-lived)",
            category: "Cloud / AWS",
            severity: Severity::Critical,
            regex: re(r"bedrock-api-key-[A-Za-z0-9.-]{10,}"),
        },
        SecretPattern {
            name: "AWS SageMaker Notebook Token URL",
            category: "Cloud / AWS",
            severity: Severity::Critical,
            regex: re(
                r"https://[^/\s]+\.notebook\.[a-z0-9-]+\.sagemaker\.aws/?\?token=[A-Fa-f0-9]+",
            ),
        },
        SecretPattern {
            name: "AWS RDS IAM Auth Connection String",
            category: "Cloud / AWS",
            severity: Severity::High,
            regex: re(
                r"mysql://[A-Za-z0-9_]+@[A-Za-z0-9.-]+\.rds\.amazonaws\.com:3306/[^\s]*AWSAuthenticationPlugin",
            ),
        },
    ]
}
