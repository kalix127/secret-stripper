use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "HTTP Basic Authorization Header",
            category: "Auth",
            severity: Severity::High,
            regex: re(r"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/]{16,512}={0,2}"),
        },
        SecretPattern {
            name: "HTTP Token Authorization Header",
            category: "Auth",
            severity: Severity::High,
            regex: re(r"(?i)Authorization:\s*Token\s+[A-Za-z0-9_\-]{20,200}"),
        },
        SecretPattern {
            name: "curl Basic Auth Flag",
            category: "Auth",
            severity: Severity::Critical,
            regex: re(r"curl\s+(?:[^\s]+\s+)*-u\s+[^\s:]+:[^\s]+"),
        },
        SecretPattern {
            name: "OAuth2 client_secret Parameter",
            category: "Auth",
            severity: Severity::Critical,
            regex: re(r"(?i)client_secret=[A-Za-z0-9._\-]{16,200}"),
        },
        SecretPattern {
            name: "OAuth2 refresh_token Parameter",
            category: "Auth",
            severity: Severity::Critical,
            regex: re(r"(?i)refresh_token=[A-Za-z0-9._\-]{20,200}"),
        },
        SecretPattern {
            name: "OAuth2 access_token Parameter",
            category: "Auth",
            severity: Severity::High,
            regex: re(r"(?i)[?#&]access_token=[A-Za-z0-9._\-]{20,200}"),
        },
        SecretPattern {
            name: "OAuth2 client_assertion Parameter",
            category: "Auth",
            severity: Severity::Critical,
            regex: re(r"(?i)client_assertion=eyJ[A-Za-z0-9._\-]{20,}"),
        },
        SecretPattern {
            name: "OAuth2 grant_type password",
            category: "Auth",
            severity: Severity::High,
            regex: re(r"(?i)grant_type=password&[^\s]*password=[^\s&]{4,}"),
        },
        SecretPattern {
            name: "OAuth2 Authorization Code Callback",
            category: "Auth",
            severity: Severity::High,
            regex: re(r"(?i)[?&]code=[A-Za-z0-9._\-]{20,200}&(?:state|session_state|scope)="),
        },
        SecretPattern {
            name: "OAuth2 Device Code",
            category: "Auth",
            severity: Severity::High,
            regex: re(r"(?i)device_code=[A-Za-z0-9._\-]{20,200}"),
        },
        SecretPattern {
            name: "SAML Response (POST binding)",
            category: "Auth",
            severity: Severity::High,
            regex: re(r"(?i)SAMLResponse=(?:PHNhbWxw|PD94bWw)[A-Za-z0-9%+/=]{40,}"),
        },
        SecretPattern {
            name: "SAML Request (POST binding)",
            category: "Auth",
            severity: Severity::Medium,
            regex: re(r"(?i)SAMLRequest=(?:PHNhbWxw|PD94bWw)[A-Za-z0-9%+/=]{40,}"),
        },
        SecretPattern {
            name: "JWT alg none",
            category: "Auth",
            severity: Severity::Critical,
            regex: re(r"\beyJhbGciOiJub25lI[A-Za-z0-9_\-]{4,}\.eyJ[A-Za-z0-9_\-]{10,}\."),
        },
        SecretPattern {
            name: "Session Cookie Header",
            category: "Auth",
            severity: Severity::High,
            regex: re(
                r"(?i)Cookie:\s*(?:session|sessionid|sid|jsessionid|connect\.sid|auth_token)=[A-Za-z0-9%._\-+/]{16,}",
            ),
        },
        SecretPattern {
            name: "Framework Session Cookie",
            category: "Auth",
            severity: Severity::High,
            regex: re(
                r"(?i)\b(?:__(?:Host|Secure)-)?(?:sessionid|laravel_session|connect\.sid|JSESSIONID|PHPSESSID|wordpress_logged_in_[0-9a-z]+|_[A-Za-z0-9]+_session|SSESS[0-9a-f]+|sb-[a-z0-9-]+-auth-token|sb-refresh-token|__clerk_db_jwt|__Secure-next-auth\.session-token)=[A-Za-z0-9%._/+-]{20,}",
            ),
        },
        SecretPattern {
            name: "Flask Signed Session Cookie",
            category: "Auth",
            severity: Severity::High,
            regex: re(r"(?i)\bsession=[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{20,}"),
        },
        SecretPattern {
            name: "ASP.NET Core Auth Cookie",
            category: "Auth",
            severity: Severity::High,
            regex: re(
                r"(?i)\.AspNetCore\.(?:Identity\.Application|Cookies|Session)=[A-Za-z0-9%._/+-]{20,}",
            ),
        },
        SecretPattern {
            name: "Cognito Refresh Token Cookie",
            category: "Auth",
            severity: Severity::Critical,
            regex: re(
                r"CognitoIdentityServiceProvider\.[A-Za-z0-9_]+\.[^.\s]+\.refreshToken=[A-Za-z0-9._-]{20,}",
            ),
        },
        SecretPattern {
            name: "ASP.NET ViewState",
            category: "Auth",
            severity: Severity::Medium,
            regex: re(r"__VIEWSTATE=[A-Za-z0-9%+/=]{40,}"),
        },
        SecretPattern {
            name: "PKCE code_verifier",
            category: "Auth",
            severity: Severity::High,
            regex: re(r"(?i)[?&]code_verifier=[A-Za-z0-9._~-]{43,128}"),
        },
        SecretPattern {
            name: "OAuth PAR request_uri",
            category: "Auth",
            severity: Severity::High,
            regex: re(r"request_uri=urn:ietf:params:oauth:request_uri:[A-Za-z0-9._-]{6,}"),
        },
        SecretPattern {
            name: "OAuth CIBA auth_req_id",
            category: "Auth",
            severity: Severity::High,
            regex: re(r"(?i)[?&]auth_req_id=[A-Za-z0-9._-]{20,}"),
        },
        SecretPattern {
            name: "OAuth Token Exchange Token",
            category: "Auth",
            severity: Severity::High,
            regex: re(r"(?i)[?&](?:subject_token|actor_token)=[A-Za-z0-9._-]{20,}"),
        },
        SecretPattern {
            name: "OIDC id_token_hint",
            category: "Auth",
            severity: Severity::High,
            regex: re(r"(?i)[?&]id_token_hint=eyJ[A-Za-z0-9._-]{20,}"),
        },
        SecretPattern {
            name: "DPoP Proof JWT",
            category: "Auth",
            severity: Severity::High,
            regex: re(r"\bDPoP\s+eyJ[A-Za-z0-9._-]{20,}"),
        },
        SecretPattern {
            name: "GitLab PRIVATE-TOKEN Header",
            category: "Auth",
            severity: Severity::Critical,
            regex: re(r"(?i)PRIVATE-TOKEN:\s*[A-Za-z0-9_-]{20,}"),
        },
        SecretPattern {
            name: "Azure Functions Key Header",
            category: "Auth",
            severity: Severity::Critical,
            regex: re(r"(?i)x-functions-key:\s*[A-Za-z0-9_=/+-]{30,}"),
        },
        SecretPattern {
            name: "API Key Auth Header",
            category: "Auth",
            severity: Severity::High,
            regex: re(r"(?i)x-(?:api-key|auth-token):\s*[A-Za-z0-9_=/.+-]{20,}"),
        },
        SecretPattern {
            name: "Negotiate/NTLM Authorization Header",
            category: "Auth",
            severity: Severity::High,
            regex: re(
                r"(?i)Authorization:\s*(?:Negotiate|NTLM)\s+(?:YII|TlRMTVNT)[A-Za-z0-9+/=]{16,}",
            ),
        },
    ]
}
