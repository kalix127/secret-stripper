use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "bcrypt Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\$2[abcxy]?\$\d{2}\$[./A-Za-z0-9]{53}"),
        },
        SecretPattern {
            name: "md5crypt Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}"),
        },
        SecretPattern {
            name: "sha256crypt Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\$5\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}"),
        },
        SecretPattern {
            name: "sha512crypt Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\$6\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}"),
        },
        SecretPattern {
            name: "yescrypt Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+"),
        },
        SecretPattern {
            name: "gost-yescrypt Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\$gy\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+"),
        },
        SecretPattern {
            name: "argon2 Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(
                r"\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+(?:,keyid=[A-Za-z0-9+/]+)?(?:,data=[A-Za-z0-9+/]+)?\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+",
            ),
        },
        SecretPattern {
            name: "scrypt Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+"),
        },
        SecretPattern {
            name: "PBKDF2 Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\$pbkdf2-sha(?:1|256|512)\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+"),
        },
        SecretPattern {
            name: "phpass Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\$P\$[./A-Za-z0-9]{31}"),
        },
        SecretPattern {
            name: "phpBB3 Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\$H\$[./A-Za-z0-9]{31}"),
        },
        SecretPattern {
            name: "Drupal7 Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\$S\$[./A-Za-z0-9]{52}"),
        },
        SecretPattern {
            name: "Apache apr1 Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}"),
        },
        SecretPattern {
            name: "Kerberos krb5 Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\$krb5(?:asrep|tgs)\$\d+\$[^\s]{20,512}"),
        },
        SecretPattern {
            name: "NTLM Hash (labeled)",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"(?i)\bNTLM[:=\s]+[a-fA-F0-9]{32}\b"),
        },
        SecretPattern {
            name: "pwdump Hash Line",
            category: "Hashes",
            severity: Severity::Critical,
            regex: re(r"[^:\s]+:\d+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::"),
        },
        SecretPattern {
            name: "htpasswd Hash Line",
            category: "Hashes",
            severity: Severity::Critical,
            regex: re(r"(?m)^[A-Za-z0-9._-]+:\$(?:2[aby]?|apr1|1|5|6|y)\$[./A-Za-z0-9$,=+]+"),
        },
        SecretPattern {
            name: "shadow Hash Line",
            category: "Hashes",
            severity: Severity::Critical,
            regex: re(r"(?m)^[A-Za-z0-9._-]+:\$[0-9a-z]+\$[^:]+:"),
        },
        SecretPattern {
            name: "LDAP/Dovecot {SCHEME} Hash",
            category: "Hashes",
            severity: Severity::Critical,
            regex: re(
                r"(?i)\{(?:s?sha(?:256|512)?|s?md5|crypt|cleartext|plain|argon2i?d?|pbkdf2|blf-crypt|sha(?:256|512)?-crypt|md5-crypt|des-crypt|ntlm|lanman|cram-md5|digest-md5|scram-sha-(?:1|256))\}\S{6,}",
            ),
        },
        SecretPattern {
            name: "PostgreSQL SCRAM-SHA-256 Verifier",
            category: "Hashes",
            severity: Severity::Critical,
            regex: re(r"SCRAM-SHA-256\$\d+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+"),
        },
        SecretPattern {
            name: "WPA Handshake Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\bWPA\*0[12]\*[0-9A-Fa-f*]{20,}"),
        },
        SecretPattern {
            name: "Application $tag$ Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(
                r"\$(?:DCC2|krb5pa|keepass|ansible|7z|zip2|RAR3|rar5|office|pdf|bitlocker|luks|fvde|bitcoin|electrum|sshng|odf|axcrypt|telegram|ethereum|metamask|blockchain|monero|multibit|androidbackup|itunes_backup)\$[^\s]{6,512}",
            ),
        },
        SecretPattern {
            name: "Cisco Type 8/9 Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\$[89]\$[A-Za-z0-9./]{12,}\$[A-Za-z0-9./]{20,}"),
        },
        SecretPattern {
            name: "GRUB2 PBKDF2 Hash",
            category: "Hashes",
            severity: Severity::Critical,
            regex: re(r"grub\.pbkdf2\.sha512\.\d+\.[0-9A-Fa-f]+\.[0-9A-Fa-f]+"),
        },
        SecretPattern {
            name: "MySQL caching_sha2 Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\$A\$[0-9]{3}\$\S{20,}"),
        },
        SecretPattern {
            name: "Django PBKDF2 Password Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\bpbkdf2_sha(?:1|256)\$\d+\$[A-Za-z0-9+/=._-]{4,}\$[A-Za-z0-9+/=._-]{16,}"),
        },
        SecretPattern {
            name: "Werkzeug PBKDF2 Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\bpbkdf2:sha(?:1|256):\d+\$[A-Za-z0-9$+/=._-]{16,}"),
        },
        SecretPattern {
            name: "NetNTLMv2 Hash",
            category: "Hashes",
            severity: Severity::Critical,
            regex: re(
                r"\b[^\s:]{1,64}::[^\s:]{0,64}:[A-Fa-f0-9]{16}:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{16,}",
            ),
        },
        SecretPattern {
            name: "MySQL Native Password Hash",
            category: "Hashes",
            severity: Severity::High,
            regex: re(r"\*[0-9A-F]{40}\b"),
        },
    ]
}
