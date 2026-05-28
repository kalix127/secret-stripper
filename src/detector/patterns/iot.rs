use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "AWS IoT Core ATS Endpoint",
            category: "IoT",
            severity: Severity::Low,
            regex: re(r"\b[a-z0-9]+-ats\.iot\.[a-z0-9-]+\.amazonaws\.com\b"),
        },
        SecretPattern {
            name: "Azure IoT Hub Device Connection String",
            category: "IoT",
            severity: Severity::Critical,
            regex: re(
                r"HostName=[^;\s]+\.azure-devices\.net;DeviceId=[^;\s]+;SharedAccessKey=[A-Za-z0-9+/=]{40,}",
            ),
        },
        SecretPattern {
            name: "Azure IoT Hub X.509 Connection String",
            category: "IoT",
            severity: Severity::High,
            regex: re(r"HostName=[^;\s]+\.azure-devices\.net;DeviceId=[^;\s]+;x509=true"),
        },
        SecretPattern {
            name: "Azure DPS Symmetric Key",
            category: "IoT",
            severity: Severity::Critical,
            regex: re(r"(?i)symmetric[_-]?key\s*[=:]\s*[A-Za-z0-9+/]{42,}={0,2}"),
        },
        SecretPattern {
            name: "The Things Stack API Key",
            category: "IoT",
            severity: Severity::Critical,
            regex: re(r"\bNNSXS\.[A-Z2-7]{52}\.[A-Z2-7]{52}\b"),
        },
        SecretPattern {
            name: "LoRaWAN AppKey",
            category: "IoT",
            severity: Severity::Critical,
            regex: re(r"(?i)(?:appkey|nwkskey|appskey)\s*[=:]\s*[0-9A-Fa-f]{32}\b"),
        },
        SecretPattern {
            name: "Balena Cloud Device API Key",
            category: "IoT",
            severity: Severity::Critical,
            regex: re(r"(?i)deviceapikey\s*[=:]\s*[0-9a-f]{32}\b"),
        },
        SecretPattern {
            name: "Adafruit IO Key",
            category: "IoT",
            severity: Severity::Critical,
            regex: re(r"\baio_[A-Za-z0-9]{28}\b"),
        },
        SecretPattern {
            name: "Tuya Cloud Access ID",
            category: "IoT",
            severity: Severity::High,
            regex: re(r"(?i)tuya[_-]?(?:access[_-]?id|client[_-]?id)\s*[=:]\s*[a-z0-9]{20}\b"),
        },
        SecretPattern {
            name: "Tuya Cloud Access Secret",
            category: "IoT",
            severity: Severity::Critical,
            regex: re(
                r"(?i)tuya[_-]?(?:access[_-]?secret|client[_-]?secret)\s*[=:]\s*[a-z0-9]{32}\b",
            ),
        },
        SecretPattern {
            name: "Tuya Device Local Key",
            category: "IoT",
            severity: Severity::Critical,
            regex: re(r"(?i)local_key\s*[=:]\s*[a-z0-9]{16}\b"),
        },
        SecretPattern {
            name: "RTSP Credentials URL (Hikvision)",
            category: "IoT",
            severity: Severity::Critical,
            regex: re(r"rtsp://[^:/\s]+:[^@\s]+@[0-9.]+(?::[0-9]+)?/Streaming/Channels/[0-9]+"),
        },
        SecretPattern {
            name: "RTSP Credentials URL (Dahua)",
            category: "IoT",
            severity: Severity::Critical,
            regex: re(r"rtsp://[^:/\s]+:[^@\s]+@[0-9.]+(?::[0-9]+)?/cam/realmonitor\?channel="),
        },
        SecretPattern {
            name: "RTSP Credentials URL (generic)",
            category: "IoT",
            severity: Severity::Critical,
            regex: re(r"rtsp://[^:/?@\s]+:[^@\s]+@[A-Za-z0-9.-]+(?::\d+)?/\S*"),
        },
    ]
}
