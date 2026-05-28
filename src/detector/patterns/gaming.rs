use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Steam Web API Key",
            category: "Gaming",
            severity: Severity::Critical,
            regex: re(r"(?i)(?:webapi_key|steam[_-]?api[_-]?key|[?&]key)\s*[=:]\s*[A-F0-9]{32}\b"),
        },
        SecretPattern {
            name: "Steam Trade URL Token",
            category: "Gaming",
            severity: Severity::Medium,
            regex: re(
                r"https://steamcommunity\.com/tradeoffer/new/\?partner=[0-9]+&token=[A-Za-z0-9_-]{8}",
            ),
        },
        SecretPattern {
            name: "PlayFab Developer Secret Key",
            category: "Gaming",
            severity: Severity::Critical,
            regex: re(r"(?i)X-SecretKey\s*[=:]\s*[A-Z0-9]{40,}"),
        },
        SecretPattern {
            name: "Twitch Client ID",
            category: "Gaming",
            severity: Severity::Low,
            regex: re(r"(?i)twitch[_-]?client[_-]?id\s*[=:]\s*[a-z0-9]{30}\b"),
        },
        SecretPattern {
            name: "Twitch Client Secret",
            category: "Gaming",
            severity: Severity::Critical,
            regex: re(r"(?i)twitch[_-]?client[_-]?secret\s*[=:]\s*[a-z0-9]{30}\b"),
        },
        SecretPattern {
            name: "Twitch OAuth Token",
            category: "Gaming",
            severity: Severity::Critical,
            regex: re(r"\boauth:[a-z0-9]{30}\b"),
        },
        SecretPattern {
            name: "Roblox .ROBLOSECURITY Cookie",
            category: "Gaming",
            severity: Severity::Critical,
            regex: re(r"_\|WARNING:-DO-NOT-SHARE-THIS\.[^|]+\|_[0-9A-F]{100,}"),
        },
        SecretPattern {
            name: "Riot Games API Key",
            category: "Gaming",
            severity: Severity::Critical,
            regex: re(r"\bRGAPI-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
        },
        SecretPattern {
            name: "Epic Online Services Client ID",
            category: "Gaming",
            severity: Severity::Medium,
            regex: re(r"\bxyz[A-Za-z0-9]{37,}\b"),
        },
    ]
}
