use super::{re, SecretPattern, Severity};

pub fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Geo URI",
            category: "PII / Geo",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::GEO_URI_RE),
        },
        SecretPattern {
            name: "ISO 6709 Coordinates",
            category: "PII / Geo",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::GEO_ISO6709_RE),
        },
        SecretPattern {
            name: "Map Link Coordinates",
            category: "PII / Geo",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::GEO_MAPLINK_RE),
        },
        SecretPattern {
            name: "KML Coordinates",
            category: "PII / Geo",
            severity: Severity::High,
            regex: re(crate::detector::validators::GEO_KML_RE),
        },
        SecretPattern {
            name: "GeoJSON Point",
            category: "PII / Geo",
            severity: Severity::Medium,
            regex: re(crate::detector::validators::GEO_GEOJSON_RE),
        },
        SecretPattern {
            name: "what3words Address",
            category: "PII / Geo",
            severity: Severity::Medium,
            regex: re(r"///\p{L}{2,}\.\p{L}{2,}\.\p{L}{2,}"),
        },
        SecretPattern {
            name: "Plus Code (Open Location Code)",
            category: "PII / Geo",
            severity: Severity::Medium,
            regex: re(r"\b[23456789CFGHJMPQRVWX]{8}\+[23456789CFGHJMPQRVWX]{2,3}\b"),
        },
        SecretPattern {
            name: "WKT Geometry",
            category: "PII / Geo",
            severity: Severity::Medium,
            regex: re(r"\b(?:POINT|POLYGON|LINESTRING|MULTIPOLYGON)\s*\(\s*-?\d"),
        },
        SecretPattern {
            name: "GPX Track Point",
            category: "PII / Geo",
            severity: Severity::High,
            regex: re(r#"(?i)<(?:trkpt|wpt|rtept)\b[^>]*\blat="[-+]?\d"#),
        },
        SecretPattern {
            name: "EXIF GPS Tag",
            category: "PII / Geo",
            severity: Severity::High,
            regex: re(r"(?i)\bGPS(?:Latitude|Longitude|Position|Coordinates)(?:Ref)?\b"),
        },
        SecretPattern {
            name: "NMEA Sentence",
            category: "PII / Geo",
            severity: Severity::High,
            regex: re(r"\$(?:GP|GN|GL)(?:GGA|RMC|GLL)\b[^*\n]*\*[0-9A-Fa-f]{2}"),
        },
    ]
}
