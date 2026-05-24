pub mod config;
pub mod detector;
pub mod lang;
pub mod stats;

pub use detector::deep_scan::DeepFinding;
pub use detector::patterns::{bucket_patterns, SecretPattern, Severity};
pub use detector::{DetectionResult, Detector};
