#[cfg(not(target_os = "linux"))]
compile_error!("secret-stripper supports Linux only");

pub mod ai_tui;
pub mod config;
pub mod detector;
pub mod image_scan;
pub mod lang;
pub mod redact_cli;
pub mod shell_rc;
pub mod stats;

pub use detector::patterns::{bucket_patterns, Severity};
pub use detector::Detector;
