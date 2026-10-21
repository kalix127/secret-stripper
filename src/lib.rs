#[cfg(not(target_os = "linux"))]
compile_error!(
    "secret-stripper 2.x supports Linux only; on macOS and Windows run \
     `cargo install secret-stripper --version 1.5.2`"
);

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
