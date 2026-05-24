use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "secret-stripper")]
#[command(about = "Secret Stripper - Clipboard PII/Secret Redactor")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    #[arg(long, global = true)]
    pub log_level: Option<String>,
}

#[derive(Subcommand)]
pub enum Command {
    Init,
    Trigger,
    Menu,
    Status,
    RegisterShortcut,
    UnregisterShortcut,
    Uninstall,
    Upgrade,
    /// Check the latest GitHub release and notify if a newer version exists.
    /// Designed for unattended runs (cron / systemd timer): silent on success
    /// and on network failure. Pass --auto-install to also swap the binary.
    UpgradeCheck {
        #[arg(long)]
        auto_install: bool,
    },
    /// Benchmark redact-trigger latency across the three detection presets.
    /// Hidden from --help; intended for maintainers comparing release builds.
    #[command(hide = true)]
    Bench {
        /// Iterations per preset.
        #[arg(long, default_value_t = 1000)]
        iterations: usize,
    },
}
