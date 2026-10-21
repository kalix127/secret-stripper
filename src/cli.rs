use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "secret-stripper")]
#[command(about = "Secret Stripper - Clipboard PII/Secret Redactor")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Log level on stderr: error, warn (default), info or debug.
    #[arg(long, global = true)]
    pub log_level: Option<String>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Set up: write the config, bind the hotkeys, install the update timer
    /// and, on Wayland, grant uinput access. Safe to run again.
    Init,
    /// Paste a redacted copy of the clipboard into the focused app, then
    /// restore the original after the app has read it. Bound to the hotkey;
    /// a clipboard without secrets pastes unchanged.
    // 1.x shortcuts and manual binds run `trigger`.
    #[command(alias = "trigger")]
    Paste {
        /// Send the terminal paste keys (Ctrl+Shift+V by default) instead of
        /// the normal ones. Bound to the hotkey plus Shift.
        #[arg(long)]
        terminal: bool,
    },
    /// Open the settings menu.
    Menu,
    /// Show the hotkeys, desktop, session and main settings.
    Status,
    /// Bind the hotkey and the terminal hotkey in the desktop's settings.
    RegisterShortcut,
    /// Remove both bindings from the desktop's settings.
    UnregisterShortcut,
    /// Remove the bindings, update timer, config and data. The program file
    /// and the uinput rule stay; the output says how to remove them.
    Uninstall,
    /// Download, verify and install the latest release.
    Upgrade,
    /// Check the latest release and notify, at most once a day, if it is
    /// newer. Run by the update timer at login; quiet on network errors.
    UpgradeCheck {
        /// Also install the new release when the binary is writable.
        #[arg(long)]
        auto_install: bool,
    },
    /// Read text from stdin, redact secrets/PII using the active config, write
    /// the result to stdout. Designed for shell pipelines and as the engine
    /// behind the `paste-guard` wrapper.
    Redact,
    /// Run a child program inside a PTY and redact any bracketed-paste
    /// payloads on the way in. Exits with the child's exit code. Use it to
    /// wrap AI TUIs like Claude Code or Codex so pasted secrets never reach
    /// the prompt.
    PasteGuard {
        /// The child command and its arguments. Pass after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        argv: Vec<String>,
    },
    #[command(hide = true)]
    ServeClipboard,
}
