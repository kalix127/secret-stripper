mod cli;
mod clipboard;
mod hotkey;
mod migrate;
mod notify;
mod paste;
mod paste_guard;
mod proc;
mod shortcut;
mod tui;
mod updater;

pub use secret_stripper::{ai_tui, config, detector, lang, redact_cli, shell_rc, stats};

/// Product name. Single source so window/notification/shortcut labels stay
/// consistent; deliberately not localized (it is a proper noun).
pub const APP_NAME: &str = "Secret Stripper";

use clap::Parser;
use config::Config;

fn main() -> anyhow::Result<()> {
    let args = cli::Cli::parse();
    setup_logging(&args);

    if matches!(
        args.command,
        cli::Command::Init
            | cli::Command::Paste { .. }
            | cli::Command::Menu
            | cli::Command::Status
            | cli::Command::RegisterShortcut
            | cli::Command::UpgradeCheck { .. }
    ) {
        migrate::run();
    }

    match args.command {
        cli::Command::Init => run_init()?,
        cli::Command::Paste { terminal } => paste::run(terminal)?,
        cli::Command::Menu => run_menu()?,
        cli::Command::Status => print_status()?,
        cli::Command::RegisterShortcut => run_register_shortcut()?,
        cli::Command::UnregisterShortcut => run_unregister_shortcut()?,
        cli::Command::Uninstall => run_uninstall()?,
        cli::Command::Upgrade => updater::run_upgrade()?,
        cli::Command::UpgradeCheck { auto_install } => updater::run_upgrade_check(auto_install)?,
        cli::Command::Redact => redact_cli::run_redact()?,
        cli::Command::PasteGuard { argv } => {
            let cfg = Config::load();
            let code = paste_guard::run(&argv, &cfg)?;
            std::process::exit(code);
        }
        cli::Command::ServeClipboard => clipboard::serve_from_stdin()?,
    }

    Ok(())
}

fn setup_logging(args: &cli::Cli) {
    let level = match args.log_level.as_deref() {
        Some("error") => log::LevelFilter::Error,
        Some("warn") => log::LevelFilter::Warn,
        Some("info") => log::LevelFilter::Info,
        Some("debug") => log::LevelFilter::Debug,
        _ => log::LevelFilter::Warn,
    };
    // arboard logs a WARN on every read on GNOME Wayland because Mutter does
    // not expose ext-data-control / wlr-data-control. The X11 fallback works,
    // so demote arboard to error-only - real clipboard failures still surface.
    let _ = env_logger::Builder::new()
        .filter_level(level)
        .filter_module("arboard", log::LevelFilter::Error)
        .try_init();
}

fn run_menu() -> anyhow::Result<()> {
    let mut config = Config::load();
    if !config.onboarding_done {
        // No (or partial) config: config.lang would be the EN default rather
        // than the user's locale, so resolve the language independently.
        println!("{}", lang::Lang::active().cli_no_config());
        return Ok(());
    }

    // show_menu loops internally; it tears the terminal down before
    // returning, so upgrade/uninstall run here with visible stdout.
    match tui::menu::show_menu(&mut config)? {
        Some(tui::menu::MenuAction::Upgrade) => {
            println!();
            let _ = updater::run_upgrade();
        }
        Some(tui::menu::MenuAction::Uninstall) => {
            println!();
            run_uninstall()?;
        }
        Some(tui::menu::MenuAction::Quit) | None => {}
    }
    Ok(())
}

fn run_uninstall() -> anyhow::Result<()> {
    let lang = lang::Lang::active();
    let _ = shortcut::unregister();
    let _ = updater::uninstall_update_check_timer();

    // Trim our managed alias block from the user's shell rc. Best effort:
    // unknown shell, missing rc, or unreadable rc just skips silently.
    // Honors SECRET_STRIPPER_NO_OS_SIDE_EFFECTS via shell_rc::uninstall_aliases.
    if let Some(shell) = shell_rc::Shell::from_env() {
        if let Some(rc) = shell.rc_path() {
            if let Ok(true) = shell_rc::uninstall_aliases(&rc) {
                println!("{}", lang.ai_tui_alias_removed(&rc.display().to_string()));
            }
        }
    }

    let removed = config::purge_config_dir();

    println!("{}", lang.cli_uninstall_done());
    println!("{}", lang.cli_uninstall_de_cleared());
    if removed.is_empty() {
        println!("{}", lang.cli_uninstall_nothing());
    } else {
        println!("{}", lang.cli_uninstall_files(&removed.join(", ")));
    }
    paste::access::print_uninstall_hint(lang);
    println!();
    println!("{}", lang.cli_run_init_again());
    Ok(())
}

fn run_register_shortcut() -> anyhow::Result<()> {
    let config = Config::load();
    let lang = lang::Lang::active();
    if config.hotkey.is_empty() {
        eprintln!("{}", lang.cli_no_hotkey());
        return Ok(());
    }
    match shortcut::register(&config.hotkey) {
        Ok(backend) => {
            println!("{}", lang.shortcut_bound(&backend, &config.hotkey));
            println!("{}", lang.cli_press_to_paste(&config.hotkey));
            print_terminal_hint(lang, &config.hotkey);
        }
        Err(e) => {
            eprintln!("{}", lang.cli_register_failed(&e.to_string()));
            print_manual_bind(lang, &config.hotkey);
        }
    }
    Ok(())
}

fn print_terminal_hint(lang: lang::Lang, chord: &str) {
    if let Some(terminal) = hotkey::terminal_chord(chord) {
        println!("{}", lang.cli_terminal_hint(&terminal));
    }
}

/// Tell the user how to bind the chord themselves when no backend could.
fn print_manual_bind(lang: lang::Lang, chord: &str) {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "secret-stripper".to_string());
    println!("{}", lang.cli_register_workaround(&exe, chord));
    let examples = shortcut::manual_examples(&exe, chord);
    if !examples.is_empty() {
        println!("{}", lang.cli_bind_examples());
        for line in examples {
            println!("  {line}");
        }
    }
}

fn run_unregister_shortcut() -> anyhow::Result<()> {
    let lang = lang::Lang::active();
    if let Err(e) = shortcut::unregister() {
        eprintln!("{}", lang.cli_unregister_failed(&e.to_string()));
    } else {
        println!("{}", lang.cli_unregister_done());
    }
    Ok(())
}

// Print `label: value` rows with values column-aligned. Label widths differ
// per locale, so the pad is computed from the labels actually used.
fn print_aligned(rows: &[(&str, String)]) {
    let w = rows
        .iter()
        .map(|(l, _)| l.chars().count())
        .max()
        .unwrap_or(0)
        + 1;
    for (l, v) in rows {
        let head = format!("{}:", l);
        println!("  {head:<w$}  {v}");
    }
}

fn run_init() -> anyhow::Result<()> {
    let path = Config::path();
    if path.exists() {
        let existing = Config::load();
        if existing.onboarding_done {
            // Idempotent path: config is already there. Re-register the DE binding to
            // recover from any state where the gsettings entry got removed (manual cleanup,
            // user upgrades, etc). Don't touch the config so user preferences are preserved.
            if existing.check_for_updates {
                let _ = updater::install_update_check_timer();
            }
            let lang = existing.lang;
            let register_result = shortcut::register(&existing.hotkey);
            let de_status = match &register_result {
                Ok(backend) => lang.shortcut_bound(backend, &existing.hotkey),
                Err(e) => lang.de_status_failed(&e.to_string()),
            };
            println!(
                "{}",
                lang.cli_already_configured(&path.display().to_string())
            );
            print_aligned(&[
                (lang.lbl_hotkey(), existing.hotkey.clone()),
                (lang.lbl_de_binding(), de_status),
            ]);
            println!();
            if register_result.is_ok() {
                print_terminal_hint(lang, &existing.hotkey);
                println!();
            }
            if register_result.is_err() {
                print_manual_bind(lang, &existing.hotkey);
                println!();
            }
            paste::access::setup(lang);
            println!("{}", lang.cli_init_done_hint());
            return Ok(());
        }
    }

    let mut config = Config::first_run(lang::Lang::detect_from_env());

    let outcome = hotkey::probe(&config.hotkey);
    let preferred = config.hotkey.clone();
    let hotkey_status = match outcome.active {
        Some(ref active) => {
            config.hotkey = active.clone();
            if active == &preferred {
                config.lang.hk_available(active)
            } else {
                config.lang.hk_fallback(active, &preferred)
            }
        }
        None => config.lang.hk_none(&outcome.tried.join(", ")),
    };

    config.save()?;

    if config.check_for_updates {
        let _ = updater::install_update_check_timer();
    }

    let lang = config.lang;
    let register_result = shortcut::register(&config.hotkey);
    let de_status = match &register_result {
        Ok(backend) => lang.shortcut_bound(backend, &config.hotkey),
        Err(e) => lang.de_status_failed(&e.to_string()),
    };

    println!("{}", lang.cli_init_header());
    print_aligned(&[
        (lang.lbl_config(), path.display().to_string()),
        (
            lang.lbl_language(),
            format!("{} ({})", config.lang.endonym(), lang.suffix_autodetected()),
        ),
        (lang.lbl_hotkey(), hotkey_status),
        (lang.lbl_de_binding(), de_status),
        (
            lang.lbl_sensitivity(),
            format!("{} ({})", config.sensitivity, lang.sensitivity_balanced()),
        ),
        (lang.lbl_redact_as(), format!("'{}'", config.redact_pattern)),
        (lang.lbl_deep_scan(), lang.deep_scan_on_desc().to_string()),
        (
            lang.lbl_entropy(),
            lang.entropy_state_desc(config.enable_entropy),
        ),
        (
            lang.lbl_notifications(),
            lang.notif_state_hint(config.silent),
        ),
        (
            lang.lbl_notif_timeout(),
            format!("{}s", config.notification_timeout_secs),
        ),
    ]);
    println!();
    if register_result.is_err() {
        print_manual_bind(lang, &config.hotkey);
        println!();
    }
    paste::access::setup(lang);
    if outcome.active.is_some() {
        println!("{}", lang.cli_init_usage(&config.hotkey));
        print_terminal_hint(lang, &config.hotkey);
    } else {
        eprintln!("{}", lang.cli_warn_no_hotkey());
        if let Some(err) = outcome.last_error {
            eprintln!("{}", lang.cli_last_error(&err.to_string()));
        }
    }
    // Print the general settings hint here, before the paste-guard section,
    // so the "tweak settings" line clearly applies to the defaults above
    // (sensitivity, redact pattern, notifications, etc.) and not to the
    // paste-guard alias snippet that follows.
    println!("{}", lang.cli_tweak_later());
    print_paste_guard_hint(lang);
    Ok(())
}

/// Show the user the alias snippet for paste-guard, explain why, and tell
/// them which file to paste it into. We never edit the file ourselves -
/// shell rc files belong to the user.
fn print_paste_guard_hint(lang: lang::Lang) {
    let detected = ai_tui::detect();
    if detected.is_empty() {
        println!();
        println!("{}", lang.ai_tui_none_detected());
        return;
    }

    let shell = shell_rc::Shell::from_env();
    let bins: Vec<&str> = detected.iter().map(|t| t.binary).collect();

    println!();
    println!("{}", lang.ai_tui_detected_title());
    for t in &detected {
        println!("  - {} ({})", t.label, t.binary);
    }
    println!();
    println!("{}", lang.ai_tui_why());
    println!();

    let snippet_shell = shell.unwrap_or(shell_rc::Shell::Bash);
    match shell.and_then(|s| s.rc_path().map(|p| (s, p))) {
        Some((_, path)) => {
            let path_str = path.display().to_string();
            println!("{}", lang.ai_tui_add_to_file(&path_str));
        }
        None => {
            println!("{}", lang.ai_tui_add_to_unknown_shell());
        }
    }
    println!();
    print!("{}", shell_rc::render_alias_snippet(snippet_shell, &bins));
    println!();
    println!("{}", lang.ai_tui_remove_hint());
}

fn print_status() -> anyhow::Result<()> {
    let config = Config::load();

    let lang = lang::Lang::active();
    println!("{}", lang.status_title());
    println!("===================");
    print_aligned(&[
        (lang.lbl_hotkey(), config.hotkey.clone()),
        (lang.lbl_de_binding(), shortcut::detect_desktop()),
        (lang.lbl_sensitivity(), config.sensitivity.to_string()),
        (lang.lbl_silent(), config.silent.to_string()),
        (
            lang.lbl_onboarding_done(),
            config.onboarding_done.to_string(),
        ),
        (
            lang.lbl_config_path(),
            format!("{:?}", config::Config::path()),
        ),
    ]);

    Ok(())
}
