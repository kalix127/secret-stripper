mod cli;
mod clipboard;
mod hotkey;
mod notify;
mod paste_guard;
mod proc;
mod shortcut;
mod tui;
mod updater;

pub use secret_stripper::{ai_tui, config, detector, lang, redact_cli, shell_rc, stats};

/// Product name. Single source so window/notification/shortcut labels stay
/// consistent; deliberately not localized (it is a proper noun).
pub const APP_NAME: &str = "Secret Stripper";

use anyhow::Context;
use clap::Parser;
use config::Config;
use detector::Detector;

fn main() -> anyhow::Result<()> {
    let args = cli::Cli::parse();
    setup_logging(&args);

    match args.command {
        cli::Command::Init => run_init()?,
        cli::Command::Trigger => run_trigger()?,
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

fn init_monitor() -> Option<clipboard::ClipboardMonitor> {
    match clipboard::ClipboardMonitor::new(0) {
        Ok(m) => Some(m),
        Err(e) => {
            log::error!("Failed to access clipboard: {}", e);
            eprintln!(
                "{}",
                lang::Lang::active().cli_clipboard_access_failed(&e.to_string())
            );
            None
        }
    }
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
    println!();
    println!("{}", lang.cli_run_init_again());
    notify::uninstalled_notification(5, lang);
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
            println!("{}", lang.cli_press_to_redact(&config.hotkey));
        }
        Err(e) => {
            eprintln!("{}", lang.cli_register_failed(&e.to_string()));
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "secret-stripper".to_string());
            eprintln!("{}", lang.cli_register_workaround(&exe, &config.hotkey));
        }
    }
    Ok(())
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

fn run_trigger() -> anyhow::Result<()> {
    let config = Config::load();
    if !config.onboarding_done {
        eprintln!("{}", lang::Lang::active().cli_run_init_first());
        return Ok(());
    }

    let detector = Detector::from_config(&config);
    let mut monitor = match init_monitor() {
        Some(m) => m,
        None => return Ok(()),
    };

    // Source order: prefer the PRIMARY selection (highlighted text). Most Linux apps
    // populate it automatically when the user selects text with the mouse, so no Ctrl+C
    // is needed. If PRIMARY is empty (some Electron apps skip it, or the user is on a
    // platform without primary selection), fall back to the regular CLIPBOARD which
    // assumes the user pre-copied with Ctrl+C.
    let text = monitor
        .read_primary()
        .filter(|s| !s.is_empty())
        .or_else(|| monitor.read_text())
        .filter(|s| !s.is_empty());

    let text = match text {
        Some(t) => t,
        None => {
            eprintln!("{}", config.lang.cli_nothing_to_redact());
            return Ok(());
        }
    };

    // Hard size cap: a multi-MB clipboard runs every regex over the whole text
    // and can stall the engine. Skip rather than truncate: truncating could
    // split a multi-byte char or, worse, split a secret span and leave half of
    // it in the clipboard.
    const MAX_INPUT_BYTES: usize = 1024 * 1024;
    if text.len() > MAX_INPUT_BYTES {
        eprintln!(
            "{}",
            config
                .lang
                .cli_clipboard_too_large(text.len(), MAX_INPUT_BYTES)
        );
        return Ok(());
    }

    // Best-effort zeroization for buffers we own. arboard hands us a String we
    // cannot zero from outside, so anything before this point may linger; from
    // here on the local copy is wiped on drop.
    let text: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(text);

    let result = detector.scan(&text);
    if !result.has_secrets {
        eprintln!("{}", config.lang.cli_no_secrets());
        return Ok(());
    }

    let entropy_tokens: Vec<&str> = result
        .high_entropy_tokens
        .iter()
        .map(|(t, _)| t.as_str())
        .collect();
    let mut deep_spans: Vec<(usize, usize, &'static str)> = result
        .deep_findings
        .iter()
        .filter_map(|f| f.span.map(|(s, e)| (s, e, f.finding_type)))
        .collect();
    deep_spans.extend(result.extra_spans.iter().copied());
    let redacted: zeroize::Zeroizing<String> =
        zeroize::Zeroizing::new(detector::redact::redact_with_spans(
            &text,
            &result.matched_spans,
            &entropy_tokens,
            &deep_spans,
            detector.allowlist(),
            config.redact_style,
            &config.redact_pattern,
        ));

    let total = result.matched_patterns.len()
        + result.deep_findings.len()
        + result.high_entropy_tokens.len();

    // Fallback: detection found something but the redactor produced an
    // identical string. This happens when only deep-scan caught the secret
    // (DeepFinding does not carry the matched span). Fail-closed per style:
    // Marker writes the configured marker; Typed writes [SECRET]; Drop empties
    // the clipboard and force-notifies regardless of `silent` so an empty
    // clipboard does not look like silent breakage.
    let drop_fallback_fired =
        *redacted == *text && matches!(config.redact_style, config::RedactStyle::Drop);
    let to_write: zeroize::Zeroizing<String> = if *redacted == *text {
        let fallback = match config.redact_style {
            config::RedactStyle::Marker => config.redact_pattern.clone(),
            config::RedactStyle::Typed => "[SECRET]".to_string(),
            config::RedactStyle::Drop => String::new(),
        };
        zeroize::Zeroizing::new(fallback)
    } else {
        redacted
    };

    // The high-entropy token plaintext lives in `result` as a plain String;
    // it is no longer needed past this point, so drop it before the clipboard
    // round-trip rather than letting it linger to function end.
    drop(entropy_tokens);
    drop(result);

    if let Err(e) = monitor.replace_text(&to_write) {
        log::error!("clipboard write failed: {}", e);
        let clear_ok = monitor.replace_text("").is_ok();
        // Safety override: notify on write failure regardless of config.silent.
        notify::write_failed_notification(config.notification_timeout_secs, config.lang, clear_ok);
        eprintln!(
            "{}",
            config
                .lang
                .cli_clipboard_write_failed(clear_ok, &e.to_string())
        );
        return Ok(());
    }

    eprintln!("{}", config.lang.cli_redacted(total));

    stats::append(total as u64);

    if drop_fallback_fired {
        notify::drop_fallback_notification(config.notification_timeout_secs, config.lang);
    } else if !config.silent {
        notify::redacted_notification(total, config.notification_timeout_secs, config.lang);
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
            if let Err(e) = register_result {
                return Err(e).context(lang.err_rebind_failed(&existing.hotkey));
            }
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
            lang.notif_silent_hint().to_string(),
        ),
        (
            lang.lbl_notif_timeout(),
            format!("{}s", config.notification_timeout_secs),
        ),
    ]);
    println!();
    if let Err(e) = register_result {
        return Err(e).context(lang.err_autobind_failed(&config.hotkey));
    }
    if outcome.active.is_some() {
        println!("{}", lang.cli_init_usage(&config.hotkey));
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
