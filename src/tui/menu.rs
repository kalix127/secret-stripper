use crate::config::Config;
use crate::tui::chrome::scaffold;
use crate::tui::manage_install::{self, Outcome};
use crate::tui::star;
use crate::tui::theme;
use crate::tui::widgets::{confirm, render_menu, MenuRow};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

pub enum MenuAction {
    Quit,
    Upgrade,
    Uninstall,
}

#[derive(Clone, Copy)]
enum MenuItem {
    ToggleNotifications,
    RebindHotkey,
    Language,
    DetectionSettings,
    RedactStyle,
    ManageInstallation,
    Exit,
    StarOnGitHub,
}

pub fn show_menu(config: &mut Config) -> anyhow::Result<Option<MenuAction>> {
    let mut terminal = ratatui::init();
    terminal.clear()?;

    let mut selected = 0usize;
    let mut flash: Option<String> = None;

    let items: [MenuItem; 8] = [
        MenuItem::ToggleNotifications,
        MenuItem::RebindHotkey,
        MenuItem::Language,
        MenuItem::DetectionSettings,
        MenuItem::RedactStyle,
        MenuItem::ManageInstallation,
        MenuItem::Exit,
        MenuItem::StarOnGitHub,
    ];
    // Indices that begin a new visual group (blank line before).
    let group_starts = [6usize, 7];

    let result = loop {
        let rows = [
            MenuRow {
                icon: "\u{1F514}",
                label: config.lang.lbl_menu_notifications().to_string(),
                icon_color: theme::icon_yellow(),
            },
            MenuRow {
                icon: "\u{1F3B9}",
                label: config.lang.lbl_rebind_hotkey(&config.hotkey),
                icon_color: theme::icon_blue(),
            },
            MenuRow {
                icon: "\u{1F310}",
                label: config.lang.lbl_menu_language(config.lang.endonym()),
                icon_color: theme::icon_green(),
            },
            MenuRow {
                icon: "\u{2699}\u{FE0F}",
                label: config.lang.lbl_detection_settings().to_string(),
                icon_color: theme::icon_green(),
            },
            MenuRow {
                icon: "\u{270F}\u{FE0F}",
                label: config.lang.dm_redact_style().to_string(),
                icon_color: theme::icon_yellow(),
            },
            MenuRow {
                icon: "\u{1F9F0}",
                label: config.lang.lbl_manage_installation().to_string(),
                icon_color: theme::icon_magenta(),
            },
            MenuRow {
                icon: "\u{1F6AA}",
                label: config.lang.lbl_exit().to_string(),
                icon_color: theme::icon_blue(),
            },
            MenuRow {
                icon: "\u{2B50}",
                label: config.lang.lbl_star_github().to_string(),
                icon_color: theme::icon_yellow(),
            },
        ];

        let footer = if let Some(msg) = &flash {
            msg.clone()
        } else {
            match items[selected] {
                MenuItem::ToggleNotifications => config.lang.help_notifications().to_string(),
                MenuItem::RebindHotkey => config.lang.help_rebind_hotkey().to_string(),
                MenuItem::Language => config.lang.help_language().to_string(),
                MenuItem::DetectionSettings => config.lang.help_detection_settings().to_string(),
                MenuItem::RedactStyle => config.lang.help_dm_redact_style().to_string(),
                MenuItem::ManageInstallation => config.lang.help_manage_installation().to_string(),
                MenuItem::Exit => config.lang.help_exit().to_string(),
                MenuItem::StarOnGitHub => config.lang.help_star_github().to_string(),
            }
        };

        terminal.draw(|f| {
            let body = scaffold(f, config.lang.section_main_menu(), &footer, config);
            render_menu(f, body, &rows, &group_starts, &[], selected);
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            flash = None;
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('c'))
            {
                break None;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break None,
                KeyCode::Up => selected = selected.saturating_sub(1),
                KeyCode::Down => selected = (selected + 1) % items.len(),
                KeyCode::Enter => match items[selected] {
                    MenuItem::ToggleNotifications => {
                        config.silent = !config.silent;
                        config.save()?;
                        continue;
                    }
                    MenuItem::RebindHotkey => {
                        let _ = crate::tui::hotkey_capture::capture_hotkey(&mut terminal, config);
                        terminal.clear()?;
                        let _ = crate::tui::drain_pending_events();
                        continue;
                    }
                    MenuItem::Language => {
                        let _ = crate::tui::language_select::select_language(&mut terminal, config);
                        terminal.clear()?;
                        let _ = crate::tui::drain_pending_events();
                        continue;
                    }
                    MenuItem::DetectionSettings => {
                        crate::tui::detection_menu::show(&mut terminal, config)?;
                        terminal.clear()?;
                        let _ = crate::tui::drain_pending_events();
                        continue;
                    }
                    MenuItem::RedactStyle => {
                        let _ = crate::tui::redact_style::show(&mut terminal, config);
                        terminal.clear()?;
                        let _ = crate::tui::drain_pending_events();
                        continue;
                    }
                    MenuItem::ManageInstallation => {
                        match manage_install::show(&mut terminal, config)? {
                            Outcome::Back => {
                                terminal.clear()?;
                                let _ = crate::tui::drain_pending_events();
                                continue;
                            }
                            // Run outside the TUI so output is visible. Tear
                            // the terminal down once (end of show_menu) then
                            // let run_menu handle it.
                            Outcome::Upgrade => break Some(MenuAction::Upgrade),
                            Outcome::Uninstall => break Some(MenuAction::Uninstall),
                        }
                    }
                    MenuItem::Exit => break Some(MenuAction::Quit),
                    MenuItem::StarOnGitHub => {
                        let yes = confirm(
                            &mut terminal,
                            config,
                            config.lang.star_title(),
                            config.lang.star_question(),
                            star::REPO_URL,
                            config.lang.star_hint(),
                        )?;
                        if yes {
                            flash = match star::open_url(star::REPO_URL) {
                                Ok(()) => Some(config.lang.star_opened().to_string()),
                                Err(_) => Some(config.lang.star_open_failed().to_string()),
                            };
                        }
                        terminal.clear()?;
                        let _ = crate::tui::drain_pending_events();
                        continue;
                    }
                },
                _ => {}
            }
        }
    };

    ratatui::restore();
    Ok(result)
}
