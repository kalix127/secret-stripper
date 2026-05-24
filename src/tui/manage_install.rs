use crate::config::Config;
use crate::shortcut;
use crate::tui::chrome::scaffold;
use crate::tui::theme;
use crate::tui::widgets::{confirm, render_menu, MenuRow};
use crate::updater::{self, UpdateStatus};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

pub enum Outcome {
    Back,
    Upgrade,
    Uninstall,
}

#[derive(Clone, Copy)]
enum Item {
    CheckUpdates,
    AutoCheck,
    AutoUpgrade,
    Uninstall,
    Back,
}

const ITEMS: [Item; 5] = [
    Item::CheckUpdates,
    Item::AutoCheck,
    Item::AutoUpgrade,
    Item::Uninstall,
    Item::Back,
];

pub fn show(
    terminal: &mut ratatui::DefaultTerminal,
    config: &mut Config,
) -> anyhow::Result<Outcome> {
    terminal.clear()?;
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "secret-stripper".to_string());
    let desktop = shortcut::detect_desktop();

    let mut selected = 0usize;
    // (text, is_warning) shown under the Current/Binary lines.
    let mut status: Option<(String, bool)> = None;
    let mut pending_check = false;

    loop {
        let on = config.lang.state_on();
        let off = config.lang.state_off();
        let rows = [
            MenuRow {
                icon: "\u{1F50D}",
                label: config.lang.lbl_check_updates().to_string(),
                icon_color: theme::icon_green(),
            },
            MenuRow {
                icon: "\u{23F0}",
                label: config
                    .lang
                    .lbl_auto_check(if config.check_for_updates { on } else { off }),
                icon_color: theme::icon_blue(),
            },
            MenuRow {
                icon: "\u{1F4E5}",
                label: config
                    .lang
                    .lbl_auto_upgrade(if config.auto_install { on } else { off }),
                icon_color: theme::icon_blue(),
            },
            MenuRow {
                icon: "\u{1F5D1}\u{FE0F}",
                label: config.lang.lbl_uninstall().to_string(),
                icon_color: theme::icon_magenta(),
            },
            MenuRow {
                icon: "\u{2190} ",
                label: config.lang.lbl_back().to_string(),
                icon_color: theme::icon_blue(),
            },
        ];
        let footer = match ITEMS[selected] {
            Item::CheckUpdates => config.lang.help_check_updates(),
            Item::AutoCheck => config.lang.help_auto_check(),
            Item::AutoUpgrade => config.lang.help_auto_upgrade(),
            Item::Uninstall => config.lang.help_uninstall(),
            Item::Back => config.lang.help_back(),
        };

        terminal.draw(|f| {
            let body = scaffold(f, config.lang.mi_title(), footer, config);
            let parts = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(5), Constraint::Min(1)])
                .split(body);
            let status_line = match &status {
                Some((msg, true)) => {
                    Line::from(Span::styled(msg.clone(), Style::new().fg(theme::warn())))
                }
                Some((msg, false)) => Line::from(Span::styled(
                    msg.clone(),
                    Style::new()
                        .fg(theme::success())
                        .add_modifier(Modifier::BOLD),
                )),
                None => Line::from(""),
            };
            let info = vec![
                Line::from(Span::styled(
                    config.lang.mi_current(&desktop, &config.hotkey),
                    Style::new().fg(theme::text()),
                )),
                Line::from(Span::styled(
                    config.lang.mi_path(&exe),
                    Style::new().fg(theme::text_dim()),
                )),
                Line::from(""),
                status_line,
                Line::from(""),
            ];
            f.render_widget(Paragraph::new(info), parts[0]);
            render_menu(
                f,
                parts[1],
                &rows,
                &[rows.len() - 1],
                &[rows.len() - 1],
                selected,
            );
        })?;

        // Draw "checking..." first, then perform the blocking network call.
        if pending_check {
            pending_check = false;
            match updater::check_status() {
                UpdateStatus::UpToDate => {
                    status = Some((config.lang.mi_up_to_date(updater::current_version()), false));
                }
                UpdateStatus::Failed => {
                    status = Some((config.lang.mi_check_failed().to_string(), true));
                }
                UpdateStatus::Available(latest) => {
                    status = Some((
                        config
                            .lang
                            .mi_update_available(updater::current_version(), &latest),
                        false,
                    ));
                    let yes = confirm(
                        terminal,
                        config,
                        config.lang.mi_title(),
                        &config.lang.mi_upgrade_now_q(&latest),
                        "",
                        config.lang.star_hint(),
                    )?;
                    if yes {
                        return Ok(Outcome::Upgrade);
                    }
                    terminal.clear()?;
                }
            }
            continue;
        }

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('c'))
            {
                return Ok(Outcome::Back);
            }
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => return Ok(Outcome::Back),
                KeyCode::Up => selected = selected.saturating_sub(1),
                KeyCode::Down => selected = (selected + 1) % ITEMS.len(),
                KeyCode::Enter => match ITEMS[selected] {
                    Item::CheckUpdates => {
                        status = Some((config.lang.mi_checking().to_string(), false));
                        pending_check = true;
                    }
                    Item::AutoCheck => {
                        config.check_for_updates = !config.check_for_updates;
                        let install = config.check_for_updates;
                        if !install {
                            // Auto-upgrade needs the check; turn it off too.
                            config.auto_install = false;
                        }
                        // Persist BEFORE spawning so the background thread's
                        // Config::load reads the fully-written file.
                        config.save()?;
                        // systemctl calls block ~1s; do them off the UI thread
                        // so the toggle stays instant. They are idempotent.
                        std::thread::spawn(move || {
                            let _ = if install {
                                updater::install_update_check_timer()
                            } else {
                                updater::uninstall_update_check_timer()
                            };
                        });
                    }
                    Item::AutoUpgrade => {
                        config.auto_install = !config.auto_install;
                        let need_timer = config.auto_install && !config.check_for_updates;
                        if need_timer {
                            config.check_for_updates = true;
                        }
                        config.save()?;
                        if need_timer {
                            std::thread::spawn(|| {
                                let _ = updater::install_update_check_timer();
                            });
                        }
                    }
                    Item::Uninstall => return Ok(Outcome::Uninstall),
                    Item::Back => return Ok(Outcome::Back),
                },
                _ => {}
            }
        }
    }
}
