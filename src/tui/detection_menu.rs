use crate::config::Config;
use crate::detector::custom;
use crate::tui::chrome::scaffold;
use crate::tui::theme;
use crate::tui::widgets::{render_menu, MenuRow};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

#[derive(Clone, Copy, PartialEq)]
enum Item {
    Presets,
    Categories,
    ManageAllowlist,
    AddCustom,
    ManageCustom,
    Back,
}

pub fn show(terminal: &mut ratatui::DefaultTerminal, config: &mut Config) -> anyhow::Result<()> {
    terminal.clear()?;
    let mut selected = 0usize;

    loop {
        let has_custom = !custom::load_specs().is_empty();
        let mut items: Vec<(Item, &'static str, String, String, ratatui::style::Color)> = vec![
            (
                Item::Presets,
                "\u{2699}\u{FE0F}",
                config.lang.dm_presets().to_string(),
                config.lang.help_dm_presets().to_string(),
                theme::icon_green(),
            ),
            (
                Item::Categories,
                "\u{1F4C2}",
                config.lang.dm_categories().to_string(),
                config.lang.help_dm_categories().to_string(),
                theme::icon_green(),
            ),
            (
                Item::ManageAllowlist,
                "\u{1F4DD}",
                config.lang.dm_manage_allowlist().to_string(),
                config.lang.help_dm_manage_allowlist().to_string(),
                theme::icon_green(),
            ),
        ];
        // Group break before the custom-pattern entries.
        let grp_add = items.len();
        items.push((
            Item::AddCustom,
            "\u{2795}",
            config.lang.dm_add_custom().to_string(),
            config.lang.help_dm_add_custom().to_string(),
            theme::icon_blue(),
        ));
        if has_custom {
            items.push((
                Item::ManageCustom,
                "\u{1F6E0}\u{FE0F}",
                config.lang.dm_manage_custom().to_string(),
                config.lang.help_dm_manage_custom().to_string(),
                theme::icon_blue(),
            ));
        }
        items.push((
            Item::Back,
            "\u{2190} ",
            config.lang.dm_back().to_string(),
            config.lang.help_dm_back().to_string(),
            theme::icon_blue(),
        ));
        selected = selected.min(items.len() - 1);

        let rows: Vec<MenuRow> = items
            .iter()
            .map(|(_, icon, label, _, color)| MenuRow {
                icon,
                label: label.clone(),
                icon_color: *color,
            })
            .collect();
        let footer = items[selected].3.clone();
        let group_starts = [grp_add, items.len() - 1];

        terminal.draw(|f| {
            let body = scaffold(f, config.lang.dm_title(), &footer, config);
            render_menu(f, body, &rows, &group_starts, &[items.len() - 1], selected);
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('c'))
            {
                return Ok(());
            }
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => return Ok(()),
                KeyCode::Up => selected = selected.saturating_sub(1),
                KeyCode::Down => selected = (selected + 1) % items.len(),
                KeyCode::Enter => {
                    match items[selected].0 {
                        Item::Presets => {
                            let _ = crate::tui::presets::show(terminal, config);
                        }
                        Item::Categories => {
                            let _ = crate::tui::categories::show(terminal, config);
                        }
                        Item::AddCustom => {
                            let _ = crate::tui::custom_patterns::manage(terminal, config, true);
                        }
                        Item::ManageCustom => {
                            let _ = crate::tui::custom_patterns::manage(terminal, config, false);
                        }
                        Item::ManageAllowlist => {
                            let _ = crate::tui::allowlist::show(terminal, config);
                        }
                        Item::Back => return Ok(()),
                    }
                    terminal.clear()?;
                    let _ = crate::tui::drain_pending_events();
                }
                _ => {}
            }
        }
    }
}
