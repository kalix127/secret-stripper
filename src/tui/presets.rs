use crate::config::Config;
use crate::detector::presets::{self, Preset};
use crate::tui::chrome::scaffold;
use crate::tui::theme;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

/// Returns true if a preset was applied and saved, false on cancel.
pub fn show(terminal: &mut ratatui::DefaultTerminal, config: &mut Config) -> anyhow::Result<bool> {
    terminal.clear()?;

    let presets = Preset::all();
    let back_idx = presets.len();
    let total = presets.len() + 1;
    let mut selected = presets::detect(config)
        .and_then(|cur| presets.iter().position(|p| *p == cur))
        .unwrap_or(0);
    let mut changed = false;

    loop {
        let active = presets::detect(config);
        let footer: &str = if selected == back_idx {
            config.lang.help_back()
        } else {
            config.lang.help_preset_pick()
        };
        terminal.draw(|f| {
            let body = scaffold(f, config.lang.preset_title(), footer, config);
            let mut lines: Vec<Line> = Vec::with_capacity(presets.len() + 4);
            for (i, p) in presets.iter().enumerate() {
                let is_sel = i == selected;
                let (name, desc) = config.lang.preset_label(p);
                let arrow = if is_sel { " \u{25B6} " } else { "   " };
                let name_style = crate::tui::chrome::list_label_style(is_sel);
                let mut spans = vec![
                    Span::styled(arrow, Style::new().fg(theme::select_arrow())),
                    Span::styled(format!("{name:<10}"), name_style),
                    Span::styled(format!("  {desc}"), Style::new().fg(theme::text_dim())),
                ];
                if active == Some(*p) {
                    spans.push(Span::styled(
                        format!("   ({})", config.lang.preset_current()),
                        Style::new().fg(theme::success()),
                    ));
                }
                lines.push(Line::from(spans));
            }
            lines.push(Line::from(""));
            let mut custom_spans = vec![Span::styled(
                format!("   {}", config.lang.preset_custom()),
                Style::new().fg(theme::text_dim()),
            )];
            if active.is_none() {
                custom_spans.push(Span::styled(
                    format!("   ({})", config.lang.preset_current()),
                    Style::new().fg(theme::success()),
                ));
            }
            lines.push(Line::from(custom_spans));
            lines.push(Line::from(""));
            let is_back_sel = selected == back_idx;
            lines.push(Line::from(vec![
                Span::styled("   ", Style::new().fg(theme::select_arrow())),
                Span::styled(
                    format!("{}  ", "\u{2190} "),
                    Style::new().fg(theme::icon_blue()),
                ),
                Span::styled(
                    config.lang.lbl_back().to_string(),
                    crate::tui::chrome::list_label_style(is_back_sel),
                ),
            ]));
            f.render_widget(Paragraph::new(lines), body);
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('c'))
            {
                break;
            }
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => break,
                KeyCode::Up => selected = selected.saturating_sub(1),
                KeyCode::Down => selected = (selected + 1) % total,
                KeyCode::Enter => {
                    if selected == back_idx {
                        break;
                    }
                    presets[selected].apply(config);
                    config.save()?;
                    changed = true;
                }
                _ => {}
            }
        }
    }

    Ok(changed)
}
