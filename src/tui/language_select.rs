use crate::config::Config;
use crate::lang::Lang;
use crate::tui::chrome::scaffold;
use crate::tui::theme;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

/// Returns true if the language was changed and saved, false on cancel.
pub fn select_language(
    terminal: &mut ratatui::DefaultTerminal,
    config: &mut Config,
) -> anyhow::Result<bool> {
    terminal.clear()?;

    let langs = Lang::all();
    let back_idx = langs.len();
    let total = langs.len() + 1;
    let mut selected = langs.iter().position(|l| *l == config.lang).unwrap_or(0);

    let saved = loop {
        let footer: &str = if selected == back_idx {
            config.lang.help_back()
        } else {
            config.lang.help_lang_pick()
        };
        terminal.draw(|f| {
            let body = scaffold(f, config.lang.lang_title(), footer, config);
            let mut lines: Vec<Line> = Vec::with_capacity(total + 1);
            for (i, l) in langs.iter().enumerate() {
                let is_sel = i == selected;
                let arrow = if is_sel { " \u{25B6} " } else { "   " };
                lines.push(Line::from(vec![
                    Span::styled(arrow, Style::new().fg(theme::select_arrow())),
                    Span::styled("\u{2022} ", Style::new().fg(theme::text_dim())),
                    Span::styled(
                        l.endonym().to_string(),
                        crate::tui::chrome::list_label_style(is_sel),
                    ),
                ]));
            }
            lines.push(Line::from(""));
            let is_back_sel = selected == back_idx;
            let back_arrow = if is_back_sel { " \u{25B6} " } else { "   " };
            lines.push(Line::from(vec![
                Span::styled(back_arrow, Style::new().fg(theme::select_arrow())),
                Span::styled("\u{2190} ", Style::new().fg(theme::icon_blue())),
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
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => break false,
                KeyCode::Up => {
                    selected = selected.saturating_sub(1);
                }
                KeyCode::Down => {
                    selected = (selected + 1) % total;
                }
                KeyCode::Enter => {
                    if selected == back_idx {
                        break false;
                    }
                    config.lang = langs[selected];
                    config.save()?;
                    break true;
                }
                _ => {}
            }
        }
    };

    Ok(saved)
}
