use crate::config::Config;
use crate::tui::chrome::scaffold;
use crate::tui::theme;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};

pub fn rounded_block<'a>(title: &str, color: Color) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(color))
        .title(format!(" {} ", title))
}

pub struct MenuRow {
    pub icon: &'static str,
    pub label: String,
    pub icon_color: Color,
}

/// Render a grouped menu list. `group_starts` holds row indices (other than 0)
/// that begin a new visual group; a blank line is drawn before each.
/// `arrowless_rows` holds indices that never get the selection ▶ marker (label
/// still color-highlights normally when selected).
pub fn render_menu(
    f: &mut Frame,
    area: Rect,
    rows: &[MenuRow],
    group_starts: &[usize],
    arrowless_rows: &[usize],
    selected: usize,
) {
    let mut lines: Vec<Line> = Vec::with_capacity(rows.len() + group_starts.len());
    for (i, row) in rows.iter().enumerate() {
        if i != 0 && group_starts.contains(&i) {
            lines.push(Line::from(""));
        }
        let is_sel = i == selected;
        let show_arrow = is_sel && !arrowless_rows.contains(&i);
        let arrow = if show_arrow { " \u{25B6} " } else { "   " };
        let label_style = if is_sel {
            Style::new()
                .fg(theme::accent())
                .add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(theme::text())
        };
        lines.push(Line::from(vec![
            Span::styled(arrow, Style::new().fg(theme::select_arrow())),
            Span::styled(format!("{}  ", row.icon), Style::new().fg(row.icon_color)),
            Span::styled(row.label.clone(), label_style),
        ]));
    }
    f.render_widget(Paragraph::new(lines), area);
}

/// Scroll window with vim-style scroll-off: keeps `scrolloff` rows of context
/// below the cursor when possible, so the user can see what is coming without
/// having to land on the bottom-most visible row first. Clamped so the window
/// never overruns the end of the list.
pub fn scrolled_window(
    total: usize,
    selected: usize,
    rows: usize,
    scrolloff: usize,
) -> (usize, usize) {
    if total == 0 || rows == 0 {
        return (0, 0);
    }
    let rows = rows.min(total);
    let scrolloff = scrolloff.min(rows.saturating_sub(1));
    let start = selected.saturating_sub(scrolloff).min(total - rows);
    (start, start + rows)
}

/// Scroll window: returns the `[start, end)` slice of `total` items that keeps
/// `selected` visible within `rows` visible lines.
pub fn visible_window(total: usize, selected: usize, rows: usize) -> (usize, usize) {
    if total == 0 || rows == 0 {
        return (0, 0);
    }
    let rows = rows.min(total);
    let start = if selected < rows {
        0
    } else if selected >= total {
        total - rows
    } else {
        (selected + 1).saturating_sub(rows).min(total - rows)
    };
    (start, start + rows)
}

/// Generic Yes/No confirmation screen drawn through the shared chrome.
/// `detail` is an optional second line (e.g. a URL). Yes is the default;
/// Esc / q return false.
pub fn confirm(
    terminal: &mut ratatui::DefaultTerminal,
    config: &Config,
    section_title: &str,
    question: &str,
    detail: &str,
    footer_help: &str,
) -> anyhow::Result<bool> {
    terminal.clear()?;
    let mut yes = true;
    let result = loop {
        terminal.draw(|f| {
            let body = scaffold(f, section_title, footer_help, config);
            let mut lines = vec![
                Line::from(Span::styled(
                    question.to_string(),
                    Style::new().fg(theme::text()),
                )),
                Line::from(""),
            ];
            if !detail.is_empty() {
                lines.push(Line::from(Span::styled(
                    detail.to_string(),
                    Style::new().fg(theme::accent()),
                )));
                lines.push(Line::from(""));
            }
            for (i, label) in [config.lang.confirm_yes(), config.lang.confirm_no()]
                .iter()
                .enumerate()
            {
                let is_sel = (i == 0) == yes;
                let arrow = if is_sel { " \u{25B6} " } else { "   " };
                let style = if is_sel {
                    Style::new()
                        .fg(theme::accent())
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::new().fg(theme::text())
                };
                lines.push(Line::from(vec![
                    Span::styled(arrow, Style::new().fg(theme::select_arrow())),
                    Span::styled((*label).to_string(), style),
                ]));
            }
            f.render_widget(Paragraph::new(lines), body);
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => break false,
                KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right => {
                    yes = !yes;
                }
                KeyCode::Enter => break yes,
                _ => {}
            }
        }
    };
    Ok(result)
}

/// Single-line text editor. Cursor is a byte index kept on a char boundary.
pub struct TextInput {
    pub buffer: String,
    pub cursor: usize,
}

impl TextInput {
    pub fn new(initial: impl Into<String>) -> Self {
        let buffer = initial.into();
        let cursor = buffer.len();
        Self { buffer, cursor }
    }

    /// Returns true if the key was consumed (so the caller does not treat it
    /// as navigation). Tab/Up/Down/Enter/Esc are never consumed.
    pub fn handle_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Char(c) => {
                self.buffer.insert(self.cursor, c);
                self.cursor += c.len_utf8();
                true
            }
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    let prev = self.buffer[..self.cursor]
                        .char_indices()
                        .last()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    self.buffer.replace_range(prev..self.cursor, "");
                    self.cursor = prev;
                }
                true
            }
            KeyCode::Left => {
                if self.cursor > 0 {
                    self.cursor = self.buffer[..self.cursor]
                        .char_indices()
                        .last()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                }
                true
            }
            KeyCode::Right => {
                if self.cursor < self.buffer.len() {
                    let step = self.buffer[self.cursor..]
                        .chars()
                        .next()
                        .map(|c| c.len_utf8())
                        .unwrap_or(0);
                    self.cursor += step;
                }
                true
            }
            _ => false,
        }
    }

    pub fn render(&self, f: &mut Frame, area: Rect, label: &str, focused: bool, accent: Color) {
        let inner_w = area.width.saturating_sub(2) as usize;
        let chars: Vec<char> = self.buffer.chars().collect();
        let caret_col = self.buffer[..self.cursor].chars().count();
        let start = caret_col.saturating_sub(inner_w.saturating_sub(1));
        let visible: String = chars.iter().skip(start).take(inner_w).collect();
        let mut spans = vec![Span::raw(visible)];
        if focused {
            spans.push(Span::styled("_", Style::new().fg(accent)));
        }
        let border = if focused { accent } else { theme::border() };
        f.render_widget(
            Paragraph::new(Line::from(spans)).block(rounded_block(label, border)),
            area,
        );
    }
}
