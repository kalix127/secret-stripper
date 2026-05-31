use crate::config::{Config, RedactStyle};
use crate::tui::chrome::scaffold;
use crate::tui::theme;
use crate::tui::widgets::TextInput;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

const PRESETS: [&str; 8] = [
    "[REDACTED]",
    "[REMOVED]",
    "[SECRET]",
    "[HIDDEN]",
    "<REDACTED>",
    "[***]",
    "***",
    "...",
];

enum Mode {
    Style,
    Marker,
    Custom,
}

pub fn show(terminal: &mut ratatui::DefaultTerminal, config: &mut Config) -> anyhow::Result<bool> {
    terminal.clear()?;
    let mut changed = false;
    let mut mode = Mode::Style;
    let mut style_selected = match config.redact_style {
        RedactStyle::Marker => 0usize,
        RedactStyle::Drop => 1usize,
        RedactStyle::Typed => 2usize,
        RedactStyle::Placeholder => 3usize,
    };
    let style_total = 5usize;
    let style_back = 4usize;

    let custom_idx = PRESETS.len();
    let back_idx = custom_idx + 1;
    let marker_total = back_idx + 1;
    let mut marker_selected = PRESETS
        .iter()
        .position(|p| *p == config.redact_pattern)
        .unwrap_or(custom_idx);
    let mut input = TextInput::new("");
    let mut error: Option<String> = None;

    loop {
        match mode {
            Mode::Style => {
                let footer: &str = match style_selected {
                    0 => config.lang.help_rs_style_marker(),
                    1 => config.lang.help_rs_style_drop(),
                    2 => config.lang.help_rs_style_typed(),
                    3 => config.lang.help_rs_style_placeholder(),
                    _ => config.lang.help_back(),
                };
                terminal.draw(|f| {
                    let body = scaffold(f, config.lang.rs_title(), footer, config);
                    let style_row = |idx: usize, label: &str, current: bool| -> Line<'static> {
                        let is_sel = idx == style_selected;
                        let arrow = if is_sel { " \u{25B6} " } else { "   " };
                        let style = crate::tui::chrome::list_label_style(is_sel);
                        let mut spans = vec![
                            Span::styled(arrow, Style::new().fg(theme::select_arrow())),
                            Span::styled("\u{2022} ", Style::new().fg(theme::text_dim())),
                            Span::styled(label.to_string(), style),
                        ];
                        if current {
                            spans.push(Span::styled(
                                format!("   ({})", config.lang.rs_current()),
                                Style::new().fg(theme::success()),
                            ));
                        }
                        Line::from(spans)
                    };
                    let cur = config.redact_style;
                    let mut lines: Vec<Line> = Vec::with_capacity(6);
                    lines.push(style_row(
                        0,
                        config.lang.rs_style_marker(),
                        cur == RedactStyle::Marker,
                    ));
                    lines.push(style_row(
                        1,
                        config.lang.rs_style_drop(),
                        cur == RedactStyle::Drop,
                    ));
                    lines.push(style_row(
                        2,
                        config.lang.rs_style_typed(),
                        cur == RedactStyle::Typed,
                    ));
                    lines.push(style_row(
                        3,
                        config.lang.rs_style_placeholder(),
                        cur == RedactStyle::Placeholder,
                    ));
                    lines.push(Line::from(""));
                    let is_back_sel = style_selected == style_back;
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
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(key.code, KeyCode::Char('c'))
                    {
                        break;
                    }
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('q') => break,
                        KeyCode::Up => style_selected = style_selected.saturating_sub(1),
                        KeyCode::Down => style_selected = (style_selected + 1) % style_total,
                        KeyCode::Enter => match style_selected {
                            0 => {
                                if config.redact_style != RedactStyle::Marker {
                                    config.redact_style = RedactStyle::Marker;
                                    config.save()?;
                                    changed = true;
                                }
                                marker_selected = PRESETS
                                    .iter()
                                    .position(|p| *p == config.redact_pattern)
                                    .unwrap_or(custom_idx);
                                mode = Mode::Marker;
                            }
                            1 => {
                                if config.redact_style != RedactStyle::Drop {
                                    config.redact_style = RedactStyle::Drop;
                                    config.save()?;
                                    changed = true;
                                }
                                break;
                            }
                            2 => {
                                if config.redact_style != RedactStyle::Typed {
                                    config.redact_style = RedactStyle::Typed;
                                    config.save()?;
                                    changed = true;
                                }
                                break;
                            }
                            3 => {
                                if config.redact_style != RedactStyle::Placeholder {
                                    config.redact_style = RedactStyle::Placeholder;
                                    config.save()?;
                                    changed = true;
                                }
                                break;
                            }
                            _ => break,
                        },
                        _ => {}
                    }
                }
            }

            Mode::Marker => {
                let footer: &str = if marker_selected == back_idx {
                    config.lang.help_back()
                } else if marker_selected == custom_idx {
                    config.lang.help_rs_custom()
                } else {
                    config.lang.help_rs_preset()
                };
                terminal.draw(|f| {
                    let body = scaffold(f, config.lang.rs_title(), footer, config);
                    let mut lines: Vec<Line> = Vec::with_capacity(PRESETS.len() + 1);
                    let row = |idx: usize, value: &str, is_current: bool| {
                        let is_sel = idx == marker_selected;
                        let arrow = if is_sel { " \u{25B6} " } else { "   " };
                        let style = crate::tui::chrome::list_label_style(is_sel);
                        let mut spans = vec![
                            Span::styled(arrow, Style::new().fg(theme::select_arrow())),
                            Span::styled("\u{2022} ", Style::new().fg(theme::text_dim())),
                            Span::styled(value.to_string(), style),
                        ];
                        if is_current {
                            spans.push(Span::styled(
                                format!("   ({})", config.lang.rs_current()),
                                Style::new().fg(theme::success()),
                            ));
                        }
                        Line::from(spans)
                    };
                    for (i, p) in PRESETS.iter().enumerate() {
                        lines.push(row(i, p, *p == config.redact_pattern));
                    }
                    let custom_is_current = !PRESETS.iter().any(|p| *p == config.redact_pattern);
                    let custom_label = if custom_is_current {
                        format!("\"{}\"", config.redact_pattern)
                    } else {
                        config.lang.rs_custom().to_string()
                    };
                    lines.push(Line::from(""));
                    lines.push(row(custom_idx, &custom_label, custom_is_current));
                    lines.push(Line::from(""));
                    let is_back_sel = marker_selected == back_idx;
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
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(key.code, KeyCode::Char('c'))
                    {
                        break;
                    }
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('q') => mode = Mode::Style,
                        KeyCode::Up => marker_selected = marker_selected.saturating_sub(1),
                        KeyCode::Down => marker_selected = (marker_selected + 1) % marker_total,
                        KeyCode::Enter => {
                            if marker_selected == back_idx {
                                mode = Mode::Style;
                            } else if marker_selected == custom_idx {
                                input = TextInput::new("");
                                error = None;
                                mode = Mode::Custom;
                            } else {
                                config.redact_pattern = PRESETS[marker_selected].to_string();
                                config.save()?;
                                changed = true;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }

            Mode::Custom => {
                terminal.draw(|f| {
                    let body = scaffold(
                        f,
                        config.lang.rs_title(),
                        config.lang.rs_custom_hint(),
                        config,
                    );
                    let parts = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([
                            Constraint::Length(3),
                            Constraint::Length(1),
                            Constraint::Length(1),
                            Constraint::Min(0),
                        ])
                        .split(body);
                    input.render(
                        f,
                        parts[0],
                        config.lang.rs_custom_field(),
                        true,
                        theme::accent(),
                    );
                    if let Some(err) = &error {
                        f.render_widget(
                            Paragraph::new(Span::styled(
                                err.clone(),
                                Style::new().fg(theme::warn()),
                            )),
                            parts[2],
                        );
                    }
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
                        KeyCode::Esc => mode = Mode::Marker,
                        KeyCode::Enter => {
                            if input.buffer.trim().is_empty() {
                                error = Some(config.lang.rs_empty_err().to_string());
                            } else {
                                config.redact_pattern = input.buffer.clone();
                                config.save()?;
                                changed = true;
                                break;
                            }
                        }
                        code => {
                            error = None;
                            input.handle_key(code);
                        }
                    }
                }
            }
        }
    }

    Ok(changed)
}
