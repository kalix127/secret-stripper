use crate::config::Config;
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
    List,
    Custom,
}

pub fn show(terminal: &mut ratatui::DefaultTerminal, config: &mut Config) -> anyhow::Result<bool> {
    terminal.clear()?;
    let mut changed = false;
    let mut mode = Mode::List;
    let custom_idx = PRESETS.len();
    let back_idx = custom_idx + 1;
    let total = back_idx + 1;
    let mut selected = PRESETS
        .iter()
        .position(|p| *p == config.redact_pattern)
        .unwrap_or(custom_idx);
    let mut input = TextInput::new("");
    let mut error: Option<String> = None;

    loop {
        match mode {
            Mode::List => {
                let footer: &str = if selected == back_idx {
                    config.lang.help_back()
                } else if selected == custom_idx {
                    config.lang.help_rs_custom()
                } else {
                    config.lang.help_rs_preset()
                };
                terminal.draw(|f| {
                    let body = scaffold(f, config.lang.rs_title(), footer, config);
                    let mut lines: Vec<Line> = Vec::with_capacity(PRESETS.len() + 1);
                    let row = |idx: usize, value: &str, is_current: bool| {
                        let is_sel = idx == selected;
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
                            } else if selected == custom_idx {
                                input = TextInput::new("");
                                error = None;
                                mode = Mode::Custom;
                            } else {
                                config.redact_pattern = PRESETS[selected].to_string();
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
                        KeyCode::Esc => mode = Mode::List,
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
