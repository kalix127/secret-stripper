use crate::config::Config;
use crate::detector::custom::validate_regex;
use crate::tui::chrome::scaffold;
use crate::tui::theme;
use crate::tui::widgets::{confirm, visible_window, TextInput};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

enum Mode {
    List,
    Form,
}

pub fn show(terminal: &mut ratatui::DefaultTerminal, config: &mut Config) -> anyhow::Result<bool> {
    terminal.clear()?;
    let mut changed = false;
    let mut selected = 0usize;
    let mut mode = Mode::List;
    let mut input = TextInput::new("");
    let mut editing: Option<usize> = None;

    loop {
        match mode {
            Mode::List => {
                let count = config.allowlist_regex.len();
                let back_idx = count;
                let total = count + 1;
                selected = selected.min(back_idx);
                let on_back = selected == back_idx;
                let footer: &str = if on_back {
                    config.lang.help_back()
                } else {
                    config.lang.al_list_hint()
                };
                terminal.draw(|f| {
                    let body = scaffold(f, config.lang.al_title(), footer, config);
                    let mut lines: Vec<Line> = Vec::new();
                    if count == 0 {
                        lines.push(Line::from(Span::styled(
                            config.lang.al_empty(),
                            Style::new().fg(theme::text_dim()),
                        )));
                    } else {
                        let rows = body.height.saturating_sub(2) as usize;
                        let (off, end) = visible_window(count, selected.min(count - 1), rows);
                        for (i, r) in config.allowlist_regex[off..end].iter().enumerate() {
                            let idx = off + i;
                            let is_sel = idx == selected;
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
                                Span::styled(r.clone(), style),
                            ]));
                        }
                    }
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![
                        Span::styled("   ", Style::new().fg(theme::select_arrow())),
                        Span::styled(
                            format!("{}  ", "\u{2190} "),
                            Style::new().fg(theme::icon_blue()),
                        ),
                        Span::styled(
                            config.lang.lbl_back().to_string(),
                            crate::tui::chrome::list_label_style(on_back),
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
                        KeyCode::Char('a') => {
                            input = TextInput::new("");
                            editing = None;
                            mode = Mode::Form;
                        }
                        KeyCode::Enter => {
                            if on_back {
                                break;
                            }
                            if let Some(r) = config.allowlist_regex.get(selected) {
                                input = TextInput::new(r.clone());
                                editing = Some(selected);
                                mode = Mode::Form;
                            }
                        }
                        KeyCode::Char('d') | KeyCode::Delete => {
                            if on_back {
                                continue;
                            }
                            if let Some(r) = config.allowlist_regex.get(selected).cloned() {
                                let yes = confirm(
                                    terminal,
                                    config,
                                    config.lang.al_title(),
                                    &config.lang.al_confirm_delete(&r),
                                    "",
                                    config.lang.star_hint(),
                                )?;
                                if yes {
                                    config.allowlist_regex.remove(selected);
                                    config.save()?;
                                    changed = true;
                                }
                                terminal.clear()?;
                                let _ = crate::tui::drain_pending_events();
                            }
                        }
                        _ => {}
                    }
                }
            }

            Mode::Form => {
                let check = validate_regex(&input.buffer);
                let status: Line = match &check {
                    Ok(_) => Line::from(Span::styled(
                        config.lang.al_valid(),
                        Style::new()
                            .fg(theme::success())
                            .add_modifier(Modifier::BOLD),
                    )),
                    Err(e) => Line::from(Span::styled(
                        config.lang.cp_regex_invalid(e),
                        Style::new().fg(theme::warn()),
                    )),
                };
                terminal.draw(|f| {
                    let body = scaffold(
                        f,
                        config.lang.al_title(),
                        config.lang.al_form_hint(),
                        config,
                    );
                    let parts = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([Constraint::Length(3), Constraint::Length(1)])
                        .split(body);
                    input.render(
                        f,
                        parts[0],
                        config.lang.al_field_regex(),
                        true,
                        theme::accent(),
                    );
                    f.render_widget(Paragraph::new(status.clone()), parts[1]);
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
                            if validate_regex(&input.buffer).is_ok() {
                                match editing {
                                    Some(i) if i < config.allowlist_regex.len() => {
                                        config.allowlist_regex[i] = input.buffer.clone();
                                    }
                                    _ => config.allowlist_regex.push(input.buffer.clone()),
                                }
                                config.save()?;
                                changed = true;
                                mode = Mode::List;
                            }
                        }
                        code => {
                            input.handle_key(code);
                        }
                    }
                }
            }
        }
    }

    Ok(changed)
}
