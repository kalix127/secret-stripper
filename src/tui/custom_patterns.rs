use crate::config::Config;
use crate::detector::custom::{self, validate_regex, CustomPatternSpec, CustomPatternsFile};
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

const SEVERITIES: [&str; 4] = ["critical", "high", "medium", "low"];

enum Mode {
    List,
    Form,
}

struct Form {
    editing: Option<usize>,
    name: TextInput,
    category: TextInput,
    sev: usize,
    regex: TextInput,
    sample: TextInput,
    focus: usize,
    error: Option<String>,
}

impl Form {
    fn new() -> Self {
        Self {
            editing: None,
            name: TextInput::new(""),
            category: TextInput::new(""),
            sev: 2,
            regex: TextInput::new(""),
            sample: TextInput::new(""),
            focus: 0,
            error: None,
        }
    }

    fn from_spec(idx: usize, s: &CustomPatternSpec) -> Self {
        let sev = SEVERITIES
            .iter()
            .position(|x| *x == s.severity.to_ascii_lowercase())
            .unwrap_or(2);
        Self {
            editing: Some(idx),
            name: TextInput::new(s.name.clone()),
            category: TextInput::new(s.category.clone()),
            sev,
            regex: TextInput::new(s.regex.clone()),
            sample: TextInput::new(""),
            focus: 0,
            error: None,
        }
    }
}

pub fn manage(
    terminal: &mut ratatui::DefaultTerminal,
    config: &mut Config,
    start_in_form: bool,
) -> anyhow::Result<bool> {
    terminal.clear()?;
    let mut specs = custom::load_specs();
    let mut changed = false;
    let mut selected = 0usize;
    let mut mode = if start_in_form {
        Mode::Form
    } else {
        Mode::List
    };
    let mut form = Form::new();

    loop {
        match mode {
            Mode::List => {
                if !specs.is_empty() {
                    selected = selected.min(specs.len() - 1);
                }
                terminal.draw(|f| {
                    let body = scaffold(
                        f,
                        config.lang.cp_title_list(),
                        config.lang.cp_list_hint(),
                        config,
                    );
                    if specs.is_empty() {
                        f.render_widget(
                            Paragraph::new(Span::styled(
                                config.lang.cp_empty(),
                                Style::new().fg(theme::text_dim()),
                            )),
                            body,
                        );
                        return;
                    }
                    let rows = body.height as usize;
                    let (off, end) = visible_window(specs.len(), selected, rows);
                    let mut lines: Vec<Line> = Vec::with_capacity(end - off);
                    for (i, s) in specs[off..end].iter().enumerate() {
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
                            Span::styled(format!("{}  ", s.name), style),
                            Span::styled(
                                format!("[{}]  ", s.category),
                                Style::new().fg(theme::icon_blue()),
                            ),
                            Span::styled(
                                s.severity.to_uppercase(),
                                Style::new().fg(theme::text_dim()),
                            ),
                        ]));
                    }
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
                        KeyCode::Down if !specs.is_empty() => {
                            selected = (selected + 1) % specs.len();
                        }
                        KeyCode::Char('a') => {
                            form = Form::new();
                            mode = Mode::Form;
                        }
                        KeyCode::Enter => {
                            if let Some(s) = specs.get(selected) {
                                form = Form::from_spec(selected, s);
                                mode = Mode::Form;
                            }
                        }
                        KeyCode::Char('d') | KeyCode::Delete => {
                            if let Some(s) = specs.get(selected).cloned() {
                                let yes = confirm(
                                    terminal,
                                    config,
                                    config.lang.cp_title_list(),
                                    &config.lang.cp_confirm_delete(&s.name),
                                    "",
                                    config.lang.star_hint(),
                                )?;
                                if yes {
                                    specs.remove(selected);
                                    custom::save(&CustomPatternsFile {
                                        patterns: specs.clone(),
                                    })?;
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
                let title = if form.editing.is_some() {
                    config.lang.cp_title_edit()
                } else {
                    config.lang.cp_title_add()
                };
                let preview_line: Line = if form.regex.buffer.is_empty() {
                    // Empty regex is not an "error" to surface yet - stay
                    // neutral until the user actually types something.
                    Line::from(Span::styled(
                        config.lang.cp_preview_na(),
                        Style::new().fg(theme::text_dim()),
                    ))
                } else {
                    match validate_regex(&form.regex.buffer) {
                        Err(e) => Line::from(Span::styled(
                            config.lang.cp_regex_invalid(&e),
                            Style::new().fg(theme::warn()),
                        )),
                        Ok(re) => {
                            if form.sample.buffer.is_empty() {
                                Line::from(Span::styled(
                                    config.lang.cp_preview_na(),
                                    Style::new().fg(theme::text_dim()),
                                ))
                            } else if let Some(m) = re.find(&form.sample.buffer) {
                                Line::from(Span::styled(
                                    config.lang.cp_preview_match(m.as_str()),
                                    Style::new()
                                        .fg(theme::success())
                                        .add_modifier(Modifier::BOLD),
                                ))
                            } else {
                                Line::from(Span::styled(
                                    config.lang.cp_preview_nomatch(),
                                    Style::new().fg(theme::text_dim()),
                                ))
                            }
                        }
                    }
                };

                terminal.draw(|f| {
                    let body = scaffold(f, title, config.lang.cp_form_hint(), config);
                    let parts = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([
                            Constraint::Length(3),
                            Constraint::Length(3),
                            Constraint::Length(1),
                            Constraint::Length(3),
                            Constraint::Length(3),
                            Constraint::Length(1),
                            Constraint::Length(1),
                        ])
                        .split(body);
                    form.name.render(
                        f,
                        parts[0],
                        config.lang.cp_field_name(),
                        form.focus == 0,
                        theme::accent(),
                    );
                    form.category.render(
                        f,
                        parts[1],
                        config.lang.cp_field_category(),
                        form.focus == 1,
                        theme::accent(),
                    );
                    let sev_style = if form.focus == 2 {
                        Style::new()
                            .fg(theme::accent())
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::new().fg(theme::text())
                    };
                    f.render_widget(
                        Paragraph::new(Line::from(vec![
                            Span::styled(
                                format!("{}: ", config.lang.cp_field_severity()),
                                Style::new().fg(theme::text_dim()),
                            ),
                            Span::styled(SEVERITIES[form.sev].to_uppercase(), sev_style),
                            Span::styled("   (left/right)  ", Style::new().fg(theme::text_dim())),
                            Span::styled(
                                config.lang.cp_severity_help(),
                                Style::new().fg(theme::text_dim()),
                            ),
                        ])),
                        parts[2],
                    );
                    form.regex.render(
                        f,
                        parts[3],
                        config.lang.cp_field_regex(),
                        form.focus == 3,
                        theme::accent(),
                    );
                    form.sample.render(
                        f,
                        parts[4],
                        config.lang.cp_field_sample(),
                        form.focus == 4,
                        theme::accent(),
                    );
                    f.render_widget(Paragraph::new(preview_line.clone()), parts[5]);
                    if let Some(err) = &form.error {
                        f.render_widget(
                            Paragraph::new(Span::styled(
                                err.clone(),
                                Style::new().fg(theme::warn()),
                            )),
                            parts[6],
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
                    // Any interaction clears a stale validation error; the
                    // Enter handler re-sets it if validation still fails.
                    form.error = None;
                    match key.code {
                        KeyCode::Esc => {
                            if start_in_form {
                                break;
                            }
                            mode = Mode::List;
                        }
                        KeyCode::Tab | KeyCode::Down => {
                            form.focus = (form.focus + 1) % 5;
                        }
                        KeyCode::Up => {
                            form.focus = (form.focus + 4) % 5;
                        }
                        KeyCode::Enter => {
                            if form.name.buffer.trim().is_empty() {
                                form.error = Some(config.lang.cp_err_name_empty().to_string());
                            } else if let Err(e) = validate_regex(&form.regex.buffer) {
                                form.error = Some(config.lang.cp_regex_invalid(&e));
                            } else {
                                let spec = CustomPatternSpec {
                                    name: form.name.buffer.trim().to_string(),
                                    category: form.category.buffer.trim().to_string(),
                                    severity: SEVERITIES[form.sev].to_string(),
                                    regex: form.regex.buffer.clone(),
                                };
                                match form.editing {
                                    Some(i) if i < specs.len() => specs[i] = spec,
                                    _ => specs.push(spec),
                                }
                                custom::save(&CustomPatternsFile {
                                    patterns: specs.clone(),
                                })?;
                                changed = true;
                                specs = custom::load_specs();
                                if start_in_form {
                                    break;
                                }
                                mode = Mode::List;
                            }
                        }
                        code => {
                            if form.focus == 2 {
                                match code {
                                    KeyCode::Left => {
                                        form.sev = (form.sev + 3) % 4;
                                    }
                                    KeyCode::Right | KeyCode::Char(' ') => {
                                        form.sev = (form.sev + 1) % 4;
                                    }
                                    _ => {}
                                }
                            } else {
                                let input = match form.focus {
                                    0 => &mut form.name,
                                    1 => &mut form.category,
                                    3 => &mut form.regex,
                                    _ => &mut form.sample,
                                };
                                input.handle_key(code);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(changed)
}
