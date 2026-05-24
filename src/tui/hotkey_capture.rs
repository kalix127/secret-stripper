use crate::config::Config;
use crate::hotkey;
use crate::shortcut;
use crate::tui::chrome::scaffold;
use crate::tui::theme::{success, text, text_dim, warn};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

pub fn capture_hotkey(
    terminal: &mut ratatui::DefaultTerminal,
    config: &mut Config,
) -> anyhow::Result<bool> {
    terminal.clear()?;

    let mut captured: Option<String> = None;
    let mut error: Option<String> = None;

    let saved = loop {
        let chord_preview = captured
            .clone()
            .unwrap_or_else(|| config.lang.hk_placeholder().to_string());
        let preview_style = if captured.is_some() {
            Style::new().fg(success()).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(text_dim())
        };

        let mut body_lines: Vec<Line> = vec![
            Line::from(Span::styled(
                config.lang.hk_instr1(),
                Style::new().fg(text()),
            )),
            Line::from(Span::styled(
                config.lang.hk_instr2(),
                Style::new().fg(text_dim()),
            )),
            Line::from(""),
            Line::from(Span::styled(
                config.lang.hk_current(&config.hotkey),
                Style::new().fg(text_dim()),
            )),
            Line::from(Span::styled(
                config.lang.hk_new(&chord_preview),
                preview_style,
            )),
        ];
        if let Some(err) = &error {
            body_lines.push(Line::from(""));
            body_lines.push(Line::from(Span::styled(
                err.clone(),
                Style::new().fg(warn()),
            )));
        }

        terminal.draw(|f| {
            let body = scaffold(f, config.lang.hk_title(), config.lang.hk_hint(), config);
            f.render_widget(Paragraph::new(body_lines.clone()), body);
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Esc => break false,
                KeyCode::Enter => {
                    match &captured {
                        Some(chord) => {
                            match hotkey::parse_chord(chord) {
                                Ok(_) => {
                                    // Tear down the old DE binding before persisting the new
                                    // chord so the OS shortcut points at the right key after.
                                    let _ = shortcut::unregister();
                                    config.hotkey = chord.clone();
                                    config.save()?;
                                    if let Err(e) = shortcut::register(&config.hotkey) {
                                        error = Some(config.lang.hk_err_rebind(&e.to_string()));
                                    } else {
                                        break true;
                                    }
                                }
                                Err(e) => {
                                    error = Some(config.lang.hk_err_invalid(&e.to_string()));
                                }
                            }
                        }
                        None => {
                            error = Some(config.lang.hk_err_press_first().to_string());
                        }
                    }
                }
                KeyCode::Backspace => {
                    captured = None;
                    error = None;
                }
                code => {
                    if let Some(chord) = build_chord(key.modifiers, code) {
                        match hotkey::parse_chord(&chord) {
                            Ok(_) => {
                                captured = Some(chord);
                                error = None;
                            }
                            Err(e) => {
                                captured = None;
                                error = Some(config.lang.hk_err_unsupported(&e.to_string()));
                            }
                        }
                    }
                }
            }
        }
    };

    Ok(saved)
}

fn build_chord(mods: KeyModifiers, code: KeyCode) -> Option<String> {
    let key_part = match code {
        KeyCode::Char(c) if c.is_ascii_alphanumeric() => c.to_ascii_uppercase().to_string(),
        KeyCode::F(n) if (1..=12).contains(&n) => format!("F{}", n),
        KeyCode::Tab => "Tab".to_string(),
        KeyCode::Enter => return None,
        KeyCode::Esc => return None,
        KeyCode::Backspace => return None,
        _ => return None,
    };

    let mut parts: Vec<String> = Vec::new();
    if mods.contains(KeyModifiers::CONTROL) {
        parts.push("Ctrl".to_string());
    }
    if mods.contains(KeyModifiers::ALT) {
        parts.push("Alt".to_string());
    }
    if mods.contains(KeyModifiers::SHIFT) {
        parts.push("Shift".to_string());
    }
    if mods.contains(KeyModifiers::SUPER) || mods.contains(KeyModifiers::META) {
        parts.push(if cfg!(target_os = "macos") {
            "Cmd".to_string()
        } else {
            "Super".to_string()
        });
    }

    if parts.is_empty() {
        return None;
    }

    parts.push(key_part);
    Some(parts.join("+"))
}
