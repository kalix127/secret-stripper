use crate::config::Config;
use crate::tui::theme;
use crate::tui::widgets::rounded_block;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Padding, Paragraph},
    Frame,
};

/// Inset a rect horizontally so content does not hug the screen edge.
fn pad_h(r: Rect, m: u16) -> Rect {
    let m = m.min(r.width / 2);
    Rect {
        x: r.x + m,
        y: r.y,
        width: r.width.saturating_sub(m * 2),
        height: r.height,
    }
}

/// Owned snapshot of every config-derived value rendered in the status panel.
/// Built fresh per draw inside `scaffold` - cheap, no caching needed
/// (stats::read_buckets reads a tiny JSONL and the config clones are short
/// strings). Private to this module: callers only pass `&Config`.
struct StatusSnapshot {
    hotkey: String,
    lang_endonym: String,
    sensitivity_label: String,
    notif: String,
    deep: String,
    redact_style: String,
    buckets_label: String,
    /// `Some(tag)` when a newer release has been seen by the daily
    /// update-check timer; `None` when up-to-date or unknown. The status
    /// panel omits the Update row entirely in the `None` case so the panel
    /// stays compact in the common case.
    update: Option<String>,
    stats: crate::stats::StatBuckets,
}

impl StatusSnapshot {
    fn from_config(config: &Config) -> Self {
        use crate::detector::presets::{self, Preset};
        let lang = config.lang;
        let preset_name = match presets::detect(config) {
            Some(p) => lang.preset_label(&p).0.to_string(),
            None => lang.preset_custom_short().to_string(),
        };
        let sensitivity_label = format!("{} ({})", config.sensitivity, preset_name);
        let notif = if config.silent {
            lang.status_silent()
        } else {
            lang.status_on()
        }
        .to_string();
        let deep = if config.enable_deep_scan {
            lang.status_on()
        } else {
            lang.status_off()
        }
        .to_string();
        // Preset::Full enables every bucket, so its enabled-stem count is the
        // total - avoids needing access to the (pub(crate)) BUCKETS table.
        let total_buckets = Preset::Full.enabled_stems().len();
        let enabled_buckets = total_buckets.saturating_sub(config.disabled_categories.len());
        let buckets_label = format!("{}/{}", enabled_buckets, total_buckets);
        let update = match config.last_seen_version.as_deref() {
            Some(tag) if crate::updater::is_newer(tag) => Some(tag.to_string()),
            _ => None,
        };
        let redact_style = match config.redact_style {
            crate::config::RedactStyle::Marker => {
                format!("{}: {}", lang.rs_style_marker(), config.redact_pattern)
            }
            crate::config::RedactStyle::Drop => lang.rs_style_drop().to_string(),
            crate::config::RedactStyle::Typed => lang.rs_style_typed().to_string(),
            crate::config::RedactStyle::Placeholder => lang.rs_style_placeholder().to_string(),
        };
        Self {
            hotkey: config.hotkey.clone(),
            lang_endonym: lang.endonym().to_string(),
            sensitivity_label,
            notif,
            deep,
            redact_style,
            buckets_label,
            update,
            stats: crate::stats::read_buckets(),
        }
    }

    /// Number of content rows the left column needs. Always renders the seven
    /// stable rows (Hotkey, Lang, Sens, Notif, Deep, Style, Buckets) plus the
    /// optional Update row when present.
    fn panel_rows(&self) -> usize {
        if self.update.is_some() {
            8
        } else {
            7
        }
    }
}

/// Label style for one row of a selectable list: accent + bold when the row
/// is the cursor, plain otherwise. Single source for the radio/list screens
/// (language, presets, redact-style) so their highlight stays identical.
pub fn list_label_style(is_selected: bool) -> Style {
    if is_selected {
        Style::new()
            .fg(theme::accent())
            .add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(theme::text())
    }
}

/// Draws the shared screen chrome (header bar, framed status panel, section
/// label, footer help line) and returns the inner Rect the caller renders its
/// own body into.
pub fn scaffold(f: &mut Frame, section_title: &str, footer_help: &str, config: &Config) -> Rect {
    let area = f.area();
    let status = StatusSnapshot::from_config(config);
    let panel_h = (status.panel_rows() + 2) as u16;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),       // 0 header bar
            Constraint::Length(1),       // 1 spacer
            Constraint::Length(panel_h), // 2 status panel
            Constraint::Length(1),       // 3 spacer
            Constraint::Length(1),       // 4 section title
            Constraint::Length(1),       // 5 help line (above the menu)
            Constraint::Length(1),       // 6 spacer
            Constraint::Min(3),          // 7 body
        ])
        .split(area);

    let lang = config.lang;
    let margin = 2u16;

    let header = Paragraph::new(Line::from(vec![
        Span::raw(" "),
        Span::styled(
            crate::APP_NAME,
            Style::new()
                .fg(theme::header_app())
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("   |   ", Style::new().fg(theme::header_sep())),
        Span::styled(
            format!("v{}", env!("CARGO_PKG_VERSION")),
            Style::new().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
    ]));
    f.render_widget(header, chunks[0]);

    render_status_panel(f, pad_h(chunks[2], margin), lang, &status);

    let section = Paragraph::new(Span::styled(
        section_title.trim().to_string(),
        Style::new()
            .fg(theme::accent())
            .add_modifier(Modifier::BOLD),
    ));
    f.render_widget(section, pad_h(chunks[4], margin));

    // Help line: color the key (first token of each "|"-separated segment)
    // distinctly from its action label so it scans at a glance.
    let key_style = Style::new()
        .fg(theme::accent())
        .add_modifier(Modifier::BOLD);
    let action_style = Style::new().fg(theme::text_dim());
    let sep_style = Style::new().fg(theme::border());
    let help_line = if footer_help.contains('|') {
        let mut help_spans: Vec<Span> = Vec::new();
        for (i, seg) in footer_help.split('|').enumerate() {
            let seg = seg.trim();
            if seg.is_empty() {
                continue;
            }
            if i > 0 {
                help_spans.push(Span::styled("  |  ", sep_style));
            }
            let mut it = seg.splitn(2, char::is_whitespace);
            let key = it.next().unwrap_or("");
            let action = it.next().unwrap_or("").trim_start();
            help_spans.push(Span::styled(key.to_string(), key_style));
            if !action.is_empty() {
                help_spans.push(Span::styled(format!(" {}", action), action_style));
            }
        }
        Line::from(help_spans)
    } else {
        Line::from(Span::styled(footer_help.to_string(), action_style))
    };
    f.render_widget(Paragraph::new(help_line), pad_h(chunks[5], margin));

    pad_h(chunks[7], margin)
}

fn render_status_panel(f: &mut Frame, area: Rect, lang: crate::lang::Lang, snap: &StatusSnapshot) {
    let bucket_value = |n: u64| -> String {
        if snap.stats.file_exists {
            n.to_string()
        } else {
            "-".to_string()
        }
    };

    let mut left: Vec<(&str, String)> = vec![
        (lang.status_hotkey(), snap.hotkey.clone()),
        (lang.status_lang(), snap.lang_endonym.clone()),
        (lang.status_sens(), snap.sensitivity_label.clone()),
        (lang.status_notif(), snap.notif.clone()),
        (lang.status_deep(), snap.deep.clone()),
        (lang.status_style(), snap.redact_style.clone()),
        (lang.status_buckets(), snap.buckets_label.clone()),
    ];
    if let Some(tag) = &snap.update {
        left.push((lang.status_update(), format!("{}!", tag)));
    }
    let right: Vec<(&str, String)> = vec![
        (lang.stats_24h(), bucket_value(snap.stats.last_24h)),
        (lang.stats_7d(), bucket_value(snap.stats.last_7d)),
        (lang.stats_30d(), bucket_value(snap.stats.last_30d)),
        (lang.stats_total(), bucket_value(snap.stats.total)),
    ];

    let left_label_w = left
        .iter()
        .map(|(l, _)| l.chars().count())
        .max()
        .unwrap_or(0);
    let left_value_w = left
        .iter()
        .map(|(_, v)| v.chars().count())
        .max()
        .unwrap_or(0);
    let right_label_w = right
        .iter()
        .map(|(l, _)| l.chars().count())
        .max()
        .unwrap_or(0);
    let right_value_w = right
        .iter()
        .map(|(_, v)| v.chars().count())
        .max()
        .unwrap_or(0);

    let left_col_w = (left_label_w + 2 + left_value_w) as u16;
    let right_col_w = (right_label_w + 2 + right_value_w) as u16;
    let natural_w = 2 + 2 + left_col_w + 3 + right_col_w;
    let panel_w = natural_w.min(area.width);

    let panel_rect = Rect {
        x: area.x,
        y: area.y,
        width: panel_w,
        height: area.height,
    };

    let title = format!(" {} ", lang.status_panel_title());
    let block = rounded_block(&title, theme::soft_white()).padding(Padding::horizontal(1));
    let inner = block.inner(panel_rect);
    f.render_widget(block, panel_rect);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(left_col_w),
            Constraint::Length(3),
            Constraint::Length(right_col_w),
        ])
        .split(inner);

    let label_style = Style::new()
        .fg(theme::soft_white())
        .add_modifier(Modifier::BOLD);
    let value_style = Style::new().fg(theme::text());

    let render_col = |lines: &mut Vec<Line>, rows: &[(&str, String)], label_w: usize| {
        for (label, value) in rows {
            lines.push(Line::from(vec![
                Span::styled(format!("{:<width$}  ", label, width = label_w), label_style),
                Span::styled(value.clone(), value_style),
            ]));
        }
    };

    let panel_rows = left.len().max(right.len());
    let mut left_lines: Vec<Line> = Vec::with_capacity(panel_rows);
    render_col(&mut left_lines, &left, left_label_w);
    f.render_widget(Paragraph::new(left_lines), cols[0]);

    let sep_style = Style::new().fg(theme::border());
    let sep_lines: Vec<Line> = (0..panel_rows)
        .map(|_| Line::from(vec![Span::raw(" "), Span::styled("\u{2502}", sep_style)]))
        .collect();
    f.render_widget(Paragraph::new(sep_lines), cols[1]);

    let mut right_lines: Vec<Line> = Vec::with_capacity(panel_rows);
    render_col(&mut right_lines, &right, right_label_w);
    while right_lines.len() < panel_rows {
        right_lines.push(Line::from(""));
    }
    f.render_widget(Paragraph::new(right_lines), cols[2]);
}
