use crate::config::Config;
use crate::detector::{custom, patterns};
use crate::tui::chrome::scaffold;
use crate::tui::theme;
use crate::tui::widgets::scrolled_window;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

/// Very short, English-only descriptor of what a built-in bucket covers.
/// Bucket stems are themselves untranslated technical labels, so adjacent
/// descriptors stay English-only for consistency. Unknown (custom) buckets
/// fall back to "custom".
fn bucket_desc(stem: &str) -> &'static str {
    match stem {
        "legacy" => "core AWS/GitHub/Slack/JWT set",
        "cloud_aws" => "AWS keys, STS, ARNs",
        "cloud_gcp" => "GCP keys, service accounts",
        "cloud_azure" => "Azure keys, SAS, AAD",
        "cloud_other" => "DigitalOcean, Linode, etc.",
        "infra" => "Terraform, Vault, K8s, CI infra",
        "networking" => "IPs, MACs, CIDRs, hosts",
        "payments" => "Stripe, PayPal, card keys",
        "messaging" => "Slack, Twilio, SendGrid, etc.",
        "vcs_ci" => "GitHub/GitLab/CI tokens",
        "ai" => "OpenAI/Anthropic/LLM keys",
        "monitoring" => "Datadog, Sentry, New Relic",
        "databases" => "DB conn strings & creds",
        "edge" => "Cloudflare, Fastly, CDNs",
        "crypto_keys" => "private keys, PEM, SSH",
        "auth_tokens" => "OAuth, bearer, refresh tokens",
        "packages" => "npm, PyPI, crates tokens",
        "healthcare" => "health/medical identifiers",
        "pii_contact" => "emails, phones, addresses",
        "pii_financial" => "cards, IBAN, bank accounts",
        "pii_govid_us" => "US SSN/ITIN/EIN",
        "pii_govid_eu" => "EU national IDs",
        "pii_govid_intl" => "other national IDs",
        "pii_network" => "PII tied to network IDs",
        "hashes" => "password/credential hashes",
        "structured" => "env/JSON/kv secret shapes",
        "wallets" => "crypto wallet keys/seeds",
        "exchanges" => "crypto exchange API keys",
        "rpc_chain" => "blockchain RPC endpoints",
        "mobile" => "mobile app/store keys",
        "gaming" => "game platform API keys",
        "iot" => "IoT device credentials",
        "saas_iam" => "Okta/Auth0/IAM tokens",
        "saas_collab" => "Notion, Figma, Atlassian",
        "saas_crm_marketing" => "HubSpot, Salesforce, etc.",
        "saas_hr_finance" => "HR/finance SaaS keys",
        "ad_tech" => "ad platform API keys",
        "banking" => "banking API credentials",
        "threat_intel" => "threat-intel API keys",
        "industry_other" => "misc industry secrets",
        _ => "custom",
    }
}

pub fn show(terminal: &mut ratatui::DefaultTerminal, config: &mut Config) -> anyhow::Result<bool> {
    terminal.clear()?;

    let mut buckets: Vec<(String, usize)> = patterns::bucket_catalog()
        .into_iter()
        .map(|(s, c)| (s.to_string(), c))
        .collect();
    for spec in custom::load_specs() {
        if !buckets.iter().any(|(s, _)| *s == spec.category) {
            buckets.push((spec.category.clone(), 0));
        }
    }
    buckets.sort_by(|a, b| a.0.cmp(&b.0));

    let mut selected = 0usize;
    let mut changed = false;

    let result = loop {
        if !buckets.is_empty() {
            selected = selected.min(buckets.len() - 1);
        }

        terminal.draw(|f| {
            let body = scaffold(f, config.lang.cat_title(), config.lang.cat_hint(), config);
            if buckets.is_empty() {
                f.render_widget(
                    Paragraph::new(Span::styled(
                        config.lang.cat_empty(),
                        Style::new().fg(theme::text_dim()),
                    )),
                    body,
                );
                return;
            }
            let rows = body.height as usize;
            // Treat 3 trailing blank rows as virtual items so the cursor can
            // approach them as the list ends, giving the user a visible
            // "end of list" buffer beneath the last bucket.
            const TAIL_BLANK: usize = 3;
            let virtual_total = buckets.len() + TAIL_BLANK;
            // Keep ~5 rows of context below the cursor so the user does not
            // have to land on the bottom-most visible row to see what is next.
            let (off, end) = scrolled_window(virtual_total, selected, rows, 5);
            let mut lines: Vec<Line> = Vec::with_capacity(end - off);
            let real_end = end.min(buckets.len());
            for (i, (stem, count)) in buckets[off..real_end].iter().enumerate() {
                let idx = off + i;
                let enabled = !config.disabled_categories.iter().any(|d| d == stem);
                let mark = if enabled { "[x]" } else { "[ ]" };
                let is_sel = idx == selected;
                let arrow = if is_sel { " \u{25B6} " } else { "   " };
                let mark_color = if enabled {
                    theme::success()
                } else {
                    theme::text_dim()
                };
                let label_style = if is_sel {
                    Style::new()
                        .fg(theme::accent())
                        .add_modifier(Modifier::BOLD)
                } else if enabled {
                    Style::new().fg(theme::text())
                } else {
                    Style::new().fg(theme::text_dim())
                };
                lines.push(Line::from(vec![
                    Span::styled(arrow, Style::new().fg(theme::select_arrow())),
                    Span::styled(format!("{} ", mark), Style::new().fg(mark_color)),
                    Span::styled(format!("{:<20}", stem), label_style),
                    Span::styled(
                        format!("{:>5}  ", format!("({})", count)),
                        Style::new().fg(theme::text_dim()),
                    ),
                    Span::styled(
                        bucket_desc(stem).to_string(),
                        Style::new().fg(theme::text_dim()),
                    ),
                ]));
            }
            for _ in real_end..end {
                lines.push(Line::from(""));
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
                break changed;
            }
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => break changed,
                KeyCode::Up if !buckets.is_empty() => {
                    selected = if selected == 0 {
                        buckets.len() - 1
                    } else {
                        selected - 1
                    };
                }
                KeyCode::Down if !buckets.is_empty() => {
                    selected = (selected + 1) % buckets.len();
                }
                KeyCode::Char(' ') => {
                    if let Some((stem, _)) = buckets.get(selected) {
                        if let Some(pos) = config.disabled_categories.iter().position(|d| d == stem)
                        {
                            config.disabled_categories.remove(pos);
                        } else {
                            config.disabled_categories.push(stem.clone());
                        }
                        config.save()?;
                        changed = true;
                    }
                }
                _ => {}
            }
        }
    };

    Ok(result)
}
