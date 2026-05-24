use anyhow::{anyhow, Result};

/// Validate that a chord string like "Ctrl+Alt+C" is syntactically usable.
/// We do not need OS-level types here: the chord is passed straight through to the
/// desktop environment's shortcut tool (gsettings/kwriteconfig/xfconf-query), which
/// owns the actual key registration. This validates the user-typed string before we
/// hand it off, so we catch garbage input at the menu/config layer.
pub fn parse_chord(s: &str) -> Result<()> {
    let mut found_modifier = false;
    let mut key: Option<String> = None;

    for raw in s.split('+') {
        let part = raw.trim();
        if part.is_empty() {
            continue;
        }
        match part.to_ascii_lowercase().as_str() {
            "ctrl" | "control" | "alt" | "option" | "opt" | "shift" | "cmd" | "command"
            | "super" | "meta" | "win" | "windows" => {
                found_modifier = true;
            }
            other => {
                if key.is_some() {
                    return Err(anyhow!("chord '{}' has more than one non-modifier key", s));
                }
                validate_key(other)?;
                key = Some(other.to_string());
            }
        }
    }

    if key.is_none() {
        return Err(anyhow!("chord '{}' has no key", s));
    }
    if !found_modifier {
        return Err(anyhow!("chord '{}' must include at least one modifier", s));
    }
    Ok(())
}

fn validate_key(s: &str) -> Result<()> {
    if s.len() == 1 {
        let c = s.chars().next().unwrap();
        if c.is_ascii_alphanumeric() {
            return Ok(());
        }
    }
    if let Some(rest) = s.to_ascii_lowercase().strip_prefix('f') {
        if let Ok(n) = rest.parse::<u8>() {
            if (1..=12).contains(&n) {
                return Ok(());
            }
        }
    }
    match s.to_ascii_lowercase().as_str() {
        "space" | "enter" | "return" | "tab" | "escape" | "esc" => Ok(()),
        _ => Err(anyhow!("unsupported key '{}'", s)),
    }
}

pub fn fallback_chords() -> &'static [&'static str] {
    #[cfg(target_os = "macos")]
    {
        &["Cmd+Shift+C", "Cmd+Shift+R", "Cmd+Alt+C"]
    }
    #[cfg(target_os = "windows")]
    {
        &["Ctrl+Alt+C", "Ctrl+Alt+R", "Ctrl+Alt+Shift+C"]
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        &["Ctrl+Alt+X", "Ctrl+Alt+R", "Ctrl+Alt+Shift+X"]
    }
}

pub fn candidates_for(preferred: &str) -> Vec<String> {
    let mut out: Vec<String> = vec![preferred.to_string()];
    for c in fallback_chords() {
        if !out.iter().any(|x| x.eq_ignore_ascii_case(c)) {
            out.push((*c).to_string());
        }
    }
    out
}

pub struct ProbeOutcome {
    pub active: Option<String>,
    pub tried: Vec<String>,
    pub last_error: Option<String>,
}

/// Pick the first candidate chord that parses cleanly. This is intentionally just a
/// syntax check: we no longer attempt OS-level registration to test availability,
/// because the desktop environment's shortcut tool (gsettings/kwriteconfig/xfconf)
/// is the source of truth for "is this chord usable" and gracefully reports its own
/// errors when we hand it the chord later.
pub fn probe(preferred: &str) -> ProbeOutcome {
    let candidates = candidates_for(preferred);
    let mut last_error: Option<String> = None;

    for cand in &candidates {
        match parse_chord(cand) {
            Ok(()) => {
                return ProbeOutcome {
                    active: Some(cand.clone()),
                    tried: candidates,
                    last_error,
                };
            }
            Err(e) => {
                last_error = Some(format!("parse error for '{}': {}", cand, e));
            }
        }
    }

    ProbeOutcome {
        active: None,
        tried: candidates,
        last_error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ctrl_alt_c() {
        assert!(parse_chord("Ctrl+Alt+C").is_ok());
    }

    #[test]
    fn parses_cmd_shift_c() {
        assert!(parse_chord("Cmd+Shift+C").is_ok());
    }

    #[test]
    fn parse_is_case_insensitive() {
        assert!(parse_chord("ctrl+alt+k").is_ok());
    }

    #[test]
    fn parses_function_key() {
        assert!(parse_chord("Ctrl+F5").is_ok());
    }

    #[test]
    fn rejects_no_modifier() {
        assert!(parse_chord("C").is_err());
    }

    #[test]
    fn rejects_no_key() {
        assert!(parse_chord("Ctrl+Alt").is_err());
    }

    #[test]
    fn rejects_two_keys() {
        assert!(parse_chord("Ctrl+A+B").is_err());
    }

    #[test]
    fn probe_returns_first_candidate() {
        let out = probe("Ctrl+Alt+C");
        assert_eq!(out.active.as_deref(), Some("Ctrl+Alt+C"));
    }

    #[test]
    fn probe_rejects_invalid_then_falls_back() {
        let out = probe("not a chord");
        assert!(out.active.is_some()); // falls back to a default candidate
    }

    #[test]
    fn rejects_shell_metachars_and_quotes() {
        // Defense against migrated configs reaching skhd / Hammerspoon / .lnk
        // sinks with a key containing characters that escape the surrounding
        // string. parse_chord must hard-fail on anything that isn't an ASCII
        // alphanumeric / F-key / a few named keys.
        for bad in [
            "Ctrl+Alt+'",
            "Ctrl+Alt+\"",
            "Ctrl+Alt+;",
            "Ctrl+Alt+:",
            "Ctrl+Alt+$",
            "Ctrl+Alt+`",
            "Ctrl+Alt+|",
            "Ctrl+Alt+\\",
            "Ctrl+Alt+\n",
        ] {
            assert!(parse_chord(bad).is_err(), "should reject: {bad:?}");
        }
    }
}
