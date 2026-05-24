use anyhow::{anyhow, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::lang::ShortcutBackend;

const SKHD_MARKER: &str = "# secret-stripper (managed - do not edit this block)";
const SKHD_END: &str = "# end secret-stripper";
const HS_MARKER: &str = "-- secret-stripper (managed - do not edit this block)";
const HS_END: &str = "-- end secret-stripper";

struct Chord {
    /// Modifier names in canonical order, using each backend's own spelling
    /// resolved later (here we keep neutral tokens: ctrl/alt/shift/cmd).
    mods: Vec<&'static str>,
    key: String,
}

fn parse_chord(chord: &str) -> Result<Chord> {
    let mut ctrl = false;
    let mut alt = false;
    let mut shift = false;
    let mut cmd = false;
    let mut key: Option<String> = None;

    for raw in chord.split('+') {
        let part = raw.trim();
        if part.is_empty() {
            continue;
        }
        match part.to_ascii_lowercase().as_str() {
            "ctrl" | "control" => ctrl = true,
            "alt" | "option" | "opt" => alt = true,
            "shift" => shift = true,
            "cmd" | "command" | "super" | "meta" | "win" | "windows" => cmd = true,
            other => {
                if key.is_some() {
                    return Err(anyhow!("chord '{}' has multiple non-modifier keys", chord));
                }
                key = Some(other.to_string());
            }
        }
    }

    let key = key.ok_or_else(|| anyhow!("chord '{}' has no key", chord))?;
    let mut mods = Vec::new();
    if ctrl {
        mods.push("ctrl");
    }
    if alt {
        mods.push("alt");
    }
    if shift {
        mods.push("shift");
    }
    if cmd {
        mods.push("cmd");
    }
    if mods.is_empty() {
        return Err(anyhow!(
            "chord '{}' must include at least one modifier",
            chord
        ));
    }
    Ok(Chord {
        mods,
        key: key.to_lowercase(),
    })
}

fn tool_on_path(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Drop the contiguous managed block (marker line through end line, inclusive)
/// from `content`, leaving everything else untouched. Idempotent.
fn strip_managed_block(content: &str, marker: &str, end: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut skipping = false;
    for line in content.lines() {
        if skipping {
            if line.trim() == end {
                skipping = false;
            }
            continue;
        }
        if line.trim() == marker {
            skipping = true;
            continue;
        }
        out.push(line);
    }
    let mut joined = out.join("\n");
    if !joined.is_empty() && !joined.ends_with('\n') {
        joined.push('\n');
    }
    joined
}

fn skhd_block(exe: &str, chord: &Chord) -> String {
    // skhd syntax: "<mods joined by +> - <key> : <command>"
    let mods = chord.mods.join(" + ");
    format!(
        "{marker}\n{mods} - {key} : \"{exe}\" trigger\n{end}\n",
        marker = SKHD_MARKER,
        mods = mods,
        key = chord.key,
        exe = exe,
        end = SKHD_END
    )
}

fn hammerspoon_block(exe: &str, chord: &Chord) -> String {
    let mods = chord
        .mods
        .iter()
        .map(|m| format!("\"{}\"", m))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{marker}\nhs.hotkey.bind({{{mods}}}, \"{key}\", function()\n  hs.task.new(\"{exe}\", nil, {{\"trigger\"}}):start()\nend)\n{end}\n",
        marker = HS_MARKER,
        mods = mods,
        key = chord.key,
        exe = exe,
        end = HS_END
    )
}

fn append_managed(path: &Path, marker: &str, end: &str, block: &str) -> Result<()> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    let mut base = strip_managed_block(&existing, marker, end);
    if !base.is_empty() && !base.ends_with('\n') {
        base.push('\n');
    }
    base.push_str(block);
    fs::write(path, base)?;
    Ok(())
}

pub(super) fn register(chord_str: &str) -> Result<ShortcutBackend> {
    let chord = parse_chord(chord_str)?;
    let exe = std::env::current_exe()
        .map_err(|e| anyhow!("could not resolve our own binary path: {}", e))?;
    let exe_str = exe
        .to_str()
        .ok_or_else(|| anyhow!("non-UTF8 binary path"))?;
    let home = dirs::home_dir().ok_or_else(|| anyhow!("no home dir"))?;

    if tool_on_path("skhd") {
        let skhdrc = home.join(".skhdrc");
        append_managed(&skhdrc, SKHD_MARKER, SKHD_END, &skhd_block(exe_str, &chord))?;
        crate::proc::run_optional("skhd", &["--reload"]);
        return Ok(ShortcutBackend::Skhd);
    }

    let hs_init = home.join(".hammerspoon").join("init.lua");
    if hs_init.exists() || Path::new("/Applications/Hammerspoon.app").exists() {
        if let Some(parent) = hs_init.parent() {
            fs::create_dir_all(parent)?;
        }
        append_managed(
            &hs_init,
            HS_MARKER,
            HS_END,
            &hammerspoon_block(exe_str, &chord),
        )?;
        crate::proc::run_optional(
            "osascript",
            &["-e", "tell application \"Hammerspoon\" to reload"],
        );
        return Ok(ShortcutBackend::Hammerspoon);
    }

    Err(anyhow!(
        "No supported macOS hotkey tool found. Install skhd (brew install koekeishiya/formulae/skhd) or Hammerspoon, or bind 'secret-stripper trigger' to {} manually in System Settings > Keyboard > Shortcuts.",
        chord_str
    ))
}

pub(super) fn unregister() -> Result<()> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("no home dir"))?;

    let skhdrc = home.join(".skhdrc");
    if skhdrc.exists() {
        let content = fs::read_to_string(&skhdrc).unwrap_or_default();
        fs::write(
            &skhdrc,
            strip_managed_block(&content, SKHD_MARKER, SKHD_END),
        )?;
        crate::proc::run_optional("skhd", &["--reload"]);
    }

    let hs_init = home.join(".hammerspoon").join("init.lua");
    if hs_init.exists() {
        let content = fs::read_to_string(&hs_init).unwrap_or_default();
        fs::write(&hs_init, strip_managed_block(&content, HS_MARKER, HS_END))?;
        crate::proc::run_optional(
            "osascript",
            &["-e", "tell application \"Hammerspoon\" to reload"],
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skhd_syntax() {
        let c = parse_chord("Cmd+Shift+C").unwrap();
        let b = skhd_block("/bin/ss", &c);
        assert!(b.contains("cmd + shift - c : \"/bin/ss\" trigger"));
        assert!(b.starts_with(SKHD_MARKER));
        assert!(b.trim_end().ends_with(SKHD_END));
    }

    #[test]
    fn hammerspoon_syntax() {
        let c = parse_chord("Cmd+Shift+C").unwrap();
        let b = hammerspoon_block("/bin/ss", &c);
        assert!(b.contains("hs.hotkey.bind({\"cmd\",\"shift\"}, \"c\""));
        assert!(b.contains("hs.task.new(\"/bin/ss\", nil, {\"trigger\"})"));
    }

    #[test]
    fn strip_is_idempotent() {
        let c = parse_chord("Cmd+Shift+C").unwrap();
        let base = "other line\n";
        let with = format!("{}{}", base, skhd_block("/bin/ss", &c));
        let stripped = strip_managed_block(&with, SKHD_MARKER, SKHD_END);
        assert_eq!(stripped, base);
    }

    #[test]
    fn rejects_modifierless_chord() {
        assert!(parse_chord("C").is_err());
    }
}
