use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::lang::ShortcutBackend;

const AHK_FILE_NAME: &str = "secret-stripper.ahk";
const STARTUP_LNK_NAME: &str = "Secret Stripper Hotkey.lnk";

/// `(<script path>, <startup .lnk path>)`.
/// Script: `%APPDATA%\secret-stripper\secret-stripper.ahk` (sits next to `config.toml`).
/// Startup .lnk: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<name>` so the
/// AHK process is re-launched at every login without us needing a service.
fn ahk_paths() -> Result<(PathBuf, PathBuf)> {
    let appdata = std::env::var("APPDATA").map_err(|_| anyhow!("APPDATA not set"))?;
    let appdata = Path::new(&appdata);
    let script = appdata.join("secret-stripper").join(AHK_FILE_NAME);
    let startup_lnk = appdata
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Startup")
        .join(STARTUP_LNK_NAME);
    Ok((script, startup_lnk))
}

struct ChordParts {
    shift: bool,
    key: String,
}

/// Windows requires Ctrl+Alt+<key> (optionally +Shift). AHK itself accepts
/// broader chords, but Ctrl+Alt avoids stomping on Win+key (reserved by the
/// OS) and Alt-alone (menu-mnemonic activation).
fn parse_windows_chord(chord: &str) -> Result<ChordParts> {
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
    if cmd || !(ctrl && alt) {
        return Err(anyhow!(
            "Windows shortcut keys must be Ctrl+Alt+<key> (optionally +Shift); got '{}'",
            chord
        ));
    }
    Ok(ChordParts { shift, key })
}

/// AHK v2 hotkey form: `^` Ctrl, `!` Alt, `+` Shift; F-keys keep their `F<n>`
/// spelling, letters/digits are lowercased by convention.
fn chord_to_ahk_hotkey(chord: &str) -> Result<String> {
    let p = parse_windows_chord(chord)?;
    let mut hk = String::from("^!");
    if p.shift {
        hk.push('+');
    }
    let key_lower = p.key.to_ascii_lowercase();
    let is_fkey = key_lower.len() >= 2
        && key_lower.starts_with('f')
        && key_lower[1..].chars().all(|c| c.is_ascii_digit());
    if is_fkey {
        hk.push('F');
        hk.push_str(&key_lower[1..]);
    } else {
        hk.push_str(&key_lower);
    }
    Ok(hk)
}

/// Content of the managed `.ahk` script. v2 syntax. Single-quoted outer string
/// so the embedded double-quoted exe path needs no escaping; any literal `'`
/// in the exe path is doubled per AHK v2's same-quote-doubling rule.
fn ahk_script_content(exe_path: &str, ahk_hotkey: &str) -> String {
    let escaped_exe = exe_path.replace('\'', "''");
    format!(
        "; secret-stripper (managed - do not edit)\n\
         #Requires AutoHotkey v2.0\n\
         #SingleInstance Force\n\
         {hk}:: Run('\"{exe}\" trigger', , 'Hide')\n",
        hk = ahk_hotkey,
        exe = escaped_exe,
    )
}

fn ps_quote(s: &str) -> String {
    s.replace('\'', "''")
}

/// Probe for AutoHotkey v2. Order: PATH first (`where`), then the common
/// install locations the official installer + winget use. Returns the path to
/// `AutoHotkey.exe` (or `AutoHotkey64.exe`); when ambiguous, prefer the v2
/// subdirectory so we never accidentally launch a v1-only install.
fn detect_autohotkey() -> Option<PathBuf> {
    if let Ok(out) = Command::new("where").arg("AutoHotkey.exe").output() {
        if out.status.success() {
            if let Ok(stdout) = String::from_utf8(out.stdout) {
                if let Some(first) = stdout.lines().next() {
                    let p = PathBuf::from(first.trim());
                    if p.exists() {
                        return Some(p);
                    }
                }
            }
        }
    }

    let pf = std::env::var("ProgramFiles").ok();
    let local = std::env::var("LOCALAPPDATA").ok();
    let candidates: Vec<PathBuf> = [
        pf.as_deref().map(|p| {
            PathBuf::from(p)
                .join("AutoHotkey")
                .join("v2")
                .join("AutoHotkey64.exe")
        }),
        pf.as_deref().map(|p| {
            PathBuf::from(p)
                .join("AutoHotkey")
                .join("v2")
                .join("AutoHotkey.exe")
        }),
        pf.as_deref()
            .map(|p| PathBuf::from(p).join("AutoHotkey").join("AutoHotkey.exe")),
        local.as_deref().map(|p| {
            PathBuf::from(p)
                .join("Programs")
                .join("AutoHotkey")
                .join("v2")
                .join("AutoHotkey64.exe")
        }),
    ]
    .into_iter()
    .flatten()
    .collect();

    candidates.into_iter().find(|p| p.exists())
}

/// Atomic write: temp file in the same directory, then rename. Matches the
/// pattern used by `config.rs` so a crash mid-write cannot leave a half
/// `.ahk` that AHK would try to parse.
fn write_atomic(target: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let parent = target
        .parent()
        .ok_or_else(|| anyhow!("no parent for {:?}", target))?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    use std::io::Write;
    tmp.write_all(contents.as_bytes())?;
    tmp.flush()?;
    tmp.persist(target)
        .map_err(|e| anyhow!("rename to {:?} failed: {}", target, e.error))?;
    Ok(())
}

/// Create the startup `.lnk` so AHK re-runs our managed script at every
/// login. WindowStyle 7 keeps AHK's tray icon visible (the user can still
/// right-click and exit) but does not steal focus.
fn create_startup_lnk(startup_lnk: &Path, ahk_exe: &Path, script: &Path) -> Result<()> {
    let lnk_str = startup_lnk
        .to_str()
        .ok_or_else(|| anyhow!("non-UTF8 startup lnk path"))?;
    let exe_str = ahk_exe
        .to_str()
        .ok_or_else(|| anyhow!("non-UTF8 AHK exe path"))?;
    let script_str = script
        .to_str()
        .ok_or_else(|| anyhow!("non-UTF8 script path"))?;
    let arguments = format!("\"{}\"", script_str);

    let ps = format!(
        "$ws = New-Object -ComObject WScript.Shell; \
         $s = $ws.CreateShortcut('{lnk}'); \
         $s.TargetPath = '{exe}'; \
         $s.Arguments = '{args}'; \
         $s.WindowStyle = 7; \
         $s.Save()",
        lnk = ps_quote(lnk_str),
        exe = ps_quote(exe_str),
        args = ps_quote(&arguments),
    );
    let status = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .status()
        .map_err(|e| anyhow!("powershell invocation failed: {}", e))?;
    if !status.success() {
        return Err(anyhow!("powershell exited with status {}", status));
    }
    Ok(())
}

fn register_via_ahk(ahk_exe: &Path, exe_str: &str, chord: &str) -> Result<()> {
    let ahk_hotkey = chord_to_ahk_hotkey(chord)?;
    let (script_path, startup_lnk) = ahk_paths()?;
    let content = ahk_script_content(exe_str, &ahk_hotkey);
    write_atomic(&script_path, &content)?;
    create_startup_lnk(&startup_lnk, ahk_exe, &script_path)?;
    // Spawn AHK so the chord is live without a logout. `#SingleInstance Force`
    // in the script means relaunching just replaces any previous instance
    // bound to the same script path.
    Command::new(ahk_exe)
        .arg(&script_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| anyhow!("spawning AutoHotkey failed: {}", e))?;
    Ok(())
}

/// Path-scoped cleanup: kill ONLY the AHK processes whose command-line
/// references our `.ahk` (leaves the user's other AHK scripts running),
/// then delete the script and the startup `.lnk`. Each step swallows
/// errors so an absent file or missing AHK does not abort uninstall.
fn unregister_ahk() {
    let ps = "Get-CimInstance Win32_Process -Filter \"Name LIKE 'AutoHotkey%.exe'\" \
              | Where-Object { $_.CommandLine -like '*secret-stripper.ahk*' } \
              | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }";
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", ps])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if let Ok((script_path, startup_lnk)) = ahk_paths() {
        let _ = std::fs::remove_file(&script_path);
        let _ = std::fs::remove_file(&startup_lnk);
    }
}

pub(super) fn register(chord: &str) -> Result<ShortcutBackend> {
    let exe = std::env::current_exe()
        .map_err(|e| anyhow!("could not resolve our own binary path: {}", e))?;
    let exe_str = exe
        .to_str()
        .ok_or_else(|| anyhow!("non-UTF8 binary path"))?;

    let ahk_exe = detect_autohotkey().ok_or_else(|| {
        anyhow!(
            "AutoHotkey v2 is required for the Windows hotkey backend but was not found. \
             Install it via `winget install AutoHotkey.AutoHotkey` (or from https://www.autohotkey.com/), \
             then re-run `secret-stripper init`."
        )
    })?;
    register_via_ahk(&ahk_exe, exe_str, chord)?;
    Ok(ShortcutBackend::WindowsAhk)
}

pub(super) fn unregister() -> Result<()> {
    unregister_ahk();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ahk_maps_ctrl_alt() {
        assert_eq!(chord_to_ahk_hotkey("Ctrl+Alt+C").unwrap(), "^!c");
    }

    #[test]
    fn ahk_keeps_shift() {
        assert_eq!(chord_to_ahk_hotkey("Ctrl+Alt+Shift+C").unwrap(), "^!+c");
    }

    #[test]
    fn ahk_handles_function_keys() {
        assert_eq!(chord_to_ahk_hotkey("Ctrl+Alt+F5").unwrap(), "^!F5");
        assert_eq!(chord_to_ahk_hotkey("Ctrl+Alt+Shift+F12").unwrap(), "^!+F12");
    }

    #[test]
    fn ahk_rejects_non_ctrl_alt() {
        assert!(chord_to_ahk_hotkey("Cmd+Shift+C").is_err());
        assert!(chord_to_ahk_hotkey("Ctrl+Shift+C").is_err());
        assert!(chord_to_ahk_hotkey("Alt+C").is_err());
    }

    #[test]
    fn ahk_script_contains_required_directives() {
        let s = ahk_script_content(
            r"C:\Program Files\secret-stripper\secret-stripper.exe",
            "^!c",
        );
        assert!(s.contains("; secret-stripper (managed - do not edit)"));
        assert!(s.contains("#Requires AutoHotkey v2.0"));
        assert!(s.contains("#SingleInstance Force"));
        assert!(s.contains("^!c::"));
        assert!(s.contains("'Hide'"));
        assert!(s.contains(r"C:\Program Files\secret-stripper\secret-stripper.exe"));
    }

    #[test]
    fn ahk_script_escapes_quotes_in_exe_path() {
        let s = ahk_script_content(r"C:\Weird'Path\secret-stripper.exe", "^!c");
        assert!(s.contains(r"C:\Weird''Path\secret-stripper.exe"));
        assert!(!s.contains(r"C:\Weird'Path\secret-stripper.exe"));
    }
}
