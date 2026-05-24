use anyhow::Result;

use crate::lang::ShortcutBackend;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// Tests and CI runners set `SECRET_STRIPPER_NO_OS_SIDE_EFFECTS` so an
/// `init`/`uninstall` cannot mutate the host's real desktop bindings.
fn os_side_effects_disabled() -> bool {
    std::env::var_os("SECRET_STRIPPER_NO_OS_SIDE_EFFECTS").is_some()
}

/// A human-readable label for the current desktop/OS, shown in `status` and the
/// install-management screen. Linux returns `$XDG_CURRENT_DESKTOP`.
pub fn detect_desktop() -> String {
    #[cfg(target_os = "linux")]
    {
        linux::detect_desktop()
    }
    #[cfg(target_os = "macos")]
    {
        "macOS".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        "Windows".to_string()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        String::new()
    }
}

pub fn register(chord: &str) -> Result<ShortcutBackend> {
    // Re-validate the chord here, not just at TUI capture time. The chord
    // string flows into shell-quoted skhd lines (macOS), Lua interpolation
    // (Hammerspoon), and an AutoHotkey script (Windows); an attacker-
    // controlled or migrated config that bypassed parse_chord on TUI entry
    // must not reach those sinks unvalidated.
    crate::hotkey::parse_chord(chord)
        .map_err(|e| anyhow::anyhow!("invalid hotkey chord {:?}: {}", chord, e))?;
    if os_side_effects_disabled() {
        return Ok(ShortcutBackend::Gnome);
    }
    #[cfg(target_os = "linux")]
    {
        linux::register(chord)
    }
    #[cfg(target_os = "macos")]
    {
        macos::register(chord)
    }
    #[cfg(target_os = "windows")]
    {
        windows::register(chord)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(anyhow::anyhow!(
            "unsupported OS; bind 'secret-stripper trigger' to {} manually",
            chord
        ))
    }
}

pub fn unregister() -> Result<()> {
    if os_side_effects_disabled() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        linux::unregister()
    }
    #[cfg(target_os = "macos")]
    {
        macos::unregister()
    }
    #[cfg(target_os = "windows")]
    {
        windows::unregister()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Ok(())
    }
}
