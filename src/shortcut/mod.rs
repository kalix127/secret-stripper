use anyhow::Result;

use crate::lang::ShortcutBackend;

mod linux;

/// Tests and CI runners set `SECRET_STRIPPER_NO_OS_SIDE_EFFECTS` so an
/// `init`/`uninstall` cannot mutate the host's real desktop bindings.
pub(crate) fn os_side_effects_disabled() -> bool {
    std::env::var_os("SECRET_STRIPPER_NO_OS_SIDE_EFFECTS").is_some()
}

/// A human-readable label for the current desktop, shown in `status` and the
/// install-management screen. Returns `$XDG_CURRENT_DESKTOP`.
pub fn detect_desktop() -> String {
    linux::detect_desktop()
}

pub fn register(chord: &str) -> Result<ShortcutBackend> {
    // Re-validate here, not just at TUI capture time: the chord flows into
    // desktop config tools, and a hand-edited config may bypass the TUI.
    crate::hotkey::parse_chord(chord)
        .map_err(|e| anyhow::anyhow!("invalid hotkey chord {:?}: {}", chord, e))?;
    if os_side_effects_disabled() {
        return Ok(ShortcutBackend::Gnome);
    }
    linux::register(chord)
}

/// Config lines for window managers we cannot bind automatically.
pub fn manual_examples(exe: &str, chord: &str) -> Vec<String> {
    linux::manual_examples(exe, chord)
}

pub fn unregister() -> Result<()> {
    if os_side_effects_disabled() {
        return Ok(());
    }
    linux::unregister()
}
