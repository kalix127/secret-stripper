pub mod allowlist;
pub mod categories;
pub mod chrome;
pub mod custom_patterns;
pub mod detection_menu;
pub mod hotkey_capture;
pub mod language_select;
pub mod manage_install;
pub mod menu;
pub mod presets;
pub mod redact_style;
pub mod star;
pub mod theme;
pub mod widgets;

use crossterm::event::{self, Event};
use std::time::Duration;

/// Drain any key/mouse/resize events already buffered by crossterm.
/// Call after returning from a submenu so a buffered key release does not
/// leak into the parent's next event::read() and trigger an unintended action.
pub fn drain_pending_events() -> std::io::Result<()> {
    while event::poll(Duration::from_millis(0))? {
        let _: Event = event::read()?;
    }
    Ok(())
}
