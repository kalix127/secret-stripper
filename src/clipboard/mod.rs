pub struct ClipboardMonitor {
    clipboard: arboard::Clipboard,
}

impl ClipboardMonitor {
    pub fn new(_interval_ms: u64) -> Result<Self, arboard::Error> {
        let clipboard = arboard::Clipboard::new()?;
        Ok(Self { clipboard })
    }

    pub fn read_text(&mut self) -> Option<String> {
        self.clipboard.get_text().ok()
    }

    /// Read the X11/Wayland PRIMARY selection (whatever the user currently has highlighted).
    /// Linux only; returns None on other OSes. The PRIMARY selection is populated automatically
    /// by most desktop apps when text is highlighted with the mouse - no Ctrl+C required.
    pub fn read_primary(&mut self) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            use arboard::GetExtLinux;
            self.clipboard
                .get()
                .clipboard(arboard::LinuxClipboardKind::Primary)
                .text()
                .ok()
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    pub fn replace_text(&mut self, text: &str) -> anyhow::Result<()> {
        self.clipboard.set_text(text.to_string())?;
        Ok(())
    }
}
