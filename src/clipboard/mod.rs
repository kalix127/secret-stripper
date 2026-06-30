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

    /// Read a bitmap from the clipboard as (width, height, RGBA8 bytes). None when
    /// the clipboard holds no image.
    pub fn read_image(&mut self) -> Option<(usize, usize, Vec<u8>)> {
        let img = self.clipboard.get_image().ok()?;
        Some((img.width, img.height, img.bytes.into_owned()))
    }

    #[cfg(target_os = "linux")]
    pub fn replace_image(
        &mut self,
        width: usize,
        height: usize,
        bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        self.clipboard.set_image(arboard::ImageData {
            width,
            height,
            bytes: std::borrow::Cow::Owned(bytes),
        })?;
        Ok(())
    }
}
