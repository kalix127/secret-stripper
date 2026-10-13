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
    /// The PRIMARY selection is populated automatically by most desktop apps when text is
    /// highlighted with the mouse - no Ctrl+C required.
    pub fn read_primary(&mut self) -> Option<String> {
        use arboard::GetExtLinux;
        self.clipboard
            .get()
            .clipboard(arboard::LinuxClipboardKind::Primary)
            .text()
            .ok()
    }

    pub fn replace_text(&mut self, text: &str) -> anyhow::Result<()> {
        let mut child = spawn_server("text", text.as_bytes())?;
        let clipboard = &mut self.clipboard;
        await_ownership(&mut child, || {
            clipboard.get_text().unwrap_or_default() == text
        })
    }

    /// Read a bitmap from the clipboard as (width, height, RGBA8 bytes). None when
    /// the clipboard holds no image.
    pub fn read_image(&mut self) -> Option<(usize, usize, Vec<u8>)> {
        let img = self.clipboard.get_image().ok()?;
        Some((img.width, img.height, img.bytes.into_owned()))
    }

    pub fn replace_image(
        &mut self,
        width: usize,
        height: usize,
        bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        let mut child = spawn_server(&format!("image {width} {height}"), &bytes)?;
        let clipboard = &mut self.clipboard;
        await_ownership(&mut child, || {
            clipboard
                .get_image()
                .is_ok_and(|img| img.width == width && img.height == height)
        })
    }
}

// Clipboard contents vanish when the owning process exits (arboard serves
// Wayland from a thread), so a detached child keeps serving them.
fn spawn_server(header: &str, body: &[u8]) -> anyhow::Result<std::process::Child> {
    use anyhow::Context;
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let exe = std::env::current_exe().context("locate own binary")?;
    let mut child = Command::new(exe)
        .arg("serve-clipboard")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .context("spawn clipboard server")?;
    let mut stdin = child.stdin.take().context("clipboard server stdin")?;
    let sent = stdin
        .write_all(header.as_bytes())
        .and_then(|()| stdin.write_all(b"\n"))
        .and_then(|()| stdin.write_all(body));
    drop(stdin);
    if let Err(e) = sent {
        let _ = child.kill();
        return Err(e).context("send payload to clipboard server");
    }
    Ok(child)
}

fn await_ownership(
    child: &mut std::process::Child,
    mut served: impl FnMut() -> bool,
) -> anyhow::Result<()> {
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait()? {
            anyhow::ensure!(status.success(), "clipboard server exited with {status}");
            return Ok(());
        }
        if served() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            anyhow::bail!("clipboard server did not take ownership within 2s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Entry point of the `serve-clipboard` child: read `<header>\n<body>` from
/// stdin, own the clipboard, and return once another program replaces it.
pub fn serve_from_stdin() -> anyhow::Result<()> {
    use anyhow::Context;
    use arboard::SetExtLinux;
    use std::io::Read;

    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    let split = input
        .iter()
        .position(|&b| b == b'\n')
        .context("missing payload header")?;
    let header = std::str::from_utf8(&input[..split])?;
    let body = &input[split + 1..];

    let mut clipboard = arboard::Clipboard::new()?;
    let mut fields = header.split(' ');
    match fields.next() {
        Some("text") => {
            let text = String::from_utf8(body.to_vec())?;
            clipboard.set().wait().text(text)?;
        }
        Some("image") => {
            let mut dim = || -> anyhow::Result<usize> {
                Ok(fields.next().context("missing image size")?.parse()?)
            };
            let (width, height) = (dim()?, dim()?);
            clipboard.set().wait().image(arboard::ImageData {
                width,
                height,
                bytes: std::borrow::Cow::Borrowed(body),
            })?;
        }
        _ => anyhow::bail!("unknown payload header: {header}"),
    }
    Ok(())
}
