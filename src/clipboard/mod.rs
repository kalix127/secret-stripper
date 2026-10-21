mod serve;
mod wayland;
mod x11;

use anyhow::Context;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

pub use serve::serve_from_stdin;

pub struct ClipboardReader {
    clipboard: arboard::Clipboard,
}

/// What `paste` reads from the clipboard; a trait so tests can fake it.
pub trait ClipboardSource {
    fn read_text(&mut self) -> Option<String>;
    /// A bitmap as (width, height, RGBA8 bytes). None when the clipboard holds
    /// no image.
    fn read_image(&mut self) -> Option<(usize, usize, Vec<u8>)>;
}

impl ClipboardReader {
    pub fn new() -> Result<Self, arboard::Error> {
        Ok(Self {
            clipboard: arboard::Clipboard::new()?,
        })
    }
}

impl ClipboardSource for ClipboardReader {
    fn read_text(&mut self) -> Option<String> {
        self.clipboard
            .get_text()
            .map_err(|e| log::debug!("clipboard text unavailable: {e}"))
            .ok()
    }

    fn read_image(&mut self) -> Option<(usize, usize, Vec<u8>)> {
        let img = self
            .clipboard
            .get_image()
            .map_err(|e| log::debug!("clipboard image unavailable: {e}"))
            .ok()?;
        Some((img.width, img.height, img.bytes.into_owned()))
    }
}

pub enum Payload {
    Text(zeroize::Zeroizing<String>),
    Png(Vec<u8>),
}

impl Payload {
    pub fn png_from_rgba(width: usize, height: usize, rgba: Vec<u8>) -> anyhow::Result<Self> {
        let img = image::RgbaImage::from_raw(width as u32, height as u32, rgba)
            .context("clipboard image has inconsistent dimensions")?;
        let mut png = std::io::Cursor::new(Vec::new());
        img.write_to(&mut png, image::ImageFormat::Png)
            .context("encode clipboard image as png")?;
        Ok(Payload::Png(png.into_inner()))
    }

    fn header(&self) -> &'static str {
        match self {
            Payload::Text(_) => "text",
            Payload::Png(_) => "png",
        }
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Payload::Text(t) => t.as_bytes(),
            Payload::Png(b) => b,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ServerEvent {
    Ready,
    Read,
}

/// A detached `serve-clipboard` child that owns the clipboard. Clipboard
/// contents vanish when the owning process exits, so the child keeps serving
/// them after `paste` returns, until another program takes the clipboard.
pub struct Server {
    child: Child,
    events: Receiver<ServerEvent>,
    ready_at: Instant,
}

impl Server {
    pub fn start(payload: &Payload) -> anyhow::Result<Self> {
        use std::os::unix::process::CommandExt;

        let exe = std::env::current_exe().context("locate own binary")?;
        let mut child = Command::new(exe)
            .arg("serve-clipboard")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .context("spawn clipboard server")?;

        let mut stdin = child.stdin.take().context("clipboard server stdin")?;
        let sent = stdin
            .write_all(payload.header().as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.write_all(payload.bytes()));
        drop(stdin);
        if let Err(e) = sent {
            let _ = child.kill();
            return Err(e).context("send payload to clipboard server");
        }

        let stdout = child.stdout.take().context("clipboard server stdout")?;
        let (tx, events) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let event = match line.as_deref() {
                    Ok(serve::READY) => ServerEvent::Ready,
                    Ok(serve::READ) => ServerEvent::Read,
                    _ => break,
                };
                if tx.send(event).is_err() {
                    break;
                }
            }
        });

        let mut server = Self {
            child,
            events,
            ready_at: Instant::now(),
        };
        server.await_ready()?;
        server.ready_at = Instant::now();
        Ok(server)
    }

    fn await_ready(&mut self) -> anyhow::Result<()> {
        match self.events.recv_timeout(Duration::from_secs(3)) {
            Ok(ServerEvent::Ready) => Ok(()),
            Ok(ServerEvent::Read) => anyhow::bail!("clipboard server read before ready"),
            Err(_) => {
                let _ = self.child.kill();
                match self.child.wait() {
                    Ok(status) if !status.success() => {
                        anyhow::bail!("clipboard server exited with {status}")
                    }
                    _ => anyhow::bail!("clipboard server did not take ownership within 3s"),
                }
            }
        }
    }

    /// Forget the reads of clipboard managers, which fetch every new selection
    /// as soon as it appears. Waits until `grace` after taking ownership so
    /// a manager's read cannot be mistaken for the paste.
    pub fn discard_reads(&self, grace: Duration) {
        discard_events(&self.events, self.ready_at, grace);
    }

    /// Wait for an app to read the clipboard, then for reads to go quiet so a
    /// client fetching several formats is not cut off mid-paste.
    pub fn await_read(&self, timeout: Duration, quiet: Duration) -> bool {
        await_read_event(&self.events, timeout, quiet)
    }
}

fn discard_events(events: &Receiver<ServerEvent>, ready_at: Instant, grace: Duration) {
    std::thread::sleep(grace.saturating_sub(ready_at.elapsed()));
    while events.try_recv().is_ok() {}
}

fn await_read_event(events: &Receiver<ServerEvent>, timeout: Duration, quiet: Duration) -> bool {
    match events.recv_timeout(timeout) {
        Ok(ServerEvent::Read) => {}
        _ => return false,
    }
    let mut last = Instant::now();
    loop {
        let wait = quiet.saturating_sub(last.elapsed());
        match events.recv_timeout(wait) {
            Ok(_) => last = Instant::now(),
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => return true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LONG: Duration = Duration::from_secs(5);

    #[test]
    fn no_read_before_timeout_is_false() {
        let (_tx, rx) = mpsc::channel();
        assert!(!await_read_event(&rx, Duration::from_millis(20), LONG));
    }

    #[test]
    fn closed_server_without_a_read_is_false() {
        let (tx, rx) = mpsc::channel::<ServerEvent>();
        drop(tx);
        assert!(!await_read_event(&rx, LONG, LONG));
    }

    #[test]
    fn read_then_exit_is_true() {
        let (tx, rx) = mpsc::channel();
        tx.send(ServerEvent::Read).unwrap();
        drop(tx);
        assert!(await_read_event(&rx, LONG, LONG));
    }

    #[test]
    fn waits_for_reads_to_go_quiet() {
        let (tx, rx) = mpsc::channel();
        let quiet = Duration::from_millis(150);
        let sender = std::thread::spawn(move || {
            for _ in 0..3 {
                tx.send(ServerEvent::Read).unwrap();
                std::thread::sleep(Duration::from_millis(50));
            }
            std::thread::sleep(LONG);
        });
        let start = Instant::now();
        assert!(await_read_event(&rx, LONG, quiet));
        // The last read lands at ~100ms, so quiet ends no earlier than ~250ms.
        assert!(start.elapsed() >= Duration::from_millis(240));
        assert!(start.elapsed() < LONG);
        drop(sender);
    }

    #[test]
    fn discard_drops_reads_from_the_grace_period() {
        let (tx, rx) = mpsc::channel();
        tx.send(ServerEvent::Read).unwrap();
        tx.send(ServerEvent::Read).unwrap();
        let start = Instant::now();
        discard_events(&rx, start, Duration::from_millis(50));
        assert!(start.elapsed() >= Duration::from_millis(50));
        assert!(rx.try_recv().is_err());
    }
}
