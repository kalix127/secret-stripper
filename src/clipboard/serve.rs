use anyhow::Context;
use std::io::{Read, Write};

pub(super) const READY: &str = "ready";
pub(super) const READ: &str = "read";

pub(super) const TEXT_MIMES: &[&str] = &[
    "text/plain;charset=utf-8",
    "UTF8_STRING",
    "text/plain",
    "STRING",
    "TEXT",
];
pub(super) const PNG_MIMES: &[&str] = &["image/png"];

// KDE's Klipper and similar managers skip offers carrying this hint instead
// of fetching them, which keeps their reads from looking like a paste.
pub(super) const PASSWORD_HINT_MIME: &str = "x-kde-passwordManagerHint";
pub(super) const PASSWORD_HINT_VALUE: &[u8] = b"secret";

pub(super) struct Content {
    pub mimes: &'static [&'static str],
    pub data: Vec<u8>,
}

/// Reports ownership and data reads to the parent `paste` process. Write
/// errors are ignored: once the parent exits nobody is listening, but the
/// child keeps serving the clipboard.
pub(super) fn report(event: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{event}").and_then(|()| out.flush());
}

/// Entry point of the `serve-clipboard` child: read `<header>\n<body>` from
/// stdin, own the clipboard, and return once another program replaces it.
pub fn serve_from_stdin() -> anyhow::Result<()> {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    let split = input
        .iter()
        .position(|&b| b == b'\n')
        .context("missing payload header")?;
    let mimes = match &input[..split] {
        b"text" => TEXT_MIMES,
        b"png" => PNG_MIMES,
        other => anyhow::bail!("unknown payload header: {}", String::from_utf8_lossy(other)),
    };
    let content = Content {
        mimes,
        data: input.split_off(split + 1),
    };

    // Compositors without a data-control protocol (GNOME) bridge the X11
    // clipboard to Wayland apps, so X11 is the fallback there.
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        match super::wayland::connect() {
            Ok(owner) => return owner.serve(&content),
            Err(e) => log::debug!("wayland data-control unavailable, using X11: {e}"),
        }
    }
    super::x11::serve(&content)
}
