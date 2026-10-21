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
    let content = parse_payload(input)?;

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

/// Split `<header>\n<body>`; the body is raw bytes and may hold newlines.
fn parse_payload(mut input: Vec<u8>) -> anyhow::Result<Content> {
    let split = input
        .iter()
        .position(|&b| b == b'\n')
        .context("missing payload header")?;
    let mimes = match &input[..split] {
        b"text" => TEXT_MIMES,
        b"png" => PNG_MIMES,
        other => anyhow::bail!("unknown payload header: {}", String::from_utf8_lossy(other)),
    };
    Ok(Content {
        mimes,
        data: input.split_off(split + 1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_payload_keeps_newlines_in_the_body() {
        let c = parse_payload(b"text\nline 1\nline 2\n".to_vec()).unwrap();
        assert_eq!(c.mimes, TEXT_MIMES);
        assert_eq!(c.data, b"line 1\nline 2\n");
    }

    #[test]
    fn png_payload_keeps_binary_bytes() {
        let mut input = b"png\n".to_vec();
        input.extend_from_slice(&[0x89, b'P', b'N', b'G', b'\n', 0]);
        let c = parse_payload(input).unwrap();
        assert_eq!(c.mimes, PNG_MIMES);
        assert_eq!(c.data, [0x89, b'P', b'N', b'G', b'\n', 0]);
    }

    #[test]
    fn empty_body_is_allowed() {
        assert!(parse_payload(b"text\n".to_vec()).unwrap().data.is_empty());
    }

    #[test]
    fn missing_or_unknown_header_is_rejected() {
        assert!(parse_payload(b"text".to_vec()).is_err());
        assert!(parse_payload(Vec::new()).is_err());
        assert!(parse_payload(b"html\n<b>x</b>".to_vec()).is_err());
    }
}
