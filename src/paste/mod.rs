pub mod access;
mod keys;
mod reentry;
mod uinput;
mod x11;

use keys::PasteKeys;

use std::fs::File;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::clipboard::{ClipboardReader, Payload, Server};
use crate::config::{self, Config, RedactStyle};
use crate::detector::{self, Detector};
use crate::{lang, notify, stats};

// A multi-MB clipboard runs every regex over the whole text and can stall the
// engine. Refuse rather than truncate: truncating could split a secret span.
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(3);
const READ_QUIET: Duration = Duration::from_millis(150);
const MODIFIER_TIMEOUT: Duration = Duration::from_secs(2);
const UINPUT_SETTLE: Duration = Duration::from_millis(250);
// Without re-entry detection a held chord cannot be seen, so give the user
// time to release it.
const HELD_CHORD_DELAY: Duration = Duration::from_millis(600);
const REENTRY_WINDOW: Duration = Duration::from_millis(500);
const REENTRY_RETRY: Duration = Duration::from_millis(100);
const REENTRY_CAP: Duration = Duration::from_secs(2);

enum Plan {
    AsIs {
        scanned_clean: bool,
    },
    Redacted {
        redacted: Payload,
        original: Payload,
        count: usize,
    },
    Blocked(Blocked),
}

#[derive(Clone, Copy)]
enum Blocked {
    TooLarge(usize),
    ImageScanFailed,
    ImageUnmappable,
    NoLocation,
}

enum Input {
    X11(Box<x11::X11Input>),
    Uinput {
        keyboard: uinput::UinputKeyboard,
        created: Instant,
        settle: Duration,
    },
}

impl Input {
    fn open(keys: &[&PasteKeys], reentrant: bool) -> anyhow::Result<Self> {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            Ok(Input::Uinput {
                keyboard: uinput::UinputKeyboard::create(keys)?,
                created: Instant::now(),
                settle: if reentrant {
                    UINPUT_SETTLE
                } else {
                    HELD_CHORD_DELAY
                },
            })
        } else {
            Ok(Input::X11(Box::new(x11::X11Input::connect()?)))
        }
    }

    /// Block until the synthetic keys will not merge with the chord the user
    /// pressed. X11 reads the real key state; a uinput device also needs time
    /// for the compositor to pick it up.
    fn wait_until_ready(&self) -> anyhow::Result<()> {
        match self {
            Input::X11(x) => x.wait_modifiers_released(MODIFIER_TIMEOUT),
            Input::Uinput {
                created, settle, ..
            } => {
                std::thread::sleep(settle.saturating_sub(created.elapsed()));
                Ok(())
            }
        }
    }

    /// `keys` are already the terminal keys for `paste --terminal`; X11 can
    /// also spot a terminal from the focused window.
    fn send(&self, keys: &PasteKeys, terminal_keys: &PasteKeys) -> anyhow::Result<()> {
        match self {
            Input::X11(x) if x.focused_is_terminal() => x.send(terminal_keys),
            Input::X11(x) => x.send(keys),
            Input::Uinput { keyboard, .. } => keyboard.send(keys),
        }
    }
}

/// Whether a held `chord` plus the paste keys fires the chord again, which
/// the second `paste` it launches can report.
pub fn chord_reenters(chord: &str, paste_keys: &str) -> bool {
    match (PasteKeys::parse(chord), PasteKeys::parse(paste_keys)) {
        (Ok(chord), Ok(paste)) => chord.key == paste.key,
        _ => false,
    }
}

pub fn run(terminal: bool) -> anyhow::Result<()> {
    // Taken first so a re-entrant launch reports itself as fast as possible.
    let lock = match lock_file().map(|f| (f.try_lock(), f)) {
        Ok((Ok(()), f)) => Some(f),
        Ok((Err(std::fs::TryLockError::WouldBlock), _)) => {
            reentry::notify();
            return Ok(());
        }
        Ok((Err(std::fs::TryLockError::Error(e)), _)) | Err(e) => {
            log::warn!("paste lock unavailable: {e}");
            None
        }
    };

    let config = Config::load();
    let lang = config.lang;
    if !config.onboarding_done {
        not_pasted(&config, lang::Lang::active().cli_run_init_first());
        return Ok(());
    }

    let (keys, terminal_keys, reentrant) = match select_keys(&config, terminal) {
        Ok(k) => k,
        Err(e) => {
            not_pasted(&config, &format!("{e:#}"));
            return Ok(());
        }
    };

    // Opened before scanning so the uinput settle time overlaps redaction.
    let input = match Input::open(&[&keys, &terminal_keys], reentrant) {
        Ok(i) => i,
        Err(e) => {
            not_pasted(&config, &lang.cli_input_unavailable(&format!("{e:#}")));
            return Ok(());
        }
    };
    // X11 waits for the real modifier release, so only uinput can re-enter.
    let listener = match &input {
        Input::Uinput { .. } if reentrant && lock.is_some() => reentry::Listener::bind()
            .map_err(|e| log::warn!("re-entry socket unavailable: {e}"))
            .ok(),
        _ => None,
    };
    let sender = Sender {
        input: &input,
        keys: &keys,
        terminal_keys: &terminal_keys,
        listener: listener.as_ref(),
    };

    let plan = match ClipboardReader::new() {
        Ok(mut reader) => plan(&mut reader, &config),
        Err(e) => {
            not_pasted(&config, &lang.cli_clipboard_access_failed(&e.to_string()));
            return Ok(());
        }
    };

    match plan {
        Plan::Blocked(reason) => {
            let msg = match reason {
                Blocked::TooLarge(len) => lang.cli_clipboard_too_large(len, MAX_INPUT_BYTES),
                Blocked::ImageScanFailed => lang.cli_image_scan_failed().to_string(),
                Blocked::ImageUnmappable => lang.cli_image_detected_unmappable().to_string(),
                Blocked::NoLocation => lang.cli_secret_without_location().to_string(),
            };
            not_pasted(&config, &msg);
        }
        Plan::AsIs { scanned_clean } => {
            if scanned_clean {
                eprintln!("{}", lang.cli_no_secrets());
            }
            if let Err(e) = input.wait_until_ready() {
                not_pasted(&config, &lang.cli_input_unavailable(&format!("{e:#}")));
            } else if let Err(e) = sender.paste(lang) {
                not_pasted(&config, &format!("{e:#}"));
            }
        }
        Plan::Redacted {
            redacted,
            original,
            count,
        } => {
            if let Err(e) = paste_redacted(&sender, &redacted, &original, lang) {
                not_pasted(&config, &lang.cli_paste_failed(&format!("{e:#}")));
                return Ok(());
            }
            eprintln!("{}", lang.cli_redacted(count));
            stats::append(count as u64);
            notify::redacted(count, &config);
        }
    }
    Ok(())
}

/// The paste keys, the terminal paste keys, and whether the held chord plus
/// the keys sent fires the chord again.
fn select_keys(config: &Config, terminal: bool) -> anyhow::Result<(PasteKeys, PasteKeys, bool)> {
    let terminal_keys = PasteKeys::parse(&config.terminal_paste_keys)?;
    if terminal {
        let chord = crate::hotkey::terminal_chord(&config.hotkey).unwrap_or_default();
        let reentrant = chord_reenters(&chord, &config.terminal_paste_keys);
        Ok((terminal_keys.clone(), terminal_keys, reentrant))
    } else {
        let keys = PasteKeys::parse(&config.paste_keys)?;
        let reentrant = chord_reenters(&config.hotkey, &config.paste_keys);
        Ok((keys, terminal_keys, reentrant))
    }
}

fn not_pasted(config: &Config, reason: &str) {
    eprintln!("{reason}");
    notify::not_pasted(config, reason);
}

struct Sender<'a> {
    input: &'a Input,
    keys: &'a PasteKeys,
    terminal_keys: &'a PasteKeys,
    listener: Option<&'a reentry::Listener>,
}

impl Sender<'_> {
    /// Send the paste keys. A chord still held on Wayland merges with them;
    /// when it ends in the same key the compositor fires it again instead of
    /// passing the paste on, and the `paste` it launches signals us. Resend
    /// until a send goes through without that signal.
    fn paste(&self, lang: lang::Lang) -> anyhow::Result<()> {
        let start = Instant::now();
        loop {
            if let Some(l) = self.listener {
                l.drain();
            }
            self.input.send(self.keys, self.terminal_keys)?;
            match self.listener {
                Some(l) if l.wait(REENTRY_WINDOW) => {}
                _ => return Ok(()),
            }
            if start.elapsed() >= REENTRY_CAP {
                anyhow::bail!("{}", lang.cli_chord_held());
            }
            std::thread::sleep(REENTRY_RETRY);
        }
    }
}

/// Swap the redacted payload in, paste it, and restore the original only
/// after the target app has read it. Restoring earlier would let a slow app
/// paste the unredacted original, so without an observed read the redacted
/// copy stays on the clipboard.
fn paste_redacted(
    sender: &Sender,
    redacted: &Payload,
    original: &Payload,
    lang: lang::Lang,
) -> anyhow::Result<()> {
    let server = Server::start(redacted)?;
    // Both failures mean no paste reached an app, so the original is safe to
    // put back.
    if let Err(e) = sender.input.wait_until_ready() {
        Server::start(original)?;
        return Err(e);
    }
    server.discard_reads();
    if let Err(e) = sender.paste(lang) {
        Server::start(original)?;
        return Err(e);
    }

    if server.await_read(READ_TIMEOUT, READ_QUIET) {
        if let Err(e) = Server::start(original) {
            log::warn!("restoring the original clipboard failed: {e:#}");
        }
    } else {
        eprintln!("{}", lang.cli_restore_skipped());
    }
    Ok(())
}

fn plan(reader: &mut ClipboardReader, config: &Config) -> Plan {
    let detector = Detector::from_config(config);

    // A clipboard image never goes through the text path: reading it as text
    // yields raw bytes the detector can mistake for secrets.
    if let Some((width, height, bytes)) = reader.read_image() {
        if !config.enable_image_scan {
            return Plan::AsIs {
                scanned_clean: false,
            };
        }
        return plan_image(&detector, width, height, bytes);
    }

    let Some(text) = reader.read_text().filter(|t| !t.is_empty()) else {
        return Plan::AsIs {
            scanned_clean: false,
        };
    };
    if text.len() > MAX_INPUT_BYTES {
        return Plan::Blocked(Blocked::TooLarge(text.len()));
    }
    // Best-effort zeroization for buffers we own. arboard hands us a String we
    // cannot zero from outside, so anything before this point may linger.
    plan_text(&detector, config, Zeroizing::new(text))
}

fn plan_image(detector: &Detector, width: usize, height: usize, bytes: Vec<u8>) -> Plan {
    use secret_stripper::image_scan::{self, ImageResult, TesseractOcr};

    match image_scan::redact_image(&bytes, width as u32, height as u32, &TesseractOcr, detector) {
        ImageResult::Unavailable => Plan::Blocked(Blocked::ImageScanFailed),
        ImageResult::NoSecrets => Plan::AsIs {
            scanned_clean: true,
        },
        ImageResult::DetectedUnmappable => Plan::Blocked(Blocked::ImageUnmappable),
        ImageResult::Redacted {
            bytes: out,
            w,
            h,
            count,
        } => {
            let encoded = Payload::png_from_rgba(w as usize, h as usize, out)
                .and_then(|r| Ok((r, Payload::png_from_rgba(width, height, bytes)?)));
            match encoded {
                Ok((redacted, original)) => Plan::Redacted {
                    redacted,
                    original,
                    count,
                },
                Err(e) => {
                    log::error!("{e:#}");
                    Plan::Blocked(Blocked::ImageScanFailed)
                }
            }
        }
    }
}

fn plan_text(detector: &Detector, config: &Config, text: Zeroizing<String>) -> Plan {
    let result = detector.scan(&text);
    if !result.has_secrets {
        return Plan::AsIs {
            scanned_clean: true,
        };
    }

    let entropy_tokens: Vec<&str> = result
        .high_entropy_tokens
        .iter()
        .map(|(t, _)| t.as_str())
        .collect();
    let mut deep_spans: Vec<(usize, usize, &'static str)> = result
        .deep_findings
        .iter()
        .filter_map(|f| f.span.map(|(s, e)| (s, e, f.finding_type)))
        .collect();
    deep_spans.extend(result.extra_spans.iter().copied());
    let mut redacted = Zeroizing::new(detector::redact::redact_with_spans(
        &text,
        &result.matched_spans,
        &entropy_tokens,
        &deep_spans,
        detector.allowlist(),
        config.redact_style,
        &config.redact_pattern,
    ));
    let count = result.matched_patterns.len()
        + result.deep_findings.len()
        + result.high_entropy_tokens.len();

    // Detection found something but the redactor produced an identical string.
    // For Marker/Typed/Drop that only happens when no span was located (a
    // deep-scan-only hit), so fail closed. Placeholder sample values can
    // legitimately equal the original (a fixed point), so for that style only
    // fail closed when there was genuinely no span to redact.
    let had_spans =
        !result.matched_spans.is_empty() || !entropy_tokens.is_empty() || !deep_spans.is_empty();
    let noop = *redacted == *text
        && !(matches!(config.redact_style, RedactStyle::Placeholder) && had_spans);
    let output = if noop {
        Zeroizing::new(match config.redact_style {
            RedactStyle::Marker => config.redact_pattern.clone(),
            RedactStyle::Typed => "[SECRET]".to_string(),
            RedactStyle::Drop => return Plan::Blocked(Blocked::NoLocation),
            RedactStyle::Placeholder => detector::placeholders::GENERIC.to_string(),
        })
    } else {
        Zeroizing::new(std::mem::take(&mut *redacted))
    };

    Plan::Redacted {
        redacted: Payload::Text(output),
        original: Payload::Text(text),
        count,
    }
}

fn runtime_dir() -> std::path::PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(config::ensure_base_dir)
}

fn lock_file() -> std::io::Result<File> {
    File::create(runtime_dir().join("secret-stripper-paste.lock"))
}

#[cfg(test)]
mod tests {
    use super::chord_reenters;

    #[test]
    fn chord_reenters_only_on_the_paste_key() {
        assert!(chord_reenters("Ctrl+Alt+V", "Ctrl+V"));
        assert!(chord_reenters("super+alt+v", "Ctrl+Shift+V"));
        assert!(!chord_reenters("Ctrl+Alt+P", "Ctrl+V"));
        assert!(!chord_reenters("Ctrl+Alt+F5", "Ctrl+V"));
        assert!(!chord_reenters("Ctrl+Alt+V", "Shift+Insert"));
    }
}
