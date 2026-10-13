mod keys;
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

enum Plan {
    AsIs { scanned_clean: bool },
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
    },
}

impl Input {
    fn open(keys: &[&PasteKeys]) -> anyhow::Result<Self> {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            Ok(Input::Uinput {
                keyboard: uinput::UinputKeyboard::create(keys)?,
                created: Instant::now(),
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
            Input::Uinput { created, .. } => {
                std::thread::sleep(UINPUT_SETTLE.saturating_sub(created.elapsed()));
                Ok(())
            }
        }
    }

    fn send(&self, keys: &PasteKeys, terminal_keys: &PasteKeys) -> anyhow::Result<()> {
        match self {
            Input::X11(x) if x.focused_is_terminal() => x.send(terminal_keys),
            Input::X11(x) => x.send(keys),
            Input::Uinput { keyboard, .. } => keyboard.send(keys),
        }
    }
}

pub fn run() -> anyhow::Result<()> {
    let config = Config::load();
    let lang = config.lang;
    if !config.onboarding_done {
        eprintln!("{}", lang::Lang::active().cli_run_init_first());
        return Ok(());
    }

    let _lock = match lock_file().map(|f| (f.try_lock(), f)) {
        Ok((Ok(()), f)) => Some(f),
        Ok((Err(std::fs::TryLockError::WouldBlock), _)) => return Ok(()),
        Ok((Err(std::fs::TryLockError::Error(e)), _)) | Err(e) => {
            log::warn!("paste lock unavailable: {e}");
            None
        }
    };

    let keys = PasteKeys::parse(&config.paste_keys)?;
    let terminal_keys = PasteKeys::parse(&config.terminal_paste_keys)?;

    // Opened before scanning so the uinput settle time overlaps redaction.
    let input = match Input::open(&[&keys, &terminal_keys]) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("{}", lang.cli_input_unavailable(&format!("{e:#}")));
            return Ok(());
        }
    };

    let plan = match ClipboardReader::new() {
        Ok(mut reader) => plan(&mut reader, &config),
        Err(e) => {
            eprintln!("{}", lang.cli_clipboard_access_failed(&e.to_string()));
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
            eprintln!("{msg}");
        }
        Plan::AsIs { scanned_clean } => {
            if scanned_clean {
                eprintln!("{}", lang.cli_no_secrets());
            }
            if let Err(e) = input
                .wait_until_ready()
                .and_then(|()| input.send(&keys, &terminal_keys))
            {
                eprintln!("{}", lang.cli_input_unavailable(&format!("{e:#}")));
            }
        }
        Plan::Redacted {
            redacted,
            original,
            count,
        } => {
            if let Err(e) = paste_redacted(&input, &keys, &terminal_keys, &redacted, &original, lang)
            {
                eprintln!("{}", lang.cli_paste_failed(&format!("{e:#}")));
                return Ok(());
            }
            eprintln!("{}", lang.cli_redacted(count));
            stats::append(count as u64);
            notify::redacted(count, &config);
        }
    }
    Ok(())
}

/// Swap the redacted payload in, paste it, and restore the original only
/// after the target app has read it. Restoring earlier would let a slow app
/// paste the unredacted original, so without an observed read the redacted
/// copy stays on the clipboard.
fn paste_redacted(
    input: &Input,
    keys: &PasteKeys,
    terminal_keys: &PasteKeys,
    redacted: &Payload,
    original: &Payload,
    lang: lang::Lang,
) -> anyhow::Result<()> {
    let server = Server::start(redacted)?;
    if let Err(e) = input.wait_until_ready() {
        Server::start(original)?;
        return Err(e);
    }
    server.discard_reads();
    input.send(keys, terminal_keys)?;

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
        ImageResult::Redacted { bytes: out, w, h, count } => {
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

fn lock_file() -> std::io::Result<File> {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(config::ensure_base_dir);
    File::create(dir.join("secret-stripper-paste.lock"))
}
