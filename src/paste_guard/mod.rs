use std::io::{Read, Write};
use std::sync::Arc;
use std::thread;

use anyhow::Context;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

use crate::config::Config;
use crate::detector::Detector;
use crate::redact_cli::redact_with;

mod parser;
pub use parser::PasteParser;

/// Limit on a single paste payload before we give up on in-flight redaction.
/// Above this the parser falls back to passthrough so we never OOM on a
/// pathological paste. 1 MiB matches the cap in `run_trigger`.
pub const MAX_PASTE_BYTES: usize = 1024 * 1024;

pub const START_SEQ: &[u8] = b"\x1b[200~";
pub const END_SEQ: &[u8] = b"\x1b[201~";

const ENV_NO_OS: &str = "SECRET_STRIPPER_NO_OS_SIDE_EFFECTS";

/// Spawn `argv` in a PTY, intercept bracketed-paste payloads on the way in,
/// redact them, and forward. Returns the child's exit code.
///
/// Long-lived for the lifetime of the child - this is the second carve-out
/// from the one-shot model documented in CLAUDE.md (the first is the daily
/// update-check scheduler). Holds no global state, no PID file.
pub fn run(argv: &[String], cfg: &Config) -> anyhow::Result<i32> {
    if argv.is_empty() {
        let lang = cfg.lang;
        eprintln!("{}", lang.pg_no_child());
        return Ok(2);
    }
    // Allow tests / scripts to verify wiring without touching the real PTY.
    if std::env::var_os(ENV_NO_OS).is_some() {
        return Ok(0);
    }

    let detector = Arc::new(Detector::from_config(cfg));
    let cfg = Arc::new(cfg.clone());

    let pty_system = native_pty_system();
    let (rows, cols) = terminal_size().unwrap_or((24, 80));
    let pair = pty_system
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .context("openpty failed")?;

    let mut cmd = CommandBuilder::new(&argv[0]);
    for a in &argv[1..] {
        cmd.arg(a);
    }
    if let Ok(cwd) = std::env::current_dir() {
        cmd.cwd(cwd);
    }

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .with_context(|| format!("failed to spawn '{}'", argv[0]))?;
    drop(pair.slave);

    // RAII: raw mode + force bracketed-paste on the parent terminal for the
    // duration of the wrapped session. Forcing the mode on means the wrapper
    // works for ANY child, not just AI TUIs that enable bracketed paste
    // themselves (vim, claude, codex). Children that re-enable it
    // independently are unaffected - the request is idempotent. Restored
    // on Drop so the user's shell prompt comes back the way they left it.
    let _guard = TerminalGuard::enter();

    let mut pty_reader = pair.master.try_clone_reader().context("clone reader")?;
    let mut pty_writer = pair.master.take_writer().context("take_writer (master)")?;
    // Drop the master itself; the cloned reader and the moved writer keep
    // their own references. Holding `master` here would keep an extra handle
    // alive after the input pump finishes and stop the child from ever
    // seeing EOF on its stdin.
    drop(pair.master);

    // Child -> stdout pump.
    let stdout_pump = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        let stdout = std::io::stdout();
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let mut out = stdout.lock();
                    if out.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = out.flush();
                }
                Err(_) => break,
            }
        }
    });

    // Stdin -> child pump (paste parser). Owns the PTY master writer so it
    // is dropped on stdin EOF, which closes the master and signals EOF to
    // the child. If we kept a clone in the main thread, `child.wait()`
    // would deadlock against a child that exits only on stdin close (cat,
    // grep, etc.).
    //
    // Feedback policy: never write to the parent's stderr while the wrapped
    // child is rendering a TUI - it punches through the frame (see
    // CLAUDE.md::tui-no-stdout). Instead, fire a desktop notification per
    // redaction event (gated on `!config.silent` to match the trigger
    // flow). The visible proof is the AI TUI rendering `[REDACTED]` in
    // place of the secret in its own input field.
    let detector_for_parser = Arc::clone(&detector);
    let cfg_for_parser = Arc::clone(&cfg);
    let stdin_pump = thread::spawn(move || {
        let mut parser = PasteParser::new();
        let mut buf = [0u8; 8192];
        let stdin = std::io::stdin();
        loop {
            let n = match stdin.lock().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let mut redacted_total: usize = 0;
            let mut redactor = |payload: &[u8]| match std::str::from_utf8(payload) {
                Ok(s) => {
                    let (red, names) = redact_with(&detector_for_parser, &cfg_for_parser, s);
                    redacted_total += names.len();
                    red.into_bytes()
                }
                Err(_) => payload.to_vec(),
            };
            let out_bytes = parser.feed(&buf[..n], &mut redactor);
            // Overflow is rare and unactionable mid-session; drop it on the
            // floor rather than corrupt the TUI frame. The fact that the
            // paste was not redacted is observable in the child itself.
            let _ = parser.take_overflow();
            if redacted_total > 0 && !cfg_for_parser.silent {
                crate::notify::redacted_notification(
                    redacted_total,
                    cfg_for_parser.notification_timeout_secs,
                    cfg_for_parser.lang,
                );
            }
            if !out_bytes.is_empty() && pty_writer.write_all(&out_bytes).is_err() {
                break;
            }
            let _ = pty_writer.flush();
        }
        // Explicit drop: makes the EOF -> child semantics easy to spot.
        drop(pty_writer);
    });

    let status = child.wait().context("child wait")?;
    let _ = stdout_pump.join();
    // The stdin pump may still be parked in a blocking stdin read when an
    // interactive child exits on its own; the process exit at the call site
    // tears that thread down.
    let _ = stdin_pump;
    let code = status.exit_code() as i32;
    drop(_guard);
    Ok(code)
}

fn terminal_size() -> Option<(u16, u16)> {
    crossterm::terminal::size().ok().map(|(c, r)| (r, c))
}

struct TerminalGuard;

const ENABLE_BRACKETED_PASTE: &[u8] = b"\x1b[?2004h";
const DISABLE_BRACKETED_PASTE: &[u8] = b"\x1b[?2004l";

impl TerminalGuard {
    fn enter() -> Self {
        let _ = crossterm::terminal::enable_raw_mode();
        // Force bracketed-paste mode on the parent terminal so the wrapper
        // sees framed pastes regardless of whether the child requests them.
        // Best effort: a terminal that doesn't understand the sequence will
        // silently ignore it, which is the same as the wrapper not being
        // there.
        let mut out = std::io::stdout();
        let _ = out.write_all(ENABLE_BRACKETED_PASTE);
        let _ = out.flush();
        Self
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let mut out = std::io::stdout();
        let _ = out.write_all(DISABLE_BRACKETED_PASTE);
        let _ = out.flush();
        let _ = crossterm::terminal::disable_raw_mode();
    }
}
