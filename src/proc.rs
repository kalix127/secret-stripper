use anyhow::{anyhow, Result};
use std::process::{Command, Stdio};

/// Run `cmd args` to completion with all stdio nulled. Errors if the process
/// cannot be spawned or exits non-zero; `fail` is the human context.
// Only the Windows scheduler path needs the checked variant; other targets
// use `run_optional`, so this is dead on non-Windows builds.
#[allow(dead_code)]
pub fn run(cmd: &str, args: &[&str], fail: &str) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| anyhow!("{fail}: could not run {cmd}: {e}"))?;
    if !status.success() {
        return Err(anyhow!("{fail}: {cmd} exited with {status}"));
    }
    Ok(())
}

/// Fire-and-forget: spawn `cmd args` with stdio nulled and ignore every
/// outcome. For idempotent reload/teardown steps where a failure is not
/// actionable (the prior `let _ = Command::new(..).status()` idiom).
// Unused on the bare fallback target (no shortcut/updater backend).
#[allow(dead_code)]
pub fn run_optional(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
