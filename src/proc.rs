use std::process::{Command, Stdio};

/// Fire-and-forget: spawn `cmd args` with stdio nulled and ignore every
/// outcome. For idempotent reload/teardown steps where a failure is not
/// actionable.
pub fn run_optional(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
