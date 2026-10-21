pub const REPO_URL: &str = "https://github.com/kalix127/secret-stripper";

/// Open a URL in the user's default browser without pulling in an extra
/// crate (the release binary is size-optimized). Spawned detached; a failure
/// is reported to the caller rather than panicking.
pub fn open_url(url: &str) -> std::io::Result<()> {
    use std::process::{Command, Stdio};

    Command::new("xdg-open")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
}
