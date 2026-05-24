use std::fs;

use anyhow::{anyhow, Context};
use semver::Version;
use serde_json::Value;

use crate::config::Config;
use crate::notify;

const DEFAULT_REPO: &str = "kalix127/secret-stripper";
const USER_AGENT: &str = "secret-stripper-upgrader";
const DOWNLOAD_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
const SUMS_LIMIT_BYTES: u64 = 64 * 1024;

// Override the release-source repo (useful for forks). Unset in normal use.
fn repo() -> String {
    std::env::var("SECRET_STRIPPER_REPO").unwrap_or_else(|_| DEFAULT_REPO.to_string())
}

fn agent() -> ureq::Agent {
    let cfg = ureq::Agent::config_builder().user_agent(USER_AGENT).build();
    ureq::Agent::new_with_config(cfg)
}

fn fetch_latest_release(agent: &ureq::Agent) -> anyhow::Result<Value> {
    let url = format!("https://api.github.com/repos/{}/releases/latest", repo());
    let body = agent
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .call()?
        .body_mut()
        .read_to_string()?;
    let release: Value = serde_json::from_str(&body)?;
    Ok(release)
}

fn current_asset_suffix() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("linux-x86_64"),
        ("linux", "aarch64") => Some("linux-aarch64"),
        ("macos", "x86_64") => Some("macos-x86_64"),
        ("macos", "aarch64") => Some("macos-aarch64"),
        ("windows", "x86_64") => Some("windows-x86_64.exe"),
        ("windows", "aarch64") => Some("windows-aarch64.exe"),
        _ => None,
    }
}

// Returns the API asset URL (https://api.github.com/.../releases/assets/<id>),
// not browser_download_url. Fetched with `Accept: application/octet-stream` it
// redirects to the CDN blob.
fn resolve_asset_url(release: &Value, asset_name: &str) -> Option<String> {
    release["assets"].as_array().and_then(|assets| {
        assets.iter().find_map(|a| {
            if a["name"].as_str() == Some(asset_name) {
                a["url"].as_str().map(|s| s.to_string())
            } else {
                None
            }
        })
    })
}

/// Fetch a small text asset (e.g. SHA256SUMS) from the same release that
/// `release` came from. Uses the API URL so it works for draft releases as
/// well as published ones.
fn fetch_release_asset_bytes(
    agent: &ureq::Agent,
    release: &Value,
    asset_name: &str,
    limit: u64,
) -> anyhow::Result<Vec<u8>> {
    let url = resolve_asset_url(release, asset_name)
        .ok_or_else(|| anyhow!("asset {asset_name} not present in release"))?;
    let bytes = agent
        .get(&url)
        .header("Accept", "application/octet-stream")
        .call()?
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()?;
    Ok(bytes)
}

/// Verify that `binary` matches the SHA256 line for `asset_name` in `sums`.
/// This protects against CDN/network tampering on the binary download but
/// NOT against a compromised GitHub release process (an attacker who can
/// publish a release can also publish a matching SHA256SUMS). Adding a
/// cryptographic signature on SHA256SUMS would close that gap if the
/// project ever needs it.
fn verify_release_artifact(binary: &[u8], sums: &[u8], asset_name: &str) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(binary);
    let actual_hex: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let sums_text = std::str::from_utf8(sums).map_err(|e| anyhow!("SHA256SUMS not utf-8: {e}"))?;
    let mut expected: Option<&str> = None;
    for line in sums_text.lines() {
        let mut it = line.split_whitespace();
        let hash = match it.next() {
            Some(h) => h,
            None => continue,
        };
        // Lines look like "<hash>  <name>" or "<hash>  *<name>".
        let name = match it.next() {
            Some(n) => n.trim_start_matches('*'),
            None => continue,
        };
        if name == asset_name {
            expected = Some(hash);
            break;
        }
    }
    let expected =
        expected.ok_or_else(|| anyhow!("no SHA256 entry for {asset_name} in SHA256SUMS"))?;
    if !expected.eq_ignore_ascii_case(&actual_hex) {
        return Err(anyhow!(
            "SHA256 mismatch for {asset_name}: expected {expected}, got {actual_hex}"
        ));
    }
    Ok(())
}

fn download_and_swap(
    agent: &ureq::Agent,
    url: &str,
    asset_name: &str,
    release: &Value,
    current_exe: &std::path::Path,
) -> anyhow::Result<()> {
    let bytes = agent
        .get(url)
        .header("Accept", "application/octet-stream")
        .call()?
        .body_mut()
        .with_config()
        .limit(DOWNLOAD_LIMIT_BYTES)
        .read_to_vec()?;

    // Verify the downloaded binary against the release's SHA256SUMS BEFORE
    // we touch the running binary. This catches CDN/network tampering; it
    // does NOT defend against a compromised release-publish path (the same
    // actor could publish a matching SHA256SUMS). See verify_release_artifact.
    let sums = fetch_release_asset_bytes(agent, release, "SHA256SUMS", SUMS_LIMIT_BYTES)
        .map_err(|e| anyhow!("fetching SHA256SUMS: {e}"))?;
    verify_release_artifact(&bytes, &sums, asset_name)?;

    // Stage in the same directory as the current binary. fs::rename is atomic
    // only within a single filesystem; staging in $TMPDIR (often tmpfs) and
    // renaming to /usr/local/bin or $HOME/.local/bin would fail with EXDEV.
    let tmp = current_exe.with_file_name("secret-stripper-upgrade");
    let old = current_exe.with_file_name("secret-stripper-old");

    // A previous swap on Windows can't unlink its own running image, so it
    // leaves the old binary behind for the next run to reap.
    let _ = fs::remove_file(&old);

    fs::write(&tmp, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, PermissionsExt::from_mode(0o755))?;
    }

    // Rename the running binary aside (required on Windows: a running .exe
    // can't be overwritten, only renamed), put the new one in place, then
    // delete the old. On Unix the unlink succeeds immediately; on Windows it
    // fails while the process holds the image and is reaped on the next run.
    fs::rename(current_exe, &old)?;
    fs::rename(&tmp, current_exe)?;
    let _ = fs::remove_file(&old);
    Ok(())
}

fn parse_version(tag: &str) -> Option<Version> {
    let trimmed = tag.trim_start_matches('v');
    Version::parse(trimmed).ok()
}

pub(crate) fn is_newer(latest_tag: &str) -> bool {
    let current = match Version::parse(env!("CARGO_PKG_VERSION")) {
        Ok(v) => v,
        Err(_) => return false,
    };
    match parse_version(latest_tag) {
        Some(latest) => latest > current,
        None => false,
    }
}

pub enum UpdateStatus {
    UpToDate,
    Available(String),
    Failed,
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Check-only: queries the latest release and reports whether a newer one
/// exists. No install, no stdout, no notification - for the in-TUI button.
pub fn check_status() -> UpdateStatus {
    let agent = agent();
    let release = match fetch_latest_release(&agent) {
        Ok(r) => r,
        Err(_) => return UpdateStatus::Failed,
    };
    match release["tag_name"].as_str() {
        Some(tag) if is_newer(tag) => UpdateStatus::Available(tag.to_string()),
        Some(_) => UpdateStatus::UpToDate,
        None => UpdateStatus::Failed,
    }
}

/// Manual, interactive upgrade. Prints to stdout/stderr; surfaces errors.
pub fn run_upgrade() -> anyhow::Result<()> {
    let lang = crate::lang::Lang::active();
    let current_exe = std::env::current_exe()?;
    println!("{}", lang.up_checking());

    let agent = agent();
    let release = fetch_latest_release(&agent).context("fetching latest release")?;

    let tag = release["tag_name"].as_str().unwrap_or("unknown");
    let body = release["body"].as_str().unwrap_or("");

    println!("{}", lang.up_latest(tag));
    if let Some(first_line) = body.lines().next() {
        println!("  {}", first_line);
    }
    println!(
        "{}",
        lang.up_current_binary(&current_exe.display().to_string())
    );

    if !is_newer(tag) {
        println!("{}", lang.up_up_to_date(current_version()));
        return Ok(());
    }

    let suffix = match current_asset_suffix() {
        Some(s) => s,
        None => {
            println!(
                "{}",
                lang.up_no_binary(std::env::consts::OS, std::env::consts::ARCH)
            );
            return Ok(());
        }
    };

    let asset_name = format!("secret-stripper-{}", suffix);
    let url = resolve_asset_url(&release, &asset_name)
        .ok_or_else(|| anyhow!("Asset '{}' not found in release {}", asset_name, tag))?;

    println!(
        "{}",
        lang.up_downloading(url.split('/').next_back().unwrap_or(&url))
    );

    download_and_swap(&agent, &url, &asset_name, &release, &current_exe)?;
    println!("{}", lang.up_updated(tag));
    Ok(())
}

/// Unattended update check. Silent on success-with-nothing-to-do AND on
/// network failure: a daily cron / timer must never spam the user. Notifies
/// via desktop notification when a newer release is found, and optionally
/// performs the swap when `auto_install` (CLI) or `config.auto_install` is
/// set.
pub fn run_upgrade_check(auto_install_flag: bool) -> anyhow::Result<()> {
    let config = Config::load();

    if !config.check_for_updates && !auto_install_flag {
        log::debug!("upgrade-check: disabled in config");
        return Ok(());
    }

    let agent = agent();
    let release = match fetch_latest_release(&agent) {
        Ok(r) => r,
        Err(e) => {
            log::debug!("upgrade-check: fetch failed: {}", e);
            return Ok(());
        }
    };

    let tag = match release["tag_name"].as_str() {
        Some(t) => t.to_string(),
        None => {
            log::debug!("upgrade-check: release missing tag_name");
            return Ok(());
        }
    };

    // Persist the observed latest tag so the TUI status panel can render
    // "Update available" without making its own network call. Saved on every
    // successful fetch (not only when newer) so a stale entry left over from
    // a previous version self-clears after the user upgrades.
    if config.last_seen_version.as_deref() != Some(tag.as_str()) {
        let mut updated = config.clone();
        updated.last_seen_version = Some(tag.clone());
        let _ = updated.save();
    }

    if let Some(skip) = config.skip_version.as_ref() {
        if skip == &tag {
            log::debug!("upgrade-check: skip_version matches {}", tag);
            return Ok(());
        }
    }

    if !is_newer(&tag) {
        log::debug!(
            "upgrade-check: {} is not newer than {}",
            tag,
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }

    let do_install = auto_install_flag || config.auto_install;

    // Update notifications are independent of `config.silent`: that flag only
    // mutes clipboard-redaction toasts, not "a new version is available".
    notify::update_available_notification(
        config.notification_timeout_secs,
        config.lang,
        env!("CARGO_PKG_VERSION"),
        &tag,
    );

    if !do_install {
        return Ok(());
    }

    let current_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            log::debug!("upgrade-check: current_exe failed: {}", e);
            return Ok(());
        }
    };

    let suffix = match current_asset_suffix() {
        Some(s) => s,
        None => {
            log::debug!(
                "upgrade-check: no asset for {}-{}",
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            return Ok(());
        }
    };
    let asset_name = format!("secret-stripper-{}", suffix);
    let url = match resolve_asset_url(&release, &asset_name) {
        Some(u) => u,
        None => {
            log::debug!("upgrade-check: asset {} missing in {}", asset_name, tag);
            return Ok(());
        }
    };

    match download_and_swap(&agent, &url, &asset_name, &release, &current_exe) {
        Ok(_) => {
            notify::update_installed_notification(
                config.notification_timeout_secs,
                config.lang,
                &tag,
            );
        }
        Err(e) => log::debug!("upgrade-check: install failed: {}", e),
    }

    Ok(())
}

#[cfg(target_os = "linux")]
const TIMER_NAME: &str = "secret-stripper-update-check.timer";
#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "secret-stripper-update-check.service";

#[cfg(any(target_os = "macos", target_os = "windows"))]
const BUNDLE_ID: &str = "com.kalix127.secret-stripper-update-check";

/// Tests and CI runners set `SECRET_STRIPPER_NO_OS_SIDE_EFFECTS` so an
/// `init`/`uninstall` cannot mutate the host's real scheduler.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn os_side_effects_disabled() -> bool {
    std::env::var_os("SECRET_STRIPPER_NO_OS_SIDE_EFFECTS").is_some()
}

#[cfg(target_os = "linux")]
pub fn install_update_check_timer() -> anyhow::Result<()> {
    use crate::proc;

    if os_side_effects_disabled() {
        return Ok(());
    }

    let lang = crate::lang::Lang::active();
    let exe = std::env::current_exe()?;
    let config_dir = dirs::config_dir().ok_or_else(|| anyhow!("no XDG config dir"))?;
    let unit_dir = config_dir.join("systemd").join("user");
    fs::create_dir_all(&unit_dir)?;

    let service = format!(
        r#"[Unit]
Description={}

[Service]
Type=oneshot
ExecStart={} upgrade-check
Nice=10
"#,
        lang.svc_update_desc(),
        exe.display()
    );

    // RandomizedDelaySec spreads the GitHub API load across users instead of
    // having every install fire at 00:00 UTC.
    let timer = format!(
        r#"[Unit]
Description={}

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1h
Unit=secret-stripper-update-check.service

[Install]
WantedBy=timers.target
"#,
        lang.svc_timer_desc()
    );

    fs::write(unit_dir.join(SERVICE_NAME), service)?;
    fs::write(unit_dir.join(TIMER_NAME), timer)?;

    proc::run_optional("systemctl", &["--user", "daemon-reload"]);
    proc::run_optional("systemctl", &["--user", "enable", "--now", TIMER_NAME]);

    Ok(())
}

#[cfg(target_os = "macos")]
pub fn install_update_check_timer() -> anyhow::Result<()> {
    use crate::proc;

    if os_side_effects_disabled() {
        return Ok(());
    }

    let exe = std::env::current_exe()?;
    let exe_str = exe
        .to_str()
        .ok_or_else(|| anyhow!("non-UTF8 binary path"))?;
    let home = dirs::home_dir().ok_or_else(|| anyhow!("no home dir"))?;
    let agents = home.join("Library").join("LaunchAgents");
    fs::create_dir_all(&agents)?;
    let plist_path = agents.join(format!("{}.plist", BUNDLE_ID));

    // launchd has no RandomizedDelaySec; a fixed off-peak hour is the closest
    // equivalent to the Linux timer's load spreading.
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>upgrade-check</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>11</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>RunAtLoad</key>
    <false/>
    <key>Nice</key>
    <integer>10</integer>
</dict>
</plist>
"#,
        label = BUNDLE_ID,
        exe = exe_str
    );
    fs::write(&plist_path, plist)?;

    let plist_arg = plist_path
        .to_str()
        .ok_or_else(|| anyhow!("non-UTF8 plist path"))?;
    // Unload first so a rewritten plist is picked up on re-install.
    proc::run_optional("launchctl", &["unload", "-w", plist_arg]);
    proc::run_optional("launchctl", &["load", "-w", plist_arg]);
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn install_update_check_timer() -> anyhow::Result<()> {
    use crate::proc;

    if os_side_effects_disabled() {
        return Ok(());
    }

    let exe = std::env::current_exe()?;
    let exe_str = exe
        .to_str()
        .ok_or_else(|| anyhow!("non-UTF8 binary path"))?;
    let tr = format!("\"{}\" upgrade-check", exe_str);
    // /F overwrites an existing task so re-install is idempotent.
    proc::run(
        "schtasks",
        &[
            "/Create", "/F", "/SC", "DAILY", "/TN", BUNDLE_ID, "/TR", &tr, "/ST", "11:00",
        ],
        "schtasks /Create",
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn install_update_check_timer() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn uninstall_update_check_timer() -> anyhow::Result<()> {
    use crate::proc;

    if os_side_effects_disabled() {
        return Ok(());
    }

    proc::run_optional("systemctl", &["--user", "disable", "--now", TIMER_NAME]);

    if let Some(config_dir) = dirs::config_dir() {
        let unit_dir = config_dir.join("systemd").join("user");
        let _ = fs::remove_file(unit_dir.join(TIMER_NAME));
        let _ = fs::remove_file(unit_dir.join(SERVICE_NAME));
    }

    proc::run_optional("systemctl", &["--user", "daemon-reload"]);
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn uninstall_update_check_timer() -> anyhow::Result<()> {
    use crate::proc;

    if os_side_effects_disabled() {
        return Ok(());
    }

    if let Some(home) = dirs::home_dir() {
        let plist_path = home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{}.plist", BUNDLE_ID));
        if let Some(plist_arg) = plist_path.to_str() {
            proc::run_optional("launchctl", &["unload", "-w", plist_arg]);
        }
        let _ = fs::remove_file(&plist_path);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn uninstall_update_check_timer() -> anyhow::Result<()> {
    use crate::proc;

    if os_side_effects_disabled() {
        return Ok(());
    }

    proc::run_optional("schtasks", &["/Delete", "/F", "/TN", BUNDLE_ID]);
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn uninstall_update_check_timer() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_accepts_v_prefix() {
        assert_eq!(
            parse_version("v1.2.3"),
            Some(Version::parse("1.2.3").unwrap())
        );
    }

    #[test]
    fn parse_version_accepts_bare_version() {
        assert_eq!(
            parse_version("1.2.3"),
            Some(Version::parse("1.2.3").unwrap())
        );
    }

    #[test]
    fn parse_version_rejects_garbage() {
        assert_eq!(parse_version("not-a-version"), None);
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("v"), None);
    }

    #[test]
    fn is_newer_only_for_strictly_greater() {
        // current pkg version is whatever env!() resolves to at build time;
        // construct a tag that is provably newer / older than that.
        let cur = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        let newer = Version::new(cur.major + 1, 0, 0);
        let older = Version::new(0, 0, 0);
        assert!(is_newer(&format!("v{}", newer)));
        assert!(!is_newer(&format!("v{}", cur)));
        assert!(!is_newer(&format!("v{}", older)));
        assert!(!is_newer("not-semver"));
    }

    #[test]
    fn current_asset_suffix_matches_host() {
        // Whatever host runs the test must hit a known arm or None; never
        // panic. Trade-off: this is mostly a smoke test that the match is
        // exhaustive enough for the supported targets.
        let _ = current_asset_suffix();
    }

    #[test]
    fn resolve_asset_url_finds_named_asset() {
        let release: serde_json::Value = serde_json::from_str(
            r#"{
                "tag_name": "v1.2.3",
                "assets": [
                    {"name": "secret-stripper-linux-x86_64", "url": "https://api.github.com/asset/1"},
                    {"name": "secret-stripper-macos-aarch64", "url": "https://api.github.com/asset/2"}
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(
            resolve_asset_url(&release, "secret-stripper-linux-x86_64").as_deref(),
            Some("https://api.github.com/asset/1")
        );
        assert_eq!(resolve_asset_url(&release, "missing-asset"), None);
    }

    #[test]
    fn resolve_asset_url_handles_no_assets_array() {
        let release: serde_json::Value = serde_json::from_str(r#"{"tag_name": "v1"}"#).unwrap();
        assert_eq!(resolve_asset_url(&release, "anything"), None);
    }

    #[test]
    fn repo_env_override_round_trips() {
        // Default path: env unset -> DEFAULT_REPO.
        std::env::remove_var("SECRET_STRIPPER_REPO");
        assert_eq!(repo(), DEFAULT_REPO);
        std::env::set_var("SECRET_STRIPPER_REPO", "owner/fork");
        assert_eq!(repo(), "owner/fork");
        std::env::remove_var("SECRET_STRIPPER_REPO");
    }
}
