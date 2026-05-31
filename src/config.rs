use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::lang::Lang;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RedactStyle {
    Marker,
    Drop,
    Typed,
    Placeholder,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub lang: Lang,
    pub notification_timeout_secs: u64,
    pub onboarding_done: bool,
    pub redact_pattern: String,
    #[serde(default = "default_redact_style")]
    pub redact_style: RedactStyle,
    pub sensitivity: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy_threshold: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy_min_len: Option<usize>,
    pub enable_deep_scan: bool,
    /// Shannon-entropy scanner. Off by default - the named-pattern catalogue
    /// covers the high-precision cases; entropy is a safety net for unknown
    /// secret shapes that costs a moderate false-positive rate. Users can
    /// flip it on from the menu or by setting `enable_entropy = true` in
    /// `config.toml`. `serde(default)` matches the new-install default so a
    /// config.toml missing the field also loads as off.
    #[serde(default = "default_enable_entropy")]
    pub enable_entropy: bool,
    pub silent: bool,
    #[serde(default = "default_hotkey")]
    pub hotkey: String,
    #[serde(default = "default_check_for_updates")]
    pub check_for_updates: bool,
    #[serde(default)]
    pub auto_install: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_version: Option<String>,
    /// Latest release tag observed by `upgrade-check` (e.g. "v1.2.3").
    /// Persisted so the TUI status panel can show "update available" without
    /// hitting GitHub on every menu draw. Cleared by `upgrade` after a
    /// successful swap (the running binary IS that version).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disabled_categories: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowlist_regex: Vec<String>,
}

/// Files secret-stripper owns inside `base_dir()`. Single source of truth so
/// uninstall and the integration tests cannot drift apart. `last_detection.json`
/// and `last_update_check.json` are not written by the current code path but
/// kept on the cleanup list so `uninstall` reaps them from older installs that
/// did. `stats.jsonl` is the redaction-count log written by `crate::stats`.
pub const OWNED_FILES: &[&str] = &[
    "config.toml",
    "patterns.toml",
    "last_detection.json",
    "last_update_check.json",
    "stats.jsonl",
];

/// Resolve the base config directory without touching the filesystem.
///
/// `SECRET_STRIPPER_CONFIG_HOME` (when set and non-empty) overrides the
/// platform config dir; the `secret-stripper` subdir is kept either way so the
/// on-disk layout is identical. Callers that need the directory to exist must
/// call `ensure_base_dir()` (or rely on `Config::save()`, which creates it).
pub fn base_dir() -> PathBuf {
    let mut p = match std::env::var_os("SECRET_STRIPPER_CONFIG_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")),
    };
    p.push("secret-stripper");
    p
}

/// Create the base dir on demand. Best-effort, matching the prior `.ok()` use.
pub fn ensure_base_dir() -> PathBuf {
    let p = base_dir();
    let _ = fs::create_dir_all(&p);
    p
}

/// Replace `dest` atomically: create its parent, write a randomly-named temp
/// file in the same directory (so `rename` stays on the same filesystem and
/// is atomic), then rename over the target so a concurrent reader never
/// observes a torn/truncated file. Single source of truth for every config-
/// dir write (`Config::save`, custom patterns).
///
/// On Unix the temp file is created mode 0o600 before content is written, so
/// config files holding the hotkey / allowlist / custom patterns aren't world-
/// readable on shared hosts. A `NamedTempFile` is used (random suffix in the
/// parent dir) instead of a fixed `dest.with_extension("tmp")` sibling, so an
/// attacker-planted symlink cannot redirect the write.
pub fn atomic_write(dest: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = match dest.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    fs::create_dir_all(&parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(&parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o600))?;
    }
    tmp.as_file_mut().write_all(bytes)?;
    tmp.as_file_mut().sync_all()?;
    tmp.persist(dest)
        .map_err(|e| anyhow::anyhow!("persist temp file: {}", e))?;
    Ok(())
}

/// Remove every owned file and the base directory. Returns the names that were
/// actually removed (for the uninstall summary). Pure filesystem: no
/// subprocess, no OS-level shortcut/scheduler teardown.
pub fn purge_config_dir() -> Vec<String> {
    let dir = base_dir();
    let mut removed = Vec::new();
    for f in OWNED_FILES {
        let p = dir.join(f);
        if p.exists() && fs::remove_file(&p).is_ok() {
            removed.push((*f).to_string());
        }
    }
    let _ = fs::remove_dir_all(&dir);
    removed
}

fn default_hotkey() -> String {
    #[cfg(target_os = "macos")]
    {
        "Cmd+Shift+C".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        "Ctrl+Alt+C".to_string()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        "Ctrl+Alt+X".to_string()
    }
}

fn default_check_for_updates() -> bool {
    true
}

fn default_enable_entropy() -> bool {
    false
}

fn default_redact_style() -> RedactStyle {
    RedactStyle::Marker
}

impl Default for Config {
    fn default() -> Self {
        Self {
            lang: Lang::EN,
            notification_timeout_secs: 5,
            onboarding_done: false,
            redact_pattern: "[REDACTED]".to_string(),
            redact_style: RedactStyle::Marker,
            sensitivity: 3,
            entropy_threshold: None,
            entropy_min_len: None,
            enable_deep_scan: false,
            enable_entropy: false,
            silent: true,
            hotkey: default_hotkey(),
            check_for_updates: true,
            auto_install: false,
            skip_version: None,
            last_seen_version: None,
            disabled_categories: Vec::new(),
            allowlist_regex: Vec::new(),
        }
    }
}

impl Config {
    /// The exact `Config` that `init` persists on a clean first run (before
    /// hotkey probing adjusts `hotkey`). Centralized so the init file contract
    /// is testable without the bin's subprocess code.
    pub fn first_run(lang: Lang) -> Self {
        let mut c = Self {
            lang,
            onboarding_done: true,
            ..Config::default()
        };
        crate::detector::presets::Preset::Balanced.apply(&mut c);
        c
    }

    pub fn path() -> PathBuf {
        let mut p = base_dir();
        p.push("config.toml");
        p
    }

    pub fn path_exists() -> bool {
        Self::path().exists()
    }

    pub fn load() -> Self {
        let p = Self::path();
        if let Ok(data) = fs::read_to_string(&p) {
            match toml::from_str(&data) {
                Ok(cfg) => cfg,
                Err(_) => {
                    // Migrate old config: replace redact_char with redact_pattern
                    let lines: Vec<&str> = data.lines().collect();
                    let mut migrated = Vec::new();
                    for line in &lines {
                        if line.trim().starts_with("redact_char") {
                            let val = line.split('\'').nth(1).unwrap_or("*");
                            migrated.push(format!("redact_pattern = \"{}\"", val));
                        } else {
                            migrated.push(line.to_string());
                        }
                    }
                    let new_data = migrated.join("\n");
                    // Try with added lang field for newer configs
                    let with_lang = format!("{}\nlang = \"EN\"\n", new_data);
                    if let Ok(cfg) = toml::from_str(&with_lang) {
                        let _ = atomic_write(&p, with_lang.as_bytes());
                        return cfg;
                    }
                    if let Ok(cfg) = toml::from_str(&new_data) {
                        let _ = atomic_write(&p, new_data.as_bytes());
                        return cfg;
                    }
                    // Never print to stdout/stderr here: the TUI runs on an
                    // alternate screen and this is reachable from background
                    // code paths (Lang::active -> Config::load).
                    log::warn!("config corrupted, using defaults");
                    Self::default()
                }
            }
        } else {
            Self::default()
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let data = toml::to_string_pretty(self)?;
        atomic_write(&Self::path(), data.as_bytes())
    }
}
