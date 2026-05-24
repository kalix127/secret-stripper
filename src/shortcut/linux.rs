use anyhow::{anyhow, Result};
use std::fs;
use std::process::Command;

use crate::lang::ShortcutBackend;

const KDE_DESKTOP_FILE_NAME: &str = "secret-stripper-trigger.desktop";

// Per-DE binding spec for the gsettings-based desktops (GNOME, Cinnamon, MATE).
// The schemas differ in subtle ways verified against each project's gschema.xml:
//   list_key            - key holding the array of custom keybindings
//   list_entry_short_id - Cinnamon stores SHORT IDs ("secret-stripper");
//                         GNOME and MATE store FULL DCONF PATHS
//   command_field       - "command" on GNOME/Cinnamon, "action" on MATE
//   chord_modifier_ctrl - "<Control>" everywhere except MATE which expects "<Ctrl>"
//   binding_is_array    - Cinnamon's `binding` is type `as`; GNOME and MATE are type `s`
struct GsettingsBinding {
    list_schema: &'static str,
    list_key: &'static str,
    list_entry_short_id: Option<&'static str>,
    item_schema: &'static str,
    item_path: &'static str,
    command_field: &'static str,
    chord_modifier_ctrl: &'static str,
    binding_is_array: bool,
}

const GNOME_BINDING: GsettingsBinding = GsettingsBinding {
    list_schema: "org.gnome.settings-daemon.plugins.media-keys",
    list_key: "custom-keybindings",
    list_entry_short_id: None,
    item_schema: "org.gnome.settings-daemon.plugins.media-keys.custom-keybinding",
    item_path: "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/secret-stripper/",
    command_field: "command",
    chord_modifier_ctrl: "<Control>",
    binding_is_array: false,
};

const CINNAMON_BINDING: GsettingsBinding = GsettingsBinding {
    list_schema: "org.cinnamon.desktop.keybindings",
    list_key: "custom-list",
    list_entry_short_id: Some("secret-stripper"),
    item_schema: "org.cinnamon.desktop.keybindings.custom-keybinding",
    item_path: "/org/cinnamon/desktop/keybindings/custom-keybindings/secret-stripper/",
    command_field: "command",
    chord_modifier_ctrl: "<Control>",
    binding_is_array: true,
};

const MATE_BINDING: GsettingsBinding = GsettingsBinding {
    list_schema: "org.mate.SettingsDaemon.plugins.media-keys",
    list_key: "custom-keybindings",
    list_entry_short_id: None,
    item_schema: "org.mate.SettingsDaemon.plugins.media-keys.custom-keybinding",
    item_path: "/org/mate/desktop/keybindings/secret-stripper/",
    command_field: "action",
    chord_modifier_ctrl: "<Ctrl>",
    binding_is_array: false,
};

pub(super) fn detect_desktop() -> String {
    std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default()
}

pub(super) fn register(chord: &str) -> Result<ShortcutBackend> {
    let de = detect_desktop();
    let de_lower = de.to_ascii_lowercase();

    if de_lower.contains("gnome")
        || de_lower.contains("unity")
        || de_lower.contains("budgie")
        || de_lower.contains("pantheon")
    {
        // Unity, Budgie, and Pantheon all reuse the GNOME schema in practice.
        register_gsettings(&GNOME_BINDING, chord)?;
        Ok(ShortcutBackend::Gnome)
    } else if de_lower.contains("cinnamon") || de_lower.contains("x-cinnamon") {
        register_gsettings(&CINNAMON_BINDING, chord)?;
        Ok(ShortcutBackend::Cinnamon)
    } else if de_lower.contains("mate") {
        register_gsettings(&MATE_BINDING, chord)?;
        Ok(ShortcutBackend::Mate)
    } else if de_lower.contains("xfce") {
        register_xfce(chord)?;
        Ok(ShortcutBackend::Xfce)
    } else if de_lower.contains("kde") || de_lower.contains("plasma") {
        register_kde(chord)?;
        Ok(ShortcutBackend::Kde)
    } else if de.is_empty() {
        Err(anyhow!(
            "No desktop environment detected ($XDG_CURRENT_DESKTOP is empty). Bind 'secret-stripper trigger' to {} via your window manager's config (sway, hyprland, i3, etc.).",
            chord
        ))
    } else {
        Err(anyhow!(
            "Auto-binding for '{}' is not implemented. Bind 'secret-stripper trigger' to {} via your desktop's shortcut settings.",
            de, chord
        ))
    }
}

pub(super) fn unregister() -> Result<()> {
    let de = detect_desktop();
    let de_lower = de.to_ascii_lowercase();
    if de_lower.contains("gnome")
        || de_lower.contains("unity")
        || de_lower.contains("budgie")
        || de_lower.contains("pantheon")
    {
        unregister_gsettings(&GNOME_BINDING)?;
    } else if de_lower.contains("cinnamon") || de_lower.contains("x-cinnamon") {
        unregister_gsettings(&CINNAMON_BINDING)?;
    } else if de_lower.contains("mate") {
        unregister_gsettings(&MATE_BINDING)?;
    } else if de_lower.contains("xfce") {
        unregister_xfce()?;
    } else if de_lower.contains("kde") || de_lower.contains("plasma") {
        unregister_kde()?;
    }
    Ok(())
}

fn register_gsettings(b: &GsettingsBinding, chord: &str) -> Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| anyhow!("could not resolve our own binary path: {}", e))?;
    let exe_str = exe
        .to_str()
        .ok_or_else(|| anyhow!("non-UTF8 binary path"))?;

    let chord_value = chord_to_keysym_format(chord, b.chord_modifier_ctrl)?;
    let binding_value = if b.binding_is_array {
        format!("['{}']", chord_value)
    } else {
        chord_value
    };

    // First: write the per-key properties (name, command, binding). gnome-settings-daemon
    // reads these when the entry shows up in the list.
    let entries = [
        ("name", crate::APP_NAME.to_string()),
        (b.command_field, format!("{} trigger", exe_str)),
        ("binding", binding_value),
    ];

    let schema_path = format!("{}:{}", b.item_schema, b.item_path);
    for (key, value) in &entries {
        let status = Command::new("gsettings")
            .args(["set", &schema_path, key, value])
            .status()
            .map_err(|e| anyhow!("gsettings invocation failed: {}", e))?;
        if !status.success() {
            return Err(anyhow!(
                "gsettings set {} {} failed (status {})",
                key,
                value,
                status
            ));
        }
    }

    // Force gnome-settings-daemon to re-read by toggling the entry off-then-on in the list.
    // Setting the list to a value that DROPS our path makes the daemon release any prior
    // grab; then re-adding the path makes it re-read the per-key properties (which now hold
    // the new chord). Without this toggle, the daemon caches the original binding and the
    // rebind silently no-ops at the OS level even though dconf is correct.
    remove_from_list(b)?;
    add_gsettings_list_entry(b)?;

    Ok(())
}

fn remove_from_list(b: &GsettingsBinding) -> Result<()> {
    let output = Command::new("gsettings")
        .args(["get", b.list_schema, b.list_key])
        .output()
        .map_err(|e| anyhow!("gsettings get failed: {}", e))?;
    let current = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let entry = list_entry_value(b);
    let target = format!("'{}'", entry);
    if !current.contains(&target) {
        return Ok(());
    }
    let new_list = strip_path_from_list(&current, &entry);
    let _ = Command::new("gsettings")
        .args(["set", b.list_schema, b.list_key, &new_list])
        .status();
    Ok(())
}

fn list_entry_value(b: &GsettingsBinding) -> String {
    match b.list_entry_short_id {
        Some(id) => id.to_string(),
        None => b.item_path.to_string(),
    }
}

fn unregister_gsettings(b: &GsettingsBinding) -> Result<()> {
    let output = Command::new("gsettings")
        .args(["get", b.list_schema, b.list_key])
        .output()
        .map_err(|e| anyhow!("gsettings get failed: {}", e))?;
    let current = String::from_utf8_lossy(&output.stdout).trim().to_string();

    let entry = list_entry_value(b);
    let target = format!("'{}'", entry);
    if !current.contains(&target) {
        return Ok(());
    }

    let new_list = strip_path_from_list(&current, &entry);
    let _ = Command::new("gsettings")
        .args(["set", b.list_schema, b.list_key, &new_list])
        .status();
    Ok(())
}

fn add_gsettings_list_entry(b: &GsettingsBinding) -> Result<()> {
    let output = Command::new("gsettings")
        .args(["get", b.list_schema, b.list_key])
        .output()
        .map_err(|e| anyhow!("gsettings get failed: {}", e))?;
    let current = String::from_utf8_lossy(&output.stdout).trim().to_string();

    let entry = list_entry_value(b);
    let target = format!("'{}'", entry);
    if current.contains(&target) {
        return Ok(());
    }

    let new_list = if current == "@as []" || current.is_empty() {
        format!("['{}']", entry)
    } else {
        let inner = current.trim_start_matches('[').trim_end_matches(']').trim();
        if inner.is_empty() {
            format!("['{}']", entry)
        } else {
            format!("[{}, '{}']", inner, entry)
        }
    };

    let status = Command::new("gsettings")
        .args(["set", b.list_schema, b.list_key, &new_list])
        .status()
        .map_err(|e| anyhow!("gsettings set list failed: {}", e))?;
    if !status.success() {
        return Err(anyhow!(
            "gsettings set {} list failed (status {})",
            b.list_key,
            status
        ));
    }
    Ok(())
}

fn register_xfce(chord: &str) -> Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| anyhow!("could not resolve our own binary path: {}", e))?;
    let exe_str = exe
        .to_str()
        .ok_or_else(|| anyhow!("non-UTF8 binary path"))?;

    let chord_keysym = chord_to_keysym_format(chord, "<Control>")?;
    let prop = format!("/commands/custom/{}", chord_keysym);
    let value = format!("{} trigger", exe_str);

    // -n creates the property, -t string sets type, -s sets value.
    let status = Command::new("xfconf-query")
        .args([
            "-c",
            "xfce4-keyboard-shortcuts",
            "-p",
            &prop,
            "-n",
            "-t",
            "string",
            "-s",
            &value,
        ])
        .status()
        .map_err(|e| anyhow!("xfconf-query invocation failed: {}", e))?;
    if !status.success() {
        // -n fails if the property already exists; retry without -n to update in place.
        let status2 = Command::new("xfconf-query")
            .args([
                "-c",
                "xfce4-keyboard-shortcuts",
                "-p",
                &prop,
                "-t",
                "string",
                "-s",
                &value,
            ])
            .status()
            .map_err(|e| anyhow!("xfconf-query invocation failed: {}", e))?;
        if !status2.success() {
            return Err(anyhow!("xfconf-query exited with status {}", status2));
        }
    }
    Ok(())
}

fn unregister_xfce() -> Result<()> {
    // We do not know which chord we registered without reading config; iterate the common
    // candidates plus the user's currently-configured chord (caller passes via env if needed).
    // Simplest: scan all custom commands and remove ours.
    let output = Command::new("xfconf-query")
        .args(["-c", "xfce4-keyboard-shortcuts", "-l", "-v"])
        .output()
        .map_err(|e| anyhow!("xfconf-query list failed: {}", e))?;
    let listing = String::from_utf8_lossy(&output.stdout);

    for line in listing.lines() {
        if line.contains("secret-stripper") {
            if let Some(prop) = line.split_whitespace().next() {
                let _ = Command::new("xfconf-query")
                    .args(["-c", "xfce4-keyboard-shortcuts", "-p", prop, "-r"])
                    .status();
            }
        }
    }
    Ok(())
}

fn register_kde(chord: &str) -> Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| anyhow!("could not resolve our own binary path: {}", e))?;
    let exe_str = exe
        .to_str()
        .ok_or_else(|| anyhow!("non-UTF8 binary path"))?;

    let kwc = pick_kwriteconfig()?;

    let apps_dir = dirs::data_dir()
        .ok_or_else(|| anyhow!("no XDG data dir"))?
        .join("applications");
    fs::create_dir_all(&apps_dir)?;
    let desktop_path = apps_dir.join(KDE_DESKTOP_FILE_NAME);
    let desktop_content = format!(
        "[Desktop Entry]\nName=Secret Stripper Trigger\nExec=\"{}\" trigger\nType=Application\nNoDisplay=true\nX-KDE-StartupNotify=false\n",
        exe_str
    );
    fs::write(&desktop_path, desktop_content)?;

    let value = format!("{},none,Run Secret Stripper Trigger", chord);
    let status = Command::new(&kwc)
        .args([
            "--file",
            "kglobalshortcutsrc",
            "--group",
            KDE_DESKTOP_FILE_NAME,
            "--key",
            "_launch",
            &value,
        ])
        .status()
        .map_err(|e| anyhow!("{} invocation failed: {}", kwc, e))?;
    if !status.success() {
        return Err(anyhow!("{} exited with status {}", kwc, status));
    }

    for tool in ["qdbus6", "qdbus-qt6", "qdbus"] {
        let r = Command::new(tool)
            .args([
                "org.kde.kglobalaccel",
                "/component/secret_stripper_trigger_desktop",
                "org.kde.kglobalaccel.Component.cleanUp",
            ])
            .status();
        if let Ok(s) = r {
            if s.success() {
                break;
            }
        }
    }

    Ok(())
}

fn unregister_kde() -> Result<()> {
    if let Some(apps_dir) = dirs::data_dir().map(|p| p.join("applications")) {
        let _ = fs::remove_file(apps_dir.join(KDE_DESKTOP_FILE_NAME));
    }
    if let Ok(kwc) = pick_kwriteconfig() {
        let _ = Command::new(&kwc)
            .args([
                "--file",
                "kglobalshortcutsrc",
                "--group",
                KDE_DESKTOP_FILE_NAME,
                "--key",
                "_launch",
                "--delete",
            ])
            .status();
    }
    Ok(())
}

fn pick_kwriteconfig() -> Result<String> {
    for tool in ["kwriteconfig6", "kwriteconfig5"] {
        if Command::new(tool).arg("--help").output().is_ok() {
            return Ok(tool.to_string());
        }
    }
    Err(anyhow!(
        "Neither kwriteconfig6 nor kwriteconfig5 is installed; cannot bind a KDE shortcut. Install plasma-workspace or kde-cli-tools."
    ))
}

fn strip_path_from_list(list: &str, path: &str) -> String {
    let inner = list.trim_start_matches('[').trim_end_matches(']');
    let kept: Vec<&str> = inner
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && *s != format!("'{}'", path).as_str())
        .collect();
    if kept.is_empty() {
        "@as []".to_string()
    } else {
        format!("[{}]", kept.join(", "))
    }
}

// Convert "Ctrl+Alt+C" to GTK accelerator format like "<Control><Alt>c".
// `ctrl_modifier` lets MATE override "<Control>" to "<Ctrl>".
fn chord_to_keysym_format(chord: &str, ctrl_modifier: &str) -> Result<String> {
    let mut out = String::new();
    let mut key: Option<String> = None;

    for raw in chord.split('+') {
        let part = raw.trim();
        if part.is_empty() {
            continue;
        }
        match part.to_ascii_lowercase().as_str() {
            "ctrl" | "control" => out.push_str(ctrl_modifier),
            "alt" | "option" | "opt" => out.push_str("<Alt>"),
            "shift" => out.push_str("<Shift>"),
            "cmd" | "command" | "super" | "meta" | "win" | "windows" => out.push_str("<Super>"),
            other => {
                if key.is_some() {
                    return Err(anyhow!("chord '{}' has multiple non-modifier keys", chord));
                }
                key = Some(other.to_string());
            }
        }
    }

    let k = key.ok_or_else(|| anyhow!("chord '{}' has no key", chord))?;
    out.push_str(&k);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gnome_format_basic() {
        assert_eq!(
            chord_to_keysym_format("Ctrl+Alt+C", "<Control>").unwrap(),
            "<Control><Alt>c"
        );
    }

    #[test]
    fn mate_format_uses_ctrl() {
        assert_eq!(
            chord_to_keysym_format("Ctrl+Alt+R", "<Ctrl>").unwrap(),
            "<Ctrl><Alt>r"
        );
    }

    #[test]
    fn keysym_super() {
        assert_eq!(
            chord_to_keysym_format("Super+Shift+R", "<Control>").unwrap(),
            "<Super><Shift>r"
        );
    }

    #[test]
    fn keysym_case_insensitive() {
        assert_eq!(
            chord_to_keysym_format("ctrl+ALT+r", "<Control>").unwrap(),
            "<Control><Alt>r"
        );
    }

    #[test]
    fn strip_removes_target() {
        let s = strip_path_from_list("['/a/', '/b/']", "/a/");
        assert_eq!(s, "['/b/']");
    }

    #[test]
    fn strip_handles_only_entry() {
        let s = strip_path_from_list("['/a/']", "/a/");
        assert_eq!(s, "@as []");
    }

    #[test]
    fn cinnamon_uses_short_id_in_list() {
        assert_eq!(list_entry_value(&CINNAMON_BINDING), "secret-stripper");
    }

    #[test]
    fn gnome_uses_full_path_in_list() {
        assert!(list_entry_value(&GNOME_BINDING).starts_with("/org/gnome/"));
    }

    #[test]
    fn mate_uses_full_path_in_list() {
        assert!(list_entry_value(&MATE_BINDING).starts_with("/org/mate/"));
    }

    // Compile-time invariant: Cinnamon's `binding` schema is `as` (array) while
    // GNOME and MATE use `s` (string). Flipping these at the const level breaks
    // the gsettings call format, so guard with a const assertion that fires at
    // build time rather than at runtime. clippy rejects assert! in #[test] when
    // the operand is a compile-time constant.
    const _: () = {
        assert!(CINNAMON_BINDING.binding_is_array);
        assert!(!GNOME_BINDING.binding_is_array);
        assert!(!MATE_BINDING.binding_is_array);
    };
}
