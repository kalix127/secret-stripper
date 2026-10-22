use anyhow::{anyhow, Result};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use crate::hotkey::chord_parts;
use crate::lang::ShortcutBackend;

/// One shortcut we register. Terminals paste with Ctrl+Shift+V and no
/// Wayland compositor tells us the focused app, so they get their own chord.
struct Entry {
    /// gsettings item id, also Cinnamon's list entry.
    id: &'static str,
    name: &'static str,
    args: &'static str,
    kde_desktop_file: &'static str,
}

const PASTE: Entry = Entry {
    id: "secret-stripper",
    name: "Secret Stripper",
    args: "paste",
    kde_desktop_file: "secret-stripper-paste.desktop",
};

const PASTE_TERMINAL: Entry = Entry {
    id: "secret-stripper-terminal",
    name: "Secret Stripper (terminal)",
    args: "paste --terminal",
    kde_desktop_file: "secret-stripper-paste-terminal.desktop",
};

const ENTRIES: [&Entry; 2] = [&PASTE, &PASTE_TERMINAL];

// 1.x bound `trigger` under this name; removed so an upgraded install does
// not keep a second, dead shortcut.
const KDE_LEGACY_DESKTOP_FILE_NAME: &str = "secret-stripper-trigger.desktop";
const HYPRLAND_INCLUDE_NAME: &str = "secret-stripper.conf";

// Per-DE binding spec for the gsettings-based desktops (GNOME, Cinnamon, MATE).
// The schemas differ in subtle ways verified against each project's gschema.xml:
//   list_key            - key holding the array of custom keybindings
//   list_uses_short_id  - Cinnamon stores SHORT IDs ("secret-stripper");
//                         GNOME and MATE store FULL DCONF PATHS
//   command_field       - "command" on GNOME/Cinnamon, "action" on MATE
//   chord_modifier_ctrl - "<Control>" everywhere except MATE which expects "<Ctrl>"
//   binding_is_array    - Cinnamon's `binding` is type `as`; GNOME and MATE are type `s`
struct GsettingsBinding {
    list_schema: &'static str,
    list_key: &'static str,
    list_uses_short_id: bool,
    item_schema: &'static str,
    item_dir: &'static str,
    command_field: &'static str,
    chord_modifier_ctrl: &'static str,
    binding_is_array: bool,
}

const GNOME_BINDING: GsettingsBinding = GsettingsBinding {
    list_schema: "org.gnome.settings-daemon.plugins.media-keys",
    list_key: "custom-keybindings",
    list_uses_short_id: false,
    item_schema: "org.gnome.settings-daemon.plugins.media-keys.custom-keybinding",
    item_dir: "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/",
    command_field: "command",
    chord_modifier_ctrl: "<Control>",
    binding_is_array: false,
};

const CINNAMON_BINDING: GsettingsBinding = GsettingsBinding {
    list_schema: "org.cinnamon.desktop.keybindings",
    list_key: "custom-list",
    list_uses_short_id: true,
    item_schema: "org.cinnamon.desktop.keybindings.custom-keybinding",
    item_dir: "/org/cinnamon/desktop/keybindings/custom-keybindings/",
    command_field: "command",
    chord_modifier_ctrl: "<Control>",
    binding_is_array: true,
};

const MATE_BINDING: GsettingsBinding = GsettingsBinding {
    list_schema: "org.mate.SettingsDaemon.plugins.media-keys",
    list_key: "custom-keybindings",
    list_uses_short_id: false,
    item_schema: "org.mate.SettingsDaemon.plugins.media-keys.custom-keybinding",
    item_dir: "/org/mate/desktop/keybindings/",
    command_field: "action",
    chord_modifier_ctrl: "<Ctrl>",
    binding_is_array: false,
};

pub(super) fn detect_desktop() -> String {
    std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default()
}

fn is_hyprland(de_lower: &str) -> bool {
    de_lower.contains("hyprland") || std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_some()
}

/// Each entry with its chord; None means the entry must be removed (no
/// terminal chord when the main chord already uses Shift).
fn planned(chord: &str) -> [(&'static Entry, Option<String>); 2] {
    [
        (&PASTE, Some(chord.to_string())),
        (&PASTE_TERMINAL, crate::hotkey::terminal_chord(chord)),
    ]
}

fn own_exe() -> Result<String> {
    let exe = std::env::current_exe()
        .map_err(|e| anyhow!("could not resolve our own binary path: {}", e))?;
    exe.to_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("non-UTF8 binary path"))
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
    } else if is_hyprland(&de_lower) {
        register_hyprland(chord)?;
        Ok(ShortcutBackend::Hyprland)
    } else if de.is_empty() {
        Err(anyhow!(
            "No desktop environment detected ($XDG_CURRENT_DESKTOP is empty). Bind 'secret-stripper paste' to {} and 'secret-stripper paste --terminal' to the same chord plus Shift via your window manager's config.",
            chord
        ))
    } else {
        Err(anyhow!(
            "Auto-binding for '{}' is not implemented. Bind 'secret-stripper paste' to {} and 'secret-stripper paste --terminal' to the same chord plus Shift via your desktop's shortcut settings.",
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
    } else if is_hyprland(&de_lower) {
        unregister_hyprland()?;
    }
    Ok(())
}

fn register_gsettings(b: &GsettingsBinding, chord: &str) -> Result<()> {
    let exe_str = own_exe()?;
    for (entry, chord) in planned(chord) {
        match chord {
            Some(chord) => register_gsettings_entry(b, entry, &chord, &exe_str)?,
            None => remove_from_list(b, entry)?,
        }
    }
    Ok(())
}

fn register_gsettings_entry(
    b: &GsettingsBinding,
    entry: &Entry,
    chord: &str,
    exe_str: &str,
) -> Result<()> {
    let chord_value = chord_to_keysym_format(chord, b.chord_modifier_ctrl)?;
    let binding_value = if b.binding_is_array {
        format!("['{}']", chord_value)
    } else {
        chord_value
    };

    // First: write the per-key properties (name, command, binding). gnome-settings-daemon
    // reads these when the entry shows up in the list.
    let entries = [
        ("name", entry.name.to_string()),
        (b.command_field, format!("{} {}", exe_str, entry.args)),
        ("binding", binding_value),
    ];

    let schema_path = format!("{}:{}", b.item_schema, item_path(b, entry));
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
    remove_from_list(b, entry)?;
    add_gsettings_list_entry(b, entry)?;

    Ok(())
}

fn item_path(b: &GsettingsBinding, entry: &Entry) -> String {
    format!("{}{}/", b.item_dir, entry.id)
}

fn list_entry_value(b: &GsettingsBinding, entry: &Entry) -> String {
    if b.list_uses_short_id {
        entry.id.to_string()
    } else {
        item_path(b, entry)
    }
}

fn read_list(b: &GsettingsBinding) -> Result<String> {
    let output = Command::new("gsettings")
        .args(["get", b.list_schema, b.list_key])
        .output()
        .map_err(|e| anyhow!("gsettings get failed: {}", e))?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn remove_from_list(b: &GsettingsBinding, entry: &Entry) -> Result<()> {
    let current = read_list(b)?;
    let value = list_entry_value(b, entry);
    if !current.contains(&format!("'{}'", value)) {
        return Ok(());
    }
    let new_list = strip_path_from_list(&current, &value);
    let _ = Command::new("gsettings")
        .args(["set", b.list_schema, b.list_key, &new_list])
        .status();
    Ok(())
}

fn unregister_gsettings(b: &GsettingsBinding) -> Result<()> {
    for entry in ENTRIES {
        remove_from_list(b, entry)?;
    }
    Ok(())
}

fn add_gsettings_list_entry(b: &GsettingsBinding, entry: &Entry) -> Result<()> {
    let current = read_list(b)?;
    let Some(new_list) = list_with_entry(&current, &list_entry_value(b, entry)) else {
        return Ok(());
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

/// The gsettings list `current` with `value` appended, or None when it is
/// already there.
fn list_with_entry(current: &str, value: &str) -> Option<String> {
    if current.contains(&format!("'{}'", value)) {
        return None;
    }
    let inner = current
        .trim_start_matches("@as")
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    Some(if inner.is_empty() {
        format!("['{}']", value)
    } else {
        format!("[{}, '{}']", inner, value)
    })
}

fn register_xfce(chord: &str) -> Result<()> {
    let exe_str = own_exe()?;
    // Properties are keyed by chord, so stale ones from an older chord would
    // otherwise stay bound.
    unregister_xfce()?;
    for (entry, chord) in planned(chord) {
        let Some(chord) = chord else { continue };
        let chord_keysym = chord_to_keysym_format(&chord, "<Control>")?;
        let prop = format!("/commands/custom/{}", chord_keysym);
        let value = format!("{} {}", exe_str, entry.args);

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
    }
    Ok(())
}

fn unregister_xfce() -> Result<()> {
    // Scan all custom commands and remove every one that runs us.
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

fn kde_component_path(desktop_file: &str) -> String {
    format!("/component/{}", desktop_file.replace(['-', '.'], "_"))
}

fn register_kde(chord: &str) -> Result<()> {
    let exe_str = own_exe()?;
    let kwc = pick_kwriteconfig()?;
    remove_kde_entry(KDE_LEGACY_DESKTOP_FILE_NAME);

    let apps_dir = dirs::data_dir()
        .ok_or_else(|| anyhow!("no XDG data dir"))?
        .join("applications");
    fs::create_dir_all(&apps_dir)?;

    for (entry, chord) in planned(chord) {
        let Some(chord) = chord else {
            remove_kde_entry(entry.kde_desktop_file);
            continue;
        };
        let desktop_content = format!(
            "[Desktop Entry]\nName={}\nExec=\"{}\" {}\nType=Application\nNoDisplay=true\nX-KDE-StartupNotify=false\n",
            entry.name, exe_str, entry.args
        );
        fs::write(apps_dir.join(entry.kde_desktop_file), desktop_content)?;

        let value = format!("{},none,{}", chord, entry.name);
        let status = Command::new(&kwc)
            .args([
                "--file",
                "kglobalshortcutsrc",
                "--group",
                entry.kde_desktop_file,
                "--key",
                "_launch",
                &value,
            ])
            .status()
            .map_err(|e| anyhow!("{} invocation failed: {}", kwc, e))?;
        if !status.success() {
            return Err(anyhow!("{} exited with status {}", kwc, status));
        }
        kde_clean_up(entry.kde_desktop_file);
    }

    Ok(())
}

/// Make the running kglobalaccel drop shortcuts it still holds for this entry;
/// otherwise a removed or changed binding keeps grabbing its chord until
/// re-login.
fn kde_clean_up(desktop_file: &str) {
    let component = kde_component_path(desktop_file);
    for tool in ["qdbus6", "qdbus-qt6", "qdbus"] {
        let r = Command::new(tool)
            .args([
                "org.kde.kglobalaccel",
                &component,
                "org.kde.kglobalaccel.Component.cleanUp",
            ])
            .status();
        if let Ok(s) = r {
            if s.success() {
                break;
            }
        }
    }
}

fn unregister_kde() -> Result<()> {
    for entry in ENTRIES {
        remove_kde_entry(entry.kde_desktop_file);
    }
    remove_kde_entry(KDE_LEGACY_DESKTOP_FILE_NAME);
    Ok(())
}

fn remove_kde_entry(name: &str) {
    if let Some(dir) = dirs::data_dir().map(|p| p.join("applications")) {
        let _ = fs::remove_file(dir.join(name));
    }
    if let Ok(kwc) = pick_kwriteconfig() {
        let _ = Command::new(&kwc)
            .args([
                "--file",
                "kglobalshortcutsrc",
                "--group",
                name,
                "--key",
                "_launch",
                "--delete",
            ])
            .status();
    }
    kde_clean_up(name);
}

fn hyprland_dir() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .ok_or_else(|| anyhow!("no XDG config dir"))?
        .join("hypr"))
}

fn hyprland_source_line(include: &std::path::Path) -> String {
    format!("source = {}", include.display())
}

// The binds live in their own sourced file so unregister never has to edit
// lines the user wrote; hyprland.conf only gains one `source` line.
fn register_hyprland(chord: &str) -> Result<()> {
    write_hyprland_binds(&hyprland_dir()?, &own_exe()?, chord)?;
    crate::proc::run_optional("hyprctl", &["reload"]);
    Ok(())
}

fn write_hyprland_binds(dir: &std::path::Path, exe_str: &str, chord: &str) -> Result<()> {
    if exe_str.contains('\'') {
        return Err(anyhow!("binary path contains a quote: {}", exe_str));
    }

    let main = dir.join("hyprland.conf");
    if !main.is_file() {
        return Err(anyhow!("{} not found", main.display()));
    }
    // Opened before the include is written so a read-only config (e.g. one
    // generated by Nix) fails without leaving an orphan include behind.
    let mut main_file = fs::OpenOptions::new().append(true).open(&main)?;
    let include = dir.join(HYPRLAND_INCLUDE_NAME);
    let mut binds = String::new();
    for (entry, chord) in planned(chord) {
        if let Some(chord) = chord {
            binds.push_str(&format!(
                "bind = {}, exec, '{}' {}\n",
                hyprland_bind(&chord)?,
                exe_str,
                entry.args
            ));
        }
    }
    fs::write(&include, binds)?;

    let source = hyprland_source_line(&include);
    let current = fs::read_to_string(&main)?;
    if !current.lines().any(|l| l.trim() == source) {
        let sep = if current.is_empty() || current.ends_with('\n') {
            ""
        } else {
            "\n"
        };
        writeln!(main_file, "{sep}{source}")?;
    }
    Ok(())
}

fn unregister_hyprland() -> Result<()> {
    remove_hyprland_binds(&hyprland_dir()?)?;
    crate::proc::run_optional("hyprctl", &["reload"]);
    Ok(())
}

fn remove_hyprland_binds(dir: &std::path::Path) -> Result<()> {
    let main = dir.join("hyprland.conf");
    let include = dir.join(HYPRLAND_INCLUDE_NAME);
    let source = hyprland_source_line(&include);
    if let Ok(current) = fs::read_to_string(&main) {
        if current.lines().any(|l| l.trim() == source) {
            replace_file(&main, &without_line(&current, &source))?;
        }
    }
    let _ = fs::remove_file(&include);
    Ok(())
}

/// Drop every line equal to `line` after trimming, keeping the other lines
/// byte for byte, CRLF endings included.
fn without_line(text: &str, line: &str) -> String {
    text.split_inclusive('\n')
        .filter(|l| l.trim() != line)
        .collect()
}

/// Replace a user config atomically. Writes through a symlink (dotfile
/// managers link hyprland.conf) and keeps the file's permissions.
fn replace_file(path: &std::path::Path, contents: &str) -> Result<()> {
    let target = fs::canonicalize(path)?;
    let dir = target
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent dir", target.display()))?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(contents.as_bytes())?;
    tmp.as_file()
        .set_permissions(fs::metadata(&target)?.permissions())?;
    tmp.persist(&target)?;
    Ok(())
}

// xkb keysym names shared by Hyprland and sway/i3; letters and digits are
// used as is.
fn xkb_key_name(key: &str) -> String {
    match key {
        "space" => "space".to_string(),
        "enter" | "return" => "Return".to_string(),
        "tab" => "Tab".to_string(),
        "escape" | "esc" => "Escape".to_string(),
        k if k.starts_with('f') && k.len() > 1 => k.to_ascii_uppercase(),
        k => k.to_string(),
    }
}

// "Ctrl+Alt+V" -> "CTRL ALT, V", the letter case Hyprland documents.
fn hyprland_bind(chord: &str) -> Result<String> {
    let (mods, key) = chord_parts(chord)?;
    let mods: Vec<String> = mods.iter().map(|m| m.to_ascii_uppercase()).collect();
    let key = if key.len() == 1 {
        key.to_ascii_uppercase()
    } else {
        xkb_key_name(&key)
    };
    Ok(format!("{}, {}", mods.join(" "), key))
}

// "Ctrl+Alt+V" -> "Ctrl+Mod1+v"; an uppercase letter would be the shifted
// keysym and never match.
fn sway_bind(chord: &str) -> Result<String> {
    let (mods, key) = chord_parts(chord)?;
    let mut parts: Vec<String> = mods
        .iter()
        .map(|m| {
            match *m {
                "ctrl" => "Ctrl",
                "alt" => "Mod1",
                "shift" => "Shift",
                _ => "Mod4",
            }
            .to_string()
        })
        .collect();
    parts.push(xkb_key_name(&key));
    Ok(parts.join("+"))
}

pub(super) fn manual_examples(exe: &str, chord: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (entry, chord) in planned(chord) {
        let Some(chord) = chord else { continue };
        if let Ok(b) = sway_bind(&chord) {
            out.push(format!(
                "sway / i3:  bindsym {b} exec '{exe}' {}",
                entry.args
            ));
        }
    }
    for (entry, chord) in planned(chord) {
        let Some(chord) = chord else { continue };
        if let Ok(b) = hyprland_bind(&chord) {
            out.push(format!(
                "Hyprland:   bind = {b}, exec, '{exe}' {}",
                entry.args
            ));
        }
    }
    out
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
    let (mods, key) = chord_parts(chord)?;
    let mut out: String = mods
        .iter()
        .map(|m| match *m {
            "ctrl" => ctrl_modifier,
            "alt" => "<Alt>",
            "shift" => "<Shift>",
            _ => "<Super>",
        })
        .collect();
    out.push_str(&key);
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
    fn hyprland_bind_format() {
        assert_eq!(hyprland_bind("Ctrl+Alt+V").unwrap(), "CTRL ALT, V");
        assert_eq!(hyprland_bind("Super+Shift+F5").unwrap(), "SUPER SHIFT, F5");
        assert_eq!(hyprland_bind("ctrl+alt+enter").unwrap(), "CTRL ALT, Return");
    }

    #[test]
    fn sway_bind_format() {
        assert_eq!(sway_bind("Ctrl+Alt+V").unwrap(), "Ctrl+Mod1+v");
        assert_eq!(sway_bind("Super+Shift+Space").unwrap(), "Mod4+Shift+space");
    }

    #[test]
    fn manual_examples_cover_sway_and_hyprland() {
        let lines = manual_examples("/usr/local/bin/secret-stripper", "Ctrl+Alt+V");
        assert_eq!(lines.len(), 4);
        assert!(lines[0].contains("bindsym Ctrl+Mod1+v exec"));
        assert!(lines[1].contains("bindsym Ctrl+Mod1+Shift+v exec"));
        assert!(lines[1].ends_with("paste --terminal"));
        assert!(lines[2].contains("bind = CTRL ALT, V, exec"));
        assert!(lines[3].contains("bind = CTRL ALT SHIFT, V, exec"));
    }

    #[test]
    fn without_line_keeps_other_lines_and_crlf() {
        let text = "a = 1\r\n  source = /x.conf\r\nb = 2\r\nsource = /x.conf";
        assert_eq!(without_line(text, "source = /x.conf"), "a = 1\r\nb = 2\r\n");
    }

    const EXE: &str = "/usr/local/bin/secret-stripper";

    fn hypr_dir(main: &str) -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        fs::write(dir.path().join("hyprland.conf"), main).unwrap();
        dir
    }

    fn read(dir: &tempfile::TempDir, name: &str) -> String {
        fs::read_to_string(dir.path().join(name)).unwrap()
    }

    #[test]
    fn hyprland_register_writes_both_binds_and_one_source_line() {
        let dir = hypr_dir("monitor = ,preferred,auto,1\n");
        write_hyprland_binds(dir.path(), EXE, "Ctrl+Alt+V").unwrap();
        write_hyprland_binds(dir.path(), EXE, "Ctrl+Alt+V").unwrap();

        let include = dir.path().join(HYPRLAND_INCLUDE_NAME);
        let source = hyprland_source_line(&include);
        let main = read(&dir, "hyprland.conf");
        assert!(main.starts_with("monitor = ,preferred,auto,1\n"));
        assert_eq!(main.lines().filter(|l| l.trim() == source).count(), 1);
        assert_eq!(
            read(&dir, HYPRLAND_INCLUDE_NAME),
            format!(
                "bind = CTRL ALT, V, exec, '{EXE}' paste\n\
                 bind = CTRL ALT SHIFT, V, exec, '{EXE}' paste --terminal\n"
            )
        );
    }

    #[test]
    fn hyprland_register_adds_a_newline_before_the_source_line() {
        let dir = hypr_dir("monitor = ,preferred,auto,1");
        write_hyprland_binds(dir.path(), EXE, "Ctrl+Alt+V").unwrap();
        let main = read(&dir, "hyprland.conf");
        assert!(main.starts_with("monitor = ,preferred,auto,1\nsource = "));
    }

    #[test]
    fn hyprland_register_needs_the_main_config() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(write_hyprland_binds(dir.path(), EXE, "Ctrl+Alt+V").is_err());
        assert!(!dir.path().join(HYPRLAND_INCLUDE_NAME).exists());
    }

    #[test]
    fn hyprland_register_rejects_a_quote_in_the_binary_path() {
        let dir = hypr_dir("");
        assert!(write_hyprland_binds(dir.path(), "/opt/it's/bin", "Ctrl+Alt+V").is_err());
        assert!(!dir.path().join(HYPRLAND_INCLUDE_NAME).exists());
    }

    #[test]
    fn hyprland_unregister_restores_the_config_and_crlf() {
        let dir = hypr_dir("a = 1\r\nb = 2\r\n");
        write_hyprland_binds(dir.path(), EXE, "Ctrl+Alt+V").unwrap();
        remove_hyprland_binds(dir.path()).unwrap();
        assert_eq!(read(&dir, "hyprland.conf"), "a = 1\r\nb = 2\r\n");
        assert!(!dir.path().join(HYPRLAND_INCLUDE_NAME).exists());
        remove_hyprland_binds(dir.path()).unwrap();
    }

    #[test]
    fn hyprland_unregister_without_a_config_is_ok() {
        let dir = tempfile::TempDir::new().unwrap();
        remove_hyprland_binds(dir.path()).unwrap();
    }

    #[test]
    fn kde_component_matches_desktop_file() {
        assert_eq!(
            kde_component_path(PASTE.kde_desktop_file),
            "/component/secret_stripper_paste_desktop"
        );
    }

    #[test]
    fn list_entry_appends_to_any_list_shape() {
        assert_eq!(list_with_entry("@as []", "/a/").as_deref(), Some("['/a/']"));
        assert_eq!(list_with_entry("", "/a/").as_deref(), Some("['/a/']"));
        assert_eq!(list_with_entry("[]", "/a/").as_deref(), Some("['/a/']"));
        assert_eq!(
            list_with_entry("['/x/', '/y/']", "/a/").as_deref(),
            Some("['/x/', '/y/', '/a/']")
        );
    }

    #[test]
    fn list_entry_already_present_is_left_alone() {
        assert_eq!(list_with_entry("['/x/', '/a/']", "/a/"), None);
        // A longer path that merely contains the value is a different entry.
        assert!(list_with_entry("['/a/b/']", "/a/").is_some());
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
        assert_eq!(
            list_entry_value(&CINNAMON_BINDING, &PASTE),
            "secret-stripper"
        );
        assert_eq!(
            list_entry_value(&CINNAMON_BINDING, &PASTE_TERMINAL),
            "secret-stripper-terminal"
        );
    }

    #[test]
    fn gnome_uses_full_path_in_list() {
        // Same path 1.x used, so upgrades overwrite the old entry.
        assert_eq!(
            list_entry_value(&GNOME_BINDING, &PASTE),
            "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/secret-stripper/"
        );
    }

    #[test]
    fn mate_uses_full_path_in_list() {
        assert_eq!(
            list_entry_value(&MATE_BINDING, &PASTE_TERMINAL),
            "/org/mate/desktop/keybindings/secret-stripper-terminal/"
        );
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
