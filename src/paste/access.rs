use std::fs::OpenOptions;
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use std::process::Command;

use super::uinput::DEVICE_PATH;
use crate::lang::Lang;

const MODULE_PATH: &str = "/etc/modules-load.d/secret-stripper-uinput.conf";
const RULE_PATH: &str = "/etc/udev/rules.d/60-secret-stripper-uinput.rules";
// uaccess grants the node to the user of the active seat session only;
// static_node applies it before the module has created the device.
const RULE: &str =
    r#"KERNEL=="uinput", SUBSYSTEM=="misc", TAG+="uaccess", OPTIONS+="static_node=uinput""#;
const FILES: [(&str, &str); 2] = [(MODULE_PATH, "uinput"), (RULE_PATH, RULE)];
const COMMANDS: [&str; 3] = [
    "modprobe uinput",
    "udevadm control --reload-rules",
    "udevadm trigger --settle --action=change --sysname-match=uinput",
];

fn writable() -> bool {
    OpenOptions::new().write(true).open(DEVICE_PATH).is_ok()
}

fn installed() -> bool {
    Path::new(RULE_PATH).exists()
}

fn manual_commands() -> Vec<String> {
    FILES
        .iter()
        .map(|(path, line)| format!("echo '{line}' | sudo tee {path}"))
        .chain(COMMANDS.iter().map(|c| format!("sudo {c}")))
        .collect()
}

fn root_script() -> String {
    FILES
        .iter()
        .map(|(path, line)| format!("printf '%s\\n' '{line}' > {path}"))
        .chain(COMMANDS.iter().map(|c| c.to_string()))
        .collect::<Vec<_>>()
        .join(" && ")
}

/// Grant the session user write access to /dev/uinput so `paste` can type
/// on Wayland. Shows the root commands and asks before running them.
pub fn setup(lang: Lang) {
    if crate::shortcut::os_side_effects_disabled()
        || std::env::var_os("WAYLAND_DISPLAY").is_none()
        || (installed() && writable())
    {
        return;
    }
    grant(lang);
    println!();
}

fn grant(lang: Lang) {
    println!("{}", lang.uinput_intro());
    for cmd in manual_commands() {
        println!("  {cmd}");
    }
    println!();

    if !std::io::stdin().is_terminal() {
        println!("{}", lang.uinput_no_tty());
        return;
    }
    print!("{}", lang.uinput_confirm());
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    let _ = std::io::stdin().lock().read_line(&mut answer);
    if answer.trim().to_ascii_lowercase().starts_with('n') {
        println!("{}", lang.uinput_declined());
        return;
    }

    match Command::new("sudo")
        .args(["sh", "-c", &root_script()])
        .status()
    {
        Ok(status) if status.success() && writable() => println!("{}", lang.uinput_done()),
        Ok(status) if status.success() => println!("{}", lang.uinput_relogin()),
        Ok(status) => println!("{}", lang.uinput_failed(&status.to_string())),
        Err(e) => println!("{}", lang.uinput_failed(&e.to_string())),
    }
}

/// Root-owned files cannot be removed without sudo, so uninstall only prints
/// the command.
pub fn print_uninstall_hint(lang: Lang) {
    if FILES.iter().any(|(path, _)| Path::new(path).exists()) {
        let cmd = format!("sudo rm -f {MODULE_PATH} {RULE_PATH}");
        println!("{}", lang.uinput_uninstall_hint(&cmd));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_has_no_single_quote() {
        assert!(!RULE.contains('\''));
    }

    #[test]
    fn root_script_writes_both_files() {
        let script = root_script();
        assert!(script.contains(&format!("> {MODULE_PATH}")));
        assert!(script.contains(&format!("> {RULE_PATH}")));
        assert!(script.contains("TAG+=\"uaccess\""));
    }
}
